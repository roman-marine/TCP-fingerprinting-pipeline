import argparse
import csv
import json
import logging
import struct
import sys
from pathlib import Path
import subprocess
import tempfile

"""
Extracts TCP/IP header features from TCP SYN packets for passive OS fingerprinting. Designed for labeled pcap datasets where each file corresponds to a single OS instance. Because capture is at the adapter itself, the TTL value observed is the *initial* TTL set by the OS - no hops have been consumed.

Architecture :
This script uses a hybrid approach combining tshark and Python:
 
  Phase 1 - tshark (per file):
    Filters packets to TCP SYN only (SYN set, ACK not set) originating from the OS under test, identified by its MAC address from OSNAME.csv. Exports selected IP and TCP header fields to a temporary CSV file on disk. Using tshark for this phase leverages its battle-tested dissectors and avoids the performance overhead of pure-Python packet parsing.
 
  Phase 2 - Python options parser (per row):
    The tcp.options hex blob exported by tshark is parsed in Python using struct, giving full control over wire-order preservation, NOP position tracking, and malformed option handling. This is the part of the pipeline that requires byte-level precision.
 
  Phase 3 - Python enrichment (per row):
    OS metadata (label, kernel version, family) is attached from OSNAME.csv. Session type and capture method are derived from the filename convention. The anomaly flag is computed from TTL and fragmentation fields. Rows are written incrementally to the output CSV so partial results are preserved if the run is interrupted.
 
Features extracted :
  IP layer   : TTL, DF flag, MF flag, fragment offset, total length, DSCP, IP-layer ECN bits
  TCP layer  : CWR and ECE flags, window size, MSS, window scale, SACK permitted, timestamp presence, TSecr anomaly flag
  Options    : Full options order (wire order preserved), NOP positions, unknown option kinds and lengths
  Metadata   : pcap filename, frame number, timestamp, 4-tuple, OS label, kernel version, OS family, session type, capture method, malformed flag, anomaly flag
 
OSNAME.csv format :
  Semicolon-separated with a named header row. Required columns:
    file_stem     : matches the prefix of the pcap filename
    os_family     : OS family string
    os_label      : ground-truth label for ML
    kernel_version: kernel version string
    mac_address   : Ethernet MAC of the OS under test (colon-separated)
 
Filename convention :
  <os_key>_<session_type>[_<capture_method>].pcap
 
  Examples:
    tails_active.pcap             -> active  / standard
    tails_active_unsafe_browser.pcap -> active  / unsafe_browser
    tails_passive_1h.pcap         -> passive / 1h
    tails_passive_30m.pcap        -> passive / 30m
    tails_passive_boot_cycle.pcap -> passive / boot_cycle
 
Output :
  Semicolon-separated CSV, one row per SYN packet. List-valued columns
  (tcp_options_order, tcp_nop_positions, tcp_unknown_options) are
  JSON-encoded to remain flat within the CSV structure.
"""

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s | %(message)s",
)
log = logging.getLogger(__name__)

# IANA-assigned TCP option kind integers.
# Reference: https://www.iana.org/assignments/tcp-parameters/
OPT_EOL       = 0   # End of Option List        -- no length, no data
OPT_NOP       = 1   # No-Operation (padding)    -- no length, no data
OPT_MSS       = 2   # Maximum Segment Size      -- length=4
OPT_WSCALE    = 3   # Window Scale              -- length=3
OPT_SACK_OK   = 4   # SACK Permitted            -- length=2
OPT_SACK      = 5   # Selective ACK data        -- variable
OPT_TIMESTAMP = 8   # Timestamps (TSval/TSecr)  -- length=10

# Full IANA TCP option kind registry -- used for logging and unknown option
# classification. Kinds not in this dict are truly unassigned/unknown.
KIND_NAMES: dict[int, str] = {
    0:   "EOL",
    1:   "NOP",
    2:   "MSS",
    3:   "WScale",
    4:   "SAckOK",
    5:   "SAck",
    6:   "Echo",                  # obsoleted by kind 8 (RFC1072/RFC6247)
    7:   "EchoReply",             # obsoleted by kind 8 (RFC1072/RFC6247)
    8:   "Timestamp",
    9:   "POCPermitted",          # obsolete (RFC1693/RFC6247)
    10:  "POCProfile",            # obsolete (RFC1693/RFC6247)
    11:  "CC",                    # obsolete (RFC1644/RFC6247)
    12:  "CC.NEW",                # obsolete (RFC1644/RFC6247)
    13:  "CC.ECHO",               # obsolete (RFC1644/RFC6247)
    14:  "AltChkSumReq",          # obsolete (RFC1146/RFC6247)
    15:  "AltChkSumData",         # obsolete (RFC1146/RFC6247)
    16:  "Skeeter",
    17:  "Bubba",
    18:  "TrailerChecksum",
    19:  "MD5",                   # obsoleted by kind 29 (RFC2385)
    20:  "SCPSCapabilities",
    21:  "SNACK",
    22:  "RecordBoundaries",
    23:  "CorruptionExperienced",
    24:  "SNAP",
    25:  "Unassigned25",
    26:  "TCPCompressionFilter",
    27:  "QuickStartResponse",
    28:  "UserTimeout",
    29:  "TCP-AO",               # TCP Authentication Option (RFC5925)
    30:  "MPTCP",                # Multipath TCP (RFC8684)
    31:  "Reserved31",
    32:  "Reserved32",
    33:  "Reserved33",
    34:  "TFO",                  # TCP Fast Open Cookie (RFC7413)
    69:  "TCP-ENO",              # Encryption Negotiation (RFC8547)
    70:  "Reserved70",
    76:  "Reserved76",
    77:  "Reserved77",
    78:  "Reserved78",
    172: "AccECN0",              # Accurate ECN Order 0
    174: "AccECN1",              # Accurate ECN Order 1
    253: "Experimental1",        # RFC3692-style Experiment 1 (RFC4727)
    254: "Experimental2",        # RFC3692-style Experiment 2 (RFC4727)
}


OUTPUT_COLUMNS: list[str] = [
    # Provenance / metadata
    "pcap_filename",         # Source .pcap filename (basename only)
    "frame_number",          # packet index within the capture file
    "timestamp",             # Packet capture timestamp (float, Unix epoch)
    "src_ip",                # Source IP of the OS under test
    "dst_ip",                # Destination IP
    "src_port",              # Source TCP port
    "dst_port",              # Destination TCP port
    "seq_num",               # TCP initial sequence number (ISN)
    "os_label",              # Ground-truth OS label (from OSNAME.csv)
    "kernel_version",        # Kernel version string (from OSNAME.csv)
    "os_family",             # OS family (from OSNAME.csv)
    "session_type",          # 'active' or 'passive' (derived from filename)
    "capture_method",        # Duration string, boot_cycle, standard, or unsafe_browser

    # IP layer
    "ip_ttl",                # Raw initial TTL (no hops consumed -- captured at VM adapter)
    "ip_df",                 # Don't-Fragment flag: 1 = set, 0 = not set
    "ip_mf",                 # More-Fragments flag: should always be 0 for SYN
    "ip_fragment_offset",    # Fragment offset (bytes): should always be 0 for SYN

    # CONTEXTUAL NOTE -- ip_total_length:
    #   Meaningful for SYN packets specifically because payload is always empty.
    #   NOT a stable signal in other packet types where payload dominates length.
    "ip_total_length",

    # ip_dscp -- Differentiated Services Code Point (upper 6 bits of TOS byte).
    "ip_dscp",

    # ip_ecn_bits -- IP-layer ECN capability (lower 2 bits of TOS byte).
    # DISTINCT from TCP-layer ECE/CWR flags below.
    "ip_ecn_bits",

    # TCP ECN flags (transport layer NOT the IP ECN bits above)
    "tcp_flag_cwr",          # Congestion Window Reduced (TCP flags bit 7)
    "tcp_flag_ece",          # ECN-Echo (TCP flags bit 6)

    # TCP layer
    "tcp_window_size",       # Advertised receive window size (raw, before scaling)
    "tcp_mss",               # MSS value from options (None if absent)
    "tcp_window_scale",      # Window scale factor from options (None if absent)
    "tcp_sack_permitted",    # True if SAckOK option (kind 4) is present
    "tcp_timestamp_present", # True if Timestamps option (kind 8) is present

    # tcp_tsecr_nonzero -- RFC 7323 s3.2 mandates TSecr = 0 in a SYN.
    # True indicates a non-standards-compliant stack (fingerprinting signal).
    # TSval is discarded -- reflects uptime/clock granularity, not OS identity.
    "tcp_tsecr_nonzero",

    # TCP options structure
    # Exact wire order preserved -- do NOT sort or normalise.
    # JSON-encoded to remain flat within the semicolon-separated CSV.
    "tcp_options_order",     # Kind integers in wire order e.g. [2, 4, 8, 1, 3]
    "tcp_nop_positions",     # 0-based indices of NOPs in tcp_options_order e.g. [3]
    "tcp_unknown_options",

    # Data quality flags
    "malformed",             # True if any TCP option caused a parse error
    "anomaly",               # True if TTL not in {64, 128, 255} or fragmentation present
]



def load_os_metadata(csv_path: str) -> dict[str, dict]:
    """
    Load OS metadata from OSNAME.csv.

    The CSV is semicolon-separated with a named header row. The file_stem
    column matches the first component of the pcap filename
    (e.g. 'tails' for tails_active.pcap).

    Returns
    -------
    dict mapping file_stem (lowercase str) -> {
        'os_family':       str,
        'os_label':        str,
        'kernel_version':  str,
        'mac_address':     str,  # colon-separated lowercase e.g. '08:00:27:87:10:f7'
    }
    """
    metadata: dict[str, dict] = {}
    path = Path(csv_path)

    if not path.exists():
        log.error(f"OSNAME.csv not found: {path}")
        sys.exit(1)

    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter=";")
        for row_idx, row in enumerate(reader):
            file_stem = row.get("file_stem", "").strip().lower()
            if not file_stem:
                log.warning(f"OSNAME.csv row {row_idx + 2}: empty file_stem - skipping")
                continue

            mac = row.get("mac_address", "").strip().lower()
            if not mac:
                log.warning(f"OSNAME.csv row {row_idx + 2}: missing mac_address for '{file_stem}'")

            metadata[file_stem] = {
                "os_family":      row.get("os_family", "").strip(),
                "os_label":       row.get("os_label", "").strip(),
                "kernel_version": row.get("kernel_version", "").strip(),
                "mac_address":    mac,
            }

    log.info(f"Loaded metadata for {len(metadata)} OS entries from {path.name}")
    return metadata


def collect_pcap_files(input_path: str) -> list[Path]:
    """
    Collect pcap/pcapng files from a single file path or a directory.

    Returns
    -------
    Sorted list of Path objects for each file to process.
    """
    path = Path(input_path)

    if path.is_file():
        if path.suffix not in (".pcap", ".pcapng"):
            log.warning(f"Input file '{path.name}' does not have a .pcap or .pcapng extension - proceeding anyway")
        return [path]

    if path.is_dir():
        files = sorted(list(path.glob("*.pcap")) + list(path.glob("*.pcapng")))
        if not files:
            log.error(f"No .pcap or .pcapng files found in {path}")
            sys.exit(1)
        log.info(f"Found {len(files)} file(s) in {path}")
        return files

    log.error(f"Input path does not exist: {path}")
    sys.exit(1)


def run_tshark(pcap_path: Path, mac_address: str, temp_dir: Path) -> Path | None:
    """
    Run tshark on a single pcap file, filtering to TCP SYN packets
    originating from the OS under test (identified by MAC address),
    and writing selected fields to a temporary CSV file.

    Output is written to a tempfile on disk rather than captured in memory
    because active-traffic captures may produce large outputs.

    Parameters
    ----------
    pcap_path   : path to the input .pcap / .pcapng file
    mac_address : Ethernet source MAC of the OS under test (from OSNAME.csv)
    temp_dir    : directory where the temporary tshark CSV will be written

    Returns
    -------
    Path to the tshark output CSV, or None if tshark failed.
    """
    temp_out = temp_dir / f"{pcap_path.stem}_tshark.csv"

    # Filter: Ethernet source matches the OS MAC, SYN set, ACK not set.
    # Using eth.src rather than ip.src avoids any dependency on DHCP
    # and correctly handles the case where the IP is not yet known.
    # Only display IPv4 packets
    display_filter = (
        f"ip and "
        f"eth.src == {mac_address} and "
        f"tcp.flags.syn == 1 and "
        f"tcp.flags.ack == 0"
    )

    # Fields exported by tshark, in output column order.
    # tcp.options is the raw hex blob parsed in Phase 2.
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.seq_raw",
        "ip.ttl",
        "ip.flags.df",
        "ip.flags.mf",
        "ip.frag_offset",
        "ip.len",
        "ip.dsfield.dscp",
        "ip.dsfield.ecn",
        "tcp.flags.cwr",
        "tcp.flags.ece",
        "tcp.window_size_value",
        "tcp.options",
    ]

    cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-Y", f"({display_filter})",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=;",
        "-E", "quote=d",        # double-quote all fields (handles commas in hex blobs)
        "-E", "occurrence=f",   # take first occurrence if field appears multiple times
    ]
    for field in fields:
        cmd += ["-e", field]

    log.info(f"  Running tshark on {pcap_path.name} ...")
    log.debug(f"  Command: {' '.join(cmd)}")

    try:
        with open(temp_out, "w") as out_fh:
            result = subprocess.run(
                cmd,
                stdout=out_fh,
                stderr=subprocess.PIPE,
                text=True,
            )

        if result.returncode != 0:
            log.error(
                f"  tshark exited with code {result.returncode} "
                f"for {pcap_path.name}:\n{result.stderr.strip()}"
            )
            return None

        if result.stderr.strip():
            # tshark often emits non-fatal warnings on stderr even on success
            log.debug(f"  tshark stderr: {result.stderr.strip()}")

        return temp_out

    except FileNotFoundError:
        log.error("  tshark not found - ensure it is installed and on PATH")
        sys.exit(1)
    except Exception as exc:
        log.error(f"  Unexpected error running tshark on {pcap_path.name}: {exc}")
        return None
    

def parse_bool(value: str) -> bool:
    """Convert tshark boolean string ('True'/'False') to Python bool."""
    return value.strip().lower() == "true"


def parse_session_info(stem: str) -> tuple[str, str]:
    """
    Derive session_type and capture_method from the pcap filename stem.

    Examples:
        tails_passive_1h         -> ('passive', '1h')
        tails_passive_30m        -> ('passive', '30m')
        tails_passive_boot_cycle     -> ('passive', 'boot_cycle')
        tails_active             -> ('active', 'standard')
        tails_active_unsafe_browser  -> ('active', 'unsafe_browser')
    """
    parts = stem.split("_")
    # Find the index of 'active' or 'passive' token
    for i, part in enumerate(parts):
        if part in ("active", "passive"):
            session_type   = part
            suffix_parts   = parts[i + 1:]
            capture_method = "_".join(suffix_parts) if suffix_parts else "standard"
            return session_type, capture_method

    log.warning(f"Could not determine session type from filename stem '{stem}' - defaulting to passive/unknown")
    return "passive", "unknown"
    

def parse_options_row(raw_hex: str) -> dict:
    """
    Parse the tcp.options hex string exported by tshark into structured fields
    by passing the raw bytes to the existing parse_tcp_options() function.

    Parameters
    ----------
    raw_hex : the tcp.options field value from the tshark CSV row, may be empty if the packet has no TCP options.

    Returns
    -------
    dict from parse_tcp_options(), with keys:
        options_order, nop_positions, mss, window_scale, sack_permitted,
        ts_present, tsecr_nonzero, unknown_options, malformed
    """
    if not raw_hex or not raw_hex.strip():
        # No options present - return clean defaults from parse_tcp_options
        return parse_tcp_options(b"")

    try:
        clean_hex = raw_hex.strip()
        opts_bytes = bytes.fromhex(clean_hex)
    except ValueError as exc:
        log.warning(f"  Could not decode tcp.options hex '{raw_hex}': {exc}")
        return {
            "options_order":   json.dumps([]),
            "nop_positions":   json.dumps([]),
            "mss":             None,
            "window_scale":    None,
            "sack_permitted":  False,
            "ts_present":      False,
            "tsecr_nonzero":   False,
            "unknown_options": json.dumps([]),
            "malformed":       True,  # Flag packet as Malformed
        }

    opts = parse_tcp_options(opts_bytes)

    # JSON-encode list fields here so the caller receives a flat dict
    # ready for direct CSV writing - no further transformation needed.
    return {
        "options_order":   json.dumps(opts["options_order"]),
        "nop_positions":   json.dumps(opts["nop_positions"]),
        "mss":             opts["mss"],
        "window_scale":    opts["window_scale"],
        "sack_permitted":  opts["sack_permitted"],
        "ts_present":      opts["ts_present"],
        "tsecr_nonzero":   opts["tsecr_nonzero"],
        "unknown_options": json.dumps(opts["unknown_options"]),
        "malformed":       opts["malformed"],
    }


def parse_tcp_options(opts_bytes: bytes) -> dict:
    """
    Parse raw TCP options bytes into structured fields.

    TCP options are encoded as a sequence of Type-Length-Value (TLV) triplets,
    with two single-byte special cases:
      - Kind 0 (EOL): single byte, terminates the option list
      - Kind 1 (NOP): single byte, padding only, no length or data

    All other options have the form:
      [kind: 1 byte] [length: 1 byte] [data: (length - 2) bytes]
    where 'length' counts the kind and length bytes themselves, so the
    minimum valid length is 2. Data length = length - 2.
    Reference: https://www.iana.org/assignments/tcp-parameters/

    Wire-order preservation
    -----------------------
    We iterate the raw bytes sequentially and append each discovered kind to
    options_order before parsing its value. This preserves the exact wire
    order, including NOP positions which is an OS fingerprinting signal.
    Do NOT sort or deduplicate options_order.

    NOP handling
    ------------
    NOP bytes (kind=1) are recorded in options_order (for full sequence
    preservation) and also in nop_positions (their 0-based indices in
    options_order), allowing callers to reconstruct the NOP padding pattern.

    Timestamp handling
    ------------------
    TSval reflects uptime and clock granularityand is discarded.
    TSecr MUST be zero in a SYN (RFC 7323). A non-zero value
    indicates a non-standards-compliant stack and is stored as a boolean
    anomaly flag (tsecr_nonzero) rather than the raw value.

    Unknown options
    ---------------
    Any kind not present in KIND_NAMES is appended to unknown_options with
    its kind number and full TLV byte length. Raw data is not stored (by
    design decision), but kind+length may itself be a fingerprint signal.

    Malformed handling
    ------------------
    'Malformed' means the length field is absent, < 2, or would read past
    the end of the buffer. We set malformed=True and stop parsing further
    options, preserving whatever was successfully parsed up to that point.

    Parameters
    ----------
    opts_bytes : raw TCP options bytes (everything after the 20-byte fixed header)

    Returns
    -------
    dict with keys:
        options_order    list[int]   -- kind integers in wire order (NOPs included)
        nop_positions    list[int]   -- 0-based indices of NOPs in options_order
        mss              int | None
        window_scale     int | None
        sack_permitted   bool
        ts_present       bool
        tsecr_nonzero    bool        -- True if TSecr != 0 (RFC 7323 violation)
        unknown_options  list[dict]  -- [{"kind": int, "length": int}, ...]
        malformed        bool        -- True if a parse error was encountered
    """
    result: dict = {
        "options_order":   [],
        "nop_positions":   [],
        "mss":             None,
        "window_scale":    None,
        "sack_permitted":  False,
        "ts_present":      False,
        "tsecr_nonzero":   False,
        "unknown_options": [],
        "malformed":       False,
    }

    i   = 0        # byte cursor into opts_bytes
    n   = len(opts_bytes)
    idx = 0        # position counter into options_order (for nop_positions)

    while i < n:
        kind = opts_bytes[i]
        i += 1

        # Single-byte options (no length field)
        if kind == OPT_EOL:
            # End of Option List -- stop processing; remainder is zero padding.
            result["options_order"].append(kind)
            break

        if kind == OPT_NOP:
            # No-Operation -- single padding byte, no data.
            result["options_order"].append(kind)
            result["nop_positions"].append(idx)
            idx += 1
            continue

        # Multi-byte TLV options
        # The next byte is the 'length' field, covering kind + length + data.
        # Minimum valid length is 2 (kind byte + length byte, no data).
        if i >= n:
            log.warning(
                f"    Options parser: kind={kind} ({KIND_NAMES.get(kind, 'unknown')}) "
                f"at position {i-1} has no length byte (buffer truncated)"
            )
            result["malformed"] = True
            break

        length = opts_bytes[i]
        i += 1

        if length < 2:
            # Length < 2 is impossible (kind + length alone = 2 bytes).
            log.warning(
                f"    Options parser: kind={kind} ({KIND_NAMES.get(kind, 'unknown')}) "
                f"has invalid length={length} (must be >= 2)"
            )
            result["malformed"] = True
            break

        data_len = length - 2     # bytes of actual option payload
        data_end = i + data_len

        if data_end > n:
            # The length field claims more bytes than remain in the buffer.
            log.warning(
                f"    Options parser: kind={kind} ({KIND_NAMES.get(kind, 'unknown')}) "
                f"length={length} would read to byte {data_end} "
                f"but buffer ends at {n} (truncated)"
            )
            result["malformed"] = True
            # Append kind to options_order anyway
            result["options_order"].append(kind)
            idx += 1
            break

        data = opts_bytes[i:data_end]
        i    = data_end

        # Append to order list BEFORE value parsing so the position is
        # preserved even if the value parse below raises an exception.
        result["options_order"].append(kind)

        # Kind-specific value extraction
        try:
            if kind == OPT_MSS:
                # MSS -- 2 bytes of payload, big-endian uint16.
                if len(data) >= 2:
                    result["mss"] = struct.unpack("!H", data[:2])[0]
                else:
                    log.warning(f"    Options parser: MSS (kind=2) data too short ({len(data)} bytes)")
                    result["malformed"] = True

            elif kind == OPT_WSCALE:
                # Window Scale -- 1 byte of payload (shift count, valid range 0-14).
                if len(data) >= 1:
                    result["window_scale"] = data[0]
                else:
                    log.warning(f"    Options parser: WScale (kind=3) data too short")
                    result["malformed"] = True

            elif kind == OPT_SACK_OK:
                # SACK Permitted -- presence is the signal, no data bytes.
                result["sack_permitted"] = True

            elif kind == OPT_SACK:
                # SACK data -- not expected in a SYN, handle gracefully.
                pass

            elif kind == OPT_TIMESTAMP:
                # Timestamps -- 8 bytes: TSval + TSecr.
                # TSval reflects uptime/clock granularity -- discarded.
                # TSecr MUST be zero in a SYN.
                if len(data) >= 8:
                    _tsval, tsecr        = struct.unpack("!II", data[:8])
                    result["ts_present"]     = True
                    result["tsecr_nonzero"]  = (tsecr != 0)
                else:
                    log.warning(f"    Options parser: Timestamp (kind=8) data too short ({len(data)} bytes)")
                    result["malformed"] = True

            elif kind not in KIND_NAMES:
                # Unknown / unrecognised option kind.
                # Store kind and full TLV length; raw payload omitted by design.
                result["unknown_options"].append({
                    "kind":   kind,
                    "length": length,
                })

            # Known but unhandled kinds (Echo, MD5, MPTCP, etc.) fall through
            # silently -- they appear in options_order, which is sufficient.

        except struct.error as exc:
            log.warning(
                f"    Options parser: kind={kind} ({KIND_NAMES.get(kind, 'unknown')}) "
                f"struct.unpack failed: {exc}"
            )
            result["malformed"] = True

        idx += 1

    return result


def enrich_and_filter(tshark_csv: Path, pcap_path: Path, meta: dict) -> tuple[list[dict], dict]:
    """
    Read the tshark CSV output, parse TCP options, attach metadata,
    and compute the anomaly flag.

    Retransmitted SYNs are kept in the dataset.

    Parameters
    ----------
    tshark_csv : path to the temp CSV produced by run_tshark()
    pcap_path  : original pcap path (used for pcap_filename column)
    meta       : metadata dict for this OS from load_os_metadata()

    Returns
    -------
    (rows, stats) where rows is a list of dicts ready for CSV output.
    """
    stats = {
        "total_packets":     0,
        "syn_packets":       0,
        "malformed_skipped": 0,
    }

    session_type, capture_method = parse_session_info(pcap_path.stem)
    rows: list[dict] = []

    with open(tshark_csv, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter=";")
        for row in reader:
            stats["total_packets"] += 1

            # Parse TCP options from hex blob
            opts = parse_options_row(row["tcp.options"])

            # Malformed
            if opts["malformed"]:
                stats["malformed_skipped"] += 1
                log.debug(f"    Frame {row['frame.number']}: malformed TCP options - skipping")
                continue

            # IP flags
            ip_df          = 1 if parse_bool(row["ip.flags.df"]) else 0
            ip_mf          = 1 if parse_bool(row["ip.flags.mf"]) else 0
            ip_frag_offset = int(row["ip.frag_offset"])

            # TCP flags
            tcp_flag_cwr   = 1 if parse_bool(row["tcp.flags.cwr"]) else 0
            tcp_flag_ece   = 1 if parse_bool(row["tcp.flags.ece"]) else 0

            # Anomaly flag
            # Anomalous if: fragmentation present (unexpected for SYN) or TTL
            # is not one of the three standard initial values used by known OSs:
            #   64, 128, 255
            ttl     = int(row["ip.ttl"])
            anomaly = bool(ip_mf or ip_frag_offset != 0 or ttl not in (64, 128, 255))
            if anomaly:
                log.warning(
                    f"    Frame {row['frame.number']}: anomaly detected "
                    f"(MF={ip_mf}, offset={ip_frag_offset}, TTL={ttl})"
                )

            # Assemble output row
            output_row = {
                "pcap_filename":         pcap_path.name,
                "frame_number":          int(row["frame.number"]),
                "timestamp":             row["frame.time_epoch"],
                "src_ip":                row["ip.src"],
                "dst_ip":                row["ip.dst"],
                "src_port":              row["tcp.srcport"],
                "dst_port":              row["tcp.dstport"],
                "seq_num":               row["tcp.seq_raw"],
                "os_label":              meta["os_label"],
                "kernel_version":        meta["kernel_version"],
                "os_family":             meta["os_family"],
                "session_type":          session_type,
                "capture_method":        capture_method,
                # IP layer
                "ip_ttl":                ttl,
                "ip_df":                 ip_df,
                "ip_mf":                 ip_mf,
                "ip_fragment_offset":    ip_frag_offset,
                "ip_total_length":       int(row["ip.len"]),
                "ip_dscp":               int(row["ip.dsfield.dscp"]),
                "ip_ecn_bits":           int(row["ip.dsfield.ecn"]),
                # TCP ECN flags
                "tcp_flag_cwr":          tcp_flag_cwr,
                "tcp_flag_ece":          tcp_flag_ece,
                # TCP layer
                "tcp_window_size":       int(row["tcp.window_size_value"]),
                "tcp_mss":               opts["mss"],
                "tcp_window_scale":      opts["window_scale"],
                "tcp_sack_permitted":    opts["sack_permitted"],
                "tcp_timestamp_present": opts["ts_present"],
                "tcp_tsecr_nonzero":     opts["tsecr_nonzero"],
                # TCP options structure
                "tcp_options_order":     opts["options_order"],
                "tcp_nop_positions":     opts["nop_positions"],
                "tcp_unknown_options":   opts["unknown_options"],
                # Quality flags
                "malformed":             opts["malformed"],
                "anomaly":               anomaly,
            }

            stats["syn_packets"] += 1
            rows.append(output_row)

    log.info(
        f"  -> {stats['syn_packets']} SYNs extracted | "
        f"{stats['malformed_skipped']} malformed skipped"
    )
    return rows, stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract TCP/IP SYN packet features for passive OS fingerprinting. "
            "Uses tshark for packet filtering and field extraction, with a "
            "Python post-processing step for TCP options parsing."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", required=True, metavar="PATH",
        help="Path to a single .pcap/.pcapng file, or a directory of such files",
    )
    parser.add_argument(
        "--osname", required=True, metavar="CSV",
        help="Path to OSNAME.csv (semicolon-separated, with header row)",
    )
    parser.add_argument(
        "--output", required=True, metavar="CSV",
        help="Output CSV file path (semicolon-separated)",
    )
    parser.add_argument(
        "--keep-temp", action="store_true",
        help="Keep tshark intermediate CSV files after processing (useful for debugging)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG-level logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load OS metadata
    os_metadata = load_os_metadata(args.osname)

    # Collect pcap files
    pcap_files = collect_pcap_files(args.input)

    # Prepare output CSV
    # File is opened once and written to incrementally as each pcap is processed.
    # This ensures partial results are preserved if the run crashes midway.
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_fh = open(output_path, "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(
        output_fh,
        fieldnames   = OUTPUT_COLUMNS,
        delimiter    = ";",
        extrasaction = "ignore",
    )
    writer.writeheader()

    # Prepare temp directory
    temp_dir = Path(tempfile.mkdtemp(prefix="syn_extractor_"))
    log.debug(f"Temp directory: {temp_dir}")

    # Global counters
    global_stats = {
        "files_processed":   0,
        "files_skipped":     0,
        "total_packets":     0,
        "syn_packets":       0,
        "malformed_skipped": 0,
    }

    # Process each file
    try:
        for pcap_path in pcap_files:

            # Look up OS metadata by filename stem prefix
            os_key = pcap_path.stem.split("_")[0].lower()
            meta   = os_metadata.get(os_key)
            if not meta:
                log.error(
                    f"No metadata found for OS key '{os_key}' "
                    f"(derived from {pcap_path.name}) - skipping file"
                )
                global_stats["files_skipped"] += 1
                continue

            # Phase 1 - tshark extraction
            tshark_csv = run_tshark(pcap_path, meta["mac_address"], temp_dir)
            if tshark_csv is None:
                log.error(f"tshark failed for {pcap_path.name} - skipping file")
                global_stats["files_skipped"] += 1
                continue

            # Phase 2+3 - options parsing, enrichment, anomaly detection
            rows, stats = enrich_and_filter(tshark_csv, pcap_path, meta)

            # Write rows immediately to output CSV
            writer.writerows(rows)
            output_fh.flush()

            # Accumulate global stats
            global_stats["files_processed"]    += 1
            global_stats["total_packets"]      += stats["total_packets"]
            global_stats["syn_packets"]        += stats["syn_packets"]
            global_stats["malformed_skipped"]  += stats["malformed_skipped"]

            # Clean up temp file unless --keep-temp
            if not args.keep_temp:
                tshark_csv.unlink(missing_ok=True)
            else:
                log.debug(f"  Kept temp file: {tshark_csv}")

    finally:
        output_fh.close()
        # Remove temp directory if empty
        if not args.keep_temp:
            try:
                temp_dir.rmdir()
            except OSError:
                pass  # not empty - leave it, user passed --keep-temp or a crash occurred

    # Completion summary
    print()
    print("=" * 60)
    print("  EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"  Files processed     : {global_stats['files_processed']}")
    print(f"  Files skipped       : {global_stats['files_skipped']}")
    print(f"  Total packets seen  : {global_stats['total_packets']}")
    print(f"  SYN packets written : {global_stats['syn_packets']}")
    print(f"  Malformed skipped   : {global_stats['malformed_skipped']}")
    print(f"  Output file         : {output_path}")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
