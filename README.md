# Passive TCP/IP Fingerprinting of Tails OS

Dataset construction, empirical evaluation, and identifiability assessment for passive TCP/IP OS fingerprinting, with a focus on whether Tails OS is identifiable by a passive local network observer.

This repository accompanies a master's thesis and contains the full dataset, traffic generation configs, feature extraction scripts, and machine learning evaluation pipeline needed to reproduce all results reported in the thesis.

> **Notable finding:** A TCP/IP fingerprinting vector was identified in
> Tails' Unsafe Browser (TTL=63 artefact), responsibly disclosed to the
> Tails team, and patched in **Tails 7.8.1**.
> See [tails/tails#21617](https://gitlab.tails.boum.org/tails/tails/-/work_items/21617).

## Repository Structure
### `datasets/`

Three versions of the same underlying capture are provided, corresponding to the two evaluation streams used in the thesis (see thesis Section on TTL Adjustment):

| File | Description |
|---|---|
| `dataset.csv` | Unmodified output of the extraction pipeline. No corrections applied. |
| `dataset_adjusted.csv` | TTL values of 63 corrected to 64 for Tails Unsafe Browser rows. Used for the core stack-identifiability evaluation. |
| `dataset_asobserved.csv` | Raw TTL values retained, but the `anomaly` flag for affected Tails rows is set to `False` so these rows are not filtered out during preprocessing. Used to document the practical fingerprinting threat. |

All datasets are semicolon-delimited CSV files. Column definitions and the full feature schema are documented in the thesis.

### `generation/`

Scripts and configurations used to generate idle and active network traffic across all 60 OS instances.

### `extraction/`

`pcap_extractor.py` and the companion `OSNAME.csv` metadata file. Converts raw `.pcap` captures into the structured feature CSV using a hybrid `tshark` + Python pipeline. See the script's module docstring for full usage instructions.

### `python/`

The classifier evaluation pipeline: partition construction, feature encoding, cross-validation, P0f baseline evaluation, feature importance analysis, and result/plot generation.

---

## Setup

This project uses [`pipenv`](https://pipenv.pypa.io/) for dependency management. All dependency versions are pinned in `requirements.txt`.

Feature extraction additionally requires `tshark` (Wireshark) to be installed and available on your `PATH`.

P0f baseline evaluation requires [P0f](https://lcamtuf.coredump.cx/p0f3/) v3.09b or later, invoked separately from the Python pipeline.

---

## Usage

Please refer to the script help for information.
---

## Citation

If you use this dataset, code, or findings, please cite the thesis:

```bibtex
@mastersthesis{TODO_citation_key,
  title  = {Passive TCP/IP Fingerprinting},
  author = {E Deroubaix},
  school = {ULB},
  year   = {2026},
  note   = {TO BE UPDATED once thesis is published in the university repository}
}
```

*[Citation details will be updated once the thesis is published on the university library website.]*

---

## License

This work is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
You are free to share and adapt the dataset and code for any purpose, including commercially, as long as you give appropriate credit.

---

## Responsible Disclosure

The TTL-63 fingerprinting artefact described in this work was disclosed to the Tails security team prior to public release, in coordination with their release schedule. 
The issue was patched in [Commit#2e1f092a](https://gitlab.tails.boum.org/tails/tails/-/commit/2e1f092a99d46d739183a31e51978fe6d23d4d28) in Tails 7.8.1. Full details are in the thesis and in the public GitLab issue: [tails/tails#21617](https://gitlab.tails.boum.org/tails/tails/-/work_items/21617).
