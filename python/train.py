import ast
from pathlib import Path
import re

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import OneHotEncoder

from collections import defaultdict

from plotter import plot_confusion_matrix, plot_feature_importance, save_confusion_matrix_csv, save_metrics_csv, plot_p0f_distribution

FEATURE_COLUMNS = [
    "ip_ttl", "ip_df", "ip_mf", "ip_fragment_offset",
    "ip_dscp", "ip_ecn_bits",
    "tcp_flag_cwr", "tcp_flag_ece",
    "tcp_window_size", "tcp_mss", "tcp_window_scale",
    "tcp_sack_permitted", "tcp_timestamp_present", "tcp_tsecr_nonzero",
    "tcp_options_order",
]

SCALAR_COLUMNS = [c for c in FEATURE_COLUMNS if c != "tcp_options_order"]

def make_feature_names(meta):
    # Makes Positional features human readable
    # Scalar features keep their column names as-is
    names = list(SCALAR_COLUMNS)

    # Positional columns: one block per position, one column per category
    # Categories are sorted([0] + vocab) where 0 is the absent sentinel
    categories = sorted([0] + meta["options_vocab"])
    for pos in range(meta["options_max_len"]):
        for kind in categories:
            if kind == 0:
                names.append(f"opt_pos{pos}_absent")
            else:
                names.append(f"opt_pos{pos}_kind{kind}")

    return names

def _extract_gini(partition, meta):
    df     = partition["df"].reset_index(drop=True)
    target = partition["target"].reset_index(drop=True)

    # Train on the full partition - Gini importance is a model property,
    # not a fold metric, so we fit once on everything just for this purpose
    X, _ = encode_features(df, df, meta)
    model = RandomForestClassifier(
        n_estimators=100, max_features="sqrt",
        class_weight="balanced", random_state=42,
    )
    model.fit(X, target)
    return model.feature_importances_


def load_and_filter(path):
    df = pd.read_csv(path, sep=";")

    # Drop rows with quality issues - malformed packets or fragmentation anomalies
    before = len(df)
    df = df[~df["malformed"] & ~df["anomaly"]].reset_index(drop=True)
    after = len(df)

    if before != after:
        print(f"Dropped {before - after} rows due to malformed/anomaly flags.")
    else:
        print(f"No rows dropped. Dataset has {after} rows.")

    return df


def build_partitions(df):
    # Derive Tails identity from data
    tails_label  = df[df["os_label"].str.lower().str.contains("tails")]["os_label"].iloc[0]
    tails_kernel = df[df["os_label"] == tails_label]["kernel_version"].iloc[0]
    print(f"Tails label: '{tails_label}'  |  kernel: '{tails_kernel}'")

    # Kernel clusters: kernel_version shared by more than one distinct os_label
    kernel_groups   = df.groupby("kernel_version")["os_label"].nunique()
    cluster_kernels = kernel_groups[kernel_groups > 1].index.tolist()
    print(f"Kernel clusters found: {len(cluster_kernels)}  (including Tails cluster)")

    # Global options vocabulary - computed once on the full dataset
    all_sequences   = df["tcp_options_order"].apply(ast.literal_eval)
    options_max_len = all_sequences.apply(len).max()
    options_vocab   = sorted(set(code for seq in all_sequences for code in seq))
    print(f"Options: max sequence length={options_max_len}, vocab={options_vocab}")

    # Masks for the main partitions
    linux_mask  = df["kernel_version"].str.lower().str.startswith("linux ")
    debian_mask = df["os_family"].str.lower() == "debian"
    tails_cluster_mask = df["kernel_version"] == tails_kernel

    # Secondary clusters: all kernel clusters except the Tails one
    secondary_cluster_kernels = [k for k in cluster_kernels if k != tails_kernel]
    secondary_clusters = {
        kernel: {
            "df":     df[df["kernel_version"] == kernel],
            "target": df[df["kernel_version"] == kernel]["os_label"],
        }
        for kernel in secondary_cluster_kernels
    }

    tails_cluster_members = df[tails_cluster_mask]["os_label"].unique().tolist()
    print(f"Tails cluster members: {tails_cluster_members}")
    print(f"Secondary clusters: {len(secondary_cluster_kernels)}")

    return {
        "full": {
            "df":     df,
            "target": df["os_label"],
        },
        "full_family": {
            "df":     df,
            "target": df["kernel_version"].str.startswith("Linux ").map({True: "Linux", False: "non-Linux"}),
        },
        "linux_only": {
            "df":     df[linux_mask],
            "target": df[linux_mask]["os_label"],
        },
        "debian_only": {
            "df":     df[debian_mask],
            "target": df[debian_mask]["os_label"],
        },
        "tails_cluster": {
            "df":     df[tails_cluster_mask],
            "target": df[tails_cluster_mask]["os_label"],
        },
        "secondary_clusters": secondary_clusters,
        "meta": {
            "tails_label":           tails_label,
            "tails_kernel":          tails_kernel,
            "tails_cluster_members": tails_cluster_members,
            "options_max_len":       options_max_len,
            "options_vocab":         options_vocab,
        },
    }


def encode_options(train_series, test_series, max_len, vocab):
    # Parse the string lists into actual lists
    train_lists = train_series.apply(ast.literal_eval)
    test_lists  = test_series.apply(ast.literal_eval)

    # Pad or truncate each sequence to max_len, using 0 for absent positions
    def to_fixed_array(lists):
        result = np.zeros((len(lists), max_len), dtype=int)
        for i, seq in enumerate(lists):
            for j, code in enumerate(seq[:max_len]):
                result[i, j] = code
        return result

    train_arr = to_fixed_array(train_lists)
    test_arr  = to_fixed_array(test_lists)

    # One-hot encode each position independently
    # categories: vocab + [0] for absent, handle_unknown="ignore" for safety
    categories = [sorted(vocab + [0])] * max_len
    enc = OneHotEncoder(categories=categories, sparse_output=False, handle_unknown="ignore")

    train_encoded = enc.fit_transform(train_arr)
    test_encoded  = enc.transform(test_arr)

    return train_encoded, test_encoded


def encode_features(X_train, X_test, meta):
    # Encode the options sequence positionally
    train_options, test_options = encode_options(
        X_train["tcp_options_order"],
        X_test["tcp_options_order"],
        meta["options_max_len"],
        meta["options_vocab"],
    )

    # Scalar features need no encoding - just convert to numpy
    train_scalars = X_train[SCALAR_COLUMNS].to_numpy()
    test_scalars  = X_test[SCALAR_COLUMNS].to_numpy()

    # Concatenate scalar and encoded options into final feature matrices
    X_train_enc = np.hstack([train_scalars, train_options])
    X_test_enc  = np.hstack([test_scalars,  test_options])

    return X_train_enc, X_test_enc


def evaluate_fold(model, X_test, y_test, tails_label=None):
    y_pred = model.predict(X_test)

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm     = confusion_matrix(y_test, y_pred, labels=model.classes_)

    result = {
        "accuracy":         accuracy_score(y_test, y_pred),
        "macro_f1":         report["macro avg"]["f1-score"],
        "report":           report,
        "confusion_matrix": cm,
    }

    # Tails-specific F1 - only when Tails is one of the classes
    if tails_label is not None and tails_label in report:
        result["tails_f1"] = report[tails_label]["f1-score"]

    return result


def cross_validate_partition(partition, model, meta, tails_label=None, n_folds=10, compute_permutation=True):
    df     = partition["df"].reset_index(drop=True)
    target = partition["target"].reset_index(drop=True)

    skf              = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    results          = []
    cm_sum           = None
    perm_importances = []

    for _, (train_idx, test_idx) in enumerate(skf.split(df, target)):
        X_train_raw, X_test_raw = df.iloc[train_idx], df.iloc[test_idx]
        y_train,     y_test     = target.iloc[train_idx], target.iloc[test_idx]

        X_train, X_test = encode_features(X_train_raw, X_test_raw, meta)

        model.fit(X_train, y_train)
        fold_result = evaluate_fold(model, X_test, y_test, tails_label)
        results.append(fold_result)

        cm_sum = fold_result["confusion_matrix"] if cm_sum is None else cm_sum + fold_result["confusion_matrix"]

        if compute_permutation:
            perm = permutation_importance(
                model, X_test, y_test,
                scoring="f1_macro",
                n_repeats=5,
                random_state=42,
            )
            perm_importances.append(perm.importances_mean)

    accuracies = [r["accuracy"] for r in results]
    macro_f1s  = [r["macro_f1"]  for r in results]

    aggregated = {
        "accuracy_mean":    np.mean(accuracies),
        "accuracy_std":     np.std(accuracies),
        "macro_f1_mean":    np.mean(macro_f1s),
        "macro_f1_std":     np.std(macro_f1s),
        "confusion_matrix": cm_sum,
        "fold_results":     results,
        "classes":          model.classes_,
    }

    if compute_permutation:
        aggregated["perm_importance_mean"] = np.mean(perm_importances, axis=0)
        aggregated["perm_importance_std"]  = np.std(perm_importances,  axis=0)

    if tails_label is not None:
        tails_f1s = [r["tails_f1"] for r in results if "tails_f1" in r]
        aggregated["tails_f1_mean"] = np.mean(tails_f1s)
        aggregated["tails_f1_std"]  = np.std(tails_f1s)

    return aggregated


def make_classifiers():
    return {
        "rf": RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            max_features="sqrt",
            class_weight="balanced",
            random_state=42,
        ),
        "knn_1":  KNeighborsClassifier(n_neighbors=1,  weights="distance", metric="euclidean"),
        "knn_5":  KNeighborsClassifier(n_neighbors=5,  weights="distance", metric="euclidean"),
        "knn_11": KNeighborsClassifier(n_neighbors=11, weights="distance", metric="euclidean"),
    }


def run_tier1(partitions, run_dir):
    print("\n--- Tier 1: OS Family Discrimination ---")
    classifiers   = make_classifiers()
    meta          = partitions["meta"]
    partition     = partitions["full_family"]
    feature_names = make_feature_names(meta)
    out_dir       = Path(run_dir) / "tier1"
    results       = {}

    for name, model in classifiers.items():
        print(f"  Running {name}...")
        results[name] = cross_validate_partition(
            partition, model, meta,
            compute_permutation=(name == "rf"),
        )
        r = results[name]
        print(f"    Accuracy: {r['accuracy_mean']:.3f} ± {r['accuracy_std']:.3f}")
        print(f"    Macro F1: {r['macro_f1_mean']:.3f} ± {r['macro_f1_std']:.3f}")

        plot_confusion_matrix(
            r["confusion_matrix"], r["classes"],
            title=f"Tier 1 - {name} - OS Family",
            path=out_dir / f"{name}_confusion_matrix.png",
        )
        save_confusion_matrix_csv(
            r["confusion_matrix"], r["classes"],
            path=out_dir / f"{name}_confusion_matrix.csv",
        )

    save_metrics_csv(results, path=out_dir / "metrics.csv")
    plot_feature_importance(
        _extract_gini(partition, meta),
        results["rf"]["perm_importance_mean"],
        results["rf"]["perm_importance_std"],
        feature_names,
        title="Tier 1 - RF Feature Importance",
        path=out_dir / "rf_feature_importance.png",
    )

    return results


def run_tier2(partitions, run_dir):
    print("\n--- Tier 2: Linux Distribution Discrimination ---")
    classifiers   = make_classifiers()
    meta          = partitions["meta"]
    tails_label   = meta["tails_label"]
    feature_names = make_feature_names(meta)
    out_dir       = Path(run_dir) / "tier2"
    results       = {}

    for name, model in classifiers.items():
        print(f"  Running {name}...")
        results[name] = cross_validate_partition(
            partitions["linux_only"], model, meta,
            tails_label=tails_label,
            compute_permutation=(name == "rf"),
        )
        r = results[name]
        print(f"    Accuracy: {r['accuracy_mean']:.3f} ± {r['accuracy_std']:.3f}")
        print(f"    Macro F1: {r['macro_f1_mean']:.3f} ± {r['macro_f1_std']:.3f}")
        print(f"    Tails F1: {r['tails_f1_mean']:.3f} ± {r['tails_f1_std']:.3f}")

        plot_confusion_matrix(
            r["confusion_matrix"], r["classes"],
            title=f"Tier 2 - {name} - Linux Distributions",
            path=out_dir / f"{name}_confusion_matrix.png",
        )
        save_confusion_matrix_csv(
            r["confusion_matrix"], r["classes"],
            path=out_dir / f"{name}_confusion_matrix.csv",
        )

    save_metrics_csv(results, path=out_dir / "metrics.csv")
    plot_feature_importance(
        _extract_gini(partitions["linux_only"], meta),
        results["rf"]["perm_importance_mean"],
        results["rf"]["perm_importance_std"],
        feature_names,
        title="Tier 2 - RF Feature Importance",
        path=out_dir / "rf_feature_importance.png",
    )

    return results


def run_tier3(partitions, run_dir):
    print("\n--- Tier 3: Debian-Family Discrimination ---")
    classifiers   = make_classifiers()
    meta          = partitions["meta"]
    tails_label   = meta["tails_label"]
    feature_names = make_feature_names(meta)
    out_dir       = Path(run_dir) / "tier3"
    results       = {}

    for name, model in classifiers.items():
        print(f"  Running {name}...")
        results[name] = cross_validate_partition(
            partitions["debian_only"], model, meta,
            tails_label=tails_label,
            compute_permutation=(name == "rf"),
        )
        r = results[name]
        print(f"    Accuracy: {r['accuracy_mean']:.3f} ± {r['accuracy_std']:.3f}")
        print(f"    Macro F1: {r['macro_f1_mean']:.3f} ± {r['macro_f1_std']:.3f}")
        print(f"    Tails F1: {r['tails_f1_mean']:.3f} ± {r['tails_f1_std']:.3f}")

        plot_confusion_matrix(
            r["confusion_matrix"], r["classes"],
            title=f"Tier 3 - {name} - Debian Family",
            path=out_dir / f"{name}_confusion_matrix.png",
        )
        save_confusion_matrix_csv(
            r["confusion_matrix"], r["classes"],
            path=out_dir / f"{name}_confusion_matrix.csv",
        )

    save_metrics_csv(results, path=out_dir / "metrics.csv")
    plot_feature_importance(
        _extract_gini(partitions["debian_only"], meta),
        results["rf"]["perm_importance_mean"],
        results["rf"]["perm_importance_std"],
        feature_names,
        title="Tier 3 - RF Feature Importance",
        path=out_dir / "rf_feature_importance.png",
    )

    return results


def run_tier4(partitions, run_dir):
    print("\n--- Tier 4: Kernel Cluster Discrimination ---")
    classifiers   = make_classifiers()
    meta          = partitions["meta"]
    tails_label   = meta["tails_label"]
    feature_names = make_feature_names(meta)
    out_dir       = Path(run_dir) / "tier4" / "tails_cluster"
    results       = {}

    for name, model in classifiers.items():
        print(f"  Running {name}...")
        results[name] = cross_validate_partition(
            partitions["tails_cluster"], model, meta,
            tails_label=tails_label,
            compute_permutation=(name == "rf"),
        )
        r = results[name]
        print(f"    Accuracy: {r['accuracy_mean']:.3f} ± {r['accuracy_std']:.3f}")
        print(f"    Macro F1: {r['macro_f1_mean']:.3f} ± {r['macro_f1_std']:.3f}")
        print(f"    Tails F1: {r['tails_f1_mean']:.3f} ± {r['tails_f1_std']:.3f}")

        plot_confusion_matrix(
            r["confusion_matrix"], r["classes"],
            title=f"Tier 4 - {name} - Kernel Cluster",
            path=out_dir / f"{name}_confusion_matrix.png",
        )
        save_confusion_matrix_csv(
            r["confusion_matrix"], r["classes"],
            path=out_dir / f"{name}_confusion_matrix.csv",
        )

    save_metrics_csv(results, path=out_dir / "metrics.csv")
    rf_results = results["rf"]
    plot_feature_importance(
        _extract_gini(partitions["tails_cluster"], meta),
        rf_results["perm_importance_mean"],
        rf_results["perm_importance_std"],
        feature_names,
        title="Tier 4 - RF Feature Importance",
        path=out_dir / "rf_feature_importance.png",
    )

    return results


def run_tier4_secondary(partitions, run_dir):
    print("\n--- Tier 4 Secondary: Corroborating Kernel Cluster Evaluation ---")
    classifiers   = make_classifiers()
    meta          = partitions["meta"]
    feature_names = make_feature_names(meta)
    out_dir       = Path(run_dir) / "tier4"/ "secondary_clusters"
    results       = {}

    for kernel, partition in partitions["secondary_clusters"].items():
        kernel_prefix = kernel.replace(" ", "_").replace("/", "-")
        print(f"  Cluster: {kernel}")
        results[kernel] = {}

        for name, model in classifiers.items():
            print(f"    Running {name}...")
            results[kernel][name] = cross_validate_partition(
                partition, model, meta,
                compute_permutation=(name == "rf"),
            )
            r = results[kernel][name]
            print(f"      Macro F1: {r['macro_f1_mean']:.3f} ± {r['macro_f1_std']:.3f}")

            plot_confusion_matrix(
                r["confusion_matrix"], r["classes"],
                title=f"Tier 4 Secondary - {kernel} - {name}",
                path=out_dir / f"{kernel_prefix}_{name}_confusion_matrix.png",
            )
            save_confusion_matrix_csv(
                r["confusion_matrix"], r["classes"],
                path=out_dir / f"{kernel_prefix}_{name}_confusion_matrix.csv",
            )

        save_metrics_csv(
            results[kernel],
            path=out_dir / f"{kernel_prefix}_metrics.csv",
        )
        plot_feature_importance(
            _extract_gini(partition, meta),
            results[kernel]["rf"]["perm_importance_mean"],
            results[kernel]["rf"]["perm_importance_std"],
            feature_names,
            title=f"Tier 4 Secondary - {kernel} - RF Feature Importance",
            path=out_dir / f"{kernel_prefix}_rf_feature_importance.png",
        )

    return results


def parse_p0f_file(path):
    # Returns a list of P0f OS label strings, one per mod=syn subj=cli line
    predictions = []
    with open(path) as f:
        for line in f:
            if "mod=syn" in line and "subj=cli" in line:
                match = re.search(r"os=([^|]+)", line)
                if match:
                    predictions.append(match.group(1).strip())
                else:
                    predictions.append("???")
    return predictions


def p0f_label_to_family(label):
    # Map P0f OS label to Linux / non-Linux using the same logic as the dataset
    if label.startswith("Linux"):
        return "Linux"
    return "non-Linux"


def run_p0f(partitions, run_dir, p0f_dir):
    print("\n--- P0f Baseline: OS Family Discrimination ---")
    out_dir = Path(run_dir) / "p0f"
    df      = partitions["full"]["df"]

    # Build map from pcap stem -> (ground truth family, ground truth os_label)
    pcap_info = (
        df[["pcap_filename", "kernel_version", "os_label"]]
        .drop_duplicates("pcap_filename")
        .assign(pcap_stem=lambda x: x["pcap_filename"].str.replace(".pcap", "", regex=False))
        .set_index("pcap_stem")
    )
    pcap_to_family = pcap_info["kernel_version"].apply(
        lambda k: "Linux" if k.startswith("Linux ") else "non-Linux"
    ).to_dict()
    pcap_to_label  = pcap_info["os_label"].to_dict()

    all_y_true        = []
    all_y_pred        = []
    unknown_count     = 0
    no_match          = []
    no_syns           = []
    all_predictions = defaultdict(lambda: defaultdict(int))

    for txt_file in sorted(Path(p0f_dir).glob("*.txt")):
        pcap_stem   = txt_file.stem
        predictions = parse_p0f_file(txt_file)

        if not predictions:
            no_syns.append(pcap_stem)
            continue

        if pcap_stem not in pcap_to_family:
            no_match.append(pcap_stem)
            continue

        true_family = pcap_to_family[pcap_stem]
        true_label  = pcap_to_label[pcap_stem]

        for pred in predictions:
            if pred == "???":
                unknown_count += 1
                #all_predictions["???"][true_label] += 1
            else:
                all_y_true.append(true_family)
                all_y_pred.append(p0f_label_to_family(pred))
                all_predictions[pred][true_label] += 1

    if no_syns:
        print(f"  Info: {len(no_syns)} P0f files had no SYN packets (empty captures), skipped.")
    if no_match:
        print(f"  Warning: {len(no_match)} P0f files had no dataset match: {no_match}")

    total = len(all_y_pred) + unknown_count
    print(f"  Total SYNs seen by P0f : {total}")
    print(f"  Classified             : {len(all_y_pred)}")
    print(f"  Unclassified (???)     : {unknown_count} ({100 * unknown_count / total:.1f}%)")

    classes  = ["Linux", "non-Linux"]
    cm       = confusion_matrix(all_y_true, all_y_pred, labels=classes)
    report   = classification_report(all_y_true, all_y_pred, output_dict=True, zero_division=0)
    accuracy = accuracy_score(all_y_true, all_y_pred)
    macro_f1 = report["macro avg"]["f1-score"]

    print(f"  Accuracy : {accuracy:.3f}")
    print(f"  Macro F1 : {macro_f1:.3f}")

    plot_confusion_matrix(
        cm, classes,
        title="P0f Baseline - OS Family",
        path=out_dir / "confusion_matrix.png",
    )
    save_confusion_matrix_csv(cm, classes, path=out_dir / "confusion_matrix.csv")

    plot_p0f_distribution(
        all_predictions,
        title="P0f Label Distribution - All Instances",
        path=out_dir / "p0f_label_distribution.png",
        top_n=19,
    )

    results = {
        "p0f": {
            "accuracy_mean":    accuracy,
            "accuracy_std":     0.0,
            "macro_f1_mean":    macro_f1,
            "macro_f1_std":     0.0,
            "confusion_matrix": cm,
            "classes":          classes,
            "unknown_count":    unknown_count,
            "total_seen":       total,
        }
    }
    save_metrics_csv(results, path=out_dir / "metrics.csv")

    return results