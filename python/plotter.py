import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from collections import defaultdict


def save_metrics_csv(results, path):
    rows = []
    for classifier, r in results.items():
        row = {
            "classifier":      classifier,
            "accuracy_mean":   r["accuracy_mean"],
            "accuracy_std":    r["accuracy_std"],
            "macro_f1_mean":   r["macro_f1_mean"],
            "macro_f1_std":    r["macro_f1_std"],
        }
        if "tails_f1_mean" in r:
            row["tails_f1_mean"] = r["tails_f1_mean"]
            row["tails_f1_std"]  = r["tails_f1_std"]
        if "unknown_count" in r:
            row["unknown_count"] = r["unknown_count"]
            row["total_seen"]    = r["total_seen"]
        rows.append(row)
    pd.DataFrame(rows).to_csv(path, index=False, sep=";")
    print(f"  Saved metrics: {path}")


def save_confusion_matrix_csv(cm, classes, path):
    pd.DataFrame(cm, index=classes, columns=classes).to_csv(path, sep=";")
    print(f"  Saved confusion matrix: {path}")


def plot_confusion_matrix(cm, classes, title, path):
    # Normalise by row - recall per class
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    fig, ax = plt.subplots(figsize=(max(6, len(classes)), max(5, len(classes) - 1)))
    im = ax.imshow(cm_norm, interpolation="nearest", cmap="Blues", vmin=0, vmax=1)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    ax.set_xticks(range(len(classes)))
    ax.set_yticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(classes, fontsize=8)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)

    # Annotate each cell with the value
    thresh = 0.5
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, f"{cm_norm[i, j]:.2f}",
                    ha="center", va="center", fontsize=7,
                    color="white" if cm_norm[i, j] > thresh else "black")

    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved confusion matrix plot: {path}")


def plot_feature_importance(gini_mean, perm_mean, perm_std, feature_names, title, path):
    pd.DataFrame({
        "feature":   feature_names,
        "gini_mean": gini_mean,
        "perm_mean": perm_mean,
        "perm_std":  perm_std,
    }).sort_values("gini_mean", ascending=False).to_csv(
        path.with_suffix(".csv"), index=False, sep=";"
        )
    # Filter out empty values (zero gini AND zero perm importance)
    non_empty_mask = (gini_mean != 0) | (perm_mean != 0)
    non_empty_indices = np.where(non_empty_mask)[0]

    selected_indices = non_empty_indices
    if len(non_empty_indices) < 5:
        # Pad with empty features up to 5
        empty_indices = np.where(~non_empty_mask)[0]
        n_pad = max(0, 5 - len(non_empty_indices))
        selected_indices = np.concatenate([non_empty_indices, empty_indices[:n_pad]])

    gini_mean = gini_mean[selected_indices]
    perm_mean = perm_mean[selected_indices]
    perm_std = perm_std[selected_indices]
    feature_names = [feature_names[i] for i in selected_indices]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, max(6, len(feature_names) * 0.3)))

    # Sort by gini importance
    gini_order = np.argsort(gini_mean)
    ax1.barh(range(len(feature_names)), gini_mean[gini_order], color="steelblue")
    ax1.set_yticks(range(len(feature_names)))
    ax1.set_yticklabels([feature_names[i] for i in gini_order], fontsize=7)
    ax1.set_xlabel("Mean Gini decrease in impurity")
    ax1.set_title("Gini importance")

    # Sort by permutation importance
    perm_order = np.argsort(perm_mean)
    ax2.barh(range(len(feature_names)), perm_mean[perm_order],
             xerr=perm_std[perm_order], color="darkorange", ecolor="black", capsize=3)
    ax2.set_yticks(range(len(feature_names)))
    ax2.set_yticklabels([feature_names[i] for i in perm_order], fontsize=7)
    ax2.set_xlabel("Mean macro F1 drop")
    ax2.set_title("Permutation importance")

    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved feature importance plot: {path}")


def plot_p0f_distribution(all_predictions, title, path, top_n=10):
    # all_predictions: {p0f_label: {os_label: count}}
    # Find top N os_labels by total packet count across all p0f labels
    os_totals = defaultdict(int)
    for os_counts in all_predictions.values():
        for os_label, count in os_counts.items():
            os_totals[os_label] += count

    top_os    = sorted(os_totals, key=os_totals.get, reverse=True)[:top_n]
    other_key = "other"
    p0f_labels = sorted(all_predictions.keys())

    # Build stacked bar data - top N os_labels + everything else collapsed into "other"
    bar_data = {os_label: [] for os_label in top_os}
    bar_data[other_key] = []

    for p0f_label in p0f_labels:
        counts = all_predictions[p0f_label]
        for os_label in top_os:
            bar_data[os_label].append(counts.get(os_label, 0))
        bar_data[other_key].append(
            sum(v for k, v in counts.items() if k not in top_os)
        )

    fig, ax  = plt.subplots(figsize=(max(8, len(p0f_labels) * 2), 7))
    bottoms  = np.zeros(len(p0f_labels))
    cmap     = plt.get_cmap("tab20")
    colors   = [cmap(i / (top_n + 1)) for i in range(top_n + 1)]

    for idx, (os_label, counts) in enumerate(bar_data.items()):
        ax.bar(p0f_labels, counts, bottom=bottoms,
               label=os_label, color=colors[idx])
        bottoms += np.array(counts)

    # Add total count on top of each bar
    for idx, p0f_label in enumerate(p0f_labels):
        total = int(bottoms[idx])
        ax.text(idx, total + ax.get_ylim()[1] * 0.01, f"{total:,}",
                ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("P0f label")
    ax.set_ylabel("Packet count")
    ax.set_title(title)
    ax.set_xticks(range(len(p0f_labels)))
    ax.set_xticklabels(p0f_labels, rotation=30, ha="right", fontsize=8)
    ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize=7)

    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved P0f distribution plot: {path}")
