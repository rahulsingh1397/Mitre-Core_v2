"""
experiments/analyse_gate_tuning.py
------------------------------------
Analysis and visualisation for gate tuning sweep results.

Usage:
    python experiments/analyse_gate_tuning.py \
        --results experiments/results/gate_tuning_results.csv \
        --calibration experiments/results/calibration_per_dataset.csv
"""

import argparse
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from scipy import stats

def analyse(results_path: str, calibration_path: str, exclude_datasets: str = None) -> None:
    df = pd.read_csv(results_path)
    calib_df = pd.read_csv(calibration_path) if Path(calibration_path).exists() else pd.DataFrame()

    if exclude_datasets:
        excludes = [d.strip() for d in exclude_datasets.split(",")]
        df = df[~df["dataset"].isin(excludes)]
        print(f"Excluded datasets: {excludes}")

    # Also filter out rows that skipped the sweep
    if "skip_gate_sweep" in df.columns:
        df = df[df["skip_gate_sweep"] != True]

    figures_dir = Path("docs/figures/gate_tuning")
    figures_dir.mkdir(parents=True, exist_ok=True)
    results_dir = Path("experiments/results")

    datasets = df["dataset"].unique()
    gate_values = sorted(df["gate_value"].unique())

    # --- Plot 1: Per-dataset ARI vs gate curves ---
    fig, axes = plt.subplots(2, 4, figsize=(16, 8), sharey=False)
    axes_flat = axes.flatten()

    optimal_rows = []
    for i, dataset in enumerate(datasets):
        ds_df = df[df["dataset"] == dataset].sort_values("gate_value")
        ax = axes_flat[i]
        ax.plot(ds_df["gate_value"], ds_df["ari"], marker="o", linewidth=2)
        ax.axvline(x=0.6, color="red", linestyle="--", alpha=0.6, label="default gate=0.6")
        ax.set_title(dataset, fontsize=9)
        ax.set_xlabel("confidence_gate")
        ax.set_ylabel("ARI")
        ax.legend(fontsize=7)

        # Individual figure
        fig_single, ax_single = plt.subplots(figsize=(7, 4))
        ax_single.plot(ds_df["gate_value"], ds_df["ari"], marker="o", linewidth=2, color="steelblue")
        ax_single.axvline(x=0.6, color="red", linestyle="--", alpha=0.7, label="default gate=0.6")
        ax_single.set_xlabel("confidence_gate")
        ax_single.set_ylabel("ARI")
        ax_single.set_title(f"ARI vs. confidence_gate — {dataset}")
        ax_single.legend()
        fig_single.tight_layout()
        fig_single.savefig(figures_dir / f"ari_vs_gate_{dataset.replace(' ', '_')}.png", dpi=150)
        plt.close(fig_single)

        # Optimal gate for this dataset
        best_idx = ds_df["ari"].idxmax()
        best_row = ds_df.loc[best_idx]
        baseline_ari = ds_df[ds_df["gate_value"] == 0.6]["ari"].values
        baseline_ari = float(baseline_ari[0]) if len(baseline_ari) > 0 else float("nan")
        
        # singleton_fraction warning — surfaces UF fragmentation proactively
        if "singleton_fraction" in best_row.index:
            sf = float(best_row["singleton_fraction"])
            mcs = float(best_row.get("mean_uf_cluster_size", float("nan")))
            if not np.isnan(sf):
                print(f"  {dataset}: singleton_fraction={sf:.3f}  mean_uf_cluster_size={mcs:.2f}")
                if sf > 0.8:
                    print(f"  *** WARNING: {dataset} singleton_fraction={sf:.3f} > 0.8.")
                    print(f"      UF refinement is producing mostly singletons.")
                    print(f"      Consider use_uf_refinement=False for this dataset/checkpoint. ***")
        
        optimal_rows.append({
            "dataset": dataset,
            "optimal_gate": float(best_row["gate_value"]),
            "optimal_ari": float(best_row["ari"]),
            "baseline_ari_gate06": baseline_ari,
            "ari_delta_vs_baseline": float(best_row["ari"]) - baseline_ari,
            "pct_uf_routed_at_optimal": float(best_row["pct_uf_routed"]),
            "n_clusters_at_optimal": int(best_row["n_clusters"]),
        })

    fig.suptitle("ARI vs. confidence_gate — All Datasets", fontsize=12)
    fig.tight_layout()
    fig.savefig(figures_dir / "ari_vs_gate_all_datasets.png", dpi=150)
    plt.close(fig)

    optimal_df = pd.DataFrame(optimal_rows)
    optimal_df.to_csv(results_dir / "gate_tuning_optimal.csv", index=False)
    print("\nOptimal gate per dataset:")
    print(optimal_df.to_string(index=False))

    # --- H2: ECE vs optimal gate correlation ---
    # calibration_per_dataset.csv must have columns: dataset, ece
    if Path(calibration_path).exists():
        merged = optimal_df.merge(calib_df[["dataset", "ece"]], on="dataset", how="inner")
        if len(merged) >= 4:
            r, p = stats.pearsonr(merged["ece"], merged["optimal_gate"])
            print(f"\nH2 Pearson r (ECE vs optimal_gate) = {r:.4f}, p = {p:.4f}")
            fig_h2, ax_h2 = plt.subplots(figsize=(6, 5))
            ax_h2.scatter(merged["ece"], merged["optimal_gate"], s=80, color="darkorange")
            for _, row in merged.iterrows():
                ax_h2.annotate(row["dataset"], (row["ece"], row["optimal_gate"]),
                               fontsize=7, ha="left", va="bottom")
            ax_h2.set_xlabel("Per-dataset ECE (from Phase 4)")
            ax_h2.set_ylabel("Optimal confidence_gate")
            ax_h2.set_title(f"H2: ECE vs. Optimal Gate  (r={r:.3f}, p={p:.3f})")
            fig_h2.tight_layout()
            fig_h2.savefig(figures_dir / "ece_vs_optimal_gate.png", dpi=150)
            plt.close(fig_h2)
            with open(results_dir / "gate_tuning_h2_correlation.json", "w") as f:
                json.dump({"pearson_r": r, "p_value": p, "n": len(merged)}, f, indent=2)

    # --- H3: pct_uf_routed vs ARI Spearman ---
    spearman_r, spearman_p = stats.spearmanr(df["pct_uf_routed"], df["ari"])
    print(f"\nH3 Spearman r (pct_uf_routed vs ARI) = {spearman_r:.4f}, p = {spearman_p:.4f}")
    fig_h3, ax_h3 = plt.subplots(figsize=(7, 5))
    for dataset in datasets:
        ds_df = df[df["dataset"] == dataset]
        ax_h3.scatter(ds_df["pct_uf_routed"], ds_df["ari"], label=dataset, alpha=0.7, s=50)
    ax_h3.set_xlabel("Fraction of Alerts Routed to UF Refinement")
    ax_h3.set_ylabel("ARI")
    ax_h3.set_title(f"H3: UF Routing Rate vs. ARI  (Spearman r={spearman_r:.3f})")
    ax_h3.legend(fontsize=7, loc="best")
    fig_h3.tight_layout()
    fig_h3.savefig(figures_dir / "pct_uf_vs_ari.png", dpi=150)
    plt.close(fig_h3)
    with open(results_dir / "gate_tuning_h3_correlation.json", "w") as f:
        json.dump({"spearman_r": spearman_r, "p_value": spearman_p,
                   "n_observations": len(df)}, f, indent=2)

    print("\nAnalysis complete. All figures saved to docs/figures/gate_tuning/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", default="experiments/results/gate_tuning_results.csv")
    parser.add_argument("--calibration", default="experiments/results/calibration_per_dataset.csv")
    parser.add_argument("--exclude-datasets", default="", help="Comma-separated list of datasets to exclude")
    args = parser.parse_args()
    analyse(args.results, args.calibration, args.exclude_datasets)
