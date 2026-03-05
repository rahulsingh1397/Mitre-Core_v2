"""
experiments/run_gate_tuning.py
-------------------------------
Confidence gate tuning sweep for MITRE-CORE v2.1.
Runs HGNNCorrelationEngine across all 8 datasets × 9 gate values.

Usage:
    python experiments/run_gate_tuning.py \
        --checkpoint hgnn_checkpoints/foundation_v2/checkpoint_best.pt \
        --output experiments/results/gate_tuning_results.csv

Constraints:
    - No synthetic data. All inputs must be real preprocessed dataset graphs.
    - All runs logged with git commit hash via scripts/generate_experiment_log.py.
    - Do NOT overwrite existing experiment results files — append or use new filename.
"""

import argparse
import time
import logging
import sys
import os
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
from sklearn.preprocessing import LabelEncoder

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hgnn.hgnn_correlation import HGNNCorrelationEngine
from utils.seed_control import set_seed
import scripts.generate_experiment_log as exp_log

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gate_tuning")

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------

GATE_VALUES = [0.4, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.9]

DATASET_CONFIG = {
    "UNSW-NB15": {
        "path": "datasets/unsw_nb15/mitre_format.csv",
        "label_col": "campaign_id",
        "hdbscan_min_cluster_size": 15,
        "hdbscan_pca_components": 32,
    },
    "TON_IoT": {
        "path": "datasets/TON_IoT/mitre_format.parquet",
        "label_col": "Category",
        "hdbscan_min_cluster_size": 15,
        "hdbscan_pca_components": 32,
        "skip_gate_sweep": True,
        "note": (
            "HGNN checkpoint trained on UNSW-NB15 campaign_id. "
            "TON_IoT Category is OOD: HDBSCAN produces 2 tight clusters, "
            "all confidence=1.0, zero UF routing at any gate. "
            "Excluded from H1/H2/H3 gate sensitivity analysis. "
            "Requires domain-specific checkpoint for meaningful results."
        ),
    },
    "Linux_APT": {
        "path": "datasets/Linux_APT/mitre_format.parquet",
        "label_col": "campaign",
        "hdbscan_min_cluster_size": 5,   # smaller — fewer alerts after sample
        "hdbscan_pca_components": 16,    # lower — fewer distinct features
        "sample_size": None,
        "note": (
            "Category has 1 unique value in 10K sample. "
            "Using 'campaign' label (3 values) and full dataset instead."
        ),
    },
    "NSL-KDD": {
        "path": "datasets/nsl_kdd/mitre_format.csv",
        "label_col": "campaign_id",
        "hdbscan_min_cluster_size": 15,
        "hdbscan_pca_components": 32,
    },
}

from typing import Optional

# -----------------------------------------------------------------------
# Helper: load a dataset DataFrame from its preprocessed path
# -----------------------------------------------------------------------

def load_dataset(path: str, sample_size: Optional[int] = 10000) -> pd.DataFrame:
    """
    Load a preprocessed dataset. Supports .csv and .parquet.
    Raises FileNotFoundError if the path does not exist — do not silently
    fall back to synthetic data.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Preprocessed dataset not found: {path}\n"
            f"Expected mitre-format file at this path."
        )
    if p.suffix == ".csv":
        df = pd.read_csv(p)
    elif p.suffix == ".parquet":
        df = pd.read_parquet(p)
    else:
        raise ValueError(f"Unsupported file format: {p.suffix}")

    # Remap mitre_format column names to HGNN AlertToGraphConverter names
    col_map = {
        "src_ip": "SourceAddress",
        "dst_ip": "DestinationAddress",
        "hostname": "SourceHostName",
        "username": "SourceUserName",
        "timestamp": "EndDate",
        "alert_type": "MalwareIntelAttackType",
        "tactic": "AttackTechnique",
    }
    for old, new in col_map.items():
        if old in df.columns and new not in df.columns:
            df[new] = df[old]

    # Sample large datasets to keep runtime manageable
    if sample_size is not None and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    return df


# -----------------------------------------------------------------------
# Helper: encode ground-truth labels to integer cluster IDs
# -----------------------------------------------------------------------

def encode_labels(df: pd.DataFrame, label_col: str) -> np.ndarray:
    if label_col not in df.columns:
        raise ValueError(
            f"Ground-truth column '{label_col}' not found. "
            f"Available columns: {list(df.columns)}"
        )
    le = LabelEncoder()
    return le.fit_transform(df[label_col].fillna("UNKNOWN").astype(str).values)


# -----------------------------------------------------------------------
# Main sweep
# -----------------------------------------------------------------------

def run_sweep(checkpoint_path: str, output_path: str) -> None:
    set_seed(42)
    git_hash = exp_log.get_git_hash()
    logger.info(f"Starting gate tuning sweep | git={git_hash}")

    results = []

    for dataset_name, config in DATASET_CONFIG.items():
        logger.info(f"\n{'='*60}")
        logger.info(f"Dataset: {dataset_name}")

        if config.get("skip_gate_sweep", False):
            logger.info(
                f"SKIPPING gate sweep for {dataset_name}: {config.get('note', 'flagged')}"
            )
            # Run a single pass at gate=0.5 for documentation only
            gate_values_for_dataset = [0.5]
        else:
            gate_values_for_dataset = GATE_VALUES

        df = load_dataset(config["path"], sample_size=config.get("sample_size", 10000))
        true_labels = encode_labels(df, config["label_col"])
        
        # Set dataset name for GAEC diagnostics logger
        df._dataset_name = dataset_name

        for gate in gate_values_for_dataset:
            logger.info(f"  gate={gate:.2f} ...")

            engine = HGNNCorrelationEngine(
                model_path=checkpoint_path,
                confidence_gate=gate,
                device="cpu", # CUDA not available for this torch version locally
                use_geometric_confidence=True,   # GAEC enabled
                hdbscan_min_cluster_size=config["hdbscan_min_cluster_size"],
                hdbscan_pca_components=config["hdbscan_pca_components"],
            )

            t_start = time.perf_counter()
            result_df = engine.correlate(df)
            latency = time.perf_counter() - t_start

            pred_labels = result_df["pred_cluster"].values
            ari = adjusted_rand_score(true_labels, pred_labels)
            nmi = normalized_mutual_info_score(
                true_labels, pred_labels, average_method="arithmetic"
            )

            uf_mask = result_df["correlation_method"] == "hgnn+uf_refinement"
            hgnn_mask = result_df["correlation_method"] == "hgnn"

            threshold_used = (
                result_df.loc[uf_mask, "correlation_threshold_used"].mean()
                if uf_mask.any()
                else float("nan")
            )

            row = {
                "dataset": dataset_name,
                "gate_value": gate,
                "ari": ari,
                "nmi": nmi,
                "n_clusters": result_df["pred_cluster"].nunique(),
                "n_hgnn_clusters": result_df.loc[hgnn_mask, "pred_cluster"].nunique() if hgnn_mask.any() else 0,
                "n_uf_clusters": result_df.loc[uf_mask, "pred_cluster"].nunique() if uf_mask.any() else 0,
                "pct_uf_routed": float(uf_mask.mean()),
                "avg_confidence": float(result_df["cluster_confidence"].mean()),
                "p25_confidence": float(result_df["cluster_confidence"].quantile(0.25)),
                "threshold_used": threshold_used,
                "skip_gate_sweep": config.get("skip_gate_sweep", False),
                "latency_s": latency,
                "git_hash": git_hash,
            }
            results.append(row)

            logger.info(
                f"    ARI={ari:.4f} | NMI={nmi:.4f} | "
                f"pct_uf={row['pct_uf_routed']:.2%} | "
                f"latency={latency:.3f}s"
            )

    results_df = pd.DataFrame(results)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(output_path, index=False)
    logger.info(f"\nSweep complete. Results saved to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--checkpoint",
        type=str,
        required=True,
        help="Path to the HGNN checkpoint (.pt file)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="experiments/results/gate_tuning_results.csv",
        help="Output CSV path",
    )
    args = parser.parse_args()
    run_sweep(args.checkpoint, args.output)
