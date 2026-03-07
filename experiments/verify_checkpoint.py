"""
experiments/verify_checkpoint.py
----------------------------------
Pre-flight verification: confirms a checkpoint produces ARI >= 0.5 on
UNSW-NB15 before allowing the gate tuning sweep to run.

Usage:
    python experiments/verify_checkpoint.py \
        --checkpoint <path_to_checkpoint.pt> \
        --dataset data/preprocessing/unsw_nb15_graph.pkl \
        --label-col attack_cat \
        --min-ari 0.5

Exit code 0 = checkpoint passes. Exit code 1 = checkpoint fails.
DO NOT run run_gate_tuning.py if this script exits with code 1.
"""

import argparse
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
import pandas as pd
import numpy as np
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import LabelEncoder

import torch
from hgnn.hgnn_correlation import HGNNCorrelationEngine
from utils.seed_control import set_seed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_checkpoint")


def verify(checkpoint_path: str, dataset_path: str,
           label_col: str, min_ari: float, hidden_dim: int) -> bool:

    set_seed(42)
    device = "cpu"
    logger.info(f"Device: {device}")
    logger.info(f"Checkpoint: {checkpoint_path}")
    logger.info(f"Dataset: {dataset_path}")
    logger.info(f"Hidden Dim: {hidden_dim}")

    # Load dataset
    if dataset_path.endswith(".pkl"):
        df = pd.read_pickle(dataset_path)
    else:
        df = pd.read_csv(dataset_path)
        # sample to avoid out of memory but get diverse campaigns
        if len(df) > 10000:
            df = df.sample(n=10000, random_state=42).reset_index(drop=True)
    logger.info(f"Loaded {len(df)} alerts")

    # Map mitre_format.csv columns to HGNN expected names if needed
    if 'src_ip' in df.columns and 'SourceAddress' not in df.columns:
        df['SourceAddress'] = df['src_ip']
    if 'dst_ip' in df.columns and 'DestinationAddress' not in df.columns:
        df['DestinationAddress'] = df['dst_ip']
    if 'timestamp' in df.columns and 'StartTime' not in df.columns:
        df['StartTime'] = df['timestamp']
    if 'timestamp' in df.columns and 'EndDate' not in df.columns:
        df['EndDate'] = df['timestamp']
    if 'alert_type' in df.columns and 'AttackTechnique' not in df.columns:
        df['AttackTechnique'] = df['alert_type']
    if 'tactic' in df.columns and 'Tactic' not in df.columns:
        df['Tactic'] = df['tactic']
    if 'campaign_id' in df.columns and 'Campaign' not in df.columns:
        df['Campaign'] = df['campaign_id']

    # Encode ground truth
    if label_col not in df.columns:
        logger.error(f"Label column '{label_col}' not found. "
                     f"Available: {list(df.columns)}")
        return False

    le = LabelEncoder()
    true_labels = le.fit_transform(
        df[label_col].fillna("UNKNOWN").astype(str).values
    )
    n_true_clusters = len(np.unique(true_labels))
    logger.info(f"Ground truth: {n_true_clusters} unique classes in '{label_col}'")

    # For pre-flight verification, use a low gate to verify HGNN base capability
    engine = HGNNCorrelationEngine(
        model_path=checkpoint_path,
        confidence_gate=0.0,  
        hidden_dim=hidden_dim,
        device=device,
        use_geometric_confidence=True,
        hdbscan_min_cluster_size=5,
        hdbscan_pca_components=32,
    )

    result_df = engine.correlate(df)

    # Report confidence distribution FIRST — this is the diagnostic
    conf = result_df["cluster_confidence"]
    logger.info(f"\n--- Confidence Distribution ---")
    logger.info(f"  mean  : {conf.mean():.4f}")
    logger.info(f"  median: {conf.median():.4f}")
    logger.info(f"  p25   : {conf.quantile(0.25):.4f}")
    logger.info(f"  p75   : {conf.quantile(0.75):.4f}")
    logger.info(f"  min   : {conf.min():.4f}")
    logger.info(f"  max   : {conf.max():.4f}")

    pct_uf = (result_df["correlation_method"] == "hgnn+uf_refinement").mean()
    logger.info(f"  pct routed to UF: {pct_uf:.2%}")

    if conf.mean() < 0.1:
        logger.error(
            f"CHECKPOINT FAIL: Mean confidence={conf.mean():.4f} < 0.1. "
            f"This is consistent with an untrained classification head "
            f"(expected ~1/num_clusters = 0.125 for uniform logits on 8 classes). "
            f"This is NOT the supervised ablation checkpoint. "
            f"Locate the correct checkpoint before proceeding."
        )
        return False

    # Compute ARI
    pred_labels = result_df["pred_cluster"].values
    n_pred_clusters = len(np.unique(pred_labels))
    ari = adjusted_rand_score(true_labels, pred_labels)

    logger.info(f"\n--- ARI Result ---")
    logger.info(f"  Predicted clusters : {n_pred_clusters}")
    logger.info(f"  True clusters      : {n_true_clusters}")
    logger.info(f"  ARI                : {ari:.4f}")
    logger.info(f"  Required minimum   : {min_ari:.4f}")

    if ari < min_ari:
        logger.error(
            f"CHECKPOINT FAIL: ARI={ari:.4f} < required {min_ari:.4f}. "
            f"This checkpoint does not reproduce the expected baseline. "
            f"Do not proceed with the gate sweep."
        )
        return False

    logger.info(f"CHECKPOINT PASS: ARI={ari:.4f} >= {min_ari:.4f}. "
                f"Proceed with run_gate_tuning.py.")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--dataset",
                        default="datasets/unsw_nb15/mitre_format.csv")
    parser.add_argument("--label-col", default="attack_cat")
    parser.add_argument("--min-ari", type=float, default=0.5)
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--hidden-dim", type=int, default=128)
    args = parser.parse_args()

    passed = verify(args.checkpoint, args.dataset,
                    args.label_col, args.min_ari, args.hidden_dim)
    sys.exit(0 if passed else 1)
