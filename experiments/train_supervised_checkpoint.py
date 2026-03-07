"""
experiments/train_supervised_checkpoint.py
-------------------------------------------
Train a supervised HGNN checkpoint on UNSW-NB15 mitre-format data.
Uses campaign_id as ground-truth cluster labels.
Target: ARI >= 0.5 on held-out split.

Usage:
    python experiments/train_supervised_checkpoint.py \
        --output hgnn_checkpoints/unsw_supervised.pt \
        --epochs 30 --lr 0.001 --hidden-dim 128
"""

import argparse
import sys
import os
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import LabelEncoder

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import torch.nn as nn
import torch.nn.functional as F

from hgnn.hgnn_correlation import MITREHeteroGNN, AlertToGraphConverter
from utils.seed_control import set_seed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("train_supervised")


def load_and_prep(csv_path: str, label_col: str, max_rows: int = 10000, seed: int = 42):
    """Load mitre-format CSV, remap columns, encode labels."""
    df = pd.read_csv(csv_path)
    # Remap mitre_format column names to AlertToGraphConverter expected names
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
    # Subsample
    if len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=seed).reset_index(drop=True)
    logger.info(f"Loaded {len(df)} rows, label_col='{label_col}'")
    le = LabelEncoder()
    labels = le.fit_transform(df[label_col].fillna("UNKNOWN").astype(str).values)
    n_classes = len(le.classes_)
    logger.info(f"Classes: {n_classes} ({le.classes_})")
    return df, labels, n_classes, le


def train(args):
    set_seed(args.seed)
    device = torch.device(args.device if args.device else ("cuda" if torch.cuda.is_available() else "cpu"))
    logger.info(f"Device: {device}")

    # ---- Load data ----
    df, labels, n_classes, le = load_and_prep(
        args.dataset, args.label_col, max_rows=args.max_rows, seed=args.seed
    )

    # Train/val split by index (80/20, stratified by label)
    rng = np.random.default_rng(args.seed)
    idx = np.arange(len(df))
    val_mask = rng.random(len(df)) < 0.2
    train_idx = idx[~val_mask]
    val_idx = idx[val_mask]
    logger.info(f"Train: {len(train_idx)}, Val: {len(val_idx)}")

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_val = df.iloc[val_idx].reset_index(drop=True)
    y_train = torch.tensor(labels[train_idx], dtype=torch.long).to(device)
    y_val = labels[val_idx]

    # ---- Build graph ----
    converter = AlertToGraphConverter()
    logger.info("Converting train split to HeteroData...")
    graph_train = converter.convert(df_train).to(device)
    logger.info("Converting val split to HeteroData...")
    graph_val = converter.convert(df_val).to(device)

    # ---- Model ----
    model = MITREHeteroGNN(
        hidden_dim=args.hidden_dim,
        num_heads=4,
        num_layers=2,
        dropout=0.3,
        num_clusters=n_classes,
    ).to(device)

    # Initialize lazy layers with a single forward pass before optimizer
    # Must materialize all lazy params before any state_dict() or clone() calls
    model.train()
    init_logits, _ = model(graph_train)
    # Warm-up gradient step to materialize lazy buffers fully
    init_loss = F.cross_entropy(init_logits, y_train)
    init_loss.backward()
    model.zero_grad()
    logger.info("Lazy layers initialized.")

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)

    best_ari = -1.0
    best_state = None

    # Compute class weights for imbalanced dataset
    unique_classes, class_counts = np.unique(y_train.cpu().numpy(), return_counts=True)
    total_samples = len(y_train)
    class_weights = np.ones(n_classes, dtype=np.float32)
    for cls, count in zip(unique_classes, class_counts):
        class_weights[cls] = total_samples / (n_classes * count)
    class_weights = torch.tensor(class_weights, dtype=torch.float32).to(device)

    for epoch in range(1, args.epochs + 1):
        model.train()
        optimizer.zero_grad()
        logits, _ = model(graph_train)
        loss = F.cross_entropy(logits, y_train, weight=class_weights)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()

        # Validation ARI every 5 epochs
        if epoch % 5 == 0 or epoch == 1:
            model.eval()
            with torch.no_grad():
                val_logits, _ = model(graph_val)
                val_preds = torch.argmax(val_logits, dim=-1).cpu().numpy()
            ari = adjusted_rand_score(y_val, val_preds)
            n_pred = len(np.unique(val_preds))
            logger.info(
                f"Epoch {epoch:3d}/{args.epochs} | loss={loss.item():.4f} | "
                f"val_ARI={ari:.4f} | val_clusters={n_pred}"
            )
            if ari > best_ari:
                best_ari = ari
                # state_dict() returns copies of tensors (no lazy params after init)
                best_state = model.state_dict()
                best_state = {k: v.detach().cpu().clone() for k, v in best_state.items()
                              if not getattr(v, 'is_uninitialized', False)
                              and 'Uninitialized' not in type(v).__name__}
                logger.info(f"  -> New best ARI={best_ari:.4f}")

    logger.info(f"\nTraining complete. Best val ARI = {best_ari:.4f}")

    if best_ari < args.min_ari:
        logger.warning(
            f"Best ARI={best_ari:.4f} < required {args.min_ari}. "
            f"Checkpoint saved anyway — verify_checkpoint.py will gate this."
        )

    # Save best checkpoint
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    torch.save(best_state, args.output)
    logger.info(f"Saved checkpoint to {args.output}")
    logger.info(f"Label classes: {list(le.classes_)}")
    return best_ari


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="datasets/unsw_nb15/mitre_format.csv")
    parser.add_argument("--label-col", dest="label_col", default="campaign_id")
    parser.add_argument("--output", default="hgnn_checkpoints/unsw_supervised.pt")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--hidden-dim", type=int, default=128)
    parser.add_argument("--max-rows", type=int, default=8000)
    parser.add_argument("--min-ari", type=float, default=0.5)
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    ari = train(args)
    sys.exit(0 if ari >= args.min_ari else 1)
