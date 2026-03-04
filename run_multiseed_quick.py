"""
Quick multi-seed evaluation script for UNSW-NB15 HGNN + HomogeneousGNN baseline.
Runs 5 seeds with minimal epochs to get mean/std for the paper.
"""
import sys
import os
import json
import logging
import numpy as np
import random
import torch
import torch.nn as nn
import torch.nn.functional as F

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hgnn'))
sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

from hgnn_correlation import MITREHeteroGNN, HomogeneousGNN
from torch_geometric.nn import GCNConv

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'datasets', 'unsw_nb15', 'mitre_format.csv')
OUTPUT_PATH  = os.path.join(os.path.dirname(__file__), 'hgnn_checkpoints_unsw', 'unsw_nb15_hgnn_stats.json')
EPOCHS = 15
CONTRASTIVE_EPOCHS = 10
SEEDS = [42, 43, 44, 45, 46]

def load_and_prepare(path):
    import pandas as pd
    from hgnn_correlation import AlertToGraphConverter
    df = pd.read_csv(path)
    logger.info(f"Loaded {len(df)} records")
    
    # Map columns to what AlertToGraphConverter expects
    df = df.rename(columns={
        'alert_type': 'MalwareIntelAttackType',
        'timestamp': 'EndDate',
        'stage': 'AttackSeverity',
        'src_ip': 'SourceAddress',
        'dst_ip': 'DestinationAddress',
        'hostname': 'SourceHostName',
        'username': 'SourceUserName'
    })
    
    attack_df = df[df['MalwareIntelAttackType'] != 'normal'].copy()
    attack_df['campaign_id'] = attack_df['campaign_id'].astype(int)
    # Give it enough data to learn
    attack_df = attack_df.head(10000)
    n_campaigns = attack_df['campaign_id'].nunique()
    logger.info(f"Campaigns: {n_campaigns}")

    converter = AlertToGraphConverter()
    campaign_size = 20
    graphs, labels = [], []
    
    unique_campaigns = attack_df['campaign_id'].unique()
    campaign_to_idx = {c: i for i, c in enumerate(unique_campaigns)}
    
    for _, grp in attack_df.groupby('campaign_id'):
        if len(grp) >= campaign_size:
            for start in range(0, len(grp) - campaign_size + 1, campaign_size):
                chunk = grp.iloc[start:start + campaign_size]
                g = converter.convert(chunk)
                if g is not None and 'alert' in g.node_types:
                    graphs.append(g)
                    labels.append(campaign_to_idx[int(chunk['campaign_id'].iloc[0])])

    logger.info(f"Created {len(graphs)} graphs")
    return graphs, labels, n_campaigns


def get_alert_dim(graphs):
    for g in graphs:
        if 'alert' in g.node_types and g['alert'].x is not None:
            return g['alert'].x.shape[1]
    return 8


def evaluate(model, test_graphs, test_labels, device, hetero=True):
    model.eval()
    correct = total = 0
    with torch.no_grad():
        for g, lbl in zip(test_graphs, test_labels):
            g = g.to(device)
            if 'alert' not in g.node_types:
                continue
            if hetero:
                logits, _ = model(g)
            else:
                x = g['alert'].x
                ei_list = [g[et].edge_index for et in g.edge_types
                           if et[0] == 'alert' and et[2] == 'alert']
                ei = torch.cat(ei_list, dim=1) if ei_list else torch.arange(
                    x.shape[0], device=device).unsqueeze(0).repeat(2, 1)
                logits, _ = model(x, ei)
            pred = logits.mean(0).argmax().item()
            if pred == lbl:
                correct += 1
            total += 1
    return correct / total if total > 0 else 0.0


def run():
    device = torch.device('cpu')
    logger.info("Loading UNSW-NB15...")
    all_graphs, all_labels, n_campaigns = load_and_prepare(DATASET_PATH)

    alert_dim = get_alert_dim(all_graphs)
    num_clusters = max(n_campaigns, 10)
    logger.info(f"alert_dim={alert_dim}, num_clusters={num_clusters}")

    hgnn_accs = []
    homo_acc = None

    for seed in SEEDS:
        torch.manual_seed(seed)
        np.random.seed(seed)
        random.seed(seed)

        # Shuffle and split for this seed
        combined = list(zip(all_graphs, all_labels))
        random.shuffle(combined)
        shuffled_graphs, shuffled_labels = zip(*combined)
        split = int(len(shuffled_graphs) * 0.8)
        train_g, test_g = shuffled_graphs[:split], shuffled_graphs[split:]
        train_l, test_l = shuffled_labels[:split], shuffled_labels[split:]

        model = MITREHeteroGNN(alert_feature_dim=alert_dim, hidden_dim=128, num_layers=3, num_clusters=num_clusters).to(device)
        opt = torch.optim.AdamW(model.parameters(), lr=0.005, weight_decay=1e-4)

        # Contrastive pre-training (simplified: just run supervised for speed)
        model.train()
        for epoch in range(CONTRASTIVE_EPOCHS + EPOCHS):
            for g, lbl in zip(train_g, train_l):
                g = g.to(device)
                if 'alert' not in g.node_types:
                    continue
                opt.zero_grad()
                logits, _ = model(g)
                lbl_tensor = torch.tensor([lbl], dtype=torch.long, device=device)
                loss = F.cross_entropy(logits.mean(0).unsqueeze(0), lbl_tensor)
                loss.backward()
                opt.step()

        acc = evaluate(model, test_g, test_l, device, hetero=True)
        hgnn_accs.append(acc)
        logger.info(f"Seed {seed}: HGNN acc = {acc:.4f}")

        # HomogeneousGNN baseline - run once on seed 42
        if seed == 42:
            homo = HomogeneousGNN(input_dim=alert_dim, feature_dim=64, hidden_dim=64,
                                  num_clusters=num_clusters).to(device)
            homo_opt = torch.optim.Adam(homo.parameters(), lr=0.001)
            homo.train()
            for epoch in range(EPOCHS):
                for g, lbl in zip(train_g, train_l):
                    g = g.to(device)
                    if 'alert' not in g.node_types:
                        continue
                    x = g['alert'].x
                    ei_list = [g[et].edge_index for et in g.edge_types 
                               if et[0] == 'alert' and et[2] == 'alert']
                    ei = torch.cat(ei_list, dim=1) if ei_list else torch.arange(
                        x.shape[0], device=device).unsqueeze(0).repeat(2, 1)
                    homo_opt.zero_grad()
                    logits, _ = homo(x, ei)
                    lbl_tensor = torch.tensor([lbl], dtype=torch.long, device=device)
                    loss = F.cross_entropy(logits.mean(0).unsqueeze(0), lbl_tensor)
                    loss.backward()
                    homo_opt.step()
            homo_acc = evaluate(homo, test_g, test_l, device, hetero=False)
            logger.info(f"HomogeneousGNN acc = {homo_acc:.4f}")

    mean_acc = float(np.mean(hgnn_accs))
    std_acc  = float(np.std(hgnn_accs))
    logger.info(f"\n{'='*50}")
    logger.info(f"HGNN Multi-Seed: {mean_acc:.4f} ± {std_acc:.4f}")
    logger.info(f"Per-seed: {[f'{a:.4f}' for a in hgnn_accs]}")
    logger.info(f"HomogeneousGNN: {homo_acc:.4f}")
    logger.info(f"HGNN advantage: {mean_acc - homo_acc:+.4f} pp")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    stats = {
        "dataset": "unsw_nb15",
        "num_seeds": len(SEEDS),
        "seeds": SEEDS,
        "seed_accuracies": hgnn_accs,
        "mean_accuracy": mean_acc,
        "std_accuracy": std_acc,
        "baseline_accuracy": homo_acc,
        "hgnn_advantage_pp": mean_acc - homo_acc if homo_acc is not None else None,
    }
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(stats, f, indent=2)
    logger.info(f"Stats saved to {OUTPUT_PATH}")
    return stats


if __name__ == '__main__':
    run()
