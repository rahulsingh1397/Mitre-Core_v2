import pandas as pd
import json
import os
from pathlib import Path
import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

# Phase B: Linux-APT evaluation
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.correlation_indexer import enhanced_correlation
from hgnn.hgnn_correlation import HGNNCorrelationEngine
from evaluation.attck_f1 import evaluate_attck_f1

def evaluate_clusters(pred_clusters, true_labels):
    return {
        "ARI": adjusted_rand_score(true_labels, pred_clusters),
        "NMI": normalized_mutual_info_score(true_labels, pred_clusters)
    }

def run_linux_apt_experiments():
    dataset_path = Path("E:/Private/MITRE-CORE 2/MITRE-CORE/datasets/Linux_APT/mitre_format.parquet")
    if not dataset_path.exists():
        print(f"Error: Could not find dataset at {dataset_path}")
        return

    print("Loading simulated Linux APT data...")
    df = pd.read_parquet(dataset_path)
    
    print(f"Sample size: {len(df)}")
    
    # Ground truth labels for clustering evaluation (group by campaign)
    ground_truth = pd.Categorical(df['campaign']).codes
    num_classes = len(np.unique(ground_truth))
    
    # B1: Baseline (Union-Find)
    print("\n--- EXPERIMENT B1: Baseline (Union-Find) ---")
    uf_df = enhanced_correlation(
        df, 
        usernames=['SourceUserName', 'DestinationUserName'], 
        addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
        use_temporal=True, # Temporal is relevant for synthetic APT sequences
        use_adaptive_threshold=True,
        use_subnet_blocking=True
    )
    uf_eval = evaluate_clusters(uf_df['pred_cluster'], ground_truth)
    print(f"Union-Find ARI: {uf_eval['ARI']:.4f}, NMI: {uf_eval['NMI']:.4f}")
    
    # Calculate ATT&CK F1 for UF
    # Let's map predicted clusters to the true campaigns they most overlap with to measure F1
    # Simple heuristic: For each predicted cluster, find the true campaign that forms the majority of it.
    
    # Group tactics by campaign
    true_campaign_tactics = df.groupby('campaign')['MalwareIntelAttackType'].apply(list).to_dict()
    
    # Calculate average F1 across the main APT campaigns
    uf_f1_scores = []
    for campaign_name in ['APT_Campaign_1', 'APT_Campaign_2']:
        campaign_indices = df[df['campaign'] == campaign_name].index
        if len(campaign_indices) == 0: continue
        
        # Which cluster captured most of this campaign?
        dominant_cluster = uf_df.loc[campaign_indices, 'pred_cluster'].mode()[0]
        
        # What tactics were in that cluster?
        pred_tactics = uf_df[uf_df['pred_cluster'] == dominant_cluster]['MalwareIntelAttackType'].tolist()
        true_tactics = true_campaign_tactics[campaign_name]
        
        _, _, f1 = evaluate_attck_f1(true_tactics, pred_tactics)
        uf_f1_scores.append(f1)
        
    uf_avg_f1 = np.mean(uf_f1_scores) if uf_f1_scores else 0
    print(f"Union-Find ATT&CK F1: {uf_avg_f1:.4f}")
        
    # B2: Zero-shot transfer (Using UNSW checkpoint)
    print("\n--- EXPERIMENT B2: Zero-shot HGNN (UNSW Checkpoint) ---")
    unsw_ckpt = Path("E:/Private/MITRE-CORE 2/MITRE-CORE/hgnn_checkpoints/unsw_finetuned.pt")
    # Force CPU to avoid CUDA kernel image errors on this specific GPU setup
    hgnn_engine = HGNNCorrelationEngine(hidden_dim=128, device='cpu')
    
    if unsw_ckpt.exists():
        try:
            import torch
            state_dict = torch.load(unsw_ckpt, map_location=hgnn_engine.device)
            keys_to_remove = []
            for k in state_dict.keys():
                if any(x in k for x in ['user_encoder', 'host_encoder', 'ip_encoder', 'device_encoder', 'gateway_encoder', 'sensor_type_encoder', 'process_encoder', 'command_line_encoder']):
                    keys_to_remove.append(k)
                    
            for k in keys_to_remove:
                del state_dict[k]
                
            hgnn_engine.model.load_state_dict(state_dict, strict=False)
            print("Loaded UNSW checkpoint (strict=False, removed dynamic entity encoders)")
        except Exception as e:
            print(f"Failed to load checkpoint: {e}")
            
    hgnn_df = hgnn_engine.correlate(df)
    hgnn_eval = evaluate_clusters(hgnn_df['pred_cluster'], ground_truth)
    print(f"HGNN Zero-Shot ARI: {hgnn_eval['ARI']:.4f}, NMI: {hgnn_eval['NMI']:.4f}")
    
    hgnn_f1_scores = []
    for campaign_name in ['APT_Campaign_1', 'APT_Campaign_2']:
        campaign_indices = df[df['campaign'] == campaign_name].index
        if len(campaign_indices) == 0: continue
        dominant_cluster = hgnn_df.loc[campaign_indices, 'pred_cluster'].mode()[0]
        pred_tactics = hgnn_df[hgnn_df['pred_cluster'] == dominant_cluster]['MalwareIntelAttackType'].tolist()
        true_tactics = true_campaign_tactics[campaign_name]
        _, _, f1 = evaluate_attck_f1(true_tactics, pred_tactics)
        hgnn_f1_scores.append(f1)
        
    hgnn_avg_f1 = np.mean(hgnn_f1_scores) if hgnn_f1_scores else 0
    print(f"HGNN Zero-Shot ATT&CK F1: {hgnn_avg_f1:.4f}")
    
    # Save results
    results = [
        {"method": "Union-Find", "ARI": uf_eval['ARI'], "NMI": uf_eval['NMI'], "ATT&CK_F1": float(uf_avg_f1)},
        {"method": "HGNN (Zero-shot)", "ARI": hgnn_eval['ARI'], "NMI": hgnn_eval['NMI'], "ATT&CK_F1": float(hgnn_avg_f1)}
    ]
    
    with open("E:/Private/MITRE-CORE 2/MITRE-CORE/experiments/results/experiment_linux_apt.json", "w") as f:
        json.dump(results, f, indent=4)
        
    print("\nLinux-APT experiments complete!")

if __name__ == "__main__":
    run_linux_apt_experiments()
