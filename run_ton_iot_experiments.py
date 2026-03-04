import pandas as pd
import json
import os
from pathlib import Path
import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

# A1, A2, A3 on TON_IoT (mitre_format.parquet)
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.correlation_indexer import enhanced_correlation
from hgnn.hgnn_correlation import HGNNCorrelationEngine

def evaluate_clusters(pred_clusters, true_labels):
    return {
        "ARI": adjusted_rand_score(true_labels, pred_clusters),
        "NMI": normalized_mutual_info_score(true_labels, pred_clusters)
    }

def run_ton_iot_experiments():
    ton_iot_path = Path("E:/Private/MITRE-CORE 2/MITRE-CORE/datasets/TON_IoT/mitre_format.parquet")
    if not ton_iot_path.exists():
        print(f"Error: Could not find dataset at {ton_iot_path}")
        return

    print("Loading TON_IoT mapped data...")
    df = pd.read_parquet(ton_iot_path)
    
    # Stratified sample of 500 records
    print(f"Taking stratified sample of n=500 from {len(df)} records...")
    if len(df) > 500:
        # Stratify by category or attack type
        try:
            sample_df = df.groupby('MalwareIntelAttackType', group_keys=False).apply(lambda x: x.sample(min(len(x), max(1, int(500 * len(x)/len(df))))))
            if len(sample_df) < 500:
                remaining = 500 - len(sample_df)
                others = df.drop(sample_df.index).sample(remaining)
                sample_df = pd.concat([sample_df, others])
        except Exception as e:
            print(f"Stratified sampling failed: {e}. Falling back to random sample.")
            sample_df = df.sample(500, random_state=42)
    else:
        sample_df = df
        
    sample_df = sample_df.reset_index(drop=True)
    # Give them unique AlertIds
    sample_df['AlertId'] = [f"TON_{i}" for i in range(len(sample_df))]
    
    print(f"Sample size: {len(sample_df)}")
    
    # Ground truth labels for evaluation
    ground_truth = pd.Categorical(sample_df['MalwareIntelAttackType']).codes
    num_classes = max(10, len(np.unique(ground_truth)))
    
    # Experiment A1: All-methods comparison (Subset: just UF vs HGNN for this phase script)
    print("\n--- EXPERIMENT A1: Baseline (Union-Find) ---")
    uf_df = enhanced_correlation(
        sample_df, 
        usernames=['SourceUserName', 'DestinationUserName'], 
        addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
        use_temporal=False, # Must be False per critical constraints
        use_adaptive_threshold=True,
        use_subnet_blocking=True
    )
    uf_eval = evaluate_clusters(uf_df['pred_cluster'], ground_truth)
    print(f"Union-Find ARI: {uf_eval['ARI']:.4f}, NMI: {uf_eval['NMI']:.4f}")
    
    with open("E:/Private/MITRE-CORE 2/MITRE-CORE/experiments/results/experiment_toniot_a1.json", "w") as f:
        json.dump([
            {"method": "Union-Find", **uf_eval}
        ], f, indent=4)
        
    # Experiment A2: Zero-shot transfer (Using UNSW checkpoint)
    print("\n--- EXPERIMENT A2: Zero-shot HGNN (UNSW Checkpoint) ---")
    unsw_ckpt = Path("E:/Private/MITRE-CORE 2/MITRE-CORE/hgnn_checkpoints_unsw/unsw_finetuned.pt")
    # Force CPU to avoid CUDA kernel image errors on this specific GPU setup
    hgnn_engine = HGNNCorrelationEngine(hidden_dim=64, device='cpu')
    
    if unsw_ckpt.exists():
        try:
            # We skip loading the checkpoint if it causes dimension mismatch due to schema extension
            # In PyTorch, we can load with strict=False
            import torch
            state_dict = torch.load(unsw_ckpt, map_location=hgnn_engine.device)
            
            # Filter out entity encoders because their input dims depend on the number of unique entities (torch.eye(N))
            # The LazyLinear will re-initialize them for the new graph size on the first forward pass
            keys_to_remove = []
            for k in state_dict.keys():
                if any(x in k for x in ['user_encoder', 'host_encoder', 'ip_encoder', 'device_encoder', 'gateway_encoder', 'sensor_type_encoder']):
                    keys_to_remove.append(k)
                    
            for k in keys_to_remove:
                del state_dict[k]
                
            hgnn_engine.model.load_state_dict(state_dict, strict=False)
            print("Loaded UNSW checkpoint (strict=False, removed dynamic entity encoders)")
        except Exception as e:
            print(f"Failed to load checkpoint: {e}")
    else:
        print(f"Checkpoint not found at {unsw_ckpt}")
    
    hgnn_df = hgnn_engine.correlate(sample_df)
    hgnn_eval = evaluate_clusters(hgnn_df['pred_cluster'], ground_truth)
    print(f"HGNN Zero-Shot ARI: {hgnn_eval['ARI']:.4f}, NMI: {hgnn_eval['NMI']:.4f}")
    
    with open("E:/Private/MITRE-CORE 2/MITRE-CORE/experiments/results/experiment_toniot_a2_zeroshot.json", "w") as f:
        json.dump({
            "dataset": "TON_IoT",
            "setting": "zero-shot",
            "ARI": hgnn_eval['ARI'],
            "NMI": hgnn_eval['NMI']
        }, f, indent=4)
        
    # Experiment A3: Fine-tuned
    print("\n--- EXPERIMENT A3: Fine-tuned HGNN ---")
    print("Fine-tuning on 20% TON_IoT, testing on 80%...")
    
    import torch
    import torch.nn.functional as F
    from torch_geometric.data import HeteroData
    
    data = hgnn_engine.converter.convert(sample_df).to(hgnn_engine.device)
    labels = torch.tensor(ground_truth, dtype=torch.long).to(hgnn_engine.device)
    
    # Masking for train/test
    indices = np.random.permutation(len(sample_df))
    split = int(0.2 * len(sample_df))
    train_idx = indices[:split]
    test_idx = indices[split:]
    
    # Freeze encoder
    for param in hgnn_engine.model.parameters():
        param.requires_grad = False
    
    # Only train classifier head
    for param in hgnn_engine.model.cluster_classifier.parameters():
        param.requires_grad = True
        
    # Also train the new encoders since they weren't in the UNSW dataset
    for param in hgnn_engine.model.device_encoder.parameters():
        param.requires_grad = True
    for param in hgnn_engine.model.gateway_encoder.parameters():
        param.requires_grad = True
    for param in hgnn_engine.model.sensor_type_encoder.parameters():
        param.requires_grad = True
        
    optimizer = torch.optim.Adam(
        filter(lambda p: p.requires_grad, hgnn_engine.model.parameters()), 
        lr=5e-4
    )
    
    hgnn_engine.model.train()
    for epoch in range(5): # 5 epochs as per instructions
        optimizer.zero_grad()
        out, _ = hgnn_engine.model(data)
        
        # We assume out represents cluster logits, but for fine-tuning we can map to attack types or clustering proxy
        # Since we don't have true clusters, we fine-tune using attack types as proxy labels
        loss = F.cross_entropy(out[train_idx], labels[train_idx])
        loss.backward()
        optimizer.step()
        print(f"Epoch {epoch+1}/5 - Loss: {loss.item():.4f}")
        
    hgnn_engine.model.eval()
    with torch.no_grad():
        out, _ = hgnn_engine.model(data)
        pred_clusters = torch.argmax(out, dim=1).cpu().numpy()
        
    # Evaluate on test set
    test_preds = pred_clusters[test_idx]
    test_true = ground_truth[test_idx]
    
    test_eval = evaluate_clusters(test_preds, test_true)
    print(f"HGNN Fine-Tuned ARI: {test_eval['ARI']:.4f}, NMI: {test_eval['NMI']:.4f}")
    
    # Update A1 results with Fine-tuned model for paper replacement
    with open("E:/Private/MITRE-CORE 2/MITRE-CORE/experiments/results/experiment_toniot_a1.json", "r") as f:
        a1_results = json.load(f)
        
    a1_results.append({"method": "HGNN (Fine-tuned)", **test_eval})
    
    with open("E:/Private/MITRE-CORE 2/MITRE-CORE/experiments/results/experiment_toniot_a1.json", "w") as f:
        json.dump(a1_results, f, indent=4)
        
    with open("E:/Private/MITRE-CORE 2/MITRE-CORE/experiments/results/experiment_toniot_a3_finetune.json", "w") as f:
        json.dump({
            "dataset": "TON_IoT",
            "setting": "fine-tuned",
            "ARI": test_eval['ARI'],
            "NMI": test_eval['NMI']
        }, f, indent=4)
        
    print("\nTON_IoT experiments complete!")

if __name__ == "__main__":
    run_ton_iot_experiments()
