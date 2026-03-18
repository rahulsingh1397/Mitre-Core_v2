"""
Debug training pipeline to identify all bugs
"""

import torch
import pandas as pd
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transformer.training.train_cybertransformer import load_datasets, AlertDataset, create_model
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB

def debug_training_pipeline():
    print("="*70)
    print("TRAINING PIPELINE DEBUG")
    print("="*70)
    
    # 1. Check dataset loading
    print("\n1. DATASET LOADING")
    print("-"*70)
    dataframes = load_datasets()
    print(f"Loaded {len(dataframes)} dataframes")
    total_alerts = 0
    for i, df in enumerate(dataframes):
        print(f"  DataFrame {i}: {len(df)} alerts, columns: {list(df.columns[:5])}...")
        total_alerts += len(df)
    print(f"\nTotal alerts: {total_alerts}")
    
    if total_alerts == 0:
        print("ERROR: No alerts loaded!")
        return
    
    # 2. Check batch creation
    print("\n2. BATCH CREATION")
    print("-"*70)
    device = torch.device('cpu')
    preprocessor = AlertPreprocessor(max_seq_length=256)
    dataset = AlertDataset(dataframes, preprocessor, device)
    print(f"Created {len(dataset)} batches")
    
    if len(dataset) == 0:
        print("ERROR: No batches created!")
        return
    
    # 3. Check a single batch
    print("\n3. BATCH INSPECTION")
    print("-"*70)
    batch = dataset[0]
    print(f"Batch keys: {batch.keys()}")
    for key, tensor in batch.items():
        if isinstance(tensor, torch.Tensor):
            print(f"  {key}: shape={tensor.shape}, dtype={tensor.dtype}")
    
    # 4. Check labels
    print("\n4. LABEL ANALYSIS")
    print("-"*70)
    labels = batch['labels']
    print(f"Labels shape: {labels.shape}")
    print(f"Labels unique values: {torch.unique(labels).tolist()}")
    print(f"Labels value counts: {torch.bincount(labels)}")
    
    # Check if we have both positive and negative pairs
    labels_2d = labels.unsqueeze(0)  # Add batch dimension [1, seq_len]
    pos_mask = (labels_2d.unsqueeze(1) == labels_2d.unsqueeze(2)).float()
    neg_mask = 1 - pos_mask
    print(f"\nPositive pair ratio: {pos_mask.sum().item() / pos_mask.numel():.3f}")
    print(f"Negative pair ratio: {neg_mask.sum().item() / neg_mask.numel():.3f}")
    
    # 5. Test forward pass
    print("\n5. MODEL FORWARD PASS")
    print("-"*70)
    model = create_model(DEFAULT_CONFIG_8GB, device)
    model.eval()
    
    with torch.no_grad():
        outputs = model(
            alert_ids=batch['alert_ids'].unsqueeze(0),
            entity_ids=batch['entity_ids'].unsqueeze(0),
            time_buckets=batch['time_buckets'].unsqueeze(0),
            attention_mask=batch['attention_mask'].unsqueeze(0),
            return_candidates=False
        )
    
    affinity_matrix = outputs['affinity_matrix']
    print(f"Affinity matrix shape: {affinity_matrix.shape}")
    print(f"Affinity range: [{affinity_matrix.min():.3f}, {affinity_matrix.max():.3f}]")
    print(f"Affinity mean: {affinity_matrix.mean():.3f}")
    
    # 6. Test loss computation
    print("\n6. LOSS COMPUTATION")
    print("-"*70)
    from transformer.training.gpu_trainer import GPUOptimizedTrainer
    
    # Use the labels from the batch (already alternating 0,1), add batch dimension
    labels_alt = batch['labels'].unsqueeze(0)  # [1, seq_len]
    
    trainer = GPUOptimizedTrainer(model, DEFAULT_CONFIG_8GB, device, checkpoint_dir="debug_ckpt")
    loss = trainer._compute_contrastive_loss(affinity_matrix, labels_alt.to(device))
    print(f"Loss value: {loss.item():.6f}")
    print(f"Expected initial loss: ~0.693 (ln(2) for random guessing)")
    
    # 7. Check if gradients flow
    print("\n7. GRADIENT FLOW TEST")
    print("-"*70)
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
    
    # Forward pass
    outputs = model(
        alert_ids=batch['alert_ids'].unsqueeze(0),
        entity_ids=batch['entity_ids'].unsqueeze(0),
        time_buckets=batch['time_buckets'].unsqueeze(0),
        attention_mask=batch['attention_mask'].unsqueeze(0),
        return_candidates=False
    )
    
    affinity_matrix = outputs['affinity_matrix']
    loss = trainer._compute_contrastive_loss(affinity_matrix, labels_alt.to(device))
    
    # Backward pass
    optimizer.zero_grad()
    loss.backward()
    
    # Check gradients
    has_gradients = False
    grad_norms = []
    for name, param in model.named_parameters():
        if param.grad is not None:
            grad_norm = param.grad.norm().item()
            grad_norms.append((name, grad_norm))
            if grad_norm > 0:
                has_gradients = True
    
    print(f"Parameters with gradients: {len(grad_norms)}")
    print(f"Has non-zero gradients: {has_gradients}")
    
    # Show top 5 gradient norms
    grad_norms.sort(key=lambda x: x[1], reverse=True)
    print("\nTop 5 gradient norms:")
    for name, norm in grad_norms[:5]:
        print(f"  {name}: {norm:.6f}")
    
    # 8. Training step test
    print("\n8. TRAINING STEP TEST")
    print("-"*70)
    
    batch_device = {
        'alert_ids': batch['alert_ids'].unsqueeze(0).to(device),
        'entity_ids': batch['entity_ids'].unsqueeze(0).to(device),
        'time_buckets': batch['time_buckets'].unsqueeze(0).to(device),
        'attention_mask': batch['attention_mask'].unsqueeze(0).to(device),
    }
    
    # Get initial parameter values
    initial_params = {name: param.clone() for name, param in model.named_parameters()}
    
    # Do 10 training steps
    losses = []
    for i in range(10):
        metrics = trainer.train_step(batch_device, labels_alt.to(device))
        losses.append(metrics.loss)
    
    print(f"Losses over 10 steps: {[f'{l:.6f}' for l in losses]}")
    
    # Check if parameters changed
    changed_params = 0
    for name, param in model.named_parameters():
        if initial_params[name] is not None and param is not None:
            diff = (param - initial_params[name]).abs().max().item()
            if diff > 1e-7:
                changed_params += 1
    
    print(f"\nParameters changed: {changed_params}/{len(list(model.parameters()))}")
    
    if changed_params == 0:
        print("ERROR: No parameters changed - model is not learning!")
    
    print("\n" + "="*70)
    print("DEBUG COMPLETE")
    print("="*70)

if __name__ == "__main__":
    debug_training_pipeline()
