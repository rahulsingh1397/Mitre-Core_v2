"""
Test training with proper optimizer stepping
"""

import torch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transformer.training.train_cybertransformer import AlertDataset, create_model, load_datasets
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB
from transformer.training.gpu_trainer import GPUOptimizedTrainer

def test_training():
    print("="*70)
    print("TRAINING TEST WITH PROPER STEPPING")
    print("="*70)
    
    device = torch.device('cpu')
    
    # Load minimal data
    print("\n1. Loading dataset...")
    dataframes = load_datasets()
    preprocessor = AlertPreprocessor(max_seq_length=256)
    dataset = AlertDataset(dataframes[:2], preprocessor, device)  # Just 2 dataframes for speed
    print(f"   {len(dataset)} batches")
    
    # Create model
    print("\n2. Creating model...")
    model = create_model(DEFAULT_CONFIG_8GB, device)
    
    # Create trainer with accumulation_steps=4 (faster testing)
    print("\n3. Creating trainer (accumulation_steps=4)...")
    config = DEFAULT_CONFIG_8GB
    config.accumulation_steps = 4  # Smaller for testing
    config.batch_size = 1
    
    trainer = GPUOptimizedTrainer(model, config, device, checkpoint_dir="test_ckpt")
    
    # Get initial parameters
    initial_params = {name: param.clone().detach() for name, param in model.named_parameters()}
    
    # Run 20 training steps (should include 5 optimizer steps with accumulation=4)
    print("\n4. Running 20 training steps...")
    losses = []
    
    for i in range(20):
        batch = dataset[i % len(dataset)]
        
        batch_device = {
            'alert_ids': batch['alert_ids'].unsqueeze(0).to(device),
            'entity_ids': batch['entity_ids'].unsqueeze(0).to(device),
            'time_buckets': batch['time_buckets'].unsqueeze(0).to(device),
            'attention_mask': batch['attention_mask'].unsqueeze(0).to(device),
        }
        labels = batch['labels'].unsqueeze(0).to(device)
        
        metrics = trainer.train_step(batch_device, labels)
        losses.append(metrics.loss)
        
        if (i + 1) % 4 == 0:
            print(f"   Step {i+1}: loss={metrics.loss:.4f}, lr={metrics.learning_rate:.6f}")
    
    # Check if parameters changed
    print("\n5. Checking parameter changes...")
    changed_count = 0
    max_change = 0
    for name, param in model.named_parameters():
        if name in initial_params:
            change = (param - initial_params[name]).abs().max().item()
            max_change = max(max_change, change)
            if change > 1e-7:
                changed_count += 1
    
    print(f"   Parameters changed: {changed_count}/{len(initial_params)}")
    print(f"   Max parameter change: {max_change:.8f}")
    
    # Check loss trend
    print("\n6. Loss trend analysis...")
    first_5_avg = sum(losses[:5]) / 5
    last_5_avg = sum(losses[-5:]) / 5
    print(f"   First 5 steps avg: {first_5_avg:.4f}")
    print(f"   Last 5 steps avg: {last_5_avg:.4f}")
    
    if last_5_avg < first_5_avg:
        print(f"   LOSS DECREASING: {first_5_avg:.4f} -> {last_5_avg:.4f} ✓")
    else:
        print(f"   WARNING: Loss not decreasing ({first_5_avg:.4f} -> {last_5_avg:.4f})")
    
    # Summary
    print("\n" + "="*70)
    if changed_count > 0 and last_5_avg < first_5_avg:
        print("SUCCESS: Training is working! Model is learning.")
    elif changed_count == 0:
        print("FAILED: No parameters changed - optimizer not stepping!")
    else:
        print("WARNING: Parameters changed but loss not decreasing")
    print("="*70)

if __name__ == "__main__":
    test_training()
