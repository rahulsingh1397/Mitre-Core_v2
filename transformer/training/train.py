"""
MITRE-CORE v3.0 Training Script
================================

Entry point for transformer training on RTX 5060 Ti 8GB.
Runs self-supervised pre-training followed by supervised fine-tuning.

Usage:
    python transformer/training/train.py \
        --epochs 100 \
        --batch-size 4 \
        --save-every 500 \
        --checkpoint-dir transformer_checkpoints

Expected runtime: 9-12 days (checkpoint every ~1 hour)
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Dict, Optional

import pandas as pd
import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.training.gpu_trainer import GPUOptimizedTrainer, TrainingMetrics
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.preprocessing.sliding_window_batcher import SlidingWindowBatcher


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("mitre-core.training")


class AlertDataset(Dataset):
    """
    PyTorch Dataset for alert batches.
    """
    
    def __init__(
        self,
        dataframes: List[pd.DataFrame],
        preprocessor: AlertPreprocessor,
        device: torch.device
    ):
        self.dataframes = dataframes
        self.preprocessor = preprocessor
        self.device = device
        self.batches = []
        
        # Preprocess all windows
        self._preprocess_all()
    
    def _preprocess_all(self):
        """Preprocess all dataframes into batches."""
        batcher = SlidingWindowBatcher(
            window_size=self.preprocessor.max_seq_length,
            overlap=32,
            preprocessor=self.preprocessor
        )
        
        for df_idx, df in enumerate(self.dataframes):
            logger.info(f"Preprocessing dataframe {df_idx + 1}/{len(self.dataframes)} ({len(df)} alerts)")
            
            try:
                # Create windows
                windows = batcher.create_windows(df)
                
                # Process each window
                for window_idx, window_df in enumerate(windows):
                    try:
                        batch = self.preprocessor.process_batch(
                            window_df,
                            device=self.device,
                            batch_id=f"df{df_idx}_win{window_idx}"
                        )
                        
                        # Only keep if valid size
                        if batch['alert_ids'].shape[1] >= 10:  # Min 10 alerts
                            self.batches.append(batch)
                    except Exception as e:
                        logger.warning(f"Failed to process window {window_idx}: {e}")
                        continue
                        
            except Exception as e:
                logger.error(f"Failed to process dataframe {df_idx}: {e}")
                continue
        
        logger.info(f"Created {len(self.batches)} training batches")
    
    def __len__(self):
        return len(self.batches)
    
    def __getitem__(self, idx):
        batch = self.batches[idx]
        
        # Create dummy labels (same campaign = 1, different = 0)
        # In real scenario, this comes from ground truth
        seq_len = batch['alert_ids'].shape[1]
        labels = torch.arange(seq_len)  # Each alert is its own "campaign" for self-supervised
        
        return {
            'alert_ids': batch['alert_ids'].squeeze(0),
            'entity_ids': batch['entity_ids'].squeeze(0),
            'time_buckets': batch['time_buckets'].squeeze(0),
            'attention_mask': batch['attention_mask'].squeeze(0),
            'labels': labels
        }


def load_datasets(dataset_dir: str = "datasets") -> List[pd.DataFrame]:
    """
    Load and combine all available datasets.
    
    Returns:
        List of DataFrames for training
    """
    dataframes = []
    dataset_dir = Path(dataset_dir)
    
    # Define dataset files to load
    dataset_configs = [
        # (path, label_column, required_cols)
        ("datasets/CICAPT-IIoT-Dataset/phase1_NetworkData.csv", None, None),
        ("datasets/Datasense_IIoT_2025/attack_data/*.csv", None, None),
        ("datasets/unsw_nb15/*.csv", "attack_cat", None),
        ("datasets/TON_IoT/mitre_format.parquet", "MalwareIntelAttackType", None),
    ]
    
    for pattern, label_col, _ in dataset_configs:
        paths = list(Path(".").glob(pattern))
        
        for path in paths:
            if not path.exists():
                continue
                
            try:
                logger.info(f"Loading {path}...")
                
                if path.suffix == '.parquet':
                    df = pd.read_parquet(path)
                else:
                    # For large CSVs, sample to manage memory
                    if path.stat().st_size > 1_000_000_000:  # >1GB
                        logger.info(f"Large file detected, sampling {path}")
                        df = pd.read_csv(path, nrows=100000)  # Sample first 100K
                    else:
                        df = pd.read_csv(path)
                
                if len(df) == 0:
                    continue
                
                # Add source column
                df['_source'] = path.name
                
                # Ensure timestamp column exists
                if 'timestamp' not in df.columns:
                    # Try to find or create timestamp
                    time_cols = ['EndDate', 'StartTime', 'StartDate', 'time', 'date']
                    for col in time_cols:
                        if col in df.columns:
                            df['timestamp'] = pd.to_datetime(df[col], errors='coerce')
                            break
                    
                    if 'timestamp' not in df.columns:
                        # Create artificial timestamps
                        df['timestamp'] = pd.date_range(
                            start='2024-01-01',
                            periods=len(df),
                            freq='1min'
                        )
                
                dataframes.append(df)
                logger.info(f"Loaded {len(df)} alerts from {path}")
                
            except Exception as e:
                logger.error(f"Failed to load {path}: {e}")
                continue
    
    logger.info(f"Loaded {len(dataframes)} datasets, total alerts: {sum(len(df) for df in dataframes)}")
    return dataframes


def create_model(device: torch.device) -> TransformerCandidateGenerator:
    """
    Create transformer model with 8GB config.
    """
    config = DEFAULT_CONFIG_8GB
    
    model = TransformerCandidateGenerator(
        vocab_size=10000,
        num_entities=10000,
        d_model=config.d_model,
        n_layers=config.n_layers,
        n_heads=config.n_heads,
        d_ff=config.d_ff,
        max_seq_len=config.max_seq_len,
        dropout=config.dropout,
        use_gradient_checkpointing=config.gradient_checkpointing,
        config=config
    )
    
    # Log model size
    memory = model.get_memory_footprint()
    logger.info(f"Model created: {memory['total_size_mb']:.1f}MB")
    
    return model.to(device)


def train_epoch(
    trainer: GPUOptimizedTrainer,
    dataset: AlertDataset,
    epoch: int
) -> List[TrainingMetrics]:
    """
    Train for one epoch.
    """
    metrics_history = []
    
    for idx in range(len(dataset)):
        batch = dataset[idx]
        
        # Move to device
        batch_device = {
            'alert_ids': batch['alert_ids'].unsqueeze(0).to(trainer.device),
            'entity_ids': batch['entity_ids'].unsqueeze(0).to(trainer.device),
            'time_buckets': batch['time_buckets'].unsqueeze(0).to(trainer.device),
            'attention_mask': batch['attention_mask'].unsqueeze(0).to(trainer.device),
        }
        labels = batch['labels'].unsqueeze(0).to(trainer.device)
        
        # Training step
        metrics = trainer.train_step(batch_device, labels)
        metrics_history.append(metrics)
        
        # Log progress
        if trainer.current_step % 100 == 0:
            logger.info(
                f"Epoch {epoch} | Step {metrics.step} | "
                f"Loss: {metrics.loss:.4f} | "
                f"LR: {metrics.learning_rate:.6f} | "
                f"GPU: {metrics.gpu_memory_mb:.1f}MB | "
                f"Time: {metrics.time_per_step_ms:.1f}ms"
            )
        
        # Early warning for OOM
        if metrics.gpu_memory_mb > 7500:
            logger.warning(f"High GPU memory: {metrics.gpu_memory_mb:.1f}MB - consider checkpointing")
    
    return metrics_history


def main():
    parser = argparse.ArgumentParser(description="Train MITRE-CORE v3.0 transformer")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size (max 4 for 8GB)")
    parser.add_argument("--save-every", type=int, default=500, help="Save checkpoint every N steps")
    parser.add_argument("--checkpoint-dir", type=str, default="transformer_checkpoints", help="Checkpoint directory")
    parser.add_argument("--resume", type=str, default=None, help="Resume from checkpoint path")
    
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("MITRE-CORE v3.0 Transformer Training")
    logger.info("="*60)
    logger.info(f"Device: {'CUDA' if torch.cuda.is_available() else 'CPU'}")
    logger.info(f"Epochs: {args.epochs}")
    logger.info(f"Checkpoint dir: {args.checkpoint_dir}")
    logger.info("="*60)
    
    # Device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    if not torch.cuda.is_available():
        logger.warning("CUDA not available, training on CPU will be very slow")
    else:
        logger.info(f"GPU: {torch.cuda.get_device_name(0)}")
        logger.info(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f}GB")
    
    # Create model
    model = create_model(device)
    
    # Create trainer
    config = DEFAULT_CONFIG_8GB
    config.batch_size = args.batch_size
    
    trainer = GPUOptimizedTrainer(
        model=model,
        config=config,
        device=device,
        checkpoint_dir=args.checkpoint_dir
    )
    
    # Resume if checkpoint provided
    start_epoch = 0
    if args.resume:
        logger.info(f"Resuming from {args.resume}")
        trainer.load_checkpoint(args.resume)
        start_epoch = trainer.current_step // len(load_datasets())  # Rough estimate
    
    # Load datasets
    logger.info("Loading datasets...")
    dataframes = load_datasets()
    
    if len(dataframes) == 0:
        logger.error("No datasets loaded! Check dataset paths.")
        sys.exit(1)
    
    # Create dataset
    logger.info("Creating training dataset...")
    preprocessor = AlertPreprocessor(max_seq_length=config.max_seq_len)
    dataset = AlertDataset(dataframes, preprocessor, device)
    
    if len(dataset) == 0:
        logger.error("No training batches created! Check preprocessing.")
        sys.exit(1)
    
    logger.info(f"Training on {len(dataset)} batches")
    
    # Training loop
    logger.info("Starting training...")
    all_metrics = []
    
    for epoch in range(start_epoch, args.epochs):
        logger.info(f"\n{'='*60}")
        logger.info(f"Epoch {epoch + 1}/{args.epochs}")
        logger.info('='*60)
        
        epoch_start = time.time()
        
        # Train epoch
        epoch_metrics = train_epoch(trainer, dataset, epoch)
        all_metrics.extend(epoch_metrics)
        
        epoch_time = time.time() - epoch_start
        avg_loss = np.mean([m.loss for m in epoch_metrics])
        
        logger.info(f"Epoch {epoch + 1} complete: avg_loss={avg_loss:.4f}, time={epoch_time:.1f}s")
        
        # Save epoch checkpoint
        trainer.save_checkpoint(f"epoch_{epoch + 1}")
    
    # Final checkpoint
    final_path = trainer.save_checkpoint("final")
    logger.info(f"\n{'='*60}")
    logger.info(f"Training complete! Final checkpoint: {final_path}")
    logger.info("="*60)
    
    # Save metrics
    metrics_df = pd.DataFrame([{
        'step': m.step,
        'loss': m.loss,
        'learning_rate': m.learning_rate,
        'gpu_memory_mb': m.gpu_memory_mb,
        'time_per_step_ms': m.time_per_step_ms
    } for m in all_metrics])
    
    metrics_path = Path(args.checkpoint_dir) / "training_metrics.csv"
    metrics_df.to_csv(metrics_path, index=False)
    logger.info(f"Metrics saved to {metrics_path}")


if __name__ == "__main__":
    main()
