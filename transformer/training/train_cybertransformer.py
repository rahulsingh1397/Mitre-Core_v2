"""
CyberTransformer Training Script v2
=====================================

Fixed NaN issues with:
- Lower learning rate (5e-5 vs 1e-4)
- Better gradient clipping
- Input validation
- Optional AMP disable for debugging
- Comprehensive hyperparameter logging

Usage:
    python transformer/training/train_cybertransformer.py \
        --epochs 100 \
        --lr 5e-5 \
        --no-amp \
        --checkpoint-dir cybertransformer_checkpoints
"""

import argparse
import logging
import sys
import time
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

import pandas as pd
import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
from torch.amp import autocast

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator, create_model
from transformer.training.gpu_trainer import GPUOptimizedTrainer, TrainingMetrics
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.preprocessing.sliding_window_batcher import SlidingWindowBatcher


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cybertransformer_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("cybertransformer.training")


def load_datasets_from_registry(dataset_names: Optional[List[str]] = None, sample_size: int = 10000) -> List[pd.DataFrame]:
    """
    Load datasets using the centralized dataset registry.
    
    Args:
        dataset_names: List of dataset names to load. If None, loads all available.
        sample_size: Number of rows to sample per dataset (for memory management)
    
    Returns:
        List of DataFrames for training
    """
    from scripts.dataset_registry import get_all_datasets, load_dataset
    
    dataframes = []
    
    if dataset_names is None:
        # Load all available datasets from registry
        dataset_names = list(get_all_datasets().keys())
    
    for name in dataset_names:
        logger.info(f"Loading dataset: {name}")
        df = load_dataset(name, sample_size=sample_size)
        
        if df is not None and len(df) > 0:
            dataframes.append(df)
            logger.info(f"  Loaded {len(df)} rows from {name}")
        else:
            logger.warning(f"  Failed to load {name} or empty")
    
    total_alerts = sum(len(df) for df in dataframes)
    logger.info(f"Loaded {len(dataframes)} datasets, total alerts: {total_alerts}")
    return dataframes


def load_datasets(dataset_dir: str = "datasets") -> List[pd.DataFrame]:
    """
    DEPRECATED: Use load_datasets_from_registry() instead.
    Kept for backward compatibility.
    """
    logger.warning("load_datasets() is deprecated. Using load_datasets_from_registry()")
    return load_datasets_from_registry()


@dataclass
class HyperparameterConfig:
    """Hyperparameter configuration with logging."""
    model_name: str = "CyberTransformer_v1"
    epochs: int = 100
    batch_size: int = 4
    learning_rate: float = 5e-5  # Reduced from 1e-4
    weight_decay: float = 0.01
    max_grad_norm: float = 0.5  # Tighter gradient clipping
    warmup_steps: int = 2000  # Increased warmup
    gradient_accumulation_steps: int = 16
    use_amp: bool = True  # Can disable for debugging
    dropout: float = 0.1
    d_model: int = 128
    n_layers: int = 2
    n_heads: int = 4
    max_seq_len: int = 256
    
    def save(self, path: Path):
        """Save config to JSON."""
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)
        logger.info(f"Hyperparameter config saved to {path}")
    
    @classmethod
    def load(cls, path: Path) -> 'HyperparameterConfig':
        """Load config from JSON."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)


class AlertDataset(Dataset):
    """PyTorch Dataset for alert batches with input validation."""
    
    MAX_ROWS_PER_DATAFRAME = 200_000  # Raised from 50K; handles UNSW-NB15 at 175K rows
    
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
        
        self._preprocess_all()
    
    def _preprocess_all(self):
        """Preprocess all dataframes into batches with validation."""
        batcher = SlidingWindowBatcher(
            window_size=self.preprocessor.max_seq_length,
            overlap=32,
            preprocessor=self.preprocessor
        )
        
        for df_idx, df in enumerate(self.dataframes):
            logger.info(f"Preprocessing dataframe {df_idx + 1}/{len(self.dataframes)} ({len(df)} alerts)")
            
            # Validate input data
            df = self._validate_dataframe(df, df_idx)
            if df is None or len(df) == 0:
                logger.warning(f"Skipping empty/invalid dataframe {df_idx}")
                continue
            
            # Apply hard cap to prevent OOM on large dataframes
            if len(df) > self.MAX_ROWS_PER_DATAFRAME:
                logger.warning(f"Dataframe {df_idx}: {len(df)} rows exceeds cap ({self.MAX_ROWS_PER_DATAFRAME}), sampling down")
                df = df.sample(n=self.MAX_ROWS_PER_DATAFRAME, random_state=42).sort_index()
            
            try:
                windows = batcher.create_windows(df)
                
                for window_idx, window_df in enumerate(windows):
                    try:
                        batch = self.preprocessor.process_batch(
                            window_df,
                            device=self.device,
                            batch_id=f"df{df_idx}_win{window_idx}"
                        )
                        
                        # Validate batch tensors
                        if self._validate_batch(batch):
                            self.batches.append(batch)
                    except Exception as e:
                        logger.warning(f"Failed to process window {window_idx}: {e}")
                        continue
                        
            except Exception as e:
                logger.error(f"Failed to process dataframe {df_idx}: {e}")
                continue
        
        logger.info(f"Created {len(self.batches)} valid training batches")
    
    def _validate_dataframe(self, df: pd.DataFrame, idx: int) -> Optional[pd.DataFrame]:
        """Validate and clean input dataframe."""
        # Check for NaN in critical columns
        critical_cols = ['timestamp', 'EndDate', 'StartTime', 'time']
        available_cols = [c for c in critical_cols if c in df.columns]
        
        if not available_cols:
            logger.warning(f"Dataframe {idx}: No timestamp columns found, creating artificial index")
            # Create artificial timestamp from index for datasets without timestamps
            df = df.copy()
            df['artificial_timestamp'] = pd.to_datetime(df.index, unit='s')
            available_cols = ['artificial_timestamp']
        
        # Check for all-NaN columns
        for col in available_cols:
            if df[col].isna().all():
                logger.warning(f"Dataframe {idx}: Column {col} is all NaN")
        
        # Remove rows with no timestamp at all
        df_clean = df.dropna(subset=available_cols, how='all')
        
        if len(df_clean) < 10:
            logger.warning(f"Dataframe {idx}: Too few valid rows ({len(df_clean)})")
            return None
        
        return df_clean
    
    def _validate_batch(self, batch: Dict) -> bool:
        """Validate batch tensors for NaN/Inf."""
        for key, tensor in batch.items():
            if isinstance(tensor, torch.Tensor):
                if torch.isnan(tensor).any():
                    logger.warning(f"Batch contains NaN in {key}")
                    return False
                if torch.isinf(tensor).any():
                    logger.warning(f"Batch contains Inf in {key}")
                    return False
        
        # Check minimum size
        if batch['alert_ids'].shape[1] < 10:
            return False
        
        return True
    
    def __len__(self):
        return len(self.batches)
    
    def __getitem__(self, idx):
        batch = self.batches[idx]
        
        # Use real campaign labels from the dataframe (extracted by preprocessor)
        # These are now properly passed through instead of synthetic alternating labels
        labels = batch['campaign_labels'].squeeze(0) if batch['campaign_labels'].dim() > 1 else batch['campaign_labels']
        
        return {
            'alert_ids': batch['alert_ids'].squeeze(0),
            'entity_ids': batch['entity_ids'].squeeze(0),
            'time_buckets': batch['time_buckets'].squeeze(0),
            'attention_mask': batch['attention_mask'].squeeze(0),
            'labels': labels
        }


def train_epoch(
    trainer: GPUOptimizedTrainer,
    dataset: AlertDataset,
    train_indices: List[int],
    epoch: int,
    config: HyperparameterConfig
) -> List[TrainingMetrics]:
    """Train for one epoch with NaN detection."""
    metrics_history = []
    nan_count = 0
    
    for idx in train_indices:
        batch = dataset[idx]
        
        batch_device = {
            'alert_ids': batch['alert_ids'].unsqueeze(0).to(trainer.device),
            'entity_ids': batch['entity_ids'].unsqueeze(0).to(trainer.device),
            'time_buckets': batch['time_buckets'].unsqueeze(0).to(trainer.device),
            'attention_mask': batch['attention_mask'].unsqueeze(0).to(trainer.device),
        }
        # Use real campaign labels from dataset (extracted from dataframe by preprocessor)
        labels = batch['labels'].unsqueeze(0).to(trainer.device)
        
        metrics = trainer.train_step(batch_device, labels)
        metrics_history.append(metrics)
        
        # Detect NaN
        if np.isnan(metrics.loss):
            nan_count += 1
            if nan_count <= 5:  # Log first few NaNs
                logger.error(f"NaN detected at step {metrics.step}! LR={metrics.learning_rate:.6f}")
            if nan_count > 10:
                logger.critical(f"Too many NaNs ({nan_count}), stopping epoch")
                break
        
        if trainer.current_step % 100 == 0:
            status = "OK" if not np.isnan(metrics.loss) else "NaN"
            logger.info(
                f"Epoch {epoch} {status} | Step {metrics.step} | "
                f"Loss: {metrics.loss:.4f} | LR: {metrics.learning_rate:.6f} | "
                f"GPU: {metrics.gpu_memory_mb:.1f}MB"
            )
    
    return metrics_history


def validate_epoch(
    trainer: GPUOptimizedTrainer,
    dataset: AlertDataset,
    val_indices: List[int]
) -> float:
    """Validate on validation set."""
    trainer.model.eval()
    total_loss = 0.0
    num_batches = 0
    
    with torch.no_grad():
        for idx in val_indices:
            batch = dataset[idx]
            
            batch_device = {
                'alert_ids': batch['alert_ids'].unsqueeze(0).to(trainer.device),
                'entity_ids': batch['entity_ids'].unsqueeze(0).to(trainer.device),
                'time_buckets': batch['time_buckets'].unsqueeze(0).to(trainer.device),
                'attention_mask': batch['attention_mask'].unsqueeze(0).to(trainer.device),
            }
            labels = batch['labels'].unsqueeze(0).to(trainer.device)
            
            # Forward pass
            with autocast('cuda', enabled=trainer.use_amp):
                outputs = trainer.model(
                    alert_ids=batch_device['alert_ids'],
                    entity_ids=batch_device['entity_ids'],
                    time_buckets=batch_device['time_buckets'],
                    attention_mask=batch_device['attention_mask'],
                    return_candidates=False
                )
                affinity_matrix = outputs['affinity_matrix'].float()
                loss = trainer._compute_contrastive_loss(affinity_matrix, labels)
            
            total_loss += loss.item()
            num_batches += 1
    
    trainer.model.train()
    return total_loss / num_batches if num_batches > 0 else float('inf')


def main():
    parser = argparse.ArgumentParser(description="Train CyberTransformer")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--lr", type=float, default=5e-5, help="Learning rate (default: 5e-5)")
    parser.add_argument("--no-amp", action="store_true", help="Disable mixed precision")
    parser.add_argument("--save-every", type=int, default=500)
    parser.add_argument("--checkpoint-dir", type=str, default="cybertransformer_checkpoints")
    parser.add_argument("--resume", type=str, default=None)
    parser.add_argument("--datasets", nargs="+", default=None, 
                      help="Dataset names to use (e.g., CICIoV2024 Datasense_IIoT_2025). If not specified, uses all available.")
    parser.add_argument("--sample-size", type=int, default=10000,
                      help="Number of rows to sample per dataset (default: 10000)")
    
    args = parser.parse_args()
    
    # Create hyperparameter config
    hparams = HyperparameterConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        use_amp=not args.no_amp
    )
    
    # Setup checkpoint directory
    checkpoint_dir = Path(args.checkpoint_dir)
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    # Save hyperparameters
    hparams.save(checkpoint_dir / "hyperparameters.json")
    
    logger.info("="*70)
    logger.info("CyberTransformer Training v2 (NaN-Fixed)")
    logger.info("="*70)
    logger.info(f"Hyperparameters: {asdict(hparams)}")
    logger.info("="*70)
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        capability = torch.cuda.get_device_capability(0)
        logger.info(f"GPU: {gpu_name} (sm_{capability[0]}{capability[1]})")
    else:
        logger.warning("CUDA not available, using CPU")
    
    # Create model with custom config
    model = create_model(hparams, device)
    
    # Update GPU config with hyperparameters
    gpu_config = DEFAULT_CONFIG_8GB
    gpu_config.batch_size = hparams.batch_size
    gpu_config.learning_rate = hparams.learning_rate
    gpu_config.max_grad_norm = hparams.max_grad_norm
    gpu_config.warmup_steps = hparams.warmup_steps
    gpu_config.mixed_precision = hparams.use_amp
    
    # Create trainer
    trainer = GPUOptimizedTrainer(
        model=model,
        config=gpu_config,
        device=device,
        checkpoint_dir=str(checkpoint_dir)
    )
    
    # Resume if requested
    start_epoch = 0
    if args.resume:
        logger.info(f"Resuming from {args.resume}")
        trainer.load_checkpoint(args.resume)
        # Load previous hyperparameters if available
        prev_config = Path(args.resume).parent / "hyperparameters.json"
        if prev_config.exists():
            hparams = HyperparameterConfig.load(prev_config)
            logger.info(f"Loaded previous hyperparameters: {asdict(hparams)}")
    
    # Load datasets using registry
    logger.info("Loading datasets from registry...")
    if args.datasets:
        logger.info(f"Using specified datasets: {args.datasets}")
    else:
        logger.info("No datasets specified, loading all available from registry")
    
    dataframes = load_datasets_from_registry(dataset_names=args.datasets, sample_size=args.sample_size)
    
    if len(dataframes) == 0:
        logger.error("No datasets loaded!")
        return
    
    # Create dataset
    logger.info("Creating training dataset with validation...")
    preprocessor = AlertPreprocessor(max_seq_length=gpu_config.max_seq_len)
    dataset = AlertDataset(dataframes, preprocessor, device)
    
    if len(dataset) == 0:
        logger.error("No valid training batches!")
        return
    
    # Create 80/20 train/val split
    total_batches = len(dataset)
    val_size = max(1, int(0.2 * total_batches))
    train_size = total_batches - val_size
    
    # Random split for train/val
    indices = list(range(total_batches))
    np.random.shuffle(indices)
    train_indices = indices[:train_size]
    val_indices = indices[train_size:]
    
    logger.info(f"Train/Val split: {train_size}/{val_size} batches")
    logger.info(f"Training on {train_size} batches, validating on {val_size} batches")
    
    # Configure scheduler with correct step count (Bug 1 fix)
    total_optimizer_steps = (train_size * hparams.epochs) // gpu_config.gradient_accumulation_steps
    trainer.configure_scheduler(total_optimizer_steps)
    
    # Training loop
    all_metrics = []
    best_val_loss = float('inf')
    patience_counter = 0
    patience = 15  # Early stopping patience for contrastive learning (longer than typical)
    
    for epoch in range(start_epoch, hparams.epochs):
        logger.info(f"\n{'='*70}")
        logger.info(f"Epoch {epoch + 1}/{hparams.epochs}")
        logger.info('='*70)
        
        epoch_start = time.time()
        
        # Train on training set
        epoch_metrics = train_epoch(trainer, dataset, train_indices, epoch, hparams)
        all_metrics.extend(epoch_metrics)
        
        # Validate on validation set
        val_loss = validate_epoch(trainer, dataset, val_indices)
        
        epoch_time = time.time() - epoch_start
        valid_losses = [m.loss for m in epoch_metrics if not np.isnan(m.loss)]
        avg_train_loss = np.mean(valid_losses) if valid_losses else float('inf')
        
        logger.info(f"Epoch {epoch + 1} complete: train_loss={avg_train_loss:.4f}, val_loss={val_loss:.4f}, time={epoch_time:.1f}s")
        
        # Save checkpoint
        trainer.save_checkpoint(f"epoch_{epoch + 1}")
        
        # Early stopping check
        if len(valid_losses) == 0:
            logger.critical("All training losses are NaN! Stopping training.")
            break
        
        # Track best validation loss with min_delta threshold
        min_delta = 1e-4
        if val_loss < best_val_loss - min_delta:
            best_val_loss = val_loss
            patience_counter = 0
            trainer.save_checkpoint("best")
            logger.info(f"New best validation loss: {best_val_loss:.4f}")
        else:
            patience_counter += 1
            if patience_counter >= patience:
                logger.info(f"Early stopping triggered after {patience} epochs without improvement")
                break
    
    # Final checkpoint
    final_path = trainer.save_checkpoint("final")
    
    # Save metrics
    metrics_df = pd.DataFrame([{
        'step': m.step,
        'loss': m.loss,
        'learning_rate': m.learning_rate,
        'gpu_memory_mb': m.gpu_memory_mb,
        'time_per_step_ms': m.time_per_step_ms
    } for m in all_metrics])
    
    metrics_path = checkpoint_dir / "training_metrics.csv"
    metrics_df.to_csv(metrics_path, index=False)
    
    # Generate summary
    summary = {
        'total_epochs': len(set(m.step // len(dataset) for m in all_metrics)),
        'total_steps': len(all_metrics),
        'final_avg_loss': avg_train_loss if 'avg_train_loss' in locals() else None,
        'nan_count': sum(1 for m in all_metrics if np.isnan(m.loss)),
        'hyperparameters': asdict(hparams)
    }
    
    with open(checkpoint_dir / "training_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("="*70)
    logger.info(f"Training complete! Final: {final_path}")
    logger.info(f"Summary: {summary}")
    logger.info("="*70)


if __name__ == "__main__":
    main()
