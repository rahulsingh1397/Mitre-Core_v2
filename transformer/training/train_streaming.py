"""
Streaming Training Script for Large Datasets
==============================================

Trains on multiple datasets including large ones (LANL 66GB, YNU 11GB)
using batch streaming to avoid memory errors.

Usage:
    python -m transformer.training.train_streaming \
        --datasets LANL CICAPT-IIoT TON_IoT YNU CICIoV2024 \
        --epochs 50 --chunksize 5000
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional, Iterator
from dataclasses import dataclass, asdict

import torch
import pandas as pd
import numpy as np
import json
from torch.utils.data import Dataset
from tqdm import tqdm

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB
from transformer.training.gpu_trainer import GPUOptimizedTrainer, TrainingMetrics
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.preprocessing.sliding_window_batcher import SlidingWindowBatcher

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mitre-core.streaming_train")


@dataclass
class StreamingConfig:
    """Configuration for streaming training."""
    chunksize: int = 5000  # Rows per chunk for streaming
    max_chunks_per_dataset: int = 20  # Limit chunks per large dataset
    min_alerts_per_chunk: int = 100  # Skip chunks with too few alerts
    window_size: int = 256
    window_overlap: int = 32
    
    
def get_dataset_paths() -> dict:
    """Get paths for all available datasets."""
    base = Path("datasets")
    return {
        "LANL": {
            "path": base / "LANL 2021–2024" / "HostEvents",
            "format": "csv",
            "pattern": "*/*",  # Files in subdirectories like wls_day-01/wls_day-01
            "streaming": True,
            "chunksize": 5000,
            "has_extension": False,  # Files have no extension
        },
        "CICAPT-IIoT": {
            "path": base / "CICAPT-IIoT-Dataset",
            "format": "csv",
            "pattern": "*.csv",
            "streaming": False,
        },
        "TON_IoT": {
            "path": base / "TON_IoT",
            "format": "parquet",
            "pattern": "*.parquet",
            "streaming": False,
        },
        "YNU": {
            "path": base / "YNU-IoTMal 2026" / "CSVs",
            "format": "csv",
            "pattern": "*.csv",
            "streaming": True,
            "chunksize": 5000,
        },
        "CICIoV2024": {
            "path": base / "CICIoV2024" / "decimal",
            "format": "csv",
            "pattern": "*.csv",
            "streaming": False,
        },
        "Real_Data": {
            "path": base / "real_data",
            "format": "csv",
            "pattern": "*.csv",
            "streaming": False,
        },
        "UNSW_NB15": {
            "path": base / "unsw_nb15",
            "format": "csv",
            "pattern": "*.csv",
            "streaming": False,
        },
    }


def stream_dataset_chunks(
    name: str,
    config: dict,
    max_chunks: Optional[int] = None
) -> Iterator[pd.DataFrame]:
    """
    Stream dataset in chunks for memory efficiency.
    
    Args:
        name: Dataset name
        config: Dataset configuration
        max_chunks: Maximum chunks to yield
        
    Yields:
        DataFrame chunks
    """
    path = config["path"]
    format_type = config.get("format", "csv")
    chunksize = config.get("chunksize", 5000)
    pattern = config.get("pattern", "*")
    
    if not path.exists():
        logger.warning(f"Path not found: {path}")
        return
    
    # Find files
    if path.is_dir():
        if pattern == "*/*":  # LANL style - files in subdirectories
            files = list(path.glob(pattern))
            files = [f for f in files if f.is_file()]  # Only files, not dirs
        elif format_type == "csv":
            files = list(path.glob(pattern)) if pattern != "*" else list(path.rglob("*.csv"))
        elif format_type == "parquet":
            files = list(path.glob("*.parquet"))
        else:
            files = list(path.iterdir())
    else:
        files = [path]
    
    if not files:
        logger.warning(f"No files found in {path}")
        return
    
    logger.info(f"[{name}] Streaming {len(files)} files, chunksize={chunksize}")
    
    chunk_count = 0
    for file in files:
        if max_chunks and chunk_count >= max_chunks:
            break
            
        try:
            logger.info(f"[{name}] Processing file: {file.name}")
            
            if format_type == "csv":
                # Stream CSV in chunks
                for chunk in pd.read_csv(file, chunksize=chunksize, low_memory=False, on_bad_lines='skip'):
                    if max_chunks and chunk_count >= max_chunks:
                        break
                    chunk['_source'] = name
                    chunk['_file'] = file.name
                    yield chunk
                    chunk_count += 1
                    
            elif format_type == "parquet":
                # Parquet - load and split manually
                df = pd.read_parquet(file)
                for i in range(0, len(df), chunksize):
                    if max_chunks and chunk_count >= max_chunks:
                        break
                    chunk = df.iloc[i:i+chunksize]
                    chunk['_source'] = name
                    chunk['_file'] = file.name
                    yield chunk
                    chunk_count += 1
                    
        except Exception as e:
            logger.error(f"[{name}] Error processing {file}: {e}")
            continue
    
    logger.info(f"[{name}] Total chunks yielded: {chunk_count}")


def validate_and_fix_timestamps(df: pd.DataFrame, dataset_name: str) -> pd.DataFrame:
    """Ensure timestamp column exists and is valid."""
    timestamp_cols = ['timestamp', 'EndDate', 'StartTime', 'StartDate', 'time', 'date', 'ts', 'Time']
    
    # Find existing timestamp column
    found_col = None
    for col in timestamp_cols:
        if col in df.columns:
            found_col = col
            break
    
    if found_col:
        # Convert to datetime
        try:
            df['timestamp'] = pd.to_datetime(df[found_col], errors='coerce')
        except:
            logger.warning(f"[{dataset_name}] Failed to parse {found_col}, creating artificial timestamps")
            df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='1s')
    else:
        # No timestamp found, create artificial ones
        logger.warning(f"[{dataset_name}] No timestamp column found, creating artificial timestamps")
        df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='1s')
    
    # Remove rows without valid timestamps
    df = df.dropna(subset=['timestamp'])
    return df


def create_batches_from_chunk(
    chunk: pd.DataFrame,
    preprocessor: AlertPreprocessor,
    batcher: SlidingWindowBatcher,
    device: torch.device
) -> List[dict]:
    """Convert a dataframe chunk into training batches."""
    batches = []
    
    # Validate chunk
    if len(chunk) < 10:
        return batches
    
    try:
        # Create windows
        windows = batcher.create_windows(chunk)
        
        for window_df in windows:
            try:
                batch = preprocessor.process_batch(window_df, device=device)
                
                # Validate batch
                if batch['alert_ids'].shape[1] >= 10:
                    batches.append(batch)
            except Exception as e:
                logger.debug(f"Failed to process window: {e}")
                continue
                
    except Exception as e:
        logger.warning(f"Failed to create windows: {e}")
    
    return batches


@dataclass
class HyperparameterConfig:
    """Hyperparameter configuration."""
    model_name: str = "CyberTransformer_v1"
    epochs: int = 50
    batch_size: int = 4
    learning_rate: float = 5e-5
    weight_decay: float = 0.01
    max_grad_norm: float = 0.5
    warmup_steps: int = 2000
    gradient_accumulation_steps: int = 16
    use_amp: bool = True
    dropout: float = 0.1
    d_model: int = 128
    n_layers: int = 2
    n_heads: int = 4
    max_seq_len: int = 256


def create_model(config: HyperparameterConfig, device: torch.device):
    """Create transformer model."""
    model = TransformerCandidateGenerator(
        vocab_size=10000,
        num_entities=10000,
        d_model=config.d_model,
        n_layers=config.n_layers,
        n_heads=config.n_heads,
        max_seq_len=config.max_seq_len,
        dropout=config.dropout,
        use_gradient_checkpointing=True,
        config=DEFAULT_CONFIG_8GB
    )
    
    # Initialize with proper scaling
    for p in model.parameters():
        if p.dim() > 1:
            torch.nn.init.xavier_uniform_(p, gain=0.1)
    
    memory = model.get_memory_footprint()
    logger.info(f"Model created: {memory['total_size_mb']:.1f}MB")
    
    return model.to(device)


def train_with_streaming(
    dataset_names: List[str],
    epochs: int,
    config: HyperparameterConfig,
    streaming_config: StreamingConfig,
    checkpoint_dir: Path,
    resume_path: Optional[str] = None,
    val_ratio: float = 0.2,
    max_val_buffer: int = 200,
    patience: int = 15,
    min_delta: float = 1e-4
):
    """Main streaming training function with validation and early stopping."""
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Using device: {device}")
    
    # Create model
    model = create_model(config, device)
    
    # Create trainer
    gpu_config = DEFAULT_CONFIG_8GB
    gpu_config.batch_size = config.batch_size
    gpu_config.learning_rate = config.learning_rate
    gpu_config.max_grad_norm = config.max_grad_norm
    gpu_config.warmup_steps = config.warmup_steps
    gpu_config.mixed_precision = config.use_amp
    gpu_config.gradient_accumulation_steps = config.gradient_accumulation_steps
    
    trainer = GPUOptimizedTrainer(
        model=model,
        config=gpu_config,
        device=device,
        checkpoint_dir=str(checkpoint_dir)
    )
    
    # Resume if requested
    if resume_path:
        logger.info(f"Resuming from {resume_path}")
        trainer.load_checkpoint(resume_path)
    
    # Setup preprocessing
    preprocessor = AlertPreprocessor(max_seq_length=config.max_seq_len)
    batcher = SlidingWindowBatcher(
        window_size=streaming_config.window_size,
        overlap=streaming_config.window_overlap,
        preprocessor=preprocessor
    )
    
    # Get dataset configs
    all_dataset_configs = get_dataset_paths()
    
    # Training state
    all_metrics = []
    best_val_loss = float('inf')
    patience_counter = 0
    chunk_counter = 0
    val_buffer = []  # Bounded buffer for validation batches
    scheduler_configured = False
    epoch1_total_steps = 0  # To configure scheduler retroactively
    
    def validate_on_buffered_batches(trainer, val_batches, device):
        """Compute validation loss on buffered validation batches."""
        if not val_batches:
            return float('inf')
        
        trainer.model.eval()
        total_loss = 0.0
        num_batches = 0
        
        with torch.no_grad():
            for batch in val_batches:
                batch_device = {
                    'alert_ids': batch['alert_ids'].unsqueeze(0).to(device),
                    'entity_ids': batch['entity_ids'].unsqueeze(0).to(device),
                    'time_buckets': batch['time_buckets'].unsqueeze(0).to(device),
                    'attention_mask': batch['attention_mask'].unsqueeze(0).to(device),
                }
                labels = batch['labels'].unsqueeze(0).to(device)
                
                try:
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
                except Exception as e:
                    logger.debug(f"Validation batch failed: {e}")
                    continue
        
        trainer.model.train()
        return total_loss / num_batches if num_batches > 0 else float('inf')
    
    logger.info(f"Streaming training with validation ratio={val_ratio}, patience={patience}")
    
    for epoch in tqdm(range(epochs), desc="Epochs", position=0, leave=True):
        logger.info(f"\n{'='*70}")
        logger.info(f"Epoch {epoch + 1}/{epochs}")
        logger.info('='*70)
        
        epoch_start = time.time()
        epoch_batches = 0
        epoch_chunks = 0
        
        # Create progress bar for datasets within epoch
        dataset_pbar = tqdm(dataset_names, desc="Datasets", position=1, leave=False)
        
        # Stream through all datasets
        for dataset_name in dataset_pbar:
            dataset_pbar.set_postfix({"dataset": dataset_name})
            if dataset_name not in all_dataset_configs:
                logger.warning(f"Unknown dataset: {dataset_name}")
                continue
            
            ds_config = all_dataset_configs[dataset_name]
            
            # Determine max chunks for this dataset
            max_chunks = None
            if ds_config.get("streaming", False):
                max_chunks = streaming_config.max_chunks_per_dataset
            
            # Stream chunks
            for chunk in stream_dataset_chunks(dataset_name, ds_config, max_chunks):
                epoch_chunks += 1
                
                # Fix timestamps
                chunk = validate_and_fix_timestamps(chunk, dataset_name)
                
                if len(chunk) < streaming_config.min_alerts_per_chunk:
                    logger.debug(f"Skipping chunk with only {len(chunk)} alerts")
                    continue
                
                # Create batches from chunk
                batches = create_batches_from_chunk(chunk, preprocessor, batcher, device)
                
                if not batches:
                    continue
                
                # Train on batches
                for batch in batches:
                    # Prepare batch
                    batch_device = {
                        'alert_ids': batch['alert_ids'].to(device),
                        'entity_ids': batch['entity_ids'].to(device),
                        'time_buckets': batch['time_buckets'].to(device),
                        'attention_mask': batch['attention_mask'].to(device),
                    }
                    
                    # Use real campaign labels extracted by preprocessor (campaign_id / tactic / label)
                    seq_len = batch['alert_ids'].shape[1]
                    if 'campaign_labels' in batch:
                        labels = batch['campaign_labels'].to(device)
                        if labels.dim() == 1:
                            labels = labels.unsqueeze(0)  # [seq_len] -> [1, seq_len]
                    else:
                        # Fallback only if preprocessor found no label column at all
                        labels = torch.zeros(1, seq_len, dtype=torch.long, device=device)
                    
                    # Train/val split: hold back every 1/val_ratio batches for validation
                    is_val_batch = (chunk_counter % int(1 / val_ratio)) == 0 if val_ratio > 0 else False
                    
                    if is_val_batch and len(val_buffer) < max_val_buffer:
                        # Store for validation (keep labels with batch)
                        batch['labels'] = labels.cpu()
                        val_buffer.append(batch)
                        continue  # Skip training on this batch
                    
                    # Train step
                    try:
                        metrics = trainer.train_step(batch_device, labels)  # labels already [1, seq_len]
                        all_metrics.append(metrics)
                        epoch_batches += 1
                        
                        if trainer.current_step % 100 == 0:
                            logger.info(
                                f"Epoch {epoch+1} | Step {metrics.step} | "
                                f"Loss: {metrics.loss:.4f} | "
                                f"GPU: {metrics.gpu_memory_mb:.1f}MB | "
                                f"Dataset: {dataset_name}"
                            )
                    except Exception as e:
                        logger.warning(f"Training step failed: {e}")
                        continue
        
        # Close dataset progress bar
        dataset_pbar.close()
        
        # Compute validation loss
        val_loss = validate_on_buffered_batches(trainer, val_buffer)
        
        epoch_time = time.time() - epoch_start
        tqdm.write(f"Epoch {epoch+1} complete: {epoch_chunks} chunks, {epoch_batches} batches, val_loss={val_loss:.4f}, time={epoch_time:.1f}s")
        
        # Configure scheduler after epoch 1 if not done
        if epoch == 0 and not scheduler_configured:
            epoch1_total_steps = epoch_batches
            total_steps_estimate = epoch1_total_steps * epochs // gpu_config.gradient_accumulation_steps
            trainer.configure_scheduler(total_steps_estimate)
            scheduler_configured = True
            logger.info(f"Scheduler configured retroactively: {total_steps_estimate} steps estimated")
        
        # Early stopping check with min_delta
        if val_loss < best_val_loss - min_delta:
            best_val_loss = val_loss
            patience_counter = 0
            trainer.save_checkpoint("best")
            logger.info(f"New best validation loss: {best_val_loss:.4f}")
        else:
            patience_counter += 1
            logger.info(f"Validation loss did not improve. Patience: {patience_counter}/{patience}")
            if patience_counter >= patience:
                logger.info(f"Early stopping triggered after {patience} epochs without improvement")
                break
        
        # Save checkpoint
        try:
            ckpt_path = trainer.save_checkpoint(f"epoch_{epoch + 1}")
            logger.info(f"Checkpoint saved: {ckpt_path}")
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
    
    # Final checkpoint
    try:
        final_path = trainer.save_checkpoint("final")
        logger.info(f"Training complete! Final: {final_path}")
    except Exception as e:
        logger.error(f"Failed to save final checkpoint: {e}")
        final_path = None
    
    # Save summary
    valid_losses = [m.loss for m in all_metrics if not np.isnan(m.loss)]
    summary = {
        'total_epochs': epochs,
        'total_steps': len(all_metrics),
        'final_avg_loss': np.mean(valid_losses) if valid_losses else None,
        'nan_count': sum(1 for m in all_metrics if np.isnan(m.loss)),
        'hyperparameters': asdict(config)
    }
    
    with open(checkpoint_dir / "training_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary


def main():
    parser = argparse.ArgumentParser(description="Streaming Training for Large Datasets")
    parser.add_argument("--datasets", nargs="+", required=True,
                      help="Dataset names to train on (LANL CICAPT-IIoT TON_IoT YNU CICIoV2024 Real_Data)")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--chunksize", type=int, default=5000,
                      help="Rows per chunk for streaming (default: 5000)")
    parser.add_argument("--max-chunks", type=int, default=20,
                      help="Max chunks per large dataset (default: 20)")
    parser.add_argument("--lr", type=float, default=5e-5)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--checkpoint-dir", type=str, default="models/checkpoints/streaming_v1")
    parser.add_argument("--resume", type=str, default=None)
    parser.add_argument("--no-amp", action="store_true")
    
    args = parser.parse_args()
    
    # Setup
    checkpoint_dir = Path(args.checkpoint_dir)
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    # Configs
    hparams = HyperparameterConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        use_amp=not args.no_amp
    )
    
    streaming_config = StreamingConfig(
        chunksize=args.chunksize,
        max_chunks_per_dataset=args.max_chunks
    )
    
    logger.info("="*70)
    logger.info("Streaming Training - Multi-Dataset")
    logger.info(f"Datasets: {args.datasets}")
    logger.info(f"Epochs: {args.epochs}, Chunksize: {args.chunksize}")
    logger.info("="*70)
    
    # Train
    summary = train_with_streaming(
        dataset_names=args.datasets,
        epochs=args.epochs,
        config=hparams,
        streaming_config=streaming_config,
        checkpoint_dir=checkpoint_dir,
        resume_path=args.resume
    )
    
    logger.info(f"\nSummary: {summary}")


if __name__ == "__main__":
    main()
