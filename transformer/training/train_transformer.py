"""
Simple Transformer Training Script
====================================

This is a lightweight wrapper around train_cybertransformer.py for quick
single-dataset training. For full multi-dataset training with advanced
features, use train_cybertransformer.py directly.

Usage:
    python -m transformer.training.train_transformer --data_path datasets/real_data/data.csv --epochs 10
    python -m transformer.training.train_transformer --epochs 50 --batch_size 8

The script automatically delegates to train_cybertransformer.py with
appropriate defaults.
"""

import argparse
import logging
import sys
from pathlib import Path

# Delegate to cybertransformer
from transformer.training.train_cybertransformer import (
    main as cyber_main,
    load_datasets_from_registry
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.train_transformer")

def main():
    parser = argparse.ArgumentParser(
        description="Train Transformer Candidate Generator (Simple Wrapper)",
        epilog="For advanced training options, use train_cybertransformer.py"
    )
    parser.add_argument("--data_path", type=str, default=None, 
                       help="Path to single dataset CSV (deprecated, use --datasets)")
    parser.add_argument("--datasets", nargs="+", default=None,
                       help="Dataset names from registry (e.g., CICIoV2024 Real_Data)")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=4, help="Batch size")
    parser.add_argument("--learning_rate", type=float, default=1e-4, help="Learning rate")
    parser.add_argument("--checkpoint_dir", type=str, default="models/checkpoints/transformer", 
                       help="Checkpoint directory")
    parser.add_argument("--sample_size", type=int, default=10000,
                       help="Rows to sample per dataset")
    args = parser.parse_args()
    
    logger.info(" train_transformer.py - Simple wrapper for transformer training")
    logger.info(" Note: For advanced features (NaN handling, hyperparameter logging), use:")
    logger.info("   python -m transformer.training.train_cybertransformer")
    logger.info("")
    
    # Build equivalent command for cybertransformer
    sys.argv = [
        "train_cybertransformer.py",
        "--epochs", str(args.epochs),
        "--batch-size", str(args.batch_size),
        "--lr", str(args.learning_rate),
        "--checkpoint-dir", args.checkpoint_dir,
        "--sample-size", str(args.sample_size)
    ]
    
    if args.datasets:
        sys.argv.extend(["--datasets"] + args.datasets)
        logger.info(f"Training on datasets: {args.datasets}")
    elif args.data_path:
        # Legacy single-file mode - warn user
        logger.warning("--data_path is deprecated. Consider using --datasets with registry names.")
        logger.warning(f"Attempting to use: {args.data_path}")
        # For single file, we can't use registry - delegate won't work perfectly
        logger.error("Single file mode not supported in wrapper. Use train_cybertransformer.py directly")
        return 1
    else:
        # Default to all available datasets
        logger.info("No datasets specified, using all available from registry")
    
    # Delegate to cybertransformer main
    logger.info("Delegating to train_cybertransformer.py...")
    return cyber_main()

if __name__ == "__main__":
    sys.exit(main())
