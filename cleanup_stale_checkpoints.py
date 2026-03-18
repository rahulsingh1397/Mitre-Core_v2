#!/usr/bin/env python3
"""Clean up stale transformer training artifacts."""

import shutil
from pathlib import Path

paths_to_delete = [
    "models/checkpoints/cybertransformer",
    "models/checkpoints/transformer",
    "models/checkpoints/streaming_test",
    "cybertransformer_training.log",
    "cybertransformer_checkpoints",
    "training_metrics.csv",
]

for p in paths_to_delete:
    path = Path(p)
    if path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        print(f"Deleted: {p}")
    else:
        print(f"Not found: {p}")

print("\nKept (as requested):")
print("  - models/checkpoints/hgnn/")
print("  - datasets/")
print("  - experiments/results/")
print("\nCleanup complete. Ready for clean training run.")
