# MITRE-CORE Model & Checkpoint Organization

This directory contains all trained models, checkpoints, and training logs organized by type and version.

## Directory Structure

```
models/
├── checkpoints/
│   ├── cybertransformer/      # Transformer-based candidate generator models
│   │   ├── v1/                 # Version 1 checkpoints
│   │   ├── v2/                 # Version 2 checkpoints
│   │   ├── v3/                 # Version 3 checkpoints
│   │   ├── v4/                 # Version 4 checkpoints
│   │   ├── v5/                 # Version 5 checkpoints (latest stable)
│   │   ├── latest/             # Symlink to most recent stable version
│   │   └── archive/            # Large training runs (100epoch, etc.)
│   ├── hgnn/                   # Heterogeneous Graph Neural Network models
│   ├── transformer/            # Base transformer models
│   ├── agentic/                  # Agentic workflow checkpoints
│   ├── debug/                    # Debug checkpoints
│   └── test/                     # Test checkpoints
└── logs/
    ├── cybertransformer/       # CyberTransformer training logs
    ├── hgnn/                   # HGNN training logs
    └── training/               # General training logs
```

## Checkpoint Naming Convention

- **v{number}**: Versioned releases (v1, v2, v3, v4, v5)
- **latest**: Always points to the most stable recent version
- **archive**: Large experimental runs that are not actively used

## Usage

### Loading a Specific Version

```python
from core.correlation_pipeline import CorrelationPipeline

# Load v5 checkpoint
pipeline = CorrelationPipeline(
    method='hybrid',
    model_path='models/checkpoints/cybertransformer/v5/cybertransformer_v5_checkpoints/best_model.pt'
)

# Or use latest
pipeline = CorrelationPipeline(
    method='hybrid',
    model_path='models/checkpoints/cybertransformer/latest/best_model.pt'
)
```

### Log Files

Training logs are organized by model type in `models/logs/`:
- `models/logs/cybertransformer/` - All CyberTransformer training logs
- `models/logs/hgnn/` - HGNN training logs
- `models/logs/training/` - General training logs

## Cleanup Information

This structure was reorganized on March 14, 2026 to consolidate:
- 15+ scattered cybertransformer folders → organized versioned structure
- Multiple checkpoint folders → unified `checkpoints/` hierarchy
- Large log files (150MB+) → centralized `logs/` directory

Previous locations (now empty/moved):
- `cybertransformer_*` folders → `models/checkpoints/cybertransformer/`
- `*_checkpoints` folders → `models/checkpoints/`
- `*.log` training logs → `models/logs/`
