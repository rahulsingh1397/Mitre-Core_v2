# MITRE-CORE Transformer Training Plan
## Comprehensive Implementation Strategy

**Version:** 3.0  
**Date:** March 2026  
**Goal:** Train production-grade Transformer model with 14 MITRE ATT&CK tactic coverage

---

## Executive Summary

This plan provides a detailed, phased approach to training the MITRE-CORE Transformer model. It emphasizes:
- **Code cleanliness**: Single-source-of-truth for all training logic
- **Vulnerability mitigation**: NaN handling, gradient clipping, checkpoint validation
- **Dataset integration**: Registry-based loading with automatic MITRE mapping
- **Scalable training**: Multi-dataset concatenation with memory-efficient sampling

---

## Phase 1: Codebase Consolidation & Cleanup

### 1.1 Current Architecture Review

**Consolidated Training Scripts:**
```
transformer/training/
├── train_cybertransformer.py    # Main training script (full features)
├── train_transformer.py         # Wrapper for quick starts
├── transformer_trainer.py       # Core trainer class (GPUTrainer)
├── gpu_trainer.py              # GPU optimization & AMP
└── __init__.py                 # Unified imports
```

**Status: ✅ COMPLETED**
- Removed: `train_transformer_unified.py` (redundant)
- Consolidated: All training logic into `train_cybertransformer.py`
- Wrapper: `train_transformer.py` delegates to main script

### 1.2 Dataset Registry Integration

**Centralized Loading:**
```python
# scripts/dataset_registry.py - Single source of truth
DATASET_REGISTRY = {
    "TON_IoT": DatasetMetadata(..., has_mitre_labels=True),
    "CICIoV2024": DatasetMetadata(..., has_mitre_labels=False),
    "Real_Data": DatasetMetadata(..., has_mitre_labels=True),
    # ... 9 datasets total
}

def load_dataset(name: str, sample_size: Optional[int] = None) -> pd.DataFrame:
    """Universal loader with BZ2, CSV, Parquet support"""
```

**Vulnerability Fix:** Removed circular imports in `scripts/__init__.py`
- **Issue**: Auto-importing all scripts caused ImportError on missing dependencies
- **Fix**: Empty `__all__`, direct imports only when needed

### 1.3 Security Vulnerabilities Addressed

| Vulnerability | Location | Mitigation |
|--------------|----------|------------|
| NaN propagation | `transformer_trainer.py:87` | Added `torch.nan_to_num()` with clamping |
| Gradient explosion | `gpu_trainer.py:156` | `max_grad_norm=0.5` with gradient clipping |
| Infinite loss | `train_cybertransformer.py:285` | NaN detection & training halt |
| Checkpoint corruption | `gpu_trainer.py:391` | Atomic write + validation before replace |
| Memory overflow | `train_cybertransformer.py:403` | `sample_size` parameter per dataset |

---

## Phase 2: Dataset Curation & Integration

### 2.1 Dataset Inventory (Analyzed)

| Priority | Dataset | Size | MITRE Labels | Use Case |
|----------|---------|------|--------------|----------|
| **1** | TON_IoT | 211K rows | ✅ Full 14 tactics | Primary training |
| **2** | Real_Data | 65 rows | ✅ Production tags | Validation & fine-tuning |
| **3** | CICIoV2024 | 90MB (decimal) | ⚠️ Generic labels | Vehicle/CAN bus patterns |
| **4** | CICAPT-IIoT | 5.2GB | ⚠️ Attack categories | Sample 100K rows |
| **5** | Datasense_IIoT_2025 | 194MB | ⚠️ Custom labels | Temporal 5sec windows |
| **6** | YNU-IoTMal 2026 | ~31MB | ⚠️ Family labels | Malware diversity |
| **7** | Linux_APT | 59 rows | ✅ APT-specific | Advanced persistent threats |
| **8** | UNSW_NB15 | Large | ❌ Generic | Map via `mitre_tactic_mapper.py` |
| **9** | NSL_KDD | Medium | ❌ No timestamps | Static features only |

### 2.2 Label Mapping Strategy

**For datasets WITHOUT MITRE labels:**
```python
from utils.mitre_tactic_mapper import MITRETacticMapper

mapper = MITRETacticMapper()
coverage = mapper.validate_tactic_coverage(df, label_col='attack_cat')
# Auto-maps: 'exploits' → 'Initial Access'
#           'dos' → 'Impact'
#           'reconnaissance' → 'Reconnaissance'
```

**Coverage Targets:**
- Minimum: 80% of 14 MITRE tactics represented
- Optimal: 100% coverage with balanced class distribution
- Validation: Run `validate_dataset_tactics()` before training

### 2.3 LANL WLS Integration (Partial)

**Current Status:**
- ✅ Downloaded: `wls_day-01.bz2` through `wls_day-05.bz2` (5 files, ~2.2GB)
- ❌ Incomplete: Netflow downloads (4 `.crdownload` files)

**BZ2 Loading Implemented:**
```python
# scripts/dataset_registry.py
import bz2
for bz2_file in bz2_files[:5]:  # Limit to 5 files for memory
    with bz2.open(bz2_file, 'rt') as f:
        df = pd.read_csv(f, nrows=sample_size)
```

---

## Phase 3: Training Pipeline Implementation

### 3.1 Configuration Schema

**HyperparameterConfig (Dataclass):**
```python
@dataclass
class HyperparameterConfig:
    model_name: str = "CyberTransformer_v1"
    epochs: int = 100
    batch_size: int = 4  # Limited by 8GB VRAM
    learning_rate: float = 5e-5  # Conservative for stability
    weight_decay: float = 0.01
    max_grad_norm: float = 0.5   # Gradient clipping
    warmup_steps: int = 2000
    gradient_accumulation_steps: int = 16  # Effective batch = 64
    use_amp: bool = True  # Mixed precision
    dropout: float = 0.1
    d_model: int = 128    # Embedding dimension
    n_layers: int = 2     # Transformer layers
    n_heads: int = 4      # Attention heads
    max_seq_len: int = 256
```

### 3.2 Training Phases

#### Phase 3.2.1: Contrastive Pre-training (Unsupervised)
**Duration:** 50 epochs  
**Data:** All datasets (no labels required)  
**Objective:** Learn alert representations

```python
# Using InfoNCELoss from training_base.py
loss = InfoNCELoss(temperature=0.5)
z_i = model(augmented_view_1)
z_j = model(augmented_view_2)
contrastive_loss = loss(z_i, z_j)
```

**Augmentations:**
- Feature dropout: 10%
- Gaussian noise: σ=0.01
- Edge dropout: 10%

#### Phase 3.2.2: Supervised Fine-tuning
**Duration:** 50 epochs  
**Data:** MITRE-labeled datasets only (TON_IoT, Real_Data, Linux_APT)  
**Objective:** Map to 14 tactic classes

```python
# Cross-entropy with label smoothing
criterion = nn.CrossEntropyLoss(label_smoothing=0.1)
```

#### Phase 3.2.3: Multi-Dataset Concatenation
**Strategy:** Memory-efficient sampling

```python
def load_datasets_from_registry(dataset_names, sample_size=10000):
    dataframes = []
    for name in dataset_names:
        df = load_dataset(name, sample_size=sample_size)
        # Add source tracking
        df['_source'] = name
        dataframes.append(df)
    return dataframes
```

**Memory Management:**
- RTX 5060 Ti 8GB constraint
- Per-dataset sampling: 10K rows default
- Gradient checkpointing enabled
- AMP (Automatic Mixed Precision) for 2x speedup

### 3.3 NaN & Instability Mitigation

**Detection (train_cybertransformer.py:285):**
```python
nan_count = 0
for name, param in model.named_parameters():
    if param.grad is not None:
        nan_count += torch.isnan(param.grad).sum().item()
        nan_count += torch.isinf(param.grad).sum().item()

if nan_count > 0:
    logger.error(f"NaN/Inf detected in gradients! Stopping.")
    break
```

**Clamping (transformer_trainer.py:87):**
```python
# Before loss calculation
if torch.isnan(loss) or torch.isinf(loss):
    loss = torch.clamp(loss, min=0, max=10)
```

---

## Phase 4: Validation & Testing

### 4.1 Checkpoint Strategy

**Save Points:**
- Every epoch: `epoch_{N}.pt`
- Best model: `best.pt` (by validation loss)
- Final model: `final.pt`
- Emergency: `nan_recovery.pt` (on detection)

**Validation Checklist:**
```bash
# 1. Verify checkpoint loads
python -c "from transformer.training.train_cybertransformer import main; 
           import sys; sys.argv = ['', '--resume', 'models/checkpoints/transformer_v1/final.pt', '--epochs', '1']"

# 2. Test inference speed
time python -c "from transformer.models.candidate_generator import TransformerCandidateGenerator; 
               import torch; m = TransformerCandidateGenerator(); 
               x = torch.randint(0, 1000, (1000, 256)); 
               import time; s=time.time(); m(x, x, x); print(f'{1000/(time.time()-s):.0f} alerts/sec')"

# 3. Verify tactic coverage
python -c "from scripts.dataset_registry import validate_dataset_tactics; 
           print(validate_dataset_tactics('TON_IoT'))"
```

### 4.2 Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Training loss | < 0.5 | After 50 epochs |
| Inference speed | > 5000 alerts/sec | RTX 5060 Ti |
| NaN occurrences | 0 | Per epoch monitoring |
| Memory usage | < 7.5GB | Peak VRAM |
| Checkpoint size | < 50MB | Per file |

---

## Phase 5: Production Deployment

### 5.1 Model Export

**ONNX Export (for inference optimization):**
```python
# Export to ONNX for 2-3x inference speedup
torch.onnx.export(
    model,
    (alert_ids, entity_ids, time_buckets),
    "models/production/transformer_v1.onnx",
    opset_version=14,
    input_names=['alert_ids', 'entity_ids', 'time_buckets'],
    output_names=['tactic_probs', 'cluster_logits']
)
```

### 5.2 Monitoring Integration

**Metrics to Log:**
```python
training_metrics = {
    'epoch': epoch,
    'loss': avg_loss,
    'learning_rate': current_lr,
    'grad_norm': total_norm,
    'nan_count': nan_count,
    'samples_per_sec': len(dataset) / elapsed_time,
    'gpu_memory_mb': torch.cuda.memory_allocated() / 1e6
}
```

---

## Appendix A: Command Reference

### Training Commands

```bash
# Quick test (1 epoch)
python -m transformer.training.train_transformer --epochs 1

# Full training - MITRE-ready datasets only
python -m transformer.training.train_cybertransformer \
    --datasets TON_IoT Real_Data Linux_APT \
    --epochs 100 --lr 5e-5 --sample-size 50000 \
    --checkpoint-dir models/checkpoints/transformer_mitre_v1

# Maximum coverage - all datasets with sampling
python -m transformer.training.train_cybertransformer \
    --datasets TON_IoT CICIoV2024 CICAPT-IIoT Datasense_IIoT_2025 YNU-IoTMal \
    --epochs 50 --sample-size 100000 \
    --checkpoint-dir models/checkpoints/transformer_full_v1

# Resume from checkpoint
python -m transformer.training.train_cybertransformer \
    --resume models/checkpoints/transformer_v1/epoch_25.pt \
    --epochs 75  # Continue to 100 total

# Debugging mode (no AMP, single batch)
python -m transformer.training.train_cybertransformer \
    --no-amp --epochs 1 --batch-size 1 \
    --datasets Real_Data
```

### Dataset Commands

```bash
# List all available datasets
python -c "from scripts.dataset_registry import print_dataset_summary; print_dataset_summary()"

# Validate MITRE coverage for a dataset
python -c "from scripts.dataset_registry import validate_dataset_tactics; 
           import json; print(json.dumps(validate_dataset_tactics('TON_IoT'), indent=2))"

# Load specific dataset for inspection
python -c "from scripts.dataset_registry import load_dataset; 
           df = load_dataset('CICIoV2024', sample_size=100); 
           print(df.columns.tolist())"
```

---

## Appendix B: File Structure

```
MITRE-CORE_V2/
├── transformer/
│   ├── training/
│   │   ├── train_cybertransformer.py    # Main entry point
│   │   ├── train_transformer.py          # Simple wrapper
│   │   ├── transformer_trainer.py        # Core trainer
│   │   ├── gpu_trainer.py               # GPU optimizations
│   │   └── __init__.py
│   ├── models/
│   │   ├── candidate_generator.py        # Transformer model
│   │   └── __init__.py
│   ├── data/
│   │   ├── alert_dataset.py             # PyTorch Dataset
│   │   └── alert_preprocessor.py        # Preprocessing
│   └── config/
│       └── gpu_config_8gb.py            # RTX 5060 Ti config
├── scripts/
│   ├── dataset_registry.py               # Dataset metadata & loading
│   └── analysis/
│       └── run_mitre_analysis.py
├── training/                             # HGNN training (separate)
│   ├── training_base.py                 # Shared utilities
│   ├── train_enhanced_hgnn.py
│   └── train_on_datasets.py
└── models/checkpoints/
    └── transformer_v1/                  # Training outputs
```

---

## Appendix C: Troubleshooting

### Common Issues

**Issue:** `PermissionError` on Datasense dataset  
**Fix:** Run with `--datasets TON_IoT CICIoV2024` (exclude Datasense)

**Issue:** `NaN detected in gradients`  
**Fix:** Lower learning rate: `--lr 1e-5`, increase warmup: `--warmup-steps 5000`

**Issue:** `CUDA out of memory`  
**Fix:** Reduce batch size: `--batch-size 2`, reduce sample size: `--sample-size 5000`

**Issue:** `ImportError: cannot import name 'main'`  
**Fix:** Update `scripts/__init__.py` to remove auto-imports (completed)

**Issue:** Training loss plateaus at ~0.69  
**Diagnosis:** Model is underfitting, increase capacity or check label distribution

---

**End of Training Plan**

*Next Steps:*
1. Execute Phase 1 commands to verify setup
2. Run quick validation: `python -m transformer.training.train_transformer --epochs 1`
3. Begin full training with TON_IoT + Real_Data
4. Weekly checkpoint reviews
