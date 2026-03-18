# MITRE-CORE v2.1 — Execution Memory

## Quick Reference
- **Current Version:** 2.1.0
- **Architecture:** 3-Tier (Transformer → HGNN → Union-Find)
- **Key Addition:** RL-based adaptive thresholding + Transformer candidate generation
- **Last Updated:** 2026-03-15

---

## Architecture Overview

```
Alerts → Transformer (candidate generation) → HGNN (correlation) → Union-Find (fallback) → Clusters
                    ↓                           ↓                      ↓
               O(n) edges                 Graph embeddings          Structural clustering
```

### 3-Tier Pipeline
| Tier | Component | Purpose | Location |
|------|-----------|---------|----------|
| 1 | **Transformer** | Sparse attention candidate generation | `transformer/` |
| 2 | **HGNN** | Heterogeneous graph neural network | `hgnn/` |
| 3 | **Union-Find** | Deterministic structural fallback | `core/correlation_pipeline.py` |

---

## Module Reference

### Core Correlation (`core/`)
- `correlation_pipeline.py` — Unified pipeline with auto method selection (Union-Find/HGNN/Hybrid)
- `correlation_indexer.py` — Union-Find baseline + confidence-guided thresholding
- `cluster_filter.py` — Top-k cluster selection with importance scoring
- `kg_enrichment.py` — MITRE ATT&CK linking + threat intel

### Transformer Architecture (`transformer/`)
| Module | Purpose |
|--------|---------|
| `models/time2vec.py` | Temporal encoding |
| `models/sliding_window_attention.py` | O(n) attention for long sequences |
| `models/hgt_encoder.py` | Heterogeneous graph transformer |
| `models/temporal_spatial_fusion.py` | Cross-modal fusion |
| `models/candidate_generator.py` | Edge candidate generation |
| `training/transformer_trainer.py` | Training loop |
| `utils/graph_builder.py` | Alert → PyG HeteroData |
| `utils/temporal_utils.py` | Timestamp processing |

### RL Integration (`core/` + `utils/`)
| Module | Purpose |
|--------|---------|
| `core/rl_anomaly_detector.py` | Multi-dimensional anomaly detection (time/source/dest) |
| `core/rl_attack_predictor.py` | DQN-based threshold optimization |
| `core/analyst_feedback_processor.py` | Feedback → RL reward pipeline |
| `core/rl_config.py` | AppConfig for RL components |
| `utils/rl_model_manager.py` | Model versioning + persistence |

---

## Key Capabilities

### 1. Correlation Methods
- **Union-Find:** Fast O(n log n), no training required
- **HGNN:** Higher accuracy, requires trained model
- **Hybrid:** Combines both (auto-selected based on data size)
- **Transformer + Union-Find:** Near-linear time with deterministic output

### 2. Confidence Scoring
- **GAEC** (Geometry-Aware Embedding Confidence): HDBSCAN + PCA whitening
- **Softmax:** Classification head confidence (legacy)
- **UF Refinement:** Low-confidence alerts → Union-Find with adaptive threshold

### 3. RL Feedback Loop
- **State:** [mean_risk, std_risk, lower_th, upper_th, fp_rate, detection_rate]
- **Actions:** Widen/narrow/shift thresholds
- **Reward:** TP=+1, TN=+0.5, FP=-1, FN=-2
- **Update:** Double DQN with experience replay

---

## Dataset Coverage

| Dataset | Year | Status | Notes |
|---------|------|--------|-------|
| UNSW-NB15 | 2015 | ✅ Production-ready | Baseline dataset |
| TON_IoT | 2020 | ✅ Validated | IoT focus |
| Linux_APT | 2021 | ✅ Validated | Temporal ordering preserved |
| CICIDS2017 | 2017 | ✅ Validated | Multi-category |
| NSL-KDD | 2009 | ✅ Validated | Classic benchmark |
| CICAPT-IIoT | 2024 | ✅ Validated | Modern APT |
| Datasense IIoT | 2025 | ✅ Validated | 1s/5s fragments merged |
| YNU-IoTMal | 2026 | ✅ Validated | Malware family clustering |
| **CICIoV2024** | **2024** | **✅ Downloaded** | **IoT vehicle traffic, 60M+ records** |
| **LANL 2021-2024** | **2024** | **⚠️ In Progress** | **1B+ enterprise telemetry** |
| **DARPA OpTC 2024** | **2024** | **🔲 Pending** | **Windows host instrumentation** |
| **SWaT/WADI 2025** | **2025** | **🔲 Future** | **Requested from iTrust** |

**Total Records:** 304,214+ across 8 datasets (expanding to 1B+ with LANL)

### New Dataset Locations
- **CICIoV2024:** `datasets/CICIoV2024/decimal/` (CSV format)
- **YNU-IoTMal 2026:** `datasets/YNU-IoTMal 2026/CSVs/`
- **LANL 2021-2024:** `datasets/LANL 2021–2024/` (BZ2 compressed)
- **Datasense IIoT 2025:** `datasets/Datasense_IIoT_2025/`

---

## Performance Benchmarks

| Metric | Value | Notes |
|--------|-------|-------|
| ARI (UNSW-NB15) | 0.4042 | HGNN no-UF mode |
| ARI (NSL-KDD) | 0.2574 | HGNN no-UF mode |
| Processing Speed | ~2s/1K alerts | GPU (RTX 5060 Ti) |
| Memory Usage | <8GB | With transformer caching |
| MITRE Coverage | 100% | All 14 tactics |

---

## Configuration

### GPU Config (`transformer/config/gpu_config_8gb.py`)
- **Target:** RTX 5060 Ti 8GB
- **Batch size:** 32
- **Mixed precision:** Enabled
- **Gradient checkpointing:** Enabled for large graphs

### RL Config (`core/rl_config.py`)
- **State dim:** 6
- **Action dim:** 5 (noop, widen, narrow, shift_up, shift_down)
- **Hidden dims:** [128, 64]
- **Learning rate:** 1e-3
- **Epsilon decay:** 0.995

---

## Usage Patterns

### Basic Correlation
```python
from core.correlation_pipeline import CorrelationPipeline

pipeline = CorrelationPipeline(method='auto')
result = pipeline.correlate(df, usernames=['src_user'], addresses=['src_ip'])
```

### Transformer-Enhanced
```python
from core.correlation_pipeline import TransformerHybridPipeline

pipeline = TransformerHybridPipeline(transformer_path='models/transformer.pt')
result = pipeline.correlate(df, usernames=['src_user'], addresses=['src_ip'])
```

### RL Threshold Optimization
```python
from core.rl_attack_predictor import RLThresholdOptimizer
from core.analyst_feedback_processor import AnalystFeedbackProcessor

optimizer = RLThresholdOptimizer(threshold_dict)
processor = AnalystFeedbackProcessor(optimizer)

# Process detection with feedback loop
new_thresholds = processor.process_feedback(user, risk_scores, feedback)
```

---

## File Structure

```
MITRE-CORE_V2/
├── core/                    # Correlation + RL
│   ├── correlation_pipeline.py
│   ├── correlation_indexer.py
│   ├── rl_anomaly_detector.py
│   ├── rl_attack_predictor.py
│   ├── analyst_feedback_processor.py
│   └── rl_config.py
├── transformer/             # Transformer architecture
│   ├── models/
│   ├── training/
│   ├── utils/
│   └── config/
├── hgnn/                    # HGNN correlation
├── utils/                   # Shared utilities
│   └── rl_model_manager.py
├── training/                # Dataset loaders
├── experiments/             # Results + benchmarks
├── docs/                    # Architecture docs
├── tests/                   # Test suite
└── requirements.txt         # Dependencies
```

---

## Changelog

### v2.1.0 (2026-03-15)
- **Added:** Transformer candidate generation (Time2Vec, HGT, SlidingWindowAttention)
- **Added:** RL-based threshold optimization (DQN agent + feedback loop)
- **Added:** Analyst feedback processor for continuous learning
- **Updated:** Unified correlation pipeline with backward compatibility
- **Updated:** All v3.0 references → v2.1 (consistent versioning)

### v2.0.x (2026-03)
- HGNN + Union-Find hybrid pipeline
- Confidence-gated correlation
- Multi-dataset support
- GAEC confidence scoring (HDBSCAN-based)

### v1.x (Legacy)
- Initial Union-Find correlation
- Basic alert clustering

---

## Development Notes

### Running Tests
```bash
pytest tests/test_correlation.py -v
```

### Training Transformer
```bash
# Simple training (wrapper for quick start)
python -m transformer.training.train_transformer --epochs 10

# Advanced multi-dataset training with NaN handling (recommended)
python -m transformer.training.train_cybertransformer --epochs 50 --lr 5e-5

# Specific datasets from registry
python -m transformer.training.train_cybertransformer --datasets CICIoV2024 Datasense_IIoT_2025 --epochs 50

# Include LANL WLS data (first 5 days downloaded)
python -m transformer.training.train_cybertransformer --datasets LANL_2021_2024 CICIoV2024 --sample-size 5000

# All available datasets with sampling for memory management
python -m transformer.training.train_cybertransformer --epochs 100 --sample-size 10000
```

### Dataset Registry
```python
from scripts.dataset_registry import get_all_datasets, load_dataset, print_dataset_summary

# List all available datasets
print_dataset_summary()

# Load specific dataset with sampling
df = load_dataset("CICIoV2024", sample_size=10000)

# Validate MITRE tactic coverage
from scripts.dataset_registry import validate_dataset_tactics
coverage = validate_dataset_tactics("Datasense_IIoT_2025")
print(f"Coverage: {coverage['coverage_percentage']:.1f}%")
```

### RL Agent Training
```python
from core.rl_attack_predictor import RLThresholdOptimizer
optimizer = RLThresholdOptimizer(threshold_dict, agent_path='models/rl_agent.pt')
# Train via feedback loop during analyst review
```

### Model Checkpoints
- **Location:** `models/checkpoints/`
- **Naming:** `{dataset}_{method}_{timestamp}.pt`
- **Versioning:** Automatic via `rl_model_manager.py`

---

## Known Limitations

| Issue | Status | Workaround |
|-------|--------|------------|
| Real-time streaming | 🔶 Partial | Use batch mode with 1-min windows |
| Cross-domain transfer | 🔶 Research | Fine-tune per domain |
| Transformer memory | 🔶 8GB limit | Use gradient checkpointing |

---

*Last commit: [git_hash to be filled]*
