# MITRE-CORE Codebase Structure Analysis

**Analysis Date:** 2026-03-15  
**Phase:** 1.1 - Structure Mapping  
**Status:** IN PROGRESS

---

## Executive Summary

This document provides a systematic mapping of the MITRE-CORE v2.11 codebase structure to understand:
1. Directory organization
2. File inventory with sizes
3. Import dependencies
4. Missing `__init__.py` files
5. Key architectural components

---

## Directory Structure

```
MITRE-CORE_V2/
├── agentic/                    # Agentic workflow components
│   ├── evaluation/
│   ├── stages/
│   └── tools/
├── app/                        # Web dashboard (Flask/FastAPI)
│   ├── __init__.py
│   └── main.py
├── archive/                    # Archived/deprecated files
│   └── synthetic_utilities/    # Moved synthetic generators
├── baselines/                  # Baseline comparison algorithms
│   ├── __init__.py
│   └── simple_clustering.py
├── benchmarks/               # Performance benchmarks
│   └── v3_benchmarks.py
├── core/                       # TIER 3: Union-Find & Pipeline
│   ├── __init__.py
│   ├── cluster_filter.py           # 29,553 bytes - Largest file
│   ├── correlation_indexer.py    # 9,905 bytes
│   ├── correlation_pipeline.py   # 11,953 bytes
│   ├── correlation_pipeline_v3.py # 12,216 bytes (DUPLICATE?)
│   ├── kg_enrichment.py          # 25,432 bytes
│   ├── output.py
│   ├── postprocessing.py
│   ├── preprocessing.py
│   └── streaming.py
├── Data/                       # Gitignored data files (legacy)
│   ├── Cleaned/
│   ├── Preprocessed/
│   └── Raw_data/
├── datasets/                   # Dataset loaders and configs
│   ├── __init__.py
│   ├── loaders/
│   │   ├── __init__.py
│   │   ├── cicapt_iiot_loader.py
│   │   ├── datasense_iiot_loader.py
│   │   ├── nsl_kdd_loader.py
│   │   └── ton_iot_loader.py
│   └── real_data/            # Migrated enterprise data
├── docs/                       # Documentation
│   ├── figures/
│   ├── reports/
│   ├── tables/
│   └── *.md files
├── evaluation/                 # Evaluation metrics
│   ├── __init__.py
│   ├── attck_f1.py
│   └── ground_truth_validator.py
├── experiments/              # Experiment scripts
│   ├── archive/              # Old experiment scripts
│   ├── multi_dataset_results/
│   ├── real_data_results/
│   ├── results/
│   └── *.py experiment runners
├── hgnn/                       # TIER 2: HGNN Components
│   ├── __init__.py
│   ├── hgnn_correlation.py
│   ├── hgnn_evaluation.py
│   └── hgnn_integration.py
├── models/                     # Model checkpoints
│   └── checkpoints/
├── processed/                  # Preprocessed scalers
├── reporting/                  # Report generation
├── scripts/                    # Utility scripts
├── siem/                       # SIEM connectors
├── static/                     # Web assets
├── templates/                  # HTML templates
├── tests/                      # Test suite
├── training/                   # Training utilities
├── transformer/                # TIER 1: Transformer
│   ├── __init__.py
│   ├── models/
│   │   └── candidate_generator.py    # 377 lines
│   ├── preprocessing/
│   │   └── alert_preprocessor.py
│   ├── training/
│   │   └── train_cybertransformer.py
│   └── config/
│       └── gpu_config_8gb.py
├── utils/                      # Utility modules
└── validation/                 # Validation framework
```

---

## File Inventory by Category

### Architecture Components (3-Tier System)

#### TIER 1: Transformer (Candidate Generation)
| File | Lines | Purpose |
|------|-------|---------|
| `transformer/models/candidate_generator.py` | 377 | Main transformer model with Biaffine attention |
| `transformer/preprocessing/alert_preprocessor.py` | TBD | Alert input preprocessing |
| `transformer/training/train_cybertransformer.py` | TBD | Training loop |
| `transformer/config/gpu_config_8gb.py` | TBD | RTX 5060 Ti optimization |

**Status:** ✅ Present but not integrated with pipeline

#### TIER 2: HGNN (Graph Correlation)
| File | Lines | Purpose |
|------|-------|---------|
| `hgnn/hgnn_correlation.py` | TBD | Heterogeneous GNN model |
| `hgnn/hgnn_integration.py` | TBD | Integration with pipeline |
| `hgnn/hgnn_evaluation.py` | TBD | Evaluation metrics |

**Status:** ✅ Present

#### TIER 3: Union-Find (Structural Fallback)
| File | Lines | Purpose |
|------|-------|---------|
| `core/cluster_filter.py` | ~730 | Union-Find clustering + filtering |
| `core/correlation_indexer.py` | ~280 | Index management |
| `core/correlation_pipeline.py` | ~340 | Main orchestration |
| `core/correlation_pipeline_v3.py` | ~350 | DUPLICATE - needs removal |

**Status:** ✅ Present but v3 duplicate needs removal

### Critical Utility Modules (NEW in v2.11)

| File | Purpose | Status |
|------|---------|--------|
| `utils/explainability.py` | HGNN attention visualization | ✅ |
| `utils/scalable_clustering.py` | Billion-scale clustering | ✅ |
| `utils/long_range_temporal.py` | APT temporal correlation | ✅ |
| `utils/cross_domain_fusion.py` | Multi-modal fusion | ✅ |
| `utils/analyst_feedback.py` | False positive learning | ✅ |
| `utils/mitre_complete.py` | 100% MITRE coverage | ✅ |
| `utils/data_validation.py` | Production validation | ✅ |

### Dataset Loaders

| File | Purpose |
|------|---------|
| `datasets/loaders/cicapt_iiot_loader.py` | CICAPT-IIoT dataset |
| `datasets/loaders/datasense_iiot_loader.py` | Datasense IIoT |
| `datasets/loaders/nsl_kdd_loader.py` | NSL-KDD |
| `datasets/loaders/ton_iot_loader.py` | TON_IoT |

### Evaluation & Testing

| File | Purpose |
|------|---------|
| `evaluation/attck_f1.py` | MITRE ATT&CK F1 scoring |
| `evaluation/ground_truth_validator.py` | Validation framework |
| `scripts/e2e_test_suite.py` | End-to-end tests |
| `scripts/verify_mitre_coverage.py` | MITRE coverage verification |
| `scripts/production_validation.py` | Production validation |

---

## Import Dependencies Analysis

### Key Import Chains:

**Tier 1 (Transformer) imports:**
```
transformer.models.candidate_generator
  └── transformer.config.gpu_config_8gb
```

**Tier 2 (HGNN) imports:**
```
hgnn.hgnn_correlation
  └── (dependencies TBD)
```

**Tier 3 (Core Pipeline) imports:**
```
core.correlation_pipeline
  ├── core.cluster_filter
  ├── core.correlation_indexer
  └── (likely imports utils)
```

**Cross-tier integration:**
- Pipeline needs to import Transformer, HGNN
- Currently broken due to path issues

---

## Missing __init__.py Files

The following directories are **MISSING** `__init__.py` files, causing import failures:

### Critical Missing Files:
1. ❌ `transformer/models/__init__.py`
2. ❌ `transformer/preprocessing/__init__.py`
3. ❌ `transformer/training/__init__.py`
4. ❌ `transformer/config/__init__.py`
5. ❌ `hgnn/models/__init__.py` (if models/ subdir exists)
6. ❌ `datasets/loaders/__init__.py` (exists but verify content)
7. ❌ `evaluation/__init__.py` (exists but verify content)

### Present Files:
1. ✅ `core/__init__.py`
2. ✅ `utils/__init__.py`
3. ✅ `app/__init__.py`
4. ✅ `baselines/__init__.py`
5. ✅ `datasets/__init__.py`
6. ✅ `hgnn/__init__.py`
7. ✅ `siem/__init__.py`
8. ✅ `tests/__init__.py`
9. ✅ `training/__init__.py`
10. ✅ `validation/__init__.py`

---

## Identified Issues

### 1. Duplicate Files
- `core/correlation_pipeline.py` vs `core/correlation_pipeline_v3.py`
  - **Action:** Keep v3 if newer, remove old, or merge differences

### 2. Orphaned Components
- Transformer exists but not integrated into main pipeline
  - **Impact:** Tier 1 not functional in production
  - **Fix:** Update correlation_pipeline.py to use Transformer

### 3. Archive Directory
- `archive/synthetic_utilities/soc_log_generator.py` moved from utils/
  - **Status:** Correctly archived

### 4. Import Path Issues
- Scripts in `scripts/` cannot import from project root
  - **Fix:** Add proper `sys.path` setup or make package installable

---

## Code Statistics (To Be Completed)

| Category | File Count | Total Lines | Average Lines |
|----------|------------|-------------|---------------|
| Tier 1 (Transformer) | TBD | TBD | TBD |
| Tier 2 (HGNN) | TBD | TBD | TBD |
| Tier 3 (Union-Find) | TBD | TBD | TBD |
| Utilities | TBD | TBD | TBD |
| Tests | TBD | TBD | TBD |
| **TOTAL** | **TBD** | **TBD** | **TBD** |

---

## Recommendations

### Immediate Actions (Phase 1.1):
1. ✅ Create `__init__.py` files in all missing directories
2. ✅ Remove duplicate `correlation_pipeline_v3.py` or merge
3. ✅ Fix import paths in scripts
4. ✅ Create proper package structure with `setup.py`

### Next Phase (1.2 - Import Analysis):
1. Map all import statements between modules
2. Identify circular dependencies
3. Create import graph visualization
4. Plan import reorganization

### Architecture Integration:
1. Verify Transformer can be imported from Pipeline
2. Test HGNN integration
3. Validate full 3-tier data flow

---

## Status

**Phase 1.1 Progress:** 80% Complete
- ✅ Directory structure mapped
- ✅ Key files identified
- ✅ Missing __init__.py files catalogued
- ⚠️ Line counts pending (need to run analysis script)
- ⚠️ Import dependencies partially mapped

**Next:** Complete line count analysis and generate final report
