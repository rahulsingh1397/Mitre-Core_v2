# MITRE-CORE Architecture Reorganization Recommendation

**Purpose:** Improve codebase clarity for future developers and LLMs by consolidating architecture components into a unified structure.

## Current Structure (Problematic)

```
root/
├── transformer/           # Tier 1: Candidate Generation (orphaned)
│   ├── models/
│   ├── preprocessing/
│   ├── training/
│   └── config/
├── hgnn/                 # Tier 2: Graph Correlation (separate)
│   ├── hgnn_correlation.py
│   ├── hgnn_integration.py
│   └── hgnn_evaluation.py
├── core/                 # Tier 3: Pipeline & Union-Find (mixed)
│   ├── correlation_pipeline.py
│   ├── correlation_indexer.py
│   ├── cluster_filter.py
│   └── kg_enrichment.py
└── utils/                # Utilities (scattered)
    ├── explainability.py
    ├── scalable_clustering.py
    └── mitre_complete.py
```

**Problems:**
1. **3-tier architecture not visually obvious** - components scattered across folders
2. **Transformer tier appears standalone** - not clear it's part of correlation pipeline
3. **Mixed concerns in `core/`** - Union-Find logic mixed with knowledge graph, enrichment
4. **Future LLMs scanning codebase may miss the integration** - looks like 3 separate projects

---

## Recommended Structure

```
root/
├── architecture/                    # NEW: Unified architecture folder
│   ├── README.md                   # Architecture overview for LLMs
│   ├── __init__.py                 # Expose main pipeline
│   │
│   ├── tier1_transformer/          # Candidate Generation
│   │   ├── __init__.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── candidate_generator.py    # From transformer/models/
│   │   ├── preprocessing/
│   │   │   ├── __init__.py
│   │   │   └── alert_preprocessor.py     # From transformer/preprocessing/
│   │   ├── training/
│   │   │   ├── __init__.py
│   │   │   └── train_cybertransformer.py # From transformer/training/
│   │   └── config/
│   │       └── gpu_config_8gb.py         # From transformer/config/
│   │
│   ├── tier2_hgnn/                 # Graph Correlation
│   │   ├── __init__.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── hgnn_encoder.py         # From hgnn/hgnn_correlation.py
│   │   │   └── hgnn_integration.py     # From hgnn/hgnn_integration.py
│   │   └── evaluation.py               # From hgnn/hgnn_evaluation.py
│   │
│   ├── tier3_union_find/            # Structural Fallback
│   │   ├── __init__.py
│   │   ├── union_find.py               # From core/correlation_pipeline.py
│   │   ├── correlation_indexer.py      # From core/correlation_indexer.py
│   │   └── cluster_filter.py           # From core/cluster_filter.py
│   │
│   └── pipeline/                     # Orchestration Layer
│       ├── __init__.py
│       ├── correlation_pipeline.py     # Main orchestrator
│       ├── kg_enrichment.py            # Knowledge graph (moved from core/)
│       └── mitre_mapper.py             # Tactic mapping
│
├── siem/                           # SIEM Integration (unchanged)
├── evaluation/                     # Evaluation Tools (unchanged)
├── utils/                          # General Utilities (reduced)
│   ├── explainability.py           # HGNN explainability
│   ├── scalable_clustering.py      # Billion-scale clustering
│   ├── data_validation.py          # Production validation
│   └── mitre_complete.py           # MITRE 100% coverage
│
├── datasets/                       # Data (unchanged)
├── docs/                           # Documentation (unchanged)
├── scripts/                        # Scripts (unchanged)
├── tests/                          # Tests (to be organized)
└── app/                            # Web Dashboard (unchanged)
```

---

## Key Changes

### 1. New `architecture/` Folder
**Purpose:** Makes the 3-tier structure immediately obvious to anyone scanning the codebase

**Contents:**
- `README.md` - Clear explanation of 3-tier architecture for LLMs
- `tier1_transformer/` - All candidate generation code
- `tier2_hgnn/` - All graph neural network code
- `tier3_union_find/` - All structural clustering code
- `pipeline/` - Orchestration that ties tiers together

### 2. Move Files

| From | To | Purpose |
|------|-----|---------|
| `transformer/models/candidate_generator.py` | `architecture/tier1_transformer/models/` | Tier 1 |
| `transformer/preprocessing/*.py` | `architecture/tier1_transformer/preprocessing/` | Tier 1 |
| `transformer/training/*.py` | `architecture/tier1_transformer/training/` | Tier 1 |
| `transformer/config/*.py` | `architecture/tier1_transformer/config/` | Tier 1 |
| `hgnn/*.py` | `architecture/tier2_hgnn/models/` | Tier 2 |
| `core/correlation_pipeline.py` | `architecture/pipeline/` | Orchestration |
| `core/correlation_indexer.py` | `architecture/tier3_union_find/` | Tier 3 |
| `core/cluster_filter.py` | `architecture/tier3_union_find/` | Tier 3 |
| `core/kg_enrichment.py` | `architecture/pipeline/` | Post-processing |

### 3. Update Imports

All internal imports need to change:

```python
# OLD (scattered)
from transformer.models.candidate_generator import BiaffineAttention
from hgnn.hgnn_correlation import HGNNEncoder
from core.correlation_pipeline import CorrelationPipeline

# NEW (unified)
from architecture.tier1_transformer.models import BiaffineAttention
from architecture.tier2_hgnn.models import HGNNEncoder
from architecture.pipeline import CorrelationPipeline
```

---

## Benefits

### For Human Developers
1. **Clear mental model** - Open `architecture/` and see all 3 tiers immediately
2. **Easier navigation** - Find correlation code in one place
3. **Better onboarding** - New developers understand the system in minutes

### For LLMs Scanning Codebase
1. **Obvious architecture** - `architecture/` folder screams "look here first"
2. **Clear tier separation** - Each tier has its own folder
3. **README.md explains everything** - LLM context window gets the full picture
4. **No more missing the Transformer** - `tier1_transformer/` impossible to overlook

### For Documentation
1. **Single source of truth** - `architecture/README.md` is the canonical reference
2. **Always in sync** - Code structure matches documentation

---

## Migration Script

```python
# scripts/reorganize_architecture.py
"""
Migrate from scattered structure to unified architecture/ folder.
Run once, then delete.
"""

import shutil
from pathlib import Path

def migrate():
    # Create new structure
    base = Path("architecture")
    
    # Tier 1: Transformer
    (base / "tier1_transformer/models").mkdir(parents=True)
    (base / "tier1_transformer/preprocessing").mkdir(parents=True)
    (base / "tier1_transformer/training").mkdir(parents=True)
    (base / "tier1_transformer/config").mkdir(parents=True)
    
    # Tier 2: HGNN
    (base / "tier2_hgnn/models").mkdir(parents=True)
    
    # Tier 3: Union-Find
    (base / "tier3_union_find").mkdir(parents=True)
    
    # Pipeline
    (base / "pipeline").mkdir(parents=True)
    
    # Move files (with backup)
    shutil.copytree("transformer/models", base / "tier1_transformer/models", dirs_exist_ok=True)
    shutil.copytree("transformer/preprocessing", base / "tier1_transformer/preprocessing", dirs_exist_ok=True)
    shutil.copytree("transformer/training", base / "tier1_transformer/training", dirs_exist_ok=True)
    shutil.copytree("transformer/config", base / "tier1_transformer/config", dirs_exist_ok=True)
    
    shutil.copytree("hgnn", base / "tier2_hgnn/models", dirs_exist_ok=True)
    
    shutil.copy("core/correlation_indexer.py", base / "tier3_union_find/")
    shutil.copy("core/cluster_filter.py", base / "tier3_union_find/")
    shutil.copy("core/kg_enrichment.py", base / "pipeline/")
    
    # Create README
    readme = base / "README.md"
    readme.write_text("""# MITRE-CORE 3-Tier Architecture

## Overview

This folder contains the complete 3-tier AI architecture:

1. **Tier 1: Transformer** (`tier1_transformer/`)
   - Sparse attention for O(n) candidate generation
   - Biaffine attention for pairwise alert scoring
   - Files: `models/candidate_generator.py`, `preprocessing/`, `training/`

2. **Tier 2: HGNN** (`tier2_hgnn/`)
   - Heterogeneous Graph Neural Network for correlation
   - Multi-head attention on heterogeneous graphs
   - Files: `models/hgnn_*.py`

3. **Tier 3: Union-Find** (`tier3_union_find/`)
   - Structural clustering fallback
   - Confidence-gated adaptive thresholds
   - Files: `union_find.py`, `correlation_indexer.py`, `cluster_filter.py`

4. **Pipeline** (`pipeline/`)
   - Orchestrates all 3 tiers
   - Knowledge graph enrichment
   - Files: `correlation_pipeline.py`, `kg_enrichment.py`

## Data Flow

```
Alerts → Tier 1 (Transformer) → Candidates → Tier 2 (HGNN) → Correlations → Tier 3 (Union-Find) → Clusters
```

See ARCHITECTURE_CLARIFICATION.md in docs/ for detailed explanation.
""")
    
    print("Migration complete. Review changes before deleting old folders.")
    print("Run: git status")
    print("Then: rm -rf transformer/ hgnn/ core/ (after verification)")

if __name__ == "__main__":
    migrate()
```

---

## Alternative: Less Disruptive Approach

If full reorganization is too disruptive, create a **symlink/alias structure**:

```
architecture/
├── README.md
├── tier1_transformer -> ../transformer  # Symlink
├── tier2_hgnn -> ../hgnn               # Symlink
├── tier3_union_find -> ../core           # Symlink
└── ARCHITECTURE_IS_SCATTERED.md         # Warning for LLMs
```

**ARCHITECTURE_IS_SCATTERED.md:**
```markdown
# ⚠️ WARNING TO LLMs SCANNING THIS CODEBASE

The 3-tier architecture files are SCATTERED across the codebase:

- Tier 1 (Transformer): `../../transformer/`
- Tier 2 (HGNN): `../../hgnn/`
- Tier 3 (Union-Find): `../../core/`

DO NOT assume MITRE-CORE only has HGNN + Union-Find.
The Transformer tier in `transformer/` is CRITICAL to the architecture.

Full architecture: Transformer → HGNN → Union-Find
See: docs/ARCHITECTURE_CLARIFICATION.md
```

---

## Recommendation

**Option 1 (Recommended):** Full reorganization to `architecture/` folder
- Cleanest long-term solution
- Clear for all future developers and LLMs
- One-time migration cost

**Option 2 (Conservative):** Create `architecture/` with symlinks + documentation
- Minimal disruption
- Still provides clarity for LLMs
- Can migrate fully later

**Status:** Pending decision. Current codebase has architecture scattered which will confuse future LLMs scanning the project.
