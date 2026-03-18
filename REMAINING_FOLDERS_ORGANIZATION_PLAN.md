# Remaining Folders Organization Plan

## Analysis Summary

| Folder | Items | Status | Action Needed |
|--------|-------|--------|---------------|
| **scripts/** | 12 files | ⚠️ Needs work | Categorize into subdirectories |
| **docs/** | 30+ files | ⚠️ Needs work | Organize by type (architecture, reports, research) |
| **models/** | 271 checkpoints | ⚠️ Needs work | Organize by version/dataset |
| **utils/** | 1 file | ✅ Good | Consolidate utilities here |
| **training/** | 6 files | ✅ Good | Already organized |
| **Empty dirs** | 10 dirs | ❌ Remove | Delete unused directories |

---

## 1. Scripts Directory Organization

### Current State
```
scripts/
├── aggregate_results.py
├── check_gpu.py
├── cleanup_old_data.py
├── create_tactic_map.py
├── generate_experiment_log.py
├── generate_figures.py
├── organize_codebase.py
├── run_mitre_analysis.py
├── security_scan.py
├── smoke_test_confidence_gate.py
└── verify_logging.py
```

### Proposed Structure
```
scripts/
├── analysis/              # Data analysis scripts
│   ├── aggregate_results.py
│   ├── generate_figures.py
│   └── run_mitre_analysis.py
├── maintenance/           # Cleanup & maintenance
│   ├── cleanup_old_data.py
│   ├── organize_codebase.py
│   └── verify_logging.py
├── security/              # Security scanning
│   └── security_scan.py
├── setup/                 # Setup & initialization
│   ├── check_gpu.py
│   ├── create_tactic_map.py
│   └── generate_experiment_log.py
└── testing/               # Testing utilities
    └── smoke_test_confidence_gate.py
```

---

## 2. Documentation Organization

### Current State
30+ files scattered in docs/

### Proposed Structure
```
docs/
├── architecture/          # System design docs
│   ├── ARCHITECTURE.md
│   ├── ARCHITECTURE_AND_DATASETS.md
│   └── foundation_model_split.md
├── research/              # Research papers & reviews
│   ├── IEEE_Research_Paper_MITRE_CORE.md
│   ├── literature_review_plan.md
│   └── research_roadmap.md
├── reports/               # Implementation reports
│   ├── FINAL_PHASE1_COMPLETION_REPORT.md
│   ├── IMPLEMENTATION_SUMMARY.md
│   ├── EXECUTION_SUMMARY.md
│   └── CYBERTRANSFORMER_*.md
├── planning/              # Planning docs
│   ├── FIX_PLAN.md
│   ├── PENDING_CHANGES.md
│   └── PROJECT_SUMMARY*.md
├── figures/               # Documentation figures
├── tables/                # Documentation tables
└── misc/                  # Other docs
    ├── RESUME_POINTS.md
    ├── SELF_EVALUATION_REPORT.md
    └── prompt*.md
```

---

## 3. Models Directory Organization

### Current State
271 checkpoint files in models/checkpoints/

### Proposed Structure
```
models/
├── checkpoints/
│   ├── v1_legacy/         # Pre-v2.0 models (archive)
│   ├── v2_x/              # v2.1 series
│   │   ├── union_find/
│   │   └── hgnn/
│   └── v2_x/              # v2.1 transformer models
│       ├── transformer/
│       └── hybrid/
├── logs/                  # Training logs
└── README.md              # Model documentation
```

---

## 4. Empty Directories to Remove

These directories have 0 items and appear unused:

- `Data/` → Remove or use for raw data
- `Testing/` → Remove (duplicates `tests/`)
- `logs/` → Remove or consolidate logs here
- `agentic/` → Remove (empty)
- `archive/` → Remove (empty - we use folder-specific archives)
- `datasets/` → Keep (expected for datasets)
- `benchmarks/` → Merge into experiments/
- `processed/` → Merge into datasets/processed/

---

## 5. Consolidation Opportunities

### Merge evaluation/ + reporting/
These appear to overlap. Suggest:
```
reporting/              # Keep this name
├── evaluation/         # Move evaluation/ contents here
├── metrics/
└── exporters/
```

### Merge utils/ + core/utils/
If core/ has utility files, move to utils/:
```
utils/
├── seed_control.py
├── logging_utils.py    # If exists in core/
└── data_utils.py       # If exists in core/
```

---

## 6. Final Clean Structure

```
MITRE-CORE/
├── app/                 # Flask web app
├── core/                # Domain logic
│   ├── cluster_filter.py
│   ├── correlation_pipeline.py
│   ├── kg_enrichment.py
│   ├── streaming.py
│   └── ...
├── hgnn/                # HGNN models
├── transformer/         # Transformer models
├── siem/                # SIEM integration
├── api/                 # API layer (if separate from app/)
├── infrastructure/      # External services
│   ├── storage/
│   ├── ml/
│   └── connectors/
├── scripts/             # Categorized scripts
│   ├── analysis/
│   ├── maintenance/
│   ├── security/
│   ├── setup/
│   └── testing/
├── docs/                # Categorized documentation
│   ├── architecture/
│   ├── research/
│   ├── reports/
│   └── planning/
├── experiments/         # Experiment runners & results
│   ├── runners/        # Move active experiment scripts here
│   ├── results/
│   └── archive/
├── tests/               # Test suite
├── validation/          # Unified validation
├── training/            # Training scripts
├── models/              # Organized checkpoints
├── utils/               # Utilities
├── datasets/            # Dataset storage
├── templates/           # HTML templates
├── static/              # CSS/JS assets
└── requirements.txt     # Dependencies
```

---

## Implementation Priority

1. **High Priority:** Organize scripts/ (currently messy)
2. **High Priority:** Organize docs/ (30+ scattered files)
3. **Medium Priority:** Organize models/checkpoints/ (271 files)
4. **Low Priority:** Remove empty directories
5. **Low Priority:** Consolidate evaluation/ + reporting/
