# MITRE-CORE v2 — Fix Plan & Structural Reorganisation
**Generated:** 2026-03-07
**Status:** COMPLETE — all items implemented 2026-03-07. See PENDING_CHANGES.md for next wave.
**Scope:** Broken imports, wrong defaults, and full directory restructure

---

## Table of Contents
1. [P1 — Broken Imports (App Crashes on Start)](#p1--broken-imports-app-crashes-on-start)
2. [P1 — Default Flag Fix](#p1--default-flag-fix)
3. [P2 — Secondary Broken Imports](#p2--secondary-broken-imports)
4. [P3 — File Structure Reorganisation](#p3--file-structure-reorganisation)
5. [P4 — Checkpoint Consolidation](#p4--checkpoint-consolidation)
6. [P5 — Experiment Artifact Cleanup](#p5--experiment-artifact-cleanup)
7. [Verification Checklist](#verification-checklist)

---

## P1 — Broken Imports (App Crashes on Start)

These three issues cause an immediate `ImportError` when `app/main.py` starts.
Fix all three before running the app again.

---

### Fix 1A — `import Testing` (5 files affected)

**Problem:**
The `Testing/` directory has no `__init__.py` and no Python source file.
`Testing.build_data()` is called in five locations but the function does not exist anywhere in the codebase.

**Files broken:**
```
app/main.py                      line 30, 252
app.py                           line 309
core/correlation_indexer.py      line 494
evaluation/comprehensive_evaluation.py  line 121
experiments/generate_figures.py  line 69
```

**Contents of Testing/ right now:**
```
Testing/
  test_incident.json   ← data file, not Python
  __pycache__/         ← stale cache from a deleted module
```

**What `build_data(n_samples)` must return:**
A `pd.DataFrame` with at least these columns, mimicking real alert data:
```
EndDate, SourceAddress, DestinationAddress, DeviceAddress,
SourceHostName, DeviceHostName, DestinationHostName,
MalwareIntelAttackType, pred_cluster (optional, for labeled tests)
```

**Fix — create `Testing/__init__.py`:**

Create the file `Testing/__init__.py` with a `build_data(n_samples)` function that generates synthetic alert rows. The function should:
- Accept a single integer `n_samples`
- Return a `pd.DataFrame` with the columns listed above
- Distribute rows across 3–5 attack types (e.g. "Lateral Movement", "Exfiltration", "Reconnaissance", "Persistence", "Command and Control")
- Assign random but plausible IP addresses (e.g. `192.168.x.y` for source, `10.0.x.y` for destination)
- Set `EndDate` to datetime strings spaced a few minutes apart
- Use `numpy.random` with a fixed seed (42) so results are reproducible

No ML or heavyweight dependencies — this is lightweight synthetic data only.

**After creating the file, verify:**
```bash
python -c "import Testing; df = Testing.build_data(10); print(df.columns.tolist())"
```
Expected: No error, prints column names.

---

### Fix 1B — `from correlation_indexer import enhanced_correlation` in `siem/ingestion_engine.py`

**Problem:**
Line 28 of `siem/ingestion_engine.py`:
```python
from correlation_indexer import enhanced_correlation
```
This is a bare module name with no package prefix. It only works if the working directory is `core/`, which it never is. The correct import path from any location is:
```python
from core.correlation_indexer import enhanced_correlation
```

**Fix — change line 28 of `siem/ingestion_engine.py`:**

Old:
```python
def _get_correlation_fn():
    global _enhanced_correlation
    if _enhanced_correlation is None:
        from correlation_indexer import enhanced_correlation
        _enhanced_correlation = enhanced_correlation
    return _enhanced_correlation
```

New:
```python
def _get_correlation_fn():
    global _enhanced_correlation
    if _enhanced_correlation is None:
        from core.correlation_indexer import enhanced_correlation
        _enhanced_correlation = enhanced_correlation
    return _enhanced_correlation
```

**After the fix, verify:**
```bash
python -c "from siem.ingestion_engine import IngestionEngine; print('OK')"
```
Expected: prints `OK` with no ImportError.

---

### Fix 1C — `from security import encrypt_value / decrypt_value` in `siem/ingestion_engine.py`

**Problem:**
Lines 446 and 461 of `siem/ingestion_engine.py`:
```python
from security import encrypt_value   # line 446
from security import decrypt_value   # line 461
```
`security.py` lives at the project root. This bare import works only when `sys.path` contains the project root — which is true at runtime but fragile and inconsistent with how every other module in the project imports (always using full package paths).

**Fix — change both lazy imports to use the absolute path:**

Line 446, inside `_redact_config()`:
```python
# Old
from security import encrypt_value

# New
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security import encrypt_value
```

A cleaner approach: move `security.py` to `core/security_utils.py` and update the import everywhere. But for a minimal fix, add the sys.path guard inside the two methods:

`_redact_config()` line 446:
```python
from security import encrypt_value   →   from security import encrypt_value  # already works via sys.path from app/main.py
```
This import is fine **when the app is started via `app/main.py`** because `app/main.py` adds PROJECT_ROOT to `sys.path` at lines 20–22. The issue only surfaces if `siem/ingestion_engine.py` is imported standalone (e.g. in unit tests).

**Recommended minimal fix:** add a `sys.path` guard at the top of `siem/ingestion_engine.py`, immediately after the existing imports:

```python
# Ensure project root is on path (needed when module is imported standalone)
import sys as _sys, os as _os
_PROJECT_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)
```

Add this block after line 18 (after `import pandas as pd`).

**After the fix, verify:**
```bash
python -c "from siem.ingestion_engine import IngestionEngine; e = IngestionEngine(); print('OK')"
```

---

## P1 — Default Flag Fix

### Fix 2 — `use_uf_refinement` default in `HGNNCorrelationEngine`

**File:** `hgnn/hgnn_correlation.py`
**Line:** 824

**Problem:**
```python
use_uf_refinement: bool = True,   # current default — WRONG
```
Every experiment from v2.6 onward confirms UF refinement is net-harmful for the UNSW-NB15 checkpoint:
- `use_uf_refinement=True` (baseline) → ARI = 0.3541, 1,855 clusters, singleton_fraction = 1.0
- `use_uf_refinement=False` (best result) → ARI = 0.4042, 6 clusters

Keeping `True` as the default means any code that instantiates `HGNNCorrelationEngine()` without explicit kwargs (the majority of callers) silently uses the worse configuration.

**Fix — change line 824:**
```python
# Old
use_uf_refinement: bool = True,

# New
use_uf_refinement: bool = False,
```

Also update the docstring on lines 857–862 to reflect the new default. Change:
```
When True (default), alerts below confidence_gate are sent through
the Union-Find refinement pass.
```
to:
```
When False (default), all alerts keep their HGNN cluster assignment
regardless of confidence. This is the empirically validated default
for the UNSW-NB15 checkpoint (ARI 0.4042 vs 0.3541 with UF enabled).
Set True only to explicitly test the hybrid UF path.
```

**Also update `core/correlation_pipeline.py`:**
The `CorrelationPipeline` auto-selection logic at the method boundary uses HGNN as the backend. Wherever it instantiates `HGNNCorrelationEngine`, confirm that no hardcoded `use_uf_refinement=True` override exists. If found, remove the override so the class default is respected.

**Verification:**
```bash
python -c "
from hgnn.hgnn_correlation import HGNNCorrelationEngine
import inspect
sig = inspect.signature(HGNNCorrelationEngine.__init__)
default = sig.parameters['use_uf_refinement'].default
assert default == False, f'Expected False, got {default}'
print('use_uf_refinement default is correctly False')
"
```

---

## P2 — Secondary Broken Imports

These do not crash the app on startup but will fail at runtime when the relevant code path is exercised.

### Fix 3 — `hgnn/hgnn_training.py` — `ContrastiveAlertLearner` and `GraphAugmenter`

**Problem:**
Lines 29–31 import `ContrastiveAlertLearner` and `GraphAugmenter` from `hgnn_correlation`. Verify that both names actually exist in `hgnn/hgnn_correlation.py`. If they do not:
- Option A: Search `mitre_core/models/objectives/contrastive.py` and `mitre_core/training/trainer.py` for equivalent classes and update the import path.
- Option B: If unused by any active code path, wrap the import in a `try/except ImportError` guard with a warning log.

**Check command:**
```bash
python -c "from hgnn.hgnn_training import HGNNTrainer; print('OK')"
```
If this raises `ImportError`, apply Option A or B above.

---

### Fix 4 — `hgnn/hgnn_integration.py` — `create_synthetic_training_data()`

**Problem:**
`migrate_to_hgnn()` calls `create_synthetic_training_data()` which is not defined anywhere in the codebase.

**Fix:**
Either:
- Point it at `Testing.build_data()` (once Fix 1A is applied): `df = Testing.build_data(100)`
- Or guard the function with a `NotImplementedError` stub until a real training dataset path is wired in.

---

### Fix 5 — `core/preprocessing.py` — KNNImputer hardcoded column count

**Problem:**
The KNNImputer is initialized for exactly 7 columns (line ~76). Any dataset with fewer or more numeric columns will raise a shape mismatch at inference time.

**Fix:**
Replace the hardcoded column list with dynamic detection:
```python
# Old
numeric_cols = ["col1", "col2", "col3", "col4", "col5", "col6", "col7"]

# New
numeric_cols = df.select_dtypes(include="number").columns.tolist()
```
Then apply the imputer only to `numeric_cols`. No hardcoded list.

---

## P3 — File Structure Reorganisation

The current layout has grown organically and has significant redundancy.
The target layout below rationalises it without breaking existing import paths.

### Current vs Target Layout

```
CURRENT (problems annotated)              TARGET (clean)
────────────────────────────              ──────────────
MITRE-CORE_V2/
├── app/                                  ├── app/
│   └── main.py                           │   └── main.py
├── app.py                ← DUPLICATE     │   (app.py at root → DELETE, use app/main.py)
├── baselines/                            ├── baselines/
│   └── simple_clustering.py             │   └── simple_clustering.py
├── checkpoints/          ← EMPTY        │   (DELETE — empty)
├── core/                                 ├── core/
│   ├── __init__.py                       │   ├── __init__.py
│   ├── correlation_indexer.py            │   ├── correlation_indexer.py
│   ├── correlation_pipeline.py           │   ├── correlation_pipeline.py
│   ├── output.py                         │   ├── output.py
│   ├── postprocessing.py                 │   ├── postprocessing.py
│   └── preprocessing.py                 │   └── preprocessing.py
├── Data/                                 ├── Data/
│   └── preprocessing/                   │   └── preprocessing/
├── datasets/                             ├── datasets/
│   └── loaders/                         │   └── loaders/
├── docs/                                 ├── docs/
│   ├── figures/                          │   ├── figures/
│   └── tables/                           │   └── tables/
├── evaluation/                           ├── evaluation/
├── evaluation_results/   ← REDUNDANT    │   (MERGE into experiments/results/ → DELETE dir)
├── experiments/                          ├── experiments/
│   ├── results/                          │   ├── results/
│   │   ├── gate_tuning_results_v2–v8.csv │   │   ├── archive/       ← move v2–v8 here
│   │   └── gate_tuning_results_v9.csv    │   │   └── gate_tuning_results_v9.csv  ← keep
│   └── *.py                             │   └── *.py
├── figures/              ← DUPLICATE    │   (MERGE contents into docs/figures/ → DELETE)
├── hgnn/                                 ├── hgnn/
│   └── *.py                             │   └── *.py
├── hgnn_checkpoints/                     ├── hgnn_checkpoints/          ← ONE canonical dir
│   ├── unsw_supervised.pt               │   ├── unsw_supervised.pt
│   ├── unsw_nb15_best.pt                │   ├── unsw_nb15_best.pt
│   ├── nsl_kdd_best.pt                  │   ├── nsl_kdd_best.pt
│   └── foundation_v2/                   │   ├── foundation_v2/
├── hgnn_checkpoints_enhanced/ ← MERGE   │   ├── nsl_kdd_optuna_best.pt  ← moved from enhanced/
├── hgnn_checkpoints_unsw/    ← MERGE    │   └── unsw_finetuned.pt       ← moved from unsw/
├── hgnn_evaluation_results/  ← REDUND. │   (MERGE into evaluation_results/ → DELETE dir)
├── mitre_core/                           ├── mitre_core/
│   └── *.py (deep structure)            │   └── *.py (unchanged)
├── outputs/              ← REDUNDANT    │   (MERGE any content into experiments/results/ → DELETE)
├── Plots/                ← DUPLICATE    │   (MERGE contents into docs/figures/ → DELETE)
├── processed/                            ├── processed/
├── reporting/                            ├── reporting/
├── results/              ← REDUNDANT    │   (MERGE into experiments/results/ → DELETE dir)
├── scripts/                              ├── scripts/
│   ├── update_memory_v5–v9.py ← ARCHIVE │   └── *.py (remove update_memory scripts)
├── security.py           ← ROOT LEVEL  │   (MOVE to core/security_utils.py)
├── siem/                                 ├── siem/
├── src/                  ← EMPTY       │   (DELETE — empty)
├── static/                               ├── static/
├── templates/                            ├── templates/
├── Testing/              ← BROKEN      │   ├── __init__.py  ← CREATE (Fix 1A)
│   └── test_incident.json               │   └── test_incident.json
├── tests/                                ├── tests/
├── training/                             ├── training/
├── utils/                                ├── utils/
│   └── seed_control.py  ← DUPLICATE    │   └── seed_control.py  (keep ONE copy)
│                                         │   (mitre_core/utils/seed_control.py → DELETE,
│                                         │    import from utils.seed_control everywhere)
├── validation/                           ├── validation/
│
│  ROOT-LEVEL SCRIPT SPRAWL — MOVE EACH:
├── app.py                → DELETE (duplicate of app/main.py)
├── evaluate_unsw.py      → experiments/evaluate_unsw.py
├── run_linux_apt_experiments.py → experiments/run_linux_apt_experiments.py
├── run_ton_iot_experiments.py   → experiments/run_ton_iot_experiments.py
├── run_multiseed_quick.py       → experiments/run_multiseed_quick.py
├── train_on_datasets.py         → training/train_on_datasets.py
├── plots.py              → reporting/plots.py
├── create_tactic_map.py  → scripts/create_tactic_map.py
├── linux_apt_mapper.py   → Data/preprocessing/linux_apt_mapper.py
├── ton_iot_mapper.py     → Data/preprocessing/ton_iot_mapper.py
├── test_annoy.py         → tests/test_annoy.py
├── test_annoy2.py        → tests/test_annoy2.py
└── security.py           → core/security_utils.py
```

---

### Step-by-Step Reorganisation Instructions

Execute these steps **in order**. Each step includes the exact shell commands to run.

#### Step 3.1 — Create the archive directory for old gate tuning results

```bash
mkdir -p "experiments/results/archive"
mv experiments/results/gate_tuning_results_v2.csv experiments/results/archive/
mv experiments/results/gate_tuning_results_v3.csv experiments/results/archive/
mv experiments/results/gate_tuning_results_v4.csv experiments/results/archive/
mv experiments/results/gate_tuning_results_v5.csv experiments/results/archive/
mv experiments/results/gate_tuning_results_v6.csv experiments/results/archive/
mv experiments/results/gate_tuning_results_v7.csv experiments/results/archive/
mv experiments/results/gate_tuning_results_v8.csv experiments/results/archive/
# Leave v9 in experiments/results/ — it is the current canonical result
```

#### Step 3.2 — Merge redundant result directories

```bash
# Move any files from evaluation_results/ into experiments/results/
cp -rn evaluation_results/* experiments/results/ 2>/dev/null || true

# Move any files from hgnn_evaluation_results/ into experiments/results/
cp -rn hgnn_evaluation_results/* experiments/results/ 2>/dev/null || true

# Move any files from outputs/ into experiments/results/
cp -rn outputs/* experiments/results/ 2>/dev/null || true

# Move any files from results/ (root-level) into experiments/results/
cp -rn results/* experiments/results/ 2>/dev/null || true
```

**Verify no files were lost:**
```bash
ls evaluation_results/ hgnn_evaluation_results/ outputs/ results/
```
Once confirmed, delete the empty dirs:
```bash
rmdir evaluation_results hgnn_evaluation_results outputs results
```

#### Step 3.3 — Merge redundant figure directories

```bash
# Move everything from figures/ and Plots/ into docs/figures/
cp -rn figures/* docs/figures/ 2>/dev/null || true
cp -rn Plots/* docs/figures/ 2>/dev/null || true
```

Verify, then:
```bash
rmdir figures Plots
```

#### Step 3.4 — Merge hgnn checkpoint directories

```bash
# Move checkpoint files from enhanced/ and unsw/ into the canonical hgnn_checkpoints/
cp hgnn_checkpoints_enhanced/nsl_kdd_optuna_best.pt hgnn_checkpoints/
cp hgnn_checkpoints_enhanced/unsw_finetuned.pt      hgnn_checkpoints/
cp hgnn_checkpoints_unsw/unsw_nb15_hgnn_stats.json  hgnn_checkpoints/ 2>/dev/null || true
```

Write a `hgnn_checkpoints/README.md` that maps each `.pt` file to its experiment:

```markdown
# Checkpoint Index

| File                      | Trained on    | Labels col   | Epoch | Notes                          |
|---------------------------|---------------|--------------|-------|--------------------------------|
| unsw_supervised.pt        | UNSW-NB15     | campaign_id  | last  | Current default checkpoint     |
| unsw_nb15_best.pt         | UNSW-NB15     | campaign_id  | best  | Best val-ARI during training   |
| nsl_kdd_best.pt           | NSL-KDD       | attack_cat   | best  | OOD for non-KDD datasets       |
| nsl_kdd_optuna_best.pt    | NSL-KDD       | attack_cat   | best  | Optuna-tuned hyperparams       |
| unsw_finetuned.pt         | UNSW-NB15     | campaign_id  | fine  | Fine-tuned from unsw_nb15_best |
| foundation_v2/            | 5 datasets    | mixed        | 10-50 | Foundation pretraining         |
| checkpoints/              | Various       | various      | misc  | Ablation D, pretrain C         |
```

Then delete the now-empty dirs:
```bash
# Only after verifying cp succeeded
rmdir hgnn_checkpoints_enhanced hgnn_checkpoints_unsw
```

#### Step 3.5 — Delete empty directories

```bash
rmdir checkpoints 2>/dev/null || echo "checkpoints/ not empty — check contents"
rmdir src         2>/dev/null || echo "src/ not empty — check contents"
```

**Do not delete `Testing/` yet** — it becomes a real module in Fix 1A.

#### Step 3.6 — Move root-level scripts to their proper homes

Each of these files must be moved, then any internal import paths updated if they use relative references.

```bash
# Experiments
mv evaluate_unsw.py            experiments/evaluate_unsw.py
mv run_linux_apt_experiments.py experiments/run_linux_apt_experiments.py
mv run_ton_iot_experiments.py   experiments/run_ton_iot_experiments.py
mv run_multiseed_quick.py       experiments/run_multiseed_quick.py

# Training
mv train_on_datasets.py         training/train_on_datasets.py

# Reporting / visualisation
mv plots.py                     reporting/plots.py

# Data / preprocessing
mv linux_apt_mapper.py          Data/preprocessing/linux_apt_mapper.py
mv ton_iot_mapper.py            Data/preprocessing/ton_iot_mapper.py
mv create_tactic_map.py         scripts/create_tactic_map.py

# Tests
mv test_annoy.py                tests/test_annoy.py
mv test_annoy2.py               tests/test_annoy2.py
```

**After each move**, run the file and check it still imports cleanly:
```bash
python -c "import py_compile; py_compile.compile('experiments/evaluate_unsw.py'); print('OK')"
```

#### Step 3.7 — Move `security.py` to `core/security_utils.py`

```bash
cp security.py core/security_utils.py
```

Update all imports of `from security import ...` → `from core.security_utils import ...` in:
- `siem/ingestion_engine.py` lines 446 and 461
- Any other file discovered by: `grep -rn "from security import\|import security" . --include="*.py" --exclude-dir=.venv`

After updating all callers:
```bash
rm security.py
```

Verify:
```bash
python -c "from core.security_utils import encrypt_value, decrypt_value; print('OK')"
python -c "from siem.ingestion_engine import IngestionEngine; print('OK')"
```

#### Step 3.8 — Delete duplicate `app.py` at root

Confirm that `app.py` and `app/main.py` are functionally identical (or that `app.py` is the older version). If `app/main.py` is the authoritative one:
```bash
diff app.py app/main.py
```
If the diff is empty or `app.py` is a strict subset:
```bash
rm app.py
```
Update any launch scripts or Dockerfiles that reference `app.py` to use `app/main.py` or the module path `app.main`.

#### Step 3.9 — Deduplicate `seed_control.py`

Both `utils/seed_control.py` and `mitre_core/utils/seed_control.py` exist. Keep `utils/seed_control.py` as canonical.

Find all files that import from `mitre_core.utils.seed_control`:
```bash
grep -rn "mitre_core.utils.seed_control\|from mitre_core.utils import seed_control" . --include="*.py" --exclude-dir=.venv
```

For each file found, change:
```python
from mitre_core.utils.seed_control import set_seed
# →
from utils.seed_control import set_seed
```

Then delete the duplicate:
```bash
rm mitre_core/utils/seed_control.py
```

#### Step 3.10 — Archive `scripts/update_memory_v*.py`

These are one-time execution scripts that have already run. Keep them for reference but move to an archive:
```bash
mkdir -p scripts/archive
mv scripts/update_memory_v5.py scripts/archive/
mv scripts/update_memory_v6.py scripts/archive/
mv scripts/update_memory_v7.py scripts/archive/
mv scripts/update_memory_v8.py scripts/archive/
mv scripts/update_memory_v9.py scripts/archive/
```

---

## P4 — Checkpoint Consolidation

After Step 3.4, add a `model_config.json` alongside each `.pt` file. This is the missing metadata that makes checkpoints reproducible.

**Template for `hgnn_checkpoints/unsw_supervised_config.json`:**
```json
{
  "checkpoint_file": "unsw_supervised.pt",
  "trained_on": "UNSW-NB15",
  "label_column": "campaign_id",
  "model_kwargs": {
    "hidden_dim": 128,
    "num_heads": 4,
    "num_layers": 1,
    "dropout": 0.3
  },
  "training": {
    "epochs": "unknown — not recorded",
    "best_val_ari": "unknown — not recorded",
    "seed": 42
  },
  "use_uf_refinement_default": false,
  "notes": "Primary checkpoint used in v2.6–v2.9 gate tuning. ARI=0.4042 with UF disabled."
}
```

Create a similar config file for each `.pt` in `hgnn_checkpoints/`.

---

## P5 — Experiment Artifact Cleanup

### Cleanup `experiments/run_gate_tuning.py`

The file currently contains `DATASET_CONFIG_V6` through `DATASET_CONFIG_V9` all stacked in one file. This is confusing because it is impossible to tell which config is active.

**Fix:**
1. Delete `DATASET_CONFIG_V6`, `V7`, `V8` from the file body (they have been superseded).
2. Rename `DATASET_CONFIG_V9` to `DATASET_CONFIG` (no version suffix, since it is the only one).
3. Add a comment at the top of the config dict noting which sweep version it corresponds to and the date.

### Cleanup `scripts/update_memory_v*.py`

Already handled in Step 3.10 (moved to `scripts/archive/`).

---

## Verification Checklist

Run each command after completing all fixes. All must exit with code 0.

```bash
# 1. Testing module imports cleanly
python -c "import Testing; df = Testing.build_data(10); assert len(df) == 10; print('PASS: Testing')"

# 2. SIEM ingestion engine imports cleanly
python -c "from siem.ingestion_engine import IngestionEngine; IngestionEngine(); print('PASS: IngestionEngine')"

# 3. security_utils imports cleanly
python -c "from core.security_utils import encrypt_value, decrypt_value; print('PASS: security_utils')"

# 4. use_uf_refinement default is False
python -c "
import inspect
from hgnn.hgnn_correlation import HGNNCorrelationEngine
p = inspect.signature(HGNNCorrelationEngine.__init__).parameters
assert p['use_uf_refinement'].default == False
print('PASS: use_uf_refinement=False')
"

# 5. App main imports without error
python -c "
import sys
sys.argv = ['test']
# Patch Flask to not bind a port
import importlib.util
spec = importlib.util.spec_from_file_location('app_main', 'app/main.py')
# Just check the top-level imports compile
import py_compile; py_compile.compile('app/main.py'); print('PASS: app/main.py compiles')
"

# 6. No references to deleted/moved files remain
grep -rn "from security import\|import security" . --include="*.py" --exclude-dir=.venv --exclude="core/security_utils.py"
# Expected: no output

grep -rn "hgnn_checkpoints_enhanced\|hgnn_checkpoints_unsw" . --include="*.py" --exclude-dir=.venv
# Expected: no output

grep -rn "from correlation_indexer import\|import correlation_indexer" . --include="*.py" --exclude-dir=.venv
# Expected: no output (replaced by core.correlation_indexer)

# 7. mitre_core.utils.seed_control no longer referenced
grep -rn "mitre_core.utils.seed_control" . --include="*.py" --exclude-dir=.venv
# Expected: no output
```

---

## Summary of Changes

| # | File / Dir | Action | Priority |
|---|---|---|---|
| 1A | `Testing/__init__.py` | CREATE with `build_data(n)` | P1 |
| 1B | `siem/ingestion_engine.py:28` | Fix import path | P1 |
| 1C | `siem/ingestion_engine.py:top` | Add sys.path guard | P1 |
| 2 | `hgnn/hgnn_correlation.py:824` | Flip default to `False` | P1 |
| 3 | `hgnn/hgnn_training.py:29–31` | Verify/fix ContrastiveAlertLearner import | P2 |
| 4 | `hgnn/hgnn_integration.py` | Stub `create_synthetic_training_data()` | P2 |
| 5 | `core/preprocessing.py:76` | Dynamic KNNImputer column detection | P2 |
| 6 | `security.py` | Move to `core/security_utils.py` | P3 |
| 7 | `app.py` (root) | Delete (duplicate of `app/main.py`) | P3 |
| 8 | `checkpoints/`, `src/` | Delete (empty) | P3 |
| 9 | `evaluation_results/`, `hgnn_evaluation_results/`, `outputs/`, `results/` (root) | Merge → delete | P3 |
| 10 | `figures/`, `Plots/` | Merge into `docs/figures/` → delete | P3 |
| 11 | `hgnn_checkpoints_enhanced/`, `hgnn_checkpoints_unsw/` | Merge into `hgnn_checkpoints/` → delete | P3 |
| 12 | Root-level scripts (10 files) | Move to correct subdirectory | P3 |
| 13 | `utils/seed_control.py` vs `mitre_core/utils/seed_control.py` | Delete mitre_core copy | P3 |
| 14 | `scripts/update_memory_v*.py` | Archive | P3 |
| 15 | `hgnn_checkpoints/*.json` config files | CREATE for each checkpoint | P4 |
| 16 | `experiments/run_gate_tuning.py` | Remove stale V6–V8 configs | P5 |
| 17 | `experiments/results/gate_tuning_results_v2–v8.csv` | Archive | P5 |
