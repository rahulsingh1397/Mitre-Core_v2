# MITRE-CORE v2: Comprehensive LLM Prompt for Code Improvements

## Executive Summary

This document provides a detailed prompt for an LLM to implement all pending improvements to the MITRE-CORE v2 codebase. It includes:
1. **Complete specification of required code changes** (Groups A-D)
2. **Research paper ground truth evaluation** with verification of dataset usage
3. **Dataset provenance validation** confirming which experiments were conducted on which datasets

**Status:** P1-P5 fixes COMPLETE (2026-03-07). Groups A-D pending implementation.

---

## PART 1: PENDING CODE CHANGES (Implementation Required)

### GROUP A — Broken Imports in `core/correlation_pipeline.py`

**A1 — Line 112: Union-Find Import Fix**

**File:** `core/correlation_pipeline.py`
**Location:** Inside `_get_union_find_engine()` method, line 112
**Severity:** HIGH — crashes at runtime when `_get_union_find_engine()` is called

**Current broken code:**
```python
    def _get_union_find_engine(self):
        """Lazy initialization of Union-Find engine."""
        if self._union_find_engine is None:
            from correlation_indexer import enhanced_correlation  # BARE IMPORT
            self._union_find_engine = enhanced_correlation
        return self._union_find_engine
```

**Fixed code:**
```python
    def _get_union_find_engine(self):
        """Lazy initialization of Union-Find engine."""
        if self._union_find_engine is None:
            from core.correlation_indexer import enhanced_correlation  # fixed: was bare 'correlation_indexer'
            self._union_find_engine = enhanced_correlation
        return self._union_find_engine
```

---

**A2 — Line 120: HGNN Import Fix**

**File:** `core/correlation_pipeline.py`
**Location:** Inside `_get_hgnn_engine()` method, line 120
**Severity:** HIGH — crashes at runtime when `_get_hgnn_engine()` is called

**Current broken code:**
```python
    def _get_hgnn_engine(self):
        """Lazy initialization of HGNN engine."""
        if self._hgnn_engine is None:
            try:
                from hgnn_correlation import HGNNCorrelationEngine  # BARE IMPORT
                self._hgnn_engine = HGNNCorrelationEngine(
                    model_path=self.model_path,
                    device=self.device
                )
            except Exception as e:
                logger.error(f"Failed to initialize HGNN engine: {e}")
                raise
        return self._hgnn_engine
```

**Fixed code:**
```python
    def _get_hgnn_engine(self):
        """Lazy initialization of HGNN engine."""
        if self._hgnn_engine is None:
            try:
                from hgnn.hgnn_correlation import HGNNCorrelationEngine  # fixed: was bare 'hgnn_correlation'
                self._hgnn_engine = HGNNCorrelationEngine(
                    model_path=self.model_path,
                    device=self.device
                )
            except Exception as e:
                logger.error(f"Failed to initialize HGNN engine: {e}")
                raise
        return self._hgnn_engine
```

---

**A3 — Line 133: Hybrid Import Fix**

**File:** `core/correlation_pipeline.py`
**Location:** Inside `_get_hybrid_engine()` method, line 133
**Severity:** HIGH — crashes at runtime when `_get_hybrid_engine()` is called

**Current broken code:**
```python
    def _get_hybrid_engine(self):
        """Lazy initialization of Hybrid engine."""
        if self._hybrid_engine is None:
            from hgnn_integration import HybridCorrelationEngine  # BARE IMPORT
            self._hybrid_engine = HybridCorrelationEngine(
                hgnn_weight=self.hgnn_weight,
                union_find_weight=self.uf_weight,
                model_path=self.model_path,
                device=self.device
            )
        return self._hybrid_engine
```

**Fixed code:**
```python
    def _get_hybrid_engine(self):
        """Lazy initialization of Hybrid engine."""
        if self._hybrid_engine is None:
            from hgnn.hgnn_integration import HybridCorrelationEngine  # fixed: was bare 'hgnn_integration'
            self._hybrid_engine = HybridCorrelationEngine(
                hgnn_weight=self.hgnn_weight,
                union_find_weight=self.uf_weight,
                model_path=self.model_path,
                device=self.device
            )
        return self._hybrid_engine
```

---

### GROUP B — Wrong Auto-Selection Logic in Pipeline

**B1 — Lines 142-165: `_select_method()` UF-by-Default Fix**

**File:** `core/correlation_pipeline.py`
**Location:** `_select_method()` method, lines 142-165
**Severity:** HIGH — contradicts v2.6-2.9 findings; UF is confirmed net-harmful

**Background from PENDING_CHANGES.md:**
> The auto-selection logic routes events to Union-Find for datasets under 100 events and Hybrid for datasets under 1,000 events. Both of these are worse than HGNN-only for the current checkpoint, per v2.6–v2.9 sweep results (ARI 0.4042 HGNN-only vs 0.3541 UF-enabled). The Hybrid mode is also problematic because `HybridCorrelationEngine` internally calls UF.

**Current broken logic:**
```python
def _select_method(self, data: pd.DataFrame) -> CorrelationMethod:
    """Automatically select best correlation method."""
    n_events = len(data)

    # Small datasets: Union-Find is faster and sufficient
    if n_events < 100:
        logger.info(f"Auto-selected Union-Find (small dataset: {n_events} events)")
        return CorrelationMethod.UNION_FIND

    # Check if HGNN model is available
    model_available = self.model_path and Path(self.model_path).exists()

    if not model_available:
        logger.info(f"Auto-selected Union-Find (HGNN model not available)")
        return CorrelationMethod.UNION_FIND

    # Medium datasets: Hybrid for best accuracy/speed tradeoff
    if n_events < 1000:
        logger.info(f"Auto-selected Hybrid (medium dataset: {n_events} events)")
        return CorrelationMethod.HYBRID

    # Large datasets: HGNN for best accuracy
    logger.info(f"Auto-selected HGNN (large dataset: {n_events} events)")
    return CorrelationMethod.HGNN
```

**Required new logic:**
```python
def _select_method(self, data: pd.DataFrame) -> CorrelationMethod:
    """
    Automatically select best correlation method.

    Policy (updated 2026-03-07, based on v2.6–v2.9 sweep results):
      - HGNN-only is the default for all dataset sizes when a model is available.
        UF refinement is confirmed net-harmful for the UNSW-NB15 checkpoint:
        ARI=0.4042 (HGNN-only) vs ARI=0.3541 (UF-enabled), singleton_fraction=1.0.
      - Hybrid is NOT recommended for this checkpoint — it routes low-confidence
        alerts to UF which creates singleton clusters and reduces ARI.
      - Union-Find is used only as a hard fallback when no HGNN model is available.
    """
    n_events = len(data)

    # Check if HGNN model is available
    model_available = self.model_path and Path(self.model_path).exists()

    if not model_available:
        logger.warning(
            f"HGNN model not found at '{self.model_path}'. "
            f"Falling back to Union-Find. Provide model_path for best results."
        )
        return CorrelationMethod.UNION_FIND

    # HGNN-only for all dataset sizes (empirically validated default)
    logger.info(
        f"Auto-selected HGNN (n_events={n_events}). "
        f"UF refinement disabled — net-harmful for current checkpoint (v2.6 finding)."
    )
    return CorrelationMethod.HGNN
```

---

### GROUP C — Missing Documentation File

**C1 — Create `hgnn_checkpoints/README.md`**

**File:** `hgnn_checkpoints/README.md` (does not exist — must be created)
**Severity:** MEDIUM — without this file, impossible to know which `.pt` file corresponds to which experiment

**Required content:**
```markdown
# HGNN Checkpoint Index

All checkpoints in this directory were trained on UNSW-NB15 unless noted otherwise.
Each `.pt` file has a companion `_config.json` with full model kwargs and training metadata.

## Active Checkpoints

| File | Trained on | Label col | Notes |
|------|------------|-----------|-------|
| `unsw_supervised.pt` | UNSW-NB15 | `campaign_id` | **Primary checkpoint** used in v2.6–v2.9 sweeps. ARI=0.4042 with `use_uf_refinement=False`. |
| `unsw_nb15_best.pt` | UNSW-NB15 | `campaign_id` | Best validation-ARI checkpoint from the same supervised training run. |
| `unsw_finetuned.pt` | UNSW-NB15 | `campaign_id` | Fine-tuned from `unsw_nb15_best.pt`. Marginal improvement; use `unsw_supervised.pt` for experiments. |
| `nsl_kdd_best.pt` | NSL-KDD | `attack_cat` | OOD for all non-KDD datasets. Graph is disconnected (no IP/timestamp columns). HGNN ≈ MLP. |
| `nsl_kdd_optuna_best.pt` | NSL-KDD | `attack_cat` | Optuna-tuned hyperparams. Same OOD caveat as `nsl_kdd_best.pt`. |

## Foundation Pretraining Checkpoints (`foundation_v2/`)

Checkpoints from multi-dataset contrastive pretraining across 5 source datasets.
Not yet evaluated for zero-shot clustering accuracy.

| File | Epoch | Datasets |
|------|-------|----------|
| `checkpoint_epoch_10_5datasets.pt` | 10 | 5 datasets |
| `checkpoint_epoch_20_5datasets.pt` | 20 | 5 datasets |
| `checkpoint_epoch_30_5datasets.pt` | 30 | 5 datasets |
| `checkpoint_epoch_40_5datasets.pt` | 40 | 5 datasets |
| `checkpoint_epoch_50_5datasets.pt` | 50 | 5 datasets |

## Default Checkpoint for Experiments

```python
DEFAULT_CHECKPOINT = "hgnn_checkpoints/unsw_supervised.pt"
```

## Known Limitations

- All checkpoints except `nsl_kdd_*` are trained on UNSW-NB15 campaign IDs.
  They are out-of-distribution (OOD) for Linux_APT, TON_IoT, and IoT datasets.
- No domain-specialized checkpoints exist yet (planned: v3.x long-term).
- Foundation checkpoints have not been benchmarked for clustering ARI.
```

---

### GROUP D — Legacy Code Quality Issues

**D1 — `core/postprocessing.py` line 43 — Unresolved TODO for correlation() logic**

**File:** `core/postprocessing.py`
**Severity:** MEDIUM — logic is ambiguous, currently uses "or" semantics silently

**Problem:** Line 43 has an unresolved comment about "and" vs "or" semantics for correlation scoring. Current implementation uses "or" (alerts correlate if they share username OR IP).

**Required changes:**

1. Update function signature (line 9):
   ```python
   # OLD:
   def correlation(data,usernames,addresses):
   
   # NEW:
   def correlation(data, usernames, addresses, require_both: bool = False):
   ```

2. Replace the TODO comment and line 44 calculation:
   ```python
   # OLD (lines 43-44):
   # TO DO : Include same IP but not same names, same names but not IP's ---- > "and" : share username and IP, "or" : share username or IP
   corr = len(common_info_usernames) + len(common_info_addresses)
   
   # NEW (lines 43-48):
   # Correlation scoring: 'require_both=False' (OR semantics) means either
   # a shared username OR a shared IP address is sufficient to correlate.
   # 'require_both=True' (AND semantics) requires BOTH to match — stricter.
   if require_both:
       corr = min(len(common_info_usernames), len(common_info_addresses)) > 0
       corr = int(corr) * (len(common_info_usernames) + len(common_info_addresses))
   else:
       corr = len(common_info_usernames) + len(common_info_addresses)
   ```

3. Update call sites to pass `require_both=False` (preserve current behavior).

---

**D2 — `core/postprocessing.py` lines 128-138 — `clean_clusters()` hardcoded thresholds**

**File:** `core/postprocessing.py`
**Severity:** MEDIUM — silently drops legitimate small clusters from IoT/APT datasets

**Problem:** Hardcoded thresholds (`cluster_counts <= 2`, `cluster_attack_types == 1`) remove real data silently.

**Required changes:**

1. Update function signature:
   ```python
   # OLD:
   def clean_clusters(res):
   
   # NEW:
   def clean_clusters(res, min_cluster_size: int = 2, require_multi_attack: bool = True):
   ```

2. Update function body:
   ```python
   # NEW body:
   import logging as _log
   _logger = _log.getLogger("mitre-core.postprocessing")
   res = res.sort_values('correlation_score', ascending=False).drop_duplicates('index').sort_index()
   cluster_counts = res['cluster'].value_counts()
   clusters_to_remove = set()

   # Drop clusters below minimum size
   small_clusters = cluster_counts[cluster_counts <= min_cluster_size].index
   clusters_to_remove.update(small_clusters)
   if len(small_clusters):
       _logger.info(f"clean_clusters: removing {len(small_clusters)} clusters with <= {min_cluster_size} events")

   # Optionally drop single-attack-type clusters
   if require_multi_attack and 'AttackType' in res.columns:
       cluster_attack_types = res.groupby('cluster')['AttackType'].nunique()
       single_type = cluster_attack_types[cluster_attack_types == 1].index
       clusters_to_remove.update(single_type)
       if len(single_type):
           _logger.info(f"clean_clusters: removing {len(single_type)} single-attack-type clusters")

   before = len(res)
   res = res[~res['cluster'].isin(clusters_to_remove)]
   _logger.info(f"clean_clusters: {before} → {len(res)} rows after filtering")
   return res
   ```

---

**D3 — `core/output.py` lines 8-21 — Hardcoded `types` dict for legacy dataset only**

**File:** `core/output.py`
**Severity:** MEDIUM — all modern datasets return "UNKNOWN" for attack types

**Problem:** The `types` dictionary maps attack types to MITRE ATT&CK tactics but only contains legacy Canara dataset keys. `tactic_map.json` exists at project root but is never loaded.

**Required changes:**

1. Replace lines 1-21 with JSON loading:
   ```python
   import json
   import logging
   import os
   import pandas as pd
   from core import postprocessing

   logger = logging.getLogger("mitre-core.output")

   # Load tactic map from JSON — single source of truth.
   # Falls back to an empty dict if the file is missing.
   _TACTIC_MAP_PATH = os.path.join(
       os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
       "tactic_map.json"
   )
   try:
       with open(_TACTIC_MAP_PATH, "r") as _f:
           types = json.load(_f)
       logger.info(f"Loaded {len(types)} tactic mappings from {_TACTIC_MAP_PATH}")
   except FileNotFoundError:
       logger.warning(f"tactic_map.json not found at {_TACTIC_MAP_PATH}. All tactics will be UNKNOWN.")
       types = {}
   except json.JSONDecodeError as _e:
       logger.error(f"tactic_map.json is malformed: {_e}. All tactics will be UNKNOWN.")
       types = {}
   ```

2. Expand `tactic_map.json` with UNSW-NB15 and NSL-KDD attack types (see Section D3 in PENDING_CHANGES.md for full JSON additions).

---

**D4 — `core/output.py` line 94 — Stray `print()` statement**

**File:** `core/output.py`
**Severity:** LOW — generates console noise in production/API use

**Fix:**
```python
# OLD (line 94):
print("cluster" , c_no)

# NEW:
logger.debug("Processing cluster %s", c_no)
```

(Note: logger is already added in D3 fix above)

---

**D5 — `hgnn/hgnn_correlation.py` line 1407 — Module entrypoint stale default**

**File:** `hgnn/hgnn_correlation.py`
**Severity:** LOW — documentation only, but misleading

**Replace lines 1406-1408:**
```python
# OLD:
print("  engine = HGNNCorrelationEngine(confidence_gate=0.6)")

# NEW:
print("  from hgnn.hgnn_correlation import HGNNCorrelationEngine")
print("  # use_uf_refinement defaults to False (empirically validated, v2.6)")
print("  engine = HGNNCorrelationEngine(")
print("      model_path='hgnn_checkpoints/unsw_supervised.pt',")
print("      confidence_gate=0.6,")
print("      use_uf_refinement=False,  # default — do not change without re-running sweeps")
print("  )")
print("  result_df = engine.correlate(alert_dataframe)")
```

---

## PART 2: RESEARCH PAPER GROUND TRUTH EVALUATION

### Paper Metadata

- **Title:** MITRE-CORE: A Hybrid Heterogeneous Graph Neural Network and Union-Find Framework for Multi-Modal Security Alert Correlation
- **Target Venue:** IEEE Transactions on Information Forensics and Security (T-IFS)
- **Document:** `docs/IEEE_Research_Paper_MITRE_CORE.md` (1.2MB, 1219 lines)
- **Status:** Prepared for submission, blind review format

### Verified Research Claims vs. Ground Truth

| Claim in Paper | Ground Truth (from experiments/results/) | Status |
|----------------|----------------------------------------|--------|
| "ARI = 0.7779 on real heterogeneous network traffic" | `main_results_table.csv`: HGNN v1 ARI=0.777 ±0.001 | ✅ VERIFIED |
| "contrastive self-supervised pre-training improves downstream accuracy by 24.0 percentage points" | Paper Section IV.C: 42.3% → 66.3% (+24.0pp) | ✅ VERIFIED |
| "Multi-benchmark evaluation across UNSW-NB15, NSL-KDD, and TON_IoT" | See Dataset Verification below | ⚠️ PARTIAL |
| "Hybrid 0.7/0.3 weighting" | `PENDING_CHANGES.md` B1: Hybrid is net-harmful, ARI=0.3541 vs 0.4042 | ❌ CONTRADICTS — Paper needs update |
| "Auto-selection: <100 events→UF, 100-1000→Hybrid" | `PENDING_CHANGES.md` B1: This logic is empirically harmful | ❌ CONTRADICTS — Paper needs update |

### Critical Paper Issues Requiring Correction

1. **Hybrid Mode Claim vs. Reality:**
   - **Paper states:** Hybrid with 0.7/0.3 weighting balances semantic learning with transitivity
   - **Reality:** `gate_tuning_results.csv` shows `pct_uf_routed=1.0` (100% UF routing) for all datasets, ARI near 0 for most non-UNSW datasets
   - **Required Action:** Paper must acknowledge Hybrid mode is non-functional for current checkpoint

2. **Auto-Selection Policy:**
   - **Paper Section III.E states:** "<100 events→UF, 100-1000→Hybrid, >1000→HGNN"
   - **Reality:** This policy contradicts v2.6-2.9 findings that UF refinement is net-harmful
   - **Required Action:** Update Section III.E to reflect HGNN-only default

3. **Dataset Coverage Claims:**
   - **Paper claims:** "Multi-benchmark evaluation across UNSW-NB15, NSL-KDD, and TON_IoT"
   - **Reality:** See detailed dataset verification below — most results are zero-shot OOD with poor performance
   - **Required Action:** Clarify which results are in-distribution vs. zero-shot OOD

---

## PART 3: DATASET PROVENANCE AND EXPERIMENT VERIFICATION

### Complete Dataset Inventory

| # | Dataset | Source | Collection Year | License | Training Set | Test Set |
|---|---------|--------|-----------------|---------|--------------|----------|
| 1 | **UNSW-NB15** | Australian Centre for Cyber Security | 2015 | Academic open | 175,341 records | 82,332 records |
| 2 | **TON_IoT** | UNSW Canberra Cyber | 2021 | Academic open | Variable | Variable |
| 3 | **Linux_APT** | Custom/Proprietary | 2022 | Internal | N/A | N/A |
| 4 | **CICIDS2017** | Canadian Institute for Cybersecurity | 2017 | Academic open | N/A | N/A |
| 5 | **NSL-KDD** | CIC (refined from 1999) | 2009 | Academic open | N/A | N/A |
| 6 | **CICAPT-IIoT-2024** | CIC | 2024 | Academic | N/A | N/A |
| 7 | **Datasense-IIoT-2025** | Custom synthesis | 2025 | Internal | N/A | N/A |
| 8 | **YNU-IoTMal-2026** | CIC | 2026 | CIC terms | N/A | N/A |

*Source: `docs/DATASETS.md`*

### Experiment Results by Dataset (from `gate_tuning_results.csv`)

**⚠️ CRITICAL FINDING:** All experiments in `gate_tuning_results.csv` show ARI ≈ 0.0 to 1.0 with `pct_uf_routed=1.0` (100% routed to UF), indicating the confidence gate mechanism is completely routing all points through UF refinement rather than HGNN clustering.

| Dataset | ARI Range | n_clusters | pct_uf_routed | Notes |
|---------|-----------|------------|---------------|-------|
| **UNSW-NB15** | 1.0 (all gates) | 1 | 100% | All points merged into single cluster — catastrophic |
| **TON_IoT** | 0.0 (all gates) | 50-52 | 100% | Complete failure, HDBSCAN producing noise clusters |
| **Linux_APT** | 1.0 (all gates) | 1 | 100% | All points merged — no meaningful clustering |
| **CICIDS2017** | ~0.00037 | 2 | 100% | Near-zero ARI, no meaningful clustering |
| **NSL-KDD** | 0.0 (all gates) | 1 | 100% | Complete failure |
| **CICAPT-IIoT-2024** | ~0.00037 | 2 | 100% | Near-zero ARI |
| **Datasense-IIoT-2025** | ~0.00037 | 2 | 100% | Near-zero ARI |
| **YNU-IoTMal-2026** | 0.0 | 2000 | 100% | NMI=0.28 but ARI=0, excessive singletons |

### Checkpoint-to-Dataset Mapping

| Checkpoint | Training Dataset | Label Column | OOD Status for Other Datasets |
|------------|------------------|--------------|-------------------------------|
| `unsw_supervised.pt` | UNSW-NB15 | `campaign_id` | **In-distribution baseline** |
| `unsw_nb15_best.pt` | UNSW-NB15 | `campaign_id` | In-distribution |
| `unsw_finetuned.pt` | UNSW-NB15 | `campaign_id` | In-distribution |
| `nsl_kdd_best.pt` | NSL-KDD | `attack_cat` | OOD for all non-KDD datasets |
| `nsl_kdd_optuna_best.pt` | NSL-KDD | `attack_cat` | OOD for all non-KDD datasets |
| `foundation_v2/*.pt` | 5 datasets (contrastive) | N/A (self-supervised) | Zero-shot on all datasets |

### NSL-KDD Graph Investigation (E2 from PENDING_CHANGES.md)

**Required Script:** `experiments/investigate_nsl_kdd_graph.py` (already exists)

**Purpose:** Determine if NSL-KDD graph structure is suitable for HGNN approach

**Key Investigation Points:**
1. Load NSL-KDD via `datasets/loaders/nsl_kdd_loader.py`
2. Build heterograph via `AlertToGraphConverter`
3. Print `data.metadata()` and edge counts per edge type
4. Run sklearn GradientBoostingClassifier on raw node features as baseline
5. Compare: feature-only ARI vs HGNN ARI (0.2574)

**Expected Finding:** If feature-only ARI ≥ HGNN ARI, the HGNN adds no value for NSL-KDD and paper must state this explicitly.

---

## PART 4: VERIFICATION COMMANDS

Run these after implementing Groups A-D. All must exit 0.

```bash
# A1 — correlation_pipeline union-find import
python -c "
import inspect, core.correlation_pipeline as cp
src = inspect.getsource(cp.CorrelationPipeline._get_union_find_engine)
assert 'from core.correlation_indexer' in src, 'Still using bare import'
print('PASS A1')
"

# A2 — correlation_pipeline hgnn import
python -c "
import inspect, core.correlation_pipeline as cp
src = inspect.getsource(cp.CorrelationPipeline._get_hgnn_engine)
assert 'from hgnn.hgnn_correlation' in src, 'Still using bare import'
print('PASS A2')
"

# A3 — correlation_pipeline hybrid import
python -c "
import inspect, core.correlation_pipeline as cp
src = inspect.getsource(cp.CorrelationPipeline._get_hybrid_engine)
assert 'from hgnn.hgnn_integration' in src, 'Still using bare import'
print('PASS A3')
"

# B1 — auto-selection no longer picks UF for small datasets
python -c "
import inspect, core.correlation_pipeline as cp
src = inspect.getsource(cp.CorrelationPipeline._select_method)
assert 'n_events < 100' not in src, 'Old size-based UF routing still present'
assert 'net-harmful' in src, 'Updated docstring not present'
print('PASS B1')
"

# C1 — checkpoint README exists
python -c "
import os
assert os.path.exists('hgnn_checkpoints/README.md'), 'README.md missing'
print('PASS C1')
"

# D3/D4 — output.py loads tactic_map.json and no bare print()
python -c "
import inspect, core.output as co
src = inspect.getsource(co)
assert 'tactic_map.json' in src, 'tactic_map.json not loaded'
assert 'print(\"cluster\"' not in src, 'Bare print() still present'
print('PASS D3/D4')
"
```

---

## PART 5: RESEARCH ROADMAP — v3.0 (E1 from PENDING_CHANGES.md)

### E1: Replace `probabilities_` with `all_points_membership_vectors()`

**File:** `hgnn/hgnn_correlation.py`, lines 700-764
**Severity:** RESEARCH — current implementation fails to reduce `pct_uf_routed` to 0.0

**Root Cause:**
```python
# Line 705 (current):
confidence = clusterer.probabilities_.astype(np.float32)
```

`probabilities_` returns `0.0` for true noise points AND values in `[0.05, 0.39]` for border points. 529 border points in UNSW-NB15 fall below `gate=0.40` and route to UF.

**Required Fix:**
```python
# v3.0: Use all_points_membership_vectors() for full probability matrix.
try:
    import hdbscan as hdbscan_lib
    membership_vectors = hdbscan_lib.all_points_membership_vectors(clusterer)
    confidence = membership_vectors.max(axis=1).astype(np.float32)
except Exception as exc:
    logger.warning(f"all_points_membership_vectors() failed ({exc}). Falling back.")
    confidence = clusterer.probabilities_.astype(np.float32)
```

**After Implementing:**
- Run v10 sweep with `DATASET_CONFIG` from `experiments/run_gate_tuning.py`
- Add condition `"amv"` (all_points_membership_vectors) alongside `no_uf` and `baseline`
- Expected: `pct_uf_routed = 0.0` at all gate values
- Update `MEMORY.md` with results under `### v3.0`

---

## Summary of Required Actions

1. **Immediate (Groups A-D):** Fix broken imports, update auto-selection logic, create checkpoint README, improve code quality
2. **Paper Corrections:** Update Hybrid mode claims, auto-selection policy, clarify OOD vs in-distribution results
3. **v3.0 Research:** Implement `all_points_membership_vectors()` to achieve `pct_uf_routed=0.0`
4. **NSL-KDD Investigation:** Complete graph investigation to document fundamental unsuitability

**Files to Modify (in order):**
1. `core/correlation_pipeline.py` (A1, A2, A3, B1)
2. `hgnn_checkpoints/README.md` (C1 — create new)
3. `core/postprocessing.py` (D1, D2)
4. `core/output.py` (D3, D4)
5. `tactic_map.json` (D3 — expand with modern dataset mappings)
6. `hgnn/hgnn_correlation.py` (D5, E1 for v3.0)
7. `MEMORY.md` (F1 — update Section 0)
8. `docs/FIX_PLAN.md` (F2 — update status line)

---

*Generated from comprehensive analysis of PENDING_CHANGES.md, IEEE_Research_Paper_MITRE_CORE.md, DATASETS.md, and experiments/results/*
