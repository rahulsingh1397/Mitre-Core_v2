# MITRE-CORE v2 — Pending Changes
**Date:** 2026-03-07
**Rule:** NO code changes to be made directly. Every required change is fully specified here
with exact file, line number, old text, and replacement text so they can be applied one
at a time after review.

---

## Status of Previous Work (P1–P5)

All P1–P5 fixes from `docs/FIX_PLAN.md` have been completed and verified.
Summary of what is confirmed done:

| Item | Status | Verified by |
|---|---|---|
| `Testing/__init__.py` created with `build_data()` | ✅ DONE | `import Testing; Testing.build_data(10)` passes |
| `siem/ingestion_engine.py` import path fixed | ✅ DONE | `from siem.ingestion_engine import IngestionEngine` passes |
| `siem/ingestion_engine.py` sys.path guard (deduplicated) | ✅ DONE | Single guard at lines 19–26 |
| `hgnn/hgnn_correlation.py` `use_uf_refinement` default → `False` | ✅ DONE | `inspect.signature` check passes |
| `core/security_utils.py` created | ✅ DONE | `from core.security_utils import encrypt_value` passes |
| `security.py` converted to re-export shim | ✅ DONE | No stale bare `from security import` elsewhere |
| `mitre_core/utils/seed_control.py` duplicate deleted | ✅ DONE | File no longer exists |
| Root-level scripts moved to proper dirs | ✅ DONE | All 12 files confirmed at new locations |
| Redundant result/figure dirs deleted | ✅ DONE | All confirmed GONE |
| `hgnn_checkpoints_enhanced/`, `_unsw/` merged → deleted | ✅ DONE | Confirmed GONE |
| Config `.json` files created alongside each `.pt` checkpoint | ✅ DONE | 5 + 5 config files exist |
| `experiments/run_gate_tuning.py` cleaned to single `DATASET_CONFIG` | ✅ DONE | Only `DATASET_CONFIG` exists |
| `experiments/results/archive/` created, v2–v8 CSVs moved | ✅ DONE | Archive confirmed |
| `scripts/archive/` created, `update_memory_v*.py` moved | ✅ DONE | Archive confirmed |

---

## Remaining Required Changes

Grouped by file. Every change includes: location, problem, exact old text, exact new text,
and why it matters.

---

## GROUP A — Broken Imports Still Present

### A1 — `core/correlation_pipeline.py` line 112
**Severity:** HIGH — crashes at runtime the first time `_get_union_find_engine()` is called.

**Problem:**
```python
from correlation_indexer import enhanced_correlation
```
Bare module name with no package prefix. `correlation_indexer` lives at `core/correlation_indexer.py`.
This import only works if the Python working directory happens to be `core/` — which it never is.

**Exact location:** `core/correlation_pipeline.py`, inside `_get_union_find_engine()`, line 112.

**Old text (lines 111–113):**
```python
    def _get_union_find_engine(self):
        """Lazy initialization of Union-Find engine."""
        if self._union_find_engine is None:
            from correlation_indexer import enhanced_correlation
            self._union_find_engine = enhanced_correlation
        return self._union_find_engine
```

**New text:**
```python
    def _get_union_find_engine(self):
        """Lazy initialization of Union-Find engine."""
        if self._union_find_engine is None:
            from core.correlation_indexer import enhanced_correlation  # fixed: was bare 'correlation_indexer'
            self._union_find_engine = enhanced_correlation
        return self._union_find_engine
```

---

### A2 — `core/correlation_pipeline.py` line 120
**Severity:** HIGH — crashes at runtime the first time `_get_hgnn_engine()` is called.

**Problem:**
```python
from hgnn_correlation import HGNNCorrelationEngine
```
`hgnn_correlation` lives at `hgnn/hgnn_correlation.py`. The correct package path is `hgnn.hgnn_correlation`.

**Exact location:** `core/correlation_pipeline.py`, inside `_get_hgnn_engine()`, line 120.

**Old text (lines 118–128):**
```python
    def _get_hgnn_engine(self):
        """Lazy initialization of HGNN engine."""
        if self._hgnn_engine is None:
            try:
                from hgnn_correlation import HGNNCorrelationEngine
                self._hgnn_engine = HGNNCorrelationEngine(
                    model_path=self.model_path,
                    device=self.device
                )
            except Exception as e:
                logger.error(f"Failed to initialize HGNN engine: {e}")
                raise
        return self._hgnn_engine
```

**New text:**
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

### A3 — `core/correlation_pipeline.py` line 133
**Severity:** HIGH — crashes at runtime the first time `_get_hybrid_engine()` is called.

**Problem:**
```python
from hgnn_integration import HybridCorrelationEngine
```
`hgnn_integration` lives at `hgnn/hgnn_integration.py`.

**Exact location:** `core/correlation_pipeline.py`, inside `_get_hybrid_engine()`, line 133.

**Old text (lines 130–140):**
```python
    def _get_hybrid_engine(self):
        """Lazy initialization of Hybrid engine."""
        if self._hybrid_engine is None:
            from hgnn_integration import HybridCorrelationEngine
            self._hybrid_engine = HybridCorrelationEngine(
                hgnn_weight=self.hgnn_weight,
                union_find_weight=self.uf_weight,
                model_path=self.model_path,
                device=self.device
            )
        return self._hybrid_engine
```

**New text:**
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

## GROUP B — Wrong Auto-Selection Logic in Pipeline

### B1 — `core/correlation_pipeline.py` lines 142–165 — `_select_method()` picks UF by default
**Severity:** HIGH — contradicts every finding since v2.6. UF is confirmed net-harmful.

**Problem:**
The auto-selection logic routes events to Union-Find for datasets under 100 events and Hybrid
for datasets under 1,000 events. Both of these are worse than HGNN-only for the current
checkpoint, per v2.6–v2.9 sweep results (ARI 0.4042 HGNN-only vs 0.3541 UF-enabled).
The Hybrid mode is also problematic because `HybridCorrelationEngine` internally calls UF.

**Current broken logic (lines 142–165):**
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

## GROUP C — Missing Documentation File

### C1 — `hgnn_checkpoints/README.md` does not exist
**Severity:** MEDIUM — without this file, it is impossible to know which `.pt` file
corresponds to which experiment, training run, or dataset. Config `.json` files exist
per checkpoint but there is no human-readable index.

**Action:** Create the file `hgnn_checkpoints/README.md` with the following exact content:

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

## GROUP D — Legacy Code Quality Issues

### D1 — `core/postprocessing.py` line 43 — Unresolved TODO (and/or logic)
**Severity:** MEDIUM — logic is ambiguous and currently uses "or" semantics silently.

**Problem:**
Line 43 has a comment that has never been resolved:
```python
# TO DO : Include same IP but not same names, same names but not IP's ---- > "and" : share username and IP, "or" : share username or IP
```
Line 44 implements "or" semantics by summing both:
```python
corr = len(common_info_usernames) + len(common_info_addresses)
```
This means two alerts are considered correlated if they share **either** a username **or** an IP address.
The alternative is "and" — requiring **both** to match, which would be much stricter.

**Decision needed:**
- Current ("or"): Higher recall, more false positives. Better for initial broad correlation.
- "and": Higher precision, more false negatives. Better for confirmed attribution.

**Required action:**
1. Make this configurable via a parameter `require_both: bool = False` on the `correlation()` function signature.
2. Update line 44 to branch on this parameter:

**Old function signature (line 9):**
```python
def correlation(data,usernames,addresses):
```

**New function signature:**
```python
def correlation(data, usernames, addresses, require_both: bool = False):
```

**Old line 44:**
```python
                corr = len(common_info_usernames) + len(common_info_addresses)
```

**New lines 43–48 (replacing the TODO comment and corr calculation):**
```python
                # Correlation scoring: 'require_both=False' (OR semantics) means either
                # a shared username OR a shared IP address is sufficient to correlate.
                # 'require_both=True' (AND semantics) requires BOTH to match — stricter.
                if require_both:
                    corr = min(len(common_info_usernames), len(common_info_addresses)) > 0
                    corr = int(corr) * (len(common_info_usernames) + len(common_info_addresses))
                else:
                    corr = len(common_info_usernames) + len(common_info_addresses)
```

**Also update the call site in `core/output.py` line 81 and any other callers of `correlation()`**
to pass `require_both` explicitly (use default `False` to preserve current behaviour).

---

### D2 — `core/postprocessing.py` lines 128–138 — `clean_clusters()` hardcoded thresholds
**Severity:** MEDIUM — silently drops legitimate small clusters from IoT/APT datasets.

**Problem:**
```python
single_instance_clusters = cluster_counts[cluster_counts <= 2].index
single_attack_type_clusters = cluster_attack_types[cluster_attack_types == 1].index
clusters_to_remove = set(single_instance_clusters).union(single_attack_type_clusters)
```
Any cluster with ≤2 events is dropped. Any cluster with only one attack type is also dropped.
For IoT datasets where a single attack may have only 1–2 events, or APT campaigns with a
single tactic phase, this removes real data silently with no logging.

**Required new function signature (line 128):**

**Old:**
```python
def clean_clusters(res):
```

**New:**
```python
def clean_clusters(res, min_cluster_size: int = 2, require_multi_attack: bool = True):
```

**Old body (lines 129–138):**
```python
  res = res.sort_values('correlation_score', ascending=False).drop_duplicates('index').sort_index()
  cluster_counts = res.groupby('cluster').size()
  cluster_counts = res['cluster'].value_counts()
  cluster_attack_types = res.groupby('cluster')['AttackType'].nunique()
  single_instance_clusters = cluster_counts[cluster_counts <= 2].index
  single_attack_type_clusters = cluster_attack_types[cluster_attack_types == 1].index
  clusters_to_remove = set(single_instance_clusters).union(single_attack_type_clusters)
  res = res[~res['cluster'].isin(clusters_to_remove)]
  return res
```

**New body:**
```python
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

### D3 — `core/output.py` lines 8–21 — `types` dict hardcoded for legacy dataset only
**Severity:** MEDIUM — all modern datasets return "UNKNOWN" for every attack type because
their attack type strings don't match the 12 hardcoded keys.

**Problem:**
The `types` dictionary maps attack type strings to MITRE ATT&CK tactics. The keys are
dataset-specific labels from the original Canara dataset (e.g. `"Privilege Escalation -
Exploiting Vulnerability"`). UNSW-NB15 uses strings like `"Exploits"`, `"DoS"`, `"Fuzzers"`.
NSL-KDD uses `"neptune"`, `"smurf"`, `"guess_passwd"` etc.

The `tactic_map.json` file exists at the project root but is **never loaded** — the `types`
dict is just pasted in as Python literals.

**Required action (two parts):**

**Part 1 — Load `tactic_map.json` instead of hardcoding (top of `core/output.py`):**

Replace lines 1–21:
```python
import pandas as pd
from core import postprocessing
import json

#  Data dictionaries

types = {
"Connection to Malicious URL for malware_download": "INITIAL ACCESS",
    "Event Triggered Execution": "EXECUTION",
    ...
}
```

With:
```python
import json
import logging
import os
import pandas as pd
from core import postprocessing

logger = logging.getLogger("mitre-core.output")

# Load tactic map from JSON — single source of truth.
# Falls back to an empty dict if the file is missing (graceful degradation).
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

**Part 2 — Expand `tactic_map.json` to include all 8 dataset attack type strings.**

The file at the project root currently only contains the 12 original Canara strings.
Add entries for at least UNSW-NB15 and NSL-KDD. Example additions:

```json
{
  "Connection to Malicious URL for malware_download": "INITIAL ACCESS",
  "Event Triggered Execution": "EXECUTION",
  "...existing entries...": "...",

  "--- UNSW-NB15 attack types ---": "--- see http://research.unsw.edu.au/projects/unsw-nb15-dataset ---",
  "Fuzzers":      "DISCOVERY",
  "Analysis":     "DISCOVERY",
  "Backdoors":    "PERSISTENCE",
  "DoS":          "IMPACT",
  "Exploits":     "EXECUTION",
  "Generic":      "INITIAL ACCESS",
  "Reconnaissance": "RECONNAISSANCE",
  "Shellcode":    "EXECUTION",
  "Worms":        "LATERAL MOVEMENT",
  "Normal":       "BENIGN",

  "--- NSL-KDD attack types ---": "--- see https://www.unb.ca/cic/datasets/nsl.html ---",
  "neptune":      "IMPACT",
  "smurf":        "IMPACT",
  "portsweep":    "RECONNAISSANCE",
  "ipsweep":      "RECONNAISSANCE",
  "land":         "IMPACT",
  "back":         "IMPACT",
  "teardrop":     "IMPACT",
  "satan":        "RECONNAISSANCE",
  "buffer_overflow": "EXECUTION",
  "warezmaster":  "EXFILTRATION",
  "guess_passwd": "CREDENTIAL ACCESS",
  "pod":          "IMPACT",
  "nmap":         "RECONNAISSANCE",
  "multihop":     "LATERAL MOVEMENT",
  "rootkit":      "PERSISTENCE",
  "ftp_write":    "EXFILTRATION",
  "imap":         "INITIAL ACCESS",
  "phf":          "INITIAL ACCESS",
  "spy":          "COLLECTION",
  "warezclient":  "EXFILTRATION",
  "normal":       "BENIGN"
}
```

Note: The keys with `"--- ... ---"` are comment markers — JSON has no comments, so use a
dummy key→value pair as a separator. Alternatively, structure by dataset as a nested object
and update the loading code to flatten it.

---

### D4 — `core/output.py` line 94 — stray `print()` statement in production code
**Severity:** LOW — generates console noise in production/API use.

**Problem (line 94):**
```python
        print("cluster" , c_no)
```

**Fix:**
```python
        logger.debug("Processing cluster %s", c_no)
```

Also add `logger = logging.getLogger("mitre-core.output")` at the top of the file
(already added in D3's fix above — include both changes together).

---

### D5 — `hgnn/hgnn_correlation.py` line 1407 — module entrypoint shows stale default
**Severity:** LOW — documentation only, but misleading.

**Problem:**
The `__main__` block at line 1402–1413 shows an example with `confidence_gate=0.6`
and does not mention `use_uf_refinement`:
```python
    print("  engine = HGNNCorrelationEngine(confidence_gate=0.6)")
```

**Fix — replace lines 1406–1408:**
```python
    print("  from hgnn.hgnn_correlation import HGNNCorrelationEngine")
    print("  engine = HGNNCorrelationEngine(confidence_gate=0.6)")
    print("  result_df = engine.correlate(alert_dataframe)")
```

With:
```python
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

## GROUP E — Research Thread (v3.0 — Next Experiment)

These are not bugs to fix immediately but must be completed before the next paper submission.
They are documented here so the implementation prompt can be written from this file.

### E1 — `hgnn/hgnn_correlation.py` line 705 — v3.0: Replace `probabilities_` with `all_points_membership_vectors()`
**Severity:** RESEARCH — the current implementation still fails to reduce `pct_uf_routed` to 0.0.

**Root cause (confirmed from v2.9 sweep):**
Line 705:
```python
confidence = clusterer.probabilities_.astype(np.float32)
```
`clusterer.probabilities_` returns `0.0` for true noise points AND values in `[0.05, 0.39]`
for **border points** (label ≥ 0, assigned to a cluster, but weak membership). There are
529 such border points in UNSW-NB15 that fall below `gate=0.40` and still route to UF.
The `soft_assign` block at lines 713–764 only catches `probabilities_ == 0.0` (noise mask),
completely missing the border points.

**Correct fix — replace lines 700–764 with `all_points_membership_vectors()`:**

This function returns a full `[N, n_clusters]` probability matrix from the condensed tree.
Every point — noise, border, AND core — gets a real probability distribution. No hard `0.0`
values. No noise mask needed.

**Precondition:** `prediction_data=True` is already set at line 687. ✅

**What to change:**

Replace this block (lines 700–784, the entire confidence extraction section):
```python
# Extract confidence from HDBSCAN probabilities_
confidence = clusterer.probabilities_.astype(np.float32)

# v2.6 — soft assignment for noise points (probability=0.0)
if self.noise_point_strategy == "soft_assign":
    noise_mask = clusterer.probabilities_ == 0.0
    ...
    [the entire 50-line soft_assign block]
    ...

# Fallback: if all noise or single cluster
if n_found <= 1 and self.fallback_to_uniform:
    ...
    confidence = np.full(n, 0.5, dtype=np.float32)

return confidence
```

With this new implementation:
```python
# v3.0: Use all_points_membership_vectors() for full probability matrix.
# Returns [N, n_clusters] where every point (noise, border, core) gets
# a real probability distribution. No hard 0.0 values, no noise mask needed.
try:
    import hdbscan as hdbscan_lib
    membership_vectors = hdbscan_lib.all_points_membership_vectors(clusterer)
    # membership_vectors shape: [N, n_clusters]
    # confidence = max probability across all clusters for each point
    confidence = membership_vectors.max(axis=1).astype(np.float32)
    logger.info(
        f"all_points_membership_vectors: shape={membership_vectors.shape}, "
        f"conf mean={confidence.mean():.3f}, min={confidence.min():.3f}, "
        f"max={confidence.max():.3f}"
    )
except Exception as exc:
    logger.warning(
        f"all_points_membership_vectors() failed ({exc}). "
        f"Falling back to clusterer.probabilities_."
    )
    confidence = clusterer.probabilities_.astype(np.float32)

# Fallback: if all noise or single cluster, return moderate uniform score
if n_found <= 1 and self.fallback_to_uniform:
    logger.warning(
        f"HDBSCAN found {n_found} cluster(s) — returning uniform confidence=0.5."
    )
    confidence = np.full(n, 0.5, dtype=np.float32)

return confidence
```

**After implementing, run a v10 sweep:**
- Config: Same as `DATASET_CONFIG` in `experiments/run_gate_tuning.py`
- Add a new condition `"amv"` (all_points_membership_vectors) alongside `no_uf` and `baseline`
- Expected: `pct_uf_routed = 0.0` at all gate values (because no point will have confidence forced below gate by a `probabilities_` floor)
- Update MEMORY.md with results under `### v3.0 — all_points_membership_vectors()`

---

### E2 — NSL-KDD Graph Investigation
**Severity:** RESEARCH — documents fundamental unsuitability of graph approach for NSL-KDD.

**Task:**
1. Load the NSL-KDD graph using `datasets/loaders/nsl_kdd_loader.py`
2. Count the number of edges for each edge type in the resulting `HeteroData` object
3. If edge counts are 0 or near-0, document that the graph-based approach is inapplicable
4. Run a feature-only baseline (GBM or MLP on the 6 raw node features without any message passing)
5. Record the ARI of the feature-only baseline vs the HGNN ARI of 0.2574
6. If feature-only ARI ≥ HGNN ARI, the HGNN adds no value for NSL-KDD and the paper
   must state this explicitly

**Script to write (do not execute yet, just create the file):**
`experiments/investigate_nsl_kdd_graph.py`

This script should:
- Load the NSL-KDD dataset
- Build the heterograph via `AlertToGraphConverter`
- Print `data.metadata()` and edge counts per edge type
- Run a sklearn GradientBoostingClassifier on raw node features as a baseline
- Print comparison table: `{method: ARI}`

---

## GROUP F — Documentation and Status Updates

### F1 — `MEMORY.md` Section 0 is stale
**Severity:** LOW — wrong status text.

**Problem:** Section 0 reads:
```
P1 fixes (crashes + wrong default) are being implemented now.
```

**Required replacement for Section 0:**
```markdown
## 0. Fix Session — 2026-03-07 (COMPLETE)
Full structural analysis completed. All 17 issues from `docs/FIX_PLAN.md` resolved.

P1–P5 status: ALL COMPLETE. Verified by automated checks.

Key fixes applied:
- `Testing/__init__.py` — created with `build_data(n_samples)` ✅
- `siem/ingestion_engine.py:28` — import path fixed to `core.correlation_indexer` ✅
- `siem/ingestion_engine.py` — sys.path guard added (deduplicated) ✅
- `hgnn/hgnn_correlation.py:824` — `use_uf_refinement` default `True` → `False` ✅
- `security.py` — copied to `core/security_utils.py`; shim left at root ✅
- All root-level scripts moved to proper subdirectories ✅
- Redundant directories merged and deleted ✅
- Checkpoint directories consolidated into single `hgnn_checkpoints/` ✅

Remaining work: see `docs/PENDING_CHANGES.md` (Groups A–F).
Next research milestone: v3.0 (`all_points_membership_vectors()`).
```

---

### F2 — `docs/FIX_PLAN.md` status line is stale
**Severity:** LOW — wrong status text.

**Problem:** Line 3 reads:
```
**Status:** Pending implementation
```

**Fix — change line 3:**
```
**Status:** COMPLETE — all items implemented 2026-03-07. See PENDING_CHANGES.md for next wave.
```

---

## Verification Commands

Run these after all changes in Groups A–D are applied. All must exit 0.

```bash
# A1 — correlation_pipeline union-find import
python -c "
from core.correlation_pipeline import CorrelationPipeline
p = CorrelationPipeline(method='auto', model_path=None)
# Force lazy init of UF engine (model_path=None triggers UF selection)
import pandas as pd, numpy as np
df = pd.DataFrame({'SourceAddress': ['1.2.3.4','1.2.3.4'], 'EndDate': ['2025-01-01','2025-01-02'], 'pred_cluster': [0,0]})
# Just check import path resolves without ImportError
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

## Change Order (Recommended)

Apply in this sequence to minimise risk:

1. **A1, A2, A3** — fix the three broken imports in `correlation_pipeline.py` (same file, one edit session)
2. **B1** — update `_select_method()` in `correlation_pipeline.py` (same file, continue edit)
3. **C1** — create `hgnn_checkpoints/README.md` (new file, no risk)
4. **D1** — parameterise `correlation()` in `postprocessing.py`
5. **D2** — parameterise `clean_clusters()` in `postprocessing.py`
6. **D3 + D4** — update `output.py` and expand `tactic_map.json` (do both together)
7. **D5** — update `__main__` block in `hgnn_correlation.py` (cosmetic, low risk)
8. **F1** — update `MEMORY.md` Section 0
9. **F2** — update `docs/FIX_PLAN.md` status line
10. **E1** — v3.0 implementation (plan and execute as a separate session)
11. **E2** — NSL-KDD investigation (plan and execute as a separate session)
