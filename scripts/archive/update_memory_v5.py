"""
scripts/update_memory_v5.py
----------------------------
Reads v5 sweep results and hypothesis test outputs, then rewrites the
existing v2.4 section in MEMORY.md with actual values.

Must be run AFTER:
  - experiments/results/gate_tuning_results_v5.csv exists
  - experiments/results/gate_tuning_optimal.csv exists
  - experiments/results/gate_tuning_h2_correlation.json exists
  - experiments/results/gate_tuning_h3_correlation.json exists
  - scripts/generate_experiment_log.py has been called with --tag gate_tuning_v5_complete

Usage:
    python scripts/update_memory_v5.py \
        --memory MEMORY.md \
        --results experiments/results/gate_tuning_results_v5.csv \
        --optimal experiments/results/gate_tuning_optimal.csv \
        --h2 experiments/results/gate_tuning_h2_correlation.json \
        --h3 experiments/results/gate_tuning_h3_correlation.json \
        --bug1-fix "DESCRIBE THE EXACT LINE CHANGED FOR BUG 1 HERE" \
        --linux-apt-label "campaign"
"""

import argparse
import json
import re
import sys
from pathlib import Path
import pandas as pd

ANCHOR_START = "### v2.4 — UF Threshold Wiring Fix (GAEC → confidence_guided_threshold)"
ANCHOR_END   = "### v2.3 — GAEC v2"


def load_results(results_path: str, optimal_path: str, h2_path: str, h3_path: str):
    results  = pd.read_csv(results_path)
    optimal  = pd.read_csv(optimal_path)
    
    # Handle optional H2 path (since we might not have matched >= 4 datasets for H2)
    h2 = {}
    if Path(h2_path).exists():
        h2 = json.loads(Path(h2_path).read_text())
    
    h3 = {}
    if Path(h3_path).exists():
        h3 = json.loads(Path(h3_path).read_text())
        
    return results, optimal, h2, h3


def get_git_hash() -> str:
    try:
        import subprocess
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return "[git hash unavailable]"


def build_v24_section(
    results: pd.DataFrame,
    optimal: pd.DataFrame,
    h2: dict,
    h3: dict,
    bug1_fix_description: str,
    linux_apt_label: str,
) -> str:
    git_hash = get_git_hash()

    # --- Per-dataset optimal gate and ARI ---
    def get_optimal(dataset):
        row = optimal[optimal["dataset"] == dataset]
        if row.empty:
            return "N/A", "N/A", "N/A"
        gate   = row["optimal_gate"].iloc[0]
        ari    = row["optimal_ari"].iloc[0]
        thresh = results[
            (results["dataset"] == dataset) &
            (results["gate_value"] == gate)
        ]["threshold_used"].mean()
        return f"{gate:.2f}", f"{ari:.4f}", f"{thresh:.4f}" if not pd.isna(thresh) else "N/A"

    unsw_gate,  unsw_ari,  unsw_thresh  = get_optimal("UNSW-NB15")
    nsl_gate,   nsl_ari,   nsl_thresh   = get_optimal("NSL-KDD")
    lapt_gate,  lapt_ari,  lapt_thresh  = get_optimal("Linux_APT")

    # --- H1: Spearman r per dataset ---
    from scipy.stats import spearmanr

    def h1_spearman(dataset):
        sub = results[
            (results["dataset"] == dataset) &
            (results.get("skip_gate_sweep", pd.Series([False]*len(results))) != True)
        ].sort_values("gate_value")
        if len(sub) < 3:
            return "N/A", "N/A"
        r, p = spearmanr(sub["gate_value"], sub["ari"])
        return f"{r:.4f}", f"{p:.4f}"

    unsw_h1_r,  unsw_h1_p  = h1_spearman("UNSW-NB15")
    nsl_h1_r,   nsl_h1_p   = h1_spearman("NSL-KDD")

    # --- H2 / H3 values ---
    h2_r = f"{h2.get('pearson_r',  'N/A'):.4f}" if isinstance(h2.get('pearson_r'),  float) else "N/A"
    h2_p = f"{h2.get('p_value',    'N/A'):.4f}" if isinstance(h2.get('p_value'),    float) else "N/A"
    h2_n = str(h2.get('n', 'N/A'))
    h2_datasets = ", ".join(h2.get("datasets_included", ["UNSW-NB15", "NSL-KDD", "Linux_APT"]))

    h3_r = f"{h3.get('spearman_r', 'N/A'):.4f}" if isinstance(h3.get('spearman_r'), float) else "N/A"
    h3_p = f"{h3.get('p_value',    'N/A'):.4f}" if isinstance(h3.get('p_value'),    float) else "N/A"

    return f"""### v2.4 Final — UF Threshold Wiring Fix + Formula Reconciliation (v5 sweep)

**Bug #1 — Primary (threshold routing fix):**
- Root cause confirmed: {bug1_fix_description}
- Expected threshold post-fix: UNSW-NB15 ~0.60 (mean=0.8026), NSL-KDD ~0.57 (mean=0.7670).

**Bug #2 — Secondary (diagnostic formula mismatch):**
- `_log_confidence_diagnostics()` used `0.3 + (p25 - 0.5) * 0.5` (p25-based).
  `confidence_guided_threshold()` uses `0.3 + (mean - 0.5)` (mean-based).
- Diagnostic was predicting 0.496 (wrong); runtime correctly produces ~0.60 for UNSW-NB15.
- Fix: Updated `_log_confidence_diagnostics()` to mirror the runtime formula.
  `verify_threshold_fix.py` docstring updated to expect ~0.60.

**Bug #3 — Dataset Config:**
- TON_IoT: `skip_gate_sweep=True`. HDBSCAN finds 2 tight clusters, all confidence=1.0,
  zero UF routing at any gate. OOD checkpoint (trained on UNSW-NB15 campaign_id).
  Excluded from H1/H2/H3. Single-pass at gate=0.5 kept in CSV for documentation.
- Linux_APT: `label_col` changed from "Category" (1 unique value in 10K sample)
  to "{linux_apt_label}". `sample_size` changed from 10000 to None (full dataset).
- `load_dataset()` refactored to accept configurable `sample_size: Optional[int]`.

**v5 Results:**
| Dataset   | Optimal Gate | ARI at Optimal | threshold_used |
|-----------|-------------|----------------|----------------|
| UNSW-NB15 | {unsw_gate} | {unsw_ari}     | {unsw_thresh}  |
| NSL-KDD   | {nsl_gate}  | {nsl_ari}      | {nsl_thresh}   |
| Linux_APT | {lapt_gate} | {lapt_ari}     | {lapt_thresh}  |
| TON_IoT   | skipped     | N/A (OOD)      | N/A            |

**H1 (ARI monotonic with gate — Spearman r):**
- UNSW-NB15: r={unsw_h1_r}, p={unsw_h1_p}
- NSL-KDD:   r={nsl_h1_r}, p={nsl_h1_p}

**H2 (ECE predicts optimal gate — Pearson r):**
- r={h2_r}, p={h2_p}, n={h2_n} (datasets: {h2_datasets})
- Previous v2.2 value: r=0.8691 (k-means GAEC). v5 uses HDBSCAN GAEC.

**H3 (pct_uf_routed correlates with ARI — Spearman r):**
- r={h3_r}, p={h3_p}

**Output files:**
- `experiments/results/gate_tuning_results_v5.csv` 
- `experiments/results/gate_tuning_optimal.csv` 
- `experiments/results/gate_tuning_h2_correlation.json` 
- `experiments/results/gate_tuning_h3_correlation.json` 
- `experiments/results/confidence_diagnostics.jsonl` (appended)

**git_hash:** {git_hash}
"""


def update_memory(memory_path: str, new_section: str) -> None:
    text = Path(memory_path).read_text(encoding="utf-8")

    # Find the bounds of the existing v2.4 block
    start_idx = text.find(ANCHOR_START)
    end_idx   = text.find(ANCHOR_END)

    if start_idx == -1:
        raise ValueError(f"Could not find anchor '{ANCHOR_START}' in {memory_path}")
    if end_idx == -1:
        raise ValueError(f"Could not find anchor '{ANCHOR_END}' in {memory_path}")
    if end_idx <= start_idx:
        raise ValueError("ANCHOR_END appears before ANCHOR_START — check MEMORY.md structure")

    updated = text[:start_idx] + new_section + "\n" + text[end_idx:]
    Path(memory_path).write_text(updated, encoding="utf-8")
    print(f"MEMORY.md updated: replaced v2.4 section ({end_idx - start_idx} chars) "
          f"with v2.4 Final ({len(new_section)} chars).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory",          required=True)
    parser.add_argument("--results",         required=True)
    parser.add_argument("--optimal",         required=True)
    parser.add_argument("--h2",              required=True)
    parser.add_argument("--h3",              required=True)
    parser.add_argument("--bug1-fix",        required=True,
                        help="One-sentence description of what was changed for Bug #1")
    parser.add_argument("--linux-apt-label", required=True,
                        help="Label column that was used for Linux_APT (e.g. 'campaign')")
    args = parser.parse_args()

    results, optimal, h2, h3 = load_results(
        args.results, args.optimal, args.h2, args.h3
    )
    new_section = build_v24_section(
        results, optimal, h2, h3,
        bug1_fix_description=args.bug1_fix,
        linux_apt_label=args.linux_apt_label,
    )
    update_memory(args.memory, new_section)
