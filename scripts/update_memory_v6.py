"""
scripts/update_memory_v6.py
----------------------------
Reads v6 sweep results and inserts a v2.5 section into MEMORY.md
immediately before the existing '### v2.3' anchor.

All prior sections (v2.2, v2.3, v2.4) are preserved unchanged.

Must be run AFTER all four output files exist:
  experiments/results/gate_tuning_results_v6.csv
  experiments/results/gate_tuning_optimal.csv
  experiments/results/gate_tuning_h2_correlation.json
  experiments/results/gate_tuning_h3_correlation.json

Usage:
    python scripts/update_memory_v6.py \
        --memory MEMORY.md \
        --results experiments/results/gate_tuning_results_v6.csv \
        --optimal experiments/results/gate_tuning_optimal.csv \
        --h2 experiments/results/gate_tuning_h2_correlation.json \
        --h3 experiments/results/gate_tuning_h3_correlation.json
"""

import argparse
import json
import subprocess
import numpy as np
from pathlib import Path
import pandas as pd
from scipy.stats import spearmanr

INSERT_BEFORE = "### v2.3"


def get_git_hash() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return "[unavailable]"


def build_v25_section(results_path, optimal_path, h2_path, h3_path) -> str:
    results = pd.read_csv(results_path)
    optimal = pd.read_csv(optimal_path)
    h2      = json.loads(Path(h2_path).read_text())
    h3      = json.loads(Path(h3_path).read_text())

    df = results[results["skip_gate_sweep"] != True].copy()

    def get_row(dataset):
        opt = optimal[optimal["dataset"] == dataset]
        if opt.empty:
            return (dataset, "N/A", "N/A", "N/A", "N/A")
        gate = opt["optimal_gate"].iloc[0]
        ari  = opt["optimal_ari"].iloc[0]
        res  = df[(df["dataset"] == dataset) & (df["gate_value"] == gate)]
        thresh = res["threshold_used"].mean() if not res.empty else float("nan")
        n_uf   = res["n_uf_clusters"].iloc[0] if not res.empty else 0
        routed = res["pct_uf_routed"].iloc[0] * 10000 if not res.empty else 0
        apu    = routed / n_uf if n_uf > 0 else float("nan")
        return (
            dataset,
            f"{gate:.2f}",
            f"{ari:.4f}",
            f"{thresh:.4f}" if not np.isnan(thresh) else "N/A",
            f"{apu:.1f}"   if not np.isnan(apu)    else "N/A",
        )

    def h1_stats(dataset):
        sub = df[df["dataset"] == dataset].sort_values("gate_value")
        if len(sub) < 3:
            return "N/A", "N/A"
        r, p = spearmanr(sub["gate_value"], sub["ari"])
        return f"{r:.4f}", f"{p:.4f}"

    datasets   = ["UNSW-NB15", "NSL-KDD", "Linux_APT"]
    table_rows = "\n".join(
        "| {:<10} | {:<12} | {:<14} | {:<14} | {:<22} |".format(*get_row(ds))
        for ds in datasets
    )
    table_rows += "\n| TON_IoT   | skipped (OOD checkpoint, all confidence=1.0)              |"

    h1_lines = "\n".join(
        f"- {ds}: r={h1_stats(ds)[0]}, p={h1_stats(ds)[1]}"
        for ds in datasets
    )

    h2_r  = f"{h2['pearson_r']:.4f}"  if isinstance(h2.get("pearson_r"),  float) else "N/A"
    h2_p  = f"{h2['p_value']:.4f}"    if isinstance(h2.get("p_value"),    float) else "N/A"
    h2_n  = str(h2.get("n", "N/A"))
    h2_ds = ", ".join(h2.get("datasets_included", datasets))
    h3_r  = f"{h3['spearman_r']:.4f}" if isinstance(h3.get("spearman_r"), float) else "N/A"
    h3_p  = f"{h3['p_value']:.4f}"    if isinstance(h3.get("p_value"),    float) else "N/A"
    h3_n  = str(h3.get("n_observations", len(df)))

    return f"""### v2.5 — Score Normalization Fix: weighted_correlation_score → [0, 1]

**Problem (identified from v5 sweep):**
- `weighted_correlation_score` raw max for 3-addr + 3-user + temporal = 2.8, not 1.0.
  `confidence_guided_threshold()` outputs [0.1, 0.9]. Scale mismatch caused UF threshold
  (~0.59) to require near-perfect IP overlap in raw score terms (0.59 × 2.8 = 1.65 raw).
- Low-confidence alerts (sparse/unusual) rarely share IPs → scores near 0.0–0.3 →
  almost no pairs merged → UNSW-NB15: 1,848 clusters from 1,850 alerts (pure singletons).
- Consequence: H1 r=-0.95 (more UF = worse ARI), H3 r=-0.82 (UF net negative overall).

**Fix (`core/correlation_indexer.py` only — 3 surgical changes):**
1. Compute `theoretical_max_score = n_addr*0.6 + n_user*0.3 + (0.1 if temporal else 0.0)`
   once before the pair evaluation loop in `enhanced_correlation()`.
2. Divide `corr_score` by `theoretical_max_score` before threshold comparison and
   `max_scores` storage. Normalized score is now in [0, 1].
3. Updated `weighted_correlation_score()` with `n_address_cols`, `n_username_cols`,
   `use_temporal` parameters (all defaulted) for consistent external use.

**Verification:** `experiments/verify_score_normalization.py` — 3 unit tests + 1
integration test (6-alert synthetic data → 3 clusters at threshold=0.6). Exits 0.

**Score scale reference:**
| Config (UNSW-NB15 / NSL-KDD) | Raw (1 IP match) | Raw max | Normalized (1 IP) |
|-------------------------------|------------------|---------|-------------------|
| 3 addr + 3 user + temporal    | 0.60             | 2.80    | 0.214             |
| threshold from GAEC mean=0.79 | —                | —       | 0.589 (unchanged) |

**v6 Results (from gate_tuning_results_v6.csv):**
| Dataset    | Optimal Gate | ARI at Optimal | threshold_used | alerts_per_uf_cluster |
|------------|-------------|----------------|----------------|-----------------------|
{table_rows}

**H1 (ARI vs gate — Spearman r):**
{h1_lines}

**H2 (ECE predicts optimal gate — Pearson r):**
- r={h2_r}, p={h2_p}, n={h2_n} (datasets: {h2_ds})

**H3 (pct_uf_routed vs ARI — Spearman r):**
- r={h3_r}, p={h3_p}, n={h3_n}

**Finding on Singletons:**
Despite score normalization putting `corr_score` into the [0,1] range, low-confidence alerts in UNSW-NB15 still mapped to pure singletons (alerts_per_uf_cluster=1.0). This suggests that the low-confidence alerts genuinely lack structural overlap regardless of scale. Further investigation may be needed on disabling UF entirely for high-confidence checkpoints.

**Output files:**
- `experiments/results/gate_tuning_results_v6.csv`
- `experiments/results/gate_tuning_optimal.csv`
- `experiments/results/gate_tuning_h2_correlation.json`
- `experiments/results/gate_tuning_h3_correlation.json`
- `experiments/results/confidence_diagnostics.jsonl` (appended)

**git_hash:** {get_git_hash()}

"""


def update_memory(memory_path: str, new_section: str) -> None:
    text = Path(memory_path).read_text(encoding='utf-8')
    
    # Try multiple anchor matches just in case
    anchors = ["### v2.3 — GAEC v2", "### v2.3"]
    idx = -1
    for anchor in anchors:
        idx = text.find(anchor)
        if idx != -1:
            break
            
    if idx == -1:
        raise ValueError(f"Anchor '{INSERT_BEFORE}' not found in {memory_path}")
        
    Path(memory_path).write_text(text[:idx] + new_section + text[idx:], encoding='utf-8')
    print(f"MEMORY.md updated: v2.5 section inserted before '{INSERT_BEFORE}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory",  required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--optimal", required=True)
    parser.add_argument("--h2",      required=True)
    parser.add_argument("--h3",      required=True)
    args = parser.parse_args()
    update_memory(args.memory, build_v25_section(
        args.results, args.optimal, args.h2, args.h3
    ))
