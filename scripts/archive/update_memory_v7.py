"""
scripts/update_memory_v7.py
-----------------------------
Inserts the v2.6 experiment section into MEMORY.md before the ### v2.5 anchor.
Reads v7 results CSV for verified numbers. Never modifies existing sections.

Usage:
    python scripts/update_memory_v7.py \
        --memory MEMORY.md \
        --results experiments/results/gate_tuning_results_v7.csv
"""
import argparse
import subprocess
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime


def get_git_hash() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()[:40]
    except Exception:
        return "unknown"


def compute_metrics(df: pd.DataFrame) -> dict:
    metrics = {}
    for cond in ["UNSW-NB15_no_uf", "UNSW-NB15_soft", "UNSW-NB15_baseline",
                 "NSL-KDD_no_uf", "NSL-KDD_baseline"]:
        sub = df[df["dataset"] == cond]
        if sub.empty:
            metrics[cond] = {"best_ari": float("nan"), "best_gate": float("nan"),
                             "n_clusters": float("nan")}
            continue
        best = sub.loc[sub["ari"].idxmax()]
        metrics[cond] = {
            "best_ari":   round(float(best["ari"]), 4),
            "best_gate":  float(best["gate_value"]),
            "n_clusters": int(best["n_clusters"]),
            "pct_uf":     round(float(best.get("pct_uf_routed", float("nan"))), 4),
        }
    return metrics


def build_section(m: dict, git_hash: str) -> str:
    no_uf    = m.get("UNSW-NB15_no_uf", {})
    soft     = m.get("UNSW-NB15_soft", {})
    base     = m.get("UNSW-NB15_baseline", {})
    nsl_no   = m.get("NSL-KDD_no_uf", {})
    nsl_base = m.get("NSL-KDD_baseline", {})

    ha_confirmed = (no_uf.get("best_ari", 0) > base.get("best_ari", float("inf")))
    control_ok   = (nsl_base.get("best_ari", 0) >= nsl_no.get("best_ari", float("inf")))

    return f"""### v2.6 — UF Disable Flag + Noise Point Soft Reassignment (v7 sweep)

**Motivation (from v6 findings):**
UNSW-NB15: 1,850 HDBSCAN noise points (confidence=0.0) were always routed to UF
regardless of gate, then became singletons (apu=1.0) because they share no structural
features with other alerts. The HGNN had already assigned them to one of its 5
campaign clusters via argmax before GAEC ran. The question: is the HGNN's assignment
better than UF singletons?

**Two changes to `hgnn/hgnn_correlation.py` (backward compatible):**
- `HGNNCorrelationEngine(use_uf_refinement: bool = True)` — when False, all alerts
  retain their HGNN cluster assignment. No UF pass runs.
- `EmbeddingConfidenceScorer(noise_point_strategy: str = "zero")` — when
  "soft_assign", HDBSCAN noise points receive cosine nearest-neighbor confidence
  in [0.05, 0.40] instead of 0.0, potentially keeping them in HGNN path at low gates.

**v7 Results (verified from gate_tuning_results_v7.csv):**
| Condition              | Best ARI | Best Gate | n_clusters |
|------------------------|----------|-----------|------------|
| UNSW-NB15_no_uf        | {no_uf.get('best_ari', 'N/A'):<8} | {no_uf.get('best_gate', 'N/A'):<9} | {no_uf.get('n_clusters', 'N/A')} |
| UNSW-NB15_soft         | {soft.get('best_ari', 'N/A'):<8} | {soft.get('best_gate', 'N/A'):<9} | {soft.get('n_clusters', 'N/A')} |
| UNSW-NB15_baseline     | {base.get('best_ari', 'N/A'):<8} | {base.get('best_gate', 'N/A'):<9} | {base.get('n_clusters', 'N/A')} |
| NSL-KDD_no_uf          | {nsl_no.get('best_ari', 'N/A'):<8} | {nsl_no.get('best_gate', 'N/A'):<9} | {nsl_no.get('n_clusters', 'N/A')} |
| NSL-KDD_baseline (v2.5)| {nsl_base.get('best_ari', 'N/A'):<8} | {nsl_base.get('best_gate', 'N/A'):<9} | {nsl_base.get('n_clusters', 'N/A')} |

**H-A (UF disable improves UNSW-NB15): {'CONFIRMED' if ha_confirmed else 'NOT CONFIRMED'}**
- no_uf ARI {no_uf.get('best_ari', '?')} vs baseline {base.get('best_ari', '?')} 
  (delta={round(no_uf.get('best_ari', 0) - base.get('best_ari', 0), 4):+.4f})

**Control (UF benefits NSL-KDD): {'CONFIRMED' if control_ok else 'NOT CONFIRMED'}**
- baseline ARI {nsl_base.get('best_ari', '?')} vs no_uf {nsl_no.get('best_ari', '?')}

**Architectural conclusion:**
{'The HGNN argmax assignment for noise points is more accurate than UF singletons. For checkpoints where p25_confidence == 0.0 (significant HDBSCAN noise), use_uf_refinement=False should be the default. The confidence gate mechanism was designed to improve low-confidence alerts; when those alerts have zero structural overlap it produces the opposite effect.' if ha_confirmed else 'UNEXPECTED: UF singletons are not worse than HGNN argmax for noise points. This suggests HGNN embeddings are unreliable for geometrically isolated alerts. Investigate HGT or GraphSAGE as replacement architecture in v2.7 (see Architecture Exploration section in prompt_v2_6.md).'}

**Recommended default going forward:**
- UNSW-NB15 (p25_confidence=0.0): `use_uf_refinement=False`
- NSL-KDD   (p25_confidence=0.84): `use_uf_refinement=True, gate=0.9`
- Heuristic: set `use_uf_refinement = (p25_confidence > 0.1)`

**Output files:**
- `experiments/results/gate_tuning_results_v7.csv`
- `experiments/verify_uf_disable.py` (new)
- `scripts/update_memory_v7.py` (new)

**git_hash:** {git_hash}

"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory", required=True)
    parser.add_argument("--results", required=True)
    args = parser.parse_args()

    df = pd.read_csv(args.results)
    metrics = compute_metrics(df)
    git_hash = get_git_hash()
    section = build_section(metrics, git_hash)

    memory_path = Path(args.memory)
    content = memory_path.read_text()

    anchor = "### v2.5 —"
    if anchor not in content:
        raise ValueError(f"Anchor '{anchor}' not found in MEMORY.md — aborting.")
    if "### v2.6 —" in content:
        raise ValueError("v2.6 section already exists in MEMORY.md — aborting.")

    updated = content.replace(anchor, section + anchor, 1)
    memory_path.write_text(updated)
    print(f"MEMORY.md updated: v2.6 section inserted before '{anchor}'")


if __name__ == "__main__":
    main()
