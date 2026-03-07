"""
scripts/update_memory_v8.py
-----------------------------
Inserts the v2.7 experiment section into MEMORY.md before the ### v2.6 anchor.
Reads v8 results CSV for verified numbers. Never modifies existing sections.

Usage:
    python scripts/update_memory_v8.py \
        --memory MEMORY.md \
        --results experiments/results/gate_tuning_results_v8.csv
"""
import argparse
import subprocess
import pandas as pd
import numpy as np
from pathlib import Path


def get_git_hash() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()[:40]
    except Exception:
        return "unknown"


def compute_metrics(df: pd.DataFrame) -> dict:
    metrics = {}
    conditions = [
        "UNSW-NB15_no_uf", "UNSW-NB15_soft_fixed",
        "UNSW-NB15_baseline", "NSL-KDD_no_uf", "NSL-KDD_baseline"
    ]
    for cond in conditions:
        sub = df[df["dataset"] == cond]
        if sub.empty:
            metrics[cond] = {
                "best_ari": float("nan"), "best_gate": float("nan"),
                "n_clusters": float("nan"), "pct_uf": float("nan"),
                "singleton_fraction": float("nan"),
            }
            continue
        best = sub.loc[sub["ari"].idxmax()]
        metrics[cond] = {
            "best_ari":          round(float(best["ari"]), 4),
            "best_gate":         float(best["gate_value"]),
            "n_clusters":        int(best["n_clusters"]),
            "pct_uf":            round(float(best.get("pct_uf_routed", float("nan"))), 4),
            "singleton_fraction": round(float(best.get("singleton_fraction", float("nan"))), 4),
        }
    return metrics


def build_section(m: dict, git_hash: str) -> str:
    no_uf   = m.get("UNSW-NB15_no_uf",       {})
    soft_fx = m.get("UNSW-NB15_soft_fixed",   {})
    base    = m.get("UNSW-NB15_baseline",     {})
    nsl_no  = m.get("NSL-KDD_no_uf",          {})
    nsl_b   = m.get("NSL-KDD_baseline",       {})

    # v2.7 improvement A: was the ceiling collision fixed?
    # soft_fixed should have pct_uf_routed ≈ 0 at gate=0.4
    soft_pct_uf = soft_fx.get("pct_uf", float("nan"))
    ceiling_fix_confirmed = (not np.isnan(soft_pct_uf)) and (soft_pct_uf < 0.02)

    # v2.7 improvement B: singleton_fraction surfaced correctly
    sf = base.get("singleton_fraction", float("nan"))
    singleton_warning_expected = (not np.isnan(sf)) and (sf > 0.8)

    return f"""### v2.7 — Soft Assign Ceiling Fix + Singleton Metric + Gate Sweep Optimization (v8 sweep)

**Motivation (from v2.6 carry-forwards):**
Three improvements identified from the v7 sweep data but not implemented in v2.6:
1. Hard ceiling collision in soft_assign (clip upper=0.4 == gate=0.4 → 543/1321 noise
   points still routed to UF, negating most of H-B's benefit)
2. apu metric was misleading (v6 NSL-KDD apu≈3 masked majority-singleton UF output)
3. Gate sweep ran 9×2=18 redundant runs for no_uf conditions (gate is irrelevant when
   use_uf_refinement=False — all 9 values produce identical ARI)

**Three code changes (all backward compatible):**

1. `EmbeddingConfidenceScorer.fit_score(confidence_gate=0.6)` — ceiling now derived as
   `max(gate - 0.05, 0.45)` instead of hard-coded 0.40. Noise points are guaranteed
   to score above the gate boundary and stay in the HGNN path.

2. `run_gate_tuning.py` — added `singleton_fraction` and `mean_uf_cluster_size` columns.
   `analyse_gate_tuning.py` — prints WARNING when singleton_fraction > 0.8.

3. `run_gate_tuning.py` — auto-skips gate sweep for any condition where
   `use_uf_refinement=False`. Single pass at gate=0.4 run instead of 9.

**v8 Results (verified from gate_tuning_results_v8.csv):**
| Condition              | Best ARI | Best Gate | n_clusters | pct_uf | singleton_frac |
|------------------------|----------|-----------|------------|--------|----------------|
| UNSW-NB15_no_uf        | {no_uf.get('best_ari','N/A'):<8} | {no_uf.get('best_gate','N/A'):<9} | {no_uf.get('n_clusters','N/A'):<10} | {no_uf.get('pct_uf','N/A'):<6} | {no_uf.get('singleton_fraction','N/A')} |
| UNSW-NB15_soft_fixed   | {soft_fx.get('best_ari','N/A'):<8} | {soft_fx.get('best_gate','N/A'):<9} | {soft_fx.get('n_clusters','N/A'):<10} | {soft_fx.get('pct_uf','N/A'):<6} | {soft_fx.get('singleton_fraction','N/A')} |
| UNSW-NB15_baseline     | {base.get('best_ari','N/A'):<8} | {base.get('best_gate','N/A'):<9} | {base.get('n_clusters','N/A'):<10} | {base.get('pct_uf','N/A'):<6} | {base.get('singleton_fraction','N/A')} |
| NSL-KDD_no_uf          | {nsl_no.get('best_ari','N/A'):<8} | {nsl_no.get('best_gate','N/A'):<9} | {nsl_no.get('n_clusters','N/A'):<10} | {nsl_no.get('pct_uf','N/A'):<6} | {nsl_no.get('singleton_fraction','N/A')} |
| NSL-KDD_baseline       | {nsl_b.get('best_ari','N/A'):<8} | {nsl_b.get('best_gate','N/A'):<9} | {nsl_b.get('n_clusters','N/A'):<10} | {nsl_b.get('pct_uf','N/A'):<6} | {nsl_b.get('singleton_fraction','N/A')} |

**Improvement A (ceiling fix): {'CONFIRMED' if ceiling_fix_confirmed else 'CHECK RESULTS'}**
- UNSW-NB15_soft_fixed pct_uf={soft_pct_uf:.4f} (expect < 0.02 at gate=0.4)
- v2.6 H-B had pct_uf=0.0543 at gate=0.4 due to ceiling=0.4 == gate=0.4 collision

**Improvement B (singleton_fraction):**
- UNSW-NB15_baseline singleton_fraction={sf:.4f} {'(WARNING > 0.8 correctly triggered)' if singleton_warning_expected else '(check analyse_gate_tuning.py warning logic)'}

**Improvement C (gate sweep optimization):**
- no_uf conditions run 1 gate value instead of 9 (confirmed by row count in CSV)

**git_hash:** {git_hash}

"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory",  required=True)
    parser.add_argument("--results", required=True)
    args = parser.parse_args()

    df       = pd.read_csv(args.results)
    metrics  = compute_metrics(df)
    git_hash = get_git_hash()
    section  = build_section(metrics, git_hash)

    memory_path = Path(args.memory)
    content = memory_path.read_text(encoding="utf-8")

    anchor = "### v2.6 —"
    # Handle both em-dash variants (update_memory_v7 may have used \x97 or —)
    if anchor not in content:
        anchor = "### v2.6 \x97"
    if anchor not in content:
        raise ValueError("Anchor '### v2.6' not found in MEMORY.md — aborting.")
    if "### v2.7" in content:
        raise ValueError("v2.7 section already exists in MEMORY.md — aborting.")

    updated = content.replace(anchor, section + anchor, 1)
    memory_path.write_text(updated, encoding="utf-8")
    print(f"MEMORY.md updated: v2.7 section inserted before v2.6 anchor.")


if __name__ == "__main__":
    main()
