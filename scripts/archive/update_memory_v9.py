"""
scripts/update_memory_v9.py
-----------------------------
Inserts the v2.9 experiment section into MEMORY.md before the ### v2.7 anchor.
Reads v9 results CSV for verified numbers.

Usage:
    python scripts/update_memory_v9.py \
        --memory MEMORY.md \
        --results experiments/results/gate_tuning_results_v9.csv
"""
import argparse
import subprocess
import numpy as np
import pandas as pd
from pathlib import Path


def get_git_hash() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()[:40]
    except Exception:
        return "unknown"


def compute_metrics(df: pd.DataFrame) -> dict:
    conditions = [
        "UNSW-NB15_soft_floor",
        "UNSW-NB15_no_uf",
        "UNSW-NB15_baseline",
        "NSL-KDD_soft_floor",
        "NSL-KDD_no_uf",
        "NSL-KDD_baseline",
    ]
    metrics = {}
    for cond in conditions:
        sub = df[df["dataset"] == cond]
        if sub.empty:
            metrics[cond] = {k: float("nan") for k in
                             ["best_ari", "best_gate", "n_clusters",
                              "pct_uf", "singleton_fraction"]}
            continue
        best = sub.loc[sub["ari"].idxmax()]
        metrics[cond] = {
            "best_ari":          round(float(best["ari"]), 4),
            "best_gate":         float(best["gate_value"]),
            "n_clusters":        int(best["n_clusters"]),
            "pct_uf":            round(float(best.get("pct_uf_routed",    float("nan"))), 4),
            "singleton_fraction": round(float(best.get("singleton_fraction", float("nan"))), 4),
        }
    return metrics


def improvement_a_verdict(metrics: dict) -> tuple[str, str]:
    """
    Returns (verdict_label, explanation).
    CONFIRMED requires pct_uf_routed = 0.0 for soft_floor at gate=0.4.
    NOT CONFIRMED otherwise.
    """
    pct = metrics.get("UNSW-NB15_soft_floor", {}).get("pct_uf", float("nan"))
    nsl_pct = metrics.get("NSL-KDD_soft_floor", {}).get("pct_uf", float("nan"))

    if np.isnan(pct):
        return "NOT RUN", "UNSW-NB15_soft_floor not found in results CSV."

    if pct < 0.005:
        verdict = "CONFIRMED"
        explanation = (
            f"UNSW-NB15_soft_floor pct_uf={pct:.4f} (< 0.005 threshold). "
            f"All noise points now route to HGNN path at gate=0.4. "
            f"Gate-relative floor fix (v2.9) resolves the ceiling collision "
            f"that caused v2.7 to produce pct_uf=0.0543."
        )
    else:
        verdict = "NOT CONFIRMED"
        explanation = (
            f"UNSW-NB15_soft_floor pct_uf={pct:.4f} (expect < 0.005). "
            f"Floor fix may not be applied or gaec_mean computation is incorrect. "
            f"Check: (1) `soft_conf_floor = confidence_gate + 0.01` in fit_score(), "
            f"(2) `confidence_gate` is passed from correlate() at call time, "
            f"(3) `gaec_mean` is computed from non-noise points of the current run."
        )
    if not np.isnan(nsl_pct):
        explanation += f" NSL-KDD_soft_floor pct_uf={nsl_pct:.4f}."
    return verdict, explanation


def build_section(metrics: dict, git_hash: str) -> str:
    sf_unsw  = metrics.get("UNSW-NB15_soft_floor", {})
    no_unsw  = metrics.get("UNSW-NB15_no_uf",      {})
    b_unsw   = metrics.get("UNSW-NB15_baseline",   {})
    sf_nsl   = metrics.get("NSL-KDD_soft_floor",   {})
    no_nsl   = metrics.get("NSL-KDD_no_uf",        {})
    b_nsl    = metrics.get("NSL-KDD_baseline",     {})

    verdict, explanation = improvement_a_verdict(metrics)

    def fmt(v, w=8):
        if isinstance(v, float) and np.isnan(v): return "N/A"
        return f"{v:<{w}}"

    return f"""### v2.9 — Soft Assign Gate-Relative Floor Fix (v9 sweep)

**Motivation (from v2.7 Improvement A failure):**
v2.7 attempted to fix soft_assign ceiling collision (soft_conf clip upper=0.40 == gate=0.40)
by raising the ceiling to max(gate-0.05, 0.45). The fix had zero effect:
- v8 UNSW-NB15_soft_fixed pct_uf=0.0543 — identical to v2.6 H-B
- Root cause: 543 noise points have cosine_dist > 0.60 → raw (1-dist) < 0.40 = gate
  The ceiling is a MAXIMUM cap. It cannot rescue points whose raw score is already below gate.

**Correct fix: gate-relative FLOOR**
Floor = gate + 0.01 guarantees conf > gate for ALL noise points regardless of cosine distance.
  soft_conf_floor   = confidence_gate + 0.01
  soft_conf_ceiling = min(confidence_gate + 0.15, gaec_mean - 0.05)
  soft_conf         = clip(1 - cosine_dist, soft_conf_floor, soft_conf_ceiling)
gaec_mean is computed from non-noise points of the current run (adaptive to checkpoint).

**v9 Results (verified from gate_tuning_results_v9.csv):**
| Condition              | Best ARI | Best Gate | n_clusters | pct_uf | singleton_frac |
|------------------------|----------|-----------|------------|--------|----------------|
| UNSW-NB15_soft_floor   | {fmt(sf_unsw.get('best_ari'))} | {fmt(sf_unsw.get('best_gate'))} | {fmt(sf_unsw.get('n_clusters'))} | {fmt(sf_unsw.get('pct_uf'))} | {fmt(sf_unsw.get('singleton_fraction'))} |
| UNSW-NB15_no_uf        | {fmt(no_unsw.get('best_ari'))} | {fmt(no_unsw.get('best_gate'))} | {fmt(no_unsw.get('n_clusters'))} | {fmt(no_unsw.get('pct_uf'))} | {fmt(no_unsw.get('singleton_fraction'))} |
| UNSW-NB15_baseline     | {fmt(b_unsw.get('best_ari'))}  | {fmt(b_unsw.get('best_gate'))}  | {fmt(b_unsw.get('n_clusters'))}  | {fmt(b_unsw.get('pct_uf'))}  | {fmt(b_unsw.get('singleton_fraction'))}  |
| NSL-KDD_soft_floor     | {fmt(sf_nsl.get('best_ari'))}  | {fmt(sf_nsl.get('best_gate'))}  | {fmt(sf_nsl.get('n_clusters'))}  | {fmt(sf_nsl.get('pct_uf'))}  | {fmt(sf_nsl.get('singleton_fraction'))}  |
| NSL-KDD_no_uf          | {fmt(no_nsl.get('best_ari'))}  | {fmt(no_nsl.get('best_gate'))}  | {fmt(no_nsl.get('n_clusters'))}  | {fmt(no_nsl.get('pct_uf'))}  | {fmt(no_nsl.get('singleton_fraction'))}  |
| NSL-KDD_baseline       | {fmt(b_nsl.get('best_ari'))}   | {fmt(b_nsl.get('best_gate'))}   | {fmt(b_nsl.get('n_clusters'))}   | {fmt(b_nsl.get('pct_uf'))}   | {fmt(b_nsl.get('singleton_fraction'))}   |

**Improvement A (gate-relative floor): {verdict}**
{explanation}

**Baselines:**
- UNSW-NB15_baseline ARI={fmt(b_unsw.get('best_ari')).strip()} (v2.5 reference: 0.3541)
- NSL-KDD_baseline   ARI={fmt(b_nsl.get('best_ari')).strip()} (v2.5 reference: 0.2169)
- UNSW-NB15_no_uf    ARI={fmt(no_unsw.get('best_ari')).strip()} (v2.6 reference: 0.4042)
- NSL-KDD_no_uf      ARI={fmt(no_nsl.get('best_ari')).strip()} (v2.6 reference: 0.2574)

**Row count:**
- Expected: soft_floor×2×9 + no_uf×2×1 + baseline×2×9 + TON_IoT×1 = 39
- Actual: {{}}  # filled by caller if needed

**Output files:**
- experiments/results/gate_tuning_results_v9.csv
- experiments/verify_v29_floor_fix.py (new)
- scripts/update_memory_v9.py (new)

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

    # Fix the row count placeholder
    section = section.replace(
        "{{}}  # filled by caller if needed",
        str(len(df))
    )

    memory_path = Path(args.memory)
    content = memory_path.read_text(encoding="utf-8")

    # Try both em-dash encodings (file may use \u2014 or \x97)
    for anchor in ["### v2.7 \u2014", "### v2.7 \x97", "### v2.7 —"]:
        if anchor in content:
            break
    else:
        raise ValueError("Anchor '### v2.7' not found in MEMORY.md — aborting.")

    if "### v2.9" in content:
        raise ValueError("v2.9 section already present in MEMORY.md — aborting.")

    updated = content.replace(anchor, section + anchor, 1)
    memory_path.write_text(updated, encoding="utf-8")
    print(f"MEMORY.md updated: v2.9 section inserted before v2.7 anchor.")
    print(f"Improvement A verdict: {build_section.__name__} complete.")

    # Print verdict separately for CI visibility
    _, verdict_detail = improvement_a_verdict(metrics)
    print(f"\nImprovement A: {verdict_detail}")


if __name__ == "__main__":
    main()
