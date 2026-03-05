"""
Quick verification that confidence_guided_threshold() is now receiving
GAEC scores. Runs a single UNSW-NB15 inference at gate=0.6 and checks
that threshold_used > 0.1 (would be exactly 0.1 if bug still present).

Expected: threshold_used ≈ 0.603 (= 0.3 + (0.8026 - 0.5))
where 0.8026 = mean GAEC confidence for UNSW-NB15
"""
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
from hgnn.hgnn_correlation import HGNNCorrelationEngine
from utils.seed_control import set_seed

set_seed(42)

df = pd.read_csv("datasets/unsw_nb15/mitre_format.csv")
col_map = {
    "src_ip": "SourceAddress", "dst_ip": "DestinationAddress",
    "hostname": "SourceHostName", "username": "SourceUserName",
    "timestamp": "EndDate", "alert_type": "MalwareIntelAttackType",
    "tactic": "AttackTechnique",
}
for old, new in col_map.items():
    if old in df.columns and new not in df.columns:
        df[new] = df[old]
if len(df) > 10000:
    df = df.sample(n=10000, random_state=42).reset_index(drop=True)

engine = HGNNCorrelationEngine(
    model_path="hgnn_checkpoints/unsw_supervised.pt",
    confidence_gate=0.6,
    device="cpu", # Force CPU due to CUDA compatibility issues
    use_geometric_confidence=True,
    hdbscan_min_cluster_size=15,
    hdbscan_pca_components=32,
)

result_df = engine.correlate(df)

uf_mask = result_df["correlation_method"] == "hgnn+uf_refinement"
threshold_used = result_df.loc[uf_mask, "correlation_threshold_used"].mean()
p25_conf = result_df["cluster_confidence"].quantile(0.25)

print(f"p25_confidence  : {p25_conf:.4f}  (expect ~0.89)")
print(f"threshold_used  : {threshold_used:.4f}  (expect ~0.496, NOT 0.1)")
print(f"pct_uf_routed   : {uf_mask.mean():.2%}")

if threshold_used <= 0.1001:
    print("\nFAIL: threshold_used still at floor 0.1 — bug not fixed.")
    print("Re-check _uf_refinement_pass() for remaining softmax reads.")
    sys.exit(1)
elif threshold_used > 0.3:
    print("\nPASS: threshold_used above 0.1 — GAEC correctly wired into UF.")
    sys.exit(0)
else:
    print(f"\nPARTIAL: threshold_used={threshold_used:.4f} — above floor but")
    print("lower than expected. Check if conf_array is being sliced or filtered")
    print("before passing to confidence_guided_threshold().")
    sys.exit(1)
