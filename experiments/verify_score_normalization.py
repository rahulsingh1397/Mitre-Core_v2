"""
experiments/verify_score_normalization.py
------------------------------------------
Confirms that weighted_correlation_score and the enhanced_correlation() pair loop
both produce scores in [0, 1] after the v2.5 normalization fix.

Run before the v6 gate sweep. Must exit with code 0.

Expected assertions:
  - Single IP match (3-addr config, with temporal): normalized = 0.6 / 2.8 = 0.2143
  - Full match (all columns + temporal):            normalized = 2.8 / 2.8 = 1.0000
  - Overflow input (4 matches, 3 cols):             capped at 1.0
  - Integration: 6 synthetic alerts in 3 true pairs → 3 clusters at threshold=0.6
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from core.correlation_indexer import weighted_correlation_score, enhanced_correlation

N_ADDR, N_USER = 3, 3

# ── Test 1: single IP match ──────────────────────────────────────────────
score = weighted_correlation_score(
    addresses_common={"10.0.0.1"},
    usernames_common=set(),
    temporal_proximity=0.0,
    n_address_cols=N_ADDR,
    n_username_cols=N_USER,
    use_temporal=True,
)
expected = 0.6 / 2.8
assert abs(score - expected) < 1e-6, f"FAIL test1: got {score:.6f}, expected {expected:.6f}"
print(f"PASS test1 (single IP):    {score:.4f}  expected {expected:.4f}")

# ── Test 2: full match ───────────────────────────────────────────────────
score = weighted_correlation_score(
    addresses_common={"10.0.0.1", "192.168.1.1", "172.16.0.1"},
    usernames_common={"hostA", "hostB", "hostC"},
    temporal_proximity=1.0,
    n_address_cols=N_ADDR,
    n_username_cols=N_USER,
    use_temporal=True,
)
assert abs(score - 1.0) < 1e-6, f"FAIL test2: got {score:.6f}, expected 1.0"
print(f"PASS test2 (full match):   {score:.4f}  expected 1.0000")

# ── Test 3: overflow capped ──────────────────────────────────────────────
score = weighted_correlation_score(
    addresses_common={"a", "b", "c", "d"},  # 4 matches but only 3 cols
    usernames_common=set(),
    temporal_proximity=0.0,
    n_address_cols=N_ADDR,
    n_username_cols=N_USER,
    use_temporal=False,
)
assert score <= 1.0, f"FAIL test3: got {score:.6f}, expected <= 1.0"
print(f"PASS test3 (overflow cap): {score:.4f}  expected <= 1.0000")

# ── Test 4: integration — 3 natural clusters ─────────────────────────────
data = pd.DataFrame({
    "SourceAddress":       ["10.0.0.1","10.0.0.1","10.0.0.2","10.0.0.2","10.0.0.3","10.0.0.3"],
    "DestinationAddress":  ["192.168.1.1","192.168.1.1","192.168.1.2","192.168.1.2","192.168.1.3","192.168.1.3"],
    "DeviceAddress":       ["172.16.0.1","172.16.0.1","172.16.0.2","172.16.0.2","172.16.0.3","172.16.0.3"],
    "SourceHostName":      ["hostA","hostA","hostB","hostB","hostC","hostC"],
    "DeviceHostName":      ["fw1","fw1","fw2","fw2","fw3","fw3"],
    "DestinationHostName": ["srv1","srv1","srv2","srv2","srv3","srv3"],
    "EndDate":             ["2024-01-01T10:00:00"] * 6,
})
addresses = ["SourceAddress", "DestinationAddress", "DeviceAddress"]
usernames  = ["SourceHostName", "DeviceHostName", "DestinationHostName"]

# mean confidence=0.8 → threshold = 0.3 + (0.8 - 0.5) = 0.6
conf = np.array([0.8] * 6)
result = enhanced_correlation(
    data=data, usernames=usernames, addresses=addresses,
    use_temporal=True, use_adaptive_threshold=False,
    threshold_override=None, cluster_confidence=conf,
)
n_clusters     = result["pred_cluster"].nunique()
threshold_used = result["correlation_threshold_used"].iloc[0]
max_score      = result["max_correlation_score"].max()

print(f"\nIntegration test:")
print(f"  threshold_used : {threshold_used:.4f}  (expect 0.6000)")
print(f"  n_clusters     : {n_clusters}           (expect 3)")
print(f"  max_score      : {max_score:.4f}  (expect 1.0000)")

assert abs(threshold_used - 0.6) < 1e-6, f"FAIL threshold: {threshold_used}"
assert n_clusters == 3,                  f"FAIL n_clusters: {n_clusters}"
assert abs(max_score - 1.0) < 1e-4,     f"FAIL max_score: {max_score}"

print("\nALL PASS: Score normalization is working correctly.")
sys.exit(0)
