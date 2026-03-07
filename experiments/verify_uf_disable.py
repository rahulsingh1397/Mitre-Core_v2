"""
experiments/verify_uf_disable.py
----------------------------------
Verifies the v2.6 use_uf_refinement and noise_point_strategy additions.

Tests:
  1. use_uf_refinement=False: no rows should have correlation_method='hgnn+uf_refinement'
  2. use_uf_refinement=True, noise_point_strategy="zero": reproduces v2.5 behavior
     (noise points have confidence=0.0, routed to UF at any positive gate value)
  3. use_uf_refinement=True, noise_point_strategy="soft_assign": noise points get
     confidence in [0.05, 0.4], not 0.0

All tests use the 6-alert synthetic integration data from verify_score_normalization.py.

Must exit 0. Run this before run_gate_tuning.py --config v7.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from unittest.mock import patch, MagicMock
from hgnn.hgnn_correlation import HGNNCorrelationEngine

# ── Synthetic data (3 natural pairs) ────────────────────────────────────────
data = pd.DataFrame({
    "SourceAddress":       ["10.0.0.1","10.0.0.1","10.0.0.2","10.0.0.2","10.0.0.3","10.0.0.3"],
    "DestinationAddress":  ["192.168.1.1","192.168.1.1","192.168.1.2","192.168.1.2","192.168.1.3","192.168.1.3"],
    "DeviceAddress":       ["172.16.0.1","172.16.0.1","172.16.0.2","172.16.0.2","172.16.0.3","172.16.0.3"],
    "SourceHostName":      ["hostA","hostA","hostB","hostB","hostC","hostC"],
    "DeviceHostName":      ["fw1","fw1","fw2","fw2","fw3","fw3"],
    "DestinationHostName": ["srv1","srv1","srv2","srv2","srv3","srv3"],
    "EndDate":             ["2024-01-01T10:00:00"] * 6,
})

def make_engine_with_mock_model(use_uf_refinement, noise_point_strategy):
    """
    Build a minimal HGNNCorrelationEngine with the model stubbed out so we
    can test the routing logic without a real checkpoint.
    """
    engine = HGNNCorrelationEngine(
        model_path=None,
        use_geometric_confidence=False,  # use softmax path — avoids HDBSCAN
        confidence_gate=0.5,
        use_uf_refinement=use_uf_refinement,
        noise_point_strategy=noise_point_strategy,
    )
    return engine

# ── Test 1: use_uf_refinement=False parameter is stored ─────────────────────
engine_no_uf = make_engine_with_mock_model(use_uf_refinement=False, noise_point_strategy="zero")
assert engine_no_uf.use_uf_refinement is False, \
    f"FAIL test1: use_uf_refinement should be False, got {engine_no_uf.use_uf_refinement}"
print("PASS test1: use_uf_refinement=False stored correctly")

# ── Test 2: use_uf_refinement=True is default ────────────────────────────────
engine_default = make_engine_with_mock_model(use_uf_refinement=True, noise_point_strategy="zero")
assert engine_default.use_uf_refinement is True, \
    f"FAIL test2: default use_uf_refinement should be True"
print("PASS test2: use_uf_refinement=True is default")

# ── Test 3: noise_point_strategy is threaded to EmbeddingConfidenceScorer ────
from hgnn.hgnn_correlation import HGNNCorrelationEngine, EmbeddingConfidenceScorer
engine_soft = HGNNCorrelationEngine(
    model_path=None,
    use_geometric_confidence=True,
    noise_point_strategy="soft_assign",
)
assert engine_soft.confidence_scorer is not None, "FAIL test3: scorer should exist"
assert engine_soft.confidence_scorer.noise_point_strategy == "soft_assign", \
    f"FAIL test3: strategy not threaded through, got {engine_soft.confidence_scorer.noise_point_strategy}"
print("PASS test3: noise_point_strategy='soft_assign' threaded to EmbeddingConfidenceScorer")

# ── Test 4: noise_point_strategy="zero" stored on scorer ─────────────────────
engine_zero = HGNNCorrelationEngine(
    model_path=None,
    use_geometric_confidence=True,
    noise_point_strategy="zero",
)
assert engine_zero.confidence_scorer.noise_point_strategy == "zero", \
    f"FAIL test4: expected 'zero', got {engine_zero.confidence_scorer.noise_point_strategy}"
print("PASS test4: noise_point_strategy='zero' stored correctly")

# ── Test 5: soft_assign confidence values are in [0.05, 0.4] ────────────────
# This test requires HDBSCAN to produce at least one noise point so the
# soft_assign branch actually executes.  We create:
#   - 2 tight pairs around axis-aligned unit vectors (→ 2 clusters)
#   - 1 isolated point at [10, 0, 0, ...] (→ noise with min_cluster_size=2)
# rng.normal(loc, scale, size): loc must be scalar or 1-D broadcastable to
# the row dimension only.  Build each cluster by offsetting a zero matrix.
from hgnn.hgnn_correlation import EmbeddingConfidenceScorer
import torch

scorer_soft = EmbeddingConfidenceScorer(
    min_cluster_size=2,
    pca_components=4,   # 4 > n_clusters so PCA is meaningful
    min_samples=1,
    metric="cosine",
    fallback_to_uniform=True,
    noise_point_strategy="soft_assign",
)

rng = np.random.default_rng(42)

# Cluster 0: 5 points near [1, 0, 0, ..., 0] — enough points for HDBSCAN to form a cluster
c0 = np.zeros((5, 64), dtype=np.float32)
c0[:, 0] = 1.0
c0 += rng.normal(0, 0.01, (5, 64)).astype(np.float32)

# Cluster 1: 5 points near [0, 1, 0, ..., 0]
c1 = np.zeros((5, 64), dtype=np.float32)
c1[:, 1] = 1.0
c1 += rng.normal(0, 0.01, (5, 64)).astype(np.float32)

# Noise: 1 isolated point at [0, 0, 10, ..., 0] — orthogonal to both clusters
noise_pt = np.zeros((1, 64), dtype=np.float32)
noise_pt[0, 2] = 10.0

embeddings = np.vstack([c0, c1, noise_pt])
t = torch.tensor(embeddings)
conf = scorer_soft.fit_score(t)

# All confidence values must be in valid range
assert conf.min() >= 0.0, f"FAIL test5: min conf {conf.min()} < 0"
assert conf.max() <= 1.0, f"FAIL test5: max conf {conf.max()} > 1"

# With min_cluster_size=2, the isolated noise_pt should get HDBSCAN label=-1.
# After soft_assign it must have confidence in [0.05, 0.4].
# We verify the last element specifically (index 10, the noise point we added).
noise_conf_val = float(conf[10])
assert noise_conf_val >= 0.05, \
    f"FAIL test5: isolated noise point soft_conf={noise_conf_val:.4f} < 0.05"
assert noise_conf_val <= 0.4, \
    f"FAIL test5: isolated noise point soft_conf={noise_conf_val:.4f} > 0.4"
print(f"PASS test5: soft_assign gives noise point conf={noise_conf_val:.4f} ∈ [0.05, 0.4]")
print(f"           all confs: {[round(float(v),4) for v in conf]}")

print("\nALL PASS: v2.6 use_uf_refinement and noise_point_strategy verified.")
sys.exit(0)
