cat > CLAUDE.md << 'EOF'
# MITRE-CORE — Claude Code Session Context

## What this project does
Cybersecurity alert correlation engine. Takes raw SOC alerts and clusters them
into attack campaigns using a Heterogeneous GNN (HGNN) + confidence-gated
Union-Find (UF) hybrid pipeline. Labels map to MITRE ATT&CK tactics.

## Current state (as of March 2026)
Main pipeline (Phases 0–8): COMPLETE. All 8 datasets preprocessed, ablations
run, LaTeX tables generated, publication figures exist.

Active research thread: v2.2 → v2.9 — tuning the GAEC confidence scoring and
UF routing decision. See MEMORY.md for full versioned history.

## Best result so far
UNSW-NB15, use_uf_refinement=False: ARI = 0.4042 (v2.6, confirmed v2.9)
Baseline (UF enabled):              ARI = 0.3541

## What just failed and why (v2.6 → v2.9 soft_assign thread)
Four versions of soft_assign fixes all failed to reduce pct_uf_routed to 0.0.

Root cause (confirmed from source code):
  noise_mask = clusterer.probabilities_ == 0.0   (line 714, hgnn_correlation.py)

This catches only true HDBSCAN noise points. But 529 HDBSCAN BORDER POINTS
(label >= 0, probabilities_ in 0.05–0.39) also route to UF because their raw
membership probability is below gate=0.40. They never enter the soft_assign
block. Every fix in fit_score() was modifying the right values for noise points
but missing the border points entirely.

## The correct next fix (v3.0)
Replace clusterer.probabilities_ with hdbscan.all_points_membership_vectors().
This returns a full [N, n_clusters] probability matrix from the condensed tree.
Every point — noise, border, and core — gets a real probability distribution.
No hard 0.0 probabilities. No noise_mask needed. No floor/ceiling engineering.

Key requirement: HDBSCAN must be initialized with prediction_data=True (already set).

## Dataset structural differences (critical finding)
Not all datasets are equal. The graph schema is unified but edge density varies
enormously:

  UNSW-NB15:  IP + host + temporal edges. MEDIUM connectivity. Checkpoint trained here.
  NSL-KDD:    NO IP columns, NO timestamps. Graph is disconnected. HGNN ≈ MLP on 6 features.
  Linux_APT:  Process + commandline + user + IP. RICH graph. But checkpoint is OOD.
  TON_IoT:    IP + temporal. MEDIUM. OOD checkpoint. HDBSCAN finds 2 tight clusters only.
  IoT others: Device/gateway/sensor edges. Custom schema. OOD checkpoint.

NSL-KDD improving with UF disabled (ARI 0.2574 vs 0.2169) is real but modest.
The graph structure is not the reason — the 4 attack families are separable in
the 6 raw node features alone.

## Recommended next steps in priority order
1. v3.0: all_points_membership_vectors() in EmbeddingConfidenceScorer.fit_score()
   File: hgnn/hgnn_correlation.py, class EmbeddingConfidenceScorer
   Replace lines 705 and 713-764 (probabilities_ + soft_assign block)
   Sweep config: DATASET_CONFIG_V10 with soft_amv condition vs no_uf vs baseline

2. NSL-KDD investigation: count actual edges in the built graph for NSL-KDD.
   If edge count ≈ 0, document that graph-based approach is inapplicable and
   consider a feature-only baseline (GBM or MLP) as the correct comparator.

3. Long-term: domain-specialized checkpoints (network IT / host-APT / IoT).
   One checkpoint trained per domain rather than forced transfer across all 8.

## Key files
hgnn/hgnn_correlation.py          — main engine (EmbeddingConfidenceScorer + correlate())
experiments/run_gate_tuning.py    — sweep runner (DATASET_CONFIG_V6 through V9)
experiments/analyse_gate_tuning.py — analysis + singleton_fraction warning
MEMORY.md                         — full versioned experiment history (v2.2 → v2.9)
experiments/results/              — all CSV sweep outputs (v3 through v9)
experiments/verify_v27_improvements.py — passes (B + C confirmed)
experiments/verify_v29_floor_fix.py    — passes unit tests but sweep not confirmed

## Confirmed findings across all versions
- use_uf_refinement=False is correct default for this checkpoint (v2.6, universal)
- UF is net-harmful: singletons fragment correct HGNN clusters regardless of gate
- singleton_fraction > 0.8 for both UNSW-NB15 and NSL-KDD baselines (v2.7)
- apu is a misleading metric — use singleton_fraction instead (v2.7)
- Gate sweep is irrelevant for use_uf_refinement=False (auto-skip, v2.7)
- soft_assign cannot work by modifying fit_score() alone — border points are
  the real population causing UF singletons, not true noise points (v2.9)

## Sweep result reference
| Version | Condition              | Best ARI | Note                    |
|---------|------------------------|----------|-------------------------|
| v7      | UNSW-NB15_no_uf        | 0.4042   | Best result, use this   |
| v7      | UNSW-NB15_soft         | 0.3675   | H-B, ceiling collision  |
| v7      | UNSW-NB15_baseline     | 0.3541   | v2.5 baseline           |
| v7      | NSL-KDD_no_uf          | 0.2574   | Control, also improved  |
| v7      | NSL-KDD_baseline       | 0.2169   | v2.5 baseline           |
| v9      | UNSW-NB15_soft_floor   | 0.3675   | Floor fix, border pts   |
| v9      | NSL-KDD_soft_floor     | 0.2436   | Floor fix, border pts   |

## git hashes
v2.6 commit: 5e568a20a301ade3d9c3911e1b091cb5799313ea
v2.7 commit: (same hash — run update_memory_v8.py for exact)
v2.9 commit: (current HEAD)
EOF