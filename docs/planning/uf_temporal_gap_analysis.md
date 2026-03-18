# Analysis of the Gap Between Union-Find and Temporal Baseline

## Context and Metric Comparison

In our cross-domain evaluations on complex multi-stage attack datasets, the baseline Temporal sequence clustering method frequently outperforms the structural Union-Find (UF) approach across Adjusted Rand Index (ARI) and Normalized Mutual Information (NMI). For instance, in our real-data ablation experiments, we observed:
- **Temporal baseline:** ARI = 0.5849 / NMI = 0.8351
- **Union-Find (UF):** ARI = 0.5650 / NMI = 0.7650

While the gap is narrower than previously suggested by synthetic zero-valued placeholders, a consistent disparity remains. This document outlines the technical and structural reasons for this phenomenon.

## Algorithmic Differences in Graph Formulation

The fundamental difference lies in how these two methods formulate the underlying graph of events:

1. **Temporal Clustering** operates under the strong inductive bias that security events occurring within a tight time window (e.g., within 24 hours) with overlapping source/destination characteristics are intrinsically linked to the same attack sequence. This aligns perfectly with how modern Advanced Persistent Threats (APTs) execute—attackers progress linearly through the kill chain (reconnaissance $\to$ exploitation $\to$ lateral movement) in bursts of activity.

2. **Union-Find (UF) Clustering**, specifically in its MITRE-CORE implementation, relies heavily on static, pairwise feature overlaps (exact matches on IP addresses, subnets, or usernames). It computes a composite similarity score to decide whether to merge two nodes into a single campaign component.

## Impact of Graph Topology and Feature Distribution

The primary reason UF underperforms relative to the temporal baseline relates to the feature distribution and evasion techniques inherent to the test datasets (e.g., UNSW-NB15, TON_IoT, Linux_APT):

- **Attribute Churn and IP Spoofing:** Modern attacks frequently rotate source IPs, use proxies, or compromise multiple internal accounts during lateral movement. This churn breaks the exact-match pairwise links that UF requires to form a cohesive component. If an attacker moves from Host A to Host B within a 5-minute window, the Temporal baseline easily clusters these events based on temporal proximity and loose shared characteristics. In contrast, UF may view them as distinct sub-graphs if the primary features (e.g., SourceAddress) have completely changed.
- **Transitive Disconnects:** UF merges components via transitive closure. If intermediate events bridging two phases of an attack are missing from the dataset (due to sensor blind spots or evasion), the UF graph splits into separate disjoint components, drastically lowering the ARI by over-penalizing fragmentation.

## Conclusion and Trade-offs

This gap is an expected structural trade-off rather than a flaw. Union-Find trades peak accuracy on highly dynamic, time-series attacks for sub-linear latency ((N \alpha(N))$ vs (N \log N)$ or worse for complex baseline searches). In high-throughput, real-time SIEM environments where evaluating complex temporal windows across millions of disparate events is computationally infeasible, UF serves as an excellent, highly scalable pre-filter. To achieve parity with the Temporal baseline, an approach must integrate both spatial structure and temporal dynamics—precisely the gap the MITRE-CORE Heterogeneous Graph Neural Network (HGNN) architecture aims to bridge.
