"""
Union-Find (Disjoint Set Union) Utilities
Consolidated implementation for use across MITRE-CORE modules.
This replaces duplicate implementations in 4+ locations.
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np
import logging

logger = logging.getLogger("mitre-core.union_find")


@dataclass
class UnionFind:
    """
    Union-Find (Disjoint Set Union) data structure with path compression and union by rank.
    Used for clustering alerts into attack campaigns.
    """
    parent: Dict[int, int] = field(default_factory=dict)
    rank: Dict[int, int] = field(default_factory=dict)
    
    def find(self, x: int) -> int:
        """Find root of x with path compression."""
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
            return x
        
        if self.parent[x] != x:
            # Path compression
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]
    
    def union(self, x: int, y: int) -> bool:
        """Union two sets. Returns True if merged, False if already in same set."""
        root_x = self.find(x)
        root_y = self.find(y)
        
        if root_x == root_y:
            return False
        
        # Union by rank
        if self.rank[root_x] < self.rank[root_y]:
            root_x, root_y = root_y, root_x
        
        self.parent[root_y] = root_x
        if self.rank[root_x] == self.rank[root_y]:
            self.rank[root_x] += 1
        
        return True
    
    def get_clusters(self) -> Dict[int, Set[int]]:
        """Get all clusters as {root: {members}}."""
        clusters = defaultdict(set)
        for x in self.parent:
            root = self.find(x)
            clusters[root].add(x)
        return dict(clusters)
    
    def get_cluster_id(self, x: int) -> int:
        """Get the cluster ID (root) for element x."""
        return self.find(x)
    
    def in_same_cluster(self, x: int, y: int) -> bool:
        """Check if two elements are in the same cluster."""
        return self.find(x) == self.find(y)
    
    def reset(self):
        """Clear all data."""
        self.parent.clear()
        self.rank.clear()


class WeightedUnionFind:
    """
    Weighted Union-Find with edge weights for correlation strength.
    Used for HGNN correlation where edge weights matter.
    """
    
    def __init__(self):
        self.parent: Dict[int, int] = {}
        self.rank: Dict[int, int] = {}
        self.weights: Dict[Tuple[int, int], float] = {}
        
    def find(self, x: int) -> int:
        """Find root with path compression."""
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
            return x
        
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]
    
    def union(self, x: int, y: int, weight: float = 1.0) -> bool:
        """Union with edge weight."""
        root_x = self.find(x)
        root_y = self.find(y)
        
        if root_x == root_y:
            return False
        
        # Store the weight
        self.weights[(min(x, y), max(x, y))] = weight
        
        # Union by rank
        if self.rank[root_x] < self.rank[root_y]:
            root_x, root_y = root_y, root_x
        
        self.parent[root_y] = root_x
        if self.rank[root_x] == self.rank[root_y]:
            self.rank[root_x] += 1
        
        return True
    
    def get_cluster_weight(self, root: int) -> float:
        """Get total weight of cluster."""
        total = 0.0
        for (a, b), w in self.weights.items():
            if self.find(a) == root and self.find(b) == root:
                total += w
        return total


def correlate_alerts_union_find(
    alert_ids: List[int],
    correlation_pairs: List[Tuple[int, int]],
    threshold: float = 0.5
) -> Dict[int, Set[int]]:
    """
    Correlate alerts using Union-Find.
    
    Args:
        alert_ids: List of alert IDs
        correlation_pairs: Pairs of alert IDs that are correlated
        threshold: Minimum correlation score (not used in basic UF, but for compatibility)
    
    Returns:
        Dict mapping cluster root to set of alert IDs in that cluster
    """
    uf = UnionFind()
    
    # Initialize all alerts
    for alert_id in alert_ids:
        uf.find(alert_id)  # This initializes them
    
    # Union correlated pairs
    for a, b in correlation_pairs:
        uf.union(a, b)
    
    return uf.get_clusters()


def merge_clusters_by_threshold(
    clusters: Dict[int, Set[int]],
    similarity_matrix: np.ndarray,
    alert_id_to_idx: Dict[int, int],
    threshold: float = 0.7
) -> Dict[int, Set[int]]:
    """
    Merge clusters based on inter-cluster similarity threshold.
    
    Args:
        clusters: Initial clusters {root: {members}}
        similarity_matrix: Pairwise similarity between alerts
        alert_id_to_idx: Mapping from alert ID to matrix index
        threshold: Minimum similarity to merge clusters
    
    Returns:
        Merged clusters
    """
    uf = UnionFind()
    
    # Initialize clusters
    cluster_roots = list(clusters.keys())
    for root in cluster_roots:
        uf.find(root)
    
    # Check inter-cluster similarity
    for i, root_i in enumerate(cluster_roots):
        for j, root_j in enumerate(cluster_roots[i+1:], i+1):
            # Calculate average similarity between clusters
            similarities = []
            for alert_i in clusters[root_i]:
                for alert_j in clusters[root_j]:
                    idx_i = alert_id_to_idx.get(alert_i)
                    idx_j = alert_id_to_idx.get(alert_j)
                    if idx_i is not None and idx_j is not None:
                        similarities.append(similarity_matrix[idx_i, idx_j])
            
            if similarities and np.mean(similarities) >= threshold:
                uf.union(root_i, root_j)
    
    # Build new clusters
    new_clusters = defaultdict(set)
    for root, members in clusters.items():
        new_root = uf.find(root)
        new_clusters[new_root].update(members)
    
    return dict(new_clusters)


__all__ = [
    'UnionFind',
    'WeightedUnionFind', 
    'correlate_alerts_union_find',
    'merge_clusters_by_threshold'
]
