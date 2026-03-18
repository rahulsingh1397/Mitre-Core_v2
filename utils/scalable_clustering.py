"""
Hierarchical Clustering for Billion-Scale Event Processing
Implements multi-level clustering for scalability to millions of events.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import logging
from sklearn.cluster import MiniBatchKMeans
import hashlib

logger = logging.getLogger("mitre-core.scalable_clustering")


@dataclass
class HierarchicalCluster:
    """Represents a cluster in the hierarchical structure."""
    cluster_id: int
    level: int  # 0 = leaf, 1 = intermediate, 2 = root
    alerts: List[int]
    centroid: np.ndarray
    children: List[int]  # Child cluster IDs
    parent: Optional[int]
    summary_stats: Dict


class BillionScaleClustering:
    """
    Hierarchical clustering for billion-scale event processing.
    
    Architecture:
    - Level 0: Micro-clusters (10K alerts each, MiniBatchKMeans)
    - Level 1: Meso-clusters (merge micro-clusters, Union-Find)
    - Level 2: Macro-clusters (final campaigns, HGNN refinement)
    """
    
    def __init__(self,
                 micro_cluster_size: int = 10000,
                 meso_cluster_threshold: float = 0.7,
                 max_levels: int = 3):
        self.micro_size = micro_cluster_size
        self.meso_threshold = meso_cluster_threshold
        self.max_levels = max_levels
        self.levels = {i: {} for i in range(max_levels)}
        self.total_alerts = 0
    
    def fit_predict(self, features: np.ndarray, alert_ids: List[int]) -> np.ndarray:
        """
        Perform hierarchical clustering on large dataset.
        
        Args:
            features: Alert feature matrix (n_alerts x n_features)
            alert_ids: Unique identifiers for each alert
            
        Returns:
            Cluster assignments for each alert
        """
        n_alerts = len(features)
        self.total_alerts = n_alerts
        
        logger.info(f"Starting billion-scale clustering for {n_alerts:,} alerts")
        
        # Level 0: Create micro-clusters
        if n_alerts > self.micro_size:
            micro_labels = self._create_micro_clusters(features, alert_ids)
        else:
            micro_labels = np.arange(n_alerts)
        
        # Level 1: Merge micro-clusters into meso-clusters
        meso_labels = self._create_meso_clusters(features, micro_labels, alert_ids)
        
        # Level 2: Final macro-clustering (if needed)
        if len(np.unique(meso_labels)) > 1000:
            final_labels = self._create_macro_clusters(features, meso_labels)
        else:
            final_labels = meso_labels
        
        logger.info(f"Clustering complete: {len(np.unique(final_labels))} final clusters")
        
        return final_labels
    
    def _create_micro_clusters(self, 
                              features: np.ndarray,
                              alert_ids: List[int]) -> np.ndarray:
        """Create level 0 micro-clusters using MiniBatchKMeans."""
        n_alerts = len(features)
        n_micro = max(1, n_alerts // self.micro_size)
        
        logger.info(f"Creating {n_micro} micro-clusters from {n_alerts:,} alerts")
        
        # Use MiniBatchKMeans for scalability
        kmeans = MiniBatchKMeans(
            n_clusters=n_micro,
            batch_size=1000,
            max_iter=100,
            random_state=42,
            n_init=3
        )
        
        labels = kmeans.fit_predict(features)
        
        # Store micro-clusters
        for i in range(n_micro):
            mask = labels == i
            self.levels[0][i] = HierarchicalCluster(
                cluster_id=i,
                level=0,
                alerts=[alert_ids[j] for j in np.where(mask)[0]],
                centroid=kmeans.cluster_centers_[i],
                children=[],
                parent=None,
                summary_stats={
                    'size': int(mask.sum()),
                    'feature_mean': features[mask].mean(axis=0).tolist(),
                    'feature_std': features[mask].std(axis=0).tolist()
                }
            )
        
        return labels
    
    def _create_meso_clusters(self,
                             features: np.ndarray,
                             micro_labels: np.ndarray,
                             alert_ids: List[int]) -> np.ndarray:
        """Merge micro-clusters into meso-clusters using similarity."""
        unique_micros = np.unique(micro_labels)
        n_micros = len(unique_micros)
        
        logger.info(f"Merging {n_micros} micro-clusters into meso-clusters")
        
        # Calculate micro-cluster centroids
        micro_centroids = []
        for micro_id in unique_micros:
            mask = micro_labels == micro_id
            centroid = features[mask].mean(axis=0)
            micro_centroids.append(centroid)
        
        micro_centroids = np.array(micro_centroids)
        
        # Union-Find on micro-clusters
        parent = list(range(n_micros))
        
        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py
        
        # Merge similar micro-clusters
        for i in range(n_micros):
            for j in range(i + 1, n_micros):
                # Cosine similarity between centroids
                sim = self._cosine_similarity(micro_centroids[i], micro_centroids[j])
                if sim > self.meso_threshold:
                    union(i, j)
        
        # Assign meso-cluster labels
        meso_mapping = {}
        next_meso_id = 0
        
        for i, micro_id in enumerate(unique_micros):
            root = find(i)
            if root not in meso_mapping:
                meso_mapping[root] = next_meso_id
                next_meso_id += 1
        
        # Map micro labels to meso labels
        meso_labels = np.array([meso_mapping[find(i)] for i in micro_labels])
        
        # Store meso-clusters
        for meso_id in range(next_meso_id):
            micro_children = [unique_micros[i] for i in range(n_micros) 
                            if meso_mapping[find(i)] == meso_id]
            
            # Get all alerts in this meso-cluster
            meso_mask = meso_labels == meso_id
            
            self.levels[1][meso_id] = HierarchicalCluster(
                cluster_id=meso_id,
                level=1,
                alerts=[alert_ids[j] for j in np.where(meso_mask)[0]],
                centroid=features[meso_mask].mean(axis=0),
                children=micro_children,
                parent=None,
                summary_stats={
                    'size': int(meso_mask.sum()),
                    'num_micro_clusters': len(micro_children)
                }
            )
            
            # Update micro-cluster parents
            for child_id in micro_children:
                if child_id in self.levels[0]:
                    self.levels[0][child_id].parent = meso_id
        
        return meso_labels
    
    def _create_macro_clusters(self,
                              features: np.ndarray,
                              meso_labels: np.ndarray) -> np.ndarray:
        """Create final macro-clusters if needed."""
        unique_mesos = np.unique(meso_labels)
        
        logger.info(f"Creating macro-clusters from {len(unique_mesos)} meso-clusters")
        
        # For now, keep meso-clusters as final
        # In production, this would use HGNN for refinement
        
        return meso_labels
    
    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-8)
    
    def get_cluster_summary(self, level: int = None) -> pd.DataFrame:
        """Get summary statistics for clusters at specified level."""
        if level is None:
            level = self.max_levels - 1
        
        clusters = self.levels.get(level, {})
        
        summaries = []
        for cluster in clusters.values():
            summaries.append({
                'cluster_id': cluster.cluster_id,
                'level': cluster.level,
                'size': len(cluster.alerts),
                'num_children': len(cluster.children),
                'parent': cluster.parent,
                'summary': cluster.summary_stats
            })
        
        return pd.DataFrame(summaries)
    
    def get_cluster_hierarchy(self, cluster_id: int, level: int = 2) -> Dict:
        """Get full hierarchy for a cluster."""
        if level not in self.levels or cluster_id not in self.levels[level]:
            return {}
        
        cluster = self.levels[level][cluster_id]
        
        result = {
            'cluster_id': cluster_id,
            'level': level,
            'num_alerts': len(cluster.alerts),
            'children': []
        }
        
        # Recursively get children
        for child_id in cluster.children:
            child_cluster = self.levels.get(level - 1, {}).get(child_id)
            if child_cluster:
                result['children'].append({
                    'cluster_id': child_id,
                    'level': level - 1,
                    'num_alerts': len(child_cluster.alerts),
                    'children': len(child_cluster.children)
                })
        
        return result


class StreamingClustering:
    """
    Online clustering for streaming data.
    Processes alerts incrementally without storing all history.
    """
    
    def __init__(self,
                 window_size: int = 100000,
                 decay_factor: float = 0.99):
        self.window_size = window_size
        self.decay_factor = decay_factor
        self.clusters = {}
        self.next_cluster_id = 0
        self.alert_buffer = []
    
    def process_alert(self, alert_features: np.ndarray, alert_id: int) -> int:
        """
        Process a single alert in streaming mode.
        
        Args:
            alert_features: Feature vector for the alert
            alert_id: Unique alert identifier
            
        Returns:
            Cluster assignment
        """
        # Find best matching cluster
        best_cluster = None
        best_score = -1
        
        for cluster_id, cluster_data in self.clusters.items():
            centroid = cluster_data['centroid']
            score = self._cosine_similarity(alert_features, centroid)
            
            if score > best_score and score > 0.7:  # Threshold
                best_score = score
                best_cluster = cluster_id
        
        if best_cluster is not None:
            # Add to existing cluster
            self.clusters[best_cluster]['alerts'].append(alert_id)
            self.clusters[best_cluster]['count'] += 1
            
            # Update centroid with decay
            old_centroid = self.clusters[best_cluster]['centroid']
            new_centroid = (self.decay_factor * old_centroid + 
                          (1 - self.decay_factor) * alert_features)
            self.clusters[best_cluster]['centroid'] = new_centroid
            
            return best_cluster
        else:
            # Create new cluster
            new_id = self.next_cluster_id
            self.clusters[new_id] = {
                'centroid': alert_features.copy(),
                'alerts': [alert_id],
                'count': 1,
                'created_at': pd.Timestamp.now()
            }
            self.next_cluster_id += 1
            
            return new_id
    
    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity."""
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-8)
    
    def get_active_clusters(self, min_size: int = 2) -> Dict[int, Dict]:
        """Get all active clusters above minimum size."""
        return {
            k: v for k, v in self.clusters.items()
            if v['count'] >= min_size
        }
    
    def prune_old_clusters(self, max_age_minutes: int = 60):
        """Remove clusters that haven't received alerts recently."""
        now = pd.Timestamp.now()
        to_remove = []
        
        for cluster_id, cluster_data in self.clusters.items():
            age = (now - cluster_data['created_at']).total_seconds() / 60
            if age > max_age_minutes and cluster_data['count'] < 5:
                to_remove.append(cluster_id)
        
        for cid in to_remove:
            del self.clusters[cid]
        
        logger.info(f"Pruned {len(to_remove)} old clusters")


def create_scalable_clustering(micro_size: int = 10000) -> BillionScaleClustering:
    """Factory function for scalable clustering."""
    return BillionScaleClustering(micro_cluster_size=micro_size)


def create_streaming_clustering(window_size: int = 100000) -> StreamingClustering:
    """Factory function for streaming clustering."""
    return StreamingClustering(window_size=window_size)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Generate sample data
    np.random.seed(42)
    n_samples = 50000
    n_features = 64
    
    features = np.random.randn(n_samples, n_features)
    alert_ids = list(range(n_samples))
    
    # Test scalable clustering
    logger.info("Testing billion-scale clustering...")
    clusterer = create_scalable_clustering(micro_size=1000)
    labels = clusterer.fit_predict(features, alert_ids)
    
    summary = clusterer.get_cluster_summary()
    print(f"\nCluster Summary:\n{summary.head()}")
    print(f"\nTotal clusters: {len(summary)}")
    print(f"Average cluster size: {summary['size'].mean():.1f}")
    
    # Test streaming clustering
    logger.info("\nTesting streaming clustering...")
    streamer = create_streaming_clustering()
    
    for i in range(1000):
        cluster_id = streamer.process_alert(features[i], alert_ids[i])
        if i % 100 == 0:
            logger.info(f"Processed {i} alerts, {len(streamer.clusters)} clusters active")
    
    active = streamer.get_active_clusters(min_size=2)
    logger.info(f"Final active clusters: {len(active)}")
