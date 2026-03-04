"""
Baseline correlation methods for comparison with MITRE-CORE
Implements standard clustering algorithms for alert correlation
"""

import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN, AgglomerativeClustering, KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics.pairwise import cosine_similarity
from typing import List, Dict, Tuple
import logging

class SimpleBaselineCorrelator:
    """Simple baseline using standard clustering algorithms"""
    
    def __init__(self):
        self.logger = logging.getLogger('SimpleBaselineCorrelator')
        self.scaler = StandardScaler()
        self.label_encoders = {}
    
    def preprocess_data(self, data: pd.DataFrame, addresses: List[str], 
                       usernames: List[str]) -> np.ndarray:
        """Preprocess data for clustering algorithms"""
        
        # Select relevant columns
        feature_columns = addresses + usernames
        df_features = data[feature_columns].copy()
        
        # Handle missing values
        df_features = df_features.fillna('UNKNOWN')
        
        # Encode categorical variables
        encoded_features = []
        for col in feature_columns:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                encoded_col = self.label_encoders[col].fit_transform(df_features[col].astype(str))
            else:
                # Handle unseen labels
                unique_labels = set(df_features[col].astype(str))
                known_labels = set(self.label_encoders[col].classes_)
                new_labels = unique_labels - known_labels
                
                if new_labels:
                    # Add new labels to encoder
                    all_labels = list(self.label_encoders[col].classes_) + list(new_labels)
                    self.label_encoders[col].classes_ = np.array(all_labels)
                
                encoded_col = self.label_encoders[col].transform(df_features[col].astype(str))
            
            encoded_features.append(encoded_col)
        
        # Combine features
        feature_matrix = np.column_stack(encoded_features)
        
        # Scale features
        feature_matrix_scaled = self.scaler.fit_transform(feature_matrix)
        
        return feature_matrix_scaled
    
    def dbscan_correlation(self, data: pd.DataFrame, addresses: List[str], 
                          usernames: List[str], eps: float = None, 
                          min_samples: int = None, auto_tune: bool = True) -> pd.DataFrame:
        """DBSCAN-based alert correlation"""
        
        # Auto-tune parameters if not provided
        if auto_tune and (eps is None or min_samples is None):
            eps, min_samples = self._tune_dbscan_parameters(data, addresses, usernames)
        
        # Set defaults if still None
        if eps is None:
            eps = 0.5
        if min_samples is None:
            min_samples = max(2, len(data) // 20)
            
        self.logger.info(f"Running DBSCAN with eps={eps:.3f}, min_samples={min_samples}")
        
        # Preprocess data
        feature_matrix = self.preprocess_data(data, addresses, usernames)
        
        # Apply DBSCAN
        clustering = DBSCAN(eps=eps, min_samples=min_samples)
        clusters = clustering.fit_predict(feature_matrix)
        
        # Handle noise points (label -1) by assigning unique clusters
        max_cluster = max(clusters) if len(clusters) > 0 else -1
        noise_counter = max_cluster + 1
        
        for i, cluster in enumerate(clusters):
            if cluster == -1:
                clusters[i] = noise_counter
                noise_counter += 1
        
        # Add results to dataframe
        result_data = data.copy()
        result_data['pred_cluster'] = clusters
        result_data['method'] = 'DBSCAN'
        
        return result_data
    
    def _tune_dbscan_parameters(self, data: pd.DataFrame, addresses: List[str], 
                               usernames: List[str]) -> Tuple[float, int]:
        """Auto-tune DBSCAN parameters using k-distance plot heuristic"""
        from sklearn.neighbors import NearestNeighbors
        
        # Preprocess data
        feature_matrix = self.preprocess_data(data, addresses, usernames)
        
        # Calculate k-distance for eps estimation
        k = max(2, min(10, len(data) // 10))  # Adaptive k based on dataset size
        neighbors = NearestNeighbors(n_neighbors=k)
        neighbors_fit = neighbors.fit(feature_matrix)
        distances, indices = neighbors_fit.kneighbors(feature_matrix)
        
        # Use knee point detection for eps
        k_distances = np.sort(distances[:, k-1])
        
        # Simple knee detection using second derivative
        if len(k_distances) > 3:
            second_derivative = np.diff(k_distances, 2)
            knee_idx = np.argmax(second_derivative) + 1
            eps = k_distances[knee_idx]
        else:
            eps = np.mean(k_distances)
        
        # Set min_samples based on dimensionality and dataset size
        n_features = feature_matrix.shape[1]
        min_samples = max(2, min(n_features + 1, len(data) // 15))
        
        return eps, min_samples
    
    def hierarchical_correlation(self, data: pd.DataFrame, addresses: List[str], 
                                usernames: List[str], n_clusters: int = None,
                                linkage: str = 'ward') -> pd.DataFrame:
        """Hierarchical clustering baseline"""
        
        if n_clusters is None:
            n_clusters = max(2, len(data) // 5)  # Heuristic
        
        self.logger.info(f"Running Hierarchical clustering with n_clusters={n_clusters}")
        
        # Preprocess data
        feature_matrix = self.preprocess_data(data, addresses, usernames)
        
        # Apply hierarchical clustering
        clustering = AgglomerativeClustering(n_clusters=n_clusters, linkage=linkage)
        clusters = clustering.fit_predict(feature_matrix)
        
        # Add results to dataframe
        result_data = data.copy()
        result_data['pred_cluster'] = clusters
        result_data['method'] = 'Hierarchical'
        
        return result_data
    
    def kmeans_correlation(self, data: pd.DataFrame, addresses: List[str], 
                          usernames: List[str], n_clusters: int = None,
                          random_state: int = 42, auto_tune: bool = True) -> pd.DataFrame:
        """K-means clustering baseline"""
        
        # Auto-tune number of clusters if requested
        if auto_tune and n_clusters is None:
            n_clusters = self._tune_kmeans_clusters(data, addresses, usernames)
        
        if n_clusters is None:
            n_clusters = max(2, len(data) // 8)  # Heuristic fallback
        
        self.logger.info(f"Running K-means with n_clusters={n_clusters}")
        
        # Preprocess data
        feature_matrix = self.preprocess_data(data, addresses, usernames)
        
        # Apply K-means
        clustering = KMeans(n_clusters=n_clusters, random_state=random_state, n_init=10)
        clusters = clustering.fit_predict(feature_matrix)
        
        # Add results to dataframe
        result_data = data.copy()
        result_data['pred_cluster'] = clusters
        result_data['method'] = 'K-means'
        
        return result_data
    
    def _tune_kmeans_clusters(self, data: pd.DataFrame, addresses: List[str], 
                             usernames: List[str]) -> int:
        """Auto-tune number of clusters using elbow method"""
        from sklearn.metrics import silhouette_score
        
        # Preprocess data
        feature_matrix = self.preprocess_data(data, addresses, usernames)
        
        # Test different numbers of clusters
        max_k = min(10, len(data) // 2)
        if max_k < 2:
            return 2
        
        inertias = []
        silhouette_scores = []
        k_range = range(2, max_k + 1)
        
        for k in k_range:
            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
            cluster_labels = kmeans.fit_predict(feature_matrix)
            
            inertias.append(kmeans.inertia_)
            if len(set(cluster_labels)) > 1:  # Need at least 2 clusters for silhouette
                silhouette_scores.append(silhouette_score(feature_matrix, cluster_labels))
            else:
                silhouette_scores.append(-1)
        
        # Find elbow using second derivative
        if len(inertias) >= 3:
            second_derivative = np.diff(inertias, 2)
            elbow_idx = np.argmax(second_derivative) + 2  # +2 because we start from k=2
            optimal_k = k_range[elbow_idx - 2]  # Adjust for range offset
        else:
            # Fallback to best silhouette score
            best_silhouette_idx = np.argmax(silhouette_scores)
            optimal_k = k_range[best_silhouette_idx]
        
        return optimal_k


class RuleBasedCorrelator:
    """Rule-based correlation baseline"""
    
    def __init__(self):
        self.logger = logging.getLogger('RuleBasedCorrelator')
    
    def simple_rule_correlation(self, data: pd.DataFrame, addresses: List[str], 
                               usernames: List[str]) -> pd.DataFrame:
        """Simple rule-based correlation using exact matches"""
        
        self.logger.info("Running rule-based correlation")
        
        result_data = data.copy()
        clusters = {}
        current_cluster = 0
        
        # Create signature for each row
        signatures = {}
        for idx, row in data.iterrows():
            # Create signature from non-null address and username fields
            sig_parts = []
            for field in addresses + usernames:
                value = str(row[field])
                if value not in ['nan', 'NIL', 'UNKNOWN', '']:
                    sig_parts.append(f"{field}:{value}")
            
            signature = "|".join(sorted(sig_parts))
            signatures[idx] = signature
        
        # Group by signature
        signature_to_cluster = {}
        for idx, signature in signatures.items():
            if signature in signature_to_cluster:
                clusters[idx] = signature_to_cluster[signature]
            else:
                clusters[idx] = current_cluster
                signature_to_cluster[signature] = current_cluster
                current_cluster += 1
        
        # Convert to list
        cluster_list = [clusters[i] for i in range(len(data))]
        
        result_data['pred_cluster'] = cluster_list
        result_data['method'] = 'Rule-based'
        
        return result_data
    
    def ip_subnet_correlation(self, data: pd.DataFrame, addresses: List[str], 
                             usernames: List[str]) -> pd.DataFrame:
        """Correlation based on IP subnet similarity"""
        
        self.logger.info("Running IP subnet correlation")
        
        result_data = data.copy()
        
        # Extract subnets
        def get_subnet(ip_str):
            try:
                parts = str(ip_str).split('.')
                if len(parts) >= 3:
                    return '.'.join(parts[:3])
                return str(ip_str)
            except (ValueError, TypeError, AttributeError):
                return 'UNKNOWN'
        
        # Create subnet signatures
        subnet_signatures = {}
        for idx, row in data.iterrows():
            subnets = []
            for addr_field in addresses:
                subnet = get_subnet(row[addr_field])
                if subnet != 'UNKNOWN':
                    subnets.append(subnet)
            
            # Add usernames for additional correlation
            for user_field in usernames:
                user_val = str(row[user_field])
                if user_val not in ['nan', 'NIL', 'UNKNOWN', '']:
                    subnets.append(f"user:{user_val}")
            
            subnet_signatures[idx] = "|".join(sorted(set(subnets)))
        
        # Group by subnet signature
        signature_to_cluster = {}
        current_cluster = 0
        clusters = {}
        
        for idx, signature in subnet_signatures.items():
            if signature in signature_to_cluster:
                clusters[idx] = signature_to_cluster[signature]
            else:
                clusters[idx] = current_cluster
                signature_to_cluster[signature] = current_cluster
                current_cluster += 1
        
        cluster_list = [clusters[i] for i in range(len(data))]
        
        result_data['pred_cluster'] = cluster_list
        result_data['method'] = 'IP-Subnet'
        
        return result_data


class UnionFind:
    """A highly optimized Union-Find data structure."""
    def __init__(self, n):
        self.parent = list(range(n))
        self.rank = [1] * n

    def find(self, i):
        """Find the root of the set containing element i with path compression."""
        if self.parent[i] == i:
            return i
        self.parent[i] = self.find(self.parent[i])  # Path compression
        return self.parent[i]

    def union(self, i, j):
        """Merge the sets containing elements i and j using union by rank."""
        root_i = self.find(i)
        root_j = self.find(j)
        if root_i != root_j:
            # Union by rank
            if self.rank[root_i] > self.rank[root_j]:
                self.parent[root_j] = root_i
            elif self.rank[root_i] < self.rank[root_j]:
                self.parent[root_i] = root_j
            else:
                self.parent[root_j] = root_i
                self.rank[root_i] += 1
            return True
        return False


class AdvancedBaselineCorrelator:
    """More sophisticated baseline methods"""
    
    def __init__(self):
        self.logger = logging.getLogger('AdvancedBaselineCorrelator')
    
    def cosine_similarity_correlation(self, data: pd.DataFrame, addresses: List[str], 
                                    usernames: List[str], threshold: float = 0.7) -> pd.DataFrame:
        """Correlation based on cosine similarity"""
        
        self.logger.info(f"Running cosine similarity correlation with threshold={threshold}")
        
        # Preprocess data
        baseline_correlator = SimpleBaselineCorrelator()
        feature_matrix = baseline_correlator.preprocess_data(data, addresses, usernames)
        
        # Calculate cosine similarity matrix
        similarity_matrix = cosine_similarity(feature_matrix)
        
        # Create clusters based on similarity threshold using Union-Find
        n_samples = len(data)
        uf = UnionFind(n_samples)
        
        # Merge similar points efficiently
        for i in range(n_samples):
            for j in range(i + 1, n_samples):
                if similarity_matrix[i][j] >= threshold:
                    uf.union(i, j)
        
        # Assign final cluster labels based on the root of each set
        clusters = [uf.find(i) for i in range(n_samples)]
        
        # Renumber clusters to be consecutive
        unique_clusters = list(set(clusters))
        cluster_mapping = {old: new for new, old in enumerate(unique_clusters)}
        final_clusters = [cluster_mapping[c] for c in clusters]
        
        result_data = data.copy()
        result_data['pred_cluster'] = final_clusters
        result_data['method'] = 'Cosine-Similarity'
        
        return result_data
    
    def temporal_clustering(self, data: pd.DataFrame, addresses: List[str], 
                           usernames: List[str], time_window_hours: int = 24) -> pd.DataFrame:
        """Temporal-based clustering"""
        
        self.logger.info(f"Running temporal clustering with {time_window_hours}h window")
        
        result_data = data.copy()
        
        # Parse timestamps
        if 'EndDate' not in data.columns:
            # If no timestamp, assign random clusters
            result_data['pred_cluster'] = np.random.randint(0, max(2, len(data)//5), len(data))
            result_data['method'] = 'Temporal-NoTime'
            return result_data
        
        timestamps = pd.to_datetime(data['EndDate'], errors='coerce')
        
        # Sort by timestamp
        sorted_indices = timestamps.argsort()
        clusters = [-1] * len(data)
        current_cluster = 0
        
        for i, idx in enumerate(sorted_indices):
            if pd.isna(timestamps.iloc[idx]):
                clusters[idx] = current_cluster
                current_cluster += 1
                continue
            
            # Check if this event is within time window of any existing cluster
            assigned = False
            current_time = timestamps.iloc[idx]
            
            for j in range(i):
                prev_idx = sorted_indices[j]
                prev_time = timestamps.iloc[prev_idx]
                
                if pd.isna(prev_time):
                    continue
                
                time_diff = abs((current_time - prev_time).total_seconds() / 3600)  # hours
                
                if time_diff <= time_window_hours:
                    # Check if they share any common features
                    row_curr = data.iloc[idx]
                    row_prev = data.iloc[prev_idx]
                    
                    common_features = 0
                    for field in addresses + usernames:
                        if (str(row_curr[field]) == str(row_prev[field]) and 
                            str(row_curr[field]) not in ['nan', 'NIL', 'UNKNOWN', '']):
                            common_features += 1
                    
                    if common_features > 0:
                        clusters[idx] = clusters[prev_idx]
                        assigned = True
                        break
            
            if not assigned:
                clusters[idx] = current_cluster
                current_cluster += 1
        
        result_data['pred_cluster'] = clusters
        result_data['method'] = 'Temporal'
        
        return result_data


# Convenience function to run all baselines
def run_all_baselines(data: pd.DataFrame, addresses: List[str], 
                     usernames: List[str]) -> Dict[str, pd.DataFrame]:
    """Run all baseline methods and return results"""
    
    results = {}
    
    # Simple clustering baselines
    simple_correlator = SimpleBaselineCorrelator()
    results['DBSCAN'] = simple_correlator.dbscan_correlation(data, addresses, usernames)
    results['Hierarchical'] = simple_correlator.hierarchical_correlation(data, addresses, usernames)
    results['K-means'] = simple_correlator.kmeans_correlation(data, addresses, usernames)
    
    # Rule-based baselines
    rule_correlator = RuleBasedCorrelator()
    results['Rule-based'] = rule_correlator.simple_rule_correlation(data, addresses, usernames)
    results['IP-Subnet'] = rule_correlator.ip_subnet_correlation(data, addresses, usernames)
    
    # Advanced baselines
    advanced_correlator = AdvancedBaselineCorrelator()
    results['Cosine-Similarity'] = advanced_correlator.cosine_similarity_correlation(data, addresses, usernames)
    results['Temporal'] = advanced_correlator.temporal_clustering(data, addresses, usernames)
    
    return results


# Example usage
if __name__ == "__main__":
    # Test with sample data
    sample_data = pd.DataFrame({
        'SourceAddress': ['192.168.1.1', '192.168.1.2', '10.0.0.1', '192.168.1.1'],
        'DestinationAddress': ['10.0.0.1', '10.0.0.2', '192.168.1.1', '10.0.0.1'],
        'DeviceAddress': ['172.16.1.1', '172.16.1.1', '172.16.2.1', '172.16.1.1'],
        'SourceHostName': ['host1', 'host2', 'host3', 'host1'],
        'DeviceHostName': ['device1', 'device1', 'device2', 'device1'],
        'DestinationHostName': ['target1', 'target2', 'target3', 'target1'],
        'EndDate': ['2023-01-01T10:00:00', '2023-01-01T10:30:00', 
                   '2023-01-01T15:00:00', '2023-01-01T10:15:00']
    })
    
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    results = run_all_baselines(sample_data, addresses, usernames)
    
    print("Baseline methods implemented successfully!")
    for method, result in results.items():
        print(f"{method}: {len(set(result['pred_cluster']))} clusters")
