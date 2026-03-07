"""
MITRE-CORE Correlation Indexer Module
=====================================

Union-Find based correlation for security alert clustering.

Changelog (v2.6): No changes to core logic. use_uf_refinement flag added in
hgnn_correlation.py; this module is unaffected.

Changelog (v2.5): Score normalization fix. weighted_correlation_score now
produces normalized scores in [0, 1] by dividing by theoretical_max_score.
This aligns the UF threshold comparison with confidence_guided_threshold() outputs.
"""

from collections import defaultdict
import random
import time
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
# Optional testing/plotting imports are moved under __main__


# Legacy function - replaced by calculate_adaptive_threshold
def adaptive_correlation_threshold(cluster_size: int, data_variance: float) -> float:
    """DEPRECATED: Use calculate_adaptive_threshold instead"""
    return 0.3


def weighted_correlation_score(
    addresses_common: set,
    usernames_common: set,
    temporal_proximity: float = 0,
    n_address_cols: int = 1,
    n_username_cols: int = 1,
    use_temporal: bool = False,
) -> float:
    """
    Compute normalized alert correlation score in [0, 1].

    The raw score (addresses * 0.6 + usernames * 0.3 + temporal * 0.1) is divided
    by the theoretical maximum for the given column configuration so the result is
    always in [0, 1], making it directly comparable to confidence_guided_threshold()
    outputs which are also in [0.1, 0.9].

    Args
    ----
    addresses_common : set
        Distinct address values shared between the two alerts.
    usernames_common : set
        Distinct username values shared between the two alerts.
    temporal_proximity : float
        Temporal closeness score in [0, 1] (1.0 = within same second).
    n_address_cols : int
        Total number of address columns in this dataset configuration.
        Used to compute the theoretical maximum score for normalization.
    n_username_cols : int
        Total number of username columns in this dataset configuration.
    use_temporal : bool
        Whether temporal scoring is active for this run.
    """
    address_weight = 0.6
    username_weight = 0.3
    temporal_weight = 0.1

    raw_score = (
        len(addresses_common) * address_weight +
        len(usernames_common) * username_weight +
        temporal_proximity * (temporal_weight if use_temporal else 0.0)
    )
    theoretical_max = (
        n_address_cols * address_weight +
        n_username_cols * username_weight +
        (temporal_weight if use_temporal else 0.0)
    )
    if theoretical_max <= 0.0:
        return 0.0
    return min(1.0, raw_score / theoretical_max)


def calculate_temporal_proximity(timestamp1: str, timestamp2: str) -> float:
    """Calculate temporal proximity score between two events"""
    try:
        from datetime import datetime
        t1 = pd.to_datetime(timestamp1)
        t2 = pd.to_datetime(timestamp2)
        time_diff = abs((t1 - t2).total_seconds())
        
        # Normalize to 0-1 scale (events within 1 hour get max score)
        max_time_window = 3600  # 1 hour in seconds
        proximity = max(0, 1 - (time_diff / max_time_window))
        return proximity
    except Exception:
        return 0.0


def enhanced_correlation(data: pd.DataFrame, usernames: List[str], addresses: List[str], 
                        use_temporal: bool = False, use_adaptive_threshold: bool = True,
                        threshold_override: Optional[float] = None,
                        use_subnet_blocking: bool = False,
                        cluster_confidence: Optional[np.ndarray] = None) -> pd.DataFrame:
    """
    Enhanced correlation function using Union-Find algorithm for proper clustering.
    Optimized O(n^2) bottleneck using vectorized operations.
    
    Args:
        data: DataFrame with security events
        usernames: List of username column names
        addresses: List of address column names  
        use_temporal: Whether to include temporal proximity in scoring
        use_adaptive_threshold: Whether to use adaptive threshold calculation
        
    Returns:
        DataFrame with predicted clusters and correlation metadata
    """
    
    if data.empty:
        raise ValueError("Input data cannot be empty")
    
    if not all(col in data.columns for col in addresses + usernames):
        missing_cols = [col for col in addresses + usernames if col not in data.columns]
        raise ValueError(f"Missing required columns: {missing_cols}")
    
    n_events = len(data)
    
    # Calculate adaptive threshold with theoretical justification
    if threshold_override is not None:
        threshold = float(threshold_override)
        threshold_source = 'override'
    elif cluster_confidence is not None:
        threshold = confidence_guided_threshold(cluster_confidence)
        threshold_source = 'confidence_guided'
    elif use_adaptive_threshold:
        threshold = calculate_adaptive_threshold(data, addresses, usernames)
        threshold_source = 'adaptive_stats'
    else:
        threshold = 0.3  # Default threshold from literature (Valeur et al., 2004)
        threshold_source = 'baseline'
    
    # Initialize Union-Find structure for proper clustering
    parent = list(range(n_events))
    rank = [0] * n_events
    
    def find(x):
        """Find root of element x with path compression"""
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]
    
    def union(x, y):
        """Union two sets by rank"""
        root_x, root_y = find(x), find(y)
        if root_x != root_y:
            if rank[root_x] < rank[root_y]:
                parent[root_x] = root_y
            elif rank[root_x] > rank[root_y]:
                parent[root_y] = root_x
            else:
                parent[root_y] = root_x
                rank[root_x] += 1
    
    # Vectorized optimization of the O(n^2) correlation loop
    
    # Pre-extract data to numpy arrays for faster access
    addr_data = data[addresses].values
    user_data = data[usernames].values
    
    # Handle NaN values explicitly
    addr_mask = ~pd.isna(data[addresses]).values if addresses else np.zeros((n_events, 0), dtype=bool)
    user_mask = ~pd.isna(data[usernames]).values if usernames else np.zeros((n_events, 0), dtype=bool)
    
    # Pre-process timestamps if needed
    if use_temporal and 'EndDate' in data.columns:
        # Convert to numpy datetime64 array for extremely fast operations
        # Handle mixed formats or NaNs gracefully
        try:
            timestamps = pd.to_datetime(data['EndDate']).values.astype('datetime64[s]').astype(np.float64)
            has_valid_times = ~np.isnan(timestamps)
        except Exception:
            timestamps = np.zeros(n_events)
            has_valid_times = np.zeros(n_events, dtype=bool)
    else:
        timestamps = np.zeros(n_events)
        has_valid_times = np.zeros(n_events, dtype=bool)
        
    # Valid value masks (ignore 'nan', 'NIL', 'UNKNOWN', '')
    addr_str_data = addr_data.astype(str)
    user_str_data = user_data.astype(str)
    
    valid_addr_vals = ~np.isin(addr_str_data, ['nan', 'NIL', 'UNKNOWN', 'None', ''])
    valid_user_vals = ~np.isin(user_str_data, ['nan', 'NIL', 'UNKNOWN', 'None', ''])
    
    valid_addr_mask = addr_mask & valid_addr_vals
    valid_user_mask = user_mask & valid_user_vals
    
    # Precompute subnets if blocking is enabled
    if use_subnet_blocking:
        row_valid_subnets = []
        for r in range(n_events):
            subnets = set()
            for c in range(len(addresses)):
                if valid_addr_mask[r, c]:
                    ip = addr_str_data[r, c]
                    parts = ip.split('.')
                    if len(parts) == 4:
                        subnets.add('.'.join(parts[:3]))
                    else:
                        subnets.add(ip)
            row_valid_subnets.append(subnets)
    
    # Weights
    address_weight = 0.6
    username_weight = 0.3
    temporal_weight = 0.1
    max_time_window = 3600.0  # 1 hour
    
    # v2.5 ADDITION: theoretical maximum score for this run's column configuration.
    # Normalizes corr_score into [0, 1] so confidence_guided_threshold() outputs
    # are on the same scale as the score being compared against them.
    _temporal_contrib = temporal_weight if use_temporal else 0.0
    theoretical_max_score = (
        len(addresses) * address_weight +
        len(usernames) * username_weight +
        _temporal_contrib
    )
    if theoretical_max_score <= 0.0:
        theoretical_max_score = 1.0  # guard against empty column config
    
    # Fast candidate generation using Annoy Approximate Nearest Neighbors
    try:
        from annoy import AnnoyIndex
        from sklearn.feature_extraction import FeatureHasher
        
        # Prepare categorical features for hashing
        text_data = []
        for i in range(n_events):
            features = []
            for c, col in enumerate(addresses):
                if valid_addr_mask[i, c]:
                    features.append(f"{col}={addr_str_data[i, c]}")
            for c, col in enumerate(usernames):
                if valid_user_mask[i, c]:
                    features.append(f"{col}={user_str_data[i, c]}")
            text_data.append(features)
            
        # Feature Hashing
        hasher = FeatureHasher(n_features=64, input_type='string')
        X_cat = hasher.transform(text_data).toarray()
        
        # Incorporate temporal proximity into the vector space
        # We normalize timestamps so that max_time_window corresponds to a sensible distance
        if use_temporal:
            valid_time_idx = np.where(has_valid_times)[0]
            if len(valid_time_idx) > 0:
                t_min = np.min(timestamps[valid_time_idx])
                t_max = np.max(timestamps[valid_time_idx])
                if t_max > t_min:
                    t_norm = (timestamps - t_min) / (t_max - t_min) * 5.0
                else:
                    t_norm = np.zeros(n_events)
            else:
                t_norm = np.zeros(n_events)
            
            # Mask out invalid times
            t_norm = np.where(has_valid_times, t_norm, 0)
            X = np.hstack([X_cat, t_norm.reshape(-1, 1)])
        else:
            X = X_cat
            
        dim = X.shape[1]
        annoy_idx = AnnoyIndex(dim, 'angular')
        
        for i in range(n_events):
            annoy_idx.add_item(i, X[i])
            
        annoy_idx.build(10) # 10 trees
        
        # Generate candidates (k=min(50, n_events) for small graphs, scaling up for larger ones)
        k_neighbors = min(100, n_events) 
        candidates = set()
        
        for i in range(n_events):
            nn = annoy_idx.get_nns_by_item(i, k_neighbors)
            for j in nn:
                if j > i:
                    candidates.add((i, j))
                    
    except ImportError:
        # Fallback to O(n^2) if Annoy or scikit-learn is not available
        candidates = ((i, j) for i in range(n_events) for j in range(i + 1, n_events))

    max_scores = np.zeros(n_events)

    # Evaluate exact correlation only on shortlisted pairs
    for i, j in candidates:
        if use_subnet_blocking and row_valid_subnets[i] and row_valid_subnets[j]:
            if not row_valid_subnets[i].intersection(row_valid_subnets[j]):
                continue

        # 1. Address similarity
        row_addr = addr_str_data[i]
        row_addr_valid = valid_addr_mask[i]
        
        # 2. Username similarity
        row_user = user_str_data[i]
        row_user_valid = valid_user_mask[i]
        
        # Compute common addresses explicitly (equivalent to set intersection)
        common_addr = 0
        for col in range(len(addresses)):
            if row_addr_valid[col] and valid_addr_mask[j, col] and row_addr[col] == addr_str_data[j, col]:
                already_counted = False
                for prev_col in range(col):
                    if row_addr_valid[prev_col] and row_addr[prev_col] == row_addr[col]:
                        already_counted = True
                        break
                if not already_counted:
                    common_addr += 1
                    
        # Compute common usernames
        common_user = 0
        for col in range(len(usernames)):
            if row_user_valid[col] and valid_user_mask[j, col] and row_user[col] == user_str_data[j, col]:
                already_counted = False
                for prev_col in range(col):
                    if row_user_valid[prev_col] and row_user[prev_col] == row_user[col]:
                        already_counted = True
                        break
                if not already_counted:
                    common_user += 1
                    
        # Compute temporal score
        temporal_score = 0.0
        if use_temporal and has_valid_times[i] and has_valid_times[j]:
            time_diff = abs(timestamps[i] - timestamps[j])
            if time_diff < max_time_window:
                temporal_score = 1.0 - (time_diff / max_time_window)
                
        # Raw score — may exceed 1.0 for multi-column configs (max = theoretical_max_score)
        corr_score_raw = (common_addr * address_weight +
                          common_user * username_weight +
                          temporal_score * temporal_weight)

        # Normalized score in [0, 1]: fraction of maximum possible overlap (v2.5)
        corr_score = corr_score_raw / theoretical_max_score

        # Update max correlation scores (store normalized for interpretability)
        max_scores[i] = max(max_scores[i], corr_score)
        max_scores[j] = max(max_scores[j], corr_score)

        # Union events if normalized correlation exceeds threshold
        if corr_score >= threshold:
            union(i, j)

    # Extract final cluster assignments
    clusters = [find(i) for i in range(n_events)]
    
    # Renumber clusters to be consecutive starting from 0
    unique_clusters = sorted(set(clusters))
    cluster_mapping = {old_id: new_id for new_id, old_id in enumerate(unique_clusters)}
    final_clusters = [cluster_mapping[cluster_id] for cluster_id in clusters]
    
    # Add results to dataframe
    result_data = data.copy()
    result_data['pred_cluster'] = final_clusters
    result_data['correlation_threshold_used'] = threshold
    result_data['threshold_source'] = threshold_source
    
    # Vectorized max computation
    # correlation_matrix was removed for memory optimization
    result_data['max_correlation_score'] = max_scores
    return result_data


def confidence_guided_threshold(confidence_scores: Optional[np.ndarray], base_threshold: float = 0.3) -> float:
    """
    Adjust the threshold based on HGNN confidence scores.
    High confidence -> raise threshold (more strict correlation)
    Low confidence -> lower threshold (more lenient correlation)
    """
    if confidence_scores is None or len(confidence_scores) == 0:
        return base_threshold
    
    mean_conf = float(np.mean(confidence_scores))
    adjustment = mean_conf - 0.5
    new_threshold = base_threshold + adjustment
    return max(0.1, min(0.9, new_threshold))

def calculate_adaptive_threshold(data: pd.DataFrame, addresses: List[str], 
                               usernames: List[str]) -> float:
    """
    Calculate adaptive threshold based on data characteristics and theoretical principles
    
    Based on:
    1. Dataset size (larger datasets need higher thresholds to avoid over-clustering)
    2. Feature diversity (more diverse data needs lower thresholds)
    3. Temporal spread (longer time spans suggest lower correlation requirements)
    
    Args:
        data: Input DataFrame
        addresses: Address column names
        usernames: Username column names
        
    Returns:
        Adaptive threshold value
    """
    
    base_threshold = 0.3  # From alert correlation literature
    
    # Size factor: larger datasets need slightly higher thresholds
    size_factor = min(0.1, np.log10(len(data)) / 10)
    
    # Diversity factor: calculate feature entropy
    diversity_factor = 0.0
    for col in addresses + usernames:
        if col in data.columns:
            unique_ratio = len(data[col].dropna().unique()) / len(data)
            diversity_factor += unique_ratio
    
    diversity_factor = diversity_factor / len(addresses + usernames)
    diversity_adjustment = (diversity_factor - 0.5) * 0.2  # Normalize around 0.5
    
    # Temporal factor: if timestamps available, consider time spread
    temporal_factor = 0.0
    if 'EndDate' in data.columns:
        try:
            timestamps = pd.to_datetime(data['EndDate'], errors='coerce').dropna()
            if len(timestamps) > 1:
                time_span_hours = (timestamps.max() - timestamps.min()).total_seconds() / 3600
                # Longer time spans suggest need for lower thresholds (more lenient correlation)
                temporal_factor = -min(0.1, time_span_hours / 1000)  # Normalize to reasonable range
        except Exception:
            temporal_factor = 0.0
    
    adaptive_threshold = base_threshold + size_factor + diversity_adjustment + temporal_factor
    
    # Ensure threshold stays in reasonable bounds
    return max(0.1, min(0.8, adaptive_threshold))


def calculate_feature_similarity(row1: pd.Series, row2: pd.Series, 
                               feature_columns: List[str]) -> set:
    """
    Calculate common features between two events, handling missing values properly
    
    Args:
        row1, row2: Event data rows
        feature_columns: Columns to compare
        
    Returns:
        Set of common non-null feature values
    """
    
    common_features = set()
    
    for col in feature_columns:
        val1 = str(row1[col]) if pd.notna(row1[col]) else None
        val2 = str(row2[col]) if pd.notna(row2[col]) else None
        
        # Only consider as common if both values are non-null and equal
        if (val1 is not None and val2 is not None and 
            val1 not in ['nan', 'NIL', 'UNKNOWN', ''] and
            val2 not in ['nan', 'NIL', 'UNKNOWN', ''] and
            val1 == val2):
            common_features.add(val1)
    
    return common_features


def correlation(data, usernames, addresses):
    """Legacy correlation function - kept for backward compatibility"""
    return enhanced_correlation(data, usernames, addresses, 
                              use_temporal=False, use_adaptive_threshold=False)
       

def main(uri = 'Data/Raw_data/test_dataset.csv', use_subnet_blocking=False):
    """Main function for testing correlation algorithm"""
    try:
        # Optional imports to avoid hard dependencies during library use
        try:
            import Testing  # noqa: F401
        except Exception as e:
            print(f"Warning: optional Testing module unavailable: {e}")
            Testing = None  # type: ignore
        try:
            import plots  # noqa: F401
        except Exception as e:
            print(f"Warning: optional plots module unavailable: {e}")
            plots = None  # type: ignore

        from pathlib import Path
        file_name = Path(uri).name
        if Testing:
            df = Testing.build_data(10)
        else:
            # Minimal fallback synthetic data for ad-hoc testing
            df = pd.DataFrame({
                'SourceAddress': ['10.0.0.1', '10.0.0.2', '10.0.0.1'],
                'DestinationAddress': ['192.168.1.5', '192.168.1.6', '192.168.1.5'],
                'DeviceAddress': ['172.16.0.10', '172.16.0.10', '172.16.0.10'],
                'SourceHostName': ['hostA', 'hostB', 'hostA'],
                'DeviceHostName': ['fw1', 'fw1', 'fw1'],
                'DestinationHostName': ['srv1', 'srv2', 'srv1'],
                'EndDate': ['2023-01-01T10:00:00', '2023-01-01T10:05:00', '2023-01-01T10:10:00']
            })
        addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]

        df = df.drop_duplicates(keep="first", ignore_index=True)
        res = enhanced_correlation(df, usernames, addresses, 
                                 use_temporal=True, use_adaptive_threshold=True,
                                 use_subnet_blocking=use_subnet_blocking)
        
        path = str(Path('Data/Cleaned') / f'Test_{file_name}')
        res.to_csv(path, index=False)   
        
        print(f"Correlation completed: {len(set(res['pred_cluster']))} clusters found")
        print(f"Threshold used: {res['correlation_threshold_used'].iloc[0]:.3f}")
        
        # Optional: generate plots if needed
        # plots.main(uri=path, addresses=addresses, usernames=usernames)   
        
    except Exception as e:
        print(f"Error in main function: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MITRE-CORE Correlation Indexer")
    parser.add_argument("--subnet-filter", action="store_true", help="Enable IP-subnet blocking pre-filter")
    parser.add_argument("--uri", type=str, default="Data/Raw_data/test_dataset.csv", help="URI of the dataset")
    args = parser.parse_args()

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Enhanced correlation testing started at: " + str(current_time))

    main(uri=args.uri, use_subnet_blocking=args.subnet_filter)

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Enhanced correlation testing ended at: " + str(current_time))
         
      
