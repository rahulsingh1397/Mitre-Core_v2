"""
Comprehensive experiments on REAL public datasets for IEEE paper.
Runs Union-Find, HGNN, Hybrid, and all baselines on UNSW-NB15.
Outputs all metrics: ARI, NMI, Homogeneity, Completeness, V-Measure, FMI.
"""

import os
import sys
import time
import json
import random
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sklearn.metrics import (
    adjusted_rand_score, normalized_mutual_info_score,
    homogeneity_score, completeness_score, v_measure_score,
    fowlkes_mallows_score, silhouette_score
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import DBSCAN, AgglomerativeClustering, KMeans
from sklearn.metrics.pairwise import cosine_similarity
from scipy.stats import ttest_rel, chi2_contingency

import warnings
warnings.filterwarnings('ignore')

# Reproducibility
SEED = 42
random.seed(SEED)
np.random.seed(SEED)


# ============================================================
# DATA LOADING
# ============================================================

def load_unsw_nb15_real(base_path, max_samples=None):
    """Load real UNSW-NB15 data with ground truth campaign labels."""
    train_path = base_path / "unsw_nb15" / "UNSW_NB15_training-set.csv"
    test_path = base_path / "unsw_nb15" / "UNSW_NB15_testing-set.csv"

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    # Use attack_cat as label
    if 'attack_cat' in df_train.columns:
        df_train['label'] = df_train['attack_cat'].fillna('Normal')
        df_test['label'] = df_test['attack_cat'].fillna('Normal')

    print(f"UNSW-NB15 loaded: {len(df_train)} train, {len(df_test)} test")
    print(f"Attack types (train): {df_train['label'].nunique()}")
    print(f"Label distribution (train top-10):\n{df_train['label'].value_counts().head(10)}")

    return df_train, df_test


def prepare_unsw_nb15_for_correlation(df, sample_size=2000):
    """
    Convert UNSW-NB15 to MITRE-CORE schema for correlation experiments.
    """
    # Sample for tractability
    if sample_size and len(df) > sample_size:
        # Stratified sample
        df = df.groupby('label', group_keys=False).apply(
            lambda x: x.sample(min(len(x), max(1, int(sample_size * len(x) / len(df)))),
                                random_state=SEED)
        ).reset_index(drop=True)

    # Create MITRE-CORE schema columns from real features
    mitre_df = pd.DataFrame()

    # Timestamps (UNSW has real ones, but we might not have them in this cut, so we simulate if needed)
    base_time = pd.Timestamp('2024-01-01')
    mitre_df['EndDate'] = [base_time + pd.Timedelta(seconds=i) for i in range(len(df))]

    # IPs derived from network features
    mitre_df['SourceAddress'] = df.apply(
        lambda r: f"10.{int(r.get('sbytes', 0)) % 256}.{int(r.get('spkts', 0)) % 256}.1", axis=1
    )
    mitre_df['DestinationAddress'] = df.apply(
        lambda r: f"192.168.{int(r.get('dbytes', 0)) % 256}.{int(r.get('dpkts', 0)) % 254 + 1}", axis=1
    )
    mitre_df['DeviceAddress'] = df.apply(
        lambda r: f"172.16.{hash(str(r.get('service', '')) ) % 256}.{hash(str(r.get('proto', ''))) % 254 + 1}", axis=1
    )

    # Hostnames from categorical features
    mitre_df['SourceHostName'] = df.get('service', pd.Series(['none']*len(df))).apply(lambda x: f"svc-{x}")
    mitre_df['DeviceHostName'] = df.get('state', pd.Series(['none']*len(df))).apply(lambda x: f"state-{x}")
    mitre_df['DestinationHostName'] = df.get('proto', pd.Series(['none']*len(df))).apply(lambda x: f"proto-{x}")

    # Attack metadata
    mitre_df['MalwareIntelAttackType'] = df['label']
    mitre_df['AttackSeverity'] = df['label'].apply(
        lambda x: 'Low' if x == 'Normal' else np.random.choice(['Medium', 'High'])
    )

    # Ground truth: attack label
    le = LabelEncoder()
    ground_truth = le.fit_transform(df['label'].astype(str))

    # Additional features for enriched analysis
    mitre_df['protocol_type'] = df.get('proto', 'unknown')
    mitre_df['service'] = df.get('service', 'unknown')
    mitre_df['flag'] = df.get('state', 'unknown')
    mitre_df['src_bytes'] = df.get('sbytes', 0)
    mitre_df['dst_bytes'] = df.get('dbytes', 0)
    mitre_df['duration'] = df.get('dur', 0)

    print(f"Prepared {len(mitre_df)} records, {len(set(ground_truth))} ground truth clusters")
    return mitre_df, ground_truth, le.classes_


# ============================================================
# CORRELATION METHODS
# ============================================================

class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x):
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            if self.rank[rx] < self.rank[ry]:
                self.parent[rx] = ry
            elif self.rank[rx] > self.rank[ry]:
                self.parent[ry] = rx
            else:
                self.parent[ry] = rx
                self.rank[rx] += 1
            return True
        return False


def mitre_core_union_find(data, addresses, usernames, use_temporal=True, use_adaptive=True):
    """MITRE-CORE Union-Find correlation on real data."""
    n = len(data)
    uf = UnionFind(n)

    # Calculate adaptive threshold
    base_threshold = 0.3
    if use_adaptive and n > 1:
        import math
        size_factor = min(0.1, math.log10(n) / 10)
        threshold = base_threshold + size_factor
        threshold = max(0.1, min(0.8, threshold))
    else:
        threshold = base_threshold

    # Pairwise scoring
    for i in range(n):
        for j in range(i + 1, n):
            # Address similarity
            addr_overlap = sum(
                1 for col in addresses
                if str(data.iloc[i][col]) == str(data.iloc[j][col])
                and str(data.iloc[i][col]) not in ['nan', 'NIL', 'UNKNOWN', '']
            )
            addr_sim = addr_overlap / max(len(addresses), 1)

            # Username/hostname similarity
            user_overlap = sum(
                1 for col in usernames
                if str(data.iloc[i][col]) == str(data.iloc[j][col])
                and str(data.iloc[i][col]) not in ['nan', 'NIL', 'UNKNOWN', '']
            )
            user_sim = user_overlap / max(len(usernames), 1)

            # Temporal proximity
            temp_sim = 0.0
            if use_temporal and 'EndDate' in data.columns:
                try:
                    t_i = pd.to_datetime(data.iloc[i]['EndDate'])
                    t_j = pd.to_datetime(data.iloc[j]['EndDate'])
                    diff_s = abs((t_i - t_j).total_seconds())
                    temp_sim = max(0, 1 - diff_s / 3600)
                except:
                    pass

            score = 0.6 * addr_sim + 0.3 * user_sim + 0.1 * temp_sim
            if score >= threshold:
                uf.union(i, j)

    clusters = [uf.find(i) for i in range(n)]
    # Renumber
    unique = list(set(clusters))
    mapping = {old: new for new, old in enumerate(unique)}
    return [mapping[c] for c in clusters]


def run_dbscan(feature_matrix, n_samples):
    from sklearn.neighbors import NearestNeighbors
    k = max(2, min(10, n_samples // 10))
    nn = NearestNeighbors(n_neighbors=k).fit(feature_matrix)
    distances, _ = nn.kneighbors(feature_matrix)
    k_distances = np.sort(distances[:, k - 1])
    if len(k_distances) > 3:
        second_deriv = np.diff(k_distances, 2)
        knee_idx = np.argmax(second_deriv) + 1
        eps = k_distances[knee_idx]
    else:
        eps = np.mean(k_distances)
    
    # Ensure eps is strictly positive
    eps = max(0.01, float(eps))
    
    min_samples = max(2, min(feature_matrix.shape[1] + 1, n_samples // 15))
    labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(feature_matrix)
    # Assign noise to unique clusters
    max_c = max(labels) if len(labels) > 0 else -1
    counter = max_c + 1
    for i in range(len(labels)):
        if labels[i] == -1:
            labels[i] = counter
            counter += 1
    return labels


def run_kmeans(feature_matrix, n_true_clusters):
    return KMeans(n_clusters=n_true_clusters, random_state=SEED, n_init=10).fit_predict(feature_matrix)


def run_hierarchical(feature_matrix, n_true_clusters):
    return AgglomerativeClustering(n_clusters=n_true_clusters, linkage='ward').fit_predict(feature_matrix)


def run_cosine_uf(feature_matrix, threshold=0.7):
    sim_matrix = cosine_similarity(feature_matrix)
    n = len(feature_matrix)
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if sim_matrix[i][j] >= threshold:
                uf.union(i, j)
    clusters = [uf.find(i) for i in range(n)]
    unique = list(set(clusters))
    mapping = {old: new for new, old in enumerate(unique)}
    return [mapping[c] for c in clusters]


def run_rule_based(data, addresses, usernames):
    clusters = {}
    current_cluster = 0
    signature_to_cluster = {}
    for idx in range(len(data)):
        row = data.iloc[idx]
        sig_parts = []
        for field in addresses + usernames:
            value = str(row[field])
            if value not in ['nan', 'NIL', 'UNKNOWN', '']:
                sig_parts.append(f"{field}:{value}")
        signature = "|".join(sorted(sig_parts))
        if signature in signature_to_cluster:
            clusters[idx] = signature_to_cluster[signature]
        else:
            clusters[idx] = current_cluster
            signature_to_cluster[signature] = current_cluster
            current_cluster += 1
    return [clusters[i] for i in range(len(data))]


def run_ip_subnet(data, addresses, usernames):
    clusters = {}
    current_cluster = 0
    sig_to_cluster = {}
    for idx in range(len(data)):
        row = data.iloc[idx]
        subnets = []
        for addr in addresses:
            ip = str(row[addr])
            parts = ip.split('.')
            if len(parts) >= 3:
                subnets.append('.'.join(parts[:3]))
        for user in usernames:
            val = str(row[user])
            if val not in ['nan', 'NIL', 'UNKNOWN', '']:
                subnets.append(f"u:{val}")
        sig = "|".join(sorted(set(subnets)))
        if sig in sig_to_cluster:
            clusters[idx] = sig_to_cluster[sig]
        else:
            clusters[idx] = current_cluster
            sig_to_cluster[sig] = current_cluster
            current_cluster += 1
    return [clusters[i] for i in range(len(data))]


def run_temporal(data, addresses, usernames, time_window_hours=24):
    if 'EndDate' not in data.columns:
        return list(range(len(data)))
    timestamps = pd.to_datetime(data['EndDate'], errors='coerce')
    sorted_indices = timestamps.argsort().values
    clusters = [-1] * len(data)
    current_cluster = 0
    for i, idx in enumerate(sorted_indices):
        if pd.isna(timestamps.iloc[idx]):
            clusters[idx] = current_cluster
            current_cluster += 1
            continue
        assigned = False
        current_time = timestamps.iloc[idx]
        for j in range(max(0, i - 50), i):  # Look back up to 50 events
            prev_idx = sorted_indices[j]
            prev_time = timestamps.iloc[prev_idx]
            if pd.isna(prev_time):
                continue
            time_diff = abs((current_time - prev_time).total_seconds() / 3600)
            if time_diff <= time_window_hours:
                row_curr = data.iloc[idx]
                row_prev = data.iloc[prev_idx]
                common = sum(
                    1 for f in addresses + usernames
                    if str(row_curr[f]) == str(row_prev[f])
                    and str(row_curr[f]) not in ['nan', 'NIL', 'UNKNOWN', '']
                )
                if common > 0:
                    clusters[idx] = clusters[prev_idx]
                    assigned = True
                    break
        if not assigned:
            clusters[idx] = current_cluster
            current_cluster += 1
    return clusters


# ============================================================
# METRICS
# ============================================================

def compute_all_metrics(y_true, y_pred):
    """Compute all clustering metrics."""
    return {
        'ARI': adjusted_rand_score(y_true, y_pred),
        'NMI': normalized_mutual_info_score(y_true, y_pred),
        'Homogeneity': homogeneity_score(y_true, y_pred),
        'Completeness': completeness_score(y_true, y_pred),
        'V-Measure': v_measure_score(y_true, y_pred),
        'FMI': fowlkes_mallows_score(y_true, y_pred),
        'Pred_Clusters': len(set(y_pred)),
    }


# ============================================================
# EXPERIMENT 1: ALL METHODS ON UNSW-NB15 (REAL DATA)
# ============================================================

def experiment1_all_methods_unsw_nb15(df_train, sample_sizes=[500, 1000, 2000]):
    """Run all correlation methods on real UNSW-NB15 data at multiple scales."""
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    all_results = {}

    for sample_size in sample_sizes:
        print(f"\n{'='*60}")
        print(f"EXPERIMENT 1: UNSW-NB15 Real Data (n={sample_size})")
        print(f"{'='*60}")

        mitre_df, ground_truth, class_names = prepare_unsw_nb15_for_correlation(df_train, sample_size)
        n = len(mitre_df)
        n_true = len(set(ground_truth))
        print(f"True clusters: {n_true}, Classes: {list(class_names[:5])}...")

        # Prepare feature matrix for sklearn methods
        feature_cols = addresses + usernames
        le_dict = {}
        encoded = []
        for col in feature_cols:
            le_dict[col] = LabelEncoder()
            encoded.append(le_dict[col].fit_transform(mitre_df[col].astype(str)))
        feature_matrix = StandardScaler().fit_transform(np.column_stack(encoded))

        results_for_size = {}

        # 1. MITRE-CORE Union-Find (only for smaller sizes due to O(n^2))
        if n <= 600:
            print("  Running MITRE-CORE Union-Find...")
            t0 = time.time()
            uf_pred = mitre_core_union_find(mitre_df, addresses, usernames)
            t1 = time.time()
            metrics = compute_all_metrics(ground_truth, uf_pred)
            metrics['Time_s'] = t1 - t0
            results_for_size['MITRE-CORE (Union-Find)'] = metrics
            print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.2f}s")
        else:
            print(f"  Skipping Union-Find for n={n} (O(n^2) too slow)")

        # 2. DBSCAN
        print("  Running DBSCAN...")
        t0 = time.time()
        dbscan_pred = run_dbscan(feature_matrix, n)
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, dbscan_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['DBSCAN'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 3. K-Means
        print("  Running K-Means...")
        t0 = time.time()
        km_pred = run_kmeans(feature_matrix, n_true)
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, km_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['K-Means'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 4. Hierarchical
        print("  Running Hierarchical...")
        t0 = time.time()
        hier_pred = run_hierarchical(feature_matrix, n_true)
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, hier_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['Hierarchical'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 5. Rule-Based
        print("  Running Rule-Based...")
        t0 = time.time()
        rule_pred = run_rule_based(mitre_df, addresses, usernames)
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, rule_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['Rule-Based'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 6. IP-Subnet
        print("  Running IP-Subnet...")
        t0 = time.time()
        ipsub_pred = run_ip_subnet(mitre_df, addresses, usernames)
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, ipsub_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['IP-Subnet'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 6.5 Hybrid Method (Union-Find + DBSCAN)
        print("  Running Hybrid (UF + DBSCAN)...")
        t0 = time.time()
        # Stage 1: Union-Find for high-precision micro-clusters
        uf_micro_pred = mitre_core_union_find(mitre_df, addresses, usernames, use_temporal=True, use_adaptive=True)
        # Stage 2: Feature matrix grouped by micro-clusters
        n_micro = len(set(uf_micro_pred))
        
        if n_micro > 1:
            micro_features = []
            for c in range(n_micro):
                indices = [i for i, x in enumerate(uf_micro_pred) if x == c]
                cluster_features = feature_matrix[indices].mean(axis=0)
                micro_features.append(cluster_features)
            
            micro_features = np.array(micro_features)
            # Run DBSCAN on micro-clusters
            from sklearn.neighbors import NearestNeighbors
            k = max(2, min(5, n_micro // 5))
            nn = NearestNeighbors(n_neighbors=k).fit(micro_features)
            distances, _ = nn.kneighbors(micro_features)
            k_distances = np.sort(distances[:, k - 1])
            if len(k_distances) > 3:
                second_deriv = np.diff(k_distances, 2)
                knee_idx = np.argmax(second_deriv) + 1
                eps = k_distances[knee_idx]
            else:
                eps = np.mean(k_distances)
            
            eps = max(0.01, float(eps))
            min_samples = max(2, min(micro_features.shape[1] + 1, n_micro // 10))
            
            dbscan = DBSCAN(eps=eps, min_samples=min_samples)
            macro_pred = dbscan.fit_predict(micro_features)
            
            # Map back to original points
            hybrid_pred = []
            for i in range(len(mitre_df)):
                micro_idx = uf_micro_pred[i]
                macro_idx = macro_pred[micro_idx]
                # If noise (-1), keep as micro-cluster
                hybrid_pred.append(macro_idx if macro_idx != -1 else micro_idx + 1000)
                
            # Renumber clusters sequentially
            unique_clusters = list(set(hybrid_pred))
            cluster_map = {old: new for new, old in enumerate(unique_clusters)}
            hybrid_pred = [cluster_map[c] for c in hybrid_pred]
        else:
            hybrid_pred = uf_micro_pred
            
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, hybrid_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['Hybrid (UF+DBSCAN)'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 7. Cosine-Similarity + Union-Find
        if n <= 600:
            print("  Running Cosine-Similarity...")
            t0 = time.time()
            cos_pred = run_cosine_uf(feature_matrix, threshold=0.7)
            t1 = time.time()
            metrics = compute_all_metrics(ground_truth, cos_pred)
            metrics['Time_s'] = t1 - t0
            results_for_size['Cosine-Similarity'] = metrics
            print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        # 8. Temporal
        print("  Running Temporal...")
        t0 = time.time()
        temp_pred = run_temporal(mitre_df, addresses, usernames)
        t1 = time.time()
        metrics = compute_all_metrics(ground_truth, temp_pred)
        metrics['Time_s'] = t1 - t0
        results_for_size['Temporal'] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} Time={metrics['Time_s']:.3f}s")

        all_results[f'unsw_nb15_n{len(mitre_df)}'] = results_for_size

    return all_results


# ============================================================
# EXPERIMENT 2: HGNN ON UNSW-NB15 (REAL DATA)
# ============================================================

def experiment2_hgnn_unsw_nb15():
    """Evaluate HGNN on real UNSW-NB15 data using trained checkpoint."""
    print(f"\n{'='*60}")
    print("EXPERIMENT 2: HGNN Evaluation on UNSW-NB15")
    print(f"{'='*60}")

    results = {}

    # Check for trained checkpoint
    checkpoint_paths = [
        PROJECT_ROOT / "hgnn_checkpoints" / "unsw_nb15_optuna_best.pt",
        PROJECT_ROOT / "hgnn_checkpoints" / "unsw_nb15_best.pt",
    ]

    checkpoint_path = None
    for cp in checkpoint_paths:
        if cp.exists():
            checkpoint_path = cp
            break

    if checkpoint_path is None:
        print("  No HGNN checkpoint found. Skipping HGNN evaluation.")
        print("  Train with: python training/train_enhanced_hgnn.py")
        return results

    print(f"  Using checkpoint: {checkpoint_path}")

    try:
        import torch
        from torch_geometric.data import HeteroData

        sys.path.insert(0, str(PROJECT_ROOT / "hgnn"))
        from hgnn_correlation import MITREHeteroGNN

        # Load checkpoint
        checkpoint = torch.load(checkpoint_path, map_location='cpu', weights_only=False)
        hyperparams = checkpoint.get('hyperparameters', {})
        num_clusters = checkpoint.get('num_clusters', 50)

        print(f"  Hyperparameters: {hyperparams}")
        print(f"  Num clusters: {num_clusters}")

        # Create model
        model = MITREHeteroGNN(
            alert_feature_dim=64,
            hidden_dim=hyperparams.get('hidden_dim', 64),
            num_heads=hyperparams.get('num_heads', 8),
            num_layers=hyperparams.get('num_layers', 1),
            dropout=hyperparams.get('dropout', 0.3),
            num_clusters=num_clusters
        )
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()

        # Load test data
        mitre_format = pd.read_csv(PROJECT_ROOT / "datasets" / "unsw_nb15" / "mitre_format.csv")

        # Filter attacks
        attack_df = mitre_format[mitre_format['alert_type'] == 'attack'].copy()
        attack_df['timestamp'] = pd.to_datetime(attack_df['timestamp'])

        # Use the same graph converter as training
        sys.path.insert(0, str(PROJECT_ROOT / "training"))
        from train_enhanced_hgnn import EnhancedPublicDatasetGraphConverter, EnhancedTrainer

        converter = EnhancedPublicDatasetGraphConverter()
        trainer = EnhancedTrainer()

        # Create test mini-campaigns
        from sklearn.model_selection import train_test_split
        _, test_df = train_test_split(attack_df, test_size=0.2, random_state=42)
        test_df = test_df.sort_values(['campaign_id', 'timestamp'])

        campaign_size = 30
        test_graphs = []
        test_labels = []

        for i in range(0, len(test_df), campaign_size):
            end_idx = min(i + campaign_size, len(test_df))
            mini_df = test_df.iloc[i:end_idx]
            if len(mini_df) < 5:
                continue
            graph = converter.convert_campaign(mini_df)
            if graph is not None and 'alert' in graph.node_types:
                test_graphs.append(graph)
                campaign_ids = mini_df['campaign_id'].values
                label = int(pd.Series(campaign_ids).mode().iloc[0]) % num_clusters
                test_labels.append(label)

        # Simplify to alert-only
        simplified = []
        for graph in test_graphs:
            if 'alert' not in graph.node_types:
                continue
            num_alerts = graph['alert'].x.shape[0]
            new_graph = HeteroData()
            new_graph['alert'].x = graph['alert'].x
            has_edges = False
            for edge_type in graph.edge_types:
                src, rel, dst = edge_type
                if src == 'alert' and dst == 'alert':
                    edge_index = graph[edge_type].edge_index
                    if edge_index.numel() > 0 and edge_index.max() < num_alerts:
                        new_graph[edge_type].edge_index = edge_index
                        has_edges = True
            if not has_edges:
                self_loops = torch.arange(num_alerts, dtype=torch.long).unsqueeze(0).repeat(2, 1)
                new_graph[('alert', 'self_loop', 'alert')].edge_index = self_loops
            simplified.append(new_graph)

        test_graphs = simplified

        # Evaluate
        correct = 0
        total = 0
        predictions = []
        true_labels = []

        with torch.no_grad():
            for graph, label in zip(test_graphs, test_labels[:len(test_graphs)]):
                if 'alert' not in graph.node_types:
                    continue
                logits, _ = model(graph)
                preds = torch.argmax(logits, dim=1)
                pred_label = torch.mode(preds).values.item()
                if pred_label == label:
                    correct += 1
                total += 1
                predictions.append(pred_label)
                true_labels.append(label)

        accuracy = correct / max(total, 1)
        print(f"  HGNN Test Accuracy: {accuracy:.4f} ({correct}/{total})")

        # Clustering metrics on predictions
        if len(true_labels) > 1:
            hgnn_metrics = compute_all_metrics(true_labels, predictions)
            hgnn_metrics['Accuracy'] = accuracy
            hgnn_metrics['Correct'] = correct
            hgnn_metrics['Total'] = total
            hgnn_metrics['Time_s'] = 0  # Already trained
            results['HGNN_UNSW_NB15'] = hgnn_metrics

            for k, v in hgnn_metrics.items():
                if isinstance(v, float):
                    print(f"    {k}: {v:.4f}")
                else:
                    print(f"    {k}: {v}")

    except Exception as e:
        print(f"  HGNN evaluation error: {e}")
        import traceback
        traceback.print_exc()

    return results


# ============================================================
# EXPERIMENT 3: SCALABILITY BENCHMARK
# ============================================================

def experiment3_scalability(df_train):
    """Scalability benchmark on real UNSW-NB15 data."""
    print(f"\n{'='*60}")
    print("EXPERIMENT 3: Scalability Benchmark (UNSW-NB15)")
    print(f"{'='*60}")

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']

    sizes = [50, 100, 200, 300, 500]
    results = []

    for target_size in sizes:
        mitre_df, gt, _ = prepare_unsw_nb15_for_correlation(df_train, target_size)
        n = len(mitre_df)

        # Union-Find timing
        t0 = time.time()
        uf_pred = mitre_core_union_find(mitre_df, addresses, usernames)
        uf_time = time.time() - t0

        # Feature matrix for sklearn methods
        feature_cols = addresses + usernames
        encoded = []
        for col in feature_cols:
            encoded.append(LabelEncoder().fit_transform(mitre_df[col].astype(str)))
        feature_matrix = StandardScaler().fit_transform(np.column_stack(encoded))

        # K-Means timing
        n_true = len(set(gt))
        t0 = time.time()
        km_pred = run_kmeans(feature_matrix, n_true)
        km_time = time.time() - t0

        # Hierarchical timing
        t0 = time.time()
        hier_pred = run_hierarchical(feature_matrix, n_true)
        hier_time = time.time() - t0

        # DBSCAN timing
        t0 = time.time()
        db_pred = run_dbscan(feature_matrix, n)
        db_time = time.time() - t0

        row = {
            'Target_Size': target_size,
            'Actual_Size': n,
            'True_Clusters': n_true,
            'UF_Time': uf_time,
            'KMeans_Time': km_time,
            'Hierarchical_Time': hier_time,
            'DBSCAN_Time': db_time,
            'UF_ARI': adjusted_rand_score(gt, uf_pred),
            'KMeans_ARI': adjusted_rand_score(gt, km_pred),
            'Hier_ARI': adjusted_rand_score(gt, hier_pred),
            'DBSCAN_ARI': adjusted_rand_score(gt, db_pred),
        }
        results.append(row)
        print(f"  n={n:4d} | UF={uf_time:7.2f}s KM={km_time:.3f}s HC={hier_time:.3f}s DB={db_time:.3f}s")

    return results


# ============================================================
# EXPERIMENT 4: ABLATION STUDY ON REAL DATA
# ============================================================

def experiment4_ablation(df_train, sample_size=500):
    """Ablation study: effect of each Union-Find component on real data."""
    print(f"\n{'='*60}")
    print("EXPERIMENT 4: Ablation Study (UNSW-NB15)")
    print(f"{'='*60}")

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']

    mitre_df, gt, _ = prepare_unsw_nb15_for_correlation(df_train, sample_size)

    configs = [
        ("Full System (adaptive + temporal)", True, True),
        ("No Adaptive Threshold (fixed 0.3)", False, True),
        ("No Temporal Features", True, False),
        ("No Temporal + No Adaptive", False, False),
    ]

    results = {}
    for name, use_adaptive, use_temporal in configs:
        print(f"  Running: {name}...")
        t0 = time.time()
        pred = mitre_core_union_find(mitre_df, addresses, usernames,
                                      use_temporal=use_temporal, use_adaptive=use_adaptive)
        t1 = time.time()
        metrics = compute_all_metrics(gt, pred)
        metrics['Time_s'] = t1 - t0
        results[name] = metrics
        print(f"    ARI={metrics['ARI']:.4f} NMI={metrics['NMI']:.4f} V={metrics['V-Measure']:.4f}")

    return results


# ============================================================
# EXPERIMENT 5: STATISTICAL SIGNIFICANCE
# ============================================================

def experiment5_statistical_tests(df_train, n_runs=5, sample_size=300):
    """Run multiple trials for statistical significance testing."""
    print(f"\n{'='*60}")
    print(f"EXPERIMENT 5: Statistical Significance ({n_runs} runs)")
    print(f"{'='*60}")

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']

    method_aris = defaultdict(list)

    for run in range(n_runs):
        seed = SEED + run
        np.random.seed(seed)
        random.seed(seed)

        mitre_df, gt, _ = prepare_unsw_nb15_for_correlation(df_train, sample_size)
        n = len(mitre_df)
        n_true = len(set(gt))

        # Union-Find
        uf_pred = mitre_core_union_find(mitre_df, addresses, usernames)
        method_aris['Union-Find'].append(adjusted_rand_score(gt, uf_pred))

        # Feature matrix
        feature_cols = addresses + usernames
        encoded = []
        for col in feature_cols:
            encoded.append(LabelEncoder().fit_transform(mitre_df[col].astype(str)))
        feature_matrix = StandardScaler().fit_transform(np.column_stack(encoded))

        # K-Means
        km_pred = run_kmeans(feature_matrix, n_true)
        method_aris['K-Means'].append(adjusted_rand_score(gt, km_pred))

        # Hierarchical
        hier_pred = run_hierarchical(feature_matrix, n_true)
        method_aris['Hierarchical'].append(adjusted_rand_score(gt, hier_pred))

        # DBSCAN
        db_pred = run_dbscan(feature_matrix, n)
        method_aris['DBSCAN'].append(adjusted_rand_score(gt, db_pred))

        # Rule-Based
        rule_pred = run_rule_based(mitre_df, addresses, usernames)
        method_aris['Rule-Based'].append(adjusted_rand_score(gt, rule_pred))

        # Temporal
        temp_pred = run_temporal(mitre_df, addresses, usernames)
        method_aris['Temporal'].append(adjusted_rand_score(gt, temp_pred))

        print(f"  Run {run+1}: UF={method_aris['Union-Find'][-1]:.4f} "
              f"KM={method_aris['K-Means'][-1]:.4f} "
              f"HC={method_aris['Hierarchical'][-1]:.4f}")

    # Statistical tests
    stat_results = {}
    for method_name, aris in method_aris.items():
        stat_results[method_name] = {
            'mean_ARI': np.mean(aris),
            'std_ARI': np.std(aris),
            'min_ARI': np.min(aris),
            'max_ARI': np.max(aris),
            'runs': aris
        }

    # Pairwise t-tests vs Union-Find
    uf_aris = method_aris['Union-Find']
    for method_name, aris in method_aris.items():
        if method_name != 'Union-Find' and len(aris) == len(uf_aris):
            try:
                t_stat, p_val = ttest_rel(uf_aris, aris)
                stat_results[f'UF_vs_{method_name}'] = {
                    't_statistic': t_stat,
                    'p_value': p_val,
                    'significant': p_val < 0.05
                }
                print(f"  UF vs {method_name}: t={t_stat:.3f}, p={p_val:.4f}, sig={p_val < 0.05}")
            except:
                pass

    return stat_results


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("MITRE-CORE: COMPREHENSIVE EXPERIMENTS ON REAL PUBLIC DATA")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("Dataset: UNSW-NB15")
    print("=" * 70)

    base_path = PROJECT_ROOT / "datasets"

    # Load real data
    df_train, df_test = load_unsw_nb15_real(base_path)

    # Output directory
    output_dir = PROJECT_ROOT / "experiments" / "real_data_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = {}

    # Experiment 1: All methods comparison
    exp1 = experiment1_all_methods_unsw_nb15(df_train, sample_sizes=[500, 1000, 2000])
    all_results['experiment1_all_methods'] = exp1

    # Experiment 2: HGNN evaluation
    exp2 = experiment2_hgnn_unsw_nb15()
    all_results['experiment2_hgnn'] = exp2

    # Experiment 3: Scalability
    exp3 = experiment3_scalability(df_train)
    all_results['experiment3_scalability'] = exp3

    # Experiment 4: Ablation
    exp4 = experiment4_ablation(df_train, sample_size=500)
    all_results['experiment4_ablation'] = exp4

    # Experiment 5: Statistical significance
    exp5 = experiment5_statistical_tests(df_train, n_runs=5, sample_size=300)
    all_results['experiment5_statistical'] = exp5

    # Save results
    def convert_numpy(obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {k: convert_numpy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_numpy(i) for i in obj]
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return obj

    results_file = output_dir / "real_data_experiment_results.json"
    with open(results_file, 'w') as f:
        json.dump(convert_numpy(all_results), f, indent=2)
    print(f"\nResults saved to: {results_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("EXPERIMENT SUMMARY")
    print("=" * 70)

    for exp_name, exp_results in exp1.items():
        print(f"\n--- {exp_name} ---")
        for method, metrics in sorted(exp_results.items(), key=lambda x: -x[1].get('ARI', 0)):
            print(f"  {method:30s} ARI={metrics['ARI']:.4f}  NMI={metrics['NMI']:.4f}  "
                  f"V={metrics['V-Measure']:.4f}  FMI={metrics['FMI']:.4f}  "
                  f"Clusters={metrics['Pred_Clusters']}  Time={metrics['Time_s']:.3f}s")

    print("\nDone!")


if __name__ == "__main__":
    main()
