"""
MITRE-CORE HGNN Integration Module
Drop-in replacement for correlation_indexer.py

This module provides backward-compatible interfaces while using HGNN internally.
Can be used as:
  1. Direct replacement in existing pipeline
  2. Hybrid approach (HGNN + Union-Find ensemble)
  3. Gradual migration path

Usage:
    # Option 1: Replace existing correlation
    from hgnn_integration import enhanced_correlation_hgnn
    result_df = enhanced_correlation_hgnn(df, usernames, addresses)
    
    # Option 2: Hybrid ensemble
    from hgnn_integration import HybridCorrelationEngine
    engine = HybridCorrelationEngine(hgnn_weight=0.7, union_find_weight=0.3)
    result_df = engine.correlate(df, usernames, addresses)
"""

import pandas as pd
import numpy as np
import torch
from typing import List, Dict, Tuple, Optional
import logging
from pathlib import Path

# Import existing Union-Find for fallback/comparison
from core.correlation_indexer import enhanced_correlation as union_find_correlation
from hgnn.hgnn_correlation import HGNNCorrelationEngine, AlertToGraphConverter

logger = logging.getLogger("mitre-core.hgnn_integration")


def enhanced_correlation_hgnn(
    data: pd.DataFrame,
    usernames: List[str],
    addresses: List[str],
    model_path: Optional[str] = None,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
    confidence_threshold: float = 0.5,
    fallback_to_union_find: bool = True
) -> pd.DataFrame:
    """
    Drop-in replacement for correlation_indexer.enhanced_correlation()
    Uses HGNN instead of Union-Find for clustering.
    
    Args:
        data: DataFrame with security events
        usernames: List of username column names
        addresses: List of address column names
        model_path: Path to trained HGNN model (if None, uses random init)
        device: 'cuda' or 'cpu'
        confidence_threshold: Minimum confidence for HGNN cluster assignment
        fallback_to_union_find: If True, falls back to Union-Find on HGNN failure
        
    Returns:
        DataFrame with 'pred_cluster' column (HGNN cluster assignments)
    """
    try:
        logger.info(f"Attempting HGNN correlation on {len(data)} events...")
        
        # Initialize HGNN engine
        engine = HGNNCorrelationEngine(
            model_path=model_path,
            device=device
        )
        
        # Run HGNN correlation
        result_df = engine.correlate(data)
        
        # Filter low-confidence predictions (optional)
        low_conf_mask = result_df['cluster_confidence'] < confidence_threshold
        if low_conf_mask.sum() > 0:
            logger.warning(
                f"{low_conf_mask.sum()} alerts have low confidence (<{confidence_threshold}). "
                "Consider manual review or using Union-Find fallback."
            )
        
        # Add metadata columns for comparison
        result_df['correlation_method'] = 'HGNN'
        
        logger.info(f"HGNN correlation successful: {result_df['pred_cluster'].nunique()} clusters")
        
        return result_df
        
    except Exception as e:
        logger.error(f"HGNN correlation failed: {e}")
        
        if fallback_to_union_find:
            logger.info("Falling back to Union-Find correlation...")
            result_df = union_find_correlation(data, usernames, addresses)
            result_df['correlation_method'] = 'Union-Find (fallback)'
            result_df['cluster_confidence'] = 1.0  # Union-Find has binary decisions
            return result_df
        else:
            raise


class HybridCorrelationEngine:
    """
    Ensemble approach combining HGNN and Union-Find.
    
    Benefits:
    - HGNN: Learns complex patterns, handles transitivity
    - Union-Find: Fast, deterministic, proven baseline
    - Ensemble: More robust than either alone
    """
    
    def __init__(
        self,
        hgnn_weight: float = 0.7,
        union_find_weight: float = 0.3,
        model_path: Optional[str] = None,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        consensus_threshold: float = 0.6
    ):
        """
        Args:
            hgnn_weight: Weight for HGNN cluster assignments (0-1)
            union_find_weight: Weight for Union-Find cluster assignments (0-1)
            model_path: Trained HGNN model path
            device: Computation device
            consensus_threshold: Agreement threshold for ensemble decision
        """
        assert abs(hgnn_weight + union_find_weight - 1.0) < 1e-6, \
            "Weights must sum to 1.0"
        
        self.hgnn_weight = hgnn_weight
        self.uf_weight = union_find_weight
        self.consensus_threshold = consensus_threshold
        
        # Initialize both engines
        self.hgnn_engine = HGNNCorrelationEngine(model_path=model_path, device=device)
        
        logger.info(
            f"HybridEngine initialized: HGNN({hgnn_weight:.2f}) + "
            f"Union-Find({union_find_weight:.2f})"
        )
    
    def correlate(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str]
    ) -> pd.DataFrame:
        """
        Ensemble correlation using both HGNN and Union-Find.
        
        Strategy:
        1. Get cluster assignments from both methods
        2. Calculate agreement score for each alert pair
        3. If high agreement: use consensus
        4. If low agreement: use weighted combination or flag for review
        """
        logger.info("Running hybrid correlation...")
        
        # Get HGNN predictions
        hgnn_result = self.hgnn_engine.correlate(data.copy())
        hgnn_clusters = hgnn_result['pred_cluster'].values
        
        # Get Union-Find predictions
        uf_result = union_find_correlation(data.copy(), usernames, addresses)
        uf_clusters = uf_result['pred_cluster'].values
        
        # Calculate ensemble clusters
        ensemble_clusters = self._ensemble_clustering(
            hgnn_clusters, 
            uf_clusters,
            data
        )
        
        # Create result DataFrame
        result_df = data.copy()
        result_df['pred_cluster'] = ensemble_clusters
        result_df['hgnn_cluster'] = hgnn_clusters
        result_df['union_find_cluster'] = uf_clusters
        result_df['cluster_agreement'] = (hgnn_clusters == uf_clusters).astype(float)
        result_df['correlation_method'] = 'Hybrid'
        
        # Calculate consensus confidence
        confidences = []
        for i in range(len(data)):
            if result_df['cluster_agreement'].iloc[i]:
                # High confidence when both agree
                confidences.append(1.0)
            else:
                # Lower confidence when they disagree
                # Use HGNN confidence if available
                if 'cluster_confidence' in hgnn_result.columns:
                    confidences.append(
                        self.hgnn_weight * hgnn_result['cluster_confidence'].iloc[i] +
                        self.uf_weight * 0.8  # Union-Find has no confidence, assume 0.8
                    )
                else:
                    confidences.append(0.5)  # Uncertain
        
        result_df['cluster_confidence'] = confidences
        
        # Log statistics
        num_clusters = len(np.unique(ensemble_clusters))
        agreement_rate = result_df['cluster_agreement'].mean()
        
        logger.info(
            f"Hybrid results: {num_clusters} clusters, "
            f"{agreement_rate:.1%} agreement between methods"
        )
        
        return result_df
    
    def _ensemble_clustering(
        self,
        hgnn_clusters: np.ndarray,
        uf_clusters: np.ndarray,
        data: pd.DataFrame
    ) -> np.ndarray:
        """
        Combine HGNN and Union-Find cluster assignments.
        
        Uses consensus clustering: if both methods agree on pairwise relationships,
        use that relationship. If they disagree, use weighted voting.
        """
        n = len(hgnn_clusters)
        
        # Build consensus similarity matrix
        consensus_sim = np.zeros((n, n))
        
        for i in range(n):
            for j in range(i+1, n):
                # HGNN agreement (0 or 1)
                hgnn_agree = float(hgnn_clusters[i] == hgnn_clusters[j])
                
                # Union-Find agreement (0 or 1)
                uf_agree = float(uf_clusters[i] == uf_clusters[j])
                
                # Weighted consensus
                consensus = (
                    self.hgnn_weight * hgnn_agree +
                    self.uf_weight * uf_agree
                )
                
                consensus_sim[i, j] = consensus
                consensus_sim[j, i] = consensus
        
        # Apply threshold to get binary adjacency
        adjacency = (consensus_sim >= self.consensus_threshold).astype(int)
        
        # Run connected components (Union-Find) on consensus graph
        parent = list(range(n))
        
        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
        
        def union(x, y):
            root_x, root_y = find(x), find(y)
            if root_x != root_y:
                parent[root_x] = root_y
        
        # Union all pairs with high consensus
        for i in range(n):
            for j in range(i+1, n):
                if adjacency[i, j]:
                    union(i, j)
        
        # Assign final cluster labels
        ensemble_clusters = np.array([find(i) for i in range(n)])
        
        # Relabel to consecutive integers
        unique_labels = np.unique(ensemble_clusters)
        label_map = {old: new for new, old in enumerate(unique_labels)}
        ensemble_clusters = np.array([label_map[x] for x in ensemble_clusters])
        
        return ensemble_clusters


class HGNNBenchmark:
    """
    Benchmarking tool to compare HGNN vs Union-Find performance.
    Generates comparison reports with ARI, NMI, speed, and accuracy metrics.
    """
    
    def __init__(self, output_dir: str = './hgnn_benchmarks'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = []
    
    def compare_on_dataset(
        self,
        data: pd.DataFrame,
        ground_truth_labels: np.ndarray,
        usernames: List[str],
        addresses: List[str],
        model_path: Optional[str] = None
    ) -> Dict:
        """
        Compare HGNN vs Union-Find on labeled dataset.
        
        Returns metrics: ARI, NMI, purity, processing time, memory usage
        """
        import time
        from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
        
        results = {
            'dataset_size': len(data),
            'num_ground_truth_clusters': len(np.unique(ground_truth_labels))
        }
        
        # Test Union-Find
        logger.info("Benchmarking Union-Find...")
        start = time.time()
        uf_result = union_find_correlation(data.copy(), usernames, addresses)
        uf_time = time.time() - start
        
        uf_pred = uf_result['pred_cluster'].values
        results['union_find'] = {
            'time_seconds': uf_time,
            'ari': adjusted_rand_score(ground_truth_labels, uf_pred),
            'nmi': normalized_mutual_info_score(ground_truth_labels, uf_pred),
            'num_clusters': len(np.unique(uf_pred))
        }
        
        # Test HGNN
        logger.info("Benchmarking HGNN...")
        try:
            start = time.time()
            hgnn_engine = HGNNCorrelationEngine(model_path=model_path)
            hgnn_result = hgnn_engine.correlate(data.copy())
            hgnn_time = time.time() - start
            
            hgnn_pred = hgnn_result['pred_cluster'].values
            results['hgnn'] = {
                'time_seconds': hgnn_time,
                'ari': adjusted_rand_score(ground_truth_labels, hgnn_pred),
                'nmi': normalized_mutual_info_score(ground_truth_labels, hgnn_pred),
                'num_clusters': len(np.unique(hgnn_pred)),
                'avg_confidence': float(hgnn_result['cluster_confidence'].mean())
            }
            
            # Speedup/slowdown
            time_ratio = hgnn_time / uf_time
            results['speed_comparison'] = {
                'hgnn_vs_union_find_ratio': time_ratio,
                'winner': 'HGNN' if time_ratio < 1.0 else 'Union-Find'
            }
            
            # Accuracy winner
            ari_improvement = results['hgnn']['ari'] - results['union_find']['ari']
            nmi_improvement = results['hgnn']['nmi'] - results['union_find']['nmi']
            results['accuracy_comparison'] = {
                'ari_improvement': ari_improvement,
                'nmi_improvement': nmi_improvement,
                'winner': 'HGNN' if ari_improvement > 0 else 'Union-Find'
            }
            
        except Exception as e:
            logger.error(f"HGNN benchmarking failed: {e}")
            results['hgnn'] = {'error': str(e)}
        
        self.results.append(results)
        return results
    
    def generate_report(self, save_path: Optional[str] = None) -> str:
        """Generate formatted benchmark report."""
        report_lines = [
            "MITRE-CORE HGNN Benchmark Report",
            "=" * 60,
            ""
        ]
        
        for i, result in enumerate(self.results):
            report_lines.extend([
                f"Dataset {i+1}: {result['dataset_size']} alerts",
                f"Ground Truth Clusters: {result['num_ground_truth_clusters']}",
                "",
                "Union-Find Performance:",
                f"  - Time: {result['union_find']['time_seconds']:.3f}s",
                f"  - ARI: {result['union_find']['ari']:.4f}",
                f"  - NMI: {result['union_find']['nmi']:.4f}",
                f"  - Clusters: {result['union_find']['num_clusters']}",
                "",
            ])
            
            if 'hgnn' in result and 'error' not in result['hgnn']:
                report_lines.extend([
                    "HGNN Performance:",
                    f"  - Time: {result['hgnn']['time_seconds']:.3f}s",
                    f"  - ARI: {result['hgnn']['ari']:.4f}",
                    f"  - NMI: {result['hgnn']['nmi']:.4f}",
                    f"  - Clusters: {result['hgnn']['num_clusters']}",
                    f"  - Avg Confidence: {result['hgnn']['avg_confidence']:.3f}",
                    "",
                    "Comparison:",
                    f"  - Speed: {result['speed_comparison']['winner']} is faster",
                    f"  - ARI Improvement: {result['accuracy_comparison']['ari_improvement']:+.4f}",
                    f"  - NMI Improvement: {result['accuracy_comparison']['nmi_improvement']:+.4f}",
                    f"  - Accuracy Winner: {result['accuracy_comparison']['winner']}",
                ])
            
            report_lines.append("-" * 60)
            report_lines.append("")
        
        report = "\n".join(report_lines)
        
        if save_path:
            with open(save_path, 'w') as f:
                f.write(report)
            logger.info(f"Benchmark report saved to {save_path}")
        
        return report


def migrate_to_hgnn(
    data_path: str,
    model_output_path: str = './hgnn_models/mitre_hgnn.pt',
    training_config: Optional[Dict] = None
):
    """
    Migration helper: Train HGNN on existing MITRE-CORE data and save model.
    
    Usage:
        migrate_to_hgnn(
            data_path='Data/Cleaned/correlated_alerts.csv',
            model_output_path='./hgnn_models/production_model.pt'
        )
    """
    from hgnn_training import train_hgnn_model, create_synthetic_training_data
    
    logger.info("Starting MITRE-CORE → HGNN migration...")
    
    # Load existing data
    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df)} alerts from {data_path}")
    
    # For migration, we use existing cluster labels as ground truth
    if 'pred_cluster' in df.columns:
        # Use existing Union-Find clusters as training labels
        labels = df['pred_cluster'].values
        logger.info(f"Using {len(np.unique(labels))} existing clusters as ground truth")
        
        # Split into training datasets (one per cluster)
        train_dfs = []
        train_labels = []
        
        for cluster_id in np.unique(labels):
            cluster_df = df[df['pred_cluster'] == cluster_id].copy()
            if len(cluster_df) >= 3:  # Minimum size for meaningful training
                train_dfs.append(cluster_df)
                train_labels.append(np.full(len(cluster_df), cluster_id))
        
        logger.info(f"Created {len(train_dfs)} training datasets from clusters")
    else:
        # No labels available, generate synthetic data
        logger.info("No cluster labels found. Generating synthetic training data...")
        train_dfs, train_labels = create_synthetic_training_data(
            num_campaigns=100,
            min_alerts_per_campaign=5,
            max_alerts_per_campaign=20
        )
    
    # Default training config
    default_config = {
        'hidden_dim': 128,
        'num_heads': 4,
        'num_layers': 2,
        'contrastive_epochs': 50,
        'supervised_epochs': 30
    }
    
    if training_config:
        default_config.update(training_config)
    
    # Train model
    logger.info("Training HGNN model...")
    model = train_hgnn_model(
        unlabeled_data=train_dfs[:int(0.7 * len(train_dfs))],
        labeled_data=(
            train_dfs[int(0.7 * len(train_dfs)):],
            train_labels[int(0.7 * len(train_labels)):]
        ),
        **default_config,
        output_dir=str(Path(model_output_path).parent)
    )
    
    # Save final model
    torch.save(model.state_dict(), model_output_path)
    logger.info(f"Migration complete! Model saved to {model_output_path}")
    
    return model


# ============================================================================
# Backward-Compatible API (matches correlation_indexer.py interface)
# ============================================================================

def enhanced_correlation(
    data: pd.DataFrame,
    usernames: List[str],
    addresses: List[str],
    use_hgnn: bool = True,
    hgnn_model_path: Optional[str] = None,
    **kwargs
) -> pd.DataFrame:
    """
    Backward-compatible wrapper that can use either HGNN or Union-Find.
    
    This function signature matches the original correlation_indexer.enhanced_correlation()
    so it can be used as a drop-in replacement.
    
    Args:
        data: DataFrame with security events
        usernames: List of username column names
        addresses: List of address column names
        use_hgnn: If True, use HGNN. If False, use original Union-Find.
        hgnn_model_path: Path to trained HGNN model
        **kwargs: Additional arguments passed to underlying implementation
        
    Returns:
        DataFrame with 'pred_cluster' column
    """
    if use_hgnn:
        return enhanced_correlation_hgnn(
            data, usernames, addresses,
            model_path=hgnn_model_path,
            **kwargs
        )
    else:
        # Use original Union-Find
        return union_find_correlation(data, usernames, addresses, **kwargs)


if __name__ == "__main__":
    print("MITRE-CORE HGNN Integration Module")
    print("=" * 50)
    print()
    print("Quick Start:")
    print("  1. Train HGNN: python hgnn_training.py")
    print("  2. Use in pipeline:")
    print("     from hgnn_integration import enhanced_correlation_hgnn")
    print("     result = enhanced_correlation_hgnn(df, usernames, addresses)")
    print()
    print("Migration:")
    print("  migrate_to_hgnn('Data/Cleaned/alerts.csv', 'hgnn_models/model.pt')")
    print()
    print("Benchmarking:")
    print("  bench = HGNNBenchmark()")
    print("  bench.compare_on_dataset(df, ground_truth, usernames, addresses)")
    print("  print(bench.generate_report())")
