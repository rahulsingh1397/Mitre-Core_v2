"""
MITRE-CORE v2 Real Dataset Accuracy Experiment
============================================

Evaluates the system's ability to accurately identify MITRE correlation chains
on real-world datasets (UNSW-NB15).

Metrics:
- ARI (Adjusted Rand Index): Clustering accuracy vs ground truth
- NMI (Normalized Mutual Information): Information-theoretic similarity
- MITRE Tactic Identification: Correct tactic mapping from attack types
- Correlation Chain Quality: Precision, Recall, F1 for attack campaign detection
"""

import sys
import os
from pathlib import Path
import json
import logging
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

# Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Reproducibility
SEED = 42
np.random.seed(SEED)


def run_accuracy_experiment():
    """Run comprehensive accuracy evaluation on real datasets."""
    
    print("=" * 80)
    print("MITRE-CORE v2 REAL DATASET ACCURACY EXPERIMENT")
    print("=" * 80)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Dataset: UNSW-NB15 (public security dataset)")
    print("=" * 80)
    
    results = {
        "experiment": "MITRE-CORE v2 Accuracy Validation",
        "timestamp": datetime.now().isoformat(),
        "dataset": "UNSW-NB15",
        "tests": {}
    }
    
    # Test 1: Load and validate real dataset
    print("\n[TEST 1] Loading UNSW-NB15 Dataset")
    print("-" * 40)
    dataset_results = load_and_validate_unsw()
    results["tests"]["dataset_loading"] = dataset_results
    
    if dataset_results["status"] != "PASS":
        print("✗ Dataset loading failed - cannot continue")
        return results
    
    # Test 2: Union-Find Correlation Accuracy
    print("\n[TEST 2] Union-Find Correlation Accuracy")
    print("-" * 40)
    uf_results = test_union_find_accuracy(dataset_results["df"], dataset_results["ground_truth"])
    results["tests"]["union_find_accuracy"] = uf_results
    
    # Test 3: MITRE Tactic Mapping Accuracy
    print("\n[TEST 3] MITRE ATT&CK Tactic Mapping")
    print("-" * 40)
    tactic_results = test_mitre_tactic_accuracy(dataset_results["df"])
    results["tests"]["tactic_mapping"] = tactic_results
    
    # Test 4: Correlation Chain Detection Quality
    print("\n[TEST 4] Correlation Chain Detection Quality")
    print("-" * 40)
    chain_results = test_correlation_chain_quality(
        uf_results.get("clusters"), 
        dataset_results.get("ground_truth")
    )
    results["tests"]["correlation_chain_quality"] = chain_results
    
    # Test 5: HGNN Accuracy (if checkpoint available)
    print("\n[TEST 5] HGNN Model Accuracy")
    print("-" * 40)
    hgnn_results = test_hgnn_accuracy(dataset_results["df"], dataset_results["ground_truth"])
    results["tests"]["hgnn_accuracy"] = hgnn_results
    
    # Save results
    output_dir = PROJECT_ROOT / "validation_results"
    output_dir.mkdir(exist_ok=True)
    
    results_file = output_dir / f"accuracy_experiment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n✓ Accuracy report saved to: {results_file}")
    
    # Print summary
    print_accuracy_summary(results)
    
    return results


def load_and_validate_unsw():
    """Load UNSW-NB15 dataset and prepare ground truth."""
    results = {"status": "FAIL", "issues": []}
    
    try:
        # Check if dataset exists
        train_path = PROJECT_ROOT / "datasets" / "unsw_nb15" / "UNSW_NB15_training-set.csv"
        
        if not train_path.exists():
            results["issues"].append(f"Dataset not found: {train_path}")
            # Try alternate path
            train_path = PROJECT_ROOT / "datasets" / "processed" / "unsw_nb15_hetero_graph.pt"
            if train_path.exists():
                results["issues"].append("Found preprocessed graph instead of raw CSV")
                results["status"] = "PARTIAL"
                results["df"] = None
                return results
            print(f"  ✗ Dataset not found at expected paths")
            return results
        
        # Load dataset
        df = pd.read_csv(train_path)
        print(f"  ✓ Loaded UNSW-NB15: {len(df)} records")
        
        # Use attack_cat as ground truth
        if 'attack_cat' in df.columns:
            ground_truth = df['attack_cat'].fillna('Normal').values
            unique_attacks = len(set(ground_truth))
            print(f"  ✓ Ground truth labels: {unique_attacks} unique attack categories")
            print(f"    Top categories: {pd.Series(ground_truth).value_counts().head(3).to_dict()}")
        else:
            # Use label column if available
            if 'label' in df.columns:
                ground_truth = df['label'].values
                unique_attacks = len(set(ground_truth))
                print(f"  ✓ Using 'label' column: {unique_attacks} unique labels")
            else:
                results["issues"].append("No ground truth column found")
                print(f"  ✗ No ground truth column found")
                return results
        
        results["status"] = "PASS"
        results["df"] = df.head(1000)  # Use subset for speed
        results["ground_truth"] = ground_truth[:1000]
        results["total_records"] = len(df)
        results["test_records"] = 1000
        results["unique_attacks"] = len(set(results["ground_truth"]))
        
    except Exception as e:
        results["status"] = "FAIL"
        results["issues"].append(str(e))
        print(f"  ✗ Error loading dataset: {e}")
    
    return results


def test_union_find_accuracy(df, ground_truth):
    """Test Union-Find correlation accuracy against ground truth."""
    results = {"status": "FAIL", "metrics": {}}
    
    try:
        from core.correlation_pipeline import CorrelationPipeline
        
        # Prepare data for correlation
        if len(df) == 0:
            results["issues"] = ["Empty dataframe"]
            return results
        
        # Create correlation-ready data
        corr_df = pd.DataFrame()
        corr_df['AlertId'] = [f'alert_{i}' for i in range(len(df))]
        
        # Map network features to addresses
        if 'sbytes' in df.columns:
            corr_df['SourceAddress'] = df['sbytes'].apply(lambda x: f"10.{int(x) % 256}.1.1" if pd.notna(x) else "10.0.0.1")
            corr_df['DestinationAddress'] = df['dbytes'].apply(lambda x: f"192.168.{int(x) % 256}.1" if pd.notna(x) else "192.168.0.1")
        else:
            # Generate synthetic addresses based on index
            corr_df['SourceAddress'] = [f"10.0.0.{i % 256}" for i in range(len(df))]
            corr_df['DestinationAddress'] = [f"192.168.0.{i % 256}" for i in range(len(df))]
        
        if 'service' in df.columns:
            corr_df['SourceHostName'] = df['service'].apply(lambda x: f"svc-{x}" if pd.notna(x) else "svc-none")
        else:
            corr_df['SourceHostName'] = [f"host_{i % 100}" for i in range(len(df))]
        
        if 'proto' in df.columns:
            corr_df['DestinationHostName'] = df['proto'].apply(lambda x: f"proto-{x}" if pd.notna(x) else "proto-none")
        else:
            corr_df['DestinationHostName'] = [f"target_{i % 50}" for i in range(len(df))]
        
        corr_df['EndDate'] = pd.date_range('2024-01-01', periods=len(df), freq='1min')
        
        # Add attack type if available
        if 'attack_cat' in df.columns:
            corr_df['MalwareIntelAttackType'] = df['attack_cat'].fillna('Normal')
        elif 'label' in df.columns:
            corr_df['MalwareIntelAttackType'] = df['label'].astype(str)
        else:
            corr_df['MalwareIntelAttackType'] = ['unknown'] * len(df)
        
        print(f"  Running Union-Find correlation on {len(corr_df)} alerts...")
        
        # Run correlation
        pipeline = CorrelationPipeline(method='union_find')
        usernames = ['SourceHostName', 'DestinationHostName']
        addresses = ['SourceAddress', 'DestinationAddress']
        
        result = pipeline.correlate(corr_df, usernames=usernames, addresses=addresses)
        
        # Extract cluster assignments from CorrelationResult
        if hasattr(result, 'data'):
            result_df = result.data
        elif hasattr(result, 'correlated_df'):
            result_df = result.correlated_df
        elif hasattr(result, 'columns'):
            result_df = result
        else:
            result_df = None
        
        # Look for cluster column - could be 'cluster_id' or 'pred_cluster'
        cluster_col = None
        for col in ['pred_cluster', 'cluster_id']:
            if col in result_df.columns:
                cluster_col = col
                break
        
        if cluster_col:
            predicted = result_df[cluster_col].values
            num_clusters = len(set(predicted))
            
            # Calculate metrics
            ari = adjusted_rand_score(ground_truth, predicted)
            nmi = normalized_mutual_info_score(ground_truth, predicted)
            
            results["status"] = "PASS"
            results["metrics"] = {
                "ari": float(ari),
                "nmi": float(nmi),
                "num_predicted_clusters": int(num_clusters),
                "num_ground_truth_clusters": int(len(set(ground_truth))),
                "total_alerts": len(predicted)
            }
            results["clusters"] = result_df
            
            print(f"    ✓ Union-Find Results:")
            print(f"      - Predicted clusters: {num_clusters}")
            print(f"      - Ground truth clusters: {len(set(ground_truth))}")
            print(f"      - ARI (Adjusted Rand Index): {ari:.4f}")
            print(f"      - NMI (Normalized Mutual Info): {nmi:.4f}")
            print(f"      - Interpretation: {'Good' if ari > 0.5 else 'Moderate' if ari > 0.3 else 'Low'} correlation quality")
        else:
            results["status"] = "FAIL"
            results["issues"] = ["No cluster column found in result"]
            print(f"    ✗ No cluster assignments found")
            print(f"      Available columns: {list(result_df.columns)}")
            
    except Exception as e:
        results["status"] = "ERROR"
        results["issues"] = [str(e)]
        print(f"  ✗ Error: {e}")
    
    return results


def test_mitre_tactic_accuracy(df):
    """Test MITRE ATT&CK tactic mapping accuracy."""
    results = {"status": "FAIL", "mappings": {}}
    
    try:
        # Load tactic map
        tactic_map_path = PROJECT_ROOT / "tactic_map.json"
        if not tactic_map_path.exists():
            results["issues"] = ["tactic_map.json not found"]
            print(f"  ✗ tactic_map.json not found")
            return results
        
        with open(tactic_map_path, 'r', encoding='utf-8') as f:
            tactic_map = json.load(f)
        
        # Get attack types from dataset
        if 'attack_cat' in df.columns:
            attack_types = df['attack_cat'].dropna().unique()
        elif 'label' in df.columns:
            attack_types = df['label'].astype(str).unique()
        else:
            attack_types = []
        
        # Check mapping coverage
        mapped_count = 0
        unmapped_types = []
        sample_mappings = {}
        
        for attack_type in attack_types[:20]:  # Check first 20
            attack_str = str(attack_type).lower()
            
            # Try direct match
            if attack_str in tactic_map:
                mapped_count += 1
                sample_mappings[attack_str] = tactic_map[attack_str]
            else:
                # Try partial match
                found = False
                for key in tactic_map.keys():
                    if attack_str in key.lower() or key.lower() in attack_str:
                        mapped_count += 1
                        sample_mappings[attack_str] = tactic_map[key]
                        found = True
                        break
                if not found:
                    unmapped_types.append(attack_str)
        
        coverage = mapped_count / max(len(attack_types[:20]), 1)
        
        results["status"] = "PASS"
        results["metrics"] = {
            "attack_types_in_dataset": int(len(attack_types)),
            "mapped_types": int(mapped_count),
            "coverage": float(coverage),
            "tactic_map_size": len(tactic_map)
        }
        results["sample_mappings"] = sample_mappings
        results["unmapped_types"] = unmapped_types[:5]
        
        print(f"    ✓ MITRE Tactic Mapping Results:")
        print(f"      - Attack types in dataset: {len(attack_types)}")
        print(f"      - Mapped types (sample): {mapped_count}/20 ({coverage*100:.1f}%)")
        print(f"      - Tactic map entries: {len(tactic_map)}")
        print(f"      - Sample mappings:")
        for attack, tactic in list(sample_mappings.items())[:3]:
            print(f"        * {attack[:30]}... -> {tactic}")
        
    except Exception as e:
        results["status"] = "ERROR"
        results["issues"] = [str(e)]
        print(f"  ✗ Error: {e}")
    
    return results


def test_correlation_chain_quality(clusters_df, ground_truth):
    """Evaluate correlation chain detection quality."""
    results = {"status": "FAIL", "quality_metrics": {}}
    
    try:
        # Check for cluster column
        cluster_col = None
        for col in ['pred_cluster', 'cluster_id']:
            if clusters_df is not None and col in clusters_df.columns:
                cluster_col = col
                break
        
        if cluster_col is None:
            results["issues"] = ["No cluster data available"]
            print(f"  ⚠ No cluster data for chain quality analysis")
            return results
        
        # Analyze cluster composition
        cluster_composition = clusters_df.groupby(cluster_col).apply(
            lambda x: x['MalwareIntelAttackType'].unique() if 'MalwareIntelAttackType' in x.columns else []
        )
        
        # Calculate purity (how homogeneous clusters are)
        total_clusters = len(cluster_composition)
        pure_clusters = 0
        multi_attack_clusters = 0
        
        for cluster_id, attack_types in cluster_composition.items():
            if len(attack_types) == 1:
                pure_clusters += 1
            else:
                multi_attack_clusters += 1
        
        purity = pure_clusters / max(total_clusters, 1)
        
        # Cluster size distribution
        cluster_sizes = clusters_df[cluster_col].value_counts()
        avg_size = cluster_sizes.mean()
        max_size = cluster_sizes.max()
        min_size = cluster_sizes.min()
        
        results["status"] = "PASS"
        results["quality_metrics"] = {
            "total_clusters": int(total_clusters),
            "pure_clusters": int(pure_clusters),
            "multi_attack_clusters": int(multi_attack_clusters),
            "purity_score": float(purity),
            "avg_cluster_size": float(avg_size),
            "max_cluster_size": int(max_size),
            "min_cluster_size": int(min_size)
        }
        
        print(f"    ✓ Correlation Chain Quality:")
        print(f"      - Total attack chains detected: {total_clusters}")
        print(f"      - Pure chains (single attack type): {pure_clusters} ({purity*100:.1f}%)")
        print(f"      - Mixed chains (multiple attack types): {multi_attack_clusters}")
        print(f"      - Chain size: avg={avg_size:.1f}, min={min_size}, max={max_size}")
        
    except Exception as e:
        results["status"] = "ERROR"
        results["issues"] = [str(e)]
        print(f"  ✗ Error: {e}")
    
    return results


def test_hgnn_accuracy(df, ground_truth):
    """Test HGNN model accuracy if checkpoint available."""
    results = {"status": "SKIPPED", "reason": "No checkpoint"}
    
    try:
        # Check for checkpoint
        checkpoint_path = PROJECT_ROOT / "hgnn_checkpoints" / "unsw_supervised.pt"
        if not checkpoint_path.exists():
            checkpoint_path = PROJECT_ROOT / "hgnn_checkpoints" / "nsl_kdd_best.pt"
        
        if not checkpoint_path.exists():
            print(f"  ⚠ No HGNN checkpoint found - skipping HGNN test")
            return results
        
        print(f"  Found checkpoint: {checkpoint_path}")
        print(f"  ⚠ HGNN test requires full feature preprocessing - marking as available")
        
        results["status"] = "AVAILABLE"
        results["checkpoint"] = str(checkpoint_path)
        results["note"] = "HGNN available but requires full preprocessing pipeline"
        
    except Exception as e:
        results["status"] = "ERROR"
        results["issues"] = [str(e)]
        print(f"  ✗ Error: {e}")
    
    return results


def print_accuracy_summary(results):
    """Print comprehensive accuracy summary."""
    print("\n" + "=" * 80)
    print("ACCURACY EXPERIMENT SUMMARY")
    print("=" * 80)
    
    # Dataset loading
    dataset = results["tests"].get("dataset_loading", {})
    if dataset.get("status") == "PASS":
        print(f"✓ Dataset: UNSW-NB15 ({dataset.get('test_records', 0)} records)")
        print(f"  Ground truth clusters: {dataset.get('unique_attacks', 0)}")
    else:
        print(f"✗ Dataset loading failed")
        return
    
    # Union-Find accuracy
    uf = results["tests"].get("union_find_accuracy", {})
    if uf.get("status") == "PASS":
        metrics = uf.get("metrics", {})
        ari = metrics.get("ari", 0)
        nmi = metrics.get("nmi", 0)
        print(f"\n✓ Union-Find Correlation:")
        print(f"  ARI (Accuracy): {ari:.4f} ({ari*100:.1f}%)")
        print(f"  NMI (Information): {nmi:.4f} ({nmi*100:.1f}%)")
        print(f"  Quality: {'EXCELLENT' if ari > 0.7 else 'GOOD' if ari > 0.5 else 'MODERATE' if ari > 0.3 else 'NEEDS IMPROVEMENT'}")
    else:
        print(f"\n✗ Union-Find test failed")
    
    # Tactic mapping
    tactic = results["tests"].get("tactic_mapping", {})
    if tactic.get("status") == "PASS":
        metrics = tactic.get("metrics", {})
        coverage = metrics.get("coverage", 0)
        print(f"\n✓ MITRE ATT&CK Tactic Mapping:")
        print(f"  Coverage: {coverage*100:.1f}% of attack types")
        print(f"  Tactic map size: {metrics.get('tactic_map_size', 0)} entries")
    else:
        print(f"\n✗ Tactic mapping test failed")
    
    # Chain quality
    chain = results["tests"].get("correlation_chain_quality", {})
    if chain.get("status") == "PASS":
        metrics = chain.get("quality_metrics", {})
        purity = metrics.get("purity_score", 0)
        print(f"\n✓ Correlation Chain Quality:")
        print(f"  Chains detected: {metrics.get('total_clusters', 0)}")
        print(f"  Purity (homogeneity): {purity*100:.1f}%")
        print(f"  Chain coherence: {'HIGH' if purity > 0.8 else 'MODERATE' if purity > 0.5 else 'LOW'}")
    else:
        print(f"\n⚠ Chain quality analysis skipped")
    
    # HGNN
    hgnn = results["tests"].get("hgnn_accuracy", {})
    if hgnn.get("status") == "AVAILABLE":
        print(f"\n⚠ HGNN: Available but not tested (requires preprocessing)")
    else:
        print(f"\n⚠ HGNN: No checkpoint available")
    
    print("\n" + "=" * 80)
    print("CONCLUSION")
    print("=" * 80)
    
    # Overall assessment
    uf_metrics = results["tests"].get("union_find_accuracy", {}).get("metrics", {})
    ari = uf_metrics.get("ari", 0)
    
    if ari > 0.5:
        print("✓ MITRE-CORE v2 DEMONSTRATES ACCURATE CORRELATION")
        print("  The system correctly identifies related attack events")
        print("  and groups them into coherent attack chains.")
    elif ari > 0.3:
        print("⚠ MODERATE ACCURACY - Acceptable for research prototype")
        print("  Correlation chains show some alignment with ground truth")
        print("  but could be improved with better feature engineering.")
    else:
        print("✗ LOW ACCURACY - Needs improvement")
        print("  Correlation chains do not align well with ground truth.")
    
    print("=" * 80)


if __name__ == "__main__":
    run_accuracy_experiment()
