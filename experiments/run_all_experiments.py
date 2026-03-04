"""
Comprehensive Experiment Runner for MITRE-CORE IEEE Research Paper
Runs all experiments, captures results, and generates output for the paper.
"""

import sys
import os
import time
import json
import logging
import traceback
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ExperimentRunner')

# Output directory
OUTPUT_DIR = Path(project_root) / "experiments" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_experiment_1_union_find():
    """Experiment 1: Union-Find correlation on synthetic datasets."""
    print("\n" + "="*70)
    print("EXPERIMENT 1: Union-Find Correlation on Synthetic Datasets")
    print("="*70)
    
    from evaluation.metrics import DatasetGenerator, CorrelationEvaluator
    from core.correlation_indexer import enhanced_correlation
    
    generator = DatasetGenerator()
    evaluator = CorrelationEvaluator()
    
    configs = [
        {"name": "Small", "campaigns": 5, "sizes": [3, 4, 5], "noise": 0.1},
        {"name": "Medium", "campaigns": 10, "sizes": [5, 8, 10], "noise": 0.15},
        {"name": "Large", "campaigns": 20, "sizes": [5, 8, 10, 15], "noise": 0.15},
    ]
    
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    results = []
    
    for config in configs:
        print(f"\n--- Dataset: {config['name']} ---")
        
        data, ground_truth = generator.create_evaluation_dataset(
            num_campaigns=config['campaigns'],
            campaign_sizes=config['sizes'],
            noise_level=config['noise']
        )
        
        print(f"  Generated {len(data)} events, {config['campaigns']} campaigns")
        
        # Run Union-Find correlation
        start_time = time.time()
        try:
            result_data = enhanced_correlation(data, usernames, addresses)
            elapsed = time.time() - start_time
            
            pred_clusters = result_data['pred_cluster'].values
            
            # Filter out noise for metrics
            valid_mask = ground_truth >= 0
            pred_valid = pred_clusters[valid_mask]
            gt_valid = ground_truth[valid_mask]
            
            from sklearn.metrics import (
                adjusted_rand_score, normalized_mutual_info_score,
                homogeneity_score, completeness_score, v_measure_score,
                fowlkes_mallows_score
            )
            
            ari = adjusted_rand_score(gt_valid, pred_valid)
            nmi = normalized_mutual_info_score(gt_valid, pred_valid)
            homo = homogeneity_score(gt_valid, pred_valid)
            comp = completeness_score(gt_valid, pred_valid)
            vmeas = v_measure_score(gt_valid, pred_valid)
            fmi = fowlkes_mallows_score(gt_valid, pred_valid)
            
            n_pred_clusters = len(set(pred_clusters))
            n_true_clusters = len(set(ground_truth[ground_truth >= 0]))
            
            result = {
                "dataset": config['name'],
                "num_events": len(data),
                "num_campaigns": config['campaigns'],
                "noise_level": config['noise'],
                "time_seconds": round(elapsed, 4),
                "ARI": round(ari, 4),
                "NMI": round(nmi, 4),
                "Homogeneity": round(homo, 4),
                "Completeness": round(comp, 4),
                "V-Measure": round(vmeas, 4),
                "Fowlkes-Mallows": round(fmi, 4),
                "pred_clusters": n_pred_clusters,
                "true_clusters": n_true_clusters
            }
            results.append(result)
            
            print(f"  Time: {elapsed:.4f}s")
            print(f"  ARI: {ari:.4f} | NMI: {nmi:.4f} | V-Measure: {vmeas:.4f}")
            print(f"  Homogeneity: {homo:.4f} | Completeness: {comp:.4f} | FMI: {fmi:.4f}")
            print(f"  Predicted clusters: {n_pred_clusters} | True clusters: {n_true_clusters}")
            
        except Exception as e:
            print(f"  ERROR: {e}")
            traceback.print_exc()
            results.append({"dataset": config['name'], "error": str(e)})
    
    # Save results
    with open(OUTPUT_DIR / "experiment1_union_find.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {OUTPUT_DIR / 'experiment1_union_find.json'}")
    return results


def run_experiment_2_baselines():
    """Experiment 2: Baseline comparison on synthetic data."""
    print("\n" + "="*70)
    print("EXPERIMENT 2: Baseline Methods Comparison")
    print("="*70)
    
    from evaluation.metrics import DatasetGenerator
    from baselines.simple_clustering import (
        SimpleBaselineCorrelator, RuleBasedCorrelator, AdvancedBaselineCorrelator
    )
    from core.correlation_indexer import enhanced_correlation
    from sklearn.metrics import (
        adjusted_rand_score, normalized_mutual_info_score,
        v_measure_score, fowlkes_mallows_score
    )
    
    generator = DatasetGenerator()
    
    # Generate medium dataset for comparison
    data, ground_truth = generator.create_evaluation_dataset(
        num_campaigns=10, campaign_sizes=[5, 8, 10], noise_level=0.15
    )
    
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    valid_mask = ground_truth >= 0
    gt_valid = ground_truth[valid_mask]
    
    print(f"Dataset: {len(data)} events, {len(set(ground_truth[ground_truth>=0]))} campaigns")
    
    results = []
    
    # Method definitions
    methods = {}
    
    # MITRE-CORE Union-Find
    methods['MITRE-CORE (Union-Find)'] = lambda d, u, a: enhanced_correlation(d, u, a)
    
    # Baselines
    simple = SimpleBaselineCorrelator()
    rule = RuleBasedCorrelator()
    advanced = AdvancedBaselineCorrelator()
    
    methods['DBSCAN'] = lambda d, u, a: simple.dbscan_correlation(d, a, u)
    methods['K-Means'] = lambda d, u, a: simple.kmeans_correlation(d, a, u)
    methods['Hierarchical'] = lambda d, u, a: simple.hierarchical_correlation(d, a, u)
    methods['Rule-Based'] = lambda d, u, a: rule.simple_rule_correlation(d, a, u)
    methods['IP-Subnet'] = lambda d, u, a: rule.ip_subnet_correlation(d, a, u)
    methods['Cosine-Similarity'] = lambda d, u, a: advanced.cosine_similarity_correlation(d, a, u)
    methods['Temporal'] = lambda d, u, a: advanced.temporal_clustering(d, a, u)
    
    for method_name, method_func in methods.items():
        print(f"\n--- {method_name} ---")
        
        start_time = time.time()
        try:
            result_data = method_func(data, usernames, addresses)
            elapsed = time.time() - start_time
            
            pred_clusters = result_data['pred_cluster'].values
            pred_valid = pred_clusters[valid_mask]
            
            ari = adjusted_rand_score(gt_valid, pred_valid)
            nmi = normalized_mutual_info_score(gt_valid, pred_valid)
            vmeas = v_measure_score(gt_valid, pred_valid)
            fmi = fowlkes_mallows_score(gt_valid, pred_valid)
            
            n_pred = len(set(pred_clusters))
            
            result = {
                "method": method_name,
                "time_seconds": round(elapsed, 4),
                "ARI": round(ari, 4),
                "NMI": round(nmi, 4),
                "V-Measure": round(vmeas, 4),
                "Fowlkes-Mallows": round(fmi, 4),
                "pred_clusters": n_pred
            }
            results.append(result)
            
            print(f"  Time: {elapsed:.4f}s | ARI: {ari:.4f} | NMI: {nmi:.4f} | V-Measure: {vmeas:.4f} | Clusters: {n_pred}")
            
        except Exception as e:
            print(f"  ERROR: {e}")
            traceback.print_exc()
            results.append({"method": method_name, "error": str(e)})
    
    # Save results
    with open(OUTPUT_DIR / "experiment2_baselines.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {OUTPUT_DIR / 'experiment2_baselines.json'}")
    return results


def run_experiment_3_ground_truth_validation():
    """Experiment 3: Ground truth validation with detailed analysis."""
    print("\n" + "="*70)
    print("EXPERIMENT 3: Ground Truth Validation")
    print("="*70)
    
    from evaluation.ground_truth_validator import GroundTruthValidator
    from evaluation.metrics import DatasetGenerator
    from core.correlation_indexer import enhanced_correlation
    from baselines.simple_clustering import SimpleBaselineCorrelator
    
    generator = DatasetGenerator()
    validator = GroundTruthValidator()
    
    data, ground_truth = generator.create_evaluation_dataset(
        num_campaigns=10, campaign_sizes=[5, 8, 10], noise_level=0.15
    )
    
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    print(f"Dataset: {len(data)} events")
    
    results_dict = {}
    
    # MITRE-CORE
    try:
        uf_result = enhanced_correlation(data, usernames, addresses)
        uf_pred = uf_result['pred_cluster'].values
        uf_validation = validator.validate_clustering_results(
            uf_pred, ground_truth, "MITRE-CORE (Union-Find)"
        )
        results_dict["MITRE-CORE (Union-Find)"] = uf_validation
        print(f"\nMITRE-CORE (UF): ARI={uf_validation['adjusted_rand_score']:.4f}, "
              f"NMI={uf_validation['normalized_mutual_info']:.4f}")
    except Exception as e:
        print(f"MITRE-CORE error: {e}")
        traceback.print_exc()
    
    # DBSCAN baseline
    try:
        simple = SimpleBaselineCorrelator()
        db_result = simple.dbscan_correlation(data, addresses, usernames)
        db_pred = db_result['pred_cluster'].values
        db_validation = validator.validate_clustering_results(
            db_pred, ground_truth, "DBSCAN"
        )
        results_dict["DBSCAN"] = db_validation
        print(f"DBSCAN: ARI={db_validation['adjusted_rand_score']:.4f}, "
              f"NMI={db_validation['normalized_mutual_info']:.4f}")
    except Exception as e:
        print(f"DBSCAN error: {e}")
        traceback.print_exc()
    
    # Generate validation report
    if results_dict:
        report = validator.generate_validation_report(
            results_dict,
            output_path=str(OUTPUT_DIR / "experiment3_validation_report.txt")
        )
        print(f"\nValidation report saved.")
        print(report[:500])
    
    return results_dict


def run_experiment_4_scalability():
    """Experiment 4: Scalability benchmarks."""
    print("\n" + "="*70)
    print("EXPERIMENT 4: Scalability Benchmarks")
    print("="*70)
    
    from evaluation.metrics import DatasetGenerator
    from core.correlation_indexer import enhanced_correlation
    
    generator = DatasetGenerator()
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    sizes = [
        {"campaigns": 2, "sizes": [3, 4], "noise": 0.1, "label": "~10"},
        {"campaigns": 5, "sizes": [5, 8], "noise": 0.1, "label": "~30-50"},
        {"campaigns": 10, "sizes": [5, 8, 10], "noise": 0.15, "label": "~80-100"},
        {"campaigns": 20, "sizes": [5, 8, 10, 15], "noise": 0.15, "label": "~200"},
        {"campaigns": 30, "sizes": [8, 10, 15], "noise": 0.15, "label": "~300+"},
    ]
    
    results = []
    
    for config in sizes:
        data, gt = generator.create_evaluation_dataset(
            num_campaigns=config['campaigns'],
            campaign_sizes=config['sizes'],
            noise_level=config['noise']
        )
        
        n_events = len(data)
        
        # Time Union-Find
        start = time.time()
        try:
            result = enhanced_correlation(data, usernames, addresses)
            elapsed = time.time() - start
            
            result_entry = {
                "label": config['label'],
                "actual_events": n_events,
                "campaigns": config['campaigns'],
                "uf_time_seconds": round(elapsed, 4)
            }
            results.append(result_entry)
            
            print(f"  {config['label']} ({n_events} events): {elapsed:.4f}s")
        except Exception as e:
            print(f"  {config['label']}: ERROR - {e}")
            results.append({"label": config['label'], "actual_events": n_events, "error": str(e)})
    
    with open(OUTPUT_DIR / "experiment4_scalability.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {OUTPUT_DIR / 'experiment4_scalability.json'}")
    return results


def run_experiment_5_ablation():
    """Experiment 5: Ablation study on Union-Find components."""
    print("\n" + "="*70)
    print("EXPERIMENT 5: Ablation Study (Union-Find)")
    print("="*70)
    
    from evaluation.metrics import DatasetGenerator
    from core.correlation_indexer import enhanced_correlation
    from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
    
    generator = DatasetGenerator()
    data, ground_truth = generator.create_evaluation_dataset(
        num_campaigns=10, campaign_sizes=[5, 8, 10], noise_level=0.15
    )
    
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    valid_mask = ground_truth >= 0
    gt_valid = ground_truth[valid_mask]
    
    results = []
    
    # Full system
    configs = [
        {"name": "Full System", "temporal": True, "adaptive": True},
        {"name": "No Adaptive Threshold", "temporal": True, "adaptive": False},
        {"name": "No Temporal Features", "temporal": False, "adaptive": True},
        {"name": "No Temporal + No Adaptive", "temporal": False, "adaptive": False},
    ]
    
    for config in configs:
        print(f"\n--- {config['name']} ---")
        try:
            result_data = enhanced_correlation(
                data, usernames, addresses,
                use_temporal=config['temporal'],
                use_adaptive_threshold=config['adaptive']
            )
            
            pred = result_data['pred_cluster'].values[valid_mask]
            ari = adjusted_rand_score(gt_valid, pred)
            nmi = normalized_mutual_info_score(gt_valid, pred)
            
            result = {
                "config": config['name'],
                "ARI": round(ari, 4),
                "NMI": round(nmi, 4),
                "temporal": config['temporal'],
                "adaptive": config['adaptive']
            }
            results.append(result)
            
            print(f"  ARI: {ari:.4f} | NMI: {nmi:.4f}")
        except Exception as e:
            print(f"  ERROR: {e}")
            traceback.print_exc()
            results.append({"config": config['name'], "error": str(e)})
    
    with open(OUTPUT_DIR / "experiment5_ablation.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {OUTPUT_DIR / 'experiment5_ablation.json'}")
    return results


def run_experiment_6_modern_dataset():
    """Experiment 6: Evaluation on Modern Datasets (DataSense IIoT 2025)."""
    print("\n" + "="*70)
    print("EXPERIMENT 6: Evaluation on Modern Datasets")
    print("="*70)

    from training.modern_loader import ModernDatasetLoader
    from core.correlation_indexer import enhanced_correlation
    from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

    loader = ModernDatasetLoader(dataset_type="datasense")
    print("Generating synthetic modern flow data (DataSense IIoT 2025 style)...")
    data = loader.load_and_preprocess(file_path="", is_synthetic=True, num_synthetic_records=1000)

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']

    ground_truth_list = []
    campaign_map = {}
    current_id = 0
    for idx, row in data.iterrows():
        if row['Attack_Type'] == 'Normal':
            ground_truth_list.append(-1)
        else:
            if row['Attack_Type'] not in campaign_map:
                campaign_map[row['Attack_Type']] = current_id
                current_id += 1
            ground_truth_list.append(campaign_map[row['Attack_Type']])

    gt_arr = np.array(ground_truth_list)
    valid_mask = gt_arr >= 0
    gt_valid = gt_arr[valid_mask]

    results = []
    start_time = time.time()
    try:
        result_data = enhanced_correlation(
            data, usernames, addresses,
            use_temporal=False,
            use_adaptive_threshold=True
        )
        elapsed = time.time() - start_time
        pred = result_data['pred_cluster'].values[valid_mask]
        ari = adjusted_rand_score(gt_valid, pred)
        nmi = normalized_mutual_info_score(gt_valid, pred)
        results.append({
            "dataset": "DataSense IIoT 2025 (Synthetic)",
            "num_events": len(data),
            "ARI": round(ari, 4),
            "NMI": round(nmi, 4),
            "time_seconds": round(elapsed, 4)
        })
        print(f"  Dataset: DataSense IIoT 2025 | Events: {len(data)}")
        print(f"  ARI: {ari:.4f} | NMI: {nmi:.4f} | Time: {elapsed:.4f}s")
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    with open(OUTPUT_DIR / "experiment6_modern_dataset.json", 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {OUTPUT_DIR / 'experiment6_modern_dataset.json'}")
    return results


def run_experiment_7_sensitivity():
    """Experiment 7: Sensitivity Analysis for Threshold Bounds."""
    print("\n" + "="*70)
    print("EXPERIMENT 7: Sensitivity Analysis for Threshold Bounds")
    print("="*70)

    from evaluation.metrics import DatasetGenerator
    from core.correlation_indexer import enhanced_correlation
    from sklearn.metrics import adjusted_rand_score

    generator = DatasetGenerator()
    data, ground_truth = generator.create_evaluation_dataset(
        num_campaigns=10, campaign_sizes=[5, 8], noise_level=0.1
    )

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']

    valid_mask = ground_truth >= 0
    gt_valid = ground_truth[valid_mask]

    thresholds = [0.1, 0.3, 0.5, 0.7, 0.9]
    results = []

    print("Running correlation at each threshold...")
    for t in thresholds:
        try:
            result_data = enhanced_correlation(
                data, usernames, addresses,
                use_temporal=False,
                use_adaptive_threshold=False,
                threshold_override=t
            )
            pred = result_data['pred_cluster'].values[valid_mask]
            ari = adjusted_rand_score(gt_valid, pred)
            n_clusters = result_data['pred_cluster'].nunique()
            results.append({"threshold": t, "ARI": round(ari, 4), "num_clusters": n_clusters})
            print(f"  Threshold {t:.1f} -> ARI: {ari:.4f} | Clusters: {n_clusters}")
        except Exception as e:
            print(f"  Threshold {t:.1f} -> ERROR: {e}")
            traceback.print_exc()

    with open(OUTPUT_DIR / "experiment7_sensitivity.json", 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {OUTPUT_DIR / 'experiment7_sensitivity.json'}")
    return results


def generate_summary_report(all_results):
    """Generate a comprehensive summary report."""
    print("\n" + "="*70)
    print("GENERATING SUMMARY REPORT")
    print("="*70)
    
    report = []
    report.append("=" * 70)
    report.append("MITRE-CORE COMPREHENSIVE EXPERIMENT RESULTS")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("=" * 70)
    
    # Experiment 1
    report.append("\n\n## EXPERIMENT 1: Union-Find on Synthetic Datasets")
    report.append("-" * 50)
    if 'exp1' in all_results and all_results['exp1']:
        for r in all_results['exp1']:
            if 'error' not in r:
                report.append(f"  {r['dataset']:8s} | Events: {r['num_events']:4d} | "
                            f"ARI: {r['ARI']:.4f} | NMI: {r['NMI']:.4f} | "
                            f"V-Measure: {r['V-Measure']:.4f} | Time: {r['time_seconds']:.4f}s")
    
    # Experiment 2
    report.append("\n\n## EXPERIMENT 2: Baseline Comparison")
    report.append("-" * 50)
    if 'exp2' in all_results and all_results['exp2']:
        for r in all_results['exp2']:
            if 'error' not in r:
                report.append(f"  {r['method']:30s} | ARI: {r['ARI']:.4f} | "
                            f"NMI: {r['NMI']:.4f} | V-Measure: {r['V-Measure']:.4f} | "
                            f"Time: {r['time_seconds']:.4f}s")
    
    # Experiment 4
    report.append("\n\n## EXPERIMENT 4: Scalability")
    report.append("-" * 50)
    if 'exp4' in all_results and all_results['exp4']:
        for r in all_results['exp4']:
            if 'error' not in r:
                report.append(f"  {r['label']:10s} | Events: {r['actual_events']:4d} | "
                            f"UF Time: {r['uf_time_seconds']:.4f}s")
    
    # Experiment 5
    report.append("\n\n## EXPERIMENT 5: Ablation Study")
    report.append("-" * 50)
    if 'exp5' in all_results and all_results['exp5']:
        for r in all_results['exp5']:
            if 'error' not in r:
                report.append(f"  {r['config']:30s} | ARI: {r['ARI']:.4f} | NMI: {r['NMI']:.4f}")

    # Experiment 6
    report.append("\n\n## EXPERIMENT 6: Modern Datasets")
    report.append("-" * 50)
    if 'exp6' in all_results and all_results['exp6']:
        for r in all_results['exp6']:
            if 'error' not in r:
                report.append(f"  {r['dataset']:35s} | Events: {r['num_events']:4d} | ARI: {r['ARI']:.4f} | NMI: {r['NMI']:.4f}")

    # Experiment 7
    report.append("\n\n## EXPERIMENT 7: Sensitivity Analysis")
    report.append("-" * 50)
    if 'exp7' in all_results and all_results['exp7']:
        for r in all_results['exp7']:
            if 'error' not in r:
                report.append(f"  Threshold: {r['threshold']:.1f} | ARI: {r['ARI']:.4f}")

    report.append("\n\n" + "=" * 70)
    report.append("END OF REPORT")
    report.append("=" * 70)
    
    report_text = "\n".join(report)
    
    with open(OUTPUT_DIR / "FULL_EXPERIMENT_REPORT.txt", 'w') as f:
        f.write(report_text)
    
    print(report_text)
    return report_text


def main():
    print("=" * 70)
    print("MITRE-CORE: Comprehensive Experiment Suite")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 70)
    
    all_results = {}
    
    # Run all experiments
    try:
        all_results['exp1'] = run_experiment_1_union_find()
    except Exception as e:
        print(f"Experiment 1 failed: {e}")
        traceback.print_exc()
        all_results['exp1'] = []
    
    try:
        all_results['exp2'] = run_experiment_2_baselines()
    except Exception as e:
        print(f"Experiment 2 failed: {e}")
        traceback.print_exc()
        all_results['exp2'] = []
    
    try:
        all_results['exp3'] = run_experiment_3_ground_truth_validation()
    except Exception as e:
        print(f"Experiment 3 failed: {e}")
        traceback.print_exc()
        all_results['exp3'] = {}
    
    try:
        all_results['exp4'] = run_experiment_4_scalability()
    except Exception as e:
        print(f"Experiment 4 failed: {e}")
        traceback.print_exc()
        all_results['exp4'] = []
    
    try:
        all_results['exp5'] = run_experiment_5_ablation()
    except Exception as e:
        print(f"Experiment 5 failed: {e}")
        traceback.print_exc()
        all_results['exp5'] = []

    try:
        all_results['exp6'] = run_experiment_6_modern_dataset()
    except Exception as e:
        print(f"Experiment 6 failed: {e}")
        traceback.print_exc()
        all_results['exp6'] = []

    try:
        all_results['exp7'] = run_experiment_7_sensitivity()
    except Exception as e:
        print(f"Experiment 7 failed: {e}")
        traceback.print_exc()
        all_results['exp7'] = []

    # Generate summary
    generate_summary_report(all_results)
    
    # Save all results
    serializable = {}
    for k, v in all_results.items():
        if isinstance(v, dict):
            serializable[k] = "See individual experiment files"
        else:
            serializable[k] = v
    
    with open(OUTPUT_DIR / "all_results.json", 'w') as f:
        json.dump(serializable, f, indent=2, default=str)
    
    print(f"\nAll experiments completed at {datetime.now().isoformat()}")
    print(f"Results directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
