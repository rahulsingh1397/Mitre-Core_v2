import pandas as pd
import numpy as np
import os
import time
import json
from pathlib import Path
import sys

# Add project root to path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

from datasets.loaders.nsl_kdd_loader import NSLKDDLoader
from datasets.loaders.ton_iot_loader import TONIoTLoader
from core.correlation_indexer import enhanced_correlation
from baselines.simple_clustering import SimpleBaselineCorrelator, RuleBasedCorrelator, AdvancedBaselineCorrelator
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score, homogeneity_score, completeness_score, v_measure_score, fowlkes_mallows_score

OUTPUT_DIR = Path(project_root) / "experiments" / "multi_dataset_results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def eval_method(name, func, data, gt_valid, valid_mask, usernames, addresses):
    start = time.time()
    try:
        res = func(data, usernames, addresses)
        pred = res['pred_cluster'].values[valid_mask]
        
        ari = adjusted_rand_score(gt_valid, pred)
        nmi = normalized_mutual_info_score(gt_valid, pred)
        homo = homogeneity_score(gt_valid, pred)
        comp = completeness_score(gt_valid, pred)
        vmeas = v_measure_score(gt_valid, pred)
        fmi = fowlkes_mallows_score(gt_valid, pred)
        clusters = len(np.unique(pred))
        t = time.time() - start
        
        return {
            'Method': name,
            'ARI': round(ari, 4),
            'NMI': round(nmi, 4),
            'Homogeneity': round(homo, 4),
            'Completeness': round(comp, 4),
            'V-Measure': round(vmeas, 4),
            'FMI': round(fmi, 4),
            'Pred_Clusters': clusters,
            'Time_s': round(t, 3)
        }
    except Exception as e:
        print(f"Error in {name}: {e}")
        return {
            'Method': name,
            'ARI': 'ERROR', 'NMI': '-', 'Homogeneity': '-', 'Completeness': '-', 
            'V-Measure': '-', 'FMI': '-', 'Pred_Clusters': '-', 'Time_s': '-'
        }

def run_evaluation(dataset_name, data):
    print(f"\n{'='*50}\nEvaluating {dataset_name}\n{'='*50}")
    
    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    # Generate ground truth mapping
    ground_truth_list = []
    campaign_map = {}
    current_id = 0
    for idx, row in data.iterrows():
        if 'MalwareIntelAttackType' in row:
            attack = str(row['MalwareIntelAttackType']).lower()
        else:
            attack = 'normal'
            
        if attack == 'normal':
            ground_truth_list.append(-1)
        else:
            if attack not in campaign_map:
                campaign_map[attack] = current_id
                current_id += 1
            ground_truth_list.append(campaign_map[attack])

    gt_arr = np.array(ground_truth_list)
    valid_mask = gt_arr >= 0
    gt_valid = gt_arr[valid_mask]
    
    if len(gt_valid) == 0:
        print("No attacks found to cluster in this sample.")
        return None
        
    n_gt_clusters = len(np.unique(gt_valid))
    data = data.reset_index(drop=True)
    
    print(f"Events: {len(data)}, Ground Truth Clusters: {n_gt_clusters}")

    simple = SimpleBaselineCorrelator()
    rule = RuleBasedCorrelator()
    advanced = AdvancedBaselineCorrelator()
    
    methods = [
        ('K-Means', lambda d, u, a: simple.kmeans_correlation(d, a, u, n_clusters=max(1, n_gt_clusters))),
        ('Hierarchical', lambda d, u, a: simple.hierarchical_correlation(d, a, u, n_clusters=max(1, n_gt_clusters))),
        ('Rule-Based', lambda d, u, a: rule.simple_rule_correlation(d, a, u)),
        ('IP-Subnet', lambda d, u, a: rule.ip_subnet_correlation(d, a, u)),
        ('Cosine-Similarity', lambda d, u, a: advanced.cosine_similarity_correlation(d, a, u)),
        ('Temporal', lambda d, u, a: advanced.temporal_clustering(d, a, u)),
        ('MITRE-CORE (Union-Find)', lambda d, u, a: enhanced_correlation(d, u, a, use_temporal=False)),
        ('DBSCAN', lambda d, u, a: simple.dbscan_correlation(d, a, u))
    ]
    
    results = []
    for name, func in methods:
        print(f"Running {name}...")
        res = eval_method(name, func, data, gt_valid, valid_mask, usernames, addresses)
        res['Dataset'] = dataset_name
        results.append(res)
        
    df_results = pd.DataFrame(results)
    
    # Save CSV
    file_prefix = dataset_name.lower().replace('-', '_')
    csv_path = OUTPUT_DIR / f"{file_prefix}_results.csv"
    df_results.to_csv(csv_path, index=False)
    
    # Save JSON
    json_path = OUTPUT_DIR / f"{file_prefix}_results.json"
    df_results.to_json(json_path, orient='records', indent=4)
    
    print(df_results[['Method', 'ARI', 'NMI', 'Time_s']])
    return df_results

if __name__ == '__main__':
    all_results = []
    
    # NSL-KDD
    if os.path.exists('datasets/nsl_kdd/KDDTrain+.txt'):
        nsl_loader = NSLKDDLoader()
        df_nsl = nsl_loader.load_and_preprocess('datasets/nsl_kdd/KDDTrain+.txt')
        # Stratified sample
        np.random.seed(42)
        counts = df_nsl['MalwareIntelAttackType'].value_counts()
        props = counts / len(df_nsl)
        samples = []
        for attack_type, prop in props.items():
            n_samples = max(1, int(np.round(prop * 500)))
            subset = df_nsl[df_nsl['MalwareIntelAttackType'] == attack_type]
            if len(subset) > 0:
                samples.append(subset.sample(n=min(n_samples, len(subset)), random_state=42))
        df_nsl_sampled = pd.concat(samples)
        if len(df_nsl_sampled) > 500:
            df_nsl_sampled = df_nsl_sampled.sample(n=500, random_state=42)
            
        res_nsl = run_evaluation('NSL-KDD', df_nsl_sampled)
        if res_nsl is not None:
            all_results.append(res_nsl)
        
    # TON_IoT
    if os.path.exists('datasets/TON_IoT/mitre_format.parquet'):
        ton_loader = TONIoTLoader()
        df_ton = ton_loader.stratified_sample('datasets/TON_IoT/mitre_format.parquet', n=500)
        res_ton = run_evaluation('TON_IoT', df_ton)
        if res_ton is not None:
            all_results.append(res_ton)
        
    if all_results:
        final_df = pd.concat(all_results, ignore_index=True)
        final_df.to_csv(OUTPUT_DIR / 'all_datasets_summary.csv', index=False)
        print("\nAll evaluation finished. Results saved to experiments/multi_dataset_results/")
