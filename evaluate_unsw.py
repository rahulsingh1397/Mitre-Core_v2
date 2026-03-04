import pandas as pd
import numpy as np
import time
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score, fowlkes_mallows_score
import sys
import os

# Ensure local imports work
sys.path.append('.')

from core.correlation_indexer import enhanced_correlation
from core.preprocessing import label_with_nulls_included
from sklearn.preprocessing import LabelEncoder
from hgnn.hgnn_correlation import HGNNCorrelationEngine

def main():
    print("Loading UNSW-NB15...")
    df = pd.read_csv('datasets/unsw_nb15/mitre_format.csv')
    
    if len(df) > 500:
        df = df.sample(500, random_state=42).reset_index(drop=True)
        
    print(f"Tactics in sample: {df['tactic'].value_counts().to_dict()}")

    mitre_df = pd.DataFrame()
    mitre_df['AlertId'] = [f'ALT-{i}' for i in range(len(df))]
    mitre_df['SourceAddress'] = df['src_ip']
    mitre_df['DestinationAddress'] = df['dst_ip']
    mitre_df['DeviceAddress'] = df['dst_ip']
    mitre_df['SourceUserName'] = df['username']
    mitre_df['SourceHostName'] = df['hostname']
    mitre_df['DeviceHostName'] = 'sensor.local'
    mitre_df['DestinationHostName'] = df['hostname']
    mitre_df['EndDate'] = df['timestamp']
    mitre_df['label'] = df['tactic']
    
    # Extra features for HGNN
    mitre_df['MalwareIntelAttackType'] = df['alert_type']
    mitre_df['AttackSeverity'] = 'Medium'
    mitre_df['protocol'] = df['protocol']
    mitre_df['service'] = df['service']
    mitre_df['tactic'] = df['tactic']

    gt = mitre_df['label'].values
    gt_encoded = LabelEncoder().fit_transform(gt)

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ['SourceUserName', 'SourceHostName', 'DeviceHostName', 'DestinationHostName']

    print("\n--- Running Union-Find (no temporal) ---")
    t0 = time.time()
    cluster_df = enhanced_correlation(
        mitre_df, usernames, addresses, use_temporal=False, use_adaptive_threshold=True
    )
    t1 = time.time()

    pred_labels = np.zeros(len(mitre_df))
    # Check if 'pred_cluster' is in columns, if not, print columns
    if 'pred_cluster' in cluster_df.columns:
        for idx, row in cluster_df.iterrows():
            pred_labels[idx] = row['pred_cluster']
    else:
        print("Columns in cluster_df:", cluster_df.columns)
        sys.exit(1)

    uf_ari = adjusted_rand_score(gt_encoded, pred_labels)
    uf_nmi = normalized_mutual_info_score(gt_encoded, pred_labels)
    uf_fmi = fowlkes_mallows_score(gt_encoded, pred_labels)
    print(f'UF Time: {t1-t0:.3f}s')
    print(f'UF ARI: {uf_ari:.4f}')
    print(f'UF NMI: {uf_nmi:.4f}')
    print(f'Pred Clusters: {len(np.unique(pred_labels))}')

    print("\n--- Running HGNN ---")
    t0 = time.time()
    try:
        engine = HGNNCorrelationEngine(device='cpu')
        clusters_hgnn = engine.correlate(mitre_df)
        t1 = time.time()

        pred_labels_hgnn = np.zeros(len(mitre_df))
        if 'pred_cluster' in clusters_hgnn.columns:
            for idx, row in clusters_hgnn.iterrows():
                pred_labels_hgnn[idx] = row['pred_cluster']
        else:
            print("Columns in clusters_hgnn:", clusters_hgnn.columns)
            sys.exit(1)
        
        hgnn_ari = adjusted_rand_score(gt_encoded, pred_labels_hgnn)
        hgnn_nmi = normalized_mutual_info_score(gt_encoded, pred_labels_hgnn)
        print(f'HGNN Time: {t1-t0:.3f}s')
        print(f'HGNN ARI: {hgnn_ari:.4f}')
        print(f'HGNN NMI: {hgnn_nmi:.4f}')
        print(f'Pred Clusters: {len(np.unique(pred_labels_hgnn))}')
        
        print("\n--- Results Summary ---")
        print(f"Dataset: UNSW-NB15 (n=500)")
        print(f"Union-Find (no temporal): ARI={uf_ari:.4f}, NMI={uf_nmi:.4f}")
        print(f"HGNN: ARI={hgnn_ari:.4f}, NMI={hgnn_nmi:.4f}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
