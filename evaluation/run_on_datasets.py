"""
Run MITRE-CORE enhanced correlation and baselines on provided datasets.
Saves concise summaries and (when available) metrics vs ground truth.
"""

import os
import json
import time
from pathlib import Path
from typing import List, Dict, Optional

import numpy as np
import pandas as pd

# Local imports
from baselines.simple_clustering import SimpleBaselineCorrelator, run_all_baselines
from core.correlation_indexer import enhanced_correlation
from evaluation.metrics import CorrelationEvaluator


# Standard field preferences
PREFERRED_ADDRESSES = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
PREFERRED_USERNAMES = [
    'SourceHostName', 'DeviceHostName', 'DestinationHostName',
    'SourceUserName', 'DestinationUserName'
]


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names to improve compatibility across datasets."""
    rename_map = {}
    for col in list(df.columns):
        norm = col.strip()
        # Common normalizations
        if norm.lower() in ['end date', 'end_date']:
            rename_map[col] = 'EndDate'
        elif norm.lower() in ['destination user name', 'destination_user_name']:
            rename_map[col] = 'DestinationUserName'
        elif norm.lower() == 'malwareintelattacktype':
            rename_map[col] = 'MalwareIntelAttackType'
        elif norm.lower() == 'devicehostname':
            rename_map[col] = 'DeviceHostName'
        elif norm.lower() == 'sourcehostname':
            rename_map[col] = 'SourceHostName'
        elif norm.lower() == 'destinationhostname':
            rename_map[col] = 'DestinationHostName'
        elif norm.lower() == 'deviceaddress':
            rename_map[col] = 'DeviceAddress'
        elif norm.lower() == 'sourceaddress':
            rename_map[col] = 'SourceAddress'
        elif norm.lower() == 'destinationaddress':
            rename_map[col] = 'DestinationAddress'
    if rename_map:
        df = df.rename(columns=rename_map)
    return df


def select_fields(df: pd.DataFrame) -> (List[str], List[str]):
    """Select available address and username fields from preferences."""
    addresses = [c for c in PREFERRED_ADDRESSES if c in df.columns]
    usernames = [c for c in PREFERRED_USERNAMES if c in df.columns]
    return addresses, usernames


def load_dataset(path: Path) -> pd.DataFrame:
    # Heuristic: read CSV with low_memory=False and handle potential bad lines
    return pd.read_csv(path, low_memory=False)


def summarize_clusters(labels: np.ndarray) -> Dict:
    vals, counts = np.unique(labels, return_counts=True)
    sizes = sorted(counts.tolist(), reverse=True)
    return {
        'num_clusters': int(len(vals)),
        'largest_clusters': sizes[:5],
    }


def evaluate_against_ground_truth(df: pd.DataFrame, y_pred: np.ndarray, gt_col: str) -> Dict:
    evaluator = CorrelationEvaluator()
    y_true = df[gt_col].astype(int).values
    metrics = evaluator.calculate_clustering_metrics(y_true, y_pred)
    return metrics


def compute_internal_silhouette(df: pd.DataFrame, labels: np.ndarray, addresses: List[str], usernames: List[str]) -> float:
    try:
        correlator = SimpleBaselineCorrelator()
        X = correlator.preprocess_data(df, addresses, usernames)
        from sklearn.metrics import silhouette_score
        if len(set(labels)) > 1:
            return float(silhouette_score(X, labels))
        return 0.0
    except Exception:
        return 0.0


def run_on_dataset(path: Path, output_dir: Path) -> Dict:
    df = load_dataset(path)
    df = normalize_columns(df)

    # Drop obvious helper columns if present
    for drop_col in ['Unnamed: 0', 'index', 'level_0']:
        if drop_col in df.columns:
            df = df.drop(columns=[drop_col])

    addresses, usernames = select_fields(df)

    result = {
        'dataset': str(path),
        'rows': int(len(df)),
        'available_addresses': addresses,
        'available_usernames': usernames,
        'has_enddate': bool('EndDate' in df.columns),
        'ground_truth_column': None,
        'mitre_core': {},
        'baselines': {}
    }

    # Determine ground truth column if available
    gt_col = None
    for candidate in ['actual_cluster', 'ground_truth', 'true_cluster']:
        if candidate in df.columns:
            gt_col = candidate
            break
    if gt_col is None and 'cluster' in df.columns:
        # Use only if appears integer-like
        try:
            if pd.api.types.is_integer_dtype(df['cluster']) or df['cluster'].dropna().astype(str).str.isdigit().all():
                gt_col = 'cluster'
        except Exception:
            pass
    if gt_col:
        result['ground_truth_column'] = gt_col

    # Skip if we have absolutely no features
    if len(addresses) + len(usernames) == 0 and 'EndDate' not in df.columns:
        result['error'] = 'No usable features found'
        return result

    # Run MITRE-CORE enhanced correlation
    mitre_df = enhanced_correlation(
        df, usernames=usernames, addresses=addresses,
        use_temporal=True, use_adaptive_threshold=True
    )
    mitre_labels = mitre_df['pred_cluster'].values

    mitre_summary = summarize_clusters(mitre_labels)
    mitre_summary['threshold_used'] = float(mitre_df['correlation_threshold_used'].iloc[0])
    mitre_summary['silhouette_internal'] = compute_internal_silhouette(df, mitre_labels, addresses, usernames)

    if gt_col:
        mitre_summary.update(evaluate_against_ground_truth(df, mitre_labels, gt_col))

    result['mitre_core'] = mitre_summary

    # Run a couple of baselines for reference (keep runtime reasonable)
    baselines_to_run = ['DBSCAN', 'K-means', 'Cosine-Similarity']
    all_baseline_results = run_all_baselines(df, addresses, usernames)

    for name in baselines_to_run:
        if name in all_baseline_results:
            bdf = all_baseline_results[name]
            blabels = bdf['pred_cluster'].values
            bsum = summarize_clusters(blabels)
            bsum['silhouette_internal'] = compute_internal_silhouette(df, blabels, addresses, usernames)
            if gt_col:
                bsum.update(evaluate_against_ground_truth(df, blabels, gt_col))
            result['baselines'][name] = bsum

    # Save per-dataset JSON
    out_json = output_dir / f"{path.stem}_summary.json"
    with out_json.open('w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    return result


def main():
    print("Running MITRE-CORE on provided datasets...")
    ts = time.strftime('%Y%m%d_%H%M%S')
    out_dir = Path('evaluation_results') / f'datasets_{ts}'
    out_dir.mkdir(parents=True, exist_ok=True)

    dataset_paths = [
        Path('Data/Cleaned/test_dataset.csv'),
        Path('Data/Cleaned/network_test_dataset.csv'),
        Path('Data/Cleaned/Canara_data_cleaned.csv'),
        Path('Data/Preprocessed/network.csv'),
        Path('Data/Raw_data/mydata2.csv'),
    ]

    results = []
    for p in dataset_paths:
        if p.exists():
            try:
                print(f"- Processing {p} ...")
                res = run_on_dataset(p, out_dir)
                results.append(res)
                # Console summary
                mc = res.get('mitre_core', {})
                print(f"  MITRE-CORE: clusters={mc.get('num_clusters')} largest={mc.get('largest_clusters')} ARI={mc.get('adjusted_rand_score', 'NA')} Sil={mc.get('silhouette_internal', 'NA')}")
            except Exception as e:
                results.append({'dataset': str(p), 'error': str(e)})
                print(f"  ERROR: {e}")
        else:
            print(f"- Skipping missing {p}")

    # Save combined report
    combined = {
        'run_started': ts,
        'num_datasets': len(results),
        'results': results,
    }
    with (out_dir / 'combined_summary.json').open('w', encoding='utf-8') as f:
        json.dump(combined, f, indent=2)

    print(f"Done. Results saved to {out_dir}")


if __name__ == '__main__':
    main()
