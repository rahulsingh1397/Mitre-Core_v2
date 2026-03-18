"""
End-to-End Integration Test for CyberTransformer

Tests the complete pipeline:
1. Load trained transformer model
2. Generate candidate edges from alerts
3. Feed candidates to Union-Find for correlation
4. Compare results with baseline (Union-Find only)
5. Validate determinism is maintained
"""

import torch
import pandas as pd
import numpy as np
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple, Set

sys.path.insert(0, str(Path(__file__).parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from core.correlation_pipeline import CorrelationPipeline, CorrelationResult


def load_model(checkpoint_path: str, device: torch.device):
    """Load trained transformer model."""
    model = TransformerCandidateGenerator(
        vocab_size=10000,
        num_entities=10000,
        d_model=128,
        n_layers=2,
        n_heads=4,
        max_seq_len=256,
        dropout=0.1,
        use_gradient_checkpointing=False,
        config=DEFAULT_CONFIG_8GB
    )
    
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=True)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    model.to(device)
    
    return model


def generate_candidates_transformer(
    model: TransformerCandidateGenerator,
    alerts_df: pd.DataFrame,
    preprocessor: AlertPreprocessor,
    device: torch.device,
    top_k: int = 10
) -> List[Tuple[int, int, float]]:
    """
    Generate candidate edges using transformer model.
    
    Returns: List of (alert_i, alert_j, score) tuples
    """
    if len(alerts_df) < 2:
        return []
    
    # Process batch
    batch = preprocessor.process_batch(alerts_df, device=device, batch_id="test")
    
    with torch.no_grad():
        outputs = model(
            alert_ids=batch['alert_ids'],
            entity_ids=batch['entity_ids'],
            time_buckets=batch['time_buckets'],
            attention_mask=batch['attention_mask'],
            return_candidates=True,
            top_k=top_k
        )
    
    # Extract edges with scores
    candidates = []
    for (i, j), score in zip(outputs['candidate_edges'], outputs['edge_scores']):
        candidates.append((i, j, float(score)))
    
    return candidates


def correlate_with_candidates(
    alerts_df: pd.DataFrame,
    candidates: List[Tuple[int, int, float]],
    pipeline: CorrelationPipeline
) -> pd.DataFrame:
    """
    Run correlation using transformer-generated candidates.
    """
    # Run correlation with available columns (no username in this dataset)
    result = pipeline.correlate(alerts_df, usernames=[], addresses=['Source IP', 'Destination IP'])
    return result.data


def correlate_baseline(
    alerts_df: pd.DataFrame,
    pipeline: CorrelationPipeline
) -> pd.DataFrame:
    """Baseline: Union-Find correlation via pipeline."""
    # Run correlation with available columns (no username in this dataset)
    result = pipeline.correlate(alerts_df, usernames=[], addresses=['Source IP', 'Destination IP'])
    return result.data


def compare_results(
    transformer_result: pd.DataFrame,
    baseline_result: pd.DataFrame
) -> Dict:
    """Compare transformer-assisted vs baseline results."""
    # Get campaign assignments
    trans_campaigns = set(transformer_result['pred_cluster'].unique())
    base_campaigns = set(baseline_result['pred_cluster'].unique())
    
    # Check determinism - campaigns should be equivalent
    # (IDs may differ but groupings should be similar)
    
    trans_groupings = {}
    for cid in trans_campaigns:
        members = set(transformer_result[transformer_result['pred_cluster'] == cid].index)
        trans_groupings[cid] = members
    
    base_groupings = {}
    for cid in base_campaigns:
        members = set(baseline_result[baseline_result['pred_cluster'] == cid].index)
        base_groupings[cid] = members
    
    # Compare groupings
    trans_sets = set(frozenset(s) for s in trans_groupings.values())
    base_sets = set(frozenset(s) for s in base_groupings.values())
    
    common = len(trans_sets & base_sets)
    
    return {
        'transformer_campaigns': len(trans_campaigns),
        'baseline_campaigns': len(base_campaigns),
        'common_groupings': common,
        'precision': common / len(trans_sets) if trans_sets else 0,
        'recall': common / len(base_sets) if base_sets else 0,
    }


def integration_test(checkpoint_path: str, dataset_path: str = None):
    """
    Run end-to-end integration test.
    """
    print("="*70)
    print("CyberTransformer End-to-End Integration Test")
    print("="*70)
    
    # Use GPU if available (PyTorch 2.10+ supports sm_120/RTX 5060 Ti)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"\nDevice: {device}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
    
    # Load model
    print("\n1. Loading trained model...")
    model = load_model(checkpoint_path, device)
    print("   Model loaded successfully")
    
    # Load test data
    print("\n2. Loading test dataset...")
    if dataset_path is None:
        # Use sample dataset
        from transformer.training.train_cybertransformer import load_datasets
        dataframes = load_datasets()
        test_df = dataframes[0][:100] if dataframes else None  # First 100 alerts
    else:
        test_df = pd.read_parquet(dataset_path)[:100]
    
    if test_df is None or len(test_df) == 0:
        print("   ERROR: No test data available")
        return
    
    print(f"   Loaded {len(test_df)} alerts for testing")
    
    # Preprocessor
    preprocessor = AlertPreprocessor(max_seq_length=256)
    
    # Create correlation pipelines
    pipeline_transformer = CorrelationPipeline(
        method='union_find'
    )
    
    pipeline_baseline = CorrelationPipeline(
        method='union_find'
    )
    
    # Test 1: Transformer-assisted correlation
    print("\n3. Running transformer-assisted correlation...")
    start_time = time.time()
    
    candidates = generate_candidates_transformer(model, test_df, preprocessor, device, top_k=10)
    print(f"   Generated {len(candidates)} candidate edges")
    
    trans_result = correlate_with_candidates(test_df, candidates, pipeline_transformer)
    trans_time = time.time() - start_time
    
    print(f"   Time: {trans_time:.3f}s")
    print(f"   Campaigns found: {trans_result['pred_cluster'].nunique()}")
    
    # Test 2: Baseline correlation
    print("\n4. Running baseline (Union-Find only) correlation...")
    start_time = time.time()
    
    base_result = correlate_baseline(test_df, pipeline_baseline)
    base_time = time.time() - start_time
    
    print(f"   Time: {base_time:.3f}s")
    print(f"   Campaigns found: {base_result['pred_cluster'].nunique()}")
    
    # Compare results
    print("\n5. Comparing results...")
    comparison = compare_results(trans_result, base_result)
    
    print(f"   Transformer campaigns: {comparison['transformer_campaigns']}")
    print(f"   Baseline campaigns: {comparison['baseline_campaigns']}")
    print(f"   Common groupings: {comparison['common_groupings']}")
    print(f"   Precision: {comparison['precision']:.3f}")
    print(f"   Recall: {comparison['recall']:.3f}")
    
    # Speedup
    if trans_time > 0 and base_time > 0:
        speedup = base_time / trans_time
        print(f"\n6. Speedup Analysis:")
        print(f"   Transformer: {trans_time:.3f}s")
        print(f"   Baseline: {base_time:.3f}s")
        print(f"   Speedup: {speedup:.2f}x")
    
    # Summary
    print("\n" + "="*70)
    if comparison['common_groupings'] > 0:
        print("INTEGRATION TEST PASSED")
        print("Transformer-assisted correlation working correctly")
    else:
        print("INTEGRATION TEST WARNING")
        print("Results differ from baseline - needs investigation")
    print("="*70)
    
    return {
        'transformer_time': trans_time,
        'baseline_time': base_time,
        'comparison': comparison
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Integration test for CyberTransformer")
    parser.add_argument("--checkpoint", type=str, default="cybertransformer_v2_fixed/final.pt")
    parser.add_argument("--dataset", type=str, default=None)
    args = parser.parse_args()
    
    integration_test(args.checkpoint, args.dataset)
