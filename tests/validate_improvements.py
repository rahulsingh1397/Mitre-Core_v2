"""
Simple validation script to test MITRE-CORE improvements
"""

import pandas as pd
import numpy as np
import sys
import traceback

def test_enhanced_correlation():
    """Test the enhanced correlation algorithm"""
    print("Testing Enhanced Correlation Algorithm...")
    
    try:
        from core.correlation_indexer import enhanced_correlation
        
        # Create simple test data
        test_data = pd.DataFrame({
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
        
        # Test enhanced correlation
        result = enhanced_correlation(test_data, usernames, addresses, 
                                    use_temporal=False, use_adaptive_threshold=True)
        
        print(f"✓ Enhanced correlation successful!")
        print(f"  - Input samples: {len(test_data)}")
        print(f"  - Output samples: {len(result)}")
        print(f"  - Clusters found: {len(set(result['pred_cluster']))}")
        print(f"  - Threshold used: {result['correlation_threshold_used'].iloc[0]:.3f}")
        
        return True
        
    except Exception as e:
        print(f"✗ Enhanced correlation failed: {e}")
        traceback.print_exc()
        return False

def test_baseline_methods():
    """Test baseline clustering methods"""
    print("\nTesting Baseline Methods...")
    
    try:
        from baselines.simple_clustering import SimpleBaselineCorrelator
        
        # Create test data
        test_data = pd.DataFrame({
            'SourceAddress': ['192.168.1.1', '192.168.1.2', '10.0.0.1', '192.168.1.1'],
            'DestinationAddress': ['10.0.0.1', '10.0.0.2', '192.168.1.1', '10.0.0.1'],
            'DeviceAddress': ['172.16.1.1', '172.16.1.1', '172.16.2.1', '172.16.1.1'],
            'SourceHostName': ['host1', 'host2', 'host3', 'host1'],
            'DeviceHostName': ['device1', 'device1', 'device2', 'device1'],
            'DestinationHostName': ['target1', 'target2', 'target3', 'target1']
        })
        
        addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
        
        correlator = SimpleBaselineCorrelator()
        
        # Test DBSCAN
        dbscan_result = correlator.dbscan_correlation(test_data, addresses, usernames, auto_tune=False)
        print(f"✓ DBSCAN: {len(set(dbscan_result['pred_cluster']))} clusters")
        
        # Test K-means
        kmeans_result = correlator.kmeans_correlation(test_data, addresses, usernames, auto_tune=False)
        print(f"✓ K-means: {len(set(kmeans_result['pred_cluster']))} clusters")
        
        return True
        
    except Exception as e:
        print(f"✗ Baseline methods failed: {e}")
        traceback.print_exc()
        return False

def test_evaluation_metrics():
    """Test evaluation framework"""
    print("\nTesting Evaluation Framework...")
    
    try:
        from evaluation.metrics import CorrelationEvaluator
        
        evaluator = CorrelationEvaluator()
        
        # Create simple test data
        predicted = np.array([0, 0, 1, 1, 2])
        ground_truth = np.array([0, 0, 1, 1, 2])
        
        metrics = evaluator.calculate_clustering_metrics(predicted, ground_truth)
        
        print(f"✓ Evaluation metrics calculated:")
        print(f"  - ARI: {metrics['adjusted_rand_score']:.3f}")
        print(f"  - NMI: {metrics['normalized_mutual_info']:.3f}")
        
        return True
        
    except Exception as e:
        print(f"✗ Evaluation framework failed: {e}")
        traceback.print_exc()
        return False

def test_ground_truth_validator():
    """Test ground truth validation"""
    print("\nTesting Ground Truth Validator...")
    
    try:
        from evaluation.ground_truth_validator import GroundTruthValidator
        
        validator = GroundTruthValidator()
        
        # Create test data
        predicted = np.array([0, 0, 1, 1, 2])
        ground_truth = np.array([0, 0, 1, 1, 2])
        
        results = validator.validate_clustering_results(predicted, ground_truth, "Test Method")
        
        print(f"✓ Ground truth validation successful:")
        print(f"  - ARI: {results['adjusted_rand_score']:.3f}")
        print(f"  - Method: {results['method_name']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Ground truth validator failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all validation tests"""
    print("MITRE-CORE Improvements Validation")
    print("=" * 40)
    
    tests = [
        test_enhanced_correlation,
        test_baseline_methods,
        test_evaluation_metrics,
        test_ground_truth_validator
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\nValidation Summary:")
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All improvements validated successfully!")
        print("MITRE-CORE is ready for research paper preparation.")
    else:
        print("✗ Some tests failed. Review errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
