import pandas as pd
import numpy as np
import sys
import traceback
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_modern_dataset_correlation():
    """Test the enhanced correlation algorithm using modern dataset loader."""
    print("Testing Pipeline with Modern Cybersecurity Datasets...")

    try:
        from core.correlation_indexer import enhanced_correlation
        from training.modern_loader import ModernDatasetLoader
        
        # 1. Initialize modern dataset loader (simulating CIC-IoT or DataSense IIoT)
        loader = ModernDatasetLoader(dataset_type="datasense")
        
        # 2. Generate large synthetic dataset simulating modern traffic patterns
        print("\n[1/3] Generating synthetic modern flow data...")
        # 2000 records for testing
        test_data = loader.load_and_preprocess(file_path="", is_synthetic=True, num_synthetic_records=2000)
        
        print(f"  - Generated {len(test_data)} records.")
        print(f"  - Attacks included: {list(test_data['Attack_Type'].unique())}")
        
        # 3. Setup correlation parameters based on modern schema
        addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
        
        print("\n[2/3] Running Enhanced Correlation (Union-Find + Adaptive Threshold)...")
        start_time = time.time()
        
        # 4. Run correlation on the modern dataset
        result = enhanced_correlation(
            test_data, 
            usernames=usernames, 
            addresses=addresses,
            use_temporal=True, 
            use_adaptive_threshold=True
        )
        
        elapsed = time.time() - start_time
        
        # 5. Evaluate and report
        num_clusters = len(set(result['pred_cluster']))
        print(f"\n[3/3] Correlation Results:")
        print(f"  ✓ Correlation completed in {elapsed:.3f} seconds")
        print(f"  ✓ Input flow records: {len(test_data)}")
        print(f"  ✓ Attack campaigns/clusters found: {num_clusters}")
        
        # Display some cluster statistics
        cluster_counts = result['pred_cluster'].value_counts()
        print(f"  ✓ Largest cluster size: {cluster_counts.max()} records")
        print(f"  ✓ Average cluster size: {cluster_counts.mean():.1f} records")
        
        if 'correlation_threshold_used' in result.columns:
            print(f"  ✓ Adaptive threshold used: {result['correlation_threshold_used'].iloc[0]:.3f}")

        return True

    except Exception as e:
        print(f"\n✗ Testing with modern dataset failed: {e}")
        traceback.print_exc()
        return False

def main():
    print("==================================================")
    print(" MITRE-CORE Modern Dataset Integration Testing ")
    print("==================================================")
    
    success = test_modern_dataset_correlation()
    
    print("\n==================================================")
    if success:
        print(" ✓ Modern Dataset Testing PASSED")
    else:
        print(" ✗ Modern Dataset Testing FAILED")
    print("==================================================")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
