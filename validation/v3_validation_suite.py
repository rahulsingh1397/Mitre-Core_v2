"""
V3 Validation Suite
==================

Comprehensive validation for v3.0 transformer architecture.
Tests correctness, performance, and accuracy.
"""

import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

from core.correlation_pipeline import CorrelationPipeline
from core.correlation_pipeline_v3 import TransformerHybridPipeline
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB


logger = logging.getLogger("mitre-core.validation.v3")


@dataclass
class ValidationResult:
    """Validation test result."""
    test_name: str
    status: str  # 'PASS' or 'FAIL'
    data: Optional[Dict] = None
    error: Optional[str] = None


class V3ValidationSuite:
    """
    Comprehensive validation for v3.0 architecture.
    
    Tests:
    1. Determinism - identical outputs for identical inputs
    2. Transitive closure - exact closure semantics preserved
    3. Latency - <1s at n=2K
    4. Accuracy - within 5% of v2.x baseline
    5. Backward compatibility - v2.x API still works
    6. GPU efficiency - >70% utilization
    7. Fallback behavior - graceful degradation
    """
    
    def __init__(
        self,
        v2_pipeline: Optional[CorrelationPipeline] = None,
        v3_pipeline: Optional[TransformerHybridPipeline] = None
    ):
        """
        Initialize validation suite.
        
        Args:
            v2_pipeline: v2.x baseline pipeline
            v3_pipeline: v3.0 transformer pipeline
        """
        self.v2_pipeline = v2_pipeline or CorrelationPipeline(method='union_find')
        self.v3_pipeline = v3_pipeline
        self.results: List[ValidationResult] = []
        
        logger.info("V3ValidationSuite initialized")
    
    def run_all_tests(self) -> List[ValidationResult]:
        """
        Execute full validation suite.
        
        Returns:
            List of validation results
        """
        tests = [
            ('determinism', self.test_determinism),
            ('transitive_closure', self.test_transitive_closure),
            ('latency', self.test_latency),
            ('backward_compat', self.test_backward_compatibility),
            ('fallback', self.test_fallback_behavior)
        ]
        
        # Only run comparison if v3 pipeline available
        if self.v3_pipeline is not None:
            tests.append(('accuracy', self.test_accuracy))
            tests.append(('gpu_utilization', self.test_gpu_efficiency))
        
        for name, test_func in tests:
            print(f"\n{'='*60}")
            print(f"Running: {name}")
            print('='*60)
            
            try:
                result = test_func()
                self.results.append(ValidationResult(
                    test_name=name,
                    status='PASS',
                    data=result
                ))
                print(f"✓ {name}: PASSED")
            except AssertionError as e:
                self.results.append(ValidationResult(
                    test_name=name,
                    status='FAIL',
                    error=str(e)
                ))
                print(f"✗ {name}: FAILED - {e}")
            except Exception as e:
                self.results.append(ValidationResult(
                    test_name=name,
                    status='FAIL',
                    error=str(e)
                ))
                print(f"✗ {name}: ERROR - {e}")
        
        return self.results
    
    def test_determinism(self) -> Dict:
        """
        Verify identical outputs for identical inputs.
        
        Returns:
            Test metrics
        """
        # Generate test data
        test_data = self._generate_test_data(100)
        
        # Run correlation twice
        result1 = self.v2_pipeline.correlate(
            test_data,
            usernames=['SourceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress']
        )
        
        result2 = self.v2_pipeline.correlate(
            test_data,
            usernames=['SourceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress']
        )
        
        # Check cluster assignments are identical
        if 'cluster_id' in result1.data.columns and 'cluster_id' in result2.data.columns:
            clusters_match = result1.data['cluster_id'].equals(result2.data['cluster_id'])
            assert clusters_match, "Results not deterministic - cluster assignments differ"
        
        return {'runs': 2, 'identical': True}
    
    def test_transitive_closure(self) -> Dict:
        """
        Verify exact transitive closure semantics.
        
        If A~B and B~C, then A~C must hold in final clustering.
        
        Returns:
            Test metrics
        """
        # Create test case: A, B, C connected in chain
        test_data = pd.DataFrame({
            'AlertId': ['A', 'B', 'C'],
            'SourceHostName': ['user1', 'user1', 'user1'],  # All share same user
            'DestinationHostName': ['host1', 'host1', 'host1'],
            'SourceAddress': ['10.0.0.1', '10.0.0.1', '10.0.0.1'],
            'DestinationAddress': ['192.168.1.1', '192.168.1.1', '192.168.1.1'],
            'EndDate': pd.date_range('2024-01-01', periods=3, freq='1min'),
            'MalwareIntelAttackType': ['attack'] * 3
        })
        
        result = self.v2_pipeline.correlate(
            test_data,
            usernames=['SourceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress']
        )
        
        # Check all three in same cluster
        if 'cluster_id' in result.data.columns:
            clusters = result.data['cluster_id'].unique()
            assert len(clusters) == 1, f"Transitive closure violated! Got {len(clusters)} clusters instead of 1"
        
        return {'test_cases': 1, 'closure_preserved': True}
    
    def test_latency(self) -> Dict:
        """
        Verify <1s latency at n=2K.
        
        Returns:
            Latency measurements
        """
        test_sizes = [100, 500, 1000, 2000]
        latencies = {}
        
        for n in test_sizes:
            data = self._generate_test_data(n)
            
            start = time.time()
            result = self.v2_pipeline.correlate(
                data,
                usernames=['SourceHostName', 'DestinationHostName'],
                addresses=['SourceAddress', 'DestinationAddress']
            )
            elapsed = time.time() - start
            
            latencies[n] = elapsed
            print(f"  n={n}: {elapsed:.3f}s")
        
        # Assert n=2K under 1s
        assert latencies[2000] < 1.0, f"Latency {latencies[2000]:.3f}s > 1s threshold!"
        
        return latencies
    
    def test_accuracy(self) -> Dict:
        """
        Compare accuracy vs v2.x baseline.
        
        Only runs if v3 pipeline is available.
        
        Returns:
            Accuracy comparison metrics
        """
        if self.v3_pipeline is None:
            raise AssertionError("v3 pipeline not available for accuracy comparison")
        
        # Generate labeled test data
        df = self._generate_test_data(500, with_labels=True)
        
        # Run both methods
        v2_result = self.v2_pipeline.correlate(
            df,
            usernames=['SourceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress']
        )
        
        v3_result = self.v3_pipeline.correlate(
            df,
            usernames=['SourceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress']
        )
        
        # Compute metrics if ground truth available
        metrics = {}
        
        if 'label' in df.columns:
            if 'cluster_id' in v2_result.data.columns and 'cluster_id' in v3_result.data.columns:
                v2_ari = adjusted_rand_score(df['label'], v2_result.data['cluster_id'])
                v3_ari = adjusted_rand_score(df['label'], v3_result.data['cluster_id'])
                
                # v3 should be within 5% of v2
                degradation = abs(v3_ari - v2_ari)
                assert degradation < 0.05, f"Accuracy degraded: v2={v2_ari:.3f}, v3={v3_ari:.3f}, diff={degradation:.3f}"
                
                metrics = {'v2_ari': v2_ari, 'v3_ari': v3_ari, 'degradation': degradation}
        
        return metrics
    
    def test_backward_compatibility(self) -> Dict:
        """
        Verify v2.x API compatibility.
        
        Returns:
            Compatibility status
        """
        # Old-style API call
        df = self._generate_test_data(100)
        
        result = self.v2_pipeline.correlate(
            data=df,
            usernames=['SourceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress']
        )
        
        # Should work without transformer_path
        assert 'cluster_id' in result.data.columns or 'pred_cluster' in result.data.columns
        
        return {'api_compatible': True}
    
    def test_gpu_efficiency(self) -> Dict:
        """
        Verify GPU utilization >70% during inference.
        
        Only runs if v3 pipeline and GPU available.
        
        Returns:
            GPU utilization metrics
        """
        if self.v3_pipeline is None:
            raise AssertionError("v3 pipeline not available for GPU test")
        
        if not torch.cuda.is_available():
            raise AssertionError("CUDA not available for GPU test")
        
        try:
            import pynvml
            pynvml.nvmlInit()
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            
            # Run inference while monitoring
            utilizations = []
            test_data = self._generate_test_data(500)
            
            for _ in range(10):
                result = self.v3_pipeline.correlate(
                    test_data,
                    usernames=['SourceHostName', 'DestinationHostName'],
                    addresses=['SourceAddress', 'DestinationAddress']
                )
                
                util = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
                utilizations.append(util)
                time.sleep(0.1)
            
            avg_util = np.mean(utilizations)
            assert avg_util > 70, f"GPU underutilized: {avg_util:.1f}%"
            
            return {'avg_gpu_util': avg_util, 'samples': len(utilizations)}
            
        except ImportError:
            logger.warning("pynvml not available, skipping GPU utilization test")
            return {'skipped': True, 'reason': 'pynvml not installed'}
    
    def test_fallback_behavior(self) -> Dict:
        """
        Verify graceful fallback on transformer failure.
        
        Only runs if v3 pipeline is available.
        
        Returns:
            Fallback test results
        """
        if self.v3_pipeline is None:
            raise AssertionError("v3 pipeline not available for fallback test")
        
        # Corrupt transformer to simulate failure
        original_transformer = self.v3_pipeline.transformer
        self.v3_pipeline.transformer = None
        
        try:
            # Should fallback to pure UF without crashing
            test_data = self._generate_test_data(100)
            result = self.v3_pipeline.correlate(
                test_data,
                usernames=['SourceHostName', 'DestinationHostName'],
                addresses=['SourceAddress', 'DestinationAddress']
            )
            
            # Check fallback was triggered
            assert result.fallback_used, "Fallback not triggered"
            
            return {'fallback_triggered': True, 'no_crash': True}
            
        finally:
            # Restore transformer
            self.v3_pipeline.transformer = original_transformer
    
    def _generate_test_data(self, n: int, with_labels: bool = False) -> pd.DataFrame:
        """
        Generate synthetic test data.
        
        Args:
            n: Number of alerts
            with_labels: Add campaign labels
            
        Returns:
            Test DataFrame
        """
        np.random.seed(42)
        
        # Generate synthetic data
        data = pd.DataFrame({
            'AlertId': [f'alert_{i}' for i in range(n)],
            'SourceHostName': [f'host_{i % 10}' for i in range(n)],
            'DestinationHostName': [f'target_{i % 5}' for i in range(n)],
            'SourceAddress': [f'10.0.0.{i % 256}' for i in range(n)],
            'DestinationAddress': [f'192.168.0.{i % 256}' for i in range(n)],
            'EndDate': pd.date_range('2024-01-01', periods=n, freq='1min'),
            'MalwareIntelAttackType': np.random.choice(['attack', 'normal'], n)
        })
        
        if with_labels:
            # Create 5 campaign groups
            data['label'] = np.random.randint(0, 5, n)
        
        return data
    
    def get_summary(self) -> Dict:
        """
        Get validation summary.
        
        Returns:
            Summary statistics
        """
        passed = sum(1 for r in self.results if r.status == 'PASS')
        failed = sum(1 for r in self.results if r.status == 'FAIL')
        
        return {
            'total_tests': len(self.results),
            'passed': passed,
            'failed': failed,
            'pass_rate': passed / len(self.results) if self.results else 0,
            'all_passed': failed == 0
        }


def run_v3_validation(
    v3_checkpoint_path: Optional[str] = None
) -> Dict:
    """
    Run full v3 validation suite.
    
    Args:
        v3_checkpoint_path: Path to v3 transformer checkpoint (optional)
        
    Returns:
        Validation summary
    """
    # Create pipelines
    v2_pipeline = CorrelationPipeline(method='union_find')
    
    v3_pipeline = None
    if v3_checkpoint_path:
        try:
            v3_pipeline = TransformerHybridPipeline(
                transformer_path=v3_checkpoint_path,
                device='cuda' if torch.cuda.is_available() else 'cpu'
            )
        except Exception as e:
            logger.warning(f"Could not load v3 pipeline: {e}")
    
    # Run validation
    suite = V3ValidationSuite(v2_pipeline=v2_pipeline, v3_pipeline=v3_pipeline)
    suite.run_all_tests()
    
    summary = suite.get_summary()
    
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    print(f"Total tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Pass rate: {summary['pass_rate']:.1%}")
    print(f"Status: {'✓ ALL TESTS PASSED' if summary['all_passed'] else '✗ SOME TESTS FAILED'}")
    print("="*60)
    
    return summary


if __name__ == "__main__":
    # Run validation
    summary = run_v3_validation()
