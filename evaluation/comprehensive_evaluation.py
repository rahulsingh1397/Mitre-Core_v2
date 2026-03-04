"""
Comprehensive Evaluation System for MITRE-CORE
Integrates all evaluation components for complete validation
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import logging
import time
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import CorrelationEvaluator, DatasetGenerator
from evaluation.ground_truth_validator import GroundTruthValidator
from baselines.simple_clustering import run_all_baselines
from core.correlation_indexer import enhanced_correlation
import Testing

class ComprehensiveEvaluator:
    """Complete evaluation system for MITRE-CORE research validation"""
    
    def __init__(self, log_level: str = 'INFO'):
        self.logger = logging.getLogger('ComprehensiveEvaluator')
        self.logger.setLevel(getattr(logging, log_level))
        
        # Create handler if not exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # Initialize components
        self.correlation_evaluator = CorrelationEvaluator()
        self.ground_truth_validator = GroundTruthValidator()
        self.dataset_generator = DatasetGenerator()
        
        # Standard field definitions
        self.addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        self.usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']
    
    def run_complete_evaluation(self, 
                               test_datasets: Optional[List[Tuple[pd.DataFrame, np.ndarray]]] = None,
                               include_synthetic: bool = True,
                               synthetic_configs: Optional[List[Dict]] = None,
                               save_results: bool = True,
                               output_dir: str = "evaluation_results") -> Dict[str, Any]:
        """
        Run complete evaluation including synthetic and provided datasets
        
        Args:
            test_datasets: List of (dataframe, ground_truth) tuples
            include_synthetic: Whether to generate and test synthetic datasets
            synthetic_configs: Configurations for synthetic dataset generation
            save_results: Whether to save detailed results
            output_dir: Directory to save results
            
        Returns:
            Complete evaluation results
        """
        
        self.logger.info("Starting comprehensive evaluation")
        start_time = time.time()
        
        # Create output directory
        if save_results:
            os.makedirs(output_dir, exist_ok=True)
        
        all_results = {
            'evaluation_metadata': {
                'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'datasets_tested': 0,
                'methods_compared': 0
            },
            'dataset_results': [],
            'method_comparison': {},
            'statistical_summary': {},
            'recommendations': []
        }
        
        # Prepare test datasets
        datasets_to_test = []
        
        # Add provided datasets
        if test_datasets:
            for i, (df, gt) in enumerate(test_datasets):
                datasets_to_test.append({
                    'name': f'provided_dataset_{i}',
                    'data': df,
                    'ground_truth': gt,
                    'type': 'provided'
                })
        
        # Add synthetic datasets
        if include_synthetic:
            if synthetic_configs is None:
                synthetic_configs = [
                    {'num_campaigns': 5, 'campaign_sizes': [3, 4, 5], 'noise_level': 0.1},
                    {'num_campaigns': 10, 'campaign_sizes': [3, 5, 8], 'noise_level': 0.15},
                    {'num_campaigns': 15, 'campaign_sizes': [4, 6, 10], 'noise_level': 0.2}
                ]
            
            for i, config in enumerate(synthetic_configs):
                self.logger.info(f"Generating synthetic dataset {i+1}")
                df, gt = self.dataset_generator.create_evaluation_dataset(**config)
                datasets_to_test.append({
                    'name': f'synthetic_dataset_{i}',
                    'data': df,
                    'ground_truth': gt,
                    'type': 'synthetic',
                    'config': config
                })
        
        # Add Testing.py generated dataset
        try:
            self.logger.info("Generating Testing.py dataset")
            test_df = Testing.build_data(50)  # Generate 50 samples
            # Create simple ground truth based on IP similarity
            test_gt = self._create_simple_ground_truth(test_df)
            datasets_to_test.append({
                'name': 'testing_py_dataset',
                'data': test_df,
                'ground_truth': test_gt,
                'type': 'testing_py'
            })
        except Exception as e:
            self.logger.warning(f"Could not generate Testing.py dataset: {e}")
        
        all_results['evaluation_metadata']['datasets_tested'] = len(datasets_to_test)
        
        # Test each dataset
        method_results_aggregated = {}
        
        for dataset_info in datasets_to_test:
            self.logger.info(f"Evaluating dataset: {dataset_info['name']}")
            
            dataset_results = self._evaluate_single_dataset(
                dataset_info['data'], 
                dataset_info['ground_truth'],
                dataset_info['name']
            )
            
            dataset_results['dataset_info'] = dataset_info
            all_results['dataset_results'].append(dataset_results)
            
            # Aggregate method results
            for method_name, method_result in dataset_results['method_results'].items():
                if method_name not in method_results_aggregated:
                    method_results_aggregated[method_name] = []
                method_results_aggregated[method_name].append(method_result)
        
        # Calculate aggregated statistics
        all_results['method_comparison'] = self._aggregate_method_results(method_results_aggregated)
        all_results['statistical_summary'] = self._calculate_statistical_summary(method_results_aggregated)
        all_results['recommendations'] = self._generate_recommendations(all_results['method_comparison'])
        
        # Update metadata
        all_results['evaluation_metadata']['methods_compared'] = len(method_results_aggregated)
        all_results['evaluation_metadata']['total_time'] = time.time() - start_time
        all_results['evaluation_metadata']['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Save results
        if save_results:
            self._save_evaluation_results(all_results, output_dir)
        
        self.logger.info(f"Comprehensive evaluation completed in {all_results['evaluation_metadata']['total_time']:.2f} seconds")
        return all_results
    
    def _evaluate_single_dataset(self, data: pd.DataFrame, ground_truth: np.ndarray, 
                                dataset_name: str) -> Dict[str, Any]:
        """Evaluate all methods on a single dataset"""
        
        results = {
            'dataset_name': dataset_name,
            'dataset_stats': {
                'num_samples': len(data),
                'num_true_clusters': len(set(ground_truth[ground_truth >= 0])),
                'num_noise_points': np.sum(ground_truth == -1),
                'features': list(data.columns)
            },
            'method_results': {}
        }
        
        # Test MITRE-CORE enhanced correlation
        try:
            self.logger.info("Testing MITRE-CORE enhanced correlation")
            mitre_result = enhanced_correlation(
                data, self.usernames, self.addresses,
                use_temporal=True, use_adaptive_threshold=True
            )
            mitre_clusters = mitre_result['pred_cluster'].values
            
            # Validate against ground truth
            validation_result = self.ground_truth_validator.validate_clustering_results(
                mitre_clusters, ground_truth, "MITRE-CORE Enhanced"
            )
            results['method_results']['MITRE-CORE Enhanced'] = validation_result
            
        except Exception as e:
            self.logger.error(f"Error testing MITRE-CORE: {e}")
            results['method_results']['MITRE-CORE Enhanced'] = {'error': str(e)}
        
        # Test baseline methods
        try:
            self.logger.info("Testing baseline methods")
            baseline_results = run_all_baselines(data, self.addresses, self.usernames)
            
            for method_name, method_result in baseline_results.items():
                try:
                    method_clusters = method_result['pred_cluster'].values
                    validation_result = self.ground_truth_validator.validate_clustering_results(
                        method_clusters, ground_truth, method_name
                    )
                    results['method_results'][method_name] = validation_result
                except Exception as e:
                    self.logger.warning(f"Error validating {method_name}: {e}")
                    results['method_results'][method_name] = {'error': str(e)}
                    
        except Exception as e:
            self.logger.error(f"Error running baseline methods: {e}")
        
        return results
    
    def _create_simple_ground_truth(self, data: pd.DataFrame) -> np.ndarray:
        """Create simple ground truth based on IP address similarity"""
        
        ground_truth = np.zeros(len(data))
        current_cluster = 0
        processed = set()
        
        for i, row in data.iterrows():
            if i in processed:
                continue
                
            # Find all rows with same source IP subnet
            source_ip = str(row['SourceAddress'])
            subnet = '.'.join(source_ip.split('.')[:3]) if '.' in source_ip else source_ip
            
            cluster_members = []
            for j, other_row in data.iterrows():
                if j not in processed:
                    other_source = str(other_row['SourceAddress'])
                    other_subnet = '.'.join(other_source.split('.')[:3]) if '.' in other_source else other_source
                    
                    if subnet == other_subnet:
                        cluster_members.append(j)
            
            # Assign cluster
            for member in cluster_members:
                ground_truth[member] = current_cluster
                processed.add(member)
            
            current_cluster += 1
        
        return ground_truth.astype(int)
    
    def _aggregate_method_results(self, method_results: Dict[str, List[Dict]]) -> Dict[str, Dict]:
        """Aggregate results across datasets for each method"""
        
        aggregated = {}
        
        for method_name, results_list in method_results.items():
            # Filter out error results
            valid_results = [r for r in results_list if 'error' not in r]
            
            if not valid_results:
                aggregated[method_name] = {'error': 'No valid results'}
                continue
            
            # Calculate means and standard deviations
            metrics_to_aggregate = [
                'adjusted_rand_score', 'normalized_mutual_info', 'homogeneity_score',
                'completeness_score', 'v_measure_score', 'fowlkes_mallows_score',
                'silhouette_score'
            ]
            
            aggregated[method_name] = {}
            
            for metric in metrics_to_aggregate:
                values = [r.get(metric, 0.0) for r in valid_results]
                if values:
                    aggregated[method_name][f'{metric}_mean'] = np.mean(values)
                    aggregated[method_name][f'{metric}_std'] = np.std(values)
                    aggregated[method_name][f'{metric}_min'] = np.min(values)
                    aggregated[method_name][f'{metric}_max'] = np.max(values)
            
            # Count statistics
            aggregated[method_name]['num_datasets'] = len(valid_results)
            aggregated[method_name]['success_rate'] = len(valid_results) / len(results_list)
        
        return aggregated
    
    def _calculate_statistical_summary(self, method_results: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Calculate statistical summary across all methods and datasets"""
        
        summary = {
            'best_method_by_metric': {},
            'method_rankings': {},
            'statistical_significance': {}
        }
        
        # Find best method for each metric
        metrics = ['adjusted_rand_score', 'normalized_mutual_info', 'homogeneity_score']
        
        for metric in metrics:
            best_score = -1
            best_method = None
            
            for method_name, results_list in method_results.items():
                valid_results = [r for r in results_list if 'error' not in r]
                if valid_results:
                    avg_score = np.mean([r.get(metric, 0.0) for r in valid_results])
                    if avg_score > best_score:
                        best_score = avg_score
                        best_method = method_name
            
            summary['best_method_by_metric'][metric] = {
                'method': best_method,
                'score': best_score
            }
        
        return summary
    
    def _generate_recommendations(self, method_comparison: Dict[str, Dict]) -> List[str]:
        """Generate recommendations based on evaluation results"""
        
        recommendations = []
        
        # Find overall best method
        best_method = None
        best_ari = -1
        
        for method_name, results in method_comparison.items():
            if 'error' not in results:
                ari_mean = results.get('adjusted_rand_score_mean', 0.0)
                if ari_mean > best_ari:
                    best_ari = ari_mean
                    best_method = method_name
        
        if best_method:
            recommendations.append(f"Best performing method: {best_method} (ARI: {best_ari:.3f})")
            
            if best_ari < 0.3:
                recommendations.append("CRITICAL: Very low clustering quality detected")
                recommendations.append("Consider fundamental algorithm redesign or feature engineering")
            elif best_ari < 0.5:
                recommendations.append("WARNING: Low clustering quality")
                recommendations.append("Recommend parameter tuning and feature improvement")
            elif best_ari < 0.7:
                recommendations.append("Moderate clustering quality - room for improvement")
            else:
                recommendations.append("Good clustering quality achieved")
        
        # Check for consistency across datasets
        mitre_results = method_comparison.get('MITRE-CORE Enhanced', {})
        if 'adjusted_rand_score_std' in mitre_results:
            std_dev = mitre_results['adjusted_rand_score_std']
            if std_dev > 0.2:
                recommendations.append("High variance in MITRE-CORE performance across datasets")
                recommendations.append("Consider more robust parameter selection")
        
        return recommendations
    
    def _save_evaluation_results(self, results: Dict[str, Any], output_dir: str):
        """Save comprehensive evaluation results"""
        
        import json
        
        # Save main results as JSON
        results_file = os.path.join(output_dir, 'comprehensive_evaluation_results.json')
        
        # Convert numpy types to Python types for JSON serialization
        def convert_numpy(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            return obj
        
        # Deep convert all numpy types
        def deep_convert(obj):
            if isinstance(obj, dict):
                return {key: deep_convert(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [deep_convert(item) for item in obj]
            else:
                return convert_numpy(obj)
        
        serializable_results = deep_convert(results)
        
        with open(results_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        # Generate and save validation report
        method_results = {}
        for dataset_result in results['dataset_results']:
            for method_name, method_result in dataset_result['method_results'].items():
                if 'error' not in method_result:
                    if method_name not in method_results:
                        method_results[method_name] = method_result
        
        if method_results:
            report = self.ground_truth_validator.generate_validation_report(
                method_results, 
                os.path.join(output_dir, 'validation_report.md')
            )
        
        self.logger.info(f"Evaluation results saved to: {output_dir}")


# Example usage and testing
if __name__ == "__main__":
    # Create comprehensive evaluator
    evaluator = ComprehensiveEvaluator()
    
    # Run complete evaluation
    results = evaluator.run_complete_evaluation(
        include_synthetic=True,
        save_results=True,
        output_dir="evaluation_results"
    )
    
    print("Comprehensive Evaluation Completed!")
    print(f"Datasets tested: {results['evaluation_metadata']['datasets_tested']}")
    print(f"Methods compared: {results['evaluation_metadata']['methods_compared']}")
    print(f"Total time: {results['evaluation_metadata']['total_time']:.2f} seconds")
    
    # Print recommendations
    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"- {rec}")
