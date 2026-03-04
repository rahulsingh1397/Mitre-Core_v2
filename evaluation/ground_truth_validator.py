"""
Ground Truth Validation System for MITRE-CORE
Provides comprehensive validation of clustering results against known ground truth
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import logging
from sklearn.metrics import (
    adjusted_rand_score, normalized_mutual_info_score, 
    homogeneity_score, completeness_score, v_measure_score,
    fowlkes_mallows_score, silhouette_score
)
from scipy.optimize import linear_sum_assignment
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns

class GroundTruthValidator:
    """Comprehensive ground truth validation system"""
    
    def __init__(self, log_level: str = 'INFO'):
        self.logger = logging.getLogger('GroundTruthValidator')
        self.logger.setLevel(getattr(logging, log_level))
        
        # Create handler if not exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def validate_clustering_results(self, predicted_clusters: np.ndarray, 
                                  ground_truth: np.ndarray,
                                  method_name: str = "Unknown",
                                  detailed_analysis: bool = True) -> Dict[str, Any]:
        """
        Comprehensive validation of clustering results
        
        Args:
            predicted_clusters: Predicted cluster labels
            ground_truth: True cluster labels
            method_name: Name of clustering method for reporting
            detailed_analysis: Whether to perform detailed cluster-by-cluster analysis
            
        Returns:
            Dictionary containing all validation metrics and analysis
        """
        
        self.logger.info(f"Validating clustering results for method: {method_name}")
        
        # Basic validation
        if len(predicted_clusters) != len(ground_truth):
            raise ValueError("Predicted clusters and ground truth must have same length")
        
        # Remove noise points from ground truth for certain metrics
        valid_mask = ground_truth >= 0
        pred_valid = predicted_clusters[valid_mask]
        gt_valid = ground_truth[valid_mask]
        
        results = {
            'method_name': method_name,
            'total_samples': len(predicted_clusters),
            'valid_samples': len(pred_valid),
            'noise_samples': len(predicted_clusters) - len(pred_valid)
        }
        
        # External validation metrics (comparing to ground truth)
        results.update(self._calculate_external_metrics(pred_valid, gt_valid))
        
        # Internal validation metrics (cluster quality without ground truth)
        if hasattr(self, 'feature_matrix') and self.feature_matrix is not None:
            results.update(self._calculate_internal_metrics(predicted_clusters, self.feature_matrix))
        
        # Detailed cluster analysis
        if detailed_analysis:
            results['cluster_analysis'] = self._analyze_cluster_quality(
                pred_valid, gt_valid, method_name
            )
        
        # Statistical significance testing
        results['statistical_tests'] = self._perform_statistical_tests(
            pred_valid, gt_valid
        )
        
        self.logger.info(f"Validation completed for {method_name}")
        return results
    
    def _calculate_external_metrics(self, predicted: np.ndarray, 
                                   ground_truth: np.ndarray) -> Dict[str, float]:
        """Calculate external validation metrics"""
        
        if len(predicted) == 0 or len(ground_truth) == 0:
            return {
                'adjusted_rand_score': 0.0,
                'normalized_mutual_info': 0.0,
                'homogeneity_score': 0.0,
                'completeness_score': 0.0,
                'v_measure_score': 0.0,
                'fowlkes_mallows_score': 0.0
            }
        
        try:
            return {
                'adjusted_rand_score': adjusted_rand_score(ground_truth, predicted),
                'normalized_mutual_info': normalized_mutual_info_score(ground_truth, predicted),
                'homogeneity_score': homogeneity_score(ground_truth, predicted),
                'completeness_score': completeness_score(ground_truth, predicted),
                'v_measure_score': v_measure_score(ground_truth, predicted),
                'fowlkes_mallows_score': fowlkes_mallows_score(ground_truth, predicted)
            }
        except Exception as e:
            self.logger.warning(f"Error calculating external metrics: {e}")
            return {metric: 0.0 for metric in [
                'adjusted_rand_score', 'normalized_mutual_info', 'homogeneity_score',
                'completeness_score', 'v_measure_score', 'fowlkes_mallows_score'
            ]}
    
    def _calculate_internal_metrics(self, predicted: np.ndarray, 
                                   feature_matrix: np.ndarray) -> Dict[str, float]:
        """Calculate internal validation metrics"""
        
        try:
            # Only calculate if we have multiple clusters
            if len(set(predicted)) > 1:
                silhouette = silhouette_score(feature_matrix, predicted)
            else:
                silhouette = -1.0
            
            return {
                'silhouette_score': silhouette,
                'num_clusters': len(set(predicted)),
                'largest_cluster_size': max(np.bincount(predicted)),
                'smallest_cluster_size': min(np.bincount(predicted))
            }
        except Exception as e:
            self.logger.warning(f"Error calculating internal metrics: {e}")
            return {
                'silhouette_score': -1.0,
                'num_clusters': len(set(predicted)),
                'largest_cluster_size': 0,
                'smallest_cluster_size': 0
            }
    
    def _analyze_cluster_quality(self, predicted: np.ndarray, 
                                ground_truth: np.ndarray, 
                                method_name: str) -> Dict[str, Any]:
        """Detailed cluster-by-cluster analysis"""
        
        analysis = {
            'confusion_matrix': self._create_confusion_matrix(predicted, ground_truth),
            'cluster_purity': self._calculate_cluster_purity(predicted, ground_truth),
            'cluster_completeness': self._calculate_cluster_completeness(predicted, ground_truth),
            'optimal_mapping': self._find_optimal_cluster_mapping(predicted, ground_truth)
        }
        
        return analysis
    
    def _create_confusion_matrix(self, predicted: np.ndarray, 
                                ground_truth: np.ndarray) -> np.ndarray:
        """Create confusion matrix between predicted and ground truth clusters"""
        
        pred_unique = sorted(set(predicted))
        gt_unique = sorted(set(ground_truth))
        
        confusion_matrix = np.zeros((len(pred_unique), len(gt_unique)))
        
        for i, pred_cluster in enumerate(pred_unique):
            for j, gt_cluster in enumerate(gt_unique):
                confusion_matrix[i, j] = np.sum(
                    (predicted == pred_cluster) & (ground_truth == gt_cluster)
                )
        
        return confusion_matrix
    
    def _calculate_cluster_purity(self, predicted: np.ndarray, 
                                 ground_truth: np.ndarray) -> Dict[int, float]:
        """Calculate purity for each predicted cluster"""
        
        purity = {}
        for cluster in set(predicted):
            cluster_mask = predicted == cluster
            if np.sum(cluster_mask) == 0:
                purity[cluster] = 0.0
                continue
            
            gt_in_cluster = ground_truth[cluster_mask]
            most_common_gt = np.bincount(gt_in_cluster).argmax()
            purity[cluster] = np.sum(gt_in_cluster == most_common_gt) / len(gt_in_cluster)
        
        return purity
    
    def _calculate_cluster_completeness(self, predicted: np.ndarray, 
                                       ground_truth: np.ndarray) -> Dict[int, float]:
        """Calculate completeness for each ground truth cluster"""
        
        completeness = {}
        for gt_cluster in set(ground_truth):
            gt_mask = ground_truth == gt_cluster
            if np.sum(gt_mask) == 0:
                completeness[gt_cluster] = 0.0
                continue
            
            pred_in_gt = predicted[gt_mask]
            most_common_pred = np.bincount(pred_in_gt).argmax()
            completeness[gt_cluster] = np.sum(pred_in_gt == most_common_pred) / len(pred_in_gt)
        
        return completeness
    
    def _find_optimal_cluster_mapping(self, predicted: np.ndarray, 
                                     ground_truth: np.ndarray) -> Dict[str, Any]:
        """Find optimal mapping between predicted and ground truth clusters"""
        
        confusion_matrix = self._create_confusion_matrix(predicted, ground_truth)
        
        # Use Hungarian algorithm to find optimal assignment
        row_ind, col_ind = linear_sum_assignment(-confusion_matrix)
        
        pred_unique = sorted(set(predicted))
        gt_unique = sorted(set(ground_truth))
        
        mapping = {}
        total_correct = 0
        
        for i, j in zip(row_ind, col_ind):
            if i < len(pred_unique) and j < len(gt_unique):
                mapping[pred_unique[i]] = gt_unique[j]
                total_correct += confusion_matrix[i, j]
        
        accuracy = total_correct / len(predicted) if len(predicted) > 0 else 0.0
        
        return {
            'mapping': mapping,
            'accuracy': accuracy,
            'total_correct': int(total_correct)
        }
    
    def _perform_statistical_tests(self, predicted: np.ndarray, 
                                  ground_truth: np.ndarray) -> Dict[str, Any]:
        """Perform statistical significance tests"""
        
        from scipy.stats import chi2_contingency
        
        try:
            # Chi-square test for independence
            confusion_matrix = self._create_confusion_matrix(predicted, ground_truth)
            chi2, p_value, dof, expected = chi2_contingency(confusion_matrix)
            
            return {
                'chi2_statistic': chi2,
                'chi2_p_value': p_value,
                'degrees_of_freedom': dof,
                'is_significant': p_value < 0.05
            }
        except Exception as e:
            self.logger.warning(f"Error in statistical tests: {e}")
            return {
                'chi2_statistic': 0.0,
                'chi2_p_value': 1.0,
                'degrees_of_freedom': 0,
                'is_significant': False
            }
    
    def compare_methods(self, results_dict: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
        """Compare multiple clustering methods"""
        
        comparison_data = []
        
        for method_name, results in results_dict.items():
            row = {
                'Method': method_name,
                'ARI': results.get('adjusted_rand_score', 0.0),
                'NMI': results.get('normalized_mutual_info', 0.0),
                'Homogeneity': results.get('homogeneity_score', 0.0),
                'Completeness': results.get('completeness_score', 0.0),
                'V-Measure': results.get('v_measure_score', 0.0),
                'Fowlkes-Mallows': results.get('fowlkes_mallows_score', 0.0),
                'Silhouette': results.get('silhouette_score', -1.0),
                'Num_Clusters': results.get('num_clusters', 0),
                'Accuracy': results.get('cluster_analysis', {}).get('optimal_mapping', {}).get('accuracy', 0.0)
            }
            comparison_data.append(row)
        
        comparison_df = pd.DataFrame(comparison_data)
        
        # Rank methods
        metrics_to_rank = ['ARI', 'NMI', 'Homogeneity', 'Completeness', 'V-Measure', 
                          'Fowlkes-Mallows', 'Silhouette', 'Accuracy']
        
        for metric in metrics_to_rank:
            if metric in comparison_df.columns:
                comparison_df[f'{metric}_Rank'] = comparison_df[metric].rank(ascending=False)
        
        # Calculate average rank
        rank_columns = [col for col in comparison_df.columns if col.endswith('_Rank')]
        comparison_df['Average_Rank'] = comparison_df[rank_columns].mean(axis=1)
        comparison_df = comparison_df.sort_values('Average_Rank')
        
        return comparison_df
    
    def generate_validation_report(self, results_dict: Dict[str, Dict[str, Any]], 
                                  output_path: Optional[str] = None) -> str:
        """Generate comprehensive validation report"""
        
        report = []
        report.append("# MITRE-CORE Clustering Validation Report")
        report.append("=" * 50)
        report.append("")
        
        # Method comparison
        comparison_df = self.compare_methods(results_dict)
        report.append("## Method Comparison Summary")
        report.append(comparison_df.to_string(index=False, float_format='%.3f'))
        report.append("")
        
        # Detailed results for each method
        for method_name, results in results_dict.items():
            report.append(f"## Detailed Results: {method_name}")
            report.append("-" * 30)
            
            # Basic metrics
            report.append(f"- Total Samples: {results.get('total_samples', 0)}")
            report.append(f"- Valid Samples: {results.get('valid_samples', 0)}")
            report.append(f"- Noise Samples: {results.get('noise_samples', 0)}")
            report.append(f"- Number of Clusters: {results.get('num_clusters', 0)}")
            report.append("")
            
            # External metrics
            report.append("### External Validation Metrics:")
            external_metrics = [
                ('Adjusted Rand Index', 'adjusted_rand_score'),
                ('Normalized Mutual Information', 'normalized_mutual_info'),
                ('Homogeneity Score', 'homogeneity_score'),
                ('Completeness Score', 'completeness_score'),
                ('V-Measure Score', 'v_measure_score'),
                ('Fowlkes-Mallows Score', 'fowlkes_mallows_score')
            ]
            
            for metric_name, metric_key in external_metrics:
                value = results.get(metric_key, 0.0)
                report.append(f"- {metric_name}: {value:.3f}")
            report.append("")
            
            # Statistical significance
            if 'statistical_tests' in results:
                stats = results['statistical_tests']
                report.append("### Statistical Significance:")
                report.append(f"- Chi-square statistic: {stats.get('chi2_statistic', 0.0):.3f}")
                report.append(f"- P-value: {stats.get('chi2_p_value', 1.0):.3f}")
                report.append(f"- Statistically significant: {stats.get('is_significant', False)}")
                report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        report.append("-" * 20)
        best_method = comparison_df.iloc[0]['Method']
        best_ari = comparison_df.iloc[0]['ARI']
        
        report.append(f"- Best performing method: {best_method} (ARI: {best_ari:.3f})")
        
        if best_ari < 0.5:
            report.append("- WARNING: Low clustering quality detected. Consider:")
            report.append("  * Adjusting algorithm parameters")
            report.append("  * Using different feature representations")
            report.append("  * Collecting more training data")
        elif best_ari < 0.7:
            report.append("- Moderate clustering quality. Consider parameter tuning for improvement.")
        else:
            report.append("- Good clustering quality achieved.")
        
        report.append("")
        
        report_text = "\n".join(report)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report_text)
            self.logger.info(f"Validation report saved to: {output_path}")
        
        return report_text
    
    def set_feature_matrix(self, feature_matrix: np.ndarray):
        """Set feature matrix for internal validation metrics"""
        self.feature_matrix = feature_matrix


# Example usage and testing
if __name__ == "__main__":
    # Create validator
    validator = GroundTruthValidator()
    
    # Example synthetic data
    np.random.seed(42)
    n_samples = 100
    
    # Create ground truth with 3 clusters
    ground_truth = np.array([0] * 30 + [1] * 35 + [2] * 25 + [-1] * 10)  # Include noise
    
    # Create predicted clusters (with some errors)
    predicted = ground_truth.copy()
    # Add some classification errors
    error_indices = np.random.choice(90, 10, replace=False)  # Don't change noise points
    predicted[error_indices] = np.random.choice([0, 1, 2], 10)
    
    # Validate results
    results = validator.validate_clustering_results(
        predicted, ground_truth, "Example Method"
    )
    
    print("Validation Results:")
    for key, value in results.items():
        if not isinstance(value, dict):
            print(f"{key}: {value}")
    
    print(f"\nAdjusted Rand Index: {results['adjusted_rand_score']:.3f}")
    print(f"Homogeneity: {results['homogeneity_score']:.3f}")
    print(f"Completeness: {results['completeness_score']:.3f}")
