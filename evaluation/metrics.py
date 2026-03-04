"""
Evaluation framework for MITRE-CORE research paper
Provides comprehensive metrics and statistical analysis tools
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    adjusted_rand_score, normalized_mutual_info_score, silhouette_score
)
from scipy.stats import ttest_rel
from typing import Dict, List, Tuple, Optional
import time
import logging

class CorrelationEvaluator:
    """Comprehensive evaluation framework for alert correlation methods"""
    
    def __init__(self):
        self.results_history = []
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Setup logging for evaluation experiments"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('CorrelationEvaluator')
    
    def calculate_clustering_metrics(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
        """Calculate standard clustering evaluation metrics"""
        try:
            metrics = {
                'adjusted_rand_score': adjusted_rand_score(y_true, y_pred),
                'normalized_mutual_info': normalized_mutual_info_score(y_true, y_pred),
                'accuracy': accuracy_score(y_true, y_pred) if len(set(y_true)) == len(set(y_pred)) else 0.0
            }
            
            # Add precision, recall, F1 if applicable
            if len(set(y_true)) == len(set(y_pred)):
                metrics.update({
                    'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
                    'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
                    'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
                })
            
            return metrics
        except Exception as e:
            self.logger.error(f"Error calculating metrics: {e}")
            return {'error': str(e)}
    
    def calculate_silhouette_score(self, X: np.ndarray, labels: np.ndarray) -> float:
        """Calculate silhouette score for clustering quality"""
        try:
            if len(set(labels)) > 1:
                return silhouette_score(X, labels)
            else:
                return 0.0
        except Exception as e:
            self.logger.error(f"Error calculating silhouette score: {e}")
            return 0.0
    
    def performance_timing(self, func, *args, **kwargs) -> Tuple[any, float]:
        """Measure execution time of correlation function"""
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        
        self.logger.info(f"Function {func.__name__} executed in {execution_time:.4f} seconds")
        return result, execution_time
    
    def statistical_significance_test(self, method1_scores: List[float], 
                                    method2_scores: List[float]) -> Dict[str, float]:
        """Perform paired t-test for statistical significance"""
        try:
            if len(method1_scores) != len(method2_scores):
                raise ValueError("Score arrays must have same length")
            
            statistic, p_value = ttest_rel(method1_scores, method2_scores)
            
            return {
                'statistic': statistic,
                'p_value': p_value,
                'significant': p_value < 0.05,
                'effect_size': np.mean(method1_scores) - np.mean(method2_scores)
            }
        except Exception as e:
            self.logger.error(f"Error in statistical test: {e}")
            return {'error': str(e)}
    
    def evaluate_method(self, method_name: str, correlation_func, data: pd.DataFrame,
                       ground_truth: np.ndarray, usernames: List[str], 
                       addresses: List[str]) -> Dict[str, any]:
        """Comprehensive evaluation of a correlation method"""
        
        self.logger.info(f"Evaluating method: {method_name}")
        
        # Time the correlation function
        result_data, execution_time = self.performance_timing(
            correlation_func, data, usernames, addresses
        )
        
        # Extract predicted clusters
        y_pred = result_data['pred_cluster'].values
        
        # Calculate metrics
        clustering_metrics = self.calculate_clustering_metrics(ground_truth, y_pred)
        
        # Calculate silhouette score if we have feature data
        try:
            feature_data = data[addresses + usernames].apply(pd.to_numeric, errors='coerce').fillna(0)
            silhouette = self.calculate_silhouette_score(feature_data.values, y_pred)
        except (ValueError, TypeError):
            silhouette = 0.0
        
        # Compile results
        evaluation_result = {
            'method_name': method_name,
            'execution_time': execution_time,
            'data_size': len(data),
            'num_clusters_true': len(set(ground_truth)),
            'num_clusters_pred': len(set(y_pred)),
            'silhouette_score': silhouette,
            **clustering_metrics
        }
        
        # Store in history
        self.results_history.append(evaluation_result)
        
        return evaluation_result
    
    def compare_methods(self, results: List[Dict[str, any]]) -> pd.DataFrame:
        """Create comparison table of multiple methods"""
        comparison_df = pd.DataFrame(results)
        
        # Sort by primary metric (adjusted_rand_score)
        if 'adjusted_rand_score' in comparison_df.columns:
            comparison_df = comparison_df.sort_values('adjusted_rand_score', ascending=False)
        
        return comparison_df
    
    def generate_evaluation_report(self, results: List[Dict[str, any]], 
                                 output_file: str = None) -> str:
        """Generate comprehensive evaluation report"""
        
        report = []
        report.append("# MITRE-CORE Evaluation Report")
        report.append("=" * 50)
        report.append("")
        
        # Summary statistics
        report.append("## Summary Statistics")
        comparison_df = self.compare_methods(results)
        report.append(comparison_df.to_string(index=False))
        report.append("")
        
        # Best performing method
        if len(results) > 0:
            best_method = max(results, key=lambda x: x.get('adjusted_rand_score', 0))
            report.append(f"## Best Performing Method: {best_method['method_name']}")
            report.append(f"- Adjusted Rand Score: {best_method.get('adjusted_rand_score', 'N/A'):.4f}")
            report.append(f"- Execution Time: {best_method.get('execution_time', 'N/A'):.4f} seconds")
            report.append(f"- Silhouette Score: {best_method.get('silhouette_score', 'N/A'):.4f}")
            report.append("")
        
        # Statistical significance tests
        if len(results) >= 2:
            report.append("## Statistical Significance Analysis")
            mitre_results = [r for r in results if 'MITRE' in r['method_name']]
            baseline_results = [r for r in results if 'MITRE' not in r['method_name']]
            
            if mitre_results and baseline_results:
                mitre_scores = [r.get('adjusted_rand_score', 0) for r in mitre_results]
                baseline_scores = [r.get('adjusted_rand_score', 0) for r in baseline_results]
                
                if len(mitre_scores) == len(baseline_scores):
                    sig_test = self.statistical_significance_test(mitre_scores, baseline_scores)
                    report.append(f"- P-value: {sig_test.get('p_value', 'N/A'):.6f}")
                    report.append(f"- Statistically Significant: {sig_test.get('significant', 'N/A')}")
                    report.append(f"- Effect Size: {sig_test.get('effect_size', 'N/A'):.4f}")
            report.append("")
        
        report_text = "\n".join(report)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            self.logger.info(f"Evaluation report saved to {output_file}")
        
        return report_text


class DatasetGenerator:
    """Generate synthetic datasets for evaluation"""
    
    def __init__(self):
        self.logger = logging.getLogger('DatasetGenerator')
    
    def create_evaluation_dataset(self, num_campaigns: int = 10, 
                                campaign_sizes: List[int] = [3, 5, 8],
                                noise_level: float = 0.1,
                                validate_quality: bool = True) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        Create synthetic dataset with ground truth for evaluation
        
        Args:
            num_campaigns: Number of attack campaigns to generate
            campaign_sizes: Possible sizes for each campaign
            noise_level: Fraction of noise events to add
            validate_quality: Whether to validate dataset quality
            
        Returns:
            Tuple of (DataFrame, ground_truth_array)
        """
        
        import random
        from datetime import datetime, timedelta
        
        # Set seed for reproducibility
        random.seed(42)
        np.random.seed(42)
        
        data_rows = []
        ground_truth = []
        current_cluster = 0
        
        # Generate realistic attack campaigns
        for campaign in range(num_campaigns):
            campaign_size = random.choice(campaign_sizes)
            
            # Generate campaign characteristics with realistic patterns
            subnet_base = f"192.168.{random.randint(1, 50)}"
            base_source_ip = f"{subnet_base}.{random.randint(1, 254)}"
            base_dest_ip = f"10.{random.randint(1, 50)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            base_hostname = f"workstation_{campaign:03d}"
            
            # Realistic time progression (attacks over hours/days)
            base_time = datetime.now() - timedelta(days=random.randint(1, 30))
            
            # Generate correlated events within campaign
            for event in range(campaign_size):
                # Maintain some consistency within campaign while adding realistic variation
                source_variation = random.random() < 0.2  # 20% chance of IP variation
                hostname_variation = random.random() < 0.3  # 30% chance of hostname variation
                
                row = {
                    'SourceAddress': (f"{subnet_base}.{random.randint(1, 254)}" 
                                    if source_variation else base_source_ip),
                    'DestinationAddress': (f"10.{random.randint(1, 50)}.{random.randint(1, 254)}.{random.randint(1, 254)}" 
                                         if random.random() < 0.4 else base_dest_ip),
                    'DeviceAddress': f"172.16.{campaign}.{random.randint(1, 10)}",
                    'SourceHostName': (f"workstation_{campaign:03d}_{event}" 
                                     if hostname_variation else base_hostname),
                    'DeviceHostName': f"firewall_{campaign // 3}",  # Multiple campaigns per device
                    'DestinationHostName': f"server_{random.randint(1, 5)}",
                    'EndDate': (base_time + timedelta(hours=event * random.uniform(0.5, 2))).isoformat(),
                    'MalwareIntelAttackType': self._get_realistic_attack_type(event, campaign_size),
                    'CustomerName': 'EVAL_CUSTOMER',
                    'AttackSeverity': random.choice(['Low', 'Medium', 'High'])
                }
                
                data_rows.append(row)
                ground_truth.append(current_cluster)
            
            current_cluster += 1
        
        # Add realistic noise events
        num_noise = int(len(data_rows) * noise_level)
        for noise in range(num_noise):
            row = {
                'SourceAddress': f"203.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'DestinationAddress': f"8.8.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'DeviceAddress': f"172.20.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'SourceHostName': f"external_host_{noise}",
                'DeviceHostName': f"edge_device_{noise}",
                'DestinationHostName': f"public_server_{noise}",
                'EndDate': (datetime.now() - timedelta(hours=random.randint(1, 720))).isoformat(),
                'MalwareIntelAttackType': f"Benign_Activity_{noise}",
                'CustomerName': 'EVAL_CUSTOMER',
                'AttackSeverity': 'Low'
            }
            
            data_rows.append(row)
            ground_truth.append(-1)  # Noise cluster
        
        df = pd.DataFrame(data_rows)
        ground_truth_array = np.array(ground_truth)
        
        # Validate dataset quality if requested
        if validate_quality:
            quality_score = self._validate_dataset_quality(df, ground_truth_array)
            self.logger.info(f"Dataset quality score: {quality_score:.3f}")
            
            if quality_score < 0.5:
                self.logger.warning("Low quality dataset generated - consider adjusting parameters")
        
        return df, ground_truth_array
    
    def _get_realistic_attack_type(self, event_index: int, campaign_size: int) -> str:
        """Generate realistic attack progression"""
        attack_progression = [
            "Initial Access - Spear Phishing",
            "Execution - PowerShell Script",
            "Persistence - Registry Modification", 
            "Privilege Escalation - Token Impersonation",
            "Defense Evasion - Process Hollowing",
            "Credential Access - LSASS Dumping",
            "Discovery - Network Scanning",
            "Lateral Movement - SMB/Admin Shares",
            "Collection - Data Staging",
            "Exfiltration - DNS Tunneling",
            "Impact - Data Encryption"
        ]
        
        # Select attack type based on progression
        stage = min(event_index, len(attack_progression) - 1)
        return attack_progression[stage]
    
    def _validate_dataset_quality(self, df: pd.DataFrame, ground_truth: np.ndarray) -> float:
        """
        Validate quality of generated dataset
        
        Returns quality score between 0 and 1
        """
        
        quality_factors = []
        
        # Factor 1: Cluster size distribution
        unique_clusters, cluster_counts = np.unique(ground_truth[ground_truth >= 0], return_counts=True)
        if len(cluster_counts) > 0:
            size_variance = np.var(cluster_counts) / np.mean(cluster_counts)
            size_quality = max(0, 1 - size_variance / 2)  # Lower variance is better
            quality_factors.append(size_quality)
        
        # Factor 2: Feature diversity within clusters
        intra_cluster_diversity = 0
        for cluster_id in unique_clusters:
            cluster_mask = ground_truth == cluster_id
            cluster_data = df[cluster_mask]
            
            # Calculate diversity of IP addresses within cluster
            unique_ips = len(set(cluster_data['SourceAddress'].unique()) | 
                           set(cluster_data['DestinationAddress'].unique()))
            total_events = len(cluster_data)
            diversity = unique_ips / (total_events * 2)  # Normalize
            intra_cluster_diversity += diversity
        
        if len(unique_clusters) > 0:
            avg_diversity = intra_cluster_diversity / len(unique_clusters)
            quality_factors.append(min(1.0, avg_diversity * 2))  # Scale appropriately
        
        # Factor 3: Temporal consistency
        temporal_quality = 0
        if 'EndDate' in df.columns:
            try:
                timestamps = pd.to_datetime(df['EndDate'])
                time_span = (timestamps.max() - timestamps.min()).total_seconds()
                if time_span > 0:
                    temporal_quality = min(1.0, time_span / (7 * 24 * 3600))  # Normalize to week
            except (ValueError, TypeError):
                temporal_quality = 0.5  # Default if timestamp parsing fails
        
        quality_factors.append(temporal_quality)
        
        # Overall quality score
        return np.mean(quality_factors) if quality_factors else 0.0


# Example usage and testing
if __name__ == "__main__":
    # Create evaluator
    evaluator = CorrelationEvaluator()
    
    # Generate test dataset
    generator = DatasetGenerator()
    test_data, ground_truth = generator.create_evaluation_dataset(
        num_campaigns=5, campaign_sizes=[3, 4, 5]
    )
    
    print("Evaluation framework created successfully!")
    print(f"Test dataset shape: {test_data.shape}")
    print(f"Ground truth clusters: {len(set(ground_truth))}")
