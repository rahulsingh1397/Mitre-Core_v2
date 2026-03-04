"""
MITRE-CORE HGNN Test & Evaluation Suite
Comprehensive testing of HGNN vs Union-Find correlation performance

Generates:
- Synthetic attack campaigns with ground truth labels
- Performance comparison reports
- Statistical significance tests
- Visualizations of clustering quality

Usage:
    python hgnn_evaluation.py --mode full
    python hgnn_evaluation.py --mode quick
    python hgnn_evaluation.py --mode benchmark
"""

import pandas as pd
import numpy as np
import torch
import time
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from tqdm import tqdm
import json
import warnings
warnings.filterwarnings('ignore')

# Setup logging first (before any imports that might use it)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.hgnn_evaluation")

# Metrics
from sklearn.metrics import (
    adjusted_rand_score,
    normalized_mutual_info_score,
    homogeneity_score,
    completeness_score,
    v_measure_score,
    fowlkes_mallows_score,
    silhouette_score,
    confusion_matrix
)

# MITRE-CORE imports
try:
    from correlation_indexer import enhanced_correlation as union_find_correlation
except ImportError:
    from postprocessing import correlation as union_find_correlation

# HGNN imports (optional - will skip if not available)
try:
    from hgnn_correlation import HGNNCorrelationEngine
    from hgnn_integration import HybridCorrelationEngine
    HGNN_AVAILABLE = True
except ImportError as e:
    logger.warning(f"HGNN not available: {e}")
    HGNN_AVAILABLE = False
    HGNNCorrelationEngine = None
    HybridCorrelationEngine = None

import Testing  # Existing synthetic data generator


@dataclass
class EvaluationResult:
    """Container for evaluation metrics."""
    method: str  # 'Union-Find', 'HGNN', 'Hybrid'
    dataset_size: int
    num_ground_truth_clusters: int
    
    # Accuracy metrics
    ari: float
    nmi: float
    homogeneity: float
    completeness: float
    v_measure: float
    fowlkes_mallows: float
    purity: float
    
    # Performance metrics
    inference_time_seconds: float
    
    # Clustering quality
    predicted_num_clusters: int
    avg_cluster_size: float
    min_cluster_size: int
    max_cluster_size: int
    
    # Optional metrics (with defaults)
    memory_usage_mb: Optional[float] = None
    confidence_mean: Optional[float] = None
    confidence_std: Optional[float] = None


class SyntheticAttackGenerator:
    """
    Enhanced synthetic attack generator with ground truth labels.
    Creates realistic APT campaigns for controlled evaluation.
    """
    
    def __init__(self, random_seed: int = 42):
        np.random.seed(random_seed)
        
        # MITRE ATT&CK phase definitions
        self.attack_phases = [
            ("Initial Access", "Connection to Malicious URL for malware_download"),
            ("Execution", "Event Triggered Execution"),
            ("Persistence", "Persistence - Registry Key Manipulation"),
            ("Privilege Escalation", "Privilege Escalation - Exploiting Vulnerability"),
            ("Defense Evasion", "Defense Evasion - Signature-based Evasion"),
            ("Credential Access", "Credential Access - Password Guessing"),
            ("Discovery", "Discovery - Network Service Scanning"),
            ("Lateral Movement", "Lateral Movement - Remote Desktop Protocol (RDP) Exploitation"),
            ("Collection", "Collection - Data Exfiltration via Email"),
            ("Command and Control", "Command and Control - Communication over Tor Network"),
            ("Exfiltration", "Exfiltration - File Transfer to External Server"),
            ("Impact", "Impact - Denial-of-Service (DoS) Attack")
        ]
    
    def generate_campaign(
        self,
        campaign_id: int,
        num_alerts: int = 10,
        num_shared_ips: int = 2,
        num_shared_hosts: int = 2,
        temporal_spread_hours: float = 24.0,
        add_noise: bool = False,
        noise_ratio: float = 0.1
    ) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        Generate a single APT campaign with ground truth labels.
        
        Returns:
            df: DataFrame with alerts
            labels: Ground truth cluster labels (all same for campaign)
        """
        alerts = []
        
        # Generate shared infrastructure
        shared_ips = [self._generate_ip() for _ in range(num_shared_ips)]
        shared_hosts = [self._generate_hostname() for _ in range(num_shared_hosts)]
        compromised_user = self._generate_username()
        
        # Base timestamp
        base_time = pd.Timestamp.now() - pd.Timedelta(hours=temporal_spread_hours)
        
        # Generate attack progression
        phase_indices = np.random.choice(
            len(self.attack_phases),
            size=min(num_alerts, len(self.attack_phases)),
            replace=False
        )
        phase_indices = sorted(phase_indices)  # Temporal progression
        
        for i, phase_idx in enumerate(phase_indices):
            tactic, attack_type = self.attack_phases[phase_idx]
            
            # Temporal spacing
            hours_offset = (temporal_spread_hours / len(phase_indices)) * i
            timestamp = base_time + pd.Timedelta(hours=hours_offset)
            
            # Network indicators (share infrastructure within campaign)
            source_ip = np.random.choice(shared_ips)
            dest_ip = self._generate_ip() if i % 3 == 0 else np.random.choice(shared_ips)
            device_ip = np.random.choice(shared_ips)
            
            source_host = np.random.choice(shared_hosts)
            dest_host = self._generate_hostname() if i % 2 == 0 else np.random.choice(shared_hosts)
            device_host = np.random.choice(shared_hosts)
            
            alert = {
                'AlertId': f'ALT-C{campaign_id:03d}-{i:03d}',
                'SourceAddress': source_ip,
                'DestinationAddress': dest_ip,
                'DeviceAddress': device_ip,
                'SourceUserName': compromised_user if i < 3 else self._generate_username(),
                'SourceHostName': source_host,
                'DeviceHostName': device_host,
                'DestinationHostName': dest_host,
                'MalwareIntelAttackType': attack_type,
                'AttackSeverity': np.random.choice(['Low', 'Medium', 'High', 'Critical'], 
                                                    p=[0.1, 0.3, 0.4, 0.2]),
                'EndDate': timestamp.isoformat(),
                'CustomerName': 'TEST_ORG',
                # Ground truth info (for evaluation)
                'ground_truth_campaign': campaign_id,
                'ground_truth_tactic': tactic
            }
            alerts.append(alert)
        
        df = pd.DataFrame(alerts)
        labels = np.full(len(df), campaign_id)
        
        # Add noise (random alerts not part of campaign)
        if add_noise and noise_ratio > 0:
            num_noise = int(len(df) * noise_ratio)
            noise_alerts = []
            for j in range(num_noise):
                noise_alert = {
                    'AlertId': f'ALT-NOISE-{campaign_id:03d}-{j:03d}',
                    'SourceAddress': self._generate_ip(),
                    'DestinationAddress': self._generate_ip(),
                    'DeviceAddress': self._generate_ip(),
                    'SourceUserName': self._generate_username(),
                    'SourceHostName': self._generate_hostname(),
                    'DeviceHostName': self._generate_hostname(),
                    'DestinationHostName': self._generate_hostname(),
                    'MalwareIntelAttackType': np.random.choice([p[1] for p in self.attack_phases]),
                    'AttackSeverity': np.random.choice(['Low', 'Medium', 'High']),
                    'EndDate': (base_time + pd.Timedelta(hours=np.random.random() * temporal_spread_hours)).isoformat(),
                    'CustomerName': 'TEST_ORG',
                    'ground_truth_campaign': -1,  # Noise label
                    'ground_truth_tactic': 'NOISE'
                }
                noise_alerts.append(noise_alert)
            
            noise_df = pd.DataFrame(noise_alerts)
            noise_labels = np.full(len(noise_df), -1)
            
            df = pd.concat([df, noise_df], ignore_index=True)
            labels = np.concatenate([labels, noise_labels])
        
        return df, labels
    
    def generate_test_suite(
        self,
        num_campaigns: int = 20,
        min_alerts_per_campaign: int = 5,
        max_alerts_per_campaign: int = 15,
        noise_ratio: float = 0.15
    ) -> Tuple[List[pd.DataFrame], List[np.ndarray]]:
        """
        Generate complete test suite with multiple campaigns.
        
        Returns:
            dataframes: List of DataFrames (one per campaign)
            labels: List of label arrays
        """
        dataframes = []
        labels = []
        
        logger.info(f"Generating test suite: {num_campaigns} campaigns...")
        
        for i in range(num_campaigns):
            num_alerts = np.random.randint(min_alerts_per_campaign, 
                                          max_alerts_per_campaign + 1)
            
            df, label = self.generate_campaign(
                campaign_id=i,
                num_alerts=num_alerts,
                add_noise=True,
                noise_ratio=noise_ratio
            )
            
            dataframes.append(df)
            labels.append(label)
        
        total_alerts = sum(len(df) for df in dataframes)
        logger.info(f"Generated {total_alerts} alerts across {num_campaigns} campaigns")
        
        return dataframes, labels
    
    def _generate_ip(self) -> str:
        """Generate random IP address."""
        return f"{np.random.randint(1, 256)}.{np.random.randint(0, 256)}.{np.random.randint(0, 256)}.{np.random.randint(1, 256)}"
    
    def _generate_hostname(self) -> str:
        """Generate random hostname."""
        prefixes = ['PC', 'SERVER', 'WORKSTATION', 'LAPTOP', 'WEB', 'DB', 'MAIL', 'DNS']
        suffixes = ['01', '02', '03', 'A', 'B', 'C', 'PROD', 'DEV', 'TEST']
        return f"{np.random.choice(prefixes)}-{np.random.choice(suffixes)}-{np.random.randint(100, 999)}"
    
    def _generate_username(self) -> str:
        """Generate random username."""
        first_names = ['john', 'jane', 'bob', 'alice', 'charlie', 'diana', 'edward', 'fiona']
        last_names = ['smith', 'doe', 'jones', 'wilson', 'brown', 'davis', 'miller', 'taylor']
        return f"{np.random.choice(first_names)}.{np.random.choice(last_names)}"


class HGNNEvaluator:
    """
    Comprehensive evaluator for HGNN performance.
    Compares against Union-Find baseline and generates reports.
    """
    
    def __init__(self, output_dir: str = './hgnn_evaluation_results'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results: List[EvaluationResult] = []
        
        # Initialize engines
        self.union_find_available = True
        self.hgnn_available = HGNN_AVAILABLE and self._check_hgnn_available()
        
    def _check_hgnn_available(self) -> bool:
        """Check if HGNN can be initialized (PyTorch available)."""
        try:
            import torch
            logger.info(f"PyTorch available: {torch.__version__}")
            logger.info(f"CUDA available: {torch.cuda.is_available()}")
            return True
        except ImportError:
            logger.warning("PyTorch not available. HGNN tests will be skipped.")
            return False
    
    def evaluate_single_campaign(
        self,
        df: pd.DataFrame,
        ground_truth: np.ndarray,
        campaign_id: int
    ) -> List[EvaluationResult]:
        """
        Evaluate all methods on single campaign.
        
        Returns results for Union-Find, HGNN (if available), and Hybrid.
        """
        usernames = ["SourceHostName", "DeviceHostName", "DestinationHostName"]
        addresses = ["SourceAddress", "DestinationAddress", "DeviceAddress"]
        
        results = []
        
        # 1. Union-Find Baseline
        try:
            logger.info(f"Campaign {campaign_id}: Testing Union-Find...")
            start = time.time()
            uf_result = union_find_correlation(df.copy(), usernames, addresses)
            uf_time = time.time() - start
            
            # Filter out noise (label = -1) for fair comparison
            valid_mask = ground_truth != -1
            if valid_mask.sum() > 0:
                uf_metrics = self._calculate_metrics(
                    ground_truth[valid_mask],
                    uf_result.loc[valid_mask, 'pred_cluster'].values
                )
                uf_metrics.method = 'Union-Find'
                uf_metrics.dataset_size = len(df)
                uf_metrics.inference_time_seconds = uf_time
                results.append(uf_metrics)
        except Exception as e:
            logger.error(f"Union-Find failed: {e}")
        
        # 2. HGNN (if available)
        if self.hgnn_available and HGNNCorrelationEngine is not None:
            try:
                logger.info(f"Campaign {campaign_id}: Testing HGNN...")
                
                # Use random-init HGNN for fair comparison (no training data advantage)
                hgnn_engine = HGNNCorrelationEngine(model_path=None, device='cpu')
                
                start = time.time()
                hgnn_result = hgnn_engine.correlate(df.copy())
                hgnn_time = time.time() - start
                
                valid_mask = ground_truth != -1
                if valid_mask.sum() > 0:
                    hgnn_metrics = self._calculate_metrics(
                        ground_truth[valid_mask],
                        hgnn_result.loc[valid_mask, 'pred_cluster'].values
                    )
                    hgnn_metrics.method = 'HGNN'
                    hgnn_metrics.dataset_size = len(df)
                    hgnn_metrics.inference_time_seconds = hgnn_time
                    hgnn_metrics.confidence_mean = hgnn_result['cluster_confidence'].mean()
                    hgnn_metrics.confidence_std = hgnn_result['cluster_confidence'].std()
                    results.append(hgnn_metrics)
            except Exception as e:
                logger.error(f"HGNN failed: {e}")
        
        # 3. Hybrid (if HGNN available)
        if self.hgnn_available and HybridCorrelationEngine is not None:
            try:
                logger.info(f"Campaign {campaign_id}: Testing Hybrid...")
                
                hybrid_engine = HybridCorrelationEngine(
                    hgnn_weight=0.7,
                    union_find_weight=0.3,
                    model_path=None,
                    device='cpu'
                )
                
                start = time.time()
                hybrid_result = hybrid_engine.correlate(df.copy(), usernames, addresses)
                hybrid_time = time.time() - start
                
                valid_mask = ground_truth != -1
                if valid_mask.sum() > 0:
                    hybrid_metrics = self._calculate_metrics(
                        ground_truth[valid_mask],
                        hybrid_result.loc[valid_mask, 'pred_cluster'].values
                    )
                    hybrid_metrics.method = 'Hybrid'
                    hybrid_metrics.dataset_size = len(df)
                    hybrid_metrics.inference_time_seconds = hybrid_time
                    results.append(hybrid_metrics)
            except Exception as e:
                logger.error(f"Hybrid failed: {e}")
        
        return results
    
    def _calculate_metrics(
        self,
        ground_truth: np.ndarray,
        predictions: np.ndarray
    ) -> EvaluationResult:
        """Calculate all evaluation metrics."""
        # Accuracy metrics
        ari = adjusted_rand_score(ground_truth, predictions)
        nmi = normalized_mutual_info_score(ground_truth, predictions)
        homogeneity = homogeneity_score(ground_truth, predictions)
        completeness = completeness_score(ground_truth, predictions)
        v_measure = v_measure_score(ground_truth, predictions)
        fowlkes_mallows = fowlkes_mallows_score(ground_truth, predictions)
        
        # Purity
        purity = self._calculate_purity(ground_truth, predictions)
        
        # Cluster statistics
        unique_preds = np.unique(predictions)
        cluster_sizes = [np.sum(predictions == c) for c in unique_preds]
        
        return EvaluationResult(
            method='',
            dataset_size=len(ground_truth),
            num_ground_truth_clusters=len(np.unique(ground_truth)),
            ari=ari,
            nmi=nmi,
            homogeneity=homogeneity,
            completeness=completeness,
            v_measure=v_measure,
            fowlkes_mallows=fowlkes_mallows,
            purity=purity,
            inference_time_seconds=0.0,
            predicted_num_clusters=len(unique_preds),
            avg_cluster_size=np.mean(cluster_sizes),
            min_cluster_size=min(cluster_sizes),
            max_cluster_size=max(cluster_sizes)
        )
    
    def _calculate_purity(
        self,
        ground_truth: np.ndarray,
        predictions: np.ndarray
    ) -> float:
        """Calculate cluster purity."""
        cm = confusion_matrix(ground_truth, predictions)
        purity_per_cluster = cm.max(axis=0) / cm.sum(axis=0)
        weights = cm.sum(axis=0) / cm.sum()
        return float((purity_per_cluster * weights).sum())
    
    def run_full_evaluation(
        self,
        num_campaigns: int = 20,
        min_alerts: int = 5,
        max_alerts: int = 15
    ) -> pd.DataFrame:
        """
        Run complete evaluation on generated test suite.
        
        Returns DataFrame with all results for analysis.
        """
        # Generate test data
        generator = SyntheticAttackGenerator(random_seed=42)
        dataframes, labels = generator.generate_test_suite(
            num_campaigns=num_campaigns,
            min_alerts_per_campaign=min_alerts,
            max_alerts_per_campaign=max_alerts,
            noise_ratio=0.15
        )
        
        # Evaluate each campaign
        all_results = []
        for i, (df, gt) in enumerate(zip(dataframes, labels)):
            logger.info(f"\n{'='*60}")
            logger.info(f"Evaluating Campaign {i+1}/{len(dataframes)}")
            logger.info(f"Alerts: {len(df)} | Ground Truth Clusters: {len(np.unique(gt[gt != -1]))}")
            logger.info(f"{'='*60}")
            
            results = self.evaluate_single_campaign(df, gt, i)
            all_results.extend(results)
        
        # Store and return
        self.results = all_results
        return pd.DataFrame([r.__dict__ for r in all_results])
    
    def generate_report(self, results_df: Optional[pd.DataFrame] = None) -> str:
        """Generate comprehensive evaluation report."""
        if results_df is None:
            results_df = pd.DataFrame([r.__dict__ for r in self.results])
        
        if len(results_df) == 0:
            return "No evaluation results available."
        
        lines = [
            "MITRE-CORE HGNN Evaluation Report",
            "=" * 80,
            "",
            f"Total Campaigns Evaluated: {len(results_df.groupby('dataset_size'))}",
            f"Methods Tested: {', '.join(results_df['method'].unique())}",
            "",
            "Summary Statistics by Method",
            "-" * 80,
            ""
        ]
        
        # Group by method and calculate statistics
        for method in results_df['method'].unique():
            method_data = results_df[results_df['method'] == method]
            
            lines.extend([
                f"\n{method}:",
                f"  Number of tests: {len(method_data)}",
                f"  Avg Dataset Size: {method_data['dataset_size'].mean():.1f} alerts",
                "",
                "  Accuracy Metrics:",
                f"    ARI:           {method_data['ari'].mean():.4f} ± {method_data['ari'].std():.4f}",
                f"    NMI:           {method_data['nmi'].mean():.4f} ± {method_data['nmi'].std():.4f}",
                f"    V-Measure:     {method_data['v_measure'].mean():.4f} ± {method_data['v_measure'].std():.4f}",
                f"    Purity:        {method_data['purity'].mean():.4f} ± {method_data['purity'].std():.4f}",
                "",
                "  Performance:",
                f"    Avg Time:      {method_data['inference_time_seconds'].mean():.3f}s",
                f"    Min/Max Time:  {method_data['inference_time_seconds'].min():.3f}s / {method_data['inference_time_seconds'].max():.3f}s",
                "",
                "  Cluster Quality:",
                f"    Avg Clusters:  {method_data['predicted_num_clusters'].mean():.1f}",
                f"    Avg Size:      {method_data['avg_cluster_size'].mean():.1f} alerts/cluster",
            ])
            
            if 'confidence_mean' in method_data.columns and not method_data['confidence_mean'].isna().all():
                lines.append(f"    Avg Confidence: {method_data['confidence_mean'].mean():.3f}")
        
        # Comparative Analysis
        if len(results_df['method'].unique()) > 1:
            lines.extend([
                "",
                "Comparative Analysis",
                "-" * 80,
                ""
            ])
            
            # Find best method per metric
            methods = results_df['method'].unique()
            metrics = ['ari', 'nmi', 'v_measure', 'purity']
            
            for metric in metrics:
                lines.append(f"\n{metric.upper()} Comparison:")
                metric_by_method = results_df.groupby('method')[metric].mean().sort_values(ascending=False)
                
                for i, (method, score) in enumerate(metric_by_method.items()):
                    rank = "[1]" if i == 0 else "[2]" if i == 1 else "[3]" if i == 2 else "   "
                    lines.append(f"  {rank} {method:15s}: {score:.4f}")
                
                # Calculate improvement of best vs second best
                if len(metric_by_method) >= 2:
                    best = metric_by_method.iloc[0]
                    second = metric_by_method.iloc[1]
                    improvement = ((best - second) / second) * 100
                    lines.append(f"\n     Best improvement: +{improvement:.1f}% vs 2nd place")
        
        # Statistical Significance
        if len(results_df['method'].unique()) >= 2:
            lines.extend([
                "",
                "Statistical Significance (Paired T-Test)",
                "-" * 80,
                ""
            ])
            
            from scipy.stats import ttest_rel
            
            # Compare HGNN vs Union-Find
            if (HGNN_AVAILABLE and 'HGNN' in results_df['method'].values and 
                'Union-Find' in results_df['method'].values):
                hgnn_ari = results_df[results_df['method'] == 'HGNN']['ari'].values
                uf_ari = results_df[results_df['method'] == 'Union-Find']['ari'].values
                
                if len(hgnn_ari) == len(uf_ari):
                    t_stat, p_value = ttest_rel(hgnn_ari, uf_ari)
                    significance = "significant" if p_value < 0.05 else "not significant"
                    lines.extend([
                        f"HGNN vs Union-Find ARI difference:",
                        f"  T-statistic: {t_stat:.4f}",
                        f"  P-value: {p_value:.4f} ({significance})",
                        ""
                    ])
        
        # Conclusion
        lines.extend([
            "",
            "Conclusion",
            "-" * 80,
            ""
        ])
        
        # Determine overall winner
        if len(results_df['method'].unique()) > 1:
            # Rank by average rank across metrics
            method_ranks = {}
            for method in results_df['method'].unique():
                ranks = []
                for metric in ['ari', 'nmi', 'v_measure']:
                    score = results_df[results_df['method'] == method][metric].mean()
                    rank = results_df.groupby('method')[metric].mean().rank(ascending=False)[method]
                    ranks.append(rank)
                method_ranks[method] = np.mean(ranks)
            
            winner = min(method_ranks, key=method_ranks.get)
            lines.append(f"Overall Best Method: {winner} (lowest average rank)")
            
            # Recommendations
            if winner == 'HGNN':
                lines.extend([
                    "",
                    "Recommendation: HGNN shows superior accuracy. Consider:",
                    "  1. Training on production data for better performance",
                    "  2. Using hybrid mode for robustness during transition",
                    "  3. Monitoring inference latency in production"
                ])
            elif winner == 'Hybrid':
                lines.extend([
                    "",
                    "Recommendation: Hybrid ensemble performs best. Benefits:",
                    "  1. Combines HGNN accuracy with Union-Find stability",
                    "  2. Graceful degradation if one method fails",
                    "  3. Good balance of performance and reliability"
                ])
            else:
                lines.extend([
                    "",
                    "Recommendation: Union-Find remains competitive. Consider:",
                    "  1. HGNN may need more training data",
                    "  2. Current handcrafted weights may be well-tuned",
                    "  3. Monitor HGNN evolution for future migration"
                ])
        
        report = "\n".join(lines)
        
        # Save report
        report_path = self.output_dir / 'evaluation_report.txt'
        with open(report_path, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {report_path}")
        
        # Save raw results
        results_path = self.output_dir / 'evaluation_results.csv'
        results_df.to_csv(results_path, index=False)
        logger.info(f"Raw results saved to {results_path}")
        
        return report


def quick_test():
    """Run quick evaluation on 5 campaigns for rapid testing."""
    logger.info("Running QUICK TEST (5 campaigns)...")
    
    evaluator = HGNNEvaluator()
    results_df = evaluator.run_full_evaluation(
        num_campaigns=5,
        min_alerts=3,
        max_alerts=10
    )
    
    report = evaluator.generate_report(results_df)
    print("\n" + report)
    
    return results_df


def full_evaluation():
    """Run comprehensive evaluation on 20 campaigns."""
    logger.info("Running FULL EVALUATION (20 campaigns)...")
    
    evaluator = HGNNEvaluator()
    results_df = evaluator.run_full_evaluation(
        num_campaigns=20,
        min_alerts=5,
        max_alerts=15
    )
    
    report = evaluator.generate_report(results_df)
    print("\n" + report)
    
    return results_df


def benchmark_mode():
    """Run speed benchmark with varying dataset sizes."""
    logger.info("Running SPEED BENCHMARK...")
    
    sizes = [10, 25, 50, 100, 200]
    results = []
    
    generator = SyntheticAttackGenerator()
    evaluator = HGNNEvaluator()
    
    for size in sizes:
        logger.info(f"\nBenchmarking size={size}...")
        
        df, labels = generator.generate_campaign(
            campaign_id=0,
            num_alerts=size,
            add_noise=False
        )
        
        usernames = ["SourceHostName", "DeviceHostName", "DestinationHostName"]
        addresses = ["SourceAddress", "DestinationAddress", "DeviceAddress"]
        
        # Union-Find timing
        start = time.time()
        uf_result = union_find_correlation(df.copy(), usernames, addresses)
        uf_time = time.time() - start
        
        # HGNN timing (if available)
        hgnn_time = None
        if evaluator.hgnn_available:
            try:
                engine = HGNNCorrelationEngine(device='cpu')
                start = time.time()
                hgnn_result = engine.correlate(df.copy())
                hgnn_time = time.time() - start
            except Exception as e:
                logger.error(f"HGNN failed at size {size}: {e}")
        
        results.append({
            'size': size,
            'union_find_time': uf_time,
            'hgnn_time': hgnn_time,
            'speedup': (uf_time / hgnn_time) if hgnn_time else None
        })
        
        logger.info(f"  Union-Find: {uf_time:.3f}s")
        if hgnn_time:
            logger.info(f"  HGNN: {hgnn_time:.3f}s ({uf_time/hgnn_time:.2f}x)")
    
    # Save benchmark
    bench_df = pd.DataFrame(results)
    bench_path = evaluator.output_dir / 'speed_benchmark.csv'
    bench_df.to_csv(bench_path, index=False)
    
    print("\nSpeed Benchmark Results:")
    print(bench_df.to_string(index=False))
    
    return bench_df


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='HGNN Evaluation Suite')
    parser.add_argument('--mode', choices=['quick', 'full', 'benchmark'], 
                       default='quick', help='Evaluation mode')
    
    args = parser.parse_args()
    
    if args.mode == 'quick':
        quick_test()
    elif args.mode == 'full':
        full_evaluation()
    elif args.mode == 'benchmark':
        benchmark_mode()
