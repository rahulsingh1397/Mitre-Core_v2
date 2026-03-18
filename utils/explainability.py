"""
HGNN Explainability Module for MITRE-CORE
Provides attention visualization and cluster explanation generation.
"""

import torch
import torch.nn.functional as F
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger("mitre-core.explainability")


@dataclass
class AttentionExplanation:
    """Explanation for a single cluster based on attention weights."""
    cluster_id: int
    importance_score: float
    key_entities: List[Dict]
    attention_flow: Dict[str, List[float]]
    explanation_text: str


@dataclass
class CorrelationExplanation:
    """Explanation for why two alerts were correlated."""
    alert_pair: Tuple[int, int]
    correlation_score: float
    contributing_features: List[Dict]
    shared_entities: Dict[str, List[str]]
    explanation_text: str


class HGNNExplainer:
    """
    Explainability module for HGNN correlation engine.
    
    Provides:
    - Attention weight visualization
    - Cluster importance ranking
    - Alert correlation explanations
    - Feature contribution analysis
    """
    
    def __init__(self, model=None):
        self.model = model
        self.attention_weights = {}
        self.feature_importance = {}
    
    def extract_attention_weights(self, 
                                   data, 
                                   model_output) -> Dict[str, torch.Tensor]:
        """
        Extract attention weights from HGNN layers.
        
        Args:
            data: HeteroData object
            model_output: Output from HGNN forward pass
            
        Returns:
            Dictionary of attention weights by edge type
        """
        attention_weights = {}
        
        # Extract from multi-head attention layers
        if hasattr(model_output, 'attention_weights'):
            attention_weights['node'] = model_output.attention_weights
        
        # Extract edge-level attention
        if hasattr(model_output, 'edge_attention'):
            attention_weights['edge'] = model_output.edge_attention
        
        return attention_weights
    
    def explain_cluster(self, 
                       cluster_alerts: pd.DataFrame,
                       attention_weights: Dict[str, torch.Tensor],
                       cluster_id: int) -> AttentionExplanation:
        """
        Generate explanation for a cluster.
        
        Args:
            cluster_alerts: DataFrame of alerts in cluster
            attention_weights: Attention weights from HGNN
            cluster_id: Cluster identifier
            
        Returns:
            AttentionExplanation with cluster insights
        """
        # Calculate cluster importance score
        importance_score = self._calculate_cluster_importance(
            cluster_alerts, attention_weights
        )
        
        # Identify key entities (high attention)
        key_entities = self._identify_key_entities(
            cluster_alerts, attention_weights
        )
        
        # Analyze attention flow
        attention_flow = self._analyze_attention_flow(attention_weights)
        
        # Generate human-readable explanation
        explanation_text = self._generate_cluster_explanation(
            cluster_id, key_entities, importance_score, cluster_alerts
        )
        
        return AttentionExplanation(
            cluster_id=cluster_id,
            importance_score=importance_score,
            key_entities=key_entities,
            attention_flow=attention_flow,
            explanation_text=explanation_text
        )
    
    def explain_correlation(self,
                           alert1: pd.Series,
                           alert2: pd.Series,
                           correlation_score: float,
                           feature_contributions: Dict[str, float]) -> CorrelationExplanation:
        """
        Explain why two alerts were correlated.
        
        Args:
            alert1: First alert data
            alert2: Second alert data
            correlation_score: Overall correlation score
            feature_contributions: Per-feature contribution scores
            
        Returns:
            CorrelationExplanation with detailed reasoning
        """
        # Identify contributing features
        contributing_features = []
        for feature, score in sorted(feature_contributions.items(), 
                                     key=lambda x: x[1], reverse=True):
            if score > 0.1:  # Threshold for significance
                contributing_features.append({
                    'feature': feature,
                    'contribution': score,
                    'description': self._describe_feature_contribution(feature, alert1, alert2)
                })
        
        # Find shared entities
        shared_entities = self._find_shared_entities(alert1, alert2)
        
        # Generate explanation text
        explanation_text = self._generate_correlation_explanation(
            alert1, alert2, correlation_score, contributing_features, shared_entities
        )
        
        return CorrelationExplanation(
            alert_pair=(alert1.get('alert_id', 0), alert2.get('alert_id', 0)),
            correlation_score=correlation_score,
            contributing_features=contributing_features,
            shared_entities=shared_entities,
            explanation_text=explanation_text
        )
    
    def _calculate_cluster_importance(self, 
                                     cluster_alerts: pd.DataFrame,
                                     attention_weights: Dict[str, torch.Tensor]) -> float:
        """Calculate overall importance score for a cluster."""
        # Base importance on cluster size (log scaled)
        size_score = np.log1p(len(cluster_alerts)) / 5.0
        
        # Attention-based importance
        if 'node' in attention_weights:
            attn_score = attention_weights['node'].mean().item()
        else:
            attn_score = 0.5
        
        # Severity boost
        if 'severity' in cluster_alerts.columns:
            severity_score = cluster_alerts['severity'].mean() / 10.0
        else:
            severity_score = 0.5
        
        # Combine scores
        importance = (0.3 * size_score + 
                     0.4 * attn_score + 
                     0.3 * severity_score)
        
        return min(1.0, importance)
    
    def _identify_key_entities(self,
                              cluster_alerts: pd.DataFrame,
                              attention_weights: Dict[str, torch.Tensor]) -> List[Dict]:
        """Identify entities with highest attention weights."""
        key_entities = []
        
        # Check for IP addresses
        if 'src_ip' in cluster_alerts.columns:
            ip_counts = cluster_alerts['src_ip'].value_counts().head(3)
            for ip, count in ip_counts.items():
                key_entities.append({
                    'type': 'source_ip',
                    'value': ip,
                    'frequency': count,
                    'importance': count / len(cluster_alerts)
                })
        
        # Check for hostnames
        if 'hostname' in cluster_alerts.columns:
            host_counts = cluster_alerts['hostname'].value_counts().head(3)
            for host, count in host_counts.items():
                key_entities.append({
                    'type': 'hostname',
                    'value': host,
                    'frequency': count,
                    'importance': count / len(cluster_alerts)
                })
        
        # Check for tactics
        if 'tactic' in cluster_alerts.columns:
            tactic_counts = cluster_alerts['tactic'].value_counts().head(3)
            for tactic, count in tactic_counts.items():
                key_entities.append({
                    'type': 'mitre_tactic',
                    'value': tactic,
                    'frequency': count,
                    'importance': count / len(cluster_alerts)
                })
        
        return sorted(key_entities, key=lambda x: x['importance'], reverse=True)
    
    def _analyze_attention_flow(self, 
                               attention_weights: Dict[str, torch.Tensor]) -> Dict[str, List[float]]:
        """Analyze how attention flows through the graph."""
        flow = {
            'alert_to_user': [],
            'alert_to_host': [],
            'alert_to_ip': [],
            'alert_to_alert': []
        }
        
        if 'edge' in attention_weights:
            weights = attention_weights['edge']
            # Categorize by edge type
            for i, w in enumerate(weights.flatten()[:20]):  # Top 20
                flow['alert_to_alert'].append(w.item())
        
        return flow
    
    def _generate_cluster_explanation(self,
                                     cluster_id: int,
                                     key_entities: List[Dict],
                                     importance_score: float,
                                     cluster_alerts: pd.DataFrame) -> str:
        """Generate human-readable explanation for cluster."""
        # Get primary entities
        primary_ip = next((e for e in key_entities if e['type'] == 'source_ip'), None)
        primary_tactic = next((e for e in key_entities if e['type'] == 'mitre_tactic'), None)
        
        # Build explanation
        parts = [f"Cluster {cluster_id} Analysis:"]
        parts.append(f"- Contains {len(cluster_alerts)} alerts")
        parts.append(f"- Importance Score: {importance_score:.2f}/1.0")
        
        if primary_tactic:
            parts.append(f"- Primary MITRE Tactic: {primary_tactic['value']} "
                        f"({primary_tactic['frequency']} alerts)")
        
        if primary_ip:
            parts.append(f"- Key Source IP: {primary_ip['value']} "
                        f"({primary_ip['frequency']} occurrences)")
        
        # Add attack chain description
        if 'timestamp' in cluster_alerts.columns:
            time_range = (cluster_alerts['timestamp'].max() - 
                         cluster_alerts['timestamp'].min())
            parts.append(f"- Attack Duration: {time_range}")
        
        return "\n".join(parts)
    
    def _describe_feature_contribution(self,
                                      feature: str,
                                      alert1: pd.Series,
                                      alert2: pd.Series) -> str:
        """Describe how a feature contributed to correlation."""
        descriptions = {
            'ip_match': f"Shared IP address: {alert1.get('src_ip', 'N/A')}",
            'user_match': f"Common user: {alert1.get('username', 'N/A')}",
            'temporal': f"Temporal proximity: {abs(pd.to_datetime(alert1.get('timestamp', 0)) - pd.to_datetime(alert2.get('timestamp', 0)))}",
            'tactic_match': f"Same MITRE tactic: {alert1.get('tactic', 'Unknown')}",
            'hostname_match': f"Common hostname: {alert1.get('hostname', 'N/A')}"
        }
        return descriptions.get(feature, f"Feature {feature} contributed to correlation")
    
    def _find_shared_entities(self,
                             alert1: pd.Series,
                             alert2: pd.Series) -> Dict[str, List[str]]:
        """Find entities shared between two alerts."""
        shared = {
            'ips': [],
            'users': [],
            'hostnames': [],
            'tactics': []
        }
        
        # Check IPs
        for ip_col in ['src_ip', 'dst_ip']:
            if ip_col in alert1 and ip_col in alert2:
                if alert1[ip_col] == alert2[ip_col]:
                    shared['ips'].append(alert1[ip_col])
        
        # Check users
        if 'username' in alert1 and 'username' in alert2:
            if alert1['username'] == alert2['username']:
                shared['users'].append(alert1['username'])
        
        # Check hostnames
        if 'hostname' in alert1 and 'hostname' in alert2:
            if alert1['hostname'] == alert2['hostname']:
                shared['hostnames'].append(alert1['hostname'])
        
        # Check tactics
        if 'tactic' in alert1 and 'tactic' in alert2:
            if alert1['tactic'] == alert2['tactic']:
                shared['tactics'].append(alert1['tactic'])
        
        return shared
    
    def _generate_correlation_explanation(self,
                                         alert1: pd.Series,
                                         alert2: pd.Series,
                                         score: float,
                                         features: List[Dict],
                                         shared: Dict[str, List[str]]) -> str:
        """Generate explanation for alert correlation."""
        parts = ["Alert Correlation Explanation:"]
        parts.append(f"- Correlation Score: {score:.3f}")
        parts.append(f"- Alert 1: {alert1.get('alert_type', 'Unknown')} "
                    f"at {alert1.get('timestamp', 'Unknown')}")
        parts.append(f"- Alert 2: {alert2.get('alert_type', 'Unknown')} "
                    f"at {alert2.get('timestamp', 'Unknown')}")
        
        parts.append("\nKey Contributing Factors:")
        for feat in features[:3]:  # Top 3
            parts.append(f"- {feat['description']} "
                        f"(contribution: {feat['contribution']:.2f})")
        
        if any(shared.values()):
            parts.append("\nShared Entities:")
            if shared['ips']:
                parts.append(f"- IP Addresses: {', '.join(shared['ips'])}")
            if shared['users']:
                parts.append(f"- Users: {', '.join(shared['users'])}")
            if shared['tactics']:
                parts.append(f"- MITRE Tactics: {', '.join(shared['tactics'])}")
        
        return "\n".join(parts)
    
    def visualize_attention(self, 
                           attention_weights: torch.Tensor,
                           node_labels: List[str] = None) -> Dict:
        """
        Prepare attention weights for visualization.
        
        Returns data structure suitable for heatmap visualization.
        """
        weights = attention_weights.detach().cpu().numpy()
        
        # Normalize
        weights = (weights - weights.min()) / (weights.max() - weights.min() + 1e-8)
        
        return {
            'weights': weights.tolist(),
            'labels': node_labels or [f"Node {i}" for i in range(len(weights))],
            'shape': weights.shape
        }


def create_explainer(model=None) -> HGNNExplainer:
    """Factory function to create HGNN explainer."""
    return HGNNExplainer(model)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create sample data
    sample_alerts = pd.DataFrame({
        'alert_id': range(10),
        'src_ip': ['192.168.1.1'] * 5 + ['10.0.0.1'] * 5,
        'tactic': ['Initial Access'] * 3 + ['Execution'] * 3 + ['Impact'] * 4,
        'severity': [8, 7, 9, 6, 8, 7, 9, 8, 7, 9],
        'timestamp': pd.date_range('2024-01-01', periods=10, freq='1min')
    })
    
    # Create explainer
    explainer = create_explainer()
    
    # Generate explanation
    dummy_attention = {'node': torch.rand(10, 1), 'edge': torch.rand(20, 1)}
    explanation = explainer.explain_cluster(sample_alerts, dummy_attention, cluster_id=1)
    
    print(explanation.explanation_text)
    print(f"\nImportance Score: {explanation.importance_score:.3f}")
    print(f"Key Entities: {len(explanation.key_entities)}")
