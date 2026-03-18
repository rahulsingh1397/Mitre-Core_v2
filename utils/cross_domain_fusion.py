"""
Cross-Domain Fusion for Multi-Modal Correlation
Unifies network, host, and cloud security logs into single correlation model.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger("mitre-core.cross_domain")


class DataDomain(Enum):
    NETWORK = "network"
    HOST = "host"
    CLOUD = "cloud"
    EMAIL = "email"
    ENDPOINT = "endpoint"


@dataclass
class DomainFeatures:
    """Features extracted from a specific domain."""
    domain_type: DataDomain
    alert_id: int
    timestamp: pd.Timestamp
    entities: Dict[str, str]  # Entity type -> value
    features: np.ndarray
    mitre_tactic: str


@dataclass
class FusedAlert:
    """Alert with fused features from multiple domains."""
    fused_id: int
    timestamp: pd.Timestamp
    source_domains: List[DataDomain]
    unified_entities: Dict[str, str]
    fused_features: np.ndarray
    mitre_tactics: List[str]
    cross_domain_indicators: List[str]


class DomainEncoder:
    """Encoder for individual security domains."""
    
    def __init__(self, domain: DataDomain, feature_dim: int = 64):
        self.domain = domain
        self.feature_dim = feature_dim
        self.entity_mappings = self._get_entity_mappings()
    
    def _get_entity_mappings(self) -> Dict[str, List[str]]:
        """Get entity column mappings for this domain."""
        mappings = {
            DataDomain.NETWORK: {
                'ip': ['src_ip', 'dst_ip', 'src_ipv6', 'dst_ipv6'],
                'port': ['src_port', 'dst_port'],
                'protocol': ['protocol', 'proto'],
                'user': ['username', 'user'],
                'host': ['hostname', 'host'],
                'bytes': ['bytes_sent', 'bytes_recv']
            },
            DataDomain.HOST: {
                'process': ['process_name', 'process_id', 'cmdline'],
                'file': ['file_path', 'filename'],
                'registry': ['registry_key', 'registry_value'],
                'user': ['username', 'uid'],
                'host': ['hostname', 'computer_name']
            },
            DataDomain.CLOUD: {
                'resource': ['resource_id', 'resource_type'],
                'action': ['action', 'operation'],
                'principal': ['principal_id', 'actor'],
                'ip': ['source_ip', 'caller_ip'],
                'region': ['region', 'az']
            },
            DataDomain.EMAIL: {
                'sender': ['sender', 'from_address'],
                'recipient': ['recipient', 'to_address'],
                'subject': ['subject'],
                'attachment': ['attachment_hash'],
                'ip': ['src_ip', 'server_ip']
            },
            DataDomain.ENDPOINT: {
                'device': ['device_id', 'endpoint_id'],
                'user': ['username', 'user_id'],
                'process': ['process_name'],
                'file': ['file_path'],
                'network': ['connection_dest']
            }
        }
        return mappings.get(self.domain, {})
    
    def encode(self, df: pd.DataFrame) -> List[DomainFeatures]:
        """Encode domain-specific alerts to unified features."""
        features_list = []
        
        for idx, row in df.iterrows():
            entities = self._extract_entities(row)
            feature_vector = self._create_feature_vector(row, entities)
            
            features_list.append(DomainFeatures(
                domain_type=self.domain,
                alert_id=idx,
                timestamp=pd.to_datetime(row.get('timestamp', row.get('time', pd.Timestamp.now()))),
                entities=entities,
                features=feature_vector,
                mitre_tactic=row.get('tactic', row.get('mitre_tactic', 'Unknown'))
            ))
        
        return features_list
    
    def _extract_entities(self, row: pd.Series) -> Dict[str, str]:
        """Extract entities from alert row."""
        entities = {}
        
        for entity_type, possible_cols in self.entity_mappings.items():
            for col in possible_cols:
                if col in row and pd.notna(row[col]):
                    entities[entity_type] = str(row[col])
                    break
        
        return entities
    
    def _create_feature_vector(self, 
                              row: pd.Series, 
                              entities: Dict[str, str]) -> np.ndarray:
        """Create numerical feature vector."""
        features = []
        
        # Temporal features
        if 'timestamp' in row:
            ts = pd.to_datetime(row['timestamp'])
            features.extend([
                ts.hour / 24.0,
                ts.dayofweek / 7.0,
                ts.day / 31.0
            ])
        else:
            features.extend([0, 0, 0])
        
        # Domain-specific numerical features
        if self.domain == DataDomain.NETWORK:
            features.extend([
                float(row.get('bytes_sent', 0)) / 1e6,
                float(row.get('bytes_recv', 0)) / 1e6,
                float(row.get('duration', 0)) / 3600,
                1.0 if row.get('protocol') == 'TCP' else 0.0,
                1.0 if row.get('protocol') == 'UDP' else 0.0
            ])
        elif self.domain == DataDomain.HOST:
            features.extend([
                float(row.get('process_id', 0)) % 10000 / 10000,
                1.0 if 'registry' in str(row.get('registry_key', '')).lower() else 0.0,
                1.0 if 'temp' in str(row.get('file_path', '')).lower() else 0.0,
                len(str(row.get('cmdline', ''))) / 1000,
                1.0 if 'powershell' in str(row.get('process_name', '')).lower() else 0.0
            ])
        elif self.domain == DataDomain.CLOUD:
            features.extend([
                hash(str(row.get('resource_type', ''))) % 100 / 100,
                hash(str(row.get('action', ''))) % 100 / 100,
                1.0 if row.get('success', False) else 0.0,
                float(row.get('response_time', 0)) / 1000,
                hash(str(row.get('region', ''))) % 100 / 100
            ])
        else:
            # Generic features
            features.extend([
                hash(str(row.get('alert_type', ''))) % 100 / 100,
                len(str(row)) / 1000,
                1.0 if 'attack' in str(row.get('label', '')).lower() else 0.0,
                0.5, 0.5  # padding
            ])
        
        # Ensure consistent dimension
        features = features[:20]  # Limit to 20 features
        while len(features) < 20:
            features.append(0.0)
        
        return np.array(features, dtype=np.float32)


class CrossDomainFusion:
    """
    Fuses features from multiple security domains.
    """
    
    def __init__(self, fusion_dim: int = 128):
        self.fusion_dim = fusion_dim
        self.encoders = {domain: DomainEncoder(domain) for domain in DataDomain}
        self.domain_projection = {}
    
    def fuse_alerts(self, 
                   domain_data: Dict[DataDomain, pd.DataFrame]) -> List[FusedAlert]:
        """
        Fuse alerts from multiple domains.
        
        Args:
            domain_data: Dict mapping domains to DataFrames
            
        Returns:
            List of fused alerts
        """
        logger.info(f"Fusing alerts from {len(domain_data)} domains")
        
        # Encode each domain
        encoded_domains = {}
        for domain, df in domain_data.items():
            if len(df) > 0:
                encoded_domains[domain] = self.encoders[domain].encode(df)
                logger.info(f"  {domain.value}: {len(encoded_domains[domain])} alerts")
        
        # Find cross-domain correlations
        fused_alerts = self._fuse_by_temporal_proximity(encoded_domains)
        
        logger.info(f"Created {len(fused_alerts)} fused alerts")
        
        return fused_alerts
    
    def _fuse_by_temporal_proximity(self, 
                                   encoded_domains: Dict[DataDomain, List[DomainFeatures]]) -> List[FusedAlert]:
        """Fuse alerts that occur close in time across domains."""
        fused = []
        fused_id = 0
        
        # Collect all alerts with domain info
        all_alerts = []
        for domain, alerts in encoded_domains.items():
            for alert in alerts:
                all_alerts.append((alert, domain))
        
        # Sort by timestamp
        all_alerts.sort(key=lambda x: x[0].timestamp)
        
        # Group by temporal window (5 minutes)
        window = pd.Timedelta(minutes=5)
        current_window = []
        window_start = None
        
        for alert, domain in all_alerts:
            if window_start is None or (alert.timestamp - window_start) <= window:
                current_window.append((alert, domain))
                if window_start is None:
                    window_start = alert.timestamp
            else:
                # Fuse current window
                if len(current_window) > 1:
                    fused_alert = self._create_fused_alert(current_window, fused_id)
                    if fused_alert:
                        fused.append(fused_alert)
                        fused_id += 1
                
                # Start new window
                current_window = [(alert, domain)]
                window_start = alert.timestamp
        
        # Handle final window
        if len(current_window) > 1:
            fused_alert = self._create_fused_alert(current_window, fused_id)
            if fused_alert:
                fused.append(fused_alert)
        
        return fused
    
    def _create_fused_alert(self, 
                           window_alerts: List[Tuple[DomainFeatures, DataDomain]],
                           fused_id: int) -> Optional[FusedAlert]:
        """Create a single fused alert from temporal window."""
        if len(window_alerts) < 2:
            return None
        
        # Collect info
        domains = list(set(d for _, d in window_alerts))
        timestamps = [a.timestamp for a, _ in window_alerts]
        tactics = list(set(a.mitre_tactic for a, _ in window_alerts))
        
        # Merge entities
        unified_entities = {}
        for alert, domain in window_alerts:
            for entity_type, value in alert.entities.items():
                key = f"{domain.value}_{entity_type}"
                unified_entities[key] = value
        
        # Fuse features (concatenate and project)
        feature_sets = [a.features for a, _ in window_alerts]
        fused_features = self._fuse_feature_vectors(feature_sets)
        
        # Detect cross-domain indicators
        indicators = self._detect_cross_domain_indicators(window_alerts)
        
        return FusedAlert(
            fused_id=fused_id,
            timestamp=min(timestamps),
            source_domains=domains,
            unified_entities=unified_entities,
            fused_features=fused_features,
            mitre_tactics=tactics,
            cross_domain_indicators=indicators
        )
    
    def _fuse_feature_vectors(self, feature_sets: List[np.ndarray]) -> np.ndarray:
        """Fuse multiple feature vectors into one."""
        # Simple fusion: mean of features (after padding to same size)
        max_len = max(len(f) for f in feature_sets)
        padded = []
        
        for features in feature_sets:
            pad_width = max_len - len(features)
            if pad_width > 0:
                padded.append(np.pad(features, (0, pad_width), mode='constant'))
            else:
                padded.append(features)
        
        # Mean fusion
        fused = np.mean(padded, axis=0)
        
        # Ensure target dimension
        if len(fused) > self.fusion_dim:
            fused = fused[:self.fusion_dim]
        elif len(fused) < self.fusion_dim:
            fused = np.pad(fused, (0, self.fusion_dim - len(fused)), mode='constant')
        
        return fused
    
    def _detect_cross_domain_indicators(self, 
                                       window_alerts: List[Tuple[DomainFeatures, DataDomain]]) -> List[str]:
        """Detect indicators of cross-domain attacks."""
        indicators = []
        
        domains_present = set(d for _, d in window_alerts)
        
        # Multi-domain presence
        if len(domains_present) >= 2:
            indicators.append(f"multi_domain:{len(domains_present)}_domains")
        
        # Network + Host = Lateral movement indicator
        if DataDomain.NETWORK in domains_present and DataDomain.HOST in domains_present:
            indicators.append("suspected_lateral_movement")
        
        # Email + Network = Phishing delivery
        if DataDomain.EMAIL in domains_present and DataDomain.NETWORK in domains_present:
            indicators.append("suspected_phishing_campaign")
        
        # Cloud + Endpoint = Cloud compromise
        if DataDomain.CLOUD in domains_present and DataDomain.ENDPOINT in domains_present:
            indicators.append("suspected_cloud_compromise")
        
        return indicators
    
    def get_fusion_summary(self, fused_alerts: List[FusedAlert]) -> pd.DataFrame:
        """Get summary statistics of fused alerts."""
        summaries = []
        
        for alert in fused_alerts:
            summaries.append({
                'fused_id': alert.fused_id,
                'timestamp': alert.timestamp,
                'num_domains': len(alert.source_domains),
                'domains': ','.join(d.value for d in alert.source_domains),
                'num_tactics': len(alert.mitre_tactics),
                'tactics': ','.join(alert.mitre_tactics),
                'num_indicators': len(alert.cross_domain_indicators),
                'indicators': ','.join(alert.cross_domain_indicators),
                'num_entities': len(alert.unified_entities)
            })
        
        return pd.DataFrame(summaries)


def create_cross_domain_fusion(fusion_dim: int = 128) -> CrossDomainFusion:
    """Factory function for cross-domain fusion."""
    return CrossDomainFusion(fusion_dim=fusion_dim)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create sample multi-domain data
    network_df = pd.DataFrame({
        'timestamp': pd.date_range('2024-01-01', periods=10, freq='1min'),
        'src_ip': ['10.0.0.1'] * 10,
        'dst_ip': ['192.168.1.' + str(i) for i in range(10)],
        'src_port': [12345] * 10,
        'dst_port': [80] * 10,
        'protocol': ['TCP'] * 10,
        'bytes_sent': [1000] * 10,
        'tactic': ['Initial Access'] * 5 + ['Lateral Movement'] * 5
    })
    
    host_df = pd.DataFrame({
        'timestamp': pd.date_range('2024-01-01', periods=8, freq='2min'),
        'hostname': ['host-' + str(i) for i in range(8)],
        'process_name': ['powershell.exe'] * 8,
        'username': ['admin'] * 8,
        'file_path': ['/tmp/script'] * 8,
        'tactic': ['Execution'] * 4 + ['Persistence'] * 4
    })
    
    # Fuse
    fusion = create_cross_domain_fusion()
    
    domain_data = {
        DataDomain.NETWORK: network_df,
        DataDomain.HOST: host_df
    }
    
    fused_alerts = fusion.fuse_alerts(domain_data)
    
    # Summary
    summary = fusion.get_fusion_summary(fused_alerts)
    print(f"\nFusion Summary:\n{summary}")
    print(f"\nTotal fused alerts: {len(fused_alerts)}")
    
    # Show first fused alert details
    if fused_alerts:
        first = fused_alerts[0]
        print(f"\nFirst fused alert:")
        print(f"  Domains: {[d.value for d in first.source_domains]}")
        print(f"  Tactics: {first.mitre_tactics}")
        print(f"  Indicators: {first.cross_domain_indicators}")
        print(f"  Entities: {len(first.unified_entities)}")
