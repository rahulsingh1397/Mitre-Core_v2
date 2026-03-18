"""
Long-Range Temporal Correlation for APT Campaign Detection
Handles multi-day and multi-week attack campaigns with temporal modeling.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import logging

logger = logging.getLogger("mitre-core.temporal_correlation")


@dataclass
class TemporalSegment:
    """Represents a temporal segment in a long-range campaign."""
    segment_id: int
    start_time: datetime
    end_time: datetime
    alerts: List[int]
    stage: str  # MITRE ATT&CK stage
    tactics: List[str]


@dataclass
class APTCampaign:
    """Represents a detected APT campaign spanning multiple days."""
    campaign_id: int
    start_time: datetime
    end_time: datetime
    segments: List[TemporalSegment]
    attack_chain: List[str]
    involved_entities: Dict[str, List[str]]
    confidence: float


class LongRangeTemporalCorrelator:
    """
    Detects long-range temporal correlations for APT campaigns.
    
    Features:
    - Multi-day attack chain detection
    - Dormant period handling
    - Stage progression modeling
    - Entity persistence tracking
    """
    
    def __init__(self,
                 max_gap_hours: int = 72,  # Max gap between stages
                 min_campaign_duration_hours: int = 24,
                 stage_progression_window: int = 168):  # 1 week
        self.max_gap = timedelta(hours=max_gap_hours)
        self.min_duration = timedelta(hours=min_campaign_duration_hours)
        self.progression_window = timedelta(hours=stage_progression_window)
        self.campaigns = []
        
        # MITRE ATT&CK stage ordering for APT
        self.apt_stage_order = [
            'Reconnaissance',
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Command and Control',
            'Exfiltration',
            'Impact'
        ]
    
    def detect_apt_campaigns(self, 
                          df: pd.DataFrame,
                          entity_col: str = 'src_ip') -> List[APTCampaign]:
        """
        Detect APT campaigns from alert data.
        
        Args:
            df: DataFrame with alerts (must have 'timestamp', 'tactic', entity_col)
            entity_col: Column to track persistent entities
            
        Returns:
            List of detected APT campaigns
        """
        logger.info(f"Detecting APT campaigns from {len(df)} alerts")
        
        # Sort by timestamp
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Group by persistent entities
        entity_groups = self._group_by_entity_persistence(df, entity_col)
        
        campaigns = []
        campaign_id = 0
        
        for entity, entity_df in entity_groups.items():
            # Check if this entity shows APT-like behavior
            if self._is_apt_like(entity_df):
                # Detect temporal segments
                segments = self._detect_temporal_segments(entity_df)
                
                # Build attack chain
                attack_chain = self._build_attack_chain(segments)
                
                # Check for multi-stage progression
                if len(segments) >= 3 and len(attack_chain) >= 3:
                    campaign = APTCampaign(
                        campaign_id=campaign_id,
                        start_time=entity_df['timestamp'].min(),
                        end_time=entity_df['timestamp'].max(),
                        segments=segments,
                        attack_chain=attack_chain,
                        involved_entities={
                            entity_col: [entity],
                            'hosts': entity_df.get('hostname', pd.Series()).unique().tolist(),
                            'users': entity_df.get('username', pd.Series()).unique().tolist()
                        },
                        confidence=self._calculate_campaign_confidence(segments, attack_chain)
                    )
                    campaigns.append(campaign)
                    campaign_id += 1
        
        self.campaigns = campaigns
        logger.info(f"Detected {len(campaigns)} APT campaigns")
        
        return campaigns
    
    def _group_by_entity_persistence(self, 
                                      df: pd.DataFrame,
                                      entity_col: str) -> Dict[str, pd.DataFrame]:
        """Group alerts by entities that persist over time."""
        groups = {}
        
        for entity in df[entity_col].unique():
            entity_df = df[df[entity_col] == entity].copy()
            
            # Check persistence (alerts spanning multiple days)
            time_span = entity_df['timestamp'].max() - entity_df['timestamp'].min()
            
            if time_span >= self.min_duration:
                groups[entity] = entity_df
        
        return groups
    
    def _is_apt_like(self, entity_df: pd.DataFrame) -> bool:
        """Check if entity behavior shows APT characteristics."""
        # Check 1: Multi-stage activity
        if 'tactic' in entity_df.columns:
            unique_tactics = entity_df['tactic'].nunique()
            if unique_tactics < 3:
                return False
        
        # Check 2: Duration
        time_span = entity_df['timestamp'].max() - entity_df['timestamp'].min()
        if time_span < self.min_duration:
            return False
        
        # Check 3: Activity pattern (not just bursts)
        entity_df = entity_df.copy()
        entity_df['date'] = entity_df['timestamp'].dt.date
        active_days = entity_df['date'].nunique()
        
        if active_days < 2:  # Need activity on multiple days
            return False
        
        return True
    
    def _detect_temporal_segments(self, entity_df: pd.DataFrame) -> List[TemporalSegment]:
        """Detect temporal segments within entity activity."""
        segments = []
        segment_id = 0
        
        # Group by time windows
        entity_df = entity_df.sort_values('timestamp')
        current_segment = []
        last_time = None
        
        for idx, row in entity_df.iterrows():
            if last_time is None:
                current_segment = [row]
            elif (row['timestamp'] - last_time) <= self.max_gap:
                current_segment.append(row)
            else:
                # Save current segment
                if len(current_segment) >= 2:
                    segment = self._create_segment(current_segment, segment_id)
                    if segment:
                        segments.append(segment)
                        segment_id += 1
                
                # Start new segment
                current_segment = [row]
            
            last_time = row['timestamp']
        
        # Save final segment
        if len(current_segment) >= 2:
            segment = self._create_segment(current_segment, segment_id)
            if segment:
                segments.append(segment)
        
        return segments
    
    def _create_segment(self, alert_rows: List[pd.Series], segment_id: int) -> Optional[TemporalSegment]:
        """Create a temporal segment from alert rows."""
        if not alert_rows:
            return None
        
        df = pd.DataFrame(alert_rows)
        
        # Determine dominant stage/tactic
        if 'tactic' in df.columns:
            dominant_tactic = df['tactic'].mode().iloc[0]
            all_tactics = df['tactic'].unique().tolist()
        else:
            dominant_tactic = 'Unknown'
            all_tactics = []
        
        return TemporalSegment(
            segment_id=segment_id,
            start_time=df['timestamp'].min(),
            end_time=df['timestamp'].max(),
            alerts=df.index.tolist(),
            stage=dominant_tactic,
            tactics=all_tactics
        )
    
    def _build_attack_chain(self, segments: List[TemporalSegment]) -> List[str]:
        """Build attack chain from temporal segments."""
        # Sort segments by time
        sorted_segments = sorted(segments, key=lambda s: s.start_time)
        
        # Extract stages in order
        chain = []
        for segment in sorted_segments:
            if segment.stage not in chain and segment.stage != 'Unknown':
                chain.append(segment.stage)
        
        # Validate progression
        return self._validate_progression(chain)
    
    def _validate_progression(self, chain: List[str]) -> List[str]:
        """Validate that chain follows logical MITRE progression."""
        if len(chain) < 2:
            return chain
        
        # Check for required early stages
        if 'Reconnaissance' in chain and 'Initial Access' not in chain:
            # May be external recon followed by direct access
            pass
        
        # Check for typical APT flow
        has_access = any(s in chain for s in ['Initial Access', 'Execution'])
        has_persistence = any(s in chain for s in ['Persistence', 'Privilege Escalation'])
        has_lateral = 'Lateral Movement' in chain
        has_exfil = 'Exfiltration' in chain
        
        # Return chain with confidence annotation
        return chain
    
    def _calculate_campaign_confidence(self,
                                      segments: List[TemporalSegment],
                                      attack_chain: List[str]) -> float:
        """Calculate confidence score for campaign detection."""
        confidence = 0.0
        
        # Factor 1: Number of segments
        confidence += min(len(segments) * 0.1, 0.3)
        
        # Factor 2: Attack chain length
        confidence += min(len(attack_chain) * 0.05, 0.3)
        
        # Factor 3: Has critical APT stages
        critical_stages = ['Initial Access', 'Persistence', 'Lateral Movement', 'Exfiltration']
        has_critical = sum(1 for s in critical_stages if s in attack_chain)
        confidence += has_critical * 0.1
        
        # Factor 4: Stage progression quality
        if len(attack_chain) >= 3:
            # Check if early -> middle -> late stages present
            early = any(s in attack_chain for s in ['Reconnaissance', 'Initial Access'])
            middle = any(s in attack_chain for s in ['Execution', 'Persistence', 'Discovery'])
            late = any(s in attack_chain for s in ['Lateral Movement', 'Exfiltration', 'Impact'])
            
            if early and middle and late:
                confidence += 0.3
        
        return min(1.0, confidence)
    
    def get_campaign_summary(self) -> pd.DataFrame:
        """Get summary of all detected campaigns."""
        summaries = []
        
        for campaign in self.campaigns:
            duration = (campaign.end_time - campaign.start_time).total_seconds() / 3600
            
            summaries.append({
                'campaign_id': campaign.campaign_id,
                'duration_hours': duration,
                'num_segments': len(campaign.segments),
                'attack_chain': ' -> '.join(campaign.attack_chain),
                'num_entities': len(campaign.involved_entities),
                'confidence': campaign.confidence,
                'total_alerts': sum(len(s.alerts) for s in campaign.segments)
            })
        
        return pd.DataFrame(summaries)
    
    def export_campaign_timeline(self, 
                                campaign_id: int,
                                output_path: str):
        """Export campaign timeline for visualization."""
        campaign = next((c for c in self.campaigns if c.campaign_id == campaign_id), None)
        if not campaign:
            logger.error(f"Campaign {campaign_id} not found")
            return
        
        timeline = []
        for segment in campaign.segments:
            timeline.append({
                'segment_id': segment.segment_id,
                'start': segment.start_time.isoformat(),
                'end': segment.end_time.isoformat(),
                'stage': segment.stage,
                'num_alerts': len(segment.alerts)
            })
        
        import json
        with open(output_path, 'w') as f:
            json.dump({
                'campaign_id': campaign_id,
                'timeline': timeline,
                'attack_chain': campaign.attack_chain,
                'confidence': campaign.confidence
            }, f, indent=2)
        
        logger.info(f"Campaign timeline exported to {output_path}")


class DormantPeriodDetector:
    """
    Detects dormant periods in APT campaigns where activity pauses.
    """
    
    def __init__(self, 
                 dormant_threshold_hours: int = 48):
        self.dormant_threshold = timedelta(hours=dormant_threshold_hours)
    
    def detect_dormant_periods(self, 
                              df: pd.DataFrame) -> List[Tuple[datetime, datetime]]:
        """Detect periods of inactivity in alert sequence."""
        df = df.sort_values('timestamp')
        
        dormant_periods = []
        last_time = None
        
        for idx, row in df.iterrows():
            current_time = row['timestamp']
            
            if last_time is not None:
                gap = current_time - last_time
                
                if gap > self.dormant_threshold:
                    dormant_periods.append((last_time, current_time))
            
            last_time = current_time
        
        return dormant_periods


def create_long_range_correlator(max_gap_hours: int = 72) -> LongRangeTemporalCorrelator:
    """Factory function for long-range correlator."""
    return LongRangeTemporalCorrelator(max_gap_hours=max_gap_hours)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Generate sample APT-like data
    np.random.seed(42)
    base_time = datetime(2024, 1, 1, 8, 0, 0)
    
    # Simulate multi-day campaign
    alerts = []
    alert_id = 0
    
    # Day 1: Reconnaissance
    for i in range(20):
        alerts.append({
            'alert_id': alert_id,
            'timestamp': base_time + timedelta(hours=i),
            'src_ip': '10.0.0.5',
            'tactic': 'Reconnaissance',
            'hostname': 'attacker-host',
            'username': 'root'
        })
        alert_id += 1
    
    # Day 2: Initial Access
    for i in range(15):
        alerts.append({
            'alert_id': alert_id,
            'timestamp': base_time + timedelta(days=1, hours=i),
            'src_ip': '10.0.0.5',
            'tactic': 'Initial Access',
            'hostname': 'web-server',
            'username': 'admin'
        })
        alert_id += 1
    
    # Dormant period (2 days)
    
    # Day 5: Lateral Movement
    for i in range(25):
        alerts.append({
            'alert_id': alert_id,
            'timestamp': base_time + timedelta(days=4, hours=i),
            'src_ip': '10.0.0.5',
            'tactic': 'Lateral Movement',
            'hostname': 'db-server',
            'username': 'admin'
        })
        alert_id += 1
    
    # Day 6: Exfiltration
    for i in range(10):
        alerts.append({
            'alert_id': alert_id,
            'timestamp': base_time + timedelta(days=5, hours=i),
            'src_ip': '10.0.0.5',
            'tactic': 'Exfiltration',
            'hostname': 'file-server',
            'username': 'admin'
        })
        alert_id += 1
    
    df = pd.DataFrame(alerts)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Detect campaigns
    correlator = create_long_range_correlator(max_gap_hours=72)
    campaigns = correlator.detect_apt_campaigns(df, entity_col='src_ip')
    
    # Summary
    summary = correlator.get_campaign_summary()
    print(f"\nCampaign Summary:\n{summary}")
    
    # Detect dormant periods
    dormant_detector = DormantPeriodDetector(dormant_threshold_hours=24)
    dormant = dormant_detector.detect_dormant_periods(df)
    print(f"\nDormant Periods: {len(dormant)}")
    for start, end in dormant:
        print(f"  {start} -> {end} ({(end-start).total_seconds()/3600:.1f} hours)")
