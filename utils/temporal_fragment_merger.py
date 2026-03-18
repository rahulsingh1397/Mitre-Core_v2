"""
Temporal Fragment Merger for MITRE-CORE
Merges fragmented temporal datasets (like Datasense IIoT) into continuous attack chains.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitre-core.temporal_merger")


@dataclass
class AttackChain:
    """Represents a continuous attack chain across temporal fragments."""
    chain_id: int
    start_time: datetime
    end_time: datetime
    attack_type: str
    source_ips: set
    target_ips: set
    events: List[Dict]
    confidence: float


class TemporalFragmentMerger:
    """
    Merges temporal fragments into continuous attack chains.
    
    Handles datasets like Datasense IIoT 2025 that split data into:
    - attack_samples_1sec.csv
    - attack_samples_5sec.csv
    - benign_samples_1sec.csv
    - benign_samples_5sec.csv
    """
    
    def __init__(self, 
                 max_gap_seconds: int = 300,
                 min_chain_duration: int = 1,
                 time_column: str = 'timestamp',
                 attack_column: str = 'label'):
        """
        Initialize the temporal fragment merger.
        
        Args:
            max_gap_seconds: Maximum time gap between events to consider same chain
            min_chain_duration: Minimum duration (seconds) for a valid attack chain
            time_column: Column name containing timestamps
            attack_column: Column name containing attack labels
        """
        self.max_gap = timedelta(seconds=max_gap_seconds)
        self.min_duration = timedelta(seconds=min_chain_duration)
        self.time_col = time_column
        self.attack_col = attack_column
        self.chains = []
    
    def merge_datasense_fragments(self, 
                                   attack_1sec_path: Path,
                                   attack_5sec_path: Path,
                                   benign_1sec_path: Optional[Path] = None,
                                   benign_5sec_path: Optional[Path] = None) -> pd.DataFrame:
        """
        Merge DataSense IIoT temporal fragments into continuous dataset.
        
        Args:
            attack_1sec_path: Path to 1-second attack samples
            attack_5sec_path: Path to 5-second attack samples
            benign_1sec_path: Path to 1-second benign samples (optional)
            benign_5sec_path: Path to 5-second benign samples (optional)
            
        Returns:
            Merged DataFrame with continuous attack chains
        """
        logger.info("Merging DataSense IIoT temporal fragments...")
        
        # Load all fragments
        fragments = []
        
        # Load attack fragments
        for path, interval in [(attack_1sec_path, 1), (attack_5sec_path, 5)]:
            if path and path.exists():
                df = pd.read_csv(path)
                df['sample_interval'] = interval
                df['fragment_type'] = 'attack'
                fragments.append(df)
                logger.info(f"  Loaded {len(df)} records from {path.name}")
        
        # Load benign fragments
        for path, interval in [(benign_1sec_path, 1), (benign_5sec_path, 5)]:
            if path and path.exists():
                df = pd.read_csv(path)
                df['sample_interval'] = interval
                df['fragment_type'] = 'benign'
                fragments.append(df)
                logger.info(f"  Loaded {len(df)} records from {path.name}")
        
        if not fragments:
            raise ValueError("No fragments found to merge")
        
        # Combine all fragments
        combined = pd.concat(fragments, ignore_index=True)
        logger.info(f"Combined {len(combined)} total records")
        
        # Normalize timestamps
        combined[self.time_col] = pd.to_datetime(combined[self.time_col], errors='coerce')
        
        # Sort by timestamp
        combined = combined.sort_values(self.time_col).reset_index(drop=True)
        
        # Build continuous attack chains
        merged = self._build_attack_chains(combined)
        
        logger.info(f"Built {len(self.chains)} continuous attack chains")
        logger.info(f"Final merged dataset: {len(merged)} records")
        
        return merged
    
    def _build_attack_chains(self, df: pd.DataFrame) -> pd.DataFrame:
        """Build continuous attack chains from sorted events."""
        if df.empty:
            return df
        
        chains = []
        current_chain = None
        chain_counter = 0
        chain_assignments = []
        
        for idx, row in df.iterrows():
            current_time = row[self.time_col]
            attack_type = row.get(self.attack_col, 'Unknown')
            
            # Check if this event continues current chain
            if current_chain is None:
                # Start first chain
                current_chain = {
                    'id': chain_counter,
                    'start': current_time,
                    'end': current_time,
                    'attack_type': attack_type,
                    'events': [row.to_dict()]
                }
                chain_assignments.append(chain_counter)
                
            elif self._is_chain_continuation(current_chain, row):
                # Continue current chain
                current_chain['end'] = current_time
                current_chain['events'].append(row.to_dict())
                chain_assignments.append(current_chain['id'])
                
            else:
                # Finalize current chain
                if len(current_chain['events']) >= 1:
                    chains.append(current_chain)
                
                # Start new chain
                chain_counter += 1
                current_chain = {
                    'id': chain_counter,
                    'start': current_time,
                    'end': current_time,
                    'attack_type': attack_type,
                    'events': [row.to_dict()]
                }
                chain_assignments.append(chain_counter)
        
        # Add final chain
        if current_chain and len(current_chain['events']) >= 1:
            chains.append(current_chain)
        
        # Store chains for later reference
        self.chains = chains
        
        # Add chain_id to dataframe
        df['chain_id'] = chain_assignments
        df['chain_start'] = df['chain_id'].map(
            {c['id']: c['start'] for c in chains}
        )
        df['chain_end'] = df['chain_id'].map(
            {c['id']: c['end'] for c in chains}
        )
        df['chain_duration'] = (df['chain_end'] - df['chain_start']).dt.total_seconds()
        df['chain_size'] = df['chain_id'].map(
            {c['id']: len(c['events']) for c in chains}
        )
        
        return df
    
    def _is_chain_continuation(self, chain: Dict, row: pd.Series) -> bool:
        """Check if row continues the current attack chain."""
        current_time = row[self.time_col]
        last_time = chain['end']
        time_diff = current_time - last_time
        
        # Check time gap
        if time_diff > self.max_gap:
            return False
        
        # Check if attack type matches or is related
        current_attack = row.get(self.attack_col, 'Unknown')
        chain_attack = chain['attack_type']
        
        # Same attack type continues chain
        if current_attack == chain_attack:
            return True
        
        # Different but related attack types can continue chain
        # (e.g., Reconnaissance -> Exploitation)
        if self._are_related_attacks(chain_attack, current_attack):
            return True
        
        return False
    
    def _are_related_attacks(self, attack1: str, attack2: str) -> bool:
        """Check if two attack types are part of same kill chain."""
        # Define related attack progressions
        related_groups = [
            {'scan', 'portscan', 'recon', 'reconnaissance'},
            {'exploit', 'injection', 'sql', 'xss', 'web'},
            {'brute', 'password', 'credential'},
            {'dos', 'ddos', 'flood'},
            {'mirai', 'bot', 'botnet', 'cnc'},
            {'backdoor', 'rootkit', 'persistence'}
        ]
        
        attack1_lower = str(attack1).lower()
        attack2_lower = str(attack2).lower()
        
        for group in related_groups:
            if any(a in attack1_lower for a in group) and any(a in attack2_lower for a in group):
                return True
        
        return False
    
    def get_chain_summary(self) -> pd.DataFrame:
        """Get summary statistics of built attack chains."""
        if not self.chains:
            return pd.DataFrame()
        
        summaries = []
        for chain in self.chains:
            duration = (chain['end'] - chain['start']).total_seconds()
            summaries.append({
                'chain_id': chain['id'],
                'attack_type': chain['attack_type'],
                'start_time': chain['start'],
                'end_time': chain['end'],
                'duration_seconds': duration,
                'num_events': len(chain['events']),
                'events_per_second': len(chain['events']) / max(duration, 1)
            })
        
        return pd.DataFrame(summaries)
    
    def filter_significant_chains(self, 
                                   df: pd.DataFrame,
                                   min_events: int = 3,
                                   min_duration_seconds: int = 5) -> pd.DataFrame:
        """
        Filter to keep only significant attack chains.
        
        Args:
            df: Merged dataframe with chain_id
            min_events: Minimum events per chain
            min_duration_seconds: Minimum chain duration
            
        Returns:
            Filtered DataFrame
        """
        # Calculate chain statistics
        chain_stats = df.groupby('chain_id').agg({
            self.time_col: ['count', 'min', 'max']
        }).reset_index()
        
        chain_stats.columns = ['chain_id', 'event_count', 'start_time', 'end_time']
        chain_stats['duration'] = (
            chain_stats['end_time'] - chain_stats['start_time']
        ).dt.total_seconds()
        
        # Filter chains
        significant_chains = chain_stats[
            (chain_stats['event_count'] >= min_events) &
            (chain_stats['duration'] >= min_duration_seconds)
        ]['chain_id'].tolist()
        
        filtered = df[df['chain_id'].isin(significant_chains)].copy()
        
        logger.info(f"Filtered from {df['chain_id'].nunique()} to "
                   f"{len(significant_chains)} significant chains")
        
        return filtered
    
    def export_chain_graph(self, output_path: Path):
        """Export attack chains as graph for visualization."""
        import json
        
        graph_data = {
            'nodes': [],
            'edges': [],
            'chains': []
        }
        
        # Add chain nodes
        for chain in self.chains:
            graph_data['nodes'].append({
                'id': f"chain_{chain['id']}",
                'type': 'chain',
                'attack_type': chain['attack_type'],
                'start': chain['start'].isoformat(),
                'end': chain['end'].isoformat(),
                'event_count': len(chain['events'])
            })
            
            graph_data['chains'].append({
                'id': chain['id'],
                'events': chain['events']
            })
        
        # Add edges between related chains (temporal proximity)
        for i, chain1 in enumerate(self.chains):
            for chain2 in self.chains[i+1:]:
                time_diff = abs((chain2['start'] - chain1['end']).total_seconds())
                if time_diff < self.max_gap.total_seconds():
                    graph_data['edges'].append({
                        'source': f"chain_{chain1['id']}",
                        'target': f"chain_{chain2['id']}",
                        'type': 'temporal_proximity',
                        'time_gap_seconds': time_diff
                    })
        
        with open(output_path, 'w') as f:
            json.dump(graph_data, f, indent=2, default=str)
        
        logger.info(f"Exported chain graph to {output_path}")


def merge_datasense_dataset(base_path: str = "./datasets/Datasense_IIoT_2025") -> pd.DataFrame:
    """
    Convenience function to merge DataSense IIoT 2025 dataset.
    
    Args:
        base_path: Path to DataSense_IIoT_2025 directory
        
    Returns:
        Merged DataFrame
    """
    base = Path(base_path)
    
    merger = TemporalFragmentMerger(
        max_gap_seconds=300,  # 5 minute gap threshold
        min_chain_duration=1,
        time_column='timestamp',
        attack_column='label'
    )
    
    # Define fragment paths
    attack_1sec = base / "attack_data" / "attack_samples_1sec.csv" / "attack_samples_1sec.csv"
    attack_5sec = base / "attack_data" / "attack_samples_5sec.csv" / "attack_samples_5sec.csv"
    benign_1sec = base / "benign_data" / "benign_samples_1sec.csv" / "benign_samples_1sec.csv"
    benign_5sec = base / "benign_data" / "benign_samples_5sec.csv" / "benign_samples_5sec.csv"
    
    # Merge fragments
    merged = merger.merge_datasense_fragments(
        attack_1sec_path=attack_1sec if attack_1sec.exists() else None,
        attack_5sec_path=attack_5sec if attack_5sec.exists() else None,
        benign_1sec_path=benign_1sec if benign_1sec.exists() else None,
        benign_5sec_path=benign_5sec if benign_5sec.exists() else None
    )
    
    # Filter significant chains
    significant = merger.filter_significant_chains(
        merged, 
        min_events=3,
        min_duration_seconds=5
    )
    
    # Export chain graph for visualization
    graph_path = base / "attack_chains_graph.json"
    merger.export_chain_graph(graph_path)
    
    # Save merged dataset
    output_path = base / "merged_continuous.csv"
    significant.to_csv(output_path, index=False)
    logger.info(f"Saved merged dataset to {output_path}")
    
    # Print summary
    summary = merger.get_chain_summary()
    logger.info("\nAttack Chain Summary:")
    logger.info(summary.describe())
    
    return significant


if __name__ == "__main__":
    # Example usage
    try:
        merged_df = merge_datasense_dataset()
        print(f"\nSuccessfully merged DataSense dataset: {len(merged_df)} records")
        print(f"Attack chains: {merged_df['chain_id'].nunique()}")
    except Exception as e:
        logger.error(f"Failed to merge dataset: {e}")
        
        # Generate synthetic example for testing
        logger.info("\nGenerating synthetic temporal fragments for testing...")
        
        np.random.seed(42)
        base_time = datetime(2025, 1, 1, 8, 0, 0)
        
        # Create synthetic fragmented data
        synthetic_data = []
        for i in range(100):
            time_offset = np.random.randint(0, 3600)
            timestamp = base_time + timedelta(seconds=time_offset)
            
            attack_types = ['Normal', 'Recon-PortScan', 'DoS-Syn', 'Mirai-Greeth']
            attack = np.random.choice(attack_types, p=[0.5, 0.2, 0.15, 0.15])
            
            synthetic_data.append({
                'timestamp': timestamp,
                'src_ip': f"192.168.1.{np.random.randint(2, 50)}",
                'dst_ip': f"10.0.0.{np.random.randint(1, 100)}",
                'label': attack,
                'value': np.random.randn()
            })
        
        df = pd.DataFrame(synthetic_data)
        df = df.sort_values('timestamp')
        
        # Test the merger
        merger = TemporalFragmentMerger(
            max_gap_seconds=60,
            time_column='timestamp',
            attack_column='label'
        )
        
        merged = merger._build_attack_chains(df)
        summary = merger.get_chain_summary()
        
        print(f"\nSynthetic data chains: {len(merger.chains)}")
        print(summary.head(10))
