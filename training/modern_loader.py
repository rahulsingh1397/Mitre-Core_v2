import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, List, Dict, Union
import logging
import datetime

logger = logging.getLogger(__name__)

class ModernDatasetLoader:
    """
    Loader and preprocessor for modern cybersecurity datasets (2023-2025).
    Handles mapping from typical flow-based or IoT datasets (e.g., CIC IoT, DataSense IIoT 2025)
    to the MITRE-CORE 11-field compatible schema for HGNN and Union-Find processing.
    """

    def __init__(self, dataset_type: str = "cic"):
        """
        Initialize the loader.
        
        Args:
            dataset_type: The format family of the dataset (e.g., 'cic' for CIC-IoT-2024/2025, 'gotham', 'ids2025')
        """
        self.dataset_type = dataset_type.lower()
        
    def load_and_preprocess(self, file_path: Union[str, Path], is_synthetic: bool = False, num_synthetic_records: int = 1000) -> pd.DataFrame:
        """
        Load a dataset and preprocess it to MITRE-CORE schema.
        
        Args:
            file_path: Path to the dataset CSV.
            is_synthetic: If True, generates a synthetic dataset matching the type instead of loading.
            num_synthetic_records: Number of records to generate if is_synthetic is True.
        """
        if is_synthetic:
            logger.info(f"Generating synthetic {self.dataset_type} dataset with {num_synthetic_records} records...")
            df_raw = self._generate_synthetic_data(num_synthetic_records)
        else:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Dataset not found at {file_path}")
            logger.info(f"Loading dataset from {file_path}...")
            df_raw = pd.read_csv(file_path)

        logger.info(f"Raw dataset shape: {df_raw.shape}")
        
        # Preprocess based on dataset type
        if self.dataset_type in ["cic", "datasense", "cic_iot"]:
            return self._preprocess_cic_format(df_raw)
        elif self.dataset_type in ["gotham", "lsnm2024"]:
            return self._preprocess_generic_flow(df_raw)
        else:
            # Fallback to generic preprocessor
            return self._preprocess_generic_flow(df_raw)

    def _generate_synthetic_data(self, n_records: int) -> pd.DataFrame:
        """Generate synthetic flow data matching modern CIC dataset features."""
        np.random.seed(42)
        
        base_time = datetime.datetime(2025, 1, 1, 8, 0, 0)
        timestamps = [base_time + datetime.timedelta(seconds=np.random.randint(0, 86400)) for _ in range(n_records)]
        timestamps.sort()

        # Modern attacks: Mirai, DoS, Recon, Normal
        labels = np.random.choice(['Normal', 'Mirai-Greeth', 'DoS-Syn', 'Recon-PortScan', 'DDoS-UDP'], size=n_records, p=[0.6, 0.1, 0.1, 0.1, 0.1])
        
        src_ips = [f"192.168.1.{np.random.randint(2, 50)}" if l == 'Normal' else f"10.0.0.{np.random.randint(1, 100)}" for l in labels]
        dst_ips = [f"192.168.1.{np.random.randint(100, 200)}" if l != 'Recon-PortScan' else f"192.168.1.{np.random.randint(2, 255)}" for l in labels]
        
        return pd.DataFrame({
            'Timestamp': [t.strftime("%d/%m/%Y %H:%M:%S") for t in timestamps],
            'Src IP': src_ips,
            'Dst IP': dst_ips,
            'Src Port': np.random.randint(1024, 65535, size=n_records),
            'Dst Port': [80 if l == 'Normal' else np.random.choice([80, 443, 22, 23, 8080]) for l in labels],
            'Protocol': np.random.choice([6, 17], size=n_records), # TCP=6, UDP=17
            'Flow Duration': np.random.randint(1000, 10000000, size=n_records),
            'Tot Fwd Pkts': np.random.randint(1, 100, size=n_records),
            'Tot Bwd Pkts': np.random.randint(1, 100, size=n_records),
            'Label': labels
        })

    def _preprocess_cic_format(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess CIC-style flow datasets into MITRE-CORE schema."""
        mitre_df = pd.DataFrame()
        
        # Mapping IPs -> Addresses
        mitre_df['SourceAddress'] = df.get('Src IP', df.get('Source IP', '0.0.0.0'))
        mitre_df['DestinationAddress'] = df.get('Dst IP', df.get('Destination IP', '0.0.0.0'))
        
        # Simulate a DeviceAddress (e.g., the firewall/sensor logging the flow)
        mitre_df['DeviceAddress'] = '172.16.254.1'
        
        # Hostnames (Infer from IPs for correlation purposes)
        mitre_df['SourceHostName'] = mitre_df['SourceAddress'].apply(lambda x: f"host-{str(x).replace('.', '-')}")
        mitre_df['DestinationHostName'] = mitre_df['DestinationAddress'].apply(lambda x: f"target-{str(x).replace('.', '-')}")
        mitre_df['DeviceHostName'] = 'sensor-alpha'
        
        # Timestamps
        if 'Timestamp' in df.columns:
            # Handle various timestamp formats, convert to ISO
            parsed_dates = pd.to_datetime(df['Timestamp'], errors='coerce')
            mitre_df['EndDate'] = parsed_dates.dt.strftime('%Y-%m-%dT%H:%M:%S').fillna('2025-01-01T00:00:00')
        else:
            base_time = pd.Timestamp('2025-01-01T00:00:00')
            mitre_df['EndDate'] = [ (base_time + pd.Timedelta(seconds=i)).strftime('%Y-%m-%dT%H:%M:%S') for i in range(len(df)) ]
            
        # Optional metadata features (useful for HGNN but ignored by pure Union-Find addresses/usernames)
        mitre_df['Protocol'] = df.get('Protocol', 6).astype(str)
        mitre_df['SourcePort'] = df.get('Src Port', df.get('Source Port', 0)).astype(str)
        mitre_df['DestinationPort'] = df.get('Dst Port', df.get('Destination Port', 0)).astype(str)
        mitre_df['FlowDuration'] = df.get('Flow Duration', 0)
        
        # Attack Labels
        mitre_df['Attack_Type'] = df.get('Label', 'Normal')
        mitre_df['Is_Attack'] = mitre_df['Attack_Type'].apply(lambda x: 0 if str(x).lower() in ['normal', 'benign'] else 1)
        
        # Tactic Mapping for Modern IoT/Cloud attacks
        mitre_df['Tactic'] = mitre_df['Attack_Type'].apply(self._map_modern_tactic)
        
        return mitre_df

    def _preprocess_generic_flow(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fallback for generic or unrecognized dataset schemas."""
        # Try to find standard columns by fuzzy matching
        cols = {c.lower(): c for c in df.columns}
        
        src_ip_col = cols.get('src_ip', cols.get('sourceip', cols.get('sa', None)))
        dst_ip_col = cols.get('dst_ip', cols.get('destinationip', cols.get('da', None)))
        
        mitre_df = pd.DataFrame()
        mitre_df['SourceAddress'] = df[src_ip_col] if src_ip_col else '10.0.0.1'
        mitre_df['DestinationAddress'] = df[dst_ip_col] if dst_ip_col else '10.0.0.2'
        mitre_df['DeviceAddress'] = '192.168.0.1'
        
        mitre_df['SourceHostName'] = mitre_df['SourceAddress'].apply(lambda x: f"src-{x}")
        mitre_df['DestinationHostName'] = mitre_df['DestinationAddress'].apply(lambda x: f"dst-{x}")
        mitre_df['DeviceHostName'] = 'generic-sensor'
        
        time_col = cols.get('timestamp', cols.get('time', cols.get('date', None)))
        if time_col:
            mitre_df['EndDate'] = pd.to_datetime(df[time_col], errors='coerce').dt.strftime('%Y-%m-%dT%H:%M:%S')
        else:
            mitre_df['EndDate'] = '2025-01-01T12:00:00'
            
        label_col = cols.get('label', cols.get('attack', cols.get('category', None)))
        mitre_df['Attack_Type'] = df[label_col] if label_col else 'Unknown'
        
        return mitre_df

    def _map_modern_tactic(self, attack_label: str) -> str:
        """Map modern attacks (Mirai, DoS, IoT-specific) to MITRE ATT&CK Tactics."""
        label = str(attack_label).lower()
        if 'normal' in label or 'benign' in label:
            return 'None'
        elif 'recon' in label or 'portscan' in label or 'scan' in label:
            return 'Discovery'
        elif 'mirai' in label or 'bot' in label:
            return 'Command and Control'
        elif 'dos' in label or 'ddos' in label or 'flood' in label:
            return 'Impact'
        elif 'brute' in label or 'crack' in label:
            return 'Credential Access'
        elif 'spoof' in label or 'mitm' in label:
            return 'Collection'
        elif 'web' in label or 'sql' in label or 'xss' in label:
            return 'Initial Access'
        return 'Execution' # Default fallback

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    loader = ModernDatasetLoader("datasense")
    # Generate 500 records of synthetic modern DataSense/CIC format data
    df = loader.load_and_preprocess(file_path="", is_synthetic=True, num_synthetic_records=500)
    print("\nSample Processed MITRE-CORE Schema Data:")
    print(df[['EndDate', 'SourceAddress', 'DestinationAddress', 'Attack_Type', 'Tactic']].head(10))
    print(f"\nUnique Tactics Found: {df['Tactic'].unique()}")
