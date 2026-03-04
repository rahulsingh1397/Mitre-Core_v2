"""
Dataset Downloader for MITRE-CORE HGNN Training
Downloads public cybersecurity datasets and converts to MITRE-CORE format
"""

import os
import urllib.request
import zipfile
import tarfile
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitre-core.datasets")


class DatasetDownloader:
    """Download and prepare public cybersecurity datasets for HGNN training."""
    
    def __init__(self, base_path: str = "./datasets"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        self.datasets = {
            'nsl_kdd': {
                'name': 'NSL-KDD',
                'urls': {
                    'train': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
                    'test': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt',
                    'features': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/training_attack_types.txt'
                },
                'format': 'csv',
                'size': '148K records'
            },
            'unsw_nb15': {
                'name': 'UNSW-NB15',
                'urls': {
                    'train': 'https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_training-set.csv',
                    'test': 'https://raw.githubusercontent.com/Nir-J/ML-Projects/master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv'
                },
                'format': 'csv',
                'size': '2M records'
            }
        }
    
    def download_file(self, url: str, dest_path: Path, desc: str) -> bool:
        """Download a file with progress tracking."""
        try:
            logger.info(f"Downloading {desc}...")
            urllib.request.urlretrieve(url, dest_path)
            logger.info(f"✓ Downloaded to {dest_path}")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to download {desc}: {e}")
            return False
    
    def download_nsl_kdd(self) -> Optional[Path]:
        """Download NSL-KDD dataset."""
        dataset_dir = self.base_path / "nsl_kdd"
        dataset_dir.mkdir(exist_ok=True)
        
        # Column names for NSL-KDD
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        train_path = dataset_dir / "KDDTrain+.txt"
        test_path = dataset_dir / "KDDTest+.txt"
        
        # Download
        if not train_path.exists():
            self.download_file(
                self.datasets['nsl_kdd']['urls']['train'],
                train_path,
                "NSL-KDD Train"
            )
        
        if not test_path.exists():
            self.download_file(
                self.datasets['nsl_kdd']['urls']['test'],
                test_path,
                "NSL-KDD Test"
            )
        
        # Convert to DataFrame and save as CSV
        if train_path.exists() and not (dataset_dir / "train.csv").exists():
            logger.info("Converting NSL-KDD to CSV format...")
            df_train = pd.read_csv(train_path, names=columns)
            df_train.to_csv(dataset_dir / "train.csv", index=False)
            
            df_test = pd.read_csv(test_path, names=columns)
            df_test.to_csv(dataset_dir / "test.csv", index=False)
            
            logger.info(f"✓ NSL-KDD: {len(df_train)} train, {len(df_test)} test records")
        
        return dataset_dir
    
    def download_unsw_nb15(self) -> Optional[Path]:
        """Download UNSW-NB15 dataset."""
        dataset_dir = self.base_path / "unsw_nb15"
        dataset_dir.mkdir(exist_ok=True)
        
        train_path = dataset_dir / "UNSW_NB15_training-set.csv"
        test_path = dataset_dir / "UNSW_NB15_testing-set.csv"
        
        if not train_path.exists():
            self.download_file(
                self.datasets['unsw_nb15']['urls']['train'],
                train_path,
                "UNSW-NB15 Train"
            )
        
        if not test_path.exists():
            self.download_file(
                self.datasets['unsw_nb15']['urls']['test'],
                test_path,
                "UNSW-NB15 Test"
            )
        
        if train_path.exists():
            df_train = pd.read_csv(train_path)
            df_test = pd.read_csv(test_path)
            logger.info(f"✓ UNSW-NB15: {len(df_train)} train, {len(df_test)} test records")
        
        return dataset_dir
    
    def convert_to_mitre_format(self, dataset_name: str) -> pd.DataFrame:
        """Convert downloaded dataset to MITRE-CORE format."""
        
        if dataset_name == 'nsl_kdd':
            return self._convert_nsl_kdd()
        elif dataset_name == 'unsw_nb15':
            return self._convert_unsw_nb15()
        else:
            raise ValueError(f"Unknown dataset: {dataset_name}")
    
    def _convert_nsl_kdd(self) -> pd.DataFrame:
        """Convert NSL-KDD to MITRE-CORE standard format."""
        dataset_dir = self.base_path / "nsl_kdd"
        
        # Load data
        df = pd.read_csv(dataset_dir / "train.csv")
        
        # Map to MITRE-CORE standard columns
        mitre_df = pd.DataFrame()
        
        # Generate synthetic timestamps
        base_time = pd.Timestamp('2024-01-01')
        mitre_df['timestamp'] = [base_time + pd.Timedelta(minutes=i*5) for i in range(len(df))]
        
        # IP addresses (synthetic, based on connection features)
        mitre_df['src_ip'] = df.apply(
            lambda row: f"10.{int(row['duration']) % 256}.{int(row['src_bytes']) % 256}.1",
            axis=1
        )
        mitre_df['dst_ip'] = df.apply(
            lambda row: f"192.168.{int(row['dst_bytes']) % 256}.1",
            axis=1
        )
        
        # Hostnames (synthetic)
        mitre_df['hostname'] = df['service'].apply(
            lambda x: f"host-{hash(str(x)) % 1000:03d}.local"
        )
        
        # Username (synthetic based on logged_in)
        mitre_df['username'] = df['logged_in'].apply(
            lambda x: f"user_{hash(str(x)) % 100:02d}@domain.com" if x else "unknown@domain.com"
        )
        
        # Alert type based on label
        mitre_df['alert_type'] = df['label'].apply(
            lambda x: 'attack' if x != 'normal' else 'normal'
        )
        
        # MITRE ATT&CK tactic mapping
        tactic_map = {
            'neptune': 'Impact',           # DoS
            'smurf': 'Impact',              # DoS
            'pod': 'Impact',                # DoS
            'back': 'Initial Access',       # Exploit
            'teardrop': 'Impact',           # DoS
            'ipsweep': 'Reconnaissance',    # Scanning
            'portsweep': 'Reconnaissance',  # Scanning
            'satan': 'Reconnaissance',      # Scanning
            'nmap': 'Reconnaissance',       # Scanning
            'guess_passwd': 'Credential Access',
            'ftp_write': 'Lateral Movement',
            'multihop': 'Lateral Movement',
            'phf': 'Initial Access',
            'spy': 'Collection',
            'buffer_overflow': 'Execution',
            'rootkit': 'Persistence',
            'loadmodule': 'Execution',
            'perl': 'Execution',
            'warezclient': 'Command and Control',
            'warezmaster': 'Command and Control',
            'imap': 'Initial Access',
            'land': 'Impact',
            'normal': 'None'
        }
        
        mitre_df['tactic'] = df['label'].map(tactic_map).fillna('Unknown')
        
        # Campaign ID (cluster same attack types together)
        mitre_df['campaign_id'] = df['label'].apply(lambda x: hash(x) % 50)
        
        # Additional features for HGNN
        mitre_df['protocol'] = df['protocol_type']
        mitre_df['service'] = df['service']
        mitre_df['flag'] = df['flag']
        mitre_df['src_bytes'] = df['src_bytes']
        mitre_df['dst_bytes'] = df['dst_bytes']
        
        # Attack stage (synthetic progression)
        mitre_df['stage'] = df.apply(
            lambda row: self._infer_stage(row['label'], row.name),
            axis=1
        )
        
        logger.info(f"Converted NSL-KDD: {len(mitre_df)} alerts")
        logger.info(f"Tactics: {mitre_df['tactic'].value_counts().to_dict()}")
        
        return mitre_df
    
    def _convert_unsw_nb15(self) -> pd.DataFrame:
        """Convert UNSW-NB15 to MITRE-CORE standard format."""
        dataset_dir = self.base_path / "unsw_nb15"
        
        df = pd.read_csv(dataset_dir / "UNSW_NB15_training-set.csv")
        
        mitre_df = pd.DataFrame()
        
        # Timestamps (UNSW has actual timestamps)
        if 'timestamp' in df.columns:
            mitre_df['timestamp'] = pd.to_datetime(df['timestamp'])
        else:
            base_time = pd.Timestamp('2024-01-01')
            mitre_df['timestamp'] = [base_time + pd.Timedelta(minutes=i) for i in range(len(df))]
        
        # IPs
        mitre_df['src_ip'] = df.get('srcip', df.get('src_ip', '0.0.0.0'))
        mitre_df['dst_ip'] = df.get('dstip', df.get('dst_ip', '0.0.0.0'))
        
        # If IPs not present, generate synthetic
        if mitre_df['src_ip'].isna().all() or (mitre_df['src_ip'] == '0.0.0.0').all():
            mitre_df['src_ip'] = [f"10.{i%256}.{(i//256)%256}.{i%254+1}" for i in range(len(df))]
            mitre_df['dst_ip'] = [f"192.168.{i%256}.{(i//256)%256+1}" for i in range(len(df))]
        
        # Hostnames from service/port
        mitre_df['hostname'] = df.get('service', df.get('proto', 'unknown')).apply(
            lambda x: f"host-{hash(str(x)) % 1000:03d}.local"
        )
        
        # Username
        mitre_df['username'] = df.get('username', df.get('srcip', 'unknown@domain.com'))
        
        # Alert type
        mitre_df['alert_type'] = df['label'].apply(
            lambda x: 'attack' if str(x).lower() in ['1', 'attack', 'true'] else 'normal'
        )
        
        # MITRE tactic mapping for UNSW attack categories
        tactic_map = {
            'Fuzzers': 'Execution',
            'Analysis': 'Collection',
            'Backdoor': 'Persistence',
            'DoS': 'Impact',
            'Exploits': 'Initial Access',
            'Generic': 'Initial Access',
            'Reconnaissance': 'Reconnaissance',
            'Shellcode': 'Execution',
            'Worms': 'Lateral Movement',
            'Normal': 'None'
        }
        
        attack_cat = df.get('attack_cat', df.get('category', 'Normal'))
        mitre_df['tactic'] = attack_cat.map(tactic_map).fillna('Unknown')
        
        # Campaign ID based on attack category
        mitre_df['campaign_id'] = attack_cat.apply(lambda x: hash(str(x)) % 50)
        
        # Features
        mitre_df['protocol'] = df.get('proto', 'tcp')
        mitre_df['service'] = df.get('service', 'unknown')
        mitre_df['src_bytes'] = df.get('sbytes', df.get('sbytes', 0))
        mitre_df['dst_bytes'] = df.get('dbytes', df.get('dbytes', 0))
        
        # Stage
        mitre_df['stage'] = df.apply(
            lambda row: self._infer_stage(row.get('attack_cat', 'Normal'), row.name),
            axis=1
        )
        
        logger.info(f"Converted UNSW-NB15: {len(mitre_df)} alerts")
        logger.info(f"Tactics: {mitre_df['tactic'].value_counts().to_dict()}")
        
        return mitre_df
    
    def _infer_stage(self, label: str, idx: int) -> str:
        """Infer attack stage from label."""
        stage_map = {
            'Reconnaissance': 'Initial Discovery',
            'Initial Access': 'Initial Compromise',
            'Credential Access': 'Credential Dumping',
            'Lateral Movement': 'Lateral Movement',
            'Impact': 'Impact',
            'normal': 'Normal',
            'Normal': 'Normal'
        }
        return stage_map.get(str(label), f'Stage_{idx % 5}')
    
    def download_all(self) -> Dict[str, Path]:
        """Download all available datasets."""
        results = {}
        
        logger.info("=" * 60)
        logger.info("Downloading Public Cybersecurity Datasets")
        logger.info("=" * 60)
        
        # Download NSL-KDD
        nsl_kdd_path = self.download_nsl_kdd()
        if nsl_kdd_path:
            results['nsl_kdd'] = nsl_kdd_path
        
        # Download UNSW-NB15
        unsw_path = self.download_unsw_nb15()
        if unsw_path:
            results['unsw_nb15'] = unsw_path
        
        # Note: CICIDS2017 and CSE-CIC-IDS2018 require manual download
        logger.info("\n" + "=" * 60)
        logger.info("NOTE: Large datasets require manual download:")
        logger.info("  - CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html")
        logger.info("  - CSE-CIC-IDS2018: https://www.unb.ca/cic/datasets/ids-2018.html")
        logger.info("  Place in ./datasets/cicids2017/ and ./datasets/cicids2018/")
        logger.info("=" * 60)
        
        return results


def main():
    """Download and prepare all datasets."""
    downloader = DatasetDownloader()
    
    # Download datasets
    downloaded = downloader.download_all()
    
    # Convert to MITRE format
    for dataset_name in downloaded.keys():
        logger.info(f"\nConverting {dataset_name} to MITRE-CORE format...")
        try:
            mitre_df = downloader.convert_to_mitre_format(dataset_name)
            
            # Save converted data
            output_path = downloader.base_path / dataset_name / "mitre_format.csv"
            mitre_df.to_csv(output_path, index=False)
            logger.info(f"✓ Saved to {output_path}")
        except FileNotFoundError as e:
            logger.error(f"✗ Cannot convert {dataset_name}: {e}")
            continue
    
    logger.info("\n" + "=" * 60)
    logger.info("Dataset preparation complete!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
