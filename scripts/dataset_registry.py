"""
Dataset Metadata for MITRE-CORE Transformer Training
======================================================

This module defines metadata for all available datasets, enabling automatic
discovery, loading, and preprocessing for transformer training.

Usage:
    from scripts.dataset_registry import get_all_datasets, load_dataset
    datasets = get_all_datasets()
    df = load_dataset("CICIoV2024")
"""

from pathlib import Path
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
import pandas as pd
import logging

logger = logging.getLogger(__name__)


@dataclass
class DatasetMetadata:
    """Metadata for a security dataset."""
    name: str
    path: str
    format: str  # 'csv', 'parquet', 'json'
    attack_label_col: str
    timestamp_col: str
    source_ip_col: Optional[str] = None
    dest_ip_col: Optional[str] = None
    source_host_col: Optional[str] = None
    dest_host_col: Optional[str] = None
    severity_col: Optional[str] = None
    vendor_col: Optional[str] = None
    has_mitre_labels: bool = False
    size_estimate: str = "unknown"  # e.g., "10K", "1M", "100M"
    attack_types: List[str] = field(default_factory=list)
    year: int = 2024
    description: str = ""
    
    # Custom preprocessing function (optional)
    preprocessor: Optional[Callable] = None


# Dataset Registry - All available datasets for transformer training
DATASET_REGISTRY: Dict[str, DatasetMetadata] = {
    # ============ NEWLY ADDED DATASETS (2024-2026) ============
    
    "CICIoV2024": DatasetMetadata(
        name="CIC IoT-2024",
        path="datasets/CICIoV2024/decimal",
        format="csv",
        attack_label_col="attack_type",  # Inferred from filename
        timestamp_col="timestamp",
        source_ip_col="src_ip",
        dest_ip_col="dst_ip",
        has_mitre_labels=False,
        size_estimate="60M+",
        attack_types=["benign", "DoS", "spoofing-GAS", "spoofing-RPM", "spoofing-SPEED", "spoofing-STEERING_WHEEL"],
        year=2024,
        description="Canadian Institute for Cybersecurity IoT Dataset 2024"
    ),
    
    "YNU_IoTMal_2026": DatasetMetadata(
        name="YNU-IoTMal 2026",
        path="datasets/YNU-IoTMal 2026/CSVs",
        format="csv",
        attack_label_col="label",
        timestamp_col="timestamp",
        source_ip_col="src_ip",
        dest_ip_col="dst_ip",
        has_mitre_labels=True,
        size_estimate="unknown",
        year=2026,
        description="YNU IoT Malware Dataset 2026"
    ),
    
    "Datasense_IIoT_2025": DatasetMetadata(
        name="Datasense IIoT 2025",
        path="datasets/Datasense_IIoT_2025/attack_data",
        format="csv",
        attack_label_col="MalwareIntelAttackType",
        timestamp_col="EndDate",
        source_ip_col="SourceAddress",
        dest_ip_col="DestinationAddress",
        source_host_col="SourceHostName",
        dest_host_col="DestinationHostName",
        severity_col="DeviceSeverity",
        vendor_col="DeviceVendor",
        has_mitre_labels=True,
        size_estimate="100K+",
        year=2025,
        description="Datasense IIoT Dataset with MITRE labels"
    ),
    
    "LANL": DatasetMetadata(
        name="LANL Unified 2021-2024",
        path="datasets/LANL 2021–2024",
        format="lanl_raw",
        attack_label_col="red_team_tag",
        timestamp_col="time",
        source_ip_col="src_computer",
        dest_ip_col="dst_computer",
        has_mitre_labels=False,
        size_estimate="1B+",
        year=2024,
        description="Los Alamos unified host-network dataset (uses computer names, not IPs)"
    ),
    
    # ============ EXISTING DATASETS ============
    
    "UNSW_NB15": DatasetMetadata(
        name="UNSW-NB15",
        path="datasets/unsw_nb15",
        format="csv",
        attack_label_col="label",
        timestamp_col=None,
        source_ip_col="srcip",
        dest_ip_col="dstip",
        has_mitre_labels=False,
        size_estimate="250K",
        year=2015,
        description="UNSW-NB15 network intrusion detection dataset"
    ),
    
    "CICAPT_IIoT": DatasetMetadata(
        name="CICAPT-IIoT",
        path="datasets/CICAPT-IIoT-Dataset",
        format="csv",
        attack_label_col="Label",
        timestamp_col=None,
        source_ip_col="Src_IP",
        dest_ip_col="Dst_IP",
        has_mitre_labels=False,
        size_estimate="500K",
        year=2022,
        description="CICAPT-IIoT APT attack dataset for industrial IoT"
    ),
    
    "Real_Data": DatasetMetadata(
        name="Real Production Data",
        path="datasets/real_data",
        format="csv",
        attack_label_col="MalwareIntelAttackType",
        timestamp_col="EndDate",
        source_ip_col="SourceAddress",
        dest_ip_col="DestinationAddress",
        source_host_col="SourceHostName",
        dest_host_col="DestinationHostName",
        severity_col="DeviceSeverity",
        vendor_col="DeviceVendor",
        has_mitre_labels=True,
        size_estimate="65",
        year=2023,
        description="Curated real-world alerts with MITRE tagging"
    ),
}


def get_all_datasets() -> Dict[str, DatasetMetadata]:
    return DATASET_REGISTRY


def get_mitre_labeled_datasets() -> List[str]:
    """Get list of datasets with MITRE labels."""
    return [
        name for name, meta in DATASET_REGISTRY.items()
        if meta.has_mitre_labels
    ]


def validate_dataset_tactics(name: str) -> Optional[Dict]:
    """
    Validate MITRE tactic coverage for a dataset.
    
    Args:
        name: Dataset name from registry
        
    Returns:
        Coverage statistics dict or None if validation fails
    """
    from utils.mitre_tactic_mapper import MITRETacticMapper
    
    metadata = DATASET_REGISTRY.get(name)
    if not metadata:
        return None
    
    df = load_dataset(name, sample_size=1000)
    if df is None:
        return None
    
    mapper = MITRETacticMapper()
    label_col = metadata.attack_label_col
    
    if label_col not in df.columns:
        logger.warning(f"Label column '{label_col}' not found in {name}")
        return None
    
    coverage = mapper.validate_tactic_coverage(df, label_col)
    coverage['dataset_name'] = name
    coverage['has_mitre_labels'] = metadata.has_mitre_labels
    
    return coverage


def print_dataset_summary():
    """Print summary of all registered datasets."""
    print("\n" + "="*60)
    print("MITRE-CORE Dataset Registry Summary")
    print("="*60)
    
    for name, meta in DATASET_REGISTRY.items():
        mitre_status = "✅ MITRE" if meta.has_mitre_labels else "⚠️  Needs Mapping"
        print(f"\n{name}")
        print(f"  Year: {meta.year} | {meta.size_estimate} records")
        print(f"  {mitre_status}")
        print(f"  {meta.description[:50]}...")
    
    print("\n" + "="*60)
    print(f"Total: {len(DATASET_REGISTRY)} datasets registered")
    print("="*60 + "\n")


def load_dataset(name: str, sample_size: Optional[int] = None) -> Optional[pd.DataFrame]:
    """Load a dataset by name."""
    metadata = DATASET_REGISTRY.get(name)
    if not metadata:
        return None
    
    path = Path(metadata.path)
    if not path.exists():
        logger.warning(f"Dataset path not found: {path}")
        return None
    
    if metadata.format == "csv":
        # Check for parquet first (faster loading)
        parquet_files = list(path.glob("*.parquet"))
        if parquet_files:
            rows_per_file = (sample_size // len(parquet_files)) if sample_size else None
            dfs = [pd.read_parquet(f) for f in parquet_files[:5]]
            df = pd.concat(dfs, ignore_index=True) if dfs else None
            if df is not None and rows_per_file:
                df = df.head(rows_per_file)
            return df
        
        csv_files = list(path.glob("*.csv"))
        if not csv_files:
            return None
        # Apply sample_size per file
        rows_per_file = (sample_size // len(csv_files)) if sample_size else None
        dfs = [pd.read_csv(f, nrows=rows_per_file) for f in csv_files[:5]]
        return pd.concat(dfs, ignore_index=True) if dfs else None
    
    elif metadata.format == "lanl_raw":
        # Handle LANL format - raw files without extensions in subdirectories
        data_files = []
        for subdir in ["HostEvents", "Netflow"]:
            subdir_path = path / subdir
            if subdir_path.exists():
                # Get all files without extension (raw LANL format)
                for item in subdir_path.iterdir():
                    if item.is_dir():
                        # Check for files inside day subdirectories (wls_day-01, etc.)
                        for file in item.iterdir():
                            if file.is_file() and not file.suffix:
                                data_files.append(file)
                    elif item.is_file() and not item.suffix:
                        data_files.append(item)
        
        if not data_files:
            logger.warning(f"No LANL raw files found in {path}")
            return None
        
        # Load first file as sample (files are huge ~14GB each)
        dfs = []
        for data_file in data_files[:2]:  # Load max 2 files
            try:
                logger.info(f"Loading LANL file {data_file.name}...")
                # Read first N rows since files are huge
                # Handle malformed lines with on_bad_lines='skip'
                df = pd.read_csv(data_file, nrows=sample_size or 50000, header=None, 
                                 names=['time', 'src_computer', 'dst_computer', 'user', 
                                        'red_team_tag', 'logon_type', 'authentication_package'],
                                 on_bad_lines='skip', engine='python')
                df['_source_file'] = data_file.name
                dfs.append(df)
            except Exception as e:
                logger.warning(f"Failed to load {data_file}: {e}")
                continue
        
        return pd.concat(dfs, ignore_index=True) if dfs else None
    
    return None


if __name__ == "__main__":
    print("Available datasets:")
    for name, meta in get_all_datasets().items():
        print(f"  - {name}: {meta.description}")
