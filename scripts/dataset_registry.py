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
    streaming: bool = False  # Whether to use streaming loader for this dataset
    file_pattern: Optional[str] = None  # Glob pattern for file selection; None = all files of format type
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
        streaming=True,  # 60M+ rows must be capped at 100K/epoch
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
        streaming=True,  # Unknown size, cap as precaution
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
        streaming=True,  # 64GB, absolutely must be capped
        year=2024,
        description="Los Alamos unified host-network dataset (uses computer names, not IPs)"
    ),
    
    # ============ EXISTING DATASETS ============
    
    "unsw_nb15": DatasetMetadata(
        name="UNSW-NB15",
        path="datasets/unsw_nb15",
        format="parquet",          # mitre_format.parquet only — avoids raw CSVs with wrong schema
        file_pattern="mitre_format.parquet",  # Explicit pattern to avoid raw CSVs
        attack_label_col="tactic",
        timestamp_col="timestamp",
        source_ip_col="src_ip",
        dest_ip_col="dst_ip",
        has_mitre_labels=True,
        size_estimate="175K",
        year=2015,
        description="UNSW-NB15 network intrusion detection dataset"
    ),
    
    "nsl_kdd": DatasetMetadata(
        name="NSL-KDD",
        path="datasets/nsl_kdd",
        format="csv",
        file_pattern="mitre_format.csv",  # raw train.csv/test.csv have no IP columns
        attack_label_col="tactic",
        timestamp_col="timestamp",
        source_ip_col="src_ip",
        dest_ip_col="dst_ip",
        has_mitre_labels=True,
        size_estimate="125K",
        year=2009,
        description="NSL-KDD network intrusion detection dataset (mitre_format only)"
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
        streaming=True,  # 9.2GB, must be capped at 100K rows/epoch
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


def _infer_schema_columns(file_path: Path, fmt: str) -> tuple:
    """
    Infer label and timestamp columns from file header.
    
    Returns:
        (label_col, timestamp_col) tuple
    """
    try:
        if fmt == "parquet":
            df = pd.read_parquet(file_path, nrows=5)
        elif fmt == "csv":
            df = pd.read_csv(file_path, nrows=5)
        else:
            return ("label", None)  # Default fallback
        
        cols = [c.lower() for c in df.columns]
        cols_orig = list(df.columns)
        
        # Label column priority
        label_candidates = ['campaign_id', 'tactic', 'label', 'red_team_tag', 
                          'attack_cat', 'attack_type', 'malwareintelattacktype', 
                          'malicious', 'threat']
        label_col = None
        for cand in label_candidates:
            if cand in cols:
                idx = cols.index(cand)
                label_col = cols_orig[idx]
                break
        
        # Timestamp column priority
        ts_candidates = ['timestamp', 'time', 'datetime', 'date', 'ts', 'enddate', 'startdate']
        ts_col = None
        for cand in ts_candidates:
            if cand in cols:
                idx = cols.index(cand)
                ts_col = cols_orig[idx]
                break
        
        return (label_col, ts_col)
    except Exception as e:
        logger.debug(f"Could not infer schema from {file_path}: {e}")
        return ("label", None)


def scan_datasets_dir(base_path: str = "datasets") -> Dict[str, DatasetMetadata]:
    """
    Scan datasets/ directory and auto-register new folders not in the static registry.
    Called at training startup — supplements, never replaces, existing entries.
    
    Args:
        base_path: Path to datasets directory
        
    Returns:
        Merged dictionary of static + discovered datasets
    """
    discovered = {}
    base = Path(base_path)
    
    if not base.exists():
        logger.warning(f"Datasets directory not found: {base}")
        return DATASET_REGISTRY
    
    # Directories to skip
    skip_dirs = {'processed', 'loaders', 'real_data', '__pycache__', '.git'}
    
    # Build set of top-level dataset folders already claimed by the static registry.
    # Handles mismatches between static key and normalized folder name, e.g.:
    #   "LANL" → path "datasets/LANL 2021–2024/HostEvents" → top-level: datasets/LANL 2021–2024
    #   "CICAPT_IIoT" → path "datasets/CICAPT-IIoT-Dataset" → top-level: datasets/CICAPT-IIoT-Dataset
    static_covered = set()
    for ds_meta in DATASET_REGISTRY.values():
        ds_path = Path(ds_meta.path)
        parts = ds_path.parts
        try:
            base_idx = list(parts).index(base.name)  # find 'datasets' component
            if base_idx + 1 < len(parts):
                static_covered.add(base / parts[base_idx + 1])
        except (ValueError, IndexError):
            pass
    
    for subdir in base.iterdir():
        if not subdir.is_dir() or subdir.name in skip_dirs:
            continue
        
        # Normalize name for registry key
        name = subdir.name.replace(' ', '_').replace('-', '_').replace('.', '_')
        
        # Skip if already covered by static registry (by name OR by folder path)
        if name in DATASET_REGISTRY or subdir in static_covered:
            continue  # Already hand-registered, skip
        
        # Auto-detect format — prefer mitre_format.* files when they exist
        mitre_parquet = list(subdir.glob("mitre_format.parquet"))
        mitre_csv = list(subdir.glob("mitre_format.csv"))
        parquet_files = list(subdir.rglob("*.parquet"))
        csv_files = list(subdir.rglob("*.csv"))
        jsonl_files = list(subdir.rglob("wls_*"))  # LANL pattern
        jsonl_files += list(subdir.rglob("*.jsonl"))

        # Determine format and files — mitre_format takes priority
        if mitre_parquet:
            fmt = "parquet"
            files = mitre_parquet
        elif mitre_csv:
            fmt = "csv"
            files = mitre_csv
        elif parquet_files:
            fmt = "parquet"
            files = parquet_files
        elif csv_files:
            fmt = "csv"
            files = csv_files
        elif jsonl_files:
            fmt = "jsonl"
            files = jsonl_files
        else:
            logger.debug(f"No data files found in {subdir}")
            continue  # No recognized data files
        
        # Infer schema from first file
        label_col, ts_col = _infer_schema_columns(files[0], fmt)
        
        # Auto-enable streaming for large datasets (> 500MB total)
        total_size_mb = sum(f.stat().st_size for f in files if f.exists()) / (1024 * 1024)
        use_streaming = (fmt == "jsonl") or (total_size_mb > 500)
        
        # Create metadata
        discovered[name] = DatasetMetadata(
            name=name,
            path=str(subdir),
            format=fmt,
            attack_label_col=label_col or "label",
            timestamp_col=ts_col,
            has_mitre_labels=(label_col is not None and label_col.lower() not in ['label', 'malicious']),
            streaming=use_streaming,  # JSONL or large datasets use streaming
            size_estimate=f"{total_size_mb:.0f}MB" if total_size_mb > 0 else "unknown",
            year=2024,
            description=f"Auto-discovered: {subdir.name}"
        )
        logger.info(f"Auto-discovered dataset: {name} ({fmt}, {len(files)} files, {total_size_mb:.0f}MB, streaming={use_streaming})")
    
    # Return merged: static entries win on conflict
    return {**discovered, **DATASET_REGISTRY}


def get_all_datasets(auto_scan: bool = True) -> Dict[str, DatasetMetadata]:
    """
    Get all datasets, including auto-discovered ones.
    
    Args:
        auto_scan: If True, scan datasets/ directory for new folders
        
    Returns:
        Dictionary of all available datasets
    """
    if auto_scan:
        return scan_datasets_dir()
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
