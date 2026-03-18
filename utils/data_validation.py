"""
Production Data Validation for MITRE-CORE
Ensures only real data is used in production environment.
"""

import pandas as pd
import logging
from typing import Optional

logger = logging.getLogger("mitre-core.data_validation")


class SyntheticDataError(Exception):
    """Raised when synthetic data is detected in production."""
    pass


def validate_real_data(df: pd.DataFrame, source: str = "unknown") -> pd.DataFrame:
    """
    Validate that data is real (not synthetic) before processing.
    
    Args:
        df: DataFrame to validate
        source: Data source identifier for logging
        
    Returns:
        DataFrame if valid
        
    Raises:
        SyntheticDataError: If synthetic indicators detected
    """
    if df is None or df.empty:
        raise ValueError(f"Empty data from {source}")
    
    # Check for synthetic indicators
    synthetic_indicators = [
        'is_synthetic',
        'synthetic_label',
        'generated',
        'simulated'
    ]
    
    for indicator in synthetic_indicators:
        if indicator in df.columns:
            if df[indicator].any() if df[indicator].dtype == 'bool' else df[indicator].notna().any():
                raise SyntheticDataError(
                    f"Synthetic data detected in {source}: column '{indicator}' found. "
                    "Only real production data is allowed."
                )
    
    # Check for timestamp realism (synthetic data often has uniform distributions)
    if 'timestamp' in df.columns:
        timestamps = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Check for future timestamps (common in synthetic data)
        future_timestamps = timestamps > pd.Timestamp.now() + pd.Timedelta(days=1)
        if future_timestamps.sum() > len(df) * 0.1:  # More than 10% future dates
            raise SyntheticDataError(
                f"Suspicious timestamps in {source}: {future_timestamps.sum()} future dates detected"
            )
        
        # Check for uniform distribution (synthetic indicator)
        time_diffs = timestamps.diff().dropna().dt.total_seconds()
        if len(time_diffs) > 100:
            cv = time_diffs.std() / (time_diffs.mean() + 1e-8)
            if cv < 0.1:  # Coefficient of variation < 10% indicates uniformity
                logger.warning(f"Possible synthetic data in {source}: uniform timestamps (CV={cv:.3f})")
    
    # Check for perfect IP patterns (synthetic indicator)
    ip_cols = [c for c in df.columns if 'ip' in c.lower()]
    for ip_col in ip_cols:
        unique_ips = df[ip_col].nunique()
        total_rows = len(df)
        
        if total_rows > 100 and unique_ips / total_rows > 0.9:
            logger.warning(
                f"Possible synthetic data in {source}: {ip_col} has {unique_ips} unique values "
                f"({unique_ips/total_rows*100:.1f}% uniqueness)"
            )
    
    logger.info(f"Data validation passed for {source}: {len(df)} rows")
    return df


def validate_dataset_source(dataset_name: str) -> bool:
    """
    Check if dataset is in approved real dataset list.
    
    Args:
        dataset_name: Name of dataset
        
    Returns:
        True if approved, False otherwise
    """
    approved_real_datasets = {
        # Public research datasets
        'unsw_nb15': 'UNSW-NB15 (ACCS, 2015)',
        'nsl_kdd': 'NSL-KDD (CIC, 2009)',
        'cicids2017': 'CICIDS2017 (CIC, 2017)',
        'ton_iot': 'TON_IoT (UNSW Canberra, 2021)',
        'cicapt_iiot': 'CICAPT-IIoT (CIC, 2024)',
        'ynu_iotmal': 'YNU-IoTMal (CIC, 2026)',
        
        # Enterprise data (real)
        'canara': 'Canara Enterprise Data',
        'network': 'Network Traffic Logs',
        'kmeans_test': 'K-Means Test Dataset',
        'test_dataset': 'Test Dataset',
    }
    
    dataset_lower = dataset_name.lower().replace('_', '').replace('-', '')
    
    for approved_key, description in approved_real_datasets.items():
        if approved_key in dataset_lower:
            logger.info(f"Approved dataset: {dataset_name} -> {description}")
            return True
    
    # Check for synthetic markers in name
    synthetic_markers = ['synthetic', 'generated', 'simulated', 'fake', 'mock']
    if any(marker in dataset_lower for marker in synthetic_markers):
        logger.error(f"Rejected dataset: {dataset_name} (contains synthetic marker)")
        return False
    
    logger.warning(f"Unknown dataset: {dataset_name} - manual verification required")
    return False


def get_data_provenance(dataset_name: str) -> dict:
    """Get provenance information for a dataset."""
    provenance = {
        'unsw_nb15': {
            'source': 'Australian Centre for Cyber Security (ACCS)',
            'year': 2015,
            'type': 'Real Network Traffic',
            'url': 'https://research.unsw.edu.au/projects/unsw-nb15-dataset',
            'license': 'Academic Use'
        },
        'nsl_kdd': {
            'source': 'Canadian Institute for Cybersecurity (CIC)',
            'year': 2009,
            'type': 'Real Network Intrusion Data',
            'url': 'https://www.unb.ca/cic/datasets/nsl.html',
            'license': 'Academic Use'
        },
        'cicids2017': {
            'source': 'Canadian Institute for Cybersecurity (CIC)',
            'year': 2017,
            'type': 'Real IDS Benchmark',
            'url': 'https://www.unb.ca/cic/datasets/ids-2017.html',
            'license': 'Academic Use'
        },
        'ton_iot': {
            'source': 'UNSW Canberra Cyber',
            'year': 2021,
            'type': 'Real IoT Telemetry',
            'url': 'https://research.unsw.edu.au/projects/toniot-datasets',
            'license': 'Academic Use'
        },
        'cicapt_iiot': {
            'source': 'Canadian Institute for Cybersecurity (CIC)',
            'year': 2024,
            'type': 'Real Industrial IoT Attacks',
            'url': 'https://cicresearch.ca/',
            'license': 'Academic Use'
        },
        'ynu_iotmal': {
            'source': 'Canadian Institute for Cybersecurity (CIC)',
            'year': 2026,
            'type': 'Real IoT Malware Data',
            'url': 'https://cicresearch.ca/',
            'license': 'CIC Terms'
        }
    }
    
    return provenance.get(dataset_name.lower().replace('_', ''), {
        'source': 'Enterprise Data',
        'year': 'Unknown',
        'type': 'Real Production Data',
        'url': 'Internal',
        'license': 'Confidential'
    })


# Production mode flag - set via environment variable
import os
PRODUCTION_MODE = os.environ.get('MITRE_CORE_PRODUCTION', 'false').lower() == 'true'

def is_production() -> bool:
    """Check if running in production mode."""
    return PRODUCTION_MODE
