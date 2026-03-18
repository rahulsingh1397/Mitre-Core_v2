"""
Shared timestamp utilities for MITRE-CORE.
"""

import pandas as pd
from datetime import datetime
from typing import Union


def parse_timestamp(ts: Union[str, datetime, pd.Timestamp], 
                   format_str: Optional[str] = None) -> Optional[pd.Timestamp]:
    """
    Parse timestamp from various formats.
    
    Args:
        ts: Timestamp string or object
        format_str: Optional format string
        
    Returns:
        Parsed timestamp or None if error
    """
    try:
        if isinstance(ts, pd.Timestamp):
            return ts
        
        if isinstance(ts, datetime):
            return pd.Timestamp(ts)
        
        if format_str:
            return pd.to_datetime(ts, format=format_str)
        else:
            return pd.to_datetime(ts, errors='coerce')
    
    except Exception as e:
        logger.warning(f"Failed to parse timestamp {ts}: {e}")
        return None


def normalize_timestamps(series: pd.Series) -> pd.Series:
    """Normalize timestamp series to standard format."""
    return pd.to_datetime(series, errors='coerce')


def get_time_bucket(ts: pd.Timestamp, bucket_minutes: int = 5) -> pd.Timestamp:
    """Get time bucket for timestamp."""
    return ts.floor(f'{bucket_minutes}min')
