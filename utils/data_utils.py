"""
Shared data loading utilities for MITRE-CORE.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, List


def safe_read_csv(filepath: Union[str, Path], 
                 required_cols: Optional[List[str]] = None) -> Optional[pd.DataFrame]:
    """
    Safely read CSV with validation.
    
    Args:
        filepath: Path to CSV file
        required_cols: List of required columns
        
    Returns:
        DataFrame or None if error
    """
    try:
        filepath = Path(filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return None
        
        df = pd.read_csv(filepath)
        
        if required_cols:
            missing = set(required_cols) - set(df.columns)
            if missing:
                logger.warning(f"Missing columns: {missing}")
        
        return df
    
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return None


def validate_dataframe(df: pd.DataFrame, 
                      required_cols: List[str]) -> bool:
    """Validate DataFrame has required columns."""
    if df is None or df.empty:
        return False
    
    missing = set(required_cols) - set(df.columns)
    if missing:
        logger.error(f"Missing required columns: {missing}")
        return False
    
    return True
