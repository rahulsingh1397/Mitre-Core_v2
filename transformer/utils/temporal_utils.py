import torch
import numpy as np
import pandas as pd
from typing import Optional, Union

def calculate_time_deltas(timestamps: pd.Series) -> torch.Tensor:
    """
    Calculate time deltas between consecutive events.
    """
    if len(timestamps) <= 1:
        return torch.zeros((len(timestamps), 1))
        
    # Convert to numeric if needed
    if pd.api.types.is_datetime64_any_dtype(timestamps):
        times = timestamps.astype(np.int64) / 10**9  # seconds
    else:
        times = timestamps.values
        
    # Calculate deltas
    deltas = np.zeros(len(times))
    deltas[1:] = np.diff(times)
    
    # Handle negative deltas (out of order events)
    deltas = np.maximum(deltas, 0)
    
    return torch.tensor(deltas, dtype=torch.float32).unsqueeze(-1)

def create_temporal_mask(
    timestamps: pd.Series,
    window_size: float
) -> torch.Tensor:
    """
    Create a temporal attention mask where events outside the window are masked.
    """
    if len(timestamps) <= 1:
        return torch.ones((len(timestamps), len(timestamps)), dtype=torch.bool)
        
    # Convert to numeric
    if pd.api.types.is_datetime64_any_dtype(timestamps):
        times = timestamps.astype(np.int64) / 10**9  # seconds
    else:
        times = timestamps.values
        
    # Calculate pairwise differences
    n = len(times)
    mask = np.zeros((n, n), dtype=bool)
    
    # Vectorized computation of time differences
    times_matrix = np.tile(times, (n, 1))
    diff_matrix = np.abs(times_matrix - times_matrix.T)
    
    mask = diff_matrix <= window_size
    
    return torch.tensor(mask, dtype=torch.bool)

def normalize_timestamps(
    timestamps: pd.Series,
    min_time: Optional[float] = None,
    max_time: Optional[float] = None
) -> torch.Tensor:
    """
    Normalize timestamps to [0, 1] range.
    """
    if pd.api.types.is_datetime64_any_dtype(timestamps):
        times = timestamps.astype(np.int64) / 10**9  # seconds
    else:
        times = timestamps.values
        
    if len(times) == 0:
        return torch.tensor([])
        
    if len(times) == 1:
        return torch.tensor([0.0])
        
    t_min = min_time if min_time is not None else np.min(times)
    t_max = max_time if max_time is not None else np.max(times)
    
    if t_max == t_min:
        return torch.zeros(len(times))
        
    normalized = (times - t_min) / (t_max - t_min)
    return torch.tensor(normalized, dtype=torch.float32)
