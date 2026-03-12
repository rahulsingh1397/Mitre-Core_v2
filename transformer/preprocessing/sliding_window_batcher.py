"""
Sliding Window Batcher
=====================

Creates overlapping windows for streaming alert processing.
Critical for maintaining continuity across batches.
"""

import logging
from typing import List, Optional
from datetime import datetime, timedelta

import pandas as pd
import numpy as np

from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.schema.alert_schema import AlertBatch


logger = logging.getLogger("mitre-core.transformer.windowing")


class SlidingWindowBatcher:
    """
    Creates overlapping windows for streaming alert processing.
    
    This batcher handles:
    1. Time gap detection (natural batch boundaries)
    2. Sliding windows with overlap (context preservation)
    3. Maximum window size enforcement (memory constraints)
    4. Minimum window size filtering (quality control)
    
    Example:
        batcher = SlidingWindowBatcher(
            window_size=256,  # 256 alerts max (8GB GPU constraint)
            overlap=32,         # 32-alert overlap
            max_time_gap=pd.Timedelta(minutes=5)
        )
        windows = batcher.create_windows(df)
    """
    
    def __init__(
        self,
        window_size: int = 256,  # Reduced from 512 for 8GB GPU
        overlap: int = 32,       # 32-alert overlap
        max_time_gap: pd.Timedelta = pd.Timedelta(minutes=5),
        min_window_size: int = 10,
        preprocessor: Optional[AlertPreprocessor] = None
    ):
        """
        Initialize window batcher.
        
        Args:
            window_size: Maximum alerts per window (sequence length)
            overlap: Number of alerts to carry over to next window
            max_time_gap: Time gap that triggers a hard break
            min_window_size: Minimum alerts for a valid window
            preprocessor: Optional preprocessor to use
        """
        self.window_size = window_size
        self.overlap = overlap
        self.max_time_gap = max_time_gap
        self.min_window_size = min_window_size
        self.preprocessor = preprocessor or AlertPreprocessor(
            max_seq_length=window_size
        )
        
        logger.info(
            f"SlidingWindowBatcher initialized: "
            f"window_size={window_size}, "
            f"overlap={overlap}, "
            f"max_time_gap={max_time_gap}"
        )
    
    def create_windows(
        self,
        df: pd.DataFrame,
        timestamp_col: Optional[str] = None
    ) -> List[pd.DataFrame]:
        """
        Split dataframe into overlapping windows.
        
        Strategy:
        1. Detect natural breaks on time gaps > max_time_gap
        2. Slide window with overlap within each segment
        3. Filter windows below minimum size
        
        Args:
            df: DataFrame with alert data
            timestamp_col: Column name for timestamp (auto-detected if None)
            
        Returns:
            List of DataFrames, each representing a window
        """
        if len(df) == 0:
            logger.warning("Empty DataFrame provided")
            return []
        
        # Auto-detect timestamp column
        if timestamp_col is None:
            timestamp_col = self._detect_timestamp_column(df)
        
        if timestamp_col not in df.columns:
            logger.warning(f"Timestamp column '{timestamp_col}' not found, using index")
            # Fallback: create artificial timestamps
            df = df.copy()
            df['_artificial_timestamp'] = pd.date_range(
                start=datetime.now(),
                periods=len(df),
                freq='1min'
            )
            timestamp_col = '_artificial_timestamp'
        
        # Convert to datetime
        df = df.copy()
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors='coerce')
        
        # Sort by time
        df = df.sort_values(timestamp_col).reset_index(drop=True)
        
        # Detect natural breaks (time gaps)
        time_diff = df[timestamp_col].diff()
        break_indices = [0] + list(np.where(time_diff > self.max_time_gap)[0])
        
        windows = []
        
        # Process each segment between breaks
        for i in range(len(break_indices)):
            start_idx = break_indices[i]
            end_idx = break_indices[i + 1] if i + 1 < len(break_indices) else len(df)
            
            segment = df.iloc[start_idx:end_idx].reset_index(drop=True)
            
            if len(segment) < self.min_window_size:
                logger.debug(f"Skipping small segment: {len(segment)} alerts")
                continue
            
            # Create sliding windows within segment
            segment_windows = self._slide_window(segment, timestamp_col)
            windows.extend(segment_windows)
        
        logger.info(f"Created {len(windows)} windows from {len(df)} alerts")
        return windows
    
    def _detect_timestamp_column(self, df: pd.DataFrame) -> str:
        """Auto-detect timestamp column from common names."""
        candidates = [
            'timestamp', 'EndDate', 'StartTime', 'EndTime',
            'event_time', 'alert_time', 'detection_time',
            'time', 'datetime', 'created_at'
        ]
        
        for col in candidates:
            if col in df.columns:
                return col
        
        # Fallback: try to find datetime column
        for col in df.columns:
            if 'time' in col.lower() or 'date' in col.lower():
                return col
        
        return 'timestamp'  # Default
    
    def _slide_window(
        self,
        segment: pd.DataFrame,
        timestamp_col: str
    ) -> List[pd.DataFrame]:
        """
        Create sliding windows within a segment.
        
        Args:
            segment: DataFrame segment (between time breaks)
            timestamp_col: Name of timestamp column
            
        Returns:
            List of window DataFrames
        """
        windows = []
        step = self.window_size - self.overlap
        
        for start in range(0, len(segment), step):
            end = start + self.window_size
            window = segment.iloc[start:end].copy()
            
            if len(window) >= self.min_window_size:
                # Add metadata
                window['_window_start'] = window[timestamp_col].min()
                window['_window_end'] = window[timestamp_col].max()
                window['_window_idx'] = len(windows)
                windows.append(window)
        
        return windows
    
    def process_to_batches(
        self,
        df: pd.DataFrame,
        device: str = 'cuda',
        timestamp_col: Optional[str] = None
    ) -> List[AlertBatch]:
        """
        Create windows and convert to AlertBatch objects.
        
        Args:
            df: DataFrame with alert data
            device: Target device ('cuda' or 'cpu')
            timestamp_col: Timestamp column name
            
        Returns:
            List of AlertBatch objects ready for transformer
        """
        import torch
        
        windows = self.create_windows(df, timestamp_col)
        batches = []
        
        device_obj = torch.device(device if torch.cuda.is_available() else 'cpu')
        
        for idx, window_df in enumerate(windows):
            try:
                result = self.preprocessor.process_batch(
                    window_df,
                    device=device_obj,
                    batch_id=f"window_{idx}"
                )
                batches.append(result['alert_batch'])
            except Exception as e:
                logger.error(f"Failed to process window {idx}: {e}")
                continue
        
        logger.info(f"Created {len(batches)} AlertBatch objects")
        return batches
    
    def get_window_statistics(self, windows: List[pd.DataFrame]) -> dict:
        """
        Get statistics about created windows.
        
        Args:
            windows: List of window DataFrames
            
        Returns:
            Dictionary with statistics
        """
        if not windows:
            return {
                'num_windows': 0,
                'avg_size': 0,
                'min_size': 0,
                'max_size': 0,
                'total_alerts': 0
            }
        
        sizes = [len(w) for w in windows]
        
        return {
            'num_windows': len(windows),
            'avg_size': np.mean(sizes),
            'min_size': min(sizes),
            'max_size': max(sizes),
            'total_alerts': sum(sizes),
            'window_sizes': sizes
        }
