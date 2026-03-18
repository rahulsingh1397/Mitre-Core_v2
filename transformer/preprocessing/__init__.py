"""Transformer preprocessing package.

This package contains preprocessing utilities for Tier 1: Candidate Generation.

Available modules:
    - AlertPreprocessor: Preprocesses raw alerts for transformer input
    - SlidingWindowBatcher: Creates sliding windows for temporal attention
"""

from .alert_preprocessor import AlertPreprocessor
from .sliding_window_batcher import SlidingWindowBatcher

__all__ = ['AlertPreprocessor', 'SlidingWindowBatcher']
