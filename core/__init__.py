"""
MITRE-CORE Core Package
=======================

Core pipeline modules for alert correlation.

Modules:
- correlation_pipeline: Unified correlation interface
- correlation_indexer: Union-Find baseline implementation
- preprocessing: Data preprocessing and feature engineering
- postprocessing: Post-correlation processing
- output: Output generation and formatting
"""

from .correlation_pipeline import (
    CorrelationPipeline,
    CorrelationMethod,
    CorrelationResult,
    enhanced_correlation
)

__all__ = [
    'CorrelationPipeline',
    'CorrelationMethod',
    'CorrelationResult',
    'enhanced_correlation'
]
