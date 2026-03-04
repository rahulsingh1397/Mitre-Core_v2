"""
MITRE-CORE HGNN Package
=======================

Heterogeneous Graph Neural Network modules for advanced alert correlation.

Modules:
- model: HGNN architecture (MITREHeteroGNN)
- training: Training loops and optimization
- evaluation: Evaluation metrics and testing
- integration: Pipeline integration helpers
- converters: Graph construction utilities
"""

try:
    from .model import MITREHeteroGNN, AlertToGraphConverter, HGNNCorrelationEngine
    from .training import HGNNTrainer, AlertGraphDataset
    from .evaluation import HGNNEvaluator
    from .integration import HybridCorrelationEngine, enhanced_correlation_hgnn
    from .converters import GraphAugmenter
    
    __all__ = [
        'MITREHeteroGNN',
        'AlertToGraphConverter',
        'HGNNCorrelationEngine',
        'HGNNTrainer',
        'AlertGraphDataset',
        'HGNNEvaluator',
        'HybridCorrelationEngine',
        'enhanced_correlation_hgnn',
        'GraphAugmenter'
    ]
    
except ImportError:
    # PyTorch Geometric not installed
    pass
