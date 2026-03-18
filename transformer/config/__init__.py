"""Transformer configuration package.

This package contains configuration utilities for Tier 1: Candidate Generation.

Available modules:
    - gpu_config_8gb: GPU configuration optimized for RTX 5060 Ti 8GB
"""

from .gpu_config_8gb import (
    GPUConfig5060Ti,
    DEFAULT_CONFIG_8GB
)
__all__ = ['GPUConfig5060Ti', 'DEFAULT_CONFIG_8GB']
