"""Transformer package initialization."""

from transformer.config.gpu_config_8gb import GPUConfig5060Ti, DEFAULT_CONFIG_8GB
from transformer.schema.alert_schema import AlertToken, AlertBatch, EntityVocab, BatchMetadata
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.preprocessing.sliding_window_batcher import SlidingWindowBatcher
from transformer.models.candidate_generator import TransformerCandidateGenerator

__version__ = "3.0.0"

__all__ = [
    "GPUConfig5060Ti",
    "DEFAULT_CONFIG_8GB",
    "AlertToken",
    "AlertBatch",
    "EntityVocab",
    "BatchMetadata",
    "AlertPreprocessor",
    "SlidingWindowBatcher",
    "TransformerCandidateGenerator",
]
