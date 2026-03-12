"""
MITRE-CORE Unified Correlation Pipeline
========================================

Integrates Union-Find (baseline) and HGNN (deep learning) correlation methods
into a single, clean pipeline with automatic method selection.

This module replaces the scattered correlation implementations with a unified interface.

Usage:
    from correlation_pipeline import CorrelationPipeline
    
    # Initialize pipeline with auto method selection
    pipeline = CorrelationPipeline(method='auto')
    
    # Or explicitly choose method
    pipeline = CorrelationPipeline(method='hgnn', model_path='path/to/model.pt')
    
    # Run correlation
    result_df = pipeline.correlate(data, usernames, addresses)
"""

import os
import sys
import logging
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Literal
from dataclasses import dataclass
from enum import Enum

import pandas as pd
import numpy as np
import torch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.pipeline")


class CorrelationMethod(Enum):
    """Available correlation methods."""
    UNION_FIND = "union_find"
    HGNN = "hgnn"
    HYBRID = "hybrid"
    AUTO = "auto"


@dataclass
class CorrelationResult:
    """Result container for correlation operations."""
    data: pd.DataFrame
    method_used: str
    num_clusters: int
    runtime_seconds: float
    confidence_score: Optional[float] = None
    fallback_used: bool = False


class CorrelationPipeline:
    """
    Unified correlation pipeline supporting multiple methods.
    
    Features:
    - Automatic method selection based on data size and availability
    - Seamless fallback between methods
    - Consistent interface regardless of backend
    - Performance metrics and logging
    """
    
    def __init__(
        self,
        method: Literal["auto", "union_find", "hgnn", "hybrid"] = "auto",
        model_path: Optional[str] = None,
        device: Optional[str] = None,
        confidence_threshold: float = 0.5,
        hgnn_weight: float = 0.7,
        union_find_weight: float = 0.3
    ):
        """
        Initialize correlation pipeline.
        
        Args:
            method: Correlation method to use
                - 'auto': Choose based on data size and model availability
                - 'union_find': Always use Union-Find (fast, no training)
                - 'hgnn': Always use HGNN (higher accuracy, requires model)
                - 'hybrid': Combine both methods
            model_path: Path to trained HGNN model (required for 'hgnn' or 'hybrid')
            device: 'cuda' or 'cpu' (auto-detected if None)
            confidence_threshold: Minimum confidence for HGNN predictions
            hgnn_weight: Weight for HGNN in hybrid mode (0-1)
            union_find_weight: Weight for Union-Find in hybrid mode (0-1)
        """
        self.method = CorrelationMethod(method)
        self.model_path = model_path
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.confidence_threshold = confidence_threshold
        self.hgnn_weight = hgnn_weight
        self.uf_weight = union_find_weight
        
        # Initialize engines lazily
        self._union_find_engine = None
        self._hgnn_engine = None
        self._hybrid_engine = None
        
        logger.info(f"Pipeline initialized: method={method}, device={self.device}")
    
    def _get_union_find_engine(self):
        """Lazy initialization of Union-Find engine."""
        if self._union_find_engine is None:
            from core.correlation_indexer import enhanced_correlation  # fixed: was bare 'correlation_indexer'
            self._union_find_engine = enhanced_correlation
        return self._union_find_engine
    
    def _get_hgnn_engine(self):
        """Lazy initialization of HGNN engine."""
        if self._hgnn_engine is None:
            try:
                from hgnn.hgnn_correlation import HGNNCorrelationEngine  # fixed: was bare 'hgnn_correlation'
                self._hgnn_engine = HGNNCorrelationEngine(
                    model_path=self.model_path,
                    device=self.device
                )
            except Exception as e:
                logger.error(f"Failed to initialize HGNN engine: {e}")
                raise
        return self._hgnn_engine
    
    def _get_hybrid_engine(self):
        """Lazy initialization of Hybrid engine."""
        if self._hybrid_engine is None:
            from hgnn.hgnn_integration import HybridCorrelationEngine  # fixed: was bare 'hgnn_integration'
            self._hybrid_engine = HybridCorrelationEngine(
                hgnn_weight=self.hgnn_weight,
                union_find_weight=self.uf_weight,
                model_path=self.model_path,
                device=self.device
            )
        return self._hybrid_engine
    
    def _select_method(self, data: pd.DataFrame) -> CorrelationMethod:
        """
        Automatically select best correlation method.

        Policy (updated 2026-03-07, based on v2.6–v2.9 sweep results):
          - HGNN-only is the default for all dataset sizes when a model is available.
            UF refinement is confirmed net-harmful for the UNSW-NB15 checkpoint:
            ARI=0.4042 (HGNN-only) vs ARI=0.3541 (UF-enabled), singleton_fraction=1.0.
          - Hybrid is NOT recommended for this checkpoint — it routes low-confidence
            alerts to UF which creates singleton clusters and reduces ARI.
          - Union-Find is used only as a hard fallback when no HGNN model is available.
        """
        n_events = len(data)

        # Check if HGNN model is available
        model_available = self.model_path and Path(self.model_path).exists()

        if not model_available:
            logger.warning(
                f"HGNN model not found at '{self.model_path}'. "
                f"Falling back to Union-Find. Provide model_path for best results."
            )
            return CorrelationMethod.UNION_FIND

        # HGNN-only for all dataset sizes (empirically validated default)
        logger.info(
            f"Auto-selected HGNN (n_events={n_events}). "
            f"UF refinement disabled — net-harmful for current checkpoint (v2.6 finding)."
        )
        return CorrelationMethod.HGNN
    
    def correlate(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str],
        use_temporal: bool = False
    ) -> CorrelationResult:
        """
        Run correlation on security event data.
        
        Args:
            data: DataFrame with security events
            usernames: List of username column names
            addresses: List of address column names
            use_temporal: Whether to include temporal features
            
        Returns:
            CorrelationResult with clustered data and metadata
        """
        start_time = time.time()
        
        # Determine method
        method = self.method
        if method == CorrelationMethod.AUTO:
            method = self._select_method(data)
        
        logger.info(f"Running correlation with method: {method.value}")
        
        try:
            # Execute correlation
            if method == CorrelationMethod.UNION_FIND:
                result_df = self._run_union_find(data, usernames, addresses, use_temporal)
                confidence = 1.0
                fallback = False
                
            elif method == CorrelationMethod.HGNN:
                result_df, confidence, fallback = self._run_hgnn(data, usernames, addresses)
                
            elif method == CorrelationMethod.HYBRID:
                result_df = self._run_hybrid(data, usernames, addresses)
                confidence = None
                fallback = False
            
            runtime = time.time() - start_time
            num_clusters = result_df['pred_cluster'].nunique()
            
            logger.info(f"Correlation complete: {num_clusters} clusters in {runtime:.3f}s")
            
            return CorrelationResult(
                data=result_df,
                method_used=method.value,
                num_clusters=num_clusters,
                runtime_seconds=runtime,
                confidence_score=confidence,
                fallback_used=fallback
            )
            
        except Exception as e:
            logger.error(f"Correlation failed: {e}")
            
            # Fallback to Union-Find on any error
            if method != CorrelationMethod.UNION_FIND:
                logger.info("Falling back to Union-Find...")
                result_df = self._run_union_find(data, usernames, addresses, use_temporal)
                runtime = time.time() - start_time
                num_clusters = result_df['pred_cluster'].nunique()
                
                return CorrelationResult(
                    data=result_df,
                    method_used="union_find (fallback)",
                    num_clusters=num_clusters,
                    runtime_seconds=runtime,
                    confidence_score=1.0,
                    fallback_used=True
                )
            else:
                raise
    
    def _run_union_find(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str],
        use_temporal: bool
    ) -> pd.DataFrame:
        """Execute Union-Find correlation."""
        engine = self._get_union_find_engine()
        result = engine(data, usernames, addresses, use_temporal=use_temporal)
        result['correlation_method'] = 'Union-Find'
        return result
    
    def _run_hgnn(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str]
    ) -> Tuple[pd.DataFrame, float, bool]:
        """Execute HGNN correlation with fallback handling."""
        try:
            engine = self._get_hgnn_engine()
            result = engine.correlate(data)
            
            # Calculate average confidence
            if 'cluster_confidence' in result.columns:
                confidence = result['cluster_confidence'].mean()
            else:
                confidence = 1.0
            
            # Check for low confidence
            if confidence < self.confidence_threshold:
                logger.warning(f"Low confidence ({confidence:.3f}), consider fallback")
            
            return result, confidence, False
            
        except Exception as e:
            logger.error(f"HGNN correlation failed: {e}")
            raise
    
    def _run_hybrid(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str]
    ) -> pd.DataFrame:
        """Execute Hybrid correlation."""
        engine = self._get_hybrid_engine()
        result = engine.correlate(data, usernames, addresses)
        return result


# Convenience function for backward compatibility
def enhanced_correlation(
    data: pd.DataFrame,
    usernames: List[str],
    addresses: List[str],
    method: str = "auto",
    model_path: Optional[str] = None,
    **kwargs
) -> pd.DataFrame:
    """
    Backward-compatible correlation function.
    
    Drop-in replacement for correlation_indexer.enhanced_correlation()
    
    Usage:
        result = enhanced_correlation(df, ['username'], ['ip'], method='hgnn')
    """
    pipeline = CorrelationPipeline(method=method, model_path=model_path, **kwargs)
    result = pipeline.correlate(data, usernames, addresses)
    return result.data


