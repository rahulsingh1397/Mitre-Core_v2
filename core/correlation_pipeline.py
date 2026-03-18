"""
MITRE-CORE Unified Correlation Pipeline v2.1
==============================================

Integrates Transformer candidate generation, Union-Find (baseline), and HGNN (deep learning) 
correlation methods into a single, clean pipeline with automatic method selection.

This is the core of the v2.1 enhanced architecture.

Usage:
    from core.correlation_pipeline import CorrelationPipeline, TransformerHybridPipeline
    
    # Traditional pipeline with auto method selection
    pipeline = CorrelationPipeline(method='auto')
    
    # Or transformer-enhanced hybrid pipeline
    pipeline = TransformerHybridPipeline(transformer_path='path/to/model.pt')
    
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
from torch.cuda.amp import autocast

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


# Import transformer components (after local class definitions to avoid circular imports)
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.config.gpu_config_8gb import GPUConfig5060Ti, DEFAULT_CONFIG_8GB


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
        union_find_weight: float = 0.3,
        # Backward-compatible parameters for enhanced_correlation
        threshold_override: Optional[float] = None,
        use_adaptive_threshold: bool = True,
        **kwargs
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
        
        # Store backward-compatible parameters
        self.threshold_override = threshold_override
        self.use_adaptive_threshold = use_adaptive_threshold
        self.kwargs = kwargs  # Store additional kwargs for enhanced_correlation
        
        # Initialize engines lazily
        self._union_find_engine = None
        self._hgnn_engine = None
        self._hybrid_engine = None
        
        logger.info(f"Pipeline initialized: method={method}, device={self.device}")
    
    def _get_union_find_engine(self):
        """Lazy initialization of Union-Find engine."""
        if self._union_find_engine is None:
            from core.correlation_indexer import enhanced_correlation
            self._union_find_engine = enhanced_correlation
        return self._union_find_engine
    
    def _get_hgnn_engine(self):
        """Lazy initialization of HGNN engine."""
        if self._hgnn_engine is None:
            try:
                from hgnn.hgnn_correlation import HGNNCorrelationEngine
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
            from hgnn.hgnn_integration import HybridCorrelationEngine
            self._hybrid_engine = HybridCorrelationEngine(
                hgnn_weight=self.hgnn_weight,
                union_find_weight=self.uf_weight,
                model_path=self.model_path,
                device=self.device
            )
        return self._hybrid_engine
    
    def _select_method(self, data: pd.DataFrame) -> CorrelationMethod:
        """Automatically select best correlation method."""
        n_events = len(data)
        
        # Small datasets: Union-Find is faster and sufficient
        if n_events < 100:
            logger.info(f"Auto-selected Union-Find (small dataset: {n_events} events)")
            return CorrelationMethod.UNION_FIND
        
        # Check if HGNN model is available
        model_available = self.model_path and Path(self.model_path).exists()
        
        if not model_available:
            logger.info(f"Auto-selected Union-Find (HGNN model not available)")
            return CorrelationMethod.UNION_FIND
        
        # Medium datasets: Hybrid for best accuracy/speed tradeoff
        if n_events < 1000:
            logger.info(f"Auto-selected Hybrid (medium dataset: {n_events} events)")
            return CorrelationMethod.HYBRID
        
        # Large datasets: HGNN for best accuracy
        logger.info(f"Auto-selected HGNN (large dataset: {n_events} events)")
        return CorrelationMethod.HGNN
    
    def correlate(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str],
        use_temporal: bool = False,
        **kwargs
    ) -> CorrelationResult:
        """
        Run correlation on security event data.
        
        Args:
            data: DataFrame with security events
            usernames: List of username column names
            addresses: List of address column names
            use_temporal: Whether to include temporal features
            **kwargs: Additional arguments (threshold_override, cluster_confidence, use_adaptive_threshold)
            
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
            # Merge stored and passed parameters
            merged_kwargs = {**self.kwargs, **kwargs}
            threshold_override = merged_kwargs.get('threshold_override', self.threshold_override)
            use_adaptive_threshold = merged_kwargs.get('use_adaptive_threshold', self.use_adaptive_threshold)
            cluster_confidence = merged_kwargs.get('cluster_confidence', None)
            
            # Prepare extra arguments for enhanced_correlation
            extra_args = {}
            if threshold_override is not None:
                extra_args['threshold_override'] = threshold_override
            if cluster_confidence is not None:
                extra_args['cluster_confidence'] = cluster_confidence
            if not use_adaptive_threshold:
                extra_args['use_adaptive_threshold'] = False
            
            # Execute correlation
            if method == CorrelationMethod.UNION_FIND:
                result_df = self._run_union_find(data, usernames, addresses, use_temporal, **extra_args)
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
                result_df = self._run_union_find(data, usernames, addresses, use_temporal, **extra_args)
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
        use_temporal: bool,
        **extra_args
    ) -> pd.DataFrame:
        """Execute Union-Find correlation."""
        engine = self._get_union_find_engine()
        result = engine(data, usernames, addresses, use_temporal=use_temporal, **extra_args)
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


class TransformerHybridPipeline:
    """
    Hybrid pipeline combining transformer candidate generation with Union-Find.
    
    Architecture:
    1. Preprocess alerts to tensors
    2. Generate candidate edges via transformer (O(n) instead of O(n┬▓))
    3. Pass candidates to Union-Find for exact transitive closure
    4. Return clusters with metadata
    
    This preserves the deterministic semantics of Union-Find while achieving
    near-linear time complexity through transformer candidate pre-filtering.
    """
    
    def __init__(
        self,
        transformer_path: Optional[str] = None,
        device: str = "cuda",
        top_k: int = 10,
        score_threshold: float = 0.5,
        use_amp: bool = True,
        config: Optional[GPUConfig5060Ti] = None
    ):
        """
        Initialize hybrid pipeline.
        
        Args:
            transformer_path: Path to trained transformer checkpoint
            device: 'cuda' or 'cpu'
            top_k: Number of candidate neighbors per alert
            score_threshold: Minimum score to include candidate
            use_amp: Use automatic mixed precision (FP16)
            config: GPU configuration
        """
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        self.top_k = top_k
        self.score_threshold = score_threshold
        self.use_amp = use_amp
        self.config = config or DEFAULT_CONFIG_8GB
        
        # Initialize components
        self.preprocessor = AlertPreprocessor(max_seq_length=self.config.max_seq_len)
        self.transformer: Optional[TransformerCandidateGenerator] = None
        self.uf_pipeline = CorrelationPipeline(method='union_find')
        
        # Load transformer if path provided
        if transformer_path:
            self.load_transformer(transformer_path)
        
        logger.info(
            f"TransformerHybridPipeline initialized: "
            f"device={self.device}, top_k={top_k}, threshold={score_threshold}"
        )
    
    def load_transformer(self, checkpoint_path: str) -> None:
        """
        Load transformer model from checkpoint.
        
        Args:
            checkpoint_path: Path to checkpoint file
        """
        checkpoint_path = Path(checkpoint_path)
        
        if not checkpoint_path.exists():
            logger.error(f"Checkpoint not found: {checkpoint_path}")
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
        
        logger.info(f"Loading transformer from {checkpoint_path}")
        
        # Create model with 8GB config
        self.transformer = TransformerCandidateGenerator(
            vocab_size=10000,
            num_entities=10000,
            d_model=self.config.d_model,
            n_layers=self.config.n_layers,
            n_heads=self.config.n_heads,
            d_ff=self.config.d_ff,
            max_seq_len=self.config.max_seq_len,
            use_gradient_checkpointing=self.config.gradient_checkpointing,
            config=self.config
        ).to(self.device)
        
        # Load weights
        checkpoint = torch.load(checkpoint_path, map_location=self.device, weights_only=True)
        self.transformer.load_state_dict(checkpoint['model_state_dict'])
        self.transformer.eval()
        
        # Compile for inference speed (PyTorch 2.0+)
        if hasattr(torch, 'compile') and self.config.torch_compile:
            try:
                self.transformer = torch.compile(self.transformer, mode="reduce-overhead")
                logger.info("Model compiled with torch.compile")
            except Exception as e:
                logger.warning(f"Could not compile model: {e}")
        
        logger.info("Transformer loaded successfully")
    
    def correlate(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str],
        use_temporal: bool = False
    ) -> CorrelationResult:
        """
        Run hybrid correlation: transformer candidates + Union-Find.
        
        Args:
            data: DataFrame with security events
            usernames: List of username column names
            addresses: List of address column names
            use_temporal: Whether to include temporal features
            
        Returns:
            CorrelationResult with clustered data and metadata
        """
        import time
        start_time = time.time()
        
        # If no transformer available, fall back to pure Union-Find
        if self.transformer is None:
            logger.warning("No transformer loaded, falling back to pure Union-Find")
            return self.uf_pipeline.correlate(data, usernames, addresses, use_temporal)
        
        try:
            # Step 1: Preprocess to tensors
            batch_result = self.preprocessor.process_batch(
                data,
                device=self.device,
                batch_id=f"hybrid_{int(start_time)}"
            )
            
            # Step 2: Generate candidates via transformer
            with torch.no_grad():
                with autocast(enabled=self.use_amp):
                    transformer_outputs = self.transformer(
                        alert_ids=batch_result['alert_ids'],
                        entity_ids=batch_result['entity_ids'],
                        time_buckets=batch_result['time_buckets'],
                        attention_mask=batch_result['attention_mask'],
                        return_candidates=True,
                        top_k=self.top_k
                    )
            
            # Step 3: Filter candidates by threshold
            candidate_edges = self._filter_candidates(
                transformer_outputs['candidate_edges'],
                transformer_outputs['edge_scores'],
                self.score_threshold
            )
            
            logger.info(f"Generated {len(candidate_edges)} candidate edges (threshold={self.score_threshold})")
            
            # Step 4: Pass candidates to Union-Find
            if len(candidate_edges) > 0:
                result_df = self._run_union_find_with_candidates(
                    data, usernames, addresses, candidate_edges
                )
                method_used = "transformer_hybrid"
                fallback = False
            else:
                # No candidates generated, fall back to pure UF
                logger.warning("No candidates generated, falling back to Union-Find")
                result_df = self.uf_pipeline.correlate(data, usernames, addresses, use_temporal)
                result_df = result_df.data
                method_used = "union_find (fallback - no candidates)"
                fallback = True
            
            # Step 5: Add metadata
            runtime = time.time() - start_time
            num_clusters = result_df['cluster_id'].nunique() if 'cluster_id' in result_df.columns else 0
            
            # Get confidence scores
            confidence = transformer_outputs['confidence'].mean().item() if 'confidence' in transformer_outputs else 1.0
            
            # Add telemetry columns
            result_df['transformer_candidates'] = len(candidate_edges)
            result_df['avg_transformer_score'] = np.mean(transformer_outputs['edge_scores']) if transformer_outputs['edge_scores'] else 0.0
            result_df['fallback_used'] = fallback
            result_df['correlation_method'] = method_used
            
            logger.info(
                f"Hybrid correlation complete: {num_clusters} clusters "
                f"in {runtime:.3f}s using {len(candidate_edges)} candidates"
            )
            
            return CorrelationResult(
                data=result_df,
                method_used=method_used,
                num_clusters=num_clusters,
                runtime_seconds=runtime,
                confidence_score=confidence,
                fallback_used=fallback
            )
            
        except Exception as e:
            logger.error(f"Hybrid correlation failed: {e}")
            logger.info("Falling back to pure Union-Find")
            
            # Fallback to pure Union-Find
            result = self.uf_pipeline.correlate(data, usernames, addresses, use_temporal)
            result.fallback_used = True
            return result
    
    def _filter_candidates(
        self,
        edges: List[Tuple[int, int]],
        scores: List[float],
        threshold: float
    ) -> List[Tuple[int, int, float]]:
        """
        Filter candidates by score threshold.
        
        Args:
            edges: List of (i, j) edge tuples
            scores: List of affinity scores
            threshold: Minimum score threshold
            
        Returns:
            List of (i, j, score) tuples above threshold
        """
        filtered = []
        for (i, j), score in zip(edges, scores):
            if score >= threshold:
                filtered.append((i, j, float(score)))
        return filtered
    
    def _run_union_find_with_candidates(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str],
        candidate_edges: List[Tuple[int, int, float]]
    ) -> pd.DataFrame:
        """
        Run Union-Find with candidate edge pre-filtering.
        
        This is the key optimization: instead of O(n┬▓) pairwise scoring,
        we only consider the O(k) candidate edges from the transformer.
        
        Args:
            data: Alert DataFrame
            usernames: Username columns
            addresses: Address columns
            candidate_edges: List of (i, j, score) candidate edges
            
        Returns:
            DataFrame with cluster assignments
        """
        from core.correlation_indexer import enhanced_correlation
        
        # Call enhanced_correlation with candidate_edges parameter
        # This skips the O(n┬▓) loop and only unions candidate pairs
        result_df = enhanced_correlation(
            data=data,
            usernames=usernames,
            addresses=addresses,
            use_temporal=False,
            candidate_edges=candidate_edges  # NEW: pass candidate edges
        )
        
        # Add metadata
        result_df['candidate_source'] = 'transformer'
        result_df['num_candidates'] = len(candidate_edges)
        
        return result_df
    
    def get_model_info(self) -> Dict:
        """Get transformer model information."""
        if self.transformer is None:
            return {"status": "not_loaded"}
        
        memory = self.transformer.get_memory_footprint()
        
        return {
            "status": "loaded",
            "d_model": self.config.d_model,
            "n_layers": self.config.n_layers,
            "n_heads": self.config.n_heads,
            "max_seq_len": self.config.max_seq_len,
            "device": str(self.device),
            **memory
        }


def create_hybrid_pipeline(
    checkpoint_path: Optional[str] = None,
    **kwargs
) -> TransformerHybridPipeline:
    """
    Factory function to create hybrid pipeline.
    
    Args:
        checkpoint_path: Path to transformer checkpoint
        **kwargs: Additional arguments for TransformerHybridPipeline
        
    Returns:
        Configured TransformerHybridPipeline
    """
    return TransformerHybridPipeline(
        transformer_path=checkpoint_path,
        **kwargs
    )


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
