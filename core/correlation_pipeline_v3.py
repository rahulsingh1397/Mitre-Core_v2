"""
Transformer-Union Find Integration Module
========================================

Integrates transformer candidate generation with Union-Find correlation.
This is the core of the v3.0 architecture.
"""

import logging
from typing import List, Tuple, Optional, Dict
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.cuda.amp import autocast

from core.correlation_pipeline import CorrelationPipeline, CorrelationMethod, CorrelationResult
from transformer.preprocessing.alert_preprocessor import AlertPreprocessor
from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.config.gpu_config_8gb import GPUConfig5060Ti, DEFAULT_CONFIG_8GB


logger = logging.getLogger("mitre-core.transformer_integration")


class TransformerHybridPipeline:
    """
    Hybrid pipeline combining transformer candidate generation with Union-Find.
    
    Architecture:
    1. Preprocess alerts to tensors
    2. Generate candidate edges via transformer (O(n) instead of O(n²))
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
        
        This is the key optimization: instead of O(n²) pairwise scoring,
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
        # This skips the O(n²) loop and only unions candidate pairs
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
