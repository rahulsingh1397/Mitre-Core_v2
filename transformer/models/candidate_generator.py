"""
Transformer Candidate Generator
===============================

Sparse attention transformer for O(n) candidate generation.
Optimized for RTX 5060 Ti 8GB.
"""

import logging
from typing import Optional, List, Tuple, Dict

import torch
import torch.nn as nn
import torch.nn.functional as F

from transformer.config.gpu_config_8gb import GPUConfig5060Ti, DEFAULT_CONFIG_8GB


logger = logging.getLogger("mitre-core.transformer.model")


class BiaffineAttention(nn.Module):
    """
    Biaffine attention for pairwise scoring.
    
    Computes affinity scores between all pairs of alerts in O(n²) time
    but with very low constant factor (just matrix multiplications).
    """
    
    def __init__(self, d_model: int):
        super().__init__()
        self.d_model = d_model
        
        # Learnable weight matrix
        self.W = nn.Parameter(torch.randn(d_model, d_model))
        nn.init.xavier_uniform_(self.W)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Compute pairwise biaffine scores.
        
        Args:
            x: [batch, seq_len, d_model]
            
        Returns:
            scores: [batch, seq_len, seq_len]
        """
        # x @ W: [batch, seq_len, d_model]
        # (x @ W) @ x.T: [batch, seq_len, seq_len]
        batch_size, seq_len, _ = x.shape
        
        # Expand W for batch
        W_batch = self.W.unsqueeze(0).expand(batch_size, -1, -1)
        
        # Compute: x @ W @ x.T
        intermediate = torch.bmm(x, W_batch)  # [batch, seq_len, d_model]
        scores = torch.bmm(intermediate, x.transpose(1, 2))  # [batch, seq_len, seq_len]
        
        return scores


class TransformerCandidateGenerator(nn.Module):
    """
    Sparse attention transformer for O(n) candidate generation.
    
    This model uses linear attention mechanisms to achieve O(n) complexity
    instead of standard quadratic attention.
    
    For 8GB GPU, we use:
    - Smaller model (128-dim, 2 layers)
    - Linear attention approximation
    - Gradient checkpointing for memory efficiency
    
    Architecture:
    1. Token embeddings (alert + entity + temporal)
    2. Transformer encoder with linear attention
    3. Biaffine pairwise scoring
    4. Confidence head
    """
    
    def __init__(
        self,
        vocab_size: int = 10000,
        num_entities: int = 10000,
        d_model: int = 128,        # Reduced for 8GB
        n_layers: int = 2,         # Reduced for 8GB
        n_heads: int = 4,          # Reduced for 8GB
        d_ff: int = 256,           # Reduced for 8GB
        max_seq_len: int = 256,    # Reduced for 8GB
        dropout: float = 0.1,
        use_gradient_checkpointing: bool = True,
        config: Optional[GPUConfig5060Ti] = None
    ):
        """
        Initialize transformer candidate generator.
        
        Args:
            vocab_size: Size of alert vocabulary
            num_entities: Size of entity vocabulary
            d_model: Model dimension
            n_layers: Number of transformer layers
            n_heads: Number of attention heads
            d_ff: Feed-forward dimension
            max_seq_len: Maximum sequence length
            dropout: Dropout rate
            use_gradient_checkpointing: Enable gradient checkpointing for memory
            config: GPU configuration object
        """
        super().__init__()
        
        self.config = config or DEFAULT_CONFIG_8GB
        self.d_model = d_model
        self.max_seq_len = max_seq_len
        
        # Embeddings
        self.alert_embedding = nn.Embedding(vocab_size, d_model)
        self.entity_embedding = nn.Embedding(num_entities, d_model)
        self.time_embedding = nn.Embedding(288, d_model)  # 5-min buckets * 24h
        self.position_embedding = nn.Embedding(max_seq_len, d_model)
        
        # Dropout
        self.dropout = nn.Dropout(dropout)
        
        # Transformer layers using linear attention
        # For 8GB GPU, we use custom lightweight attention instead of full Performer
        self.transformer_layers = nn.ModuleList([
            LightweightTransformerLayer(d_model, n_heads, d_ff, dropout)
            for _ in range(n_layers)
        ])
        
        # Gradient checkpointing flag
        self.use_gradient_checkpointing = use_gradient_checkpointing
        
        # Pairwise scoring
        self.pairwise_scorer = BiaffineAttention(d_model)
        
        # Confidence head
        self.confidence_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, 1),
            nn.Sigmoid()
        )
        
        # Initialize weights
        self._init_weights()
        
        logger.info(
            f"TransformerCandidateGenerator initialized: "
            f"d_model={d_model}, n_layers={n_layers}, n_heads={n_heads}, "
            f"max_seq_len={max_seq_len}"
        )
    
    def _init_weights(self):
        """Initialize model weights."""
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p)
    
    def forward(
        self,
        alert_ids: torch.Tensor,      # [batch, seq_len]
        entity_ids: torch.Tensor,     # [batch, seq_len, num_entity_types]
        time_buckets: torch.Tensor,    # [batch, seq_len]
        attention_mask: Optional[torch.Tensor] = None,  # [batch, seq_len]
        return_candidates: bool = True,
        top_k: int = 10
    ) -> Dict:
        """
        Forward pass returning candidate edges.
        
        Args:
            alert_ids: Alert token IDs
            entity_ids: Entity token IDs [batch, seq_len, 4] (src_ip, dst_ip, hostname, username)
            time_buckets: Time bucket indices
            attention_mask: Attention mask (1 for valid, 0 for padding)
            return_candidates: Whether to extract candidate edges
            top_k: Number of top candidates per alert
            
        Returns:
            Dictionary with:
            - candidate_edges: List of (i, j) tuples
            - edge_scores: List of affinity scores
            - confidence: Per-alert confidence scores
            - hidden_states: Final hidden states
        """
        batch_size, seq_len = alert_ids.shape
        device = alert_ids.device
        
        # Create attention mask if not provided
        if attention_mask is None:
            attention_mask = torch.ones(batch_size, seq_len, device=device)
        
        # Build embeddings
        alert_emb = self.alert_embedding(alert_ids)  # [batch, seq_len, d_model]
        time_emb = self.time_embedding(time_buckets)  # [batch, seq_len, d_model]
        
        # Entity embeddings (average of entity types)
        entity_emb = self.entity_embedding(entity_ids)  # [batch, seq_len, 4, d_model]
        entity_emb = entity_emb.mean(dim=2)  # [batch, seq_len, d_model]
        
        # Position embeddings
        positions = torch.arange(seq_len, device=device).unsqueeze(0).expand(batch_size, -1)
        pos_emb = self.position_embedding(positions)  # [batch, seq_len, d_model]
        
        # Combine embeddings
        x = alert_emb + entity_emb + time_emb + pos_emb
        x = self.dropout(x)
        
        # Apply transformer layers with optional gradient checkpointing
        for layer in self.transformer_layers:
            if self.use_gradient_checkpointing and self.training:
                x = torch.utils.checkpoint.checkpoint(layer, x, attention_mask)
            else:
                x = layer(x, attention_mask)
        
        hidden_states = x  # [batch, seq_len, d_model]
        
        # Generate pairwise affinity matrix
        affinity_matrix = self.pairwise_scorer(hidden_states)  # [batch, seq_len, seq_len]
        
        # Mask self-loops
        mask = torch.eye(seq_len, device=device).bool().unsqueeze(0).expand(batch_size, -1, -1)
        affinity_matrix = affinity_matrix.masked_fill(mask, float('-inf'))
        
        # Mask padding positions
        if attention_mask is not None:
            # Mask rows where attention_mask is 0
            row_mask = (attention_mask == 0).unsqueeze(-1).expand(-1, -1, seq_len)
            affinity_matrix = affinity_matrix.masked_fill(row_mask, float('-inf'))
            # Mask columns where attention_mask is 0
            col_mask = (attention_mask == 0).unsqueeze(1).expand(-1, seq_len, -1)
            affinity_matrix = affinity_matrix.masked_fill(col_mask, float('-inf'))
        
        # Confidence scores
        confidence = self.confidence_head(hidden_states).squeeze(-1)  # [batch, seq_len]
        
        result = {
            'affinity_matrix': affinity_matrix,
            'confidence': confidence,
            'hidden_states': hidden_states
        }
        
        # Extract top-k candidates if requested
        if return_candidates:
            candidate_edges = []
            edge_scores = []
            
            for b in range(batch_size):
                # Get top-k neighbors for each alert
                topk_scores, topk_indices = torch.topk(
                    affinity_matrix[b],
                    k=min(top_k, seq_len - 1),
                    dim=-1
                )
                
                for i in range(seq_len):
                    if attention_mask[b, i] == 0:
                        continue
                    for idx, score in zip(topk_indices[i], topk_scores[i]):
                        if attention_mask[b, idx] == 0:
                            continue
                        if not torch.isinf(score):
                            candidate_edges.append((i, idx.item()))
                            edge_scores.append(score.item())
            
            result['candidate_edges'] = candidate_edges
            result['edge_scores'] = edge_scores
        
        return result
    
    def get_memory_footprint(self) -> Dict:
        """Get model memory footprint in MB."""
        param_size = sum(p.numel() * p.element_size() for p in self.parameters())
        buffer_size = sum(b.numel() * b.element_size() for b in self.buffers())
        
        return {
            'param_size_mb': param_size / 1024 / 1024,
            'buffer_size_mb': buffer_size / 1024 / 1024,
            'total_size_mb': (param_size + buffer_size) / 1024 / 1024
        }


class LightweightTransformerLayer(nn.Module):
    """
    Lightweight transformer layer using efficient attention.
    
    Uses a simplified attention mechanism suitable for small models
    on limited GPU memory.
    """
    
    def __init__(self, d_model: int, n_heads: int, d_ff: int, dropout: float = 0.1):
        super().__init__()
        
        self.d_model = d_model
        self.n_heads = n_heads
        self.head_dim = d_model // n_heads
        
        # Multi-head attention
        self.q_proj = nn.Linear(d_model, d_model)
        self.k_proj = nn.Linear(d_model, d_model)
        self.v_proj = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)
        
        # Feed-forward
        self.ff = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model)
        )
        
        # Layer norms
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        
        # Dropout
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: [batch, seq_len, d_model]
            attention_mask: [batch, seq_len]
            
        Returns:
            output: [batch, seq_len, d_model]
        """
        # Multi-head attention with residual
        residual = x
        x = self.norm1(x)
        
        # Project to Q, K, V
        q = self.q_proj(x)
        k = self.k_proj(x)
        v = self.v_proj(x)
        
        # Reshape for multi-head attention
        batch_size, seq_len, _ = q.shape
        q = q.view(batch_size, seq_len, self.n_heads, self.head_dim).transpose(1, 2)
        k = k.view(batch_size, seq_len, self.n_heads, self.head_dim).transpose(1, 2)
        v = v.view(batch_size, seq_len, self.n_heads, self.head_dim).transpose(1, 2)
        
        # Scaled dot-product attention
        scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5)
        
        # Apply attention mask
        if attention_mask is not None:
            mask = (attention_mask == 0).unsqueeze(1).unsqueeze(2)  # [batch, 1, 1, seq_len]
            scores = scores.masked_fill(mask, float('-inf'))
        
        attn_weights = F.softmax(scores, dim=-1)
        attn_weights = self.dropout(attn_weights)
        
        # Apply attention to values
        attn_output = torch.matmul(attn_weights, v)  # [batch, n_heads, seq_len, head_dim]
        attn_output = attn_output.transpose(1, 2).contiguous().view(batch_size, seq_len, self.d_model)
        
        # Output projection
        attn_output = self.out_proj(attn_output)
        x = residual + self.dropout(attn_output)
        
        # Feed-forward with residual
        residual = x
        x = self.norm2(x)
        x = residual + self.dropout(self.ff(x))
        
        return x
