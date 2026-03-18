import torch
import torch.nn as nn
from typing import Optional, Dict

from transformer.models.sliding_window_attention import SlidingWindowAttention
from transformer.models.hgt_encoder import HGTLayer

class TemporalEncoderLayer(nn.Module):
    """Single layer of temporal encoding using SlidingWindowAttention."""
    def __init__(self, embed_dim: int, num_heads: int = 8, window_size: int = 512):
        super().__init__()
        self.self_attn = SlidingWindowAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            window_size=window_size
        )
        self.norm1 = nn.LayerNorm(embed_dim)
        self.norm2 = nn.LayerNorm(embed_dim)
        self.ff = nn.Sequential(
            nn.Linear(embed_dim, embed_dim * 4),
            nn.GELU(),
            nn.Linear(embed_dim * 4, embed_dim)
        )
        
    def forward(self, x, is_global, attention_mask=None):
        # Pre-norm architecture
        norm_x = self.norm1(x)
        attn_out = self.self_attn(
            query=norm_x, key=norm_x, value=norm_x,
            is_global=is_global, attention_mask=attention_mask
        )
        x = x + attn_out
        x = x + self.ff(self.norm2(x))
        return x


class CrossAttentionFusion(nn.Module):
    """Fuses temporal and spatial features using cross-attention."""
    def __init__(self, temporal_dim: int, spatial_dim: int, fusion_dim: int, num_heads: int = 8):
        super().__init__()
        self.temp_proj = nn.Linear(temporal_dim, fusion_dim)
        self.spat_proj = nn.Linear(spatial_dim, fusion_dim)
        
        self.cross_attn_t_to_s = nn.MultiheadAttention(fusion_dim, num_heads, batch_first=True)
        self.cross_attn_s_to_t = nn.MultiheadAttention(fusion_dim, num_heads, batch_first=True)
        
        self.norm = nn.LayerNorm(fusion_dim * 2)
        self.out_proj = nn.Linear(fusion_dim * 2, fusion_dim)
        
    def forward(self, temporal_features, spatial_features):
        """
        temporal_features: (batch, seq_len, temporal_dim)
        spatial_features: (batch, num_nodes, spatial_dim)
        """
        # Project to common dimension
        t_feat = self.temp_proj(temporal_features)
        s_feat = self.spat_proj(spatial_features)
        
        # Temporal attends to Spatial
        # Query: Temporal, Key/Value: Spatial
        t_attended, _ = self.cross_attn_t_to_s(t_feat, s_feat, s_feat)
        
        # Spatial attends to Temporal
        # Query: Spatial, Key/Value: Temporal
        s_attended, _ = self.cross_attn_s_to_t(s_feat, t_feat, t_feat)
        
        # For simplicity, we assume we want to return a unified sequence representation
        # So we align spatial attended features back to the sequence length
        # In a real implementation, this mapping depends on how nodes map to sequence elements
        
        # Placeholder alignment (assuming 1:1 mapping for alert nodes)
        seq_len = t_feat.size(1)
        s_aligned = s_attended[:, :seq_len, :]
        
        # Combine
        combined = torch.cat([t_attended, s_aligned], dim=-1)
        out = self.out_proj(self.norm(combined))
        
        return out


class TemporalSpatialFusion(nn.Module):
    """
    Lightweight Temporal-Spatial Transformer
    Based on 2024 drone network IDS research
    15x faster than standard Transformer
    """
    def __init__(
        self,
        temporal_dim: int = 256,
        spatial_dim: int = 256,
        fusion_dim: int = 256,
        num_temporal_layers: int = 4,
        num_spatial_layers: int = 2,
        node_types: list = ['alert', 'ip', 'host', 'tactic']
    ):
        super().__init__()
        
        # Temporal branch: SlidingWindowAttention
        self.temporal_encoder = nn.ModuleList([
            TemporalEncoderLayer(embed_dim=temporal_dim)
            for _ in range(num_temporal_layers)
        ])
        
        # Spatial branch: HGT
        # Setup dummy input dims for HGT based on spatial_dim
        hgt_in_dims = {nt: spatial_dim for nt in node_types}
        
        self.spatial_encoder = nn.ModuleList([
            HGTLayer(in_dim=hgt_in_dims if i==0 else {nt: spatial_dim for nt in node_types}, 
                     out_dim=spatial_dim)
            for i in range(num_spatial_layers)
        ])
        
        # Fusion layer
        self.fusion = CrossAttentionFusion(temporal_dim, spatial_dim, fusion_dim)
        
    def forward(
        self,
        temporal_sequence: torch.Tensor,  # Alert sequence: (batch, seq_len, temporal_dim)
        is_global: torch.Tensor,          # Global mask: (batch, seq_len)
        node_features: Dict[str, torch.Tensor], # PyG Data equivalent
        edge_indices: Dict[str, torch.Tensor],
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        
        # 1. Encode temporal sequence
        t_out = temporal_sequence
        for layer in self.temporal_encoder:
            t_out = layer(t_out, is_global, attention_mask)
            
        # 2. Encode spatial graph
        s_out = node_features
        for layer in self.spatial_encoder:
            s_out = layer(node_features=s_out, edge_index=edge_indices)
            
        # 3. Cross-attention fusion
        # Extract 'alert' nodes which correspond to the sequence elements
        alert_nodes = s_out.get('alert', None)
        
        if alert_nodes is not None:
            # We assume alert_nodes is shaped correctly for batch processing
            # (batch, num_alerts, spatial_dim)
            fused_out = self.fusion(t_out, alert_nodes)
        else:
            # Fallback if no alert nodes
            fused_out = t_out
            
        return fused_out
