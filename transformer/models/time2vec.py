import torch
import torch.nn as nn
import math
from typing import List

class Time2Vec(nn.Module):
    """
    Time2Vec: Learning a Vector Representation of Time
    Kazemi et al. 2019
    Enhanced for cybersecurity with multiple time scales
    """
    def __init__(
        self,
        embed_dim: int = 64,
        num_frequencies: int = 32,
        time_scales: List[str] = ['minute', 'hour', 'day', 'week']
    ):
        super(Time2Vec, self).__init__()
        self.embed_dim = embed_dim
        self.num_frequencies = num_frequencies
        self.time_scales = time_scales
        
        # We assign frequencies evenly to time scales
        self.freqs_per_scale = num_frequencies // len(time_scales)
        if self.freqs_per_scale == 0:
            self.freqs_per_scale = 1
        
        actual_frequencies = self.freqs_per_scale * len(time_scales)
        
        # Linear component (trend)
        self.trend_weight = nn.Parameter(torch.randn(1))
        self.trend_bias = nn.Parameter(torch.randn(1))
        
        # Periodic components (seasonality)
        self.freq_weights = nn.Parameter(
            torch.randn(actual_frequencies)
        )
        self.phase_shifts = nn.Parameter(
            torch.randn(actual_frequencies)
        )
        
        # Projection to desired embed_dim
        # Output dim of concat is 1 (linear) + actual_frequencies
        in_features = 1 + actual_frequencies
        self.proj = nn.Linear(in_features, embed_dim)
        
        # Base periods in seconds
        self.scale_periods = {
            'minute': 60.0,
            'hour': 3600.0,
            'day': 86400.0,
            'week': 604800.0
        }
        
    def forward(self, timestamps: torch.Tensor) -> torch.Tensor:
        """
        Args:
            timestamps: Unix timestamps (seconds since epoch)
                        Shape: (batch_size, seq_len)
        Returns:
            Time embeddings: (batch_size, seq_len, embed_dim)
        """
        # Linear trend component
        trend = self.trend_weight * timestamps + self.trend_bias
        trend = trend.unsqueeze(-1)  # (batch, seq_len, 1)
        
        periodic_components = []
        freq_idx = 0
        
        # Calculate periodic components based on time scales
        # We normalize the timestamp by the scale period
        for scale in self.time_scales:
            period = self.scale_periods.get(scale, 1.0)
            # Normalized timestamp for this scale
            scaled_ts = timestamps / period
            
            for _ in range(self.freqs_per_scale):
                w = self.freq_weights[freq_idx]
                p = self.phase_shifts[freq_idx]
                
                # sin(w * t + p)
                comp = torch.sin(w * scaled_ts + p)
                periodic_components.append(comp.unsqueeze(-1))
                freq_idx += 1
                
        # Concatenate linear and periodic
        out = torch.cat([trend] + periodic_components, dim=-1)  # (batch, seq_len, 1 + freqs)
        
        # Project to target embedding dimension
        out = self.proj(out)
        return out
