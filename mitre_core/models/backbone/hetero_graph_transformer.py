import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn.conv import MessagePassing
from torch_geometric.utils import softmax
from typing import Dict, List, Optional, Union
from torch import Tensor
import math

class TemporalHGTConv(MessagePassing):
    """
    Heterogeneous Graph Transformer Conv with Temporal Bias.
    Based on HGT (Hu et al. 2020) but customized to directly inject 
    continuous temporal bias into the attention logits.
    """
    def __init__(
        self,
        in_channels: Union[int, Dict[str, int]],
        out_channels: int,
        metadata: tuple,
        heads: int,
        dropout: float = 0.0,
        **kwargs,
    ):
        super().__init__(aggr="add", node_dim=0, **kwargs)
        
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.heads = heads
        self.dropout = dropout
        
        if out_channels % heads != 0:
            raise ValueError(f"\"out_channels\" ({out_channels}) must be divisible by \"heads\" ({heads})")
        self.dim = out_channels // heads
        
        self.node_types = metadata[0]
        self.edge_types = metadata[1]
        
        # Node-type specific projections
        self.k_lin = nn.ModuleDict()
        self.q_lin = nn.ModuleDict()
        self.v_lin = nn.ModuleDict()
        self.a_lin = nn.ModuleDict()
        self.skip = nn.ModuleDict()
        
        for node_type in self.node_types:
            in_dim = in_channels[node_type] if isinstance(in_channels, dict) else in_channels
            self.k_lin[node_type] = nn.Linear(in_dim, out_channels)
            self.q_lin[node_type] = nn.Linear(in_dim, out_channels)
            self.v_lin[node_type] = nn.Linear(in_dim, out_channels)
            self.a_lin[node_type] = nn.Linear(out_channels, out_channels)
            self.skip[node_type] = nn.Parameter(torch.Tensor(1))
            nn.init.constant_(self.skip[node_type], 1.0)
            
        # Edge-type specific projections and parameters
        self.w_k = nn.ParameterDict()
        self.w_q = nn.ParameterDict()
        self.w_v = nn.ParameterDict()
        self.mu = nn.ParameterDict()
        
        for edge_type in self.edge_types:
            edge_type_str = "__".join(edge_type)
            self.w_k[edge_type_str] = nn.Parameter(torch.empty(heads, self.dim, self.dim))
            self.w_q[edge_type_str] = nn.Parameter(torch.empty(heads, self.dim, self.dim))
            self.w_v[edge_type_str] = nn.Parameter(torch.empty(heads, self.dim, self.dim))
            self.mu[edge_type_str] = nn.Parameter(torch.empty(heads))
            
        self.reset_parameters()

    def reset_parameters(self):
        for node_type in self.node_types:
            nn.init.xavier_uniform_(self.k_lin[node_type].weight)
            nn.init.xavier_uniform_(self.q_lin[node_type].weight)
            nn.init.xavier_uniform_(self.v_lin[node_type].weight)
            nn.init.xavier_uniform_(self.a_lin[node_type].weight)
            
        for edge_type in self.edge_types:
            edge_type_str = "__".join(edge_type)
            nn.init.xavier_uniform_(self.w_k[edge_type_str])
            nn.init.xavier_uniform_(self.w_q[edge_type_str])
            nn.init.xavier_uniform_(self.w_v[edge_type_str])
            nn.init.zeros_(self.mu[edge_type_str])

    def forward(self, x_dict: Dict[str, Tensor], edge_index_dict: Dict[tuple, Tensor], 
                temporal_bias_dict: Optional[Dict[tuple, Tensor]] = None) -> Dict[str, Tensor]:
                
        # 1. Compute node type specific Q, K, V
        q_dict, k_dict, v_dict = {}, {}, {}
        for node_type, x in x_dict.items():
            q_dict[node_type] = self.q_lin[node_type](x).view(-1, self.heads, self.dim)
            k_dict[node_type] = self.k_lin[node_type](x).view(-1, self.heads, self.dim)
            v_dict[node_type] = self.v_lin[node_type](x).view(-1, self.heads, self.dim)
            
        out_dict = {node_type: [] for node_type in self.node_types}
        
        # 2. Message Passing per edge type
        for edge_type, edge_index in edge_index_dict.items():
            src_type, rel_type, dst_type = edge_type
            edge_type_str = "__".join(edge_type)
            
            k = k_dict[src_type]
            q = q_dict[dst_type]
            v = v_dict[src_type]
            
            tb = temporal_bias_dict[edge_type] if (temporal_bias_dict and edge_type in temporal_bias_dict) else None
            
            # Message passing for this edge type
            out = self.propagate(edge_index, q=q, k=k, v=v, 
                                 edge_type_str=edge_type_str,
                                 temporal_bias=tb,
                                 size=(x_dict[src_type].size(0), x_dict[dst_type].size(0)))
            out_dict[dst_type].append(out)
            
        # 3. Aggregation and Update
        final_dict = {}
        for node_type, outs in out_dict.items():
            x_in = x_dict[node_type]
            if len(outs) == 0:
                final_dict[node_type] = x_in
                continue
                
            out = torch.stack(outs, dim=0).sum(dim=0)
            
            # Update
            alpha = torch.sigmoid(self.skip[node_type])
            out = F.gelu(out)
            out = self.a_lin[node_type](out)
            
            # Residual connection
            if out.shape[-1] == x_in.shape[-1]:
                out = out * alpha + x_in * (1 - alpha)
            
            final_dict[node_type] = out
            
        return final_dict

    def message(self, q_i, k_j, v_j, index, edge_type_str, temporal_bias, ptr, size_i):
        # q_i: [E, heads, dim]
        # k_j: [E, heads, dim]
        # v_j: [E, heads, dim]
        
        w_k = self.w_k[edge_type_str] # [heads, dim, dim]
        w_q = self.w_q[edge_type_str]
        w_v = self.w_v[edge_type_str]
        
        # Edge-type specific projection
        k_j = torch.einsum("ehd, hdc -> ehc", k_j, w_k)
        q_i = torch.einsum("ehd, hdc -> ehc", q_i, w_q)
        v_j = torch.einsum("ehd, hdc -> ehc", v_j, w_v)
        
        # Compute attention scores
        # scores: [E, heads]
        scores = (q_i * k_j).sum(dim=-1) / math.sqrt(self.dim)
        
        # Add relation bias
        scores = scores + self.mu[edge_type_str]
        
        # Add temporal bias if present
        if temporal_bias is not None:
            # temporal_bias: [E] or [E, heads]
            if temporal_bias.dim() == 1:
                temporal_bias = temporal_bias.unsqueeze(-1)
            scores = scores + temporal_bias
            
        # Softmax over target nodes
        alpha = softmax(scores, index, ptr, size_i)
        alpha = F.dropout(alpha, p=self.dropout, training=self.training)
        
        # Apply attention to values
        out = v_j * alpha.unsqueeze(-1) # [E, heads, dim]
        
        return out.view(-1, self.out_channels) # [E, out_channels]

class ConstraintAwareHGT(nn.Module):
    """
    Heterogeneous Graph Transformer Backbone for MITRE-CORE v2.
    """
    def __init__(
        self,
        in_channels: Union[int, Dict[str, int]],
        hidden_channels: int,
        out_channels: int,
        metadata: tuple,
        num_layers: int,
        heads: int,
        dropout: float = 0.1,
        residual: bool = True
    ):
        super().__init__()
        self.num_layers = num_layers
        self.residual = residual
        
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleDict()
        
        # Add dict for each node type
        self.node_types = metadata[0]
        
        for i in range(num_layers):
            in_dim = in_channels if i == 0 else hidden_channels
            self.convs.append(
                TemporalHGTConv(
                    in_channels=in_dim,
                    out_channels=hidden_channels if i < num_layers - 1 else out_channels,
                    metadata=metadata,
                    heads=heads,
                    dropout=dropout
                )
            )
            
            if i < num_layers - 1:
                norms_i = nn.ModuleDict()
                for node_type in self.node_types:
                    norms_i[node_type] = nn.LayerNorm(hidden_channels)
                self.norms[str(i)] = norms_i

    def forward(self, x_dict: Dict[str, Tensor], edge_index_dict: Dict[tuple, Tensor], 
                temporal_bias_dict: Optional[Dict[tuple, Tensor]] = None) -> Dict[str, Tensor]:
                
        for i, conv in enumerate(self.convs):
            x_dict_next = conv(x_dict, edge_index_dict, temporal_bias_dict)
            
            if i < self.num_layers - 1:
                # Apply normalization, activation and optional residual
                for node_type in x_dict_next.keys():
                    h = x_dict_next[node_type]
                    h = self.norms[str(i)][node_type](h)
                    
                    if self.residual and h.shape == x_dict[node_type].shape:
                        h = h + x_dict[node_type]
                        
                    x_dict_next[node_type] = h
                    
            x_dict = x_dict_next
            
        return x_dict

