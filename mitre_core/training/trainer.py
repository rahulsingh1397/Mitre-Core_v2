import torch
import torch.nn as nn
from typing import Dict
from torch_geometric.data import HeteroData
import logging

logger = logging.getLogger(__name__)

class PreTrainer:
    def __init__(self, model: nn.Module, contrastive_loss: nn.Module, 
                 augmenter, optimizer: torch.optim.Optimizer, device: torch.device):
        self.model = model
        self.contrastive_loss = contrastive_loss
        self.augmenter = augmenter
        self.optimizer = optimizer
        self.device = device
        
    def train_step(self, data: HeteroData, campaign_labels: torch.Tensor = None) -> float:
        self.model.train()
        self.optimizer.zero_grad()
        
        # Move data to device
        data = data.to(self.device)
        
        # Generate two augmented views
        view1 = self.augmenter.augment(data, view_type="feature_noise")
        view2 = self.augmenter.augment(data, view_type="edge_drop")
        
        # Forward pass
        # Since we use dict representation for HGT
        x_dict1 = view1.x_dict
        edge_index_dict1 = view1.edge_index_dict
        x_dict2 = view2.x_dict
        edge_index_dict2 = view2.edge_index_dict
        
        # Temporal bias optional handling
        temporal_bias_dict1 = view1.temporal_bias_dict if hasattr(view1, "temporal_bias_dict") else None
        temporal_bias_dict2 = view2.temporal_bias_dict if hasattr(view2, "temporal_bias_dict") else None
        
        out1 = self.model(x_dict1, edge_index_dict1, temporal_bias_dict1)
        out2 = self.model(x_dict2, edge_index_dict2, temporal_bias_dict2)
        
        # Assume "alert" is the main node type we are contrasting
        z1 = out1["alert"]
        z2 = out2["alert"]
        
        loss = self.contrastive_loss(z1, z2, campaign_labels)
        
        loss.backward()
        self.optimizer.step()
        
        return loss.item()

