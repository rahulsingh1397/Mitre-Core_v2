import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
import copy

class SecurityGraphAugmenter:
    """
    Multi-View Graph Augmentation tailored for security graphs.
    Grounded in v1 findings: aggressive augmentation hurts performance.
    Optimal settings from v1: 5.8% feature dropout, 0.00054 noise.
    """
    def __init__(self, feature_drop_prob: float = 0.058, noise_std: float = 0.00054,
                 edge_drop_prob: float = 0.05, relation_drop_prob: float = 0.0):
        self.feature_drop_prob = feature_drop_prob
        self.noise_std = noise_std
        self.edge_drop_prob = edge_drop_prob
        self.relation_drop_prob = relation_drop_prob

    def augment(self, data: HeteroData, view_type: str = "feature_noise") -> HeteroData:
        """
        Generate an augmented view of the input HeteroData graph.
        """
        aug_data = data.clone()

        if view_type == "feature_noise":
            for node_type in aug_data.node_types:
                if "x" in aug_data[node_type]:
                    x = aug_data[node_type].x.clone()
                    # Apply Gaussian noise
                    noise = torch.randn_like(x) * self.noise_std
                    x = x + noise
                    
                    # Apply feature masking
                    mask = torch.rand_like(x) < self.feature_drop_prob
                    x[mask] = 0.0
                    aug_data[node_type].x = x
                    
        elif view_type == "edge_drop":
            for edge_type in aug_data.edge_types:
                # Relation level dropping
                if torch.rand(1).item() < self.relation_drop_prob:
                    # Drop entire relation (set edge index to empty)
                    aug_data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long, device=aug_data[edge_type].edge_index.device)
                    continue
                    
                edge_index = aug_data[edge_type].edge_index
                num_edges = edge_index.size(1)
                
                if num_edges > 0:
                    keep_mask = torch.rand(num_edges, device=edge_index.device) > self.edge_drop_prob
                    aug_data[edge_type].edge_index = edge_index[:, keep_mask]
                    if "edge_attr" in aug_data[edge_type]:
                        aug_data[edge_type].edge_attr = aug_data[edge_type].edge_attr[keep_mask]
                        
        elif view_type == "temporal_jitter":
            for edge_type in aug_data.edge_types:
                if "delta_t" in aug_data[edge_type]:
                    dt = aug_data[edge_type].delta_t.clone()
                    # Jitter by up to 5% of max window or a fixed small amount
                    jitter = (torch.rand_like(dt) - 0.5) * 10.0 # +/- 5 seconds
                    # Ensure dt doesn"t become negative if it"s strictly causal
                    aug_data[edge_type].delta_t = torch.clamp(dt + jitter, min=0.0)
                    
        return aug_data


class InfoNCELoss(nn.Module):
    """
    InfoNCE Loss for Multi-View Graph Contrastive Learning.
    Includes campaign-level positives and hard negative mining.
    """
    def __init__(self, temperature: float = 0.5, hard_negative_weight: float = 1.0):
        super().__init__()
        self.temperature = temperature
        self.hard_negative_weight = hard_negative_weight

    def forward(self, z1: torch.Tensor, z2: torch.Tensor, campaign_labels: torch.Tensor = None) -> torch.Tensor:
        """
        Args:
            z1: Embeddings from view 1, shape [N, D]
            z2: Embeddings from view 2, shape [N, D]
            campaign_labels: Optional labels indicating which events belong to the same campaign.
        """
        z1 = F.normalize(z1, dim=-1)
        z2 = F.normalize(z2, dim=-1)
        N = z1.size(0)
        
        # Similarity matrix [N, N]
        sim_matrix = torch.matmul(z1, z2.t()) / self.temperature
        
        if campaign_labels is None:
            # Standard InfoNCE (diagonal elements are positives)
            labels = torch.arange(N, device=z1.device)
            loss_1 = F.cross_entropy(sim_matrix, labels)
            loss_2 = F.cross_entropy(sim_matrix.t(), labels)
            return (loss_1 + loss_2) / 2
        else:
            # Campaign-level positives (Supervised Contrastive Learning)
            # Find all pairs belonging to the same campaign
            labels_matrix = (campaign_labels.unsqueeze(0) == campaign_labels.unsqueeze(1)).float()
            
            # Mask out background/unlabeled (e.g., if label is -1)
            valid_mask = (campaign_labels != -1).float()
            valid_pairs = valid_mask.unsqueeze(0) * valid_mask.unsqueeze(1)
            labels_matrix = labels_matrix * valid_pairs
            
            # Log-sum-exp over positives and negatives
            exp_sim = torch.exp(sim_matrix)
            
            # Sum of exp(sim) for all valid pairs
            denom = exp_sim.sum(dim=1, keepdim=True)
            
            # We want to maximize the similarity for all positive pairs
            # Compute log(exp(sim) / denom)
            log_prob = sim_matrix - torch.log(denom + 1e-8)
            
            # Mean of log-prob over positives
            num_positives = labels_matrix.sum(dim=1)
            
            # Avoid division by zero
            num_positives = torch.clamp(num_positives, min=1.0)
            
            loss = - (labels_matrix * log_prob).sum(dim=1) / num_positives
            
            # Only average over elements that have at least one positive
            valid_loss_mask = (num_positives > 0).float()
            return (loss * valid_loss_mask).sum() / torch.clamp(valid_loss_mask.sum(), min=1.0)


class MaskedNodePrediction(nn.Module):
    """
    GraphMAE-style masked node reconstruction objective.
    """
    def __init__(self, hidden_channels: int, out_channels: int):
        super().__init__()
        self.decoder = nn.Sequential(
            nn.Linear(hidden_channels, hidden_channels),
            nn.PReLU(),
            nn.Linear(hidden_channels, out_channels)
        )
        self.loss_fn = nn.MSELoss()

    def forward(self, embeddings: torch.Tensor, original_features: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        """
        Args:
            embeddings: Reconstructed embeddings from the backbone, shape [N, D]
            original_features: Original unmasked features, shape [N, F]
            mask: Boolean mask indicating which nodes were masked, shape [N]
        """
        # Only compute loss on masked nodes
        if not mask.any():
            return torch.tensor(0.0, device=embeddings.device, requires_grad=True)
            
        masked_embeddings = embeddings[mask]
        target_features = original_features[mask]
        
        predictions = self.decoder(masked_embeddings)
        return self.loss_fn(predictions, target_features)

