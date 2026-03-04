import torch
import torch.nn as nn
from torch_geometric.data import HeteroData

class SecurityHardener:
    """
    Robustness evaluation tools for testing model resilience against attacks.
    """
    def __init__(self, data: HeteroData):
        self.data = data.clone()

    def inject_edge_noise(self, corruption_level: float = 0.1) -> HeteroData:
        """
        Inject random edge noise to simulate graph poisoning.
        """
        noisy_data = self.data.clone()
        for edge_type in noisy_data.edge_types:
            edge_index = noisy_data[edge_type].edge_index
            num_edges = edge_index.size(1)
            
            # Determine how many edges to drop and add
            num_corrupt = int(num_edges * corruption_level)
            
            if num_corrupt == 0:
                continue
                
            # Drop edges
            keep_mask = torch.rand(num_edges, device=edge_index.device) > corruption_level
            
            # Add random edges
            src_type, _, dst_type = edge_type
            num_src_nodes = noisy_data[src_type].num_nodes
            num_dst_nodes = noisy_data[dst_type].num_nodes
            
            random_src = torch.randint(0, num_src_nodes, (num_corrupt,), device=edge_index.device)
            random_dst = torch.randint(0, num_dst_nodes, (num_corrupt,), device=edge_index.device)
            random_edges = torch.stack([random_src, random_dst], dim=0)
            
            new_edge_index = torch.cat([edge_index[:, keep_mask], random_edges], dim=1)
            noisy_data[edge_type].edge_index = new_edge_index
            
        return noisy_data

    def inject_feature_perturbation(self, noise_std: float = 1.0) -> HeteroData:
        """
        Add Gaussian noise to node features.
        """
        noisy_data = self.data.clone()
        for node_type in noisy_data.node_types:
            if "x" in noisy_data[node_type]:
                x = noisy_data[node_type].x
                noise = torch.randn_like(x) * noise_std
                noisy_data[node_type].x = x + noise
        return noisy_data

