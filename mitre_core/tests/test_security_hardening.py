import torch
from torch_geometric.data import HeteroData
from mitre_core.security.model_hardening import SecurityHardener

def test_security_hardener():
    # Create mock HeteroData
    data = HeteroData()
    data["alert"].x = torch.randn(10, 16)
    data["ip"].x = torch.randn(5, 8)
    
    edge_index = torch.tensor([[0, 1, 2, 3], [0, 1, 2, 3]])
    data["alert", "connects_to", "ip"].edge_index = edge_index
    
    hardener = SecurityHardener(data)
    
    # Test edge noise
    noisy_edge_data = hardener.inject_edge_noise(corruption_level=0.5)
    assert "alert" in noisy_edge_data.node_types
    assert ("alert", "connects_to", "ip") in noisy_edge_data.edge_types
    
    # Test feature perturbation
    noisy_feat_data = hardener.inject_feature_perturbation(noise_std=0.1)
    assert not torch.allclose(data["alert"].x, noisy_feat_data["alert"].x)
    assert noisy_feat_data["alert"].x.shape == data["alert"].x.shape

