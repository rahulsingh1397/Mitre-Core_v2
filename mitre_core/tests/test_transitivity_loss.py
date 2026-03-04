import torch
from mitre_core.models.objectives.transitivity import TransitivityLoss, HybridUnionFind

def test_transitivity_loss():
    loss_fn = TransitivityLoss(sample_size=100)
    embeddings = torch.randn(500, 64)
    loss = loss_fn(embeddings, temperature=0.5)
    
    assert loss.item() >= 0
    assert not torch.isnan(loss).any()

def test_hybrid_union_find():
    huf = HybridUnionFind(confidence_threshold=0.9)
    
    # Create mock probabilities
    p_matrix = torch.eye(5)
    p_matrix[0, 1] = 0.95
    p_matrix[1, 0] = 0.95
    p_matrix[3, 4] = 0.92
    p_matrix[4, 3] = 0.92
    
    clusters = huf.fit_predict(p_matrix)
    
    assert clusters.shape == (5,)
    assert clusters[0] == clusters[1]
    assert clusters[3] == clusters[4]
    assert clusters[0] != clusters[3]
    assert clusters[2] != clusters[0] and clusters[2] != clusters[3]

