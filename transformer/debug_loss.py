"""
Debug loss computation issue
"""

import torch
import torch.nn.functional as F
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB

def debug_loss():
    print("="*70)
    print("Debugging Loss Computation")
    print("="*70)
    
    # Create model
    model = TransformerCandidateGenerator(
        vocab_size=10000,
        num_entities=10000,
        d_model=128,
        n_layers=2,
        n_heads=4,
        max_seq_len=256,
        dropout=0.1,
        use_gradient_checkpointing=False,
        config=DEFAULT_CONFIG_8GB
    )
    model.eval()
    
    # Create test input
    batch_size = 1
    seq_len = 50
    
    alert_ids = torch.randint(0, 1000, (batch_size, seq_len))
    entity_ids = torch.randint(0, 1000, (batch_size, seq_len, 4))
    time_buckets = torch.randint(0, 288, (batch_size, seq_len))
    attention_mask = torch.ones(batch_size, seq_len)
    
    # Create alternating labels (0,1,0,1...)
    labels = torch.arange(seq_len, dtype=torch.long) % 2
    labels = labels.unsqueeze(0)  # [1, seq_len]
    
    print(f"\nLabels: {labels[0][:10]}... (showing first 10)")
    print(f"Label 0 count: {(labels == 0).sum().item()}")
    print(f"Label 1 count: {(labels == 1).sum().item()}")
    
    with torch.no_grad():
        outputs = model(
            alert_ids=alert_ids,
            entity_ids=entity_ids,
            time_buckets=time_buckets,
            attention_mask=attention_mask,
            return_candidates=False
        )
        
        affinity_matrix = outputs['affinity_matrix']
        print(f"\nAffinity matrix range: [{affinity_matrix.min():.3f}, {affinity_matrix.max():.3f}]")
        
        # Handle NaN/Inf
        if torch.isnan(affinity_matrix).any() or torch.isinf(affinity_matrix).any():
            print("NaN/Inf detected, clamping...")
            affinity_matrix = torch.nan_to_num(affinity_matrix, nan=0.0, posinf=10.0, neginf=-10.0)
        
        affinity_matrix = torch.clamp(affinity_matrix, -10.0, 10.0)
        print(f"After clamp: [{affinity_matrix.min():.3f}, {affinity_matrix.max():.3f}]")
        
        # Create masks
        pos_mask = (labels.unsqueeze(1) == labels.unsqueeze(2)).float()
        neg_mask = 1 - pos_mask
        eye_mask = torch.eye(seq_len).unsqueeze(0)
        pos_mask = pos_mask * (1 - eye_mask)
        
        print(f"\nPos mask sum: {pos_mask.sum().item()}")
        print(f"Neg mask sum: {neg_mask.sum().item()}")
        
        # Compute loss using softplus
        pos_loss = F.softplus(-affinity_matrix) * pos_mask
        neg_loss = F.softplus(affinity_matrix) * neg_mask
        
        print(f"\nPos loss sum: {pos_loss.sum().item():.4f}")
        print(f"Neg loss sum: {neg_loss.sum().item():.4f}")
        
        num_pos = pos_mask.sum()
        num_neg = neg_mask.sum()
        
        loss = (pos_loss.sum() + neg_loss.sum()) / (num_pos + num_neg + 1e-8)
        print(f"\nTotal loss: {loss.item():.4f}")
        
        # Debug: Show affinity values for positive vs negative pairs
        pos_affinities = affinity_matrix[pos_mask.bool()]
        neg_affinities = affinity_matrix[neg_mask.bool()]
        
        if pos_affinities.numel() > 0:
            print(f"\nPositive pair affinities: [{pos_affinities.min():.3f}, {pos_affinities.max():.3f}]")
        if neg_affinities.numel() > 0:
            print(f"Negative pair affinities: [{neg_affinities.min():.3f}, {neg_affinities.max():.3f}]")

if __name__ == "__main__":
    debug_loss()
