"""
Debug script to find source of NaN/Inf in CyberTransformer
"""

import torch
import torch.nn as nn
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator, BiaffineAttention
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB

def debug_model():
    print("="*70)
    print("Debugging CyberTransformer NaN/Inf Issue")
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
    
    print(f"\nInput shapes:")
    print(f"  alert_ids: {alert_ids.shape}")
    print(f"  entity_ids: {entity_ids.shape}")
    print(f"  time_buckets: {time_buckets.shape}")
    
    # Forward pass with debugging
    with torch.no_grad():
        # Check embeddings
        alert_emb = model.alert_embedding(alert_ids)
        entity_emb = model.entity_embedding(entity_ids).mean(dim=2)
        time_emb = model.time_embedding(time_buckets)
        
        print(f"\nEmbedding ranges:")
        print(f"  alert_emb: [{alert_emb.min():.3f}, {alert_emb.max():.3f}]")
        print(f"  entity_emb: [{entity_emb.min():.3f}, {entity_emb.max():.3f}]")
        print(f"  time_emb: [{time_emb.min():.3f}, {time_emb.max():.3f}]")
        
        # Check for NaN in embeddings
        if torch.isnan(alert_emb).any():
            print("  WARNING: NaN in alert_emb!")
        if torch.isnan(entity_emb).any():
            print("  WARNING: NaN in entity_emb!")
        
        # Combined embeddings
        x = alert_emb + entity_emb + time_emb
        x = model.dropout(x)
        print(f"\nCombined embedding: [{x.min():.3f}, {x.max():.3f}]")
        
        # Check transformer layers
        for i, layer in enumerate(model.transformer_layers):
            x = layer(x, attention_mask)
            print(f"  Layer {i} output: [{x.min():.3f}, {x.max():.3f}] NaN: {torch.isnan(x).any().item()}")
        
        hidden_states = x
        print(f"\nHidden states: [{hidden_states.min():.3f}, {hidden_states.max():.3f}]")
        
        # Check biaffine attention
        affinity_matrix = model.pairwise_scorer(hidden_states)
        print(f"\nAffinity matrix: [{affinity_matrix.min():.3f}, {affinity_matrix.max():.3f}]")
        print(f"  NaN count: {torch.isnan(affinity_matrix).sum().item()}")
        print(f"  Inf count: {torch.isinf(affinity_matrix).sum().item()}")
        
        # Check after self-loop masking
        mask = torch.eye(seq_len).bool().unsqueeze(0)
        affinity_masked = affinity_matrix.masked_fill(mask, float('-inf'))
        print(f"\nAfter self-loop masking: [{affinity_masked.min():.3f}, {affinity_masked.max():.3f}]")
        print(f"  NaN count: {torch.isnan(affinity_masked).sum().item()}")
        print(f"  Inf count: {torch.isinf(affinity_masked).sum().item()}")
    
    print("\n" + "="*70)
    print("Debugging complete")
    print("="*70)

if __name__ == "__main__":
    debug_model()
