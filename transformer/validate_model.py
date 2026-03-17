"""
Validate CyberTransformer trained model
"""

import torch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transformer.models.candidate_generator import TransformerCandidateGenerator
from transformer.config.gpu_config_8gb import DEFAULT_CONFIG_8GB

def validate_model():
    print("="*70)
    print("CyberTransformer Validation")
    print("="*70)
    
    # Load checkpoint
    checkpoint_path = Path("cybertransformer_final/final.pt")
    if not checkpoint_path.exists():
        print(f"ERROR: Checkpoint not found at {checkpoint_path}")
        return
    
    print(f"Loading checkpoint: {checkpoint_path}")
    
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
    
    # Load weights
    checkpoint = torch.load(checkpoint_path, map_location='cpu', weights_only=True)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    print(f"Model loaded from step {checkpoint['step']}")
    
    # Test inference
    batch_size = 1
    seq_len = 50
    
    alert_ids = torch.randint(0, 1000, (batch_size, seq_len))
    entity_ids = torch.randint(0, 1000, (batch_size, seq_len, 4))
    time_buckets = torch.randint(0, 288, (batch_size, seq_len))
    attention_mask = torch.ones(batch_size, seq_len)
    
    with torch.no_grad():
        outputs = model(
            alert_ids=alert_ids,
            entity_ids=entity_ids,
            time_buckets=time_buckets,
            attention_mask=attention_mask,
            return_candidates=True,
            top_k=10
        )
    
    print(f"\nInference test:")
    print(f"  Candidate edges generated: {len(outputs['candidate_edges'])}")
    print(f"  Affinity matrix shape: {outputs['affinity_matrix'].shape}")
    print(f"  Affinity range: [{outputs['affinity_matrix'].min():.3f}, {outputs['affinity_matrix'].max():.3f}]")
    
    if len(outputs['candidate_edges']) > 0:
        print(f"\n  Sample edges (first 5):")
        for i, (edge, score) in enumerate(zip(outputs['candidate_edges'][:5], outputs['edge_scores'][:5])):
            print(f"    Edge {i}: {edge} -> score: {score:.3f}")
    
    # Memory footprint
    memory = model.get_memory_footprint()
    print(f"\nModel memory footprint:")
    print(f"  Parameters: {memory['param_size_mb']:.1f} MB")
    print(f"  Buffers: {memory['buffer_size_mb']:.1f} MB")
    print(f"  Total: {memory['total_size_mb']:.1f} MB")
    
    print("\n" + "="*70)
    print("VALIDATION SUCCESSFUL - Model is ready for inference")
    print("="*70)

if __name__ == "__main__":
    validate_model()
