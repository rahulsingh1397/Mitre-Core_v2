"""
GPU Configuration for RTX 5060 Ti 8GB
======================================

Aggressive memory optimizations for training transformer on 8GB VRAM.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class GPUConfig5060Ti:
    """
    Hardware-optimized configuration for RTX 5060 Ti 8GB.
    
    Memory Budget (8GB):
    - Model weights (FP16): ~500MB
    - Activations: ~2GB
    - Optimizer states: ~1.5GB (offloaded to CPU)
    - Gradients: ~500MB
    - Data batch: ~1GB
    - CUDA overhead: ~2.5GB
    - Total: ~8GB (at limit)
    """
    
    # Model Architecture (Minimal viable size)
    d_model: int = 128           # Reduced from 256
    n_layers: int = 2             # Reduced from 4
    n_heads: int = 4            # Reduced from 8
    d_ff: int = 256             # Reduced from 1024
    max_seq_len: int = 256       # Reduced from 512
    dropout: float = 0.1
    
    # Training Configuration
    batch_size: int = 4          # Maximum for 8GB
    gradient_accumulation_steps: int = 16  # Effective batch = 64
    gradient_checkpointing: bool = True     # Essential - trades compute for memory
    mixed_precision: bool = True            # FP16 cuts memory in half
    cpu_offload: bool = True                # Offload optimizer states to CPU RAM
    
    # Optimizer
    learning_rate: float = 1e-4
    weight_decay: float = 0.01
    warmup_steps: int = 1000
    max_grad_norm: float = 1.0
    
    # Inference
    batch_inference_size: int = 8
    torch_compile: bool = True              # PyTorch 2.0+ optimization
    cuda_graphs: bool = False               # Disabled - saves memory
    
    # Checkpointing
    save_every_n_steps: int = 500
    keep_last_n_checkpoints: int = 3
    
    @property
    def effective_batch_size(self) -> int:
        """Calculate effective batch size with gradient accumulation."""
        return self.batch_size * self.gradient_accumulation_steps
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'd_model': self.d_model,
            'n_layers': self.n_layers,
            'n_heads': self.n_heads,
            'd_ff': self.d_ff,
            'max_seq_len': self.max_seq_len,
            'dropout': self.dropout,
            'batch_size': self.batch_size,
            'gradient_accumulation_steps': self.gradient_accumulation_steps,
            'gradient_checkpointing': self.gradient_checkpointing,
            'mixed_precision': self.mixed_precision,
            'cpu_offload': self.cpu_offload,
            'learning_rate': self.learning_rate,
            'weight_decay': self.weight_decay,
            'warmup_steps': self.warmup_steps,
            'max_grad_norm': self.max_grad_norm,
            'batch_inference_size': self.batch_inference_size,
            'torch_compile': self.torch_compile,
            'cuda_graphs': self.cuda_graphs,
            'effective_batch_size': self.effective_batch_size
        }
    
    @classmethod
    def from_dict(cls, config_dict: dict) -> 'GPUConfig5060Ti':
        """Create from dictionary."""
        return cls(**{
            k: v for k, v in config_dict.items()
            if k in cls.__dataclass_fields__
        })


# Default instance
DEFAULT_CONFIG_8GB = GPUConfig5060Ti()
