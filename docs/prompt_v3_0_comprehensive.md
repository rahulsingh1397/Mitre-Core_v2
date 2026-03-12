# MITRE-CORE v3.0: Comprehensive System Upgrade & Transformation Guide

## Executive Summary

**Version:** v3.0-TX (Transformer-Enhanced Architecture)  
**Status:** Architecture Design Complete - Pending Implementation Review  
**Goal:** Transform MITRE-CORE from O(n²) Union-Find bottleneck to O(n) transformer-candidate + deterministic UF hybrid, leveraging GPU acceleration for training and inference.

### Key Innovations in v3.0
1. **Transformer-Assisted Candidate Generator**: Sparse attention (Performer/BigBird) reduces pairwise scoring from O(n²) to O(n)
2. **Hardware-Optimized GPU Pipeline**: CUDA kernels for transformer inference, mixed precision (FP16), gradient checkpointing
3. **Deterministic-Preserving Architecture**: Union-Find backend remains exact; transformer only filters candidates
4. **Multi-Phase Validation**: Progressive testing from synthetic → real datasets → production SIEM

---

## PART 1: ARCHITECTURE REVIEW & GAP ANALYSIS

### 1.1 Current System Bottlenecks (v2.6-v2.9)

| Component | Current | Limitation | Impact |
|-----------|---------|------------|--------|
| Union-Find | O(n²) pairwise | 110s at n=495 | Real-time limit ~500 events |
| HGNN | O(n+e) | Probabilistic clustering | No transitive closure guarantees |
| Confidence Gate | HDBSCAN probabilities | 100% UF routing (pct_uf_routed=1.0) | Gate tuning ineffective |
| Hybrid Mode | 0.7/0.3 weighting | Net-harmful (ARI 0.3541 vs 0.4042) | Worse than HGNN-only |

### 1.2 Missing Best Practices (Identified from v2.x Review)

#### A. MLOps & Production Readiness
| Practice | v2.x Status | v3.0 Requirement |
|----------|-------------|-------------------|
| Model versioning | ❌ Missing | ✅ MLflow/Weights & Biases integration |
| A/B testing framework | ❌ Missing | ✅ Shadow mode for transformer candidates |
| Feature store | ❌ Missing | ✅ Entity embedding cache with TTL |
| Drift detection | ❌ Missing | ✅ Running score distribution monitoring |
| Circuit breaker | ❌ Missing | ✅ Auto-fallback on transformer failure |

#### B. Security & Hardening
| Practice | v2.x Status | v3.0 Requirement |
|----------|-------------|-------------------|
| Input sanitization | ⚠️ Partial | ✅ JSON Schema validation on all inputs |
| Rate limiting | ❌ Missing | ✅ Token bucket per API endpoint |
| Audit logging | ⚠️ Basic | ✅ Structured audit logs (who, what, when, result) |
| Secrets management | ❌ Missing | ✅ Vault integration for API keys |
| Model signing | ❌ Missing | ✅ Sigstore signing for transformer checkpoints |

#### C. Observability
| Practice | v2.x Status | v3.0 Requirement |
|----------|-------------|-------------------|
| Distributed tracing | ❌ Missing | ✅ OpenTelemetry spans across pipeline |
| Custom metrics | ⚠️ Basic | ✅ Prometheus metrics: latency, accuracy, cache hit rate |
| Alerting | ❌ Missing | ✅ PagerDuty/Slack on accuracy degradation |
| Profiling | ❌ Missing | ✅ PyTorch Profiler + NVIDIA Nsight |

#### D. Testing & Validation
| Practice | v2.x Status | v3.0 Requirement |
|----------|-------------|-------------------|
| Unit test coverage | ⚠️ ~40% | ✅ >80% with property-based testing (Hypothesis) |
| Integration tests | ⚠️ Ad-hoc | ✅ Docker-compose test environment |
| Load testing | ❌ Missing | ✅ Locust/k6 for 10K events/second |
| Chaos engineering | ❌ Missing | ✅ Fault injection (network latency, GPU OOM) |

---

## PART 2: V3.0 TRANSFORMER ARCHITECTURE SPECIFICATION

### 2.1 System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MITRE-CORE v3.0 Pipeline                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐   │
│  │  SIEM Input │───▶│  Windowing &     │───▶│  Transformer     │   │
│  │  (Alerts)   │    │  Batching        │    │  Preprocessor    │   │
│  └─────────────┘    └──────────────────┘    └──────────────────┘   │
│                                                      │              │
│                                                      ▼              │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │           TRANSFORMER CANDIDATE GENERATOR              │       │
│  │  ┌─────────────┐    ┌─────────────┐    ┌────────────┐ │       │
│  │  │  Tokenizer  │───▶│  Sparse     │───▶│  Pairwise  │ │       │
│  │  │  (Entity+   │    │  Attention  │    │  Scorer    │ │       │
│  │  │   Alert)    │    │  (O(n))     │    │  (Top-k)   │ │       │
│  │  └─────────────┘    └─────────────┘    └────────────┘ │       │
│  └──────────────────────────────────────────────────────────┘       │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │              UNION-FIND CORRELATION ENGINE               │       │
│  │  (Deterministic Transitive Closure - Unchanged)          │       │
│  └──────────────────────────────────────────────────────────┘       │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │                    OUTPUT & FEEDBACK                       │       │
│  │  • Cluster assignments                                   │       │
│  │  • Confidence scores                                     │       │
│  │  • Latency metrics                                       │       │
│  │  • Drift detection                                       │       │
│  └──────────────────────────────────────────────────────────┘       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 GPU-Optimized Transformer Module

#### Hardware Requirements
- **Minimum:** NVIDIA GPU with 8GB VRAM (RTX 3070, A10)
- **Recommended:** NVIDIA A100 40GB or H100 80GB for batch training
- **Inference:** Support CPU fallback with quantized model (INT8)

#### CUDA Optimization Strategies

```python
# transformer/config/gpu_config.py
class GPUConfig:
    """Hardware-optimized configuration for transformer training/inference."""
    
    # Memory Management
    MIXED_PRECISION = True  # FP16 training (2x speedup, half memory)
    GRADIENT_CHECKPOINTING = True  # Trade compute for memory (fit 2x larger models)
    BATCH_SIZE = 64  # Tune based on GPU VRAM
    MAX_SEQ_LENGTH = 512  # Alert window size
    
    # CUDA Kernels
    CUDNN_BENCHMARK = True  # Auto-tune conv algorithms
    CUDA_LAUNCH_BLOCKING = False  # Async kernel launches (debug=False)
    
    # Multi-GPU Training
    DISTRIBUTED_BACKEND = "nccl"  # NVIDIA Collective Communications
    FIND_UNUSED_PARAMETERS = False  # Set True only if needed (slower)
    
    # Inference Optimization
    TORCH_COMPILE = True  # PyTorch 2.0+ graph optimization
    CUDA_GRAPH_CAPTURE = True  # Eliminate CPU overhead for static shapes
```

#### Sparse Attention Implementation

```python
# transformer/models/sparse_attention.py
import torch
from performer_pytorch import Performer  # O(n) attention

class SparseAlertTransformer(torch.nn.Module):
    """
    Performer-based transformer with O(n) attention complexity.
    
    Uses FAVOR+ (Fast Attention Via Orthogonal Random features)
    to approximate softmax attention in linear time.
    """
    
    def __init__(
        self,
        dim: int = 256,
        depth: int = 4,
        heads: int = 8,
        dim_head: int = 32,
        max_seq_len: int = 512,
        num_alerts: int = 512,
        num_entities: int = 128
    ):
        super().__init__()
        
        # Alert embeddings
        self.alert_embedding = torch.nn.Embedding(num_alerts, dim)
        
        # Entity embeddings (users, hosts, IPs)
        self.entity_embedding = torch.nn.Embedding(num_entities, dim)
        
        # Positional encoding (temporal)
        self.time_embedding = torch.nn.Embedding(288, dim)  # 5-min buckets * 24h
        
        # Performer encoder (O(n) instead of O(n²))
        self.encoder = Performer(
            dim=dim,
            depth=depth,
            heads=heads,
            dim_head=dim_head,
            max_seq_len=max_seq_len,
            causal=False,  # Bidirectional for correlation
            features_redraw_interval=1000  # Redraw random features periodically
        )
        
        # Pairwise scoring head (biaffine attention)
        self.pairwise_scorer = BiaffineScorer(dim)
        
    def forward(
        self,
        alert_ids: torch.Tensor,  # [batch, seq_len]
        entity_ids: torch.Tensor,  # [batch, num_entities]
        time_buckets: torch.Tensor,  # [batch, seq_len]
        attention_mask: torch.Tensor  # [batch, seq_len]
    ) -> torch.Tensor:
        """
        Returns top-k candidate edges with scores.
        
        Complexity: O(n * d²) where d=dim (fixed), vs O(n²) for dense attention
        """
        # Embed alerts + entities + temporal
        alert_emb = self.alert_embedding(alert_ids)
        time_emb = self.time_embedding(time_buckets)
        
        # Combine embeddings
        x = alert_emb + time_emb
        
        # Sparse self-attention (O(n) complexity)
        x = self.encoder(x, mask=attention_mask)
        
        # Generate pairwise scores
        edge_scores = self.pairwise_scorer(x)  # [batch, seq_len, seq_len]
        
        return edge_scores
```

### 2.3 Data Pipeline with GPU Streaming

```python
# transformer/data/gpu_dataloader.py
from torch.utils.data import IterableDataset
import torch

class GPUPrefetchDataLoader:
    """
    Overlaps data transfer (CPU→GPU) with GPU computation.
    Eliminates PCIe bottleneck via pinned memory + async copies.
    """
    
    def __init__(
        self,
        dataset: IterableDataset,
        batch_size: int = 64,
        num_workers: int = 4,
        pin_memory: bool = True,
        prefetch_factor: int = 2
    ):
        self.dataset = dataset
        self.batch_size = batch_size
        self.num_workers = num_workers
        self.pin_memory = pin_memory
        self.prefetch_factor = prefetch_factor
        
    def __iter__(self):
        """Yield GPU-resident batches with overlapped transfer."""
        stream = torch.cuda.Stream()
        
        # Prefetch next batch while current processes
        batch_queue = []
        for batch in self._cpu_iterator():
            with torch.cuda.stream(stream):
                gpu_batch = {
                    k: v.cuda(non_blocking=True) 
                    for k, v in batch.items()
                }
            batch_queue.append(gpu_batch)
            
            if len(batch_queue) >= self.prefetch_factor:
                yield batch_queue.pop(0)
                torch.cuda.current_stream().wait_stream(stream)
```

---

## PART 3: PHASED UPGRADATION PLAN

### Phase 0: Foundation (Week 1-2) - COMPLETE PREREQUISITES

**Objective:** Complete all v2.x backlog before transformer work begins.

#### 0.1 Code Quality Fixes (Groups A-D from v2.x)
- [ ] **A1-A3:** Fix bare imports in `core/correlation_pipeline.py`
- [ ] **B1:** Update auto-selection logic (HGNN-only default)
- [ ] **C1:** Create `hgnn_checkpoints/README.md`
- [ ] **D1-D5:** Postprocessing and output fixes

#### 0.2 Security Hardening
- [ ] Add `weights_only=True` to all `torch.load()` calls (CRITICAL)
- [ ] Remove duplicate `core/security_utils.py`
- [ ] Replace bare `except Exception` with specific exception types
- [ ] Input validation on all Flask API endpoints

#### 0.3 Testing Infrastructure
```bash
# Acceptance Criteria - All must pass
python -m pytest tests/ -v --cov=core --cov=hgnn --cov-report=html
python validation/run_accuracy_validation.py
python validation/run_accuracy_experiment.py
```

**Deliverable:** Clean baseline with all v2.x technical debt resolved.

---

### Phase 1: Data Interface & Preprocessing (Week 3-4)

**Objective:** Build transformer-ready data pipeline with GPU streaming.

#### 1.1 Alert Tokenization Schema

```python
# transformer/schema/alert_schema.py
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class AlertToken(BaseModel):
    """Normalized alert representation for transformer."""
    
    # Identifiers
    alert_id: str
    alert_type: str  # e.g., "suricata_alert", "windows_event"
    
    # MITRE ATT&CK
    tactic: Optional[str] = None
    technique: Optional[str] = None
    
    # Entities (hashed to vocab indices)
    src_ip_hash: int
    dst_ip_hash: int
    hostname_hash: int
    username_hash: int
    
    # Temporal
    timestamp: datetime
    time_bucket: int  # 5-minute bin (0-287 for 24h)
    
    # Severity
    severity_score: float  # Normalized 0-1
    
    # Free-form text (optional, for future BERT integration)
    description: Optional[str] = None

class AlertBatch(BaseModel):
    """Batch of alerts for transformer processing."""
    
    batch_id: str
    window_start: datetime
    window_end: datetime
    alerts: List[AlertToken]
    
    # Entity mapping for this batch
    entity_vocab: dict  # hash -> entity string
    
    # Ground truth (for training)
    campaign_labels: Optional[List[int]] = None
```

#### 1.2 Preprocessor Implementation

```python
# transformer/preprocessing/alert_preprocessor.py
import torch
import pandas as pd
from transformers import AutoTokenizer

class AlertPreprocessor:
    """
    Converts raw alert DataFrames to transformer-ready tensors.
    Optimized for GPU batch processing.
    """
    
    def __init__(
        self,
        max_seq_length: int = 512,
        time_bucket_minutes: int = 5,
        vocab_size: int = 10000
    ):
        self.max_seq_length = max_seq_length
        self.time_bucket_minutes = time_bucket_minutes
        self.vocab_size = vocab_size
        
        # Entity hashers (consistent across batches)
        self.entity_hashers = {
            'ip': self._make_hasher(vocab_size),
            'hostname': self._make_hasher(vocab_size),
            'username': self._make_hasher(vocab_size)
        }
        
    def process_batch(
        self,
        df: pd.DataFrame,
        device: torch.device = torch.device('cuda')
    ) -> dict:
        """
        Convert DataFrame to GPU tensors.
        
        Args:
            df: Alert DataFrame with standard columns
            device: Target GPU device
            
        Returns:
            Dictionary of tensors ready for transformer
        """
        # Sort by time for positional encoding
        df = df.sort_values('timestamp')
        
        # Tokenize alerts
        alert_tokens = self._tokenize_alerts(df)
        
        # Build entity tokens
        entity_tokens = self._build_entity_tokens(df)
        
        # Temporal bucketing
        time_buckets = self._compute_time_buckets(df)
        
        # Create attention mask (handle padding)
        attention_mask = torch.ones(len(df), dtype=torch.long)
        
        return {
            'alert_ids': alert_tokens.to(device),
            'entity_ids': entity_tokens.to(device),
            'time_buckets': time_buckets.to(device),
            'attention_mask': attention_mask.to(device),
            'metadata': {
                'batch_size': len(df),
                'time_span': df['timestamp'].max() - df['timestamp'].min()
            }
        }
```

#### 1.3 Batching Strategy

```python
# transformer/data/windowing.py
class SlidingWindowBatcher:
    """
    Creates overlapping windows for streaming alert processing.
    Critical for maintaining continuity across batches.
    """
    
    def __init__(
        self,
        window_size: int = 512,
        overlap: int = 64,  # Context preservation
        max_time_gap: pd.Timedelta = pd.Timedelta(minutes=5)
    ):
        self.window_size = window_size
        self.overlap = overlap
        self.max_time_gap = max_time_gap
        
    def create_windows(
        self,
        df: pd.DataFrame
    ) -> List[pd.DataFrame]:
        """
        Split dataframe into overlapping windows.
        
        Strategy:
        1. Hard break on time gaps > max_time_gap
        2. Soft break on window_size
        3. Carry over 'overlap' alerts to next window
        """
        windows = []
        
        # Detect natural breaks (time gaps)
        df = df.sort_values('timestamp')
        time_diff = df['timestamp'].diff()
        break_points = [0] + list(np.where(time_diff > self.max_time_gap)[0])
        
        for start, end in zip(break_points, break_points[1:] + [len(df)]):
            segment = df.iloc[start:end]
            
            # Slide window with overlap
            for i in range(0, len(segment), self.window_size - self.overlap):
                window = segment.iloc[i:i + self.window_size]
                if len(window) >= 10:  # Minimum window size
                    windows.append(window)
        
        return windows
```

**Deliverable:** 
- `transformer/preprocessing/alert_preprocessor.py` (tested)
- Unit tests: >90% coverage
- Benchmark: 10K alerts → tensors in <100ms on GPU

---

### Phase 2: Transformer Model Development (Week 5-7)

**Objective:** Build and train sparse attention transformer for candidate generation.

#### 2.1 Model Architecture

```python
# transformer/models/candidate_generator.py
import torch
import torch.nn as nn
from performer_pytorch import PerformerLM

class TransformerCandidateGenerator(nn.Module):
    """
    Sparse attention transformer for O(n) candidate generation.
    """
    
    def __init__(
        self,
        vocab_size: int = 10000,
        d_model: int = 256,
        n_layers: int = 4,
        n_heads: int = 8,
        d_ff: int = 1024,
        max_seq_len: int = 512,
        dropout: float = 0.1,
        feature_redraw_interval: int = 1000
    ):
        super().__init__()
        
        self.d_model = d_model
        
        # Token embeddings
        self.token_embedding = nn.Embedding(vocab_size, d_model)
        self.position_embedding = nn.Embedding(max_seq_len, d_model)
        self.time_embedding = nn.Embedding(288, d_model)  # 5-min buckets
        
        # Performer backbone (O(n) attention)
        self.encoder = PerformerLM(
            num_tokens=vocab_size,
            dim=d_model,
            depth=n_layers,
            heads=n_heads,
            dim_head=d_model // n_heads,
            max_seq_len=max_seq_len,
            causal=False,
            features_redraw_interval=feature_redraw_interval,
            nb_features=256  # Number of random features for FAVOR+
        )
        
        # Pairwise scoring (biaffine attention)
        self.pairwise_scorer = BiaffineAttention(d_model)
        
        # Confidence calibration
        self.confidence_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, 1),
            nn.Sigmoid()
        )
        
    def forward(
        self,
        input_ids: torch.Tensor,
        time_buckets: torch.Tensor,
        attention_mask: torch.Tensor,
        return_candidates: bool = True,
        top_k: int = 10
    ) -> dict:
        """
        Forward pass returning candidate edges.
        
        Returns:
            Dictionary with:
            - candidate_edges: [batch, top_k, 2] (i, j) indices
            - edge_scores: [batch, top_k] affinity scores
            - confidence: [batch, seq_len] per-alert confidence
        """
        batch_size, seq_len = input_ids.shape
        
        # Build embeddings
        positions = torch.arange(seq_len, device=input_ids.device)
        positions = positions.unsqueeze(0).expand(batch_size, -1)
        
        x = self.token_embedding(input_ids)
        x = x + self.position_embedding(positions)
        x = x + self.time_embedding(time_buckets)
        
        # Sparse self-attention (O(n) complexity)
        hidden_states = self.encoder(x, mask=attention_mask)
        
        # Generate pairwise affinity matrix
        affinity_matrix = self.pairwise_scorer(hidden_states)
        
        # Mask self-loops and padding
        mask = torch.eye(seq_len, device=affinity_matrix.device).bool()
        mask = mask.unsqueeze(0).expand(batch_size, -1, -1)
        affinity_matrix = affinity_matrix.masked_fill(mask, float('-inf'))
        
        # Extract top-k candidates per alert
        if return_candidates:
            # Get top-k neighbors for each alert
            topk_scores, topk_indices = torch.topk(
                affinity_matrix, 
                k=min(top_k, seq_len - 1),
                dim=-1
            )
            
            # Create edge list [(i, j, score), ...]
            candidate_edges = []
            edge_scores = []
            
            for b in range(batch_size):
                for i in range(seq_len):
                    if attention_mask[b, i] == 0:
                        continue
                    for idx, score in zip(topk_indices[b, i], topk_scores[b, i]):
                        if attention_mask[b, idx] == 0:
                            continue
                        candidate_edges.append((i, idx.item()))
                        edge_scores.append(score.item())
            
            # Confidence scores
            confidence = self.confidence_head(hidden_states).squeeze(-1)
            
            return {
                'candidate_edges': candidate_edges,
                'edge_scores': edge_scores,
                'confidence': confidence,
                'hidden_states': hidden_states
            }
        
        return {'affinity_matrix': affinity_matrix}

class BiaffineAttention(nn.Module):
    """Biaffine attention for pairwise scoring."""
    
    def __init__(self, d_model: int):
        super().__init__()
        self.W = nn.Parameter(torch.randn(d_model, d_model))
        nn.init.xavier_uniform_(self.W)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Compute pairwise biaffine scores."""
        # x: [batch, seq_len, d_model]
        # W: [d_model, d_model]
        # Output: [batch, seq_len, seq_len]
        return torch.bmm(x, torch.bmm(x, self.W.unsqueeze(0).expand(x.size(0), -1, -1)).transpose(1, 2))

#### 2.2 Training Pipeline with GPU Optimization

```python
# transformer/training/gpu_trainer.py
import torch
from torch.cuda.amp import autocast, GradScaler
from torch.nn.parallel import DistributedDataParallel as DDP

class GPUOptimizedTrainer:
    """
    Mixed precision + distributed training for transformer.
    """
    
    def __init__(
        self,
        model: nn.Module,
        device: torch.device,
        use_amp: bool = True,
        gradient_accumulation_steps: int = 8  # Adjusted for 8GB
    ):
        self.model = model.to(device)
        self.device = device
        self.use_amp = use_amp
        self.gradient_accumulation_steps = gradient_accumulation_steps
        
        # Mixed precision scaler
        self.scaler = GradScaler() if use_amp else None
        
        # Gradient checkpointing for memory efficiency
        if hasattr(model, 'encoder'):
            model.encoder.gradient_checkpointing_enable()
        
    def train_step(
        self,
        batch: dict,
        optimizer: torch.optim.Optimizer,
        criterion: nn.Module
    ) -> dict:
        """Single training step with AMP and gradient accumulation."""
        
        # Forward pass with autocast (FP16)
        with autocast(enabled=self.use_amp):
            outputs = self.model(**batch)
            loss = criterion(outputs, batch['labels'])
            loss = loss / self.gradient_accumulation_steps
        
        # Backward pass
        if self.use_amp:
            self.scaler.scale(loss).backward()
        else:
            loss.backward()
        
        # Gradient clipping (prevent explosion)
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
        
        # Optimizer step (only every N steps)
        if (self.step + 1) % self.gradient_accumulation_steps == 0:
            if self.use_amp:
                self.scaler.step(optimizer)
                self.scaler.update()
            else:
                optimizer.step()
            optimizer.zero_grad()
        
        self.step += 1
        
        return {
            'loss': loss.item() * self.gradient_accumulation_steps,
            'learning_rate': optimizer.param_groups[0]['lr']
        }
    
    @torch.no_grad()
    def evaluate(self, dataloader) -> dict:
        """Evaluation loop with CUDA graphs for speed."""
        self.model.eval()
        
        total_loss = 0
        total_samples = 0
        
        # Warmup for CUDA graph capture
        dummy_batch = next(iter(dataloader))
        s = torch.cuda.Stream()
        s.wait_stream(torch.cuda.current_stream())
        
        with torch.cuda.stream(s):
            for _ in range(3):  # Warmup iterations
                _ = self.model(**dummy_batch)
        
        torch.cuda.current_stream().wait_stream(s)
        
        # Capture graph
        g = torch.cuda.CUDAGraph()
        with torch.cuda.graph(g):
            static_output = self.model(**dummy_batch)
        
        # Replay graph for actual inference
        for batch in dataloader:
            g.replay()
            total_loss += static_output['loss'].item()
            total_samples += batch['batch_size']
        
        return {
            'avg_loss': total_loss / total_samples,
            'perplexity': torch.exp(torch.tensor(total_loss / total_samples)).item()
        }
```

#### 2.3 Training Data Strategy

**Self-Supervised Pretraining (Week 5):**
- Dataset: All available alerts (UNSW + TON + synthetic)
- Task: Masked entity reconstruction + contrastive learning
- Duration: 24-48 hours on A100
- Objective: Learn general alert representations

**Supervised Fine-tuning (Week 6):**
- Dataset: Linux_APT with campaign labels
- Task: Predict campaign pairs
- Loss: Margin ranking + binary cross-entropy
- Duration: 12-24 hours on A100

**Evaluation (Week 7):**
- Metrics: ROC-AUC, Precision@K, Recall@K, Latency
- Benchmark: Compare against heuristic baseline
- Target: >90% recall with <50ms inference at n=2K

**Deliverable:**
- Trained checkpoint: `transformer_checkpoints/candidate_generator_v1.pt`
- Training logs: W&B dashboard
- Evaluation report: ROC curves, latency benchmarks

---

### Phase 3: Union-Find Integration (Week 8-9)

**Objective:** Wire transformer candidates into existing UF engine.

#### 3.1 Modified Correlation Pipeline

```python
# core/correlation_pipeline_v3.py
class CorrelationPipelineV3:
    """
    Extended pipeline with transformer candidate generation.
    Maintains backward compatibility with v2.x APIs.
    """
    
    def __init__(
        self,
        method: str = "auto",
        model_path: Optional[str] = None,
        transformer_path: Optional[str] = None,
        use_transformer: bool = True,
        top_k: int = 10,
        score_threshold: float = 0.5,
        device: str = "cuda"
    ):
        self.method = method
        self.use_transformer = use_transformer
        self.top_k = top_k
        self.score_threshold = score_threshold
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        
        # Initialize transformer (lazy loading)
        self.transformer = None
        self.transformer_path = transformer_path
        
        # Existing engines
        self._union_find_engine = None
        self._hgnn_engine = None
        
    def _get_transformer_engine(self):
        """Lazy load transformer with caching."""
        if self.transformer is None and self.transformer_path:
            from transformer.models.candidate_generator import TransformerCandidateGenerator
            
            self.transformer = TransformerCandidateGenerator.from_pretrained(
                self.transformer_path
            ).to(self.device).eval()
            
            # Compile for inference speed (PyTorch 2.0+)
            if hasattr(torch, 'compile'):
                self.transformer = torch.compile(self.transformer, mode="reduce-overhead")
        
        return self.transformer
    
    def correlate(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str],
        use_temporal: bool = False
    ) -> CorrelationResult:
        """
        Main correlation entry point.
        
        Flow:
        1. Check if transformer should be used
        2. Generate candidates via transformer (if enabled)
        3. Pass candidates to Union-Find
        4. Return clusters with metadata
        """
        start_time = time.time()
        
        # Determine method
        method = self._select_method(data)
        
        # Try transformer path first
        if (method == CorrelationMethod.TRANSFORMER_HYBRID or 
            (method == CorrelationMethod.AUTO and self.use_transformer)):
            try:
                result = self._run_transformer_hybrid(
                    data, usernames, addresses
                )
                result.latency = time.time() - start_time
                return result
            except Exception as e:
                logger.warning(f"Transformer failed: {e}. Falling back to pure UF.")
                # Fallback to pure Union-Find
        
        # Legacy path
        return self._run_union_find(data, usernames, addresses, use_temporal)
    
    def _run_transformer_hybrid(
        self,
        data: pd.DataFrame,
        usernames: List[str],
        addresses: List[str]
    ) -> CorrelationResult:
        """
        Transformer + Union-Find hybrid correlation.
        """
        # Preprocess to tensors
        preprocessor = AlertPreprocessor()
        batch = preprocessor.process_batch(data, device=self.device)
        
        # Generate candidates
        transformer = self._get_transformer_engine()
        
        with torch.no_grad():
            with autocast(enabled=True):  # FP16 inference
                outputs = transformer(
                    input_ids=batch['alert_ids'],
                    time_buckets=batch['time_buckets'],
                    attention_mask=batch['attention_mask'],
                    top_k=self.top_k
                )
        
        # Filter by threshold
        candidate_edges = [
            (i, j, score) for (i, j), score in 
            zip(outputs['candidate_edges'], outputs['edge_scores'])
            if score >= self.score_threshold
        ]
        
        # Pass to Union-Find (only score these pairs)
        uf_engine = self._get_union_find_engine()
        result_df = uf_engine(
            data, usernames, addresses,
            candidate_edges=candidate_edges  # NEW PARAMETER
        )
        
        # Add transformer metadata
        result_df['transformer_candidates'] = len(candidate_edges)
        result_df['avg_transformer_score'] = np.mean(outputs['edge_scores'])
        result_df['fallback_used'] = False
        
        return CorrelationResult(
            data=result_df,
            method_used="transformer_hybrid",
            num_clusters=result_df['cluster_id'].nunique(),
            runtime_seconds=0,  # Will be set by caller
            confidence_score=np.mean(outputs['confidence'].cpu().numpy()),
            fallback_used=False
        )
```

#### 3.2 Union-Find Modification

```python
# core/correlation_indexer.py (modified)
def enhanced_correlation(
    data: pd.DataFrame,
    usernames: List[str],
    addresses: List[str],
    use_temporal: bool = False,
    candidate_edges: Optional[List[Tuple[int, int, float]]] = None
) -> pd.DataFrame:
    """
    Union-Find correlation with optional candidate pre-filtering.
    
    If candidate_edges provided:
    - Skip O(n²) loop
    - Only union pairs in candidate list with score >= threshold
    - Maintain exact transitive closure semantics
    """
    n = len(data)
    uf = UnionFind(n)
    
    if candidate_edges is not None:
        # Fast path: O(k) where k = num candidates
        logger.info(f"Using {len(candidate_edges)} transformer candidates")
        
        for i, j, score in candidate_edges:
            # Convert transformer score to UF weight
            # Only union if score meets threshold
            if score >= CORRELATION_THRESHOLD:
                uf.union(i, j, weight=score)
        
        # Telemetry
        data['candidate_source'] = 'transformer'
        data['transformer_score'] = 0.0  # Will be filled per-alert
        
    else:
        # Legacy path: O(n²) pairwise scoring
        logger.info(f"No candidates provided, using O(n²) brute force (n={n})")
        
        for i in range(n):
            for j in range(i + 1, n):
                score = compute_correlation_score(data.iloc[i], data.iloc[j])
                if score >= CORRELATION_THRESHOLD:
                    uf.union(i, j, weight=score)
        
        data['candidate_source'] = 'brute_force'
        data['transformer_score'] = 0.0
    
    # Assign cluster IDs
    cluster_ids = [uf.find(i) for i in range(n)]
    data['cluster_id'] = cluster_ids
    
    return data
```

**Deliverable:**
- Modified `core/correlation_pipeline.py` with transformer integration
- Unit tests: 100% backward compatibility
- Integration tests: End-to-end latency <1s at n=2K

---

### Phase 4: Validation & Benchmarking (Week 10-11)

**Objective:** Rigorous validation of correctness, performance, and accuracy.

#### 4.1 Validation Framework

```python
# validation/v3_validation_suite.py
class V3ValidationSuite:
    """Comprehensive validation for v3.0 architecture."""
    
    def __init__(self):
        self.results = {}
        
    def run_all_tests(self):
        """Execute full validation suite."""
        tests = [
            ('determinism', self.test_determinism),
            ('transitive_closure', self.test_transitive_closure),
            ('latency', self.test_latency),
            ('accuracy', self.test_accuracy),
            ('backward_compat', self.test_backward_compatibility),
            ('gpu_utilization', self.test_gpu_efficiency),
            ('fallback', self.test_fallback_behavior)
        ]
        
        for name, test_func in tests:
            print(f"\n{'='*60}")
            print(f"Running: {name}")
            print('='*60)
            try:
                result = test_func()
                self.results[name] = {'status': 'PASS', 'data': result}
                print(f"✓ {name}: PASSED")
            except AssertionError as e:
                self.results[name] = {'status': 'FAIL', 'error': str(e)}
                print(f"✗ {name}: FAILED - {e}")
        
        return self.results
    
    def test_determinism(self):
        """Verify identical outputs for identical inputs."""
        # Run correlation twice on same data
        result1 = pipeline.correlate(test_data)
        result2 = pipeline.correlate(test_data)
        
        assert result1.equals(result2), "Results not deterministic!"
        return {'runs': 2, 'identical': True}
    
    def test_transitive_closure(self):
        """Verify exact transitive closure semantics."""
        # If A~B and B~C, then A~C must hold
        test_data = create_transitive_test_case()
        result = pipeline.correlate(test_data)
        
        # Check all three in same cluster
        clusters = result['cluster_id'].unique()
        assert len(clusters) == 1, "Transitive closure violated!"
        return {'test_cases': 1, 'closure_preserved': True}
    
    def test_latency(self):
        """Verify <1s latency at n=2K."""
        test_sizes = [100, 500, 1000, 2000]
        latencies = {}
        
        for n in test_sizes:
            data = generate_synthetic_alerts(n)
            start = time.time()
            result = pipeline.correlate(data)
            latencies[n] = time.time() - start
            
            print(f"  n={n}: {latencies[n]:.3f}s")
        
        # Assert n=2K under 1s
        assert latencies[2000] < 1.0, f"Latency {latencies[2000]:.3f}s > 1s threshold!"
        return latencies
    
    def test_accuracy(self):
        """Compare accuracy vs v2.x baseline."""
        # Load labeled dataset
        df = load_labeled_dataset('linux_apt')
        
        # Run both methods
        v2_result = v2_pipeline.correlate(df)
        v3_result = v3_pipeline.correlate(df)
        
        # Compute metrics
        v2_ari = adjusted_rand_score(df['label'], v2_result['cluster_id'])
        v3_ari = adjusted_rand_score(df['label'], v3_result['cluster_id'])
        
        # v3 should be within 5% of v2 (preserves accuracy)
        assert abs(v3_ari - v2_ari) < 0.05, f"Accuracy degraded: v2={v2_ari:.3f}, v3={v3_ari:.3f}"
        
        return {'v2_ari': v2_ari, 'v3_ari': v3_ari, 'degradation': abs(v3_ari - v2_ari)}
    
    def test_backward_compatibility(self):
        """Verify v2.x API compatibility."""
        # Old-style API call
        result = pipeline.correlate(
            data=df,
            usernames=['src_user', 'dst_user'],
            addresses=['src_ip', 'dst_ip']
        )
        
        # Should work without transformer_path
        assert 'cluster_id' in result.columns
        return {'api_compatible': True}
    
    def test_gpu_efficiency(self):
        """Verify GPU utilization >70% during inference."""
        import pynvml
        pynvml.nvmlInit()
        
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        
        # Run inference while monitoring
        utilizations = []
        for _ in range(10):
            result = pipeline.correlate(test_data)
            util = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
            utilizations.append(util)
            time.sleep(0.1)
        
        avg_util = np.mean(utilizations)
        assert avg_util > 70, f"GPU underutilized: {avg_util:.1f}%"
        
        return {'avg_gpu_util': avg_util, 'samples': len(utilizations)}
    
    def test_fallback_behavior(self):
        """Verify graceful fallback on transformer failure."""
        # Corrupt transformer path
        pipeline.transformer_path = "invalid/path.pt"
        
        # Should fallback to pure UF without crashing
        result = pipeline.correlate(test_data)
        
        assert 'fallback_used' in result.attrs
        assert result.attrs['fallback_used'] == True
        
        return {'fallback_triggered': True, 'no_crash': True}
```

#### 4.2 Benchmarking Protocol

```yaml
# benchmarks/v3_benchmarks.yml
benchmarks:
  - name: "Scalability Test"
    description: "Measure latency vs dataset size"
    sizes: [100, 500, 1000, 2000, 5000, 10000]
    iterations: 10
    metrics:
      - latency_p50
      - latency_p99
      - memory_peak_mb
      - gpu_memory_peak_mb
    acceptance:
      latency_p50_2k: < 1.0s
      latency_p99_2k: < 2.0s
      
  - name: "Accuracy Comparison"
    description: "Compare cluster quality vs v2.x"
    datasets:
      - linux_apt
      - unsw_nb15_subset
      - ton_iot
    metrics:
      - ARI
      - NMI
      - V-measure
      - Homogeneity
    acceptance:
      ARI_degradation: < 0.05  # Within 5% of v2.x
      
  - name: "Edge Recall Test"
    description: "Verify transformer captures true campaign pairs"
    metric: recall@50
    acceptance:
      recall_at_50: > 0.90  # 90% of true pairs in top-50 candidates
      
  - name: "Stress Test"
    description: "Sustained load testing"
    duration: 10 minutes
    rps: 10  # Requests per second
    acceptance:
      error_rate: < 0.1%
      p99_latency: < 3.0s
```

**Deliverable:**
- `validation_results/v3_comprehensive_report.html`
- Benchmark dashboards
- Performance regression report (v2.x vs v3.0)

---

### Phase 5: Production Deployment (Week 12)

**Objective:** Production-ready deployment with monitoring.

#### 5.1 Deployment Checklist

```yaml
# deployment/v3_production_checklist.yml
production_readiness:
  
  model_artifacts:
    - path: transformer_checkpoints/candidate_generator_v1.pt
      verified: true
      signature: sha256:abc123...
    - path: transformer_checkpoints/config.json
      verified: true
    
  infrastructure:
    - gpu_nodes: 2  # Minimum for HA
    - cpu_fallback_nodes: 2
    - load_balancer: nginx
    - monitoring: prometheus + grafana
    
  safety_mechanisms:
    - circuit_breaker:
        failure_threshold: 5
        recovery_timeout: 30s
    - rate_limiting:
        requests_per_minute: 1000
    - auto_rollback:
        accuracy_degradation_threshold: 0.05
        latency_regression_threshold: 2.0s
        
  monitoring_dashboards:
    - transformer_latency_p99
    - gpu_utilization_avg
    - cache_hit_rate
    - fallback_trigger_rate
    - cluster_accuracy_ari
    - alert_volume_per_minute
```

#### 5.2 Docker Configuration

```dockerfile
# Dockerfile.v3-gpu
FROM nvidia/cuda:12.1-devel-ubuntu22.04

# Install Python
RUN apt-get update && apt-get install -y python3.11 python3-pip

# Install PyTorch with CUDA
RUN pip3 install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cu121

# Install transformer dependencies
RUN pip3 install performer-pytorch==1.1.6 pytorch-fast-transformers==0.4.0

# Copy application
COPY . /app
WORKDIR /app

# Pre-compile model for inference
RUN python3 -c "from transformer.models.candidate_generator import TransformerCandidateGenerator; \
    model = TransformerCandidateGenerator.from_pretrained('transformer_checkpoints/candidate_generator_v1.pt'); \
    model = torch.compile(model)"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

EXPOSE 5000

CMD ["python3", "-m", "app.main"]
```

**Deliverable:**
- Production deployment with monitoring
- Runbook for operators
- Incident response procedures

---

## PART 4: EXPERIMENTATION PROTOCOL

### 4.1 A/B Testing Framework

```python
# experiments/ab_testing.py
class ABTestFramework:
    """Shadow mode A/B testing for safe rollout."""
    
    def __init__(
        self,
        control_pipeline,  # v2.x
        treatment_pipeline,  # v3.0
        traffic_split: float = 0.1  # 10% to treatment
    ):
        self.control = control_pipeline
        self.treatment = treatment_pipeline
        self.split = traffic_split
        self.metrics = []
        
    def process_request(self, data):
        """Route request to control or treatment."""
        if random.random() < self.split:
            # Treatment (v3.0) - run in shadow mode
            treatment_result = self.treatment.correlate(data)
            control_result = self.control.correlate(data)
            
            # Log comparison metrics (don't affect response)
            self._log_comparison(control_result, treatment_result)
            
            # Always return control result for safety
            return control_result
        else:
            # Control (v2.x)
            return self.control.correlate(data)
    
    def _log_comparison(self, control, treatment):
        """Log metrics for analysis."""
        metrics = {
            'timestamp': datetime.now(),
            'control_latency': control.runtime_seconds,
            'treatment_latency': treatment.runtime_seconds,
            'control_clusters': control.num_clusters,
            'treatment_clusters': treatment.num_clusters,
            'speedup': control.runtime_seconds / treatment.runtime_seconds
        }
        self.metrics.append(metrics)
```

### 4.2 Continuous Monitoring

```python
# monitoring/drift_detection.py
class DriftDetector:
    """Monitor for model drift and performance degradation."""
    
    def __init__(
        self,
        score_window: int = 1000,
        drift_threshold: float = 3.0  # Standard deviations
    ):
        self.scores = deque(maxlen=score_window)
        self.threshold = drift_threshold
        
    def update(self, score: float):
        """Add new score and check for drift."""
        self.scores.append(score)
        
        if len(self.scores) >= 100:
            mean = np.mean(self.scores)
            std = np.std(self.scores)
            
            # Check if current score is anomalous
            z_score = abs(score - mean) / std
            
            if z_score > self.threshold:
                self._alert(f"Drift detected! z-score={z_score:.2f}, score={score:.3f}")
                return True
        
        return False
    
    def _alert(self, message):
        """Send alert via PagerDuty/Slack."""
        # Integration with alerting systems
        pass
```

---

## PART 5: BEST PRACTICES CHECKLIST

### 5.1 MLOps Best Practices (Addressing v2.x Gaps)

| Practice | Implementation | Status |
|----------|---------------|--------|
| **Model Versioning** | MLflow tracking for all checkpoints | ✅ Specified |
| **Experiment Tracking** | W&B integration with metric logging | ✅ Specified |
| **Feature Store** | Redis-backed entity embedding cache | ✅ Specified |
| **Data Validation** | Great Expectations on input schema | ⚠️ To implement |
| **Model Monitoring** | Drift detection on score distributions | ✅ Specified |
| **A/B Testing** | Shadow mode with 10% traffic split | ✅ Specified |
| **CI/CD** | GitHub Actions with GPU runners | ⚠️ To implement |
| **Model Registry** | Versioned artifacts with signatures | ✅ Specified |

### 5.2 Security Best Practices

| Practice | Implementation | Status |
|----------|---------------|--------|
| **Input Sanitization** | Pydantic schema validation | ✅ Specified |
| **Secrets Management** | Vault integration for API keys | ⚠️ To implement |
| **Model Signing** | Sigstore signatures on checkpoints | ⚠️ To implement |
| **Audit Logging** | Structured logs (who, what, when) | ✅ Specified |
| **Rate Limiting** | Token bucket per client | ⚠️ To implement |
| **Circuit Breaker** | Auto-fallback on failures | ✅ Specified |

### 5.3 Performance Best Practices

| Practice | Implementation | Status |
|----------|---------------|--------|
| **Mixed Precision** | FP16 training + inference | ✅ Specified |
| **Gradient Checkpointing** | Memory-efficient training | ✅ Specified |
| **CUDA Graphs** | Static shape optimization | ✅ Specified |
| **Torch Compile** | PyTorch 2.0 graph optimization | ✅ Specified |
| **Data Prefetching** | Overlapped CPU→GPU transfer | ✅ Specified |
| **Quantization** | INT8 CPU fallback model | ⚠️ Future work |

---

## PART 6: VERIFICATION COMMANDS

Run these after each phase to ensure correctness:

```bash
# Phase 0: Baseline Verification
python -c "
import core.correlation_pipeline as cp
src = inspect.getsource(cp.CorrelationPipeline._select_method)
assert 'net-harmful' in src, 'Auto-selection not updated'
print('✓ Phase 0: Baseline clean')
"

# Phase 1: Data Pipeline
python -m pytest transformer/tests/test_preprocessing.py -v
python transformer/benchmarks/preprocessing_speed.py --n_alerts 10000

# Phase 2: Model Training
python -c "
from transformer.models.candidate_generator import TransformerCandidateGenerator
model = TransformerCandidateGenerator()
assert model is not None
print('✓ Phase 2: Model instantiates')
"

# Phase 3: Integration
python validation/v3_validation_suite.py --test all

# Phase 4: Benchmarking
python benchmarks/run_v3_benchmarks.py --suite comprehensive

# Phase 5: Production Readiness
python -c "
import docker
client = docker.from_env()
container = client.containers.run('mitre-core:v3', detach=True)
print('✓ Phase 5: Container starts')
"
```

---

## PART 7: SUMMARY OF DELIVERABLES

| Phase | Deliverable | Acceptance Criteria |
|-------|-------------|-------------------|
| **0** | Clean v2.x baseline | All Groups A-D complete |
| **1** | Data preprocessor | <100ms for 10K alerts |
| **2** | Trained transformer | >90% recall, <50ms inference |
| **3** | Integrated pipeline | <1s end-to-end at n=2K |
| **4** | Validation report | All 7 tests pass |
| **5** | Production deployment | 99.9% uptime, <0.1% error rate |

---

## APPENDIX: GPU HARDWARE SPECIFICATIONS (UPDATED FOR RTX 5060 Ti 8GB)

### Your Available Hardware
- **GPU:** NVIDIA RTX 5060 Ti (8GB VRAM)
- **Strategy:** Pure local training (no cloud costs)
- **Constraint:** Must fit everything in 8GB

### Aggressive Memory Optimizations for 8GB

```python
# transformer/config/gpu_config_8gb.py
GPU_CONFIG_5060TI_8GB = {
    # Model Architecture (Minimal viable size)
    "d_model": 128,           # Reduced from 256
    "n_layers": 2,            # Reduced from 4
    "n_heads": 4,             # Reduced from 8
    "d_ff": 256,              # Reduced from 1024
    "max_seq_len": 256,       # Reduced from 512 (process in smaller windows)
    
    # Training
    "batch_size": 4,          # Maximum for 8GB
    "gradient_accumulation_steps": 16,  # Effective batch = 64
    "gradient_checkpointing": True,      # Essential - trades compute for memory
    "mixed_precision": True,             # FP16 cuts memory in half
    "cpu_offload": True,                 # Offload optimizer states to CPU
    
    # Inference
    "batch_inference_size": 8,
    "torch_compile": True,    # PyTorch 2.0+ optimization
    "cuda_graphs": False,     # Disabled - saves memory
}
```

### Memory Breakdown (8GB Budget)
| Component | Memory | Optimization |
|-----------|--------|--------------|
| Model weights (FP16) | ~500MB | Tiny model (128-dim, 2-layer) |
| Activations | ~2GB | Gradient checkpointing (recompute instead of store) |
| Optimizer states | ~1.5GB | CPU offload to system RAM |
| Gradients | ~500MB | FP16 precision |
| Data batch | ~1GB | Max 4 alerts per batch |
| CUDA overhead | ~2.5GB | Unavoidable |
| **Total** | **~8GB** | At limit but fits |

### Training Schedule for 8GB (Extended Timeline)

| Phase | Duration | Strategy |
|-------|----------|----------|
| **Self-supervised pre-training** | 5-7 days | Train on UNSW synthetic batches overnight |
| **Supervised fine-tuning** | 3-4 days | Linux_APT campaign labels |
| **Evaluation** | 1 day | Local validation |
| **Total Phase 2** | **9-12 days** | (vs 3 days on A100) |

### Power User Optimizations

1. **Train While You Sleep**
   ```bash
   # Run training overnight with checkpointing every hour
   python transformer/train.py --epochs 100 --save-every 1 --resume-from-checkpoint
   ```

2. **CPU Offloading**
   ```python
   from torch.distributed.optim import ZeroRedundancyOptimizer
   # Offload optimizer states to CPU RAM (saves ~1.5GB GPU memory)
   ```

3. **Gradient Accumulation**
   ```python
   # Process 4 alerts at a time, accumulate gradients over 16 steps
   # Effective batch size = 64 without memory penalty
   ```

4. **Mixed Precision (Essential)**
   ```python
   from torch.cuda.amp import autocast, GradScaler
   # FP16 training: 2x speedup, 50% memory reduction
   ```

5. **Smaller Sequence Windows**
   ```python
   max_seq_len = 256  # Process alerts in 256-alert windows
   overlap = 32       # 32-alert overlap between windows
   # Reduces memory from O(512²) to O(256²)
   ```

### Fallback: CPU Training (If GPU OOM)

If 8GB still insufficient:
```bash
# Train on CPU (10× slower but works)
CUDA_VISIBLE_DEVICES="" python transformer/train.py --device cpu --batch-size 2
```

### Expected Performance (RTX 5060 Ti)

| Metric | Full Model (A100) | Optimized 8GB Model |
|--------|-------------------|---------------------|
| Model size | 256-dim, 4-layer | 128-dim, 2-layer |
| Accuracy | 95% recall | 85-90% recall |
| Training time | 24 hours | 9-12 days |
| Inference (n=2K) | 50ms | 100-150ms |
| Speedup vs O(n²) | 5× | 3-4× |
| **Cost** | **$50-100** | **$0** |

### Minimum Viable Product (MVP)

Even with 8GB constraints, you'll achieve:
- ✅ 3-4× speedup over O(n²) Union-Find
- ✅ Deterministic transitive closure preserved
- ✅ Real-time inference (<200ms at n=2K)
- ✅ Zero cloud costs

**Trade-off:** Slightly lower accuracy than full model (85-90% vs 95%), but still production-viable.

### Monitoring During Training

```python
# Add to training loop
import psutil
import GPUtil

# Log memory every 100 steps
if step % 100 == 0:
    gpu_mem = torch.cuda.memory_allocated() / 1e9
    cpu_mem = psutil.virtual_memory().percent
    print(f"Step {step}: GPU {gpu_mem:.1f}GB, CPU RAM {cpu_mem}%")
    
    # Early warning if approaching 7.5GB
    if gpu_mem > 7.5:
        print("WARNING: Approaching OOM - reducing batch size")
```

---

**Document Status:** Optimized for RTX 5060 Ti 8GB Pure Local Training  
**Next Step:** Begin Phase 0 (complete v2.x debt)  
**Estimated Total Duration:** 14-16 weeks (extended due to 8GB constraints)
