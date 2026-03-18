# MITRE-CORE v3.0 Comprehensive Upgrade Plan

**Version:** 3.0  
**Date:** March 15, 2026  
**Target:** Integration of RL Components + Advanced Transformer Architecture  
**Priority:** Critical - Core Architecture Enhancement  
**Estimated Duration:** 8-10 weeks  

---

## Executive Summary

This upgrade plan transforms MITRE-CORE from a static correlation engine into an adaptive, learning-based attack chain identification system. The integration includes:

1. **Phase 1 (Weeks 1-4):** Core Transformer Architecture Implementation
   - HGT-based heterogeneous graph encoding
   - SlidingWindowAttention (O(n) complexity)
   - Time2Vec temporal encoding
   
2. **Phase 2 (Weeks 5-6):** RL Integration from Anomaly_detection_RL
   - Multi-dimensional anomaly detection
   - Reinforcement learning for attack prediction
   - Real-time adaptive detection
   
3. **Phase 3 (Weeks 7-8):** Analyst Feedback System
   - Feedback processor integration
   - False positive learning
   - Model continuous improvement
   
4. **Phase 4 (Weeks 9-10):** Cleanup, Documentation & Validation
   - Codebase cleanup and deduplication
   - Security vulnerability scanning
   - Documentation updates for future LLMs

---

## Part 1: Pre-Implementation Cleanup

### 1.1 File Deletion Strategy

**Files to DELETE Before Implementation:**

#### Archive Directories
```
experiments/archive/*
  - run_calibration_tsne.py (superseded by new evaluation)
  - run_finetune_modern.py (replaced by new training pipeline)
  - verify_checkpoint.py (integrated into model_manager)
  - verify_score_normalization.py (merged into evaluation module)
  - verify_threshold_fix.py (deprecated)
  - verify_uf_disable.py (no longer relevant)
  - verify_v27_improvements.py (historical)
  - verify_v29_floor_fix.py (historical)

scripts/archive/*
  - update_memory_v5.py (superseded)
  - update_memory_v6.py (superseded)
  - update_memory_v7.py (superseded)
  - All versioned memory updates (keep only latest)

datasets/synthetic_scaling/*
  - synthetic_*.pt files (test artifacts, not production)
  - Keep directory structure but clear contents

archive/ (root level)
  - old_experiments/* (if exists)
  - Any .bak files from previous refactoring
```

#### Cache and Build Artifacts
```
**/__pycache__/* (all Python cache)
**/*.pyc (compiled Python)
**/*.pyo (optimized Python)
.pytest_cache/*
.mypy_cache/*
.coverage
htmlcov/*
dist/*
build/*
*.egg-info/*
```

#### Superseded Documentation
```
docs/reports/FINAL_PHASE1_COMPLETION_REPORT.md (keep latest only)
docs/reports/PHASE1_VERIFICATION_REPORT.md (archive)
docs/misc/prompt_v*.md (keep only latest prompt version)
CODEBASE_REORGANIZATION_REPORT.md (completed, archive)
CYBERTRANSFORMER_BUGFIX_REPORT.md (historical, archive)
```

#### Backup Files
```
core/correlation_pipeline_old.py.bak (already consolidated)
Any .bak, .old, .backup files throughout codebase
```

### 1.2 Pre-Cleanup Verification Checklist

Before deleting, verify:
- [ ] File is not imported by any active code
- [ ] File has no unique functionality (check with grep)
- [ ] File is truly historical (created > 3 months ago)
- [ ] Backup exists in git history

**Script to verify before deletion:**
```bash
# Check if file is imported anywhere
grep -r "from.*filename" --include="*.py" .
grep -r "import.*filename" --include="*.py" .

# Check last modification
git log -1 --format="%ci" filename
```

---

## Part 2: Core Transformer Architecture Implementation

### 2.1 Component Specifications

#### Component A: HGT (Heterogeneous Graph Transformer)
**Purpose:** Encode different node types (alerts, IPs, tactics) with type-specific attention

**Location:** `transformer/models/hgt_encoder.py`

**Architecture:**
```python
class HGTLayer(nn.Module):
    """
    Heterogeneous Graph Transformer Layer
    Based on Hu et al. 2020 (WWW)
    Enhanced with 2024 lightweight optimizations
    """
    def __init__(
        self,
        in_dim: Dict[str, int],      # Input dims per node type
        out_dim: int,                 # Output dimension
        num_heads: int = 8,
        num_edge_types: int = 5,      # temporal, src_ip, dst_ip, host, tactic
        dropout: float = 0.1
    ):
        self.in_dim = in_dim
        self.out_dim = out_dim
        self.num_heads = num_heads
        
        # Type-specific attention weights
        self.edge_type_params = nn.ModuleDict({
            'temporal': EdgeTypeAttention(in_dim, out_dim, num_heads),
            'src_ip': EdgeTypeAttention(in_dim, out_dim, num_heads),
            'dst_ip': EdgeTypeAttention(in_dim, out_dim, num_heads),
            'host': EdgeTypeAttention(in_dim, out_dim, num_heads),
            'tactic': EdgeTypeAttention(in_dim, out_dim, num_heads),
        })
        
    def forward(
        self,
        node_features: Dict[str, torch.Tensor],
        edge_index: Dict[str, torch.Tensor],
        node_types: torch.Tensor
    ) -> Dict[str, torch.Tensor]:
        # Apply type-specific attention per edge type
        # Aggregate messages from all edge types
        # Return updated node representations
```

**Node Types:**
1. `alert` - Security alert nodes (main entities)
2. `ip_address` - Source/destination IP addresses
3. `hostname` - Host/computer names
4. `user_account` - User entities
5. `mitre_tactic` - MITRE ATT&CK tactic nodes
6. `mitre_technique` - MITRE ATT&CK technique nodes

**Edge Types:**
1. `temporal_next` - Alert[i] → Alert[i+1] (time sequence)
2. `src_ip` - Alert → Source IP
3. `dst_ip` - Alert → Destination IP
4. `on_host` - Alert → Hostname
5. `involves_user` - Alert → User
6. `tactic_indicates` - Alert → MITRE Tactic
7. `technique_uses` - Alert → MITRE Technique

**Implementation Details:**
- Use PyTorch Geometric (torch-geometric) for graph operations
- Support batch processing for GPU efficiency
- Memory-optimized for RTX 5060 Ti 8GB:
  - Max batch size: 32 graphs
  - Gradient checkpointing for layers > 4
  - Mixed precision (FP16) training

**Validation Criteria:**
- [ ] Handles heterogeneous graph input
- [ ] Produces type-specific embeddings
- [ ] Memory usage < 6GB for 10K alert graphs
- [ ] Forward pass < 100ms for 1K alerts

---

#### Component B: SlidingWindowAttention
**Purpose:** O(n) attention mechanism for long alert sequences (Longformer-style)

**Location:** `transformer/models/sliding_window_attention.py`

**Architecture:**
```python
class SlidingWindowAttention(nn.Module):
    """
    Sliding Window Attention with Global Tokens
    O(n * window_size) complexity vs O(n²) standard attention
    Validated in 67+ IDS methods (2024 survey)
    """
    def __init__(
        self,
        embed_dim: int = 256,
        num_heads: int = 8,
        window_size: int = 512,       # ±512 alerts
        num_global_tokens: int = 16,  # High-severity, IOC, tactic nodes
        dropout: float = 0.1
    ):
        self.window_size = window_size
        self.num_global_tokens = num_global_tokens
        
    def forward(
        self,
        query: torch.Tensor,          # (batch, seq_len, embed_dim)
        key: torch.Tensor,
        value: torch.Tensor,
        is_global: torch.Tensor,      # (batch, seq_len) boolean mask
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        # 1. Local attention within window
        # 2. Global tokens attend to all
        # 3. All attend to global tokens
        # 4. Combine local + global
```

**Window Configuration:**
- **Window Size:** 512 (attends to ±512 recent alerts)
- **Global Tokens:** 16 per batch
  - Top 4: Highest severity alerts
  - Top 4: IOC-matched alerts
  - Top 4: Alerts from rare MITRE tactics
  - Top 4: Alerts with external threat intel

**Attention Pattern:**
```
For each alert i:
  Attends to: [i-window_size : i+window_size]  (local)
  Attends to: [global tokens]                  (global)
  Attends to: [IOC indicators]                 (indicators)
```

**Complexity Analysis:**
- Standard Attention: O(n²) = 100M ops for 10K alerts
- Sliding Window: O(n × w) = 10M ops for 10K alerts, w=512
- **10x speedup for long sequences**

**Memory Optimization:**
- Use memory-efficient attention (FlashAttention if available)
- Gradient checkpointing every 2 layers
- Mixed precision (FP16/BF16)

**Validation Criteria:**
- [ ] Memory < 4GB for 10K alert sequence
- [ ] Processing time < 500ms for 10K alerts
- [ ] Accuracy within 2% of full attention on test set

---

#### Component C: Time2Vec Temporal Encoding
**Purpose:** Learnable temporal features for APT detection

**Location:** `transformer/models/time2vec.py`

**Architecture:**
```python
class Time2Vec(nn.Module):
    """
    Time2Vec: Learning a Vector Representation of Time
    Kazemi et al. 2019
    Enhanced for cybersecurity with multiple time scales
    """
    def __init__(
        self,
        embed_dim: int = 64,
        num_frequencies: int = 32,
        time_scales: List[str] = ['minute', 'hour', 'day', 'week']
    ):
        # Linear component (trend)
        self.trend_weight = nn.Parameter(torch.randn(1))
        self.trend_bias = nn.Parameter(torch.randn(1))
        
        # Periodic components (seasonality)
        self.freq_weights = nn.Parameter(
            torch.randn(num_frequencies, len(time_scales))
        )
        self.phase_shifts = nn.Parameter(
            torch.randn(num_frequencies, len(time_scales))
        )
        
    def forward(self, timestamps: torch.Tensor) -> torch.Tensor:
        """
        Args:
            timestamps: Unix timestamps (seconds since epoch)
        Returns:
            Time embeddings: (batch, seq_len, embed_dim)
        """
        # Normalize timestamps to different scales
        # Calculate linear trend component
        # Calculate periodic components (sinusoidal)
        # Concatenate and project to embed_dim
```

**Time Scales for Cybersecurity:**
1. **Minute-level:** Immediate attack bursts, DDoS patterns
2. **Hour-level:** Business hours vs off-hours attacks
3. **Day-level:** Weekday vs weekend attack patterns
4. **Week-level:** Long-term APT campaigns, dormant periods

**Implementation Details:**
- Pre-normalize timestamps (zero-mean, unit variance)
- Multiple frequency components per scale
- Learnable frequency weights (not fixed)

**Validation Criteria:**
- [ ] Captures daily patterns (business hours)
- [ ] Captures weekly patterns (weekend attacks)
- [ ] Captures long-term trends (APT duration)
- [ ] Embedding dimension ≤ 64 for efficiency

---

#### Component D: Lightweight Temporal-Spatial Fusion
**Purpose:** Combine temporal sequence + spatial graph features (2024 innovation)

**Location:** `transformer/models/temporal_spatial_fusion.py`

**Architecture:**
```python
class TemporalSpatialFusion(nn.Module):
    """
    Lightweight Temporal-Spatial Transformer
    Based on 2024 drone network IDS research
    15x faster than standard Transformer
    """
    def __init__(
        self,
        temporal_dim: int = 256,
        spatial_dim: int = 256,
        fusion_dim: int = 256,
        num_temporal_layers: int = 4,
        num_spatial_layers: int = 2
    ):
        # Temporal branch: SlidingWindowAttention
        self.temporal_encoder = nn.ModuleList([
            TemporalEncoderLayer(temporal_dim)
            for _ in range(num_temporal_layers)
        ])
        
        # Spatial branch: HGT
        self.spatial_encoder = HGTLayer(
            in_dim={'alert': temporal_dim, ...},
            out_dim=spatial_dim
        )
        
        # Fusion layer
        self.fusion = CrossAttentionFusion(temporal_dim, spatial_dim, fusion_dim)
        
    def forward(
        self,
        temporal_sequence: torch.Tensor,  # Alert sequence
        graph_structure: Data,             # PyG Data object
        timestamps: torch.Tensor
    ) -> torch.Tensor:
        # Encode temporal sequence
        # Encode spatial graph
        # Cross-attention fusion
        # Return unified representation
```

**Fusion Strategy:**
- Temporal features inform spatial attention (when to look)
- Spatial features inform temporal attention (where to look)
- Cross-attention mechanism between branches

**Validation Criteria:**
- [ ] 10-15x faster than separate encoding
- [ ] Accuracy maintained vs full model
- [ ] Memory efficient for RTX 5060 Ti

---

### 2.2 Implementation Sequence

#### Week 1: Foundation
**Day 1-2: Setup & Infrastructure**
- [ ] Create new transformer module structure:
  ```
  transformer/
    models/
      hgt_encoder.py
      sliding_window_attention.py
      time2vec.py
      temporal_spatial_fusion.py
      __init__.py (update exports)
    training/
      train_transformer.py (new)
      transformer_trainer.py (new)
    utils/
      graph_builder.py (convert alerts to graph)
      temporal_utils.py (timestamp processing)
  ```
- [ ] Add dependencies to requirements.txt:
  ```
  torch-geometric>=2.3.0
  torch-scatter>=2.1.0
  torch-sparse>=0.6.0
  pytorch-lightning>=2.0.0 (optional, for training)
  ```
- [ ] Create unit test framework for new components

**Day 3-4: Time2Vec Implementation**
- [ ] Implement Time2Vec module
- [ ] Unit tests for temporal encoding
- [ ] Visual validation of time patterns

**Day 5-7: SlidingWindowAttention**
- [ ] Implement sliding window mechanism
- [ ] Implement global token selection
- [ ] Memory optimization
- [ ] Benchmark vs standard attention

#### Week 2: Graph Components
**Day 8-10: HGT Encoder**
- [ ] Implement HGT layer
- [ ] Implement edge type attention
- [ ] Node type embedding dictionaries
- [ ] Forward pass testing

**Day 11-12: Graph Builder Utility**
- [ ] Convert alert DataFrame to PyG Data
- [ ] Build heterogeneous edges
- [ ] Handle MITRE tactic nodes

**Day 13-14: Temporal-Spatial Fusion**
- [ ] Implement dual-branch architecture
- [ ] Cross-attention fusion
- [ ] Integration testing

#### Week 3: Integration & Training
**Day 15-17: Full Model Assembly**
- [ ] Combine all components
- [ ] Create end-to-end forward pass
- [ ] Loss function design (multi-task)

**Day 18-19: Training Pipeline**
- [ ] Data loader for graph sequences
- [ ] Training loop with gradient clipping
- [ ] Checkpointing and model saving

**Day 20-21: Validation**
- [ ] Unit tests for all components
- [ ] Integration tests
- [ ] Performance benchmarks

#### Week 4: Pipeline Integration
**Day 22-24: CorrelationPipeline Integration**
- [ ] Add transformer as Tier 1
- [ ] Configuration switches (old/new)
- [ ] Fallback mechanisms

**Day 25-26: Testing**
- [ ] End-to-end testing with real data
- [ ] Performance profiling
- [ ] Memory profiling

**Day 27-28: Documentation**
- [ ] Component documentation
- [ ] API documentation
- [ ] Usage examples

---

## Part 3: RL Integration from Anomaly_detection_RL

### 3.1 Components to Adapt

#### Component A: Multi-Dimensional Anomaly Detector
**Source:** `E:\Private\Anomaly_detection_RL\Final codes\src\anomaly_detector.py`

**Purpose:** Detect anomalies across time, source IP, destination host, and user dimensions

**Adaptation Strategy:**
```python
# New location: core/rl_anomaly_detector.py

class RLAnomalyDetector:
    """
    Multi-dimensional anomaly detection for attack chain identification.
    Adapted from Anomaly_detection_RL for MITRE-CORE.
    """
    def __init__(
        self,
        baseline_models: Dict[str, Any],  # Per-dimension baselines
        thresholds: Dict[str, List[float]],
        use_isolation_forest: bool = True
    ):
        self.dimensions = ['time', 'source_ip', 'dest_host', 'user']
        self.baseline = baseline_models
        self.thresholds = thresholds
        
    def detect(
        self,
        current_data: pd.DataFrame,
        dimension: str = 'all'
    ) -> AnomalyReport:
        """
        Detect anomalies across specified dimensions.
        
        Returns anomaly scores and flagged entities.
        """
        
    def detect_attack_chains(
        self,
        alerts: pd.DataFrame,
        time_window: timedelta = timedelta(hours=1)
    ) -> List[AttackChain]:
        """
        Identify potential attack chains through correlated anomalies.
        
        Returns list of AttackChain objects with:
        - Chain ID
        - Alerts in chain
        - Confidence score
        - Predicted next steps (from RL agent)
        """
```

**Integration Points:**
- Connect to `CorrelationPipeline` as pre-filtering stage
- Feed anomalies to RL agent for attack prediction
- Output attack chains to HGNN for correlation refinement

**Validation Criteria:**
- [ ] Detects time-based anomalies (unusual login times)
- [ ] Detects source IP anomalies (new locations)
- [ ] Detects destination anomalies (lateral movement)
- [ ] Correlates across dimensions for chain detection

---

#### Component B: RL Agent for Attack Prediction
**Source:** `E:\Private\Anomaly_detection_RL\Final codes\src\rl_agent.py`

**Purpose:** Predict next attack steps using Reinforcement Learning

**Adaptation Strategy:**
```python
# New location: core/rl_attack_predictor.py

class AttackChainPredictor:
    """
    RL-based attack chain prediction.
    Predicts next MITRE tactic/technique given current chain.
    """
    def __init__(
        self,
        state_dim: int = 512,      # Alert sequence embedding
        action_dim: int = 14,       # 14 MITRE tactics (or techniques)
        hidden_dim: int = 256,
        gamma: float = 0.99,        # Discount factor
        lr: float = 3e-4
    ):
        # Policy network: state → action probabilities
        self.policy = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim),
            nn.Softmax(dim=-1)
        )
        
        # Value network: state → expected return
        self.value = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1)
        )
        
    def predict_next_tactic(
        self,
        current_chain: List[Alert],
        available_tactics: List[str]
    ) -> Tuple[str, float]:
        """
        Predict most likely next MITRE tactic.
        
        Returns:
            tactic: Predicted MITRE tactic
            confidence: Probability score
        """
        
    def get_action_recommendation(
        self,
        state: AttackState
    ) -> DefenderAction:
        """
        Recommend defender action based on predicted attack path.
        """
```

**State Representation:**
```python
@dataclass
class AttackState:
    """Current attack chain state for RL agent."""
    recent_alerts: List[Alert]           # Last N alerts
    alert_embeddings: torch.Tensor       # Transformer-encoded
    tactics_seen: Set[str]              # MITRE tactics in chain
    techniques_seen: Set[str]           # MITRE techniques
    temporal_features: torch.Tensor    # Time2Vec encoding
    confidence_score: float              # Chain confidence
    time_since_start: float              # Campaign duration
```

**Action Space:**
- Predict next MITRE tactic (14 possibilities)
- Or predict specific technique (100+ possibilities)
- Multi-task: predict both tactic + technique

**Reward Function:**
```python
def calculate_reward(
    predicted_tactic: str,
    actual_tactic: str,
    time_delta: float
) -> float:
    """
    Reward based on prediction accuracy and timeliness.
    
    +10: Correct prediction with >1 hour advance notice
    +5:  Correct prediction with <1 hour notice
    +2:  Correct tactic family
    -5:  Wrong prediction
    -10: Missed critical tactic (e.g., Exfiltration)
    """
```

**Integration Points:**
- Receives attack chains from AnomalyDetector
- Outputs predictions to AlertEnricher
- Updates from analyst feedback (reward signal)

**Validation Criteria:**
- [ ] Predicts next tactic with >70% accuracy
- [ ] Provides >30 min advance warning
- [ ] Adapts to new attack patterns
- [ ] Low false positive rate (<10%)

---

#### Component C: Feedback Processor
**Source:** `E:\Private\Anomaly_detection_RL\Final codes\src\feedback_processor.py`

**Purpose:** Process analyst feedback for continuous learning

**Adaptation Strategy:**
```python
# New location: core/analyst_feedback_processor.py

class AnalystFeedbackProcessor:
    """
    Process analyst feedback for continuous model improvement.
    Bridges human expertise with automated detection.
    """
    def __init__(
        self,
        feedback_buffer_size: int = 10000,
        learning_rate: float = 0.001,
        update_frequency: str = 'daily'
    ):
        self.feedback_buffer = deque(maxlen=feedback_buffer_size)
        self.pending_feedback = []
        
    def record_feedback(
        self,
        alert_id: str,
        feedback_type: FeedbackType,  # TRUE_POSITIVE, FALSE_POSITIVE, etc.
        analyst_notes: Optional[str] = None,
        corrected_labels: Optional[Dict] = None
    ) -> None:
        """
        Record analyst feedback on alert/correlation.
        """
        
    def process_feedback_batch(
        self,
        model: nn.Module
    ) -> TrainingMetrics:
        """
        Process accumulated feedback and update model.
        
        Returns training metrics from feedback-driven update.
        """
        
    def generate_feedback_report(
        self,
        time_range: Tuple[datetime, datetime]
    ) -> FeedbackReport:
        """
        Generate report on feedback patterns.
        
        Shows:
        - False positive trends
        - Model blind spots
        - Emerging attack patterns
        """
```

**Feedback Types:**
```python
class FeedbackType(Enum):
    TRUE_POSITIVE = "tp"           # Correct detection
    FALSE_POSITIVE = "fp"          # Incorrect detection
    FALSE_NEGATIVE = "fn"          # Missed detection
    SEVERITY_ADJUSTMENT = "sev"    # Severity should be different
    TACTIC_CORRECTION = "tac"      # Wrong MITRE tactic
    NEW_PATTERN = "new"            # New attack pattern
    IGNORE = "ignore"              # Noise, ignore future similar
```

**Integration Points:**
- Frontend: Analyst clicks on alert to provide feedback
- Backend: Feedback stored in database
- Training: Weekly model updates from feedback
- RL: Feedback as reward signal for RL agent

**Validation Criteria:**
- [ ] Captures all feedback types
- [ ] Processes within 24 hours
- [ ] Reduces FPs by 20% per month
- [ ] Tracks analyst time savings

---

#### Component D: Model Manager
**Source:** `E:\Private\Anomaly_detection_RL\Final codes\src\model_manager.py`

**Purpose:** Version control and A/B testing for models

**Adaptation Strategy:**
```python
# New location: utils/model_manager.py (extends existing)

class ModelManager:
    """
    Manage model versions, A/B testing, and rollback.
    """
    def __init__(
        self,
        model_registry_path: str = "models/registry",
        max_versions: int = 10
    ):
        self.registry = ModelRegistry(model_registry_path)
        
    def save_version(
        self,
        model: nn.Module,
        metadata: ModelMetadata
    ) -> str:
        """Save new model version with metadata."""
        
    def load_version(
        self,
        version_id: str
    ) -> nn.Module:
        """Load specific model version."""
        
    def deploy_model(
        self,
        version_id: str,
        traffic_percentage: float = 100.0
    ):
        """
        Deploy model with optional A/B testing.
        
        traffic_percentage: % of traffic to route to this model
        """
        
    def compare_versions(
        self,
        version_a: str,
        version_b: str,
        metrics: List[str]
    ) -> ComparisonReport:
        """Compare two model versions on specified metrics."""
```

---

### 3.2 RL Integration Sequence

#### Week 5: Anomaly Detector Integration
**Day 29-30: Port & Adapt**
- [ ] Copy anomaly_detector.py to core/
- [ ] Adapt imports and dependencies
- [ ] Integrate with existing alert schema

**Day 31-33: Testing & Validation**
- [ ] Unit tests for each dimension
- [ ] Integration tests with pipeline
- [ ] Performance benchmarks

**Day 34-35: Attack Chain Detection**
- [ ] Implement chain correlation logic
- [ ] Temporal window handling
- [ ] Confidence scoring

#### Week 6: RL Agent Integration
**Day 36-38: RL Agent Setup**
- [ ] Port rl_agent.py to core/
- [ ] Define action space (MITRE tactics)
- [ ] Implement reward function

**Day 39-40: State Representation**
- [ ] Create AttackState encoder
- [ ] Connect to Transformer outputs
- [ ] Temporal feature integration

**Day 41-42: Training Pipeline**
- [ ] Historical attack sequences
- [ ] Offline RL training
- [ ] Validation on held-out campaigns

---

## Part 4: Analyst Feedback System

### 4.1 Feedback Processor Integration

#### Week 7: Core Feedback System
**Day 43-44: Feedback Capture**
- [ ] Database schema for feedback
- [ ] API endpoints for feedback submission
- [ ] Frontend feedback UI

**Day 45-46: Feedback Processing**
- [ ] Batch processing pipeline
- [ ] Model update triggers
- [ ] Version control integration

**Day 47-48: RL Reward Integration**
- [ ] Convert feedback to rewards
- [ ] Update RL agent policy
- [ ] Reward normalization

**Day 49: Reporting**
- [ ] Feedback analytics dashboard
- [ ] Model improvement tracking
- [ ] Analyst time savings metrics

#### Week 8: Advanced Features
**Day 50-51: Active Learning**
- [ ] Uncertainty sampling
- [ ] Informative alert selection
- [ ] Batch labeling optimization

**Day 52-53: Explainability**
- [ ] Why was this alert flagged?
- [ ] Which features contributed?
- [ ] Visual attention maps

**Day 54-55: Feedback Quality**
- [ ] Analyst agreement metrics
- [ ] Feedback validation
- [ ] Consensus mechanisms

**Day 56: Documentation**
- [ ] Feedback system docs
- [ ] API documentation
- [ ] User guide for analysts

---

## Part 5: Cleanup, Documentation & Validation

### 5.1 Post-Implementation Cleanup

#### Week 9: Codebase Cleanup
**Day 57-58: Deduplication**
- [ ] Run duplication scanner
- [ ] Consolidate duplicate functions:
  - find/union (use utils/union_find.py)
  - correlate (use unified correlation)
  - edge building (use graph_builder.py)
- [ ] Remove old implementations

**Day 59-60: Structure Cleanup**
- [ ] Verify __init__.py files in all modules
- [ ] Clean up import statements
- [ ] Organize imports (stdlib, third-party, local)

**Day 61-62: Dead Code Removal**
- [ ] Identify unused functions
- [ ] Remove orphaned code
- [ ] Clean up old experiments

#### Week 10: Security & Documentation
**Day 63-64: Security Scan**
- [ ] Run security scanner
- [ ] Fix any vulnerabilities found
- [ ] Penetration testing for APIs

**Day 65-66: MEMORY.md Update**
- [ ] Document new architecture
- [ ] Clear old/obsolete entries
- [ ] Add implementation details
- [ ] Update version history

**Day 67-68: README.md Update**
- [ ] New LLM-friendly structure
- [ ] Clear architecture description
- [ ] Quick start guide
- [ ] API documentation links

**Day 69-70: Final Validation**
- [ ] End-to-end testing
- [ ] Performance benchmarks
- [ ] Documentation review
- [ ] Release readiness check

---

## Part 6: Quality Assurance & Best Practices

### 6.1 Code Quality Standards

#### Testing Requirements
```python
# Minimum test coverage: 80%
# Critical paths: 95%

# Unit tests for every component
pytest tests/unit/transformer/
pytest tests/unit/rl/
pytest tests/unit/feedback/

# Integration tests
pytest tests/integration/

# End-to-end tests
pytest tests/e2e/
```

#### Code Style
- **Formatter:** Black (line length 100)
- **Linter:** Ruff (fast Rust-based)
- **Type Checker:** mypy (strict mode)
- **Import Sorting:** isort

#### Documentation Standards
- **Docstrings:** Google style
- **Type Hints:** All public functions
- **Comments:** Why, not what
- **README:** Every module has README.md

### 6.2 Performance Benchmarks

#### Target Metrics
```yaml
# Transformer Performance
alert_encoding_time: < 50ms per 1K alerts
gpu_memory_usage: < 6GB for 10K alerts
cpu_fallback: < 200ms per 1K alerts

# RL Performance
prediction_latency: < 10ms per prediction
throughput: > 1000 predictions/sec
model_size: < 100MB

# End-to-End
total_pipeline_time: < 2s per 1K alerts
memory_footprint: < 8GB total
```

### 6.3 Security Checklist

- [ ] No hardcoded credentials
- [ ] Input validation on all APIs
- [ ] SQL injection prevention
- [ ] XSS prevention in web UI
- [ ] Rate limiting on endpoints
- [ ] Audit logging for all actions
- [ ] Data encryption at rest
- [ ] Secure model serialization

---

## Part 7: Documentation for Future LLMs

### 7.1 MEMORY.md Structure

```markdown
# MITRE-CORE Memory v3.0

## Current Architecture (2026-03)
- **Version:** 3.0
- **Key Innovation:** RL-based attack chain prediction
- **Transformer:** HGT + SlidingWindow + Time2Vec
- **RL Agent:** Attack step prediction with 70%+ accuracy
- **Feedback Loop:** Continuous learning from analysts

## Quick Reference for New LLMs
1. **Core Pipeline:** Tier 1 (Transformer) → Tier 2 (HGNN) → Tier 3 (Union-Find)
2. **New RL Tier:** Tier 0 (RL Attack Prediction)
3. **Main Entry:** app/main.py
4. **Key Config:** transformer/config/gpu_config_8gb.py
5. **RL Models:** core/rl_*.py

## Implementation Details
[Comprehensive architecture docs]

## Common Tasks
- Add new dataset: training/modern_loader.py
- Add new MITRE tactic: utils/mitre_complete.py
- Tune RL agent: core/rl_attack_predictor.py
- Process feedback: core/analyst_feedback_processor.py
```

### 7.2 README.md Structure

```markdown
# MITRE-CORE v3.0

## What is MITRE-CORE?
AI-powered attack chain identification using:
- **Transformers** for alert encoding (HGT, SlidingWindow)
- **RL Agents** for attack prediction
- **HGNN** for graph correlation
- **Analyst Feedback** for continuous learning

## Architecture (3-Tier + RL)
```
┌─────────────────────────────────────┐
│  Tier 0: RL Attack Predictor        │
│  Predicts next attack steps         │
├─────────────────────────────────────┤
│  Tier 1: Transformer                │
│  HGT + SlidingWindow + Time2Vec   │
├─────────────────────────────────────┤
│  Tier 2: HGNN                      │
│  Graph correlation                 │
├─────────────────────────────────────┤
│  Tier 3: Union-Find                │
│  Structural clustering             │
└─────────────────────────────────────┘
```

## Quick Start
[Step-by-step setup]

## For Developers
[API docs, contribution guide]
```

---

## Appendix A: File Deletion Checklist

### Pre-Upgrade Cleanup
- [ ] experiments/archive/* (8 files)
- [ ] scripts/archive/* (7 files)
- [ ] datasets/synthetic_scaling/*.pt
- [ ] docs/reports/PHASE1_*.md
- [ ] **pycache** directories (20+ locations)
- [ ] *.pyc files
- [ ] .bak files
- [ ] correlation_pipeline_old.py.bak

### Post-Upgrade Cleanup
- [ ] Remove old Union-Find implementations
- [ ] Remove old correlation functions
- [ ] Consolidate duplicate graph building
- [ ] Clean up temporary training scripts

---

## Appendix B: Dependency Updates

### requirements.txt Additions
```
# Core ML
torch-geometric>=2.3.0
torch-scatter>=2.1.0
torch-sparse>=0.6.0
pytorch-lightning>=2.0.0

# RL
stable-baselines3>=2.0.0
gymnasium>=0.28.0

# Graph processing
networkx>=3.0
python-igraph>=0.10.0

# Enhanced utilities
ray>=2.5.0  # Distributed RL
optuna>=3.0  # Hyperparameter tuning
```

---

## Appendix C: Migration Guide

### From v2.x to v3.0

1. **Backup existing models**
   ```bash
   cp -r models/ models_backup_v2/
   ```

2. **Update configuration**
   - Add new transformer config
   - Add RL config section

3. **Database migration**
   - Add feedback table
   - Add RL predictions table

4. **Model retraining**
   - Transformer: Train on existing data
   - RL: Train on historical campaigns

5. **Gradual rollout**
   - A/B test: 10% → 50% → 100%
   - Monitor performance metrics

---

## Success Metrics

### Technical Metrics
- [ ] Transformer processes 10K alerts in < 500ms
- [ ] RL prediction accuracy > 70%
- [ ] False positive rate < 10%
- [ ] Memory usage < 8GB

### Business Metrics
- [ ] Analyst time saved: 30%
- [ ] Attack detection speed: 2x faster
- [ ] New attack pattern adaptation: < 1 week
- [ ] System uptime: > 99.9%

---

**End of Upgrade Plan**

**Next Steps:**
1. Approve plan
2. Begin Week 1 implementation
3. Weekly progress reviews
4. Post-implementation validation
