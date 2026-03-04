# MITRE-CORE Data Flow Architecture

## Overview

This document describes the complete data flow through the MITRE-CORE correlation pipeline, including both the traditional Union-Find approach and the new HGNN deep learning approach.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MITRE-CORE PIPELINE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │ Data Sources │───▶│ Preprocessing│───▶│ Correlation  │───▶│ Post-    │ │
│  │              │    │              │    │ Engine       │    │ Processing│ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────┘ │
│         │                   │                   │                  │        │
│         ▼                   ▼                   ▼                  ▼        │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │ SIEM/CSV/API │    │ Feature Eng. │    │ Union-Find   │    │ Feature  │ │
│  │ Datasets     │    │ Normalization│    │ HGNN         │    │ Chains   │ │
│  │              │    │              │    │ Hybrid       │    │ Output   │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Detailed Data Flow

### Stage 1: Data Ingestion

**Input:** Raw security alerts from SIEMs, CSV files, or APIs

**Sources:**
- Splunk
- ELK Stack (Elasticsearch, Logstash, Kibana)
- QRadar
- CSV files
- API endpoints

**Standard Columns:**
```python
STANDARD_COLUMNS = [
    'timestamp',      # Event timestamp
    'src_ip',         # Source IP address
    'dst_ip',         # Destination IP address
    'hostname',       # Host/device name
    'username',       # User identifier
    'alert_type',     # Type of alert/event
    'tactic',         # MITRE ATT&CK tactic
    'campaign_id'     # Ground truth campaign (if available)
]
```

### Stage 2: Preprocessing

**File:** `preprocessing.py`

**Operations:**
1. **Data Cleaning**
   - Handle missing values
   - Remove duplicates
   - Normalize timestamps

2. **Feature Engineering**
   - Extract temporal features (hour, day_of_week)
   - Encode categorical variables (protocol, service)
   - Create derived features (alert embeddings)

3. **Standardization**
   - Map column names to standard format
   - Normalize IP addresses
   - Standardize usernames

**Data Transformation:**
```
Raw Alert (raw)
    ↓
[Parse timestamp] → datetime object
    ↓
[Extract features] → 8-dimensional feature vector
    ↓
[Normalize] → Standardized alert
```

### Stage 3: Correlation Engine

**File:** `correlation_pipeline.py` (unified interface)

**Three Methods Available:**

#### Method A: Union-Find (Baseline)

**File:** `correlation_indexer.py`

**Algorithm:**
```python
# 1. Build similarity graph
for each alert pair (i, j):
    score = weighted_correlation_score(
        ip_match=0.6,
        user_match=0.3,
        temporal=0.1
    )
    if score > threshold:
        graph.add_edge(i, j)

# 2. Union-Find clustering
parent = list(range(n))
for edge in graph.edges:
    union(edge.source, edge.target)

# 3. Extract clusters
clusters = defaultdict(list)
for node in range(n):
    root = find(node)
    clusters[root].append(node)
```

**Complexity:** O(n α(n)) - nearly linear

**Best For:** Small datasets (<100 events), real-time processing

#### Method B: HGNN (Deep Learning)

**File:** `hgnn_correlation.py`

**Architecture:**
```
Alert Features (8-dim)
    ↓
Alert Encoder (Linear 8→64)
    ↓
Heterogeneous GAT Layer 1
  ├─► alert → user edges (multi-head attention)
  ├─► user → alert edges (multi-head attention)
  ├─► alert → host edges (multi-head attention)
  ├─► host → alert edges (multi-head attention)
  ├─► alert → alert edges (temporal, shared IP)
  └─► alert → ip edges (involvement)
    ↓
Heterogeneous GAT Layer 2 (optional)
    ↓
Global Pooling (mean over alerts)
    ↓
Cluster Classifier (MLP 64→num_clusters)
    ↓
Softmax → Cluster Probabilities
```

**Forward Pass:**
```python
def forward(self, data: HeteroData) -> Tuple[Tensor, Tensor]:
    # Encode node features
    x_dict = {
        'alert': self.alert_encoder(data['alert'].x),
        'user': self.user_encoder(data['user'].x),
        'host': self.host_encoder(data['host'].x),
        'ip': self.ip_encoder(data['ip'].x)
    }
    
    # Message passing through GAT layers
    for conv in self.convs:
        x_dict = conv(x_dict, data.edge_index_dict)
        x_dict = {key: F.elu(x) for key, x in x_dict.items()}
    
    # Global pooling and classification
    alert_emb = x_dict['alert'].mean(dim=0)  # Pool all alerts
    cluster_logits = self.classifier(alert_emb)
    
    return cluster_logits, x_dict
```

**Complexity:** O(n + e) per layer

**Best For:** Large datasets (>1000 events), high accuracy needed

#### Method C: Hybrid (Ensemble)

**File:** `hgnn_integration.py`

**Approach:**
1. Run Union-Find (fast initial clustering)
2. Run HGNN on each cluster (refined correlation)
3. Combine predictions:
   ```
   final_cluster = argmax(
       0.7 * hgnn_scores + 0.3 * union_find_scores
   )
   ```

**Best For:** Medium datasets (100-1000 events), best accuracy/speed tradeoff

### Stage 4: Graph Construction (HGNN only)

**File:** `hgnn/correlation.py` - `AlertToGraphConverter`

**Graph Schema:**
```
Node Types:
  - alert: Security event (64-dim features)
  - user: Username entities (32-dim features)
  - host: Hostname entities (32-dim features)
  - ip: IP addresses (32-dim features)

Edge Types:
  - (alert, owned_by, user)
  - (user, owns, alert)
  - (alert, generated_by, host)
  - (host, generates, alert)
  - (alert, involves, ip)
  - (ip, involved_in, alert)
  - (alert, shares_ip, alert)      # Same IP
  - (alert, temporal_near, alert)  # Time proximity
```

**Example Graph:**
```
    ┌─────────────────────────────────────────┐
    │           Heterogeneous Graph          │
    │                                         │
    │    ┌─────┐         ┌─────┐            │
    │    │user1│◄────────│alert│────────►┌─┐│
    │    └──┬──┘  owns   │  1  │  involves│ ││
    │       │            └──┬──┘          │ ││
    │       │               │             └─┘│
    │       │               │             ip1│
    │  ┌────▼───┐          │                │
    │  │ alert  │◄─────────┘                │
    │  │   2    │ temporal_near             │
    │  └────────┘                           │
    │       │                               │
    │       │ generated_by                  │
    │       ▼                               │
    │    ┌─────┐                            │
    │    │host1│                            │
    │    └─────┘                            │
    │                                         │
    └─────────────────────────────────────────┘
```

### Stage 5: Post-Processing

**File:** `postprocessing.py`

**Operations:**
1. **Cluster Cleaning**
   - Remove singletons (noise)
   - Merge small clusters
   - Split oversized clusters

2. **Feature Chain Extraction**
   ```python
   # Build attack progression graph
   for cluster in clusters:
       sorted_alerts = sort_by_timestamp(cluster)
       chain = extract_tactic_chain(sorted_alerts)
       # e.g., ["Reconnaissance", "Initial Access", "Execution"]
   ```

3. **MITRE ATT&CK Mapping**
   - Map clusters to MITRE tactics
   - Calculate tactic coverage
   - Identify attack stages

### Stage 6: Output Generation

**File:** `output.py`

**Output Format:**
```json
{
  "clusters": [
    {
      "cluster_id": 1,
      "alerts": ["alert_001", "alert_002", "alert_003"],
      "tactics": ["Reconnaissance", "Initial Access"],
      "confidence": 0.87,
      "method": "HGNN",
      "feature_chain": [
        {"stage": "Reconnaissance", "count": 5},
        {"stage": "Initial Access", "count": 3}
      ],
      "severity": "high"
    }
  ],
  "summary": {
    "total_alerts": 1000,
    "total_clusters": 15,
    "correlation_method": "HGNN",
    "runtime_seconds": 2.5
  }
}
```

## Training Pipeline (HGNN)

### Phase 1: Contrastive Pre-training

**Objective:** Learn good representations without labels

**InfoNCE Loss:**
```
L = -log[ exp(sim(z_i, z_j) / τ) / Σ_k exp(sim(z_i, z_k) / τ) ]

where:
- z_i, z_j: Two augmented views of same graph
- z_k: Negative samples (other graphs)
- τ: Temperature parameter
- sim: Cosine similarity
```

**Data Augmentation:**
- Feature dropout (p=0.058)
- Gaussian noise (σ=0.00054)
- Edge dropout (p=0.05)

**Training Stats:**
- Epochs: 50
- Initial loss: 3.30
- Final loss: 2.30

### Phase 2: Supervised Fine-tuning

**Objective:** Predict campaign labels

**Loss:** Cross-Entropy
```
L = -Σ_c y_c * log(p_c)

where:
- y_c: One-hot true label
- p_c: Predicted probability
```

**Training Stats:**
- Epochs: 50
- Initial accuracy: 55%
- Final accuracy: 86.4%
- Test accuracy: 86.45%

## Data Flow Diagram (Complete)

```
                    ┌─────────────────────────────────────────┐
                    │         INPUT: Raw Security Alerts      │
                    └──────────────────┬──────────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────────┐
                    │      STAGE 1: Data Ingestion              │
                    │  ┌─────────┐  ┌─────────┐  ┌─────────┐  │
                    │  │  SIEM   │  │   CSV   │  │   API   │  │
                    │  │Connectors│  │ Upload │  │ Endpoint│  │
                    │  └────┬────┘  └────┬────┘  └────┬────┘  │
                    └───────┼────────────┼────────────┼────────┘
                            └────────────┴────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │     STAGE 2: Preprocessing              │
                    │                                         │
                    │  ┌─────────────┐  ┌─────────────────┐  │
                    │  │Data Cleaning│─▶│Feature Engineering│ │
                    │  └─────────────┘  └─────────────────┘  │
                    │           │                    │      │
                    │           ▼                    ▼      │
                    │      [Missing]           [Extract]    │
                    │      [Duplicates]    [temporal features]│
                    │      [Normalize]   [categorical enc]  │
                    └─────────────────────────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │   STAGE 3: Correlation Engine            │
                    │         (Method Selection)               │
                    │                                         │
                    │    ┌──────────┬──────────┬──────────┐   │
                    │    │  < 100   │ 100-1000 │  > 1000  │   │
                    │    │  events  │  events  │  events  │   │
                    │    └────┬─────┴────┬─────┴────┬─────┘   │
                    │         │          │          │        │
                    │         ▼          ▼          ▼        │
                    │    ┌────────┐  ┌────────┐  ┌────────┐   │
                    │    │Union-  │  │ Hybrid │  │  HGNN  │   │
                    │    │ Find   │  │        │  │        │   │
                    │    └────────┘  └────────┘  └────────┘   │
                    │                                         │
                    └─────────────────────────────────────────┘
                              │           │           │
                              ▼           ▼           ▼
                         ┌────────┐  ┌────────┐  ┌────────┐
                         │ Graph  │  │ Graph  │  │Hetero- │
                         │ (simple)│ │ (simple)│ │geneous │
                         │ +       │  │ + HGNN │  │ Graph  │
                         │Union-Find│ │ refine │  │ + GNN  │
                         └────────┘  └────────┘  └────────┘
                              │           │           │
                              └───────────┴───────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────┐
                    │    STAGE 4: Cluster Assignments           │
                    │                                         │
                    │    alert_1 ──▶ Cluster A (conf: 0.9)   │
                    │    alert_2 ──▶ Cluster A (conf: 0.85)   │
                    │    alert_3 ──▶ Cluster B (conf: 0.92)   │
                    │                                         │
                    └─────────────────────────────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────┐
                    │    STAGE 5: Post-Processing               │
                    │                                         │
                    │  ┌─────────────┐  ┌─────────────────┐  │
                    │  │Cluster Clean│─▶│ Feature Chains   │  │
                    │  └─────────────┘  └─────────────────┘  │
                    │           │                    │      │
                    │           ▼                    ▼      │
                    │      [Remove]            [Extract]     │
                    │      [singletons]      [attack]       │
                    │      [Merge small]     [progression]    │
                    │      [Split large]     [tactic chain]   │
                    └─────────────────────────────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────┐
                    │    STAGE 6: Output Generation             │
                    │                                         │
                    │  ┌─────────────────────────────────────┐  │
                    │  │        JSON Output                   │  │
                    │  │                                      │  │
                    │  │  {                                   │  │
                    │  │    "clusters": [...],              │  │
                    │  │    "tactics": [...],               │  │
                    │  │    "confidence": 0.87,            │  │
                    │  │    "method": "HGNN"                │  │
                    │  │  }                                   │  │
                    │  └─────────────────────────────────────┘  │
                    │                                         │
                    │  ┌──────────────┐  ┌──────────────┐    │
                    │  │   Dashboard  │  │    Export    │    │
                    │  │   (Plotly)     │  │   (JSON/CSV) │    │
                    │  └──────────────┘  └──────────────┘    │
                    └─────────────────────────────────────────┘
```

## Integration Points

### Web Application (app.py)

**Current Flow:**
```python
# Before
from correlation_indexer import enhanced_correlation
result = enhanced_correlation(df, usernames, addresses)

# After
from correlation_pipeline import CorrelationPipeline
pipeline = CorrelationPipeline(method='auto')
result = pipeline.correlate(df, usernames, addresses)
```

**UI Components:**
- Method selector dropdown (Union-Find / HGNN / Hybrid)
- Confidence threshold slider
- Model selection (if multiple trained models)
- Real-time progress indicator

### API Endpoints

**Endpoint:** `/api/correlate`

**Request:**
```json
{
  "data": [...],
  "method": "hgnn",
  "model_path": "checkpoints/best_model.pt",
  "confidence_threshold": 0.5
}
```

**Response:**
```json
{
  "clusters": [...],
  "metadata": {
    "method_used": "HGNN",
    "runtime_seconds": 2.5,
    "num_clusters": 15,
    "accuracy": 0.86
  }
}
```

## Performance Characteristics

| Method | Speed | Accuracy | Training | GPU |
|--------|-------|----------|----------|-----|
| Union-Find | ~100ms/1K alerts | Rule-based | None | No |
| HGNN | ~2s/1K alerts | 86.45% | Required | Optional |
| Hybrid | ~500ms/1K alerts | ~85% | Required | Optional |

## File Organization (Clean)

```
MITRE-CORE/
├── core/                          # Core pipeline
│   ├── __init__.py
│   ├── correlation_pipeline.py    # ⭐ Unified interface
│   ├── correlation_indexer.py     # Union-Find baseline
│   ├── preprocessing.py
│   ├── postprocessing.py
│   └── output.py
│
├── hgnn/                          # HGNN modules
│   ├── __init__.py
│   ├── model.py                   # Neural network
│   ├── training.py                # Training loops
│   ├── evaluation.py              # Metrics & testing
│   ├── integration.py             # Pipeline integration
│   └── converters.py              # Graph builders
│
├── app/                           # Web interface
│   ├── main.py                    # Flask app
│   └── templates/
│       └── index.html
│
├── training/                      # Training scripts
│   └── train.py                   # Main training
│
└── docs/
    └── architecture.md            # This file
```

## Conclusion

The MITRE-CORE pipeline supports multiple correlation methods unified under a single interface. The data flows through 6 stages:

1. **Ingestion:** SIEM/CSV/API inputs
2. **Preprocessing:** Feature engineering & normalization
3. **Correlation:** Union-Find / HGNN / Hybrid
4. **Graph Construction:** (HGNN only) Heterogeneous graph building
5. **Post-Processing:** Cluster refinement & attack chain extraction
6. **Output:** JSON + Dashboard visualization

The new `correlation_pipeline.py` provides a unified interface for all methods with automatic method selection based on data size.
