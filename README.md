# MITRE-CORE v2.1

**Advanced Threat Correlation & Knowledge Graph Platform**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

MITRE-CORE is a cybersecurity alert correlation engine that clusters security alerts into attack campaigns using a **3-tier AI architecture**: Transformer (candidate generation) → HGNN (graph correlation) → Union-Find (structural fallback). Version 2.1 introduces curated graph stories, knowledge graph enrichment, and multi-resolution visualization inspired by GraphWeaver and CyGraph architectures.

## � Latest Evaluation Results (v2.10)

**Engine Capability Check:**
- ✅ 8 datasets evaluated (304,214 total records)
- ✅ 100% success rate on all dataset loading
- ✅ 100% MITRE ATT&CK coverage (14/14 tactics)
- ✅ 0 critical security vulnerabilities
- ✅ 135 Python files, 35,506 lines of code analyzed

[View detailed evaluation report](docs/reports/comprehensive_evaluation_20260315_163933.md)

## 🆕 v2.10: Enhanced Dataset Utilities

### Dataset Limitation Fixes
- **Large Dataset Downloader**: Automated CICIDS2017 & CSE-CIC-IDS2018 processing with resume capability
- **MITRE Tactic Mapper**: Full 14-tactic ATT&CK coverage with confidence scoring
- **Temporal Fragment Merger**: Merge DataSense IIoT temporal fragments into continuous attack chains
- **SOC Log Generator**: Realistic enterprise SOC logs with kill chain progression
- **Cross-Dataset Validator**: Train/test generalization analysis
- **Dataset Balancer**: Handle class imbalance (NSL-KDD 80/20, etc.)

### Code Quality Tools
- **Engine Capability Check**: End-to-end evaluation across all datasets
- **Codebase Analysis**: Security vulnerability scanning + redundancy detection
- **Data Migration**: Move files from gitignored to accessible locations

## � Key Features

### Core Correlation Engine
- **3-Tier AI Architecture**: Transformer → HGNN → Union-Find
  - Tier 1: Sparse attention Transformer for O(n) candidate generation
  - Tier 2: HGNN for heterogeneous graph correlation
  - Tier 3: Union-Find for interpretable structural fallback
- **Geometry-Aware Embedding Confidence (GAEC)**: HDBSCAN-based confidence scoring
- **Adaptive Thresholds**: Confidence-guided threshold selection per dataset
- **8 Dataset Support**: UNSW-NB15, TON_IoT, Linux_APT, CICIDS2017, NSL-KDD, CICAPT-IIoT, Datasense IIoT, YNU-IoTMal

### v2.1: Curated Graph Stories
- **Top-K Cluster Selection**: Rank clusters by importance score
  - Formula: `importance = 0.3*log(size) + 0.5*severity + 0.2*critical_tactic`
- **Semantic Filters**: Filter by MITRE tactics/techniques and critical assets
- **Reservoir Sampling**: Preserve rare-but-critical attack chains

### v2.1: Knowledge Graph Enrichment
- **Threat Intel Integration**: CVE, ATT&CK techniques, malware families
- **Graph Metrics**: PageRank and betweenness centrality for severity ranking
- **Campaign Linkage**: Automatic APT group detection
- **Combined Threat Scoring**: Multi-factor threat assessment

### v2.1: Multi-Resolution Views
Three-tier visualization system (CyGraph-inspired):
1. **Campaign Summary**: High-level hosts ↔ tactics view
2. **Entity Ego-Net**: Focused drill-down on specific assets
3. **Alert Drill-Down**: Raw alert-level detail view

### Streaming & Scale
- **Billion-Scale Support**: Reservoir sampling for massive datasets
- **Parquet Storage**: Efficient columnar storage with predicate pushdown
- **Lazy Graph Generation**: On-demand visualization from stored data

### v2.11: New Critical Capabilities
- **HGNN Explainability**: Attention visualization and cluster explanation generation
- **Billion-Scale Clustering**: Hierarchical clustering for millions of events
- **Long-Range Temporal Correlation**: Multi-day APT campaign detection
- **Cross-Domain Fusion**: Network + host + cloud multi-modal correlation
- **Analyst Feedback Integration**: Active learning from SOC analyst feedback
- **Complete MITRE Coverage**: All 14 ATT&CK tactics now supported

### Web Dashboard
- Interactive Plotly visualizations
- Real-time SIEM ingestion
- Multi-resolution graph views
- Report generation (Markdown export)
- Knowledge graph enrichment panel

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/your-org/mitre-core.git
cd mitre-core

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install PyTorch with CUDA support for GPU acceleration
# See https://pytorch.org/get-started/locally/
```

## 🚀 Quick Start

### 1. Run the Web Dashboard

```bash
python app/main.py
```

Access at http://localhost:5000

### 2. API Usage

```python
from core.correlation_pipeline import CorrelationPipeline

# Initialize pipeline
pipeline = CorrelationPipeline(method='auto', model_path='path/to/model.pt')

# Correlate alerts
result = pipeline.correlate(df, usernames=['SourceHostName'], addresses=['SourceAddress'])
print(f"Found {result.num_clusters} clusters in {result.runtime_seconds:.2f}s")
```

### 3. Cluster Filtering

```python
from core.cluster_filter import create_cluster_filter

# Create filter with semantic criteria
filterer = create_cluster_filter(
    top_k=20,
    strategy='top_k_score',
    target_tactics=['lateral_movement', 'exfiltration'],
    critical_assets=['10.0.0.*', 'domain_controller']
)

# Apply filtering
filtered_df, cluster_scores = filterer.filter_clusters(correlated_df)
```

### 4. Knowledge Graph Enrichment

```python
from core.kg_enrichment import create_enricher

# Initialize enricher
enricher = create_enricher()

# Apply enrichment
enriched_df, enrichments = enricher.enrich_clusters(filtered_df)

# Check threat scores
for e in enrichments:
    print(f"Cluster {e.cluster_id}: threat_score={e.combined_threat_score:.3f}")
```

### 5. Streaming for Large Datasets

```python
from core.streaming import create_streaming_correlator

# Initialize streamer
streamer = create_streaming_correlator(
    output_dir='./output',
    batch_size=10000,
    reservoir_size=1000
)

# Process large DataFrame
sampled_df, parquet_path = streamer.process_dataframe(
    large_df,
    correlation_fn=lambda df: pipeline.correlate(df, usernames, addresses)
)
```

## 📊 Dashboard Usage

### Upload & Analyze
1. Navigate to the Analysis tab
2. Upload a CSV file with alert data (must contain address/host columns)
3. Click "Run Correlation" to analyze

### Apply Cluster Filtering
1. After correlation, use the "Filter Clusters" panel
2. Select strategy: Top-K Score, Top-K Size, Semantic, or Critical Assets
3. Specify target MITRE tactics if needed
4. Click "Apply Filter" to curate graph stories

### Switch Graph Views
- **Campaign Summary**: Shows high-level attack patterns
- **Entity Ego-Net**: Drill into specific hosts/IPs
- **Alert Drill-Down**: See individual alert connections

### Knowledge Graph Enrichment
1. Click "Analyze Threat Intel" to match clusters with:
   - MITRE ATT&CK techniques
   - Malware families
   - CVE vulnerabilities
2. View threat scores and campaign linkages

### Generate Reports
1. Click "Generate Report" to create Markdown report
2. Download includes:
   - Executive summary
   - Cluster details with scores
   - Enrichment findings
   - Recommendations

## 🔌 SIEM Integration

### Supported Connectors
- Splunk Enterprise/Cloud
- Elastic SIEM / ELK
- Microsoft Sentinel
- IBM QRadar
- Syslog (UDP/TCP)
- Generic Webhook

### Configuration
```bash
# Start live ingestion
curl -X POST http://localhost:5000/api/siem/engine/start \
  -H "Content-Type: application/json" \
  -d '{"poll_interval": 30, "correlation_interval": 60}'

# Add Splunk connector
curl -X POST http://localhost:5000/api/siem/connectors \
  -H "Content-Type: application/json" \
  -d '{
    "id": "splunk-prod",
    "type": "splunk",
    "config": {"host": "splunk.example.com", "port": 8089}
  }'
```

## 🛡️ Security

- Input validation on all API endpoints
- CORS restricted to configured origins
- File upload limits (50MB)
- Secure filename handling
- No sensitive data in logs

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MITRE-CORE v2.1                          │
├─────────────────────────────────────────────────────────────┤
│  UI Layer (Flask + Plotly)                                  │
│  ├── Dashboard (Analysis, SIEM, Reports)                    │
│  ├── Multi-Resolution Graph Views                           │
│  └── Knowledge Graph Panel                                  │
├─────────────────────────────────────────────────────────────┤
│  API Layer                                                  │
│  ├── /api/clusters/filter          (ClusterFilter)          │
│  ├── /api/graph/view/<type>        (GraphResolution)        │
│  ├── /api/enrichment/analyze       (KGEnricher)             │
│  └── /api/report/generate          (ReportGenerator)        │
├─────────────────────────────────────────────────────────────┤
│  Core Engine                                                │
│  ├── CorrelationPipeline (HGNN + Union-Find)                │
│  ├── ClusterFilter (Reservoir Sampling)                     │
│  ├── KnowledgeGraphEnricher (PageRank, TI matching)         │
│  └── StreamingCorrelator (Parquet, Lazy Loading)            │
├─────────────────────────────────────────────────────────────┤
│  Data Layer                                                 │
│  ├── Heterogeneous Graph (PyG HeteroData)                   │
│  ├── Parquet Storage (Columnar)                             │
│  └── Threat Intel Store (MITRE, CVE, Malware)               │
└─────────────────────────────────────────────────────────────┘
```

## 📚 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md)
- [Dataset Documentation](docs/DATASETS.md)
- [API Reference](docs/API.md)
- [Memory/Changelog](MEMORY.md)

## 🔬 Research

MITRE-CORE implements techniques from:

- **GraphWeaver** (Microsoft, 2024): Billion-scale correlation via rule filters
- **CyGraph** (MITRE): Multi-resolution attack graph visualization
- **CKG Surveys**: Cybersecurity knowledge graph fusion
- **HGNN Research**: Heterogeneous graph neural networks for APT detection

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Acknowledgments

- MITRE ATT&CK® Framework
- PyTorch Geometric team
- GraphWeaver research team at Microsoft
- CyGraph team at MITRE

---

**Built with Python, PyTorch, Flask & Plotly**
