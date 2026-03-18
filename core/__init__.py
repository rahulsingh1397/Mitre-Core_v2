"""
MITRE-CORE Core Package
=======================

Core pipeline modules for alert correlation, filtering, and enrichment.

Modules:
- correlation_pipeline: Unified correlation interface
- correlation_indexer: Union-Find baseline implementation
- cluster_filter: Curated graph stories and cluster ranking
- kg_enrichment: Knowledge graph enrichment with threat intel
- streaming: Streaming & batching with reservoir sampling
- preprocessing: Data preprocessing and feature engineering
- postprocessing: Post-correlation processing
- output: Output generation and formatting
"""

from .correlation_pipeline import (
    CorrelationPipeline,
    CorrelationMethod,
    CorrelationResult,
    TransformerHybridPipeline,
    enhanced_correlation
)

from .cluster_filter import (
    ClusterFilter,
    FilterConfig,
    ClusterScore,
    FilterStrategy,
    GraphResolution,
    create_cluster_filter
)

from .kg_enrichment import (
    KnowledgeGraphEnricher,
    ThreatIntelStore,
    ThreatIntelEntity,
    ClusterEnrichment,
    create_enricher
)

from .streaming import (
    StreamingCorrelator,
    LazyGraphGenerator,
    StreamConfig,
    create_streaming_correlator
)

__all__ = [
    # Correlation
    'CorrelationPipeline',
    'CorrelationMethod',
    'CorrelationResult',
    'enhanced_correlation',
    
    # Cluster Filtering
    'ClusterFilter',
    'FilterConfig',
    'ClusterScore',
    'FilterStrategy',
    'GraphResolution',
    'create_cluster_filter',
    
    # Knowledge Graph
    'KnowledgeGraphEnricher',
    'ThreatIntelStore',
    'ThreatIntelEntity',
    'ClusterEnrichment',
    'create_enricher',
    
    # Streaming
    'StreamingCorrelator',
    'LazyGraphGenerator',
    'StreamConfig',
    'create_streaming_correlator',
]
