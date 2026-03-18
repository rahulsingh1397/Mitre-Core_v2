"""
MITRE-CORE Streaming & Batching Module
=======================================

Implements streaming strategy with reservoir sampling for huge datasets.
Stores full correlation output in Parquet and generates graphs lazily.

Key Features:
- Reservoir sampling per tactic for rare-but-critical chains
- Parquet-based efficient storage
- Lazy graph generation on analyst request
- Memory-efficient processing of large datasets

References:
- GraphWeaver: Billion-Scale Correlation (Microsoft)
- CyGraph: Attack Graph Abstraction (MITRE)
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Iterator, Callable, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

logger = logging.getLogger("mitre-core.streaming")


@dataclass
class StreamConfig:
    """Configuration for streaming pipeline."""
    # Sampling parameters
    reservoir_size: int = 1000  # Max items per reservoir
    sampling_ratio: float = 0.1  # Default sampling ratio for large datasets
    
    # Batch processing
    batch_size: int = 10000
    max_memory_rows: int = 50000
    
    # Storage
    output_dir: str = "./stream_output"
    parquet_compression: str = "snappy"
    
    # Tactic-based reservoir sampling
    enable_tactic_reservoir: bool = True
    rare_tactic_threshold: int = 5  # Tactics with <5 clusters are "rare"


class StreamingCorrelator:
    """
    Streaming correlation engine with reservoir sampling.
    
    Handles huge datasets by:
    1. Processing in batches
    2. Applying reservoir sampling per tactic
    3. Storing full output in Parquet
    4. Generating graphs lazily on request
    """
    
    def __init__(self, config: Optional[StreamConfig] = None):
        self.config = config or StreamConfig()
        self._reservoirs: Dict[str, List[pd.DataFrame]] = defaultdict(list)
        self._processed_batches: int = 0
        self._total_rows: int = 0
        
        # Ensure output directory exists
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
    
    def process_dataframe(
        self,
        df: pd.DataFrame,
        correlation_fn: Callable[[pd.DataFrame], pd.DataFrame],
        cluster_col: str = "pred_cluster"
    ) -> Tuple[pd.DataFrame, str]:
        """
        Process a large DataFrame with batching and reservoir sampling.
        
        Args:
            df: Input DataFrame (potentially large)
            correlation_fn: Function to apply correlation to each batch
            cluster_col: Column name for cluster assignments
            
        Returns:
            Tuple of (sampled_df, parquet_path)
        """
        cfg = self.config
        total_rows = len(df)
        
        if total_rows <= cfg.max_memory_rows:
            # Small enough to process in memory
            logger.info(f"Processing {total_rows} rows in memory")
            result = correlation_fn(df)
            parquet_path = self._save_to_parquet(result, "correlation_full")
            return result, parquet_path
        
        # Large dataset - process in batches
        logger.info(f"Processing {total_rows} rows in batches of {cfg.batch_size}")
        
        batch_files = []
        for start_idx in range(0, total_rows, cfg.batch_size):
            end_idx = min(start_idx + cfg.batch_size, total_rows)
            batch = df.iloc[start_idx:end_idx].copy()
            
            # Process batch
            batch_result = correlation_fn(batch)
            
            # Apply reservoir sampling
            sampled = self._apply_reservoir_sampling(batch_result, cluster_col)
            
            # Save batch to temporary parquet
            batch_path = self._save_to_parquet(
                batch_result, 
                f"batch_{self._processed_batches}",
                temp=True
            )
            batch_files.append(batch_path)
            self._processed_batches += 1
            
            logger.debug(f"Processed batch {self._processed_batches}: rows {start_idx}-{end_idx}")
        
        # Merge all batches
        full_result = self._merge_parquet_files(batch_files)
        final_path = self._save_to_parquet(full_result, "correlation_full")
        
        # Clean up temp files
        for temp_path in batch_files:
            Path(temp_path).unlink(missing_ok=True)
        
        # Extract sampled subset for immediate visualization
        sampled_result = self._extract_reservoir_sample(full_result, cluster_col)
        
        logger.info(f"Streaming complete: {self._processed_batches} batches, "
                   f"{len(full_result)} total rows, {len(sampled_result)} sampled")
        
        return sampled_result, final_path
    
    def _apply_reservoir_sampling(
        self,
        df: pd.DataFrame,
        cluster_col: str = "pred_cluster"
    ) -> pd.DataFrame:
        """
        Apply reservoir sampling per tactic to preserve rare-but-critical chains.
        
        Algorithm (Vitter's reservoir sampling):
        - For each new item, replace existing with probability size/count
        - Ensures uniform sample from stream without knowing total size
        """
        if not self.config.enable_tactic_reservoir:
            return df
        
        if cluster_col not in df.columns:
            return df
        
        cfg = self.config
        
        # Group by tactic if available
        tactic_col = None
        for col in ["MalwareIntelAttackType", "AttackType", "tactic", "Tactic"]:
            if col in df.columns:
                tactic_col = col
                break
        
        if not tactic_col:
            # No tactic column - apply uniform reservoir sampling
            return self._uniform_reservoir_sample(df, cfg.reservoir_size)
        
        # Group by tactic and apply reservoir sampling to each
        sampled_dfs = []
        tactic_counts = df[tactic_col].value_counts()
        
        for tactic, count in tactic_counts.items():
            tactic_df = df[df[tactic_col] == tactic]
            
            if count <= cfg.rare_tactic_threshold or len(tactic_df) <= cfg.reservoir_size:
                # Rare tactic - keep all samples
                sampled_dfs.append(tactic_df)
                logger.debug(f"Preserved rare tactic '{tactic}': {count} alerts")
            else:
                # Common tactic - apply reservoir sampling
                sampled = self._uniform_reservoir_sample(tactic_df, cfg.reservoir_size)
                sampled_dfs.append(sampled)
        
        if sampled_dfs:
            return pd.concat(sampled_dfs, ignore_index=True)
        return df
    
    def _uniform_reservoir_sample(
        self,
        df: pd.DataFrame,
        k: int
    ) -> pd.DataFrame:
        """
        Vitter's reservoir sampling: O(n) time, O(k) space.
        
        Maintains uniform probability of selection for all items
        without knowing stream length in advance.
        """
        n = len(df)
        if n <= k:
            return df
        
        # Use numpy for efficient random selection
        indices = np.random.choice(n, size=k, replace=False)
        return df.iloc[indices].copy()
    
    def _save_to_parquet(
        self,
        df: pd.DataFrame,
        name: str,
        temp: bool = False
    ) -> str:
        """Save DataFrame to Parquet with compression."""
        cfg = self.config
        
        if temp:
            path = Path(cfg.output_dir) / f"temp_{name}.parquet"
        else:
            path = Path(cfg.output_dir) / f"{name}.parquet"
        
        # Handle non-serializable types
        df_clean = df.copy()
        for col in df_clean.columns:
            if df_clean[col].dtype == 'object':
                # Convert complex objects to strings
                try:
                    df_clean[col] = df_clean[col].astype(str)
                except:
                    df_clean[col] = df_clean[col].apply(lambda x: str(x) if x is not None else None)
        
        table = pa.Table.from_pandas(df_clean)
        pq.write_table(table, str(path), compression=cfg.parquet_compression)
        
        return str(path)
    
    def _merge_parquet_files(self, paths: List[str]) -> pd.DataFrame:
        """Merge multiple Parquet files into single DataFrame."""
        dfs = []
        for path in paths:
            table = pq.read_table(path)
            dfs.append(table.to_pandas())
        
        if dfs:
            return pd.concat(dfs, ignore_index=True)
        return pd.DataFrame()
    
    def _extract_reservoir_sample(
        self,
        df: pd.DataFrame,
        cluster_col: str = "pred_cluster"
    ) -> pd.DataFrame:
        """Extract the final reservoir sample for visualization."""
        return self._apply_reservoir_sampling(df, cluster_col)
    
    def load_cluster_lazy(
        self,
        parquet_path: str,
        cluster_id: int,
        cluster_col: str = "pred_cluster"
    ) -> Optional[pd.DataFrame]:
        """
        Lazily load a specific cluster from Parquet storage.
        
        Uses predicate pushdown for efficient loading without
        reading entire file.
        """
        try:
            # Use PyArrow dataset API for filtering
            import pyarrow.dataset as ds
            
            dataset = ds.dataset(parquet_path, format="parquet")
            
            # Build filter expression
            filter_expr = ds.field(cluster_col) == cluster_id
            
            # Read only matching rows
            table = dataset.to_table(filter=filter_expr)
            
            if len(table) > 0:
                return table.to_pandas()
            return None
            
        except Exception as e:
            logger.error(f"Failed to load cluster {cluster_id}: {e}")
            # Fallback: load full and filter
            df = pq.read_table(parquet_path).to_pandas()
            return df[df[cluster_col] == cluster_id] if cluster_col in df.columns else None
    
    def get_cluster_metadata(
        self,
        parquet_path: str,
        cluster_col: str = "pred_cluster"
    ) -> Dict[str, Any]:
        """
        Get metadata about clusters without loading full data.
        
        Returns statistics useful for the curated graph stories.
        """
        try:
            table = pq.read_table(parquet_path)
            df = table.to_pandas()
            
            if cluster_col not in df.columns:
                return {}
            
            cluster_stats = []
            for cid, cluster_df in df.groupby(cluster_col):
                stat = {
                    "cluster_id": int(cid),
                    "size": len(cluster_df),
                    "sample_count": min(len(cluster_df), self.config.reservoir_size)
                }
                
                # Add severity if available
                for col in ["AttackSeverity", "severity", "cluster_importance_score"]:
                    if col in cluster_df.columns:
                        stat["mean_severity"] = float(cluster_df[col].mean())
                        break
                
                cluster_stats.append(stat)
            
            return {
                "total_clusters": len(cluster_stats),
                "parquet_path": parquet_path,
                "total_rows": len(df),
                "cluster_stats": cluster_stats,
                "storage_size_mb": Path(parquet_path).stat().st_size / (1024 * 1024)
            }
            
        except Exception as e:
            logger.error(f"Failed to get metadata: {e}")
            return {}


class LazyGraphGenerator:
    """
    Generates graph data lazily when analyst requests a specific cluster.
    
    Implements CyGraph's approach: store abstracted attack paths,
    expand nodes on demand without overloading the UI.
    """
    
    def __init__(self, parquet_path: str, streaming_correlator: StreamingCorrelator):
        self.parquet_path = parquet_path
        self.streamer = streaming_correlator
        self._cache: Dict[int, Dict] = {}
    
    def generate_graph(
        self,
        cluster_id: Optional[int] = None,
        view_type: str = "campaign_summary",
        max_nodes: int = 100
    ) -> Dict[str, Any]:
        """
        Generate graph data on demand.
        
        Args:
            cluster_id: Specific cluster to visualize (None for all)
            view_type: Type of graph view
            max_nodes: Maximum nodes to include
            
        Returns:
            Graph data dictionary
        """
        # Check cache
        cache_key = f"{cluster_id}_{view_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Load data lazily
        if cluster_id is not None:
            df = self.streamer.load_cluster_lazy(self.parquet_path, cluster_id)
            if df is None:
                return {"nodes": [], "edges": [], "error": f"Cluster {cluster_id} not found"}
        else:
            # Load sample for overview
            df = pq.read_table(self.parquet_path).to_pandas()
            if len(df) > max_nodes:
                df = df.sample(n=max_nodes)
        
        # Build graph based on view type
        if view_type == "campaign_summary":
            graph = self._build_campaign_graph(df)
        elif view_type == "entity_ego":
            graph = self._build_ego_graph(df)
        elif view_type == "alert_detail":
            graph = self._build_alert_graph(df, max_nodes)
        else:
            graph = {"nodes": [], "edges": [], "error": f"Unknown view type: {view_type}"}
        
        # Cache result
        self._cache[cache_key] = graph
        
        return graph
    
    def _build_campaign_graph(self, df: pd.DataFrame) -> Dict:
        """Build campaign-level graph (hosts ↔ tactics)."""
        # Similar to ClusterFilter._build_campaign_summary_graph
        # Simplified version for lazy loading
        nodes = []
        edges = []
        
        # Extract tactics and hosts
        tactics = set()
        hosts = set()
        connections = defaultdict(int)
        
        for _, row in df.iterrows():
            tactic = None
            for col in ["MalwareIntelAttackType", "AttackType", "tactic"]:
                if col in row and pd.notna(row[col]):
                    tactic = str(row[col])
                    tactics.add(tactic)
                    break
            
            for col in ["SourceHostName", "DestinationHostName", "DeviceHostName"]:
                if col in row and pd.notna(row[col]):
                    host = str(row[col])
                    hosts.add(host)
                    if tactic:
                        connections[(host, tactic)] += 1
        
        # Create nodes
        node_id = 0
        host_ids = {}
        for host in hosts:
            host_ids[host] = node_id
            nodes.append({
                "id": node_id,
                "label": host,
                "type": "host",
                "color": "#3b82f6"
            })
            node_id += 1
        
        tactic_ids = {}
        for tactic in tactics:
            tactic_ids[tactic] = node_id
            nodes.append({
                "id": node_id,
                "label": tactic,
                "type": "tactic",
                "color": "#ef4444"
            })
            node_id += 1
        
        # Create edges
        for (host, tactic), count in connections.items():
            edges.append({
                "source": host_ids[host],
                "target": tactic_ids[tactic],
                "weight": count
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "view": "campaign_summary",
            "cluster_count": df["pred_cluster"].nunique() if "pred_cluster" in df.columns else 0
        }
    
    def _build_ego_graph(self, df: pd.DataFrame) -> Dict:
        """Build entity ego-network graph."""
        # Find most connected entity as focus
        entity_counts = defaultdict(int)
        for col in ["SourceHostName", "SourceAddress"]:
            if col in df.columns:
                for val in df[col].dropna():
                    entity_counts[val] += 1
        
        if not entity_counts:
            return {"nodes": [], "edges": [], "view": "entity_ego"}
        
        focus = max(entity_counts, key=entity_counts.get)
        
        # Build subgraph around focus
        nodes = [{"id": 0, "label": focus, "type": "focus", "color": "#ef4444"}]
        edges = []
        
        related = defaultdict(int)
        for _, row in df.iterrows():
            is_related = False
            for col in ["SourceHostName", "SourceAddress"]:
                if col in row and str(row[col]) == focus:
                    is_related = True
                    break
            
            if is_related:
                for col in ["DestinationHostName", "DestinationAddress"]:
                    if col in row and pd.notna(row[col]):
                        related[str(row[col])] += 1
        
        node_id = 1
        for entity, count in related.items():
            nodes.append({
                "id": node_id,
                "label": entity,
                "type": "related",
                "color": "#3b82f6"
            })
            edges.append({"source": 0, "target": node_id, "weight": count})
            node_id += 1
        
        return {
            "nodes": nodes,
            "edges": edges,
            "view": "entity_ego",
            "focus": focus
        }
    
    def _build_alert_graph(self, df: pd.DataFrame, max_nodes: int) -> Dict:
        """Build detailed alert-level graph."""
        if len(df) > max_nodes:
            df = df.head(max_nodes)
        
        nodes = []
        edges = []
        
        # Create alert nodes
        for idx, (_, row) in enumerate(df.iterrows()):
            nodes.append({
                "id": idx,
                "label": f"Alert {idx}",
                "type": "alert",
                "color": "#6b7280"
            })
            
            if idx > 0:
                edges.append({"source": idx - 1, "target": idx})
        
        return {
            "nodes": nodes,
            "edges": edges,
            "view": "alert_detail"
        }
    
    def clear_cache(self):
        """Clear the graph generation cache."""
        self._cache.clear()


def create_streaming_correlator(
    output_dir: str = "./stream_output",
    batch_size: int = 10000,
    reservoir_size: int = 1000
) -> StreamingCorrelator:
    """
    Factory function to create a configured StreamingCorrelator.
    
    Args:
        output_dir: Directory for Parquet output
        batch_size: Rows per batch
        reservoir_size: Max items in reservoir per tactic
        
    Returns:
        Configured StreamingCorrelator
    """
    config = StreamConfig(
        output_dir=output_dir,
        batch_size=batch_size,
        reservoir_size=reservoir_size
    )
    return StreamingCorrelator(config)
