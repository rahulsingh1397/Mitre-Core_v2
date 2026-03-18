"""
MITRE-CORE Cluster Filter Module
===================================

Implements curated graph stories by filtering and ranking clusters
for visualization. Uses a multi-factor scoring pipeline inspired by
GraphWeaver's correlation filtering approach.

Key Features:
- Top-k cluster selection by size or severity
- Semantic filtering (MITRE tactics/techniques, critical assets)
- Multi-resolution graph views (campaign, entity, drill-down)
- Reservoir sampling for rare-but-critical chains
- Parquet-based lazy graph generation

References:
- GraphWeaver: Billion-Scale Cybersecurity Incident Correlation (Microsoft)
- CyGraph: Graph-Based Analytics and Visualization for Cybersecurity (MITRE)
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
import numpy as np
import pandas as pd
from collections import defaultdict

logger = logging.getLogger("mitre-core.cluster_filter")


class FilterStrategy(Enum):
    """Cluster selection strategies."""
    TOP_K_SIZE = "top_k_size"           # Largest clusters
    TOP_K_SEVERITY = "top_k_severity"   # Highest mean severity
    TOP_K_SCORE = "top_k_score"         # Combined importance score
    SEMANTIC = "semantic"               # MITRE tactic/technique matching
    CRITICAL_ASSETS = "critical_assets" # Asset-based filtering


class GraphResolution(Enum):
    """Multi-resolution graph view tiers."""
    CAMPAIGN_SUMMARY = "campaign_summary"   # (a) hosts ↔ tactics
    ENTITY_EGO_NET = "entity_ego_net"       # (b) entity ego-network
    ALERT_DRILL_DOWN = "alert_drill_down"   # (c) raw alert details


@dataclass
class ClusterScore:
    """Comprehensive cluster scoring container."""
    cluster_id: int
    size: int
    mean_severity: float
    max_severity: float
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    critical_assets: List[str] = field(default_factory=list)
    importance_score: float = 0.0
    inclusion_reason: str = ""
    graph_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class FilterConfig:
    """Configuration for cluster filtering pipeline."""
    # Top-k selection
    top_k: int = 20
    selection_strategy: FilterStrategy = FilterStrategy.TOP_K_SCORE
    
    # Scoring weights
    size_weight: float = 0.3
    severity_weight: float = 0.5
    tactic_weight: float = 0.2
    
    # Semantic filters
    target_tactics: Optional[Set[str]] = None
    target_techniques: Optional[Set[str]] = None
    critical_asset_patterns: Optional[List[str]] = None
    
    # Thresholds
    min_cluster_size: int = 2
    min_severity: float = 0.0
    importance_threshold: float = 0.0
    
    # Reservoir sampling for rare tactics
    reservoir_size: int = 100
    enable_reservoir: bool = True
    
    # Graph resolution tier
    resolution: GraphResolution = GraphResolution.CAMPAIGN_SUMMARY


class ClusterFilter:
    """
    Lightweight cluster filter implementing curated graph stories.
    
    Inspired by GraphWeaver's approach: prune billion-scale correlations
    via rule filters before graph export, ensuring only meaningful
    chains reach the visualization layer.
    """
    
    def __init__(self, config: Optional[FilterConfig] = None):
        self.config = config or FilterConfig()
        self._reservoir: Dict[str, List[int]] = defaultdict(list)
        
    def compute_importance_score(
        self,
        cluster_id: int,
        cluster_df: pd.DataFrame,
        critical_tactics: Optional[Set[str]] = None
    ) -> ClusterScore:
        """
        Compute cluster_importance = size_weight * log(size) + 
                                     severity_weight * mean(severity) +
                                     tactic_weight * critical_tactic_flag
        
        Args:
            cluster_id: Cluster identifier
            cluster_df: DataFrame containing alerts in this cluster
            critical_tactics: Set of high-priority MITRE tactics
            
        Returns:
            ClusterScore with computed metrics and inclusion reason
        """
        size = len(cluster_df)
        
        # Severity computation
        severity_col = None
        for col in ["AttackSeverity", "severity", "Severity", "score"]:
            if col in cluster_df.columns:
                severity_col = col
                break
        
        if severity_col:
            severities = pd.to_numeric(cluster_df[severity_col], errors="coerce").fillna(0)
            mean_severity = severities.mean()
            max_severity = severities.max()
        else:
            mean_severity = 0.5  # Default mid-severity
            max_severity = 0.5
        
        # Extract tactics and techniques
        tactics = []
        techniques = []
        
        if "MalwareIntelAttackType" in cluster_df.columns:
            tactics = cluster_df["MalwareIntelAttackType"].dropna().unique().tolist()
        elif "AttackType" in cluster_df.columns:
            tactics = cluster_df["AttackType"].dropna().unique().tolist()
            
        if "AttackTechnique" in cluster_df.columns:
            techniques = cluster_df["AttackTechnique"].dropna().unique().tolist()
        elif "Technique" in cluster_df.columns:
            techniques = cluster_df["Technique"].dropna().unique().tolist()
        
        # Identify critical assets
        critical_assets = []
        asset_patterns = self.config.critical_asset_patterns or []
        for col in ["SourceAddress", "DestinationAddress", "DeviceAddress", 
                    "SourceHostName", "DestinationHostName"]:
            if col in cluster_df.columns:
                for pattern in asset_patterns:
                    matches = cluster_df[col].astype(str).str.contains(
                        pattern, case=False, na=False
                    )
                    critical_assets.extend(cluster_df.loc[matches, col].dropna().tolist())
        
        critical_assets = list(set(critical_assets))
        
        # Critical tactic flag
        critical_tactic_flag = 0.0
        if critical_tactics and tactics:
            overlap = set(t.lower() for t in tactics) & set(t.lower() for t in critical_tactics)
            if overlap:
                critical_tactic_flag = 1.0
        
        # Compute importance score
        cfg = self.config
        size_component = np.log1p(size)  # log(size) with smoothing
        
        importance = (
            cfg.size_weight * size_component +
            cfg.severity_weight * mean_severity +
            cfg.tactic_weight * critical_tactic_flag
        )
        
        # Generate inclusion reason
        reasons = []
        if size >= 10:
            reasons.append(f"Large cluster ({size} alerts)")
        if mean_severity >= 0.7:
            reasons.append(f"High severity ({mean_severity:.2f})")
        if critical_tactic_flag > 0:
            reasons.append("Critical tactic detected")
        if critical_assets:
            reasons.append(f"Critical assets: {len(critical_assets)}")
        
        inclusion_reason = "; ".join(reasons) if reasons else "Standard cluster"
        
        return ClusterScore(
            cluster_id=cluster_id,
            size=size,
            mean_severity=mean_severity,
            max_severity=max_severity,
            tactics=tactics,
            techniques=techniques,
            critical_assets=critical_assets,
            importance_score=importance,
            inclusion_reason=inclusion_reason
        )
    
    def filter_clusters(
        self,
        df: pd.DataFrame,
        cluster_col: str = "pred_cluster"
    ) -> Tuple[pd.DataFrame, List[ClusterScore]]:
        """
        Filter clusters based on configured strategy and return
        both filtered DataFrame and cluster scores.
        
        Args:
            df: Correlated DataFrame with cluster assignments
            cluster_col: Column name containing cluster IDs
            
        Returns:
            Tuple of (filtered_df, cluster_scores)
        """
        if cluster_col not in df.columns:
            logger.warning(f"Cluster column '{cluster_col}' not found")
            return df, []
        
        # Compute scores for all clusters
        cluster_scores = []
        critical_tactics = self.config.target_tactics
        
        for cid, cluster_df in df.groupby(cluster_col):
            # Skip clusters below minimum size
            if len(cluster_df) < self.config.min_cluster_size:
                continue
                
            score = self.compute_importance_score(cid, cluster_df, critical_tactics)
            
            # Skip clusters below severity threshold
            if score.mean_severity < self.config.min_severity:
                continue
                
            # Skip clusters below importance threshold
            if score.importance_score < self.config.importance_threshold:
                continue
            
            cluster_scores.append(score)
        
        # Apply selection strategy
        cfg = self.config
        selected_ids = set()
        
        if cfg.selection_strategy == FilterStrategy.TOP_K_SIZE:
            sorted_scores = sorted(cluster_scores, key=lambda x: x.size, reverse=True)
            selected_ids = {s.cluster_id for s in sorted_scores[:cfg.top_k]}
            
        elif cfg.selection_strategy == FilterStrategy.TOP_K_SEVERITY:
            sorted_scores = sorted(
                cluster_scores, 
                key=lambda x: x.mean_severity, 
                reverse=True
            )
            selected_ids = {s.cluster_id for s in sorted_scores[:cfg.top_k]}
            
        elif cfg.selection_strategy == FilterStrategy.TOP_K_SCORE:
            sorted_scores = sorted(
                cluster_scores, 
                key=lambda x: x.importance_score, 
                reverse=True
            )
            selected_ids = {s.cluster_id for s in sorted_scores[:cfg.top_k]}
            
        elif cfg.selection_strategy == FilterStrategy.SEMANTIC:
            # Select clusters matching target tactics/techniques
            target_tactics = cfg.target_tactics or set()
            target_techniques = cfg.target_techniques or set()
            
            for score in cluster_scores:
                tactic_match = any(
                    t.lower() in target_tactics for t in score.tactics
                )
                technique_match = any(
                    t.lower() in target_techniques for t in score.techniques
                )
                if tactic_match or technique_match:
                    selected_ids.add(score.cluster_id)
                    
        elif cfg.selection_strategy == FilterStrategy.CRITICAL_ASSETS:
            # Select clusters with critical assets
            for score in cluster_scores:
                if score.critical_assets:
                    selected_ids.add(score.cluster_id)
        
        # Apply reservoir sampling for rare-but-critical tactics
        if cfg.enable_reservoir:
            selected_ids = self._apply_reservoir_sampling(
                df, cluster_scores, selected_ids, cfg.reservoir_size
            )
        
        # Filter DataFrame
        filtered_df = df[df[cluster_col].isin(selected_ids)].copy()
        
        # Add inclusion reasons to DataFrame
        reason_map = {s.cluster_id: s.inclusion_reason for s in cluster_scores}
        filtered_df["cluster_inclusion_reason"] = filtered_df[cluster_col].map(reason_map)
        
        # Add importance scores to DataFrame
        score_map = {s.cluster_id: s.importance_score for s in cluster_scores}
        filtered_df["cluster_importance_score"] = filtered_df[cluster_col].map(score_map)
        
        logger.info(
            f"Filtered {len(selected_ids)}/{df[cluster_col].nunique()} clusters "
            f"using {cfg.selection_strategy.value} strategy"
        )
        
        return filtered_df, [s for s in cluster_scores if s.cluster_id in selected_ids]
    
    def _apply_reservoir_sampling(
        self,
        df: pd.DataFrame,
        cluster_scores: List[ClusterScore],
        selected_ids: Set[int],
        reservoir_size: int
    ) -> Set[int]:
        """
        Implement reservoir sampling per tactic to ensure rare-but-critical
        chains are not dropped from visualization.
        
        Args:
            df: Full DataFrame
            cluster_scores: List of all cluster scores
            selected_ids: Currently selected cluster IDs
            reservoir_size: Maximum reservoir size per tactic
            
        Returns:
            Updated set of selected cluster IDs
        """
        # Group clusters by tactic
        tactic_clusters = defaultdict(list)
        for score in cluster_scores:
            if score.cluster_id not in selected_ids:
                for tactic in score.tactics:
                    tactic_clusters[tactic].append(score)
        
        # For each tactic with few selected clusters, add from reservoir
        for tactic, clusters in tactic_clusters.items():
            currently_selected = sum(
                1 for s in cluster_scores 
                if s.cluster_id in selected_ids and tactic in s.tactics
            )
            
            if currently_selected < 2:  # Threshold for "rare" tactic
                # Sort by importance and add top candidates
                candidates = sorted(
                    [c for c in clusters if c.cluster_id not in selected_ids],
                    key=lambda x: x.importance_score,
                    reverse=True
                )
                
                to_add = min(reservoir_size - currently_selected, len(candidates))
                for i in range(to_add):
                    selected_ids.add(candidates[i].cluster_id)
                    logger.debug(
                        f"Reservoir sampling: added cluster {candidates[i].cluster_id} "
                        f"for tactic '{tactic}'"
                    )
        
        return selected_ids
    
    def build_graph_data(
        self,
        df: pd.DataFrame,
        cluster_scores: Optional[List[ClusterScore]] = None,
        resolution: Optional[GraphResolution] = None
    ) -> Dict[str, Any]:
        """
        Build graph data at specified resolution tier.
        
        Multi-resolution views:
        (a) Campaign summary: hosts ↔ tactics
        (b) Entity ego-net: Focus on specific entity and neighbors
        (c) Alert drill-down: Raw alert details with full connections
        
        Args:
            df: Filtered DataFrame with cluster assignments
            cluster_scores: Optional pre-computed cluster scores
            resolution: Graph resolution tier (defaults to config)
            
        Returns:
            Graph data dictionary with nodes and edges
        """
        resolution = resolution or self.config.resolution
        
        if resolution == GraphResolution.CAMPAIGN_SUMMARY:
            return self._build_campaign_summary_graph(df, cluster_scores)
        elif resolution == GraphResolution.ENTITY_EGO_NET:
            return self._build_entity_ego_graph(df, cluster_scores)
        elif resolution == GraphResolution.ALERT_DRILL_DOWN:
            return self._build_alert_drill_graph(df, cluster_scores)
        else:
            raise ValueError(f"Unknown resolution: {resolution}")
    
    def _build_campaign_summary_graph(
        self,
        df: pd.DataFrame,
        cluster_scores: Optional[List[ClusterScore]] = None
    ) -> Dict[str, Any]:
        """
        Build campaign summary graph: hosts ↔ tactics.
        
        This is the highest-level view showing attack campaigns
        and their relationship to affected hosts.
        """
        nodes = []
        edges = []
        node_id_map = {}
        next_node_id = 0
        
        # Color palette for tactics
        tactic_colors = {
            "initial_access": "#ef4444",
            "execution": "#f97316",
            "persistence": "#f59e0b",
            "privilege_escalation": "#eab308",
            "defense_evasion": "#84cc16",
            "credential_access": "#22c55e",
            "discovery": "#10b981",
            "lateral_movement": "#14b8a6",
            "collection": "#06b6d4",
            "command_and_control": "#3b82f6",
            "exfiltration": "#6366f1",
            "impact": "#8b5cf6",
        }
        
        # Create tactic nodes
        all_tactics = set()
        for _, row in df.iterrows():
            if "MalwareIntelAttackType" in row:
                all_tactics.add(str(row["MalwareIntelAttackType"]))
            elif "AttackType" in row:
                all_tactics.add(str(row["AttackType"]))
        
        for tactic in all_tactics:
            node_id = next_node_id
            node_id_map[f"tactic:{tactic}"] = node_id
            next_node_id += 1
            
            # Determine color based on tactic name
            color = "#6b7280"  # Default gray
            for key, val in tactic_colors.items():
                if key in tactic.lower():
                    color = val
                    break
            
            nodes.append({
                "id": node_id,
                "label": tactic,
                "type": "tactic",
                "color": color,
                "size": 20
            })
        
        # Create host nodes and edges
        host_cluster_map = defaultdict(lambda: defaultdict(int))
        
        for _, row in df.iterrows():
            tactic = None
            if "MalwareIntelAttackType" in row:
                tactic = str(row["MalwareIntelAttackType"])
            elif "AttackType" in row:
                tactic = str(row["AttackType"])
            
            if not tactic:
                continue
            
            # Extract hosts
            for col in ["SourceHostName", "DestinationHostName", "DeviceHostName"]:
                if col in row and pd.notna(row[col]):
                    host = str(row[col])
                    host_cluster_map[host][tactic] += 1
        
        # Add host nodes
        for host, tactic_counts in host_cluster_map.items():
            node_id = next_node_id
            node_id_map[f"host:{host}"] = node_id
            next_node_id += 1
            
            # Size based on number of affected tactics
            size = 10 + min(30, len(tactic_counts) * 5)
            
            nodes.append({
                "id": node_id,
                "label": host,
                "type": "host",
                "color": "#3b82f6",
                "size": size
            })
            
            # Add edges to tactics
            for tactic, count in tactic_counts.items():
                tactic_node = node_id_map.get(f"tactic:{tactic}")
                if tactic_node is not None:
                    edges.append({
                        "source": node_id,
                        "target": tactic_node,
                        "weight": count,
                        "label": f"{count} alerts"
                    })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "resolution": "campaign_summary",
            "stats": {
                "tactic_nodes": len([n for n in nodes if n["type"] == "tactic"]),
                "host_nodes": len([n for n in nodes if n["type"] == "host"]),
                "total_edges": len(edges)
            }
        }
    
    def _build_entity_ego_graph(
        self,
        df: pd.DataFrame,
        cluster_scores: Optional[List[ClusterScore]] = None,
        focus_entity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build entity ego-network: Focus on specific entity and neighbors.
        
        Shows a subgraph centered on a specific host, IP, or user,
        with immediate neighbors and their relationships.
        """
        nodes = []
        edges = []
        node_id_map = {}
        next_node_id = 0
        
        # If no focus entity specified, use the host with most alerts
        if not focus_entity:
            host_counts = defaultdict(int)
            for col in ["SourceHostName", "DestinationHostName", "DeviceHostName"]:
                if col in df.columns:
                    for host in df[col].dropna():
                        host_counts[host] += 1
            if host_counts:
                focus_entity = max(host_counts, key=host_counts.get)
        
        if not focus_entity:
            return {"nodes": [], "edges": [], "resolution": "entity_ego_net"}
        
        # Create focus node
        focus_id = next_node_id
        node_id_map[f"host:{focus_entity}"] = focus_id
        next_node_id += 1
        
        nodes.append({
            "id": focus_id,
            "label": focus_entity,
            "type": "focus_host",
            "color": "#ef4444",
            "size": 30
        })
        
        # Find related entities
        related_ips = defaultdict(int)
        related_users = defaultdict(int)
        related_alerts = []
        
        for _, row in df.iterrows():
            is_related = False
            
            # Check if row involves focus entity
            for col in ["SourceHostName", "DestinationHostName", "DeviceHostName"]:
                if col in row and str(row[col]) == focus_entity:
                    is_related = True
                    break
            
            if is_related:
                # Extract related IPs
                for col in ["SourceAddress", "DestinationAddress", "DeviceAddress"]:
                    if col in row and pd.notna(row[col]):
                        related_ips[str(row[col])] += 1
                
                # Extract related users
                for col in ["SourceUserName", "DestinationUserName"]:
                    if col in row and pd.notna(row[col]):
                        related_users[str(row[col])] += 1
                
                related_alerts.append(row.to_dict())
        
        # Add IP nodes
        for ip, count in related_ips.items():
            node_id = next_node_id
            node_id_map[f"ip:{ip}"] = node_id
            next_node_id += 1
            
            nodes.append({
                "id": node_id,
                "label": ip,
                "type": "ip",
                "color": "#3b82f6",
                "size": 10 + min(20, count)
            })
            
            edges.append({
                "source": focus_id,
                "target": node_id,
                "weight": count
            })
        
        # Add user nodes
        for user, count in related_users.items():
            node_id = next_node_id
            node_id_map[f"user:{user}"] = node_id
            next_node_id += 1
            
            nodes.append({
                "id": node_id,
                "label": user,
                "type": "user",
                "color": "#10b981",
                "size": 10 + min(20, count)
            })
            
            edges.append({
                "source": focus_id,
                "target": node_id,
                "weight": count
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "resolution": "entity_ego_net",
            "focus_entity": focus_entity,
            "stats": {
                "related_ips": len(related_ips),
                "related_users": len(related_users),
                "related_alerts": len(related_alerts)
            }
        }
    
    def _build_alert_drill_graph(
        self,
        df: pd.DataFrame,
        cluster_scores: Optional[List[ClusterScore]] = None
    ) -> Dict[str, Any]:
        """
        Build raw alert drill-down graph with full connections.
        
        This is the most detailed view showing individual alerts
        and their direct relationships.
        """
        nodes = []
        edges = []
        
        # Assign colors per cluster
        unique_clusters = sorted(df["pred_cluster"].unique()) if "pred_cluster" in df.columns else []
        palette = [
            "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
            "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
        ]
        color_map = {c: palette[i % len(palette)] for i, c in enumerate(unique_clusters)}
        
        # Create alert nodes
        for idx, row in df.iterrows():
            cluster_id = int(row.get("pred_cluster", 0))
            
            label_parts = [f"Alert {idx}"]
            if "MalwareIntelAttackType" in row:
                label_parts.append(str(row["MalwareIntelAttackType"]))
            elif "AttackType" in row:
                label_parts.append(str(row["AttackType"]))
            
            nodes.append({
                "id": int(idx),
                "label": " | ".join(label_parts),
                "cluster": cluster_id,
                "color": color_map.get(cluster_id, "#999"),
                "type": "alert",
                "data": {k: str(v) for k, v in row.items()}
            })
        
        # Create edges within clusters
        if "pred_cluster" in df.columns:
            for c_id in unique_clusters:
                members = df[df["pred_cluster"] == c_id].index.tolist()
                for i in range(len(members) - 1):
                    edges.append({
                        "source": int(members[i]),
                        "target": int(members[i + 1]),
                        "type": "cluster_link"
                    })
        
        # Create edges based on shared attributes
        entity_to_alerts = defaultdict(list)
        
        for idx, row in df.iterrows():
            # IP-based edges
            for col in ["SourceAddress", "DestinationAddress", "DeviceAddress"]:
                if col in row and pd.notna(row[col]):
                    entity_to_alerts[f"ip:{row[col]}"].append(int(idx))
            
            # Host-based edges
            for col in ["SourceHostName", "DestinationHostName", "DeviceHostName"]:
                if col in row and pd.notna(row[col]):
                    entity_to_alerts[f"host:{row[col]}"].append(int(idx))
        
        # Add entity-based edges
        for entity, alert_ids in entity_to_alerts.items():
            for i in range(len(alert_ids)):
                for j in range(i + 1, min(i + 5, len(alert_ids))):  # Limit to 4 edges per alert
                    edges.append({
                        "source": alert_ids[i],
                        "target": alert_ids[j],
                        "type": "entity_link",
                        "entity": entity
                    })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "resolution": "alert_drill_down",
            "stats": {
                "total_alerts": len(nodes),
                "total_edges": len(edges),
                "clusters": len(unique_clusters)
            }
        }
    
    def get_summary_stats(
        self,
        df: pd.DataFrame,
        cluster_scores: List[ClusterScore]
    ) -> Dict[str, Any]:
        """
        Generate summary statistics for clusters not visualized.
        
        Returns statistics about clusters that were filtered out,
        ensuring analysts still have visibility into overall data.
        """
        total_clusters = df["pred_cluster"].nunique() if "pred_cluster" in df.columns else 0
        selected_clusters = len(cluster_scores)
        
        all_sizes = [s.size for s in cluster_scores]
        all_severities = [s.mean_severity for s in cluster_scores]
        
        # Collect all tactics
        all_tactics = set()
        for s in cluster_scores:
            all_tactics.update(s.tactics)
        
        return {
            "total_clusters": total_clusters,
            "visualized_clusters": selected_clusters,
            "filtered_clusters": total_clusters - selected_clusters,
            "average_cluster_size": np.mean(all_sizes) if all_sizes else 0,
            "max_cluster_size": max(all_sizes) if all_sizes else 0,
            "average_severity": np.mean(all_severities) if all_severities else 0,
            "max_severity": max(all_severities) if all_severities else 0,
            "unique_tactics": list(all_tactics),
            "critical_asset_count": sum(len(s.critical_assets) for s in cluster_scores),
        }


def create_cluster_filter(
    top_k: int = 20,
    strategy: str = "top_k_score",
    target_tactics: Optional[List[str]] = None,
    critical_assets: Optional[List[str]] = None,
    resolution: str = "campaign_summary"
) -> ClusterFilter:
    """
    Factory function to create a pre-configured ClusterFilter.
    
    Args:
        top_k: Number of top clusters to select
        strategy: Selection strategy (top_k_size, top_k_severity, top_k_score, semantic, critical_assets)
        target_tactics: List of MITRE tactics to prioritize
        critical_assets: List of asset patterns to flag as critical
        resolution: Graph resolution tier
        
    Returns:
        Configured ClusterFilter instance
    """
    config = FilterConfig(
        top_k=top_k,
        selection_strategy=FilterStrategy(strategy),
        target_tactics=set(t.lower() for t in (target_tactics or [])),
        critical_asset_patterns=critical_assets,
        resolution=GraphResolution(resolution)
    )
    
    return ClusterFilter(config)
