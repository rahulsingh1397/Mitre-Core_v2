"""
MITRE-CORE Knowledge Graph Enrichment Module
===============================================

Implements knowledge-graph enrichment by ingesting threat intelligence
(CVE, ATT&CK, malware families) and linking correlated clusters to known
campaigns. Ranks severity via graph metrics (PageRank/betweenness).

Inspired by:
- CyGraph: Graph-Based Analytics for Cybersecurity (MITRE)
- GraphWeaver: Billion-Scale Correlation (Microsoft)
- Cybersecurity Knowledge Graphs research

Key Features:
- Threat intel ingestion (CVE, ATT&CK, malware families)
- Graph metrics for severity ranking (PageRank, betweenness)
- Campaign linkage for correlated clusters
- Foundation for future Neo4j/RDF integration
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
import numpy as np
import pandas as pd

logger = logging.getLogger("mitre-core.kg_enrichment")


@dataclass
class ThreatIntelEntity:
    """Container for threat intelligence entity."""
    entity_id: str
    entity_type: str  # cve, technique, malware, campaign, apt_group
    name: str
    description: str = ""
    severity_score: float = 0.0  # CVSS for CVEs, custom for others
    mitre_tactics: List[str] = field(default_factory=list)
    related_entities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClusterEnrichment:
    """Enrichment data for a correlated cluster."""
    cluster_id: int
    matched_entities: List[ThreatIntelEntity] = field(default_factory=list)
    campaign_linkage: Optional[str] = None
    pagerank_score: float = 0.0
    betweenness_score: float = 0.0
    combined_threat_score: float = 0.0
    enrichment_summary: str = ""


class ThreatIntelStore:
    """
    In-memory store for threat intelligence entities.
    
    Provides fast lookup for enrichment operations.
    Can be extended to use Neo4j or other graph database.
    """
    
    def __init__(self):
        self._entities: Dict[str, ThreatIntelEntity] = {}
        self._by_type: Dict[str, List[str]] = defaultdict(list)
        self._by_name: Dict[str, List[str]] = defaultdict(list)
        self._by_tactic: Dict[str, List[str]] = defaultdict(list)
    
    def add_entity(self, entity: ThreatIntelEntity) -> None:
        """Add entity to store with indexing."""
        self._entities[entity.entity_id] = entity
        self._by_type[entity.entity_type].append(entity.entity_id)
        self._by_name[entity.name.lower()].append(entity.entity_id)
        
        for tactic in entity.mitre_tactics:
            self._by_tactic[tactic.lower()].append(entity.entity_id)
    
    def get_entity(self, entity_id: str) -> Optional[ThreatIntelEntity]:
        """Retrieve entity by ID."""
        return self._entities.get(entity_id)
    
    def find_by_name(self, name: str) -> List[ThreatIntelEntity]:
        """Find entities by name (case-insensitive)."""
        entity_ids = self._by_name.get(name.lower(), [])
        return [self._entities[eid] for eid in entity_ids]
    
    def find_by_tactic(self, tactic: str) -> List[ThreatIntelEntity]:
        """Find entities associated with a MITRE tactic."""
        entity_ids = self._by_tactic.get(tactic.lower(), [])
        return [self._entities[eid] for eid in entity_ids]
    
    def find_by_type(self, entity_type: str) -> List[ThreatIntelEntity]:
        """Find all entities of a given type."""
        entity_ids = self._by_type.get(entity_type, [])
        return [self._entities[eid] for eid in entity_ids]
    
    def load_mitre_attack(self, tactics_file: Optional[str] = None) -> None:
        """
        Load MITRE ATT&CK tactics and techniques.
        
        Args:
            tactics_file: Path to MITRE ATT&CK JSON file
        """
        # Load from file if provided
        if tactics_file and Path(tactics_file).exists():
            with open(tactics_file, 'r') as f:
                data = json.load(f)
                for technique in data.get("techniques", []):
                    entity = ThreatIntelEntity(
                        entity_id=f"technique:{technique['id']}",
                        entity_type="technique",
                        name=technique["name"],
                        description=technique.get("description", ""),
                        severity_score=self._calculate_technique_severity(technique),
                        mitre_tactics=technique.get("tactics", []),
                        metadata={
                            "url": technique.get("url", ""),
                            "platforms": technique.get("platforms", [])
                        }
                    )
                    self.add_entity(entity)
            logger.info(f"Loaded {len(data.get('techniques', []))} MITRE techniques")
        else:
            # Load minimal default set
            self._load_default_mitre_data()
    
    def _load_default_mitre_data(self) -> None:
        """Load minimal default MITRE ATT&CK data."""
        default_techniques = [
            {
                "id": "T1566", "name": "Phishing", "tactics": ["initial_access"],
                "severity": 0.7
            },
            {
                "id": "T1059", "name": "Command and Scripting Interpreter", 
                "tactics": ["execution"], "severity": 0.6
            },
            {
                "id": "T1053", "name": "Scheduled Task/Job", "tactics": ["execution", "persistence"],
                "severity": 0.5
            },
            {
                "id": "T1078", "name": "Valid Accounts", "tactics": ["persistence", "privilege_escalation"],
                "severity": 0.8
            },
            {
                "id": "T1098", "name": "Account Manipulation", "tactics": ["persistence"],
                "severity": 0.7
            },
            {
                "id": "T1110", "name": "Brute Force", "tactics": ["credential_access"],
                "severity": 0.6
            },
            {
                "id": "T1021", "name": "Remote Services", "tactics": ["lateral_movement"],
                "severity": 0.7
            },
            {
                "id": "T1041", "name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"],
                "severity": 0.8
            },
            {
                "id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"],
                "severity": 0.9
            },
            {
                "id": "T1567", "name": "Exfiltration Over Web Service", "tactics": ["exfiltration"],
                "severity": 0.8
            },
        ]
        
        for tech in default_techniques:
            entity = ThreatIntelEntity(
                entity_id=f"technique:{tech['id']}",
                entity_type="technique",
                name=tech["name"],
                severity_score=tech["severity"],
                mitre_tactics=tech["tactics"]
            )
            self.add_entity(entity)
        
        logger.info(f"Loaded {len(default_techniques)} default MITRE techniques")
    
    def _calculate_technique_severity(self, technique: Dict) -> float:
        """Calculate severity score for a MITRE technique."""
        # Base severity on tactic criticality
        tactic_weights = {
            "initial_access": 0.8,
            "execution": 0.7,
            "persistence": 0.8,
            "privilege_escalation": 0.9,
            "defense_evasion": 0.8,
            "credential_access": 0.9,
            "discovery": 0.5,
            "lateral_movement": 0.8,
            "collection": 0.6,
            "command_and_control": 0.7,
            "exfiltration": 0.9,
            "impact": 0.9
        }
        
        tactics = technique.get("tactics", [])
        if tactics:
            return max(tactic_weights.get(t.lower(), 0.5) for t in tactics)
        return 0.5
    
    def load_cve_data(self, cve_file: Optional[str] = None) -> None:
        """
        Load CVE (Common Vulnerabilities and Exposures) data.
        
        Args:
            cve_file: Path to CVE JSON file
        """
        if cve_file and Path(cve_file).exists():
            with open(cve_file, 'r') as f:
                data = json.load(f)
                for cve in data.get("cves", []):
                    cvss = cve.get("cvss", {})
                    severity = cvss.get("base_score", 0.0) / 10.0  # Normalize to 0-1
                    
                    entity = ThreatIntelEntity(
                        entity_id=f"cve:{cve['id']}",
                        entity_type="cve",
                        name=cve["id"],
                        description=cve.get("description", ""),
                        severity_score=severity,
                        metadata={
                            "cvss_score": cvss.get("base_score", 0.0),
                            "cvss_vector": cvss.get("vector_string", ""),
                            "published": cve.get("published", "")
                        }
                    )
                    self.add_entity(entity)
            logger.info(f"Loaded {len(data.get('cves', []))} CVEs")
        else:
            logger.info("No CVE data file provided, skipping CVE ingestion")
    
    def load_malware_families(self, malware_file: Optional[str] = None) -> None:
        """
        Load malware family data.
        
        Args:
            malware_file: Path to malware families JSON file
        """
        if malware_file and Path(malware_file).exists():
            with open(malware_file, 'r') as f:
                data = json.load(f)
                for malware in data.get("malware", []):
                    entity = ThreatIntelEntity(
                        entity_id=f"malware:{malware['name']}",
                        entity_type="malware",
                        name=malware["name"],
                        description=malware.get("description", ""),
                        severity_score=malware.get("severity", 0.5),
                        mitre_tactics=malware.get("tactics", []),
                        related_entities=[f"apt:{apt}" for apt in malware.get("apt_groups", [])],
                        metadata={
                            "aliases": malware.get("aliases", []),
                            "first_seen": malware.get("first_seen", "")
                        }
                    )
                    self.add_entity(entity)
            logger.info(f"Loaded {len(data.get('malware', []))} malware families")
        else:
            logger.info("No malware data file provided, loading defaults")
            self._load_default_malware_data()
    
    def _load_default_malware_data(self) -> None:
        """Load default malware family data."""
        default_malware = [
            {
                "name": "Emotet", "severity": 0.8, 
                "tactics": ["initial_access", "execution", "persistence"],
                "apt_groups": ["TA542"]
            },
            {
                "name": "TrickBot", "severity": 0.85,
                "tactics": ["execution", "persistence", "credential_access"],
                "apt_groups": ["WizardSpider"]
            },
            {
                "name": "CobaltStrike", "severity": 0.75,
                "tactics": ["execution", "command_and_control", "lateral_movement"],
                "apt_groups": ["WizardSpider", "APT29"]
            },
            {
                "name": "Ryuk", "severity": 0.9,
                "tactics": ["impact"],
                "apt_groups": ["WizardSpider"]
            },
            {
                "name": "QakBot", "severity": 0.8,
                "tactics": ["initial_access", "execution", "persistence"],
                "apt_groups": []
            },
        ]
        
        for malware in default_malware:
            entity = ThreatIntelEntity(
                entity_id=f"malware:{malware['name']}",
                entity_type="malware",
                name=malware["name"],
                severity_score=malware["severity"],
                mitre_tactics=malware["tactics"],
                related_entities=[f"apt:{apt}" for apt in malware.get("apt_groups", [])]
            )
            self.add_entity(entity)


class KnowledgeGraphEnricher:
    """
    Enriches correlated clusters with knowledge graph data.
    
    Implements:
    - Entity matching between alerts and threat intel
    - Graph metric computation (PageRank, betweenness)
    - Campaign linkage detection
    - Combined threat scoring
    """
    
    def __init__(self, threat_store: Optional[ThreatIntelStore] = None):
        self.threat_store = threat_store or ThreatIntelStore()
        self._entity_graph: Optional[Dict] = None
    
    def enrich_clusters(
        self,
        df: pd.DataFrame,
        cluster_col: str = "pred_cluster"
    ) -> Tuple[pd.DataFrame, List[ClusterEnrichment]]:
        """
        Enrich clusters with threat intelligence and graph metrics.
        
        Args:
            df: Correlated DataFrame with cluster assignments
            cluster_col: Column name containing cluster IDs
            
        Returns:
            Tuple of (enriched_df, cluster_enrichments)
        """
        enrichments = []
        
        if cluster_col not in df.columns:
            logger.warning(f"Cluster column '{cluster_col}' not found")
            return df, enrichments
        
        # Build entity graph for graph metrics
        self._entity_graph = self._build_entity_graph(df)
        
        # Compute graph metrics
        pagerank = self._compute_pagerank(self._entity_graph)
        betweenness = self._compute_betweenness(self._entity_graph)
        
        # Enrich each cluster
        for cid, cluster_df in df.groupby(cluster_col):
            enrichment = self._enrich_single_cluster(
                cid, cluster_df, pagerank, betweenness
            )
            enrichments.append(enrichment)
        
        # Add enrichment data to DataFrame
        enrichment_map = {e.cluster_id: e for e in enrichments}
        
        df = df.copy()
        df["threat_score"] = df[cluster_col].map(
            lambda x: enrichment_map.get(x, ClusterEnrichment(x)).combined_threat_score
        )
        df["campaign_linkage"] = df[cluster_col].map(
            lambda x: enrichment_map.get(x, ClusterEnrichment(x)).campaign_linkage or ""
        )
        df["pagerank_score"] = df[cluster_col].map(
            lambda x: enrichment_map.get(x, ClusterEnrichment(x)).pagerank_score
        )
        
        return df, enrichments
    
    def _enrich_single_cluster(
        self,
        cluster_id: int,
        cluster_df: pd.DataFrame,
        pagerank: Dict[str, float],
        betweenness: Dict[str, float]
    ) -> ClusterEnrichment:
        """Enrich a single cluster with threat intel."""
        enrichment = ClusterEnrichment(cluster_id=cluster_id)
        
        # Match entities in alerts
        matched_entities = []
        
        for _, row in cluster_df.iterrows():
            # Check attack types
            for col in ["MalwareIntelAttackType", "AttackType", "alert_type"]:
                if col in row and pd.notna(row[col]):
                    attack_type = str(row[col]).lower()
                    
                    # Match techniques
                    entities = self.threat_store.find_by_name(attack_type)
                    matched_entities.extend(entities)
                    
                    # Match by tactic
                    tactic_entities = self.threat_store.find_by_tactic(attack_type)
                    matched_entities.extend(tactic_entities)
            
            # Check for malware indicators
            for col in ["ProcessName", "FileName", "Hash"]:
                if col in row and pd.notna(row[col]):
                    value = str(row[col]).lower()
                    for malware in self.threat_store.find_by_type("malware"):
                        if malware.name.lower() in value:
                            matched_entities.append(malware)
        
        # Remove duplicates
        seen_ids = set()
        enrichment.matched_entities = []
        for entity in matched_entities:
            if entity.entity_id not in seen_ids:
                seen_ids.add(entity.entity_id)
                enrichment.matched_entities.append(entity)
        
        # Calculate graph metrics for this cluster
        cluster_entities = set()
        for _, row in cluster_df.iterrows():
            for col in ["SourceAddress", "DestinationAddress", "SourceHostName"]:
                if col in row and pd.notna(row[col]):
                    cluster_entities.add(f"{col}:{row[col]}")
        
        enrichment.pagerank_score = max(
            (pagerank.get(e, 0.0) for e in cluster_entities),
            default=0.0
        )
        enrichment.betweenness_score = max(
            (betweenness.get(e, 0.0) for e in cluster_entities),
            default=0.0
        )
        
        # Detect campaign linkage
        apt_groups = set()
        for entity in enrichment.matched_entities:
            apt_groups.update(
                e.replace("apt:", "") for e in entity.related_entities if e.startswith("apt:")
            )
        
        if apt_groups:
            enrichment.campaign_linkage = ", ".join(sorted(apt_groups))
        
        # Calculate combined threat score
        entity_severities = [e.severity_score for e in enrichment.matched_entities]
        avg_entity_severity = np.mean(entity_severities) if entity_severities else 0.0
        
        enrichment.combined_threat_score = (
            0.4 * avg_entity_severity +
            0.4 * enrichment.pagerank_score +
            0.2 * enrichment.betweenness_score
        )
        
        # Generate enrichment summary
        parts = []
        if enrichment.matched_entities:
            parts.append(f"{len(enrichment.matched_entities)} threat intel matches")
        if enrichment.campaign_linkage:
            parts.append(f"Linked to: {enrichment.campaign_linkage}")
        if enrichment.pagerank_score > 0.1:
            parts.append(f"High centrality (PR={enrichment.pagerank_score:.2f})")
        
        enrichment.enrichment_summary = "; ".join(parts) if parts else "No threat intel match"
        
        return enrichment
    
    def _build_entity_graph(self, df: pd.DataFrame) -> Dict:
        """
        Build entity relationship graph from alert data.
        
        Returns graph structure: {nodes: set, edges: list of (src, dst)}
        """
        graph = {
            "nodes": set(),
            "edges": [],
            "adjacency": defaultdict(set)
        }
        
        # Add entities and edges
        for _, row in df.iterrows():
            entities_in_row = []
            
            # Extract all entities from row
            for col in ["SourceAddress", "DestinationAddress", "DeviceAddress"]:
                if col in row and pd.notna(row[col]):
                    entity_id = f"ip:{row[col]}"
                    entities_in_row.append(entity_id)
                    graph["nodes"].add(entity_id)
            
            for col in ["SourceHostName", "DestinationHostName", "DeviceHostName"]:
                if col in row and pd.notna(row[col]):
                    entity_id = f"host:{row[col]}"
                    entities_in_row.append(entity_id)
                    graph["nodes"].add(entity_id)
            
            for col in ["SourceUserName", "DestinationUserName"]:
                if col in row and pd.notna(row[col]):
                    entity_id = f"user:{row[col]}"
                    entities_in_row.append(entity_id)
                    graph["nodes"].add(entity_id)
            
            # Create edges between all entities in this row
            for i, src in enumerate(entities_in_row):
                for dst in entities_in_row[i+1:]:
                    graph["edges"].append((src, dst))
                    graph["adjacency"][src].add(dst)
                    graph["adjacency"][dst].add(src)
        
        return graph
    
    def _compute_pagerank(self, graph: Dict, damping: float = 0.85, iterations: int = 20) -> Dict[str, float]:
        """
        Compute PageRank scores for graph nodes.
        
        PageRank identifies important nodes based on connectivity.
        High PageRank indicates critical assets in the attack graph.
        """
        nodes = list(graph["nodes"])
        if not nodes:
            return {}
        
        n = len(nodes)
        pagerank = {node: 1.0 / n for node in nodes}
        adjacency = graph["adjacency"]
        
        for _ in range(iterations):
            new_pagerank = {}
            for node in nodes:
                # Sum contributions from neighbors
                contribution = 0.0
                for neighbor in adjacency[node]:
                    if neighbor in pagerank and len(adjacency[neighbor]) > 0:
                        contribution += pagerank[neighbor] / len(adjacency[neighbor])
                
                new_pagerank[node] = (1 - damping) / n + damping * contribution
            
            pagerank = new_pagerank
        
        # Normalize
        max_pr = max(pagerank.values()) if pagerank else 1.0
        return {k: v / max_pr for k, v in pagerank.items()}
    
    def _compute_betweenness(self, graph: Dict) -> Dict[str, float]:
        """
        Compute approximate betweenness centrality.
        
        Betweenness identifies bridge nodes that connect different
        parts of the attack graph. High betweenness indicates
        pivot points in lateral movement.
        
        Uses Brandes' algorithm approximation for efficiency.
        """
        nodes = list(graph["nodes"])
        if not nodes:
            return {}
        
        betweenness = {node: 0.0 for node in nodes}
        adjacency = graph["adjacency"]
        
        # Sample from nodes for efficiency (approximate)
        sample_size = min(100, len(nodes))
        sample_nodes = np.random.choice(nodes, size=sample_size, replace=False)
        
        for source in sample_nodes:
            # BFS from source
            distance = {node: -1 for node in nodes}
            paths = {node: 0 for node in nodes}
            queue = [source]
            distance[source] = 0
            paths[source] = 1
            
            order = []
            while queue:
                v = queue.pop(0)
                order.append(v)
                for w in adjacency[v]:
                    if distance[w] < 0:
                        queue.append(w)
                        distance[w] = distance[v] + 1
                    if distance[w] == distance[v] + 1:
                        paths[w] += paths[v]
            
            # Accumulate dependencies
            dependency = {node: 0.0 for node in nodes}
            while order:
                w = order.pop()
                for v in adjacency[w]:
                    if distance[v] == distance[w] - 1:
                        dependency[v] += (paths[v] / paths[w]) * (1 + dependency[w])
                
                if w != source:
                    betweenness[w] += dependency[w]
        
        # Normalize
        max_b = max(betweenness.values()) if betweenness else 1.0
        if max_b == 0:
            return {k: 0.0 for k in betweenness}
        return {k: v / max_b for k, v in betweenness.items()}
    
    def get_threat_summary(self, enrichments: List[ClusterEnrichment]) -> Dict[str, Any]:
        """
        Generate summary of threat intelligence findings.
        """
        total_matches = sum(len(e.matched_entities) for e in enrichments)
        linked_campaigns = set()
        high_threat_clusters = []
        
        for e in enrichments:
            if e.campaign_linkage:
                linked_campaigns.update(e.campaign_linkage.split(", "))
            if e.combined_threat_score > 0.7:
                high_threat_clusters.append({
                    "cluster_id": e.cluster_id,
                    "threat_score": e.combined_threat_score,
                    "campaign": e.campaign_linkage,
                    "matched_entities": [ent.name for ent in e.matched_entities[:3]]
                })
        
        return {
            "total_threat_matches": total_matches,
            "linked_campaigns": list(linked_campaigns),
            "high_threat_clusters": high_threat_clusters,
            "average_threat_score": np.mean([e.combined_threat_score for e in enrichments]) if enrichments else 0.0,
            "max_threat_score": max((e.combined_threat_score for e in enrichments), default=0.0)
        }


def create_enricher(
    mitre_file: Optional[str] = None,
    cve_file: Optional[str] = None,
    malware_file: Optional[str] = None
) -> KnowledgeGraphEnricher:
    """
    Factory function to create a configured KnowledgeGraphEnricher.
    
    Args:
        mitre_file: Path to MITRE ATT&CK JSON
        cve_file: Path to CVE JSON
        malware_file: Path to malware families JSON
        
    Returns:
        Configured KnowledgeGraphEnricher
    """
    store = ThreatIntelStore()
    store.load_mitre_attack(mitre_file)
    store.load_cve_data(cve_file)
    store.load_malware_families(malware_file)
    
    return KnowledgeGraphEnricher(store)
