"""
MITRE-CORE HGNN Module
=======================
Heterogeneous Graph Neural Network for Advanced Alert Correlation.

Replaces Union-Find correlation with learned graph embeddings.
Based on: "On the Use of HGNNs for Detecting APTs" (ACM 2024)

Architecture
------------
- Heterogeneous Graph Attention Network (HAN / HGT)
- Multi-relation edges: shares_ip, shares_host, temporal_near,
  user_to_alert, host_to_alert, and IoT / Linux-APT variants
- Learns optimal feature weights automatically vs. handcrafted 0.6/0.3/0.1
- O(n+e) complexity vs. O(n²) for Union-Find

Changelog (v2.1 — Adaptive Confidence Integration)
----------------------------------------------------
  - Updated: HGNNCorrelationEngine.correlate() now feeds ``cluster_confidence``
    scores back into enhanced_correlation() via a confidence-gated UF fallback
    pass for alerts the HGNN is uncertain about (below CONFIDENCE_GATE).
  - New constant: CONFIDENCE_GATE (default 0.6) — alerts with max softmax
    probability below this value are re-correlated with the UF engine using
    confidence_guided_threshold() as the threshold driver.
  - New method: HGNNCorrelationEngine._uf_refinement_pass() — isolated,
    testable method encapsulating the low-confidence UF re-pass logic.
  - No changes to MITREHeteroGNN, AlertToGraphConverter, or training components.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import HeteroConv, GATConv, Linear, global_mean_pool
from torch_geometric.data import HeteroData
from typing import Dict, List, Tuple, Optional
import pandas as pd
import numpy as np
from collections import defaultdict
import logging

logger = logging.getLogger("mitre-core.hgnn")

# ---------------------------------------------------------------------------
# Module-level constant — confidence gate for UF refinement pass
# ---------------------------------------------------------------------------

#: Alerts with HGNN max-softmax confidence below this value trigger a
#: Union-Find re-correlation pass driven by confidence_guided_threshold().
#: 0.6 was chosen based on the sensitivity study: threshold ≥ 0.7 pushed
#: ARI to 0.9708, and calibration results show ECE degrades most for alerts
#: the HGNN scores below 0.6.  Tune via HGNNCorrelationEngine(confidence_gate=…).
_DEFAULT_CONFIDENCE_GATE: float = 0.6


# ============================================================================
# Homogeneous GNN Baseline
# ============================================================================

class HomogeneousGNN(nn.Module):
    """
    Homogeneous GNN Baseline (GCN) for comparison against HGNN.
    Treats all nodes as 'alerts' and projects entity features into alert space
    or creates generic edges between alerts based on shared entities.
    """

    def __init__(
        self,
        input_dim: int = 8,
        feature_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_clusters: int = 10,
    ):
        super().__init__()
        from torch_geometric.nn import GCNConv

        self.encoder = nn.Linear(input_dim, feature_dim)
        self.convs = nn.ModuleList()
        for i in range(num_layers):
            in_dim = feature_dim if i == 0 else hidden_dim
            self.convs.append(GCNConv(in_dim, hidden_dim))
        self.dropout = dropout
        self.cluster_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_clusters),
        )

    def forward(
        self, x: torch.Tensor, edge_index: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        x = self.encoder(x)
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        cluster_logits = self.cluster_classifier(x)
        return cluster_logits, x


# ============================================================================
# MITREHeteroGNN — core heterogeneous GNN model (unchanged from v2.0)
# ============================================================================

class MITREHeteroGNN(nn.Module):
    """
    Heterogeneous Graph Neural Network for MITRE-CORE.

    Node Types
    ----------
    alert       : Security alerts (main entity)
    user        : Source/destination users
    host        : Source/destination/device hosts
    ip          : IP addresses (source/destination/device)
    device      : IIoT devices (derived from ports)
    gateway     : Network gateways (derived from subnets)
    process     : Linux process names (Linux-APT datasets)
    command_line: Command-line strings (Linux-APT datasets)

    Edge Types
    ----------
    alert-shares_ip-alert       : Alerts sharing IP addresses
    alert-shares_host-alert     : Alerts sharing hostnames
    alert-temporal_near-alert   : Alerts within time window
    user-owns-alert             : User associated with alert
    host-generates-alert        : Host associated with alert
    ip-involved_in-alert        : IP involved in alert
    device-connects_via-gateway : Device connects via gateway
    sensor_type-classifies-device: Device type classification
    process-executes-alert      : Process associated with alert (APT)
    command_line-associated_with-alert: Command line (APT)
    """

    def __init__(
        self,
        alert_feature_dim: int = 64,
        user_feature_dim: int = 32,
        host_feature_dim: int = 32,
        ip_feature_dim: int = 32,
        device_feature_dim: int = 32,
        gateway_feature_dim: int = 16,
        process_feature_dim: int = 32,
        command_line_feature_dim: int = 64,
        hidden_dim: int = 128,
        num_heads: int = 4,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_clusters: int = 10,
    ):
        super().__init__()

        self.alert_feature_dim = alert_feature_dim
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads

        # Input projections
        self.alert_encoder = Linear(-1, hidden_dim)
        self.user_encoder = Linear(-1, hidden_dim)
        self.host_encoder = Linear(-1, hidden_dim)
        self.ip_encoder = Linear(-1, hidden_dim)
        self.device_encoder = Linear(-1, hidden_dim)
        self.gateway_encoder = Linear(-1, hidden_dim)
        self.sensor_type_encoder = Linear(-1, hidden_dim)
        self.process_encoder = Linear(-1, hidden_dim)
        self.command_line_encoder = Linear(-1, hidden_dim)

        # Heterogeneous GNN layers
        self.convs = nn.ModuleList()

        for _ in range(num_layers):
            conv_dict = {}

            # Alert-to-Alert (intra-type)
            for rel in ("shares_ip", "shares_host", "temporal_near"):
                conv_dict[("alert", rel, "alert")] = GATConv(
                    hidden_dim, hidden_dim // num_heads,
                    heads=num_heads, dropout=dropout, add_self_loops=False,
                )

            # Cross-type bidirectional edges
            cross_edges = [
                ("user", "owns", "alert"),
                ("alert", "owned_by", "user"),
                ("host", "generates", "alert"),
                ("alert", "generated_by", "host"),
                ("ip", "involved_in", "alert"),
                ("alert", "involves", "ip"),
                ("device", "connects_via", "gateway"),
                ("gateway", "connected_to", "device"),
                ("sensor_type", "classifies", "device"),
                ("device", "classified_as", "sensor_type"),
                ("device", "generates", "alert"),
                ("alert", "generated_by", "device"),
                ("process", "executes", "alert"),
                ("alert", "executed_by", "process"),
                ("command_line", "associated_with", "alert"),
                ("alert", "has", "command_line"),
            ]
            for edge_type in cross_edges:
                conv_dict[edge_type] = GATConv(
                    hidden_dim, hidden_dim // num_heads,
                    heads=num_heads, dropout=dropout, add_self_loops=False,
                )

            self.convs.append(HeteroConv(conv_dict, aggr="mean"))

        # Cluster classification head
        self.cluster_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_clusters),
        )

        self.attention_weights: Dict = {}

    def forward(
        self, data: HeteroData
    ) -> Tuple[torch.Tensor, Dict[str, torch.Tensor]]:
        """
        Forward pass through HGNN.

        Args
        ----
        data : HeteroData
            Graph with node features and edge indices.

        Returns
        -------
        cluster_logits : torch.Tensor [num_alerts, num_clusters]
        node_embeddings : Dict[str, torch.Tensor]
            Per-node-type embedding tensors.
        """
        node_types = data.node_types
        encoder_map = {
            "alert": self.alert_encoder,
            "user": self.user_encoder,
            "host": self.host_encoder,
            "ip": self.ip_encoder,
            "device": self.device_encoder,
            "gateway": self.gateway_encoder,
            "sensor_type": self.sensor_type_encoder,
            "process": self.process_encoder,
            "command_line": self.command_line_encoder,
        }

        x_dict: Dict[str, torch.Tensor] = {}
        for ntype, encoder in encoder_map.items():
            if ntype in node_types:
                x_dict[ntype] = encoder(data[ntype].x)

        if "alert" not in x_dict:
            raise ValueError("Data must contain 'alert' nodes.")

        # Filter edges to available node types
        available_edges = {
            et: ei
            for et, ei in data.edge_index_dict.items()
            if et[0] in x_dict and et[2] in x_dict
        }

        for i, conv in enumerate(self.convs):
            conv_edges = {et: available_edges[et] for et in conv.convs if et in available_edges}
            if not conv_edges:
                continue
            x_dict = conv(x_dict, conv_edges)
            if i < len(self.convs) - 1:
                x_dict = {k: F.relu(v) for k, v in x_dict.items()}
                x_dict = {k: F.dropout(v, p=0.3, training=self.training)
                          for k, v in x_dict.items()}

        alert_embeddings = x_dict["alert"]
        cluster_logits = self.cluster_classifier(alert_embeddings)
        return cluster_logits, x_dict

    def get_attention_weights(self, data: HeteroData) -> Dict[str, torch.Tensor]:
        """Extract GAT attention weights for interpretability."""
        self.eval()
        attention_weights: Dict = {}
        with torch.no_grad():
            node_types = data.node_types
            encoder_map = {
                "alert": self.alert_encoder,
                "user": self.user_encoder,
                "host": self.host_encoder,
                "ip": self.ip_encoder,
                "device": self.device_encoder,
                "gateway": self.gateway_encoder,
                "sensor_type": self.sensor_type_encoder,
                "process": self.process_encoder,
                "command_line": self.command_line_encoder,
            }
            x_dict = {
                ntype: enc(data[ntype].x)
                for ntype, enc in encoder_map.items()
                if ntype in node_types
            }
            for conv in self.convs:
                x_dict, attn = conv(x_dict, data.edge_index_dict, return_attention_weights=True)
                attention_weights.update(attn)
        return attention_weights


# ============================================================================
# AlertToGraphConverter — unchanged from v2.0
# ============================================================================

class AlertToGraphConverter:
    """
    Converts a MITRE-CORE alert DataFrame to PyTorch Geometric HeteroData.

    Handles node creation, edge construction, feature encoding, and temporal
    edge weighting. Compatible with all eight MITRE-CORE v2 datasets.
    """

    def __init__(self, temporal_window_hours: float = 1.0):
        self.temporal_window = temporal_window_hours

    def convert(self, df: pd.DataFrame) -> HeteroData:
        """Convert alert DataFrame to HeteroData."""
        data = HeteroData()

        if "AlertId" not in df.columns:
            df = df.copy()
            df["AlertId"] = [f"alert_{i}" for i in range(len(df))]

        alerts = df["AlertId"].unique()
        users = pd.concat([
            df["SourceUserName"].dropna() if "SourceUserName" in df.columns else pd.Series(dtype=str),
            df["DestinationUserName"].dropna() if "DestinationUserName" in df.columns else pd.Series(dtype=str),
        ]).unique()
        hosts = pd.concat([
            df["SourceHostName"].dropna() if "SourceHostName" in df.columns else pd.Series(dtype=str),
            df["DeviceHostName"].dropna() if "DeviceHostName" in df.columns else pd.Series(dtype=str),
            df["DestinationHostName"].dropna() if "DestinationHostName" in df.columns else pd.Series(dtype=str),
        ]).unique()
        ips = pd.concat([
            df["SourceAddress"].dropna() if "SourceAddress" in df.columns else pd.Series(dtype=str),
            df["DestinationAddress"].dropna() if "DestinationAddress" in df.columns else pd.Series(dtype=str),
            df["DeviceAddress"].dropna() if "DeviceAddress" in df.columns else pd.Series(dtype=str),
        ]).unique()

        gateways: set = set()
        devices: set = set()
        sensor_types: set = set()
        processes: set = set()
        command_lines: set = set()

        for _, row in df.iterrows():
            if all(c in df.columns for c in ("SourceUserName", "SourceAddress", "DeviceAddress")):
                u = str(row.get("SourceUserName", ""))
                if u.startswith("gateway_"):
                    gateways.add(u)
                    devices.add(str(row.get("SourceAddress", "")))
                    dev_addr = str(row.get("DeviceAddress", ""))
                    if ":" in dev_addr:
                        sensor_types.add(f"sensor_{dev_addr.split(':')[-1]}")
            if "ProcessName" in df.columns and pd.notna(row.get("ProcessName")):
                processes.add(str(row["ProcessName"]))
            if "CommandLine" in df.columns and pd.notna(row.get("CommandLine")):
                command_lines.add(str(row["CommandLine"]))

        gateways_l = list(gateways)
        devices_l = list(devices)
        sensor_types_l = list(sensor_types)
        processes_l = list(processes)
        command_lines_l = list(command_lines)

        alert_to_idx = {a: i for i, a in enumerate(alerts)}
        user_to_idx = {u: i for i, u in enumerate(users)}
        host_to_idx = {h: i for i, h in enumerate(hosts)}
        ip_to_idx = {ip: i for i, ip in enumerate(ips)}
        device_to_idx = {d: i for i, d in enumerate(devices_l)}
        gateway_to_idx = {g: i for i, g in enumerate(gateways_l)}
        sensor_type_to_idx = {s: i for i, s in enumerate(sensor_types_l)}
        process_to_idx = {p: i for i, p in enumerate(processes_l)}
        command_line_to_idx = {c: i for i, c in enumerate(command_lines_l)}

        data["alert"].x = torch.tensor(self._encode_alert_features(df), dtype=torch.float)

        for ntype, collection in [
            ("user", users), ("host", hosts), ("ip", ips),
            ("device", devices_l), ("gateway", gateways_l),
            ("sensor_type", sensor_types_l), ("process", processes_l),
            ("command_line", command_lines_l),
        ]:
            if len(collection) > 0:
                data[ntype].x = torch.ones(len(collection), 1)

        edges = self._build_edges(
            df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx,
            device_to_idx, gateway_to_idx, sensor_type_to_idx,
            process_to_idx, command_line_to_idx,
        )
        for edge_type, (src, dst) in edges.items():
            if src:
                data[edge_type].edge_index = torch.tensor([src, dst], dtype=torch.long)
            else:
                data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)

        return data

    def _encode_alert_features(self, df: pd.DataFrame) -> np.ndarray:
        # Tactic
        tactics = pd.Categorical(df["tactic"]).codes if "tactic" in df.columns else np.zeros(len(df))
        if "Tactic" in df.columns and "tactic" not in df.columns:
            tactics = pd.Categorical(df["Tactic"]).codes

        # Alert Type
        if "alert_type" in df.columns:
            alert_types = (df["alert_type"] == "attack").astype(int).values
        elif "AttackTechnique" in df.columns:
            alert_types = (df["AttackTechnique"] != "").astype(int).values
        else:
            alert_types = np.zeros(len(df))

        # Temporal
        try:
            dates = pd.to_datetime(df.get("timestamp", df.get("EndDate", df.get("StartTime"))), errors="coerce")
            hour = np.nan_to_num(dates.dt.hour.values, nan=0.0)
            dow = np.nan_to_num(dates.dt.dayofweek.values, nan=0.0)
        except Exception:
            hour = np.zeros(len(df))
            dow = np.zeros(len(df))

        # Protocol
        protocols = pd.Categorical(df["protocol"]).codes if "protocol" in df.columns else np.zeros(len(df))

        # Service
        services = pd.Categorical(df["service"]).codes if "service" in df.columns else np.zeros(len(df))

        features = np.column_stack([tactics, alert_types, hour / 23.0, dow / 6.0, protocols, services])
        return np.nan_to_num(features, nan=0.0)

    def _build_edges(
        self, df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx,
        device_to_idx, gateway_to_idx, sensor_type_to_idx,
        process_to_idx, command_line_to_idx,
    ) -> Dict:
        edges: Dict = defaultdict(lambda: ([], []))

        def add_edge(etype, src, dst):
            edges[etype][0].append(src)
            edges[etype][1].append(dst)

        # Alert-to-Alert via shared IPs
        ip_to_alerts: Dict = defaultdict(list)
        for _, row in df.iterrows():
            aid = alert_to_idx[row["AlertId"]]
            for col in ("SourceAddress", "DestinationAddress", "DeviceAddress"):
                if col in row and pd.notna(row[col]):
                    ip_to_alerts[row[col]].append(aid)
        for _, idxs in ip_to_alerts.items():
            for i, ai in enumerate(idxs):
                for aj in idxs[i + 1:]:
                    add_edge(("alert", "shares_ip", "alert"), ai, aj)
                    add_edge(("alert", "shares_ip", "alert"), aj, ai)

        # Alert-to-Alert via shared hosts
        host_to_alerts: Dict = defaultdict(list)
        for _, row in df.iterrows():
            aid = alert_to_idx[row["AlertId"]]
            for col in ("SourceHostName", "DeviceHostName", "DestinationHostName"):
                if col in row and pd.notna(row[col]):
                    host_to_alerts[row[col]].append(aid)
        for _, idxs in host_to_alerts.items():
            for i, ai in enumerate(idxs):
                for aj in idxs[i + 1:]:
                    add_edge(("alert", "shares_host", "alert"), ai, aj)
                    add_edge(("alert", "shares_host", "alert"), aj, ai)

        # Temporal edges
        if "EndDate" in df.columns:
            try:
                df_s = df.sort_values("EndDate")
                ts = pd.to_datetime(df_s["EndDate"])
                aidxs = [alert_to_idx[a] for a in df_s["AlertId"]]
                for i, (ai, tsi) in enumerate(zip(aidxs, ts)):
                    for j in range(i + 1, min(i + 100, len(aidxs))):
                        diff_h = abs((ts.iloc[j] - tsi).total_seconds() / 3600)
                        if diff_h <= self.temporal_window:
                            add_edge(("alert", "temporal_near", "alert"), ai, aidxs[j])
                            add_edge(("alert", "temporal_near", "alert"), aidxs[j], ai)
                        else:
                            break
            except Exception:
                pass

        # Cross-type edges
        for _, row in df.iterrows():
            aid = alert_to_idx[row["AlertId"]]

            if "SourceUserName" in row and pd.notna(row["SourceUserName"]) and row["SourceUserName"] in user_to_idx:
                uid = user_to_idx[row["SourceUserName"]]
                add_edge(("user", "owns", "alert"), uid, aid)
                add_edge(("alert", "owned_by", "user"), aid, uid)

            for col in ("SourceHostName", "DeviceHostName", "DestinationHostName"):
                if col in row and pd.notna(row[col]) and row[col] in host_to_idx:
                    hid = host_to_idx[row[col]]
                    add_edge(("host", "generates", "alert"), hid, aid)
                    add_edge(("alert", "generated_by", "host"), aid, hid)

            for col in ("SourceAddress", "DestinationAddress", "DeviceAddress"):
                if col in row and pd.notna(row[col]) and row[col] in ip_to_idx:
                    iid = ip_to_idx[row[col]]
                    add_edge(("ip", "involved_in", "alert"), iid, aid)
                    add_edge(("alert", "involves", "ip"), aid, iid)

            u = str(row.get("SourceUserName", ""))
            src_ip = str(row.get("SourceAddress", ""))
            dev_addr = str(row.get("DeviceAddress", ""))
            if u.startswith("gateway_") and src_ip in device_to_idx and u in gateway_to_idx:
                did = device_to_idx[src_ip]
                gid = gateway_to_idx[u]
                add_edge(("device", "connects_via", "gateway"), did, gid)
                add_edge(("gateway", "connected_to", "device"), gid, did)
                add_edge(("device", "generates", "alert"), did, aid)
                add_edge(("alert", "generated_by", "device"), aid, did)
                if ":" in dev_addr:
                    st = f"sensor_{dev_addr.split(':')[-1]}"
                    if st in sensor_type_to_idx:
                        sid = sensor_type_to_idx[st]
                        add_edge(("sensor_type", "classifies", "device"), sid, did)
                        add_edge(("device", "classified_as", "sensor_type"), did, sid)

            if "ProcessName" in df.columns and pd.notna(row.get("ProcessName")) and row["ProcessName"] in process_to_idx:
                pid = process_to_idx[row["ProcessName"]]
                add_edge(("process", "executes", "alert"), pid, aid)
                add_edge(("alert", "executed_by", "process"), aid, pid)

            if "CommandLine" in df.columns and pd.notna(row.get("CommandLine")) and row["CommandLine"] in command_line_to_idx:
                cid = command_line_to_idx[row["CommandLine"]]
                add_edge(("command_line", "associated_with", "alert"), cid, aid)
                add_edge(("alert", "has", "command_line"), aid, cid)

        return dict(edges)


# ============================================================================
# EmbeddingConfidenceScorer — Geometry-Aware Confidence (v2.2)
# ============================================================================

class EmbeddingConfidenceScorer:
    """
    Geometry-Aware Embedding Confidence (GAEC) v2 scorer.

    v2 changes from v1:
    - Replaced k-means (requires fixed n_centroids) with HDBSCAN (discovers
      cluster count automatically, handles noise, produces native probabilities).
    - Added PCA whitening pre-processing to amplify geometric variance in
      over-smoothed GNN embeddings before clustering.

    Over-smoothing diagnosis:
        If std(confidence) < 0.01 on any dataset, GNN embeddings have collapsed.
        This is diagnosed by checking mean pairwise cosine similarity of the
        raw embeddings — if > 0.95, over-smoothing is confirmed and num_layers
        should be reduced further or a residual skip connection added.

    Parameters
    ----------
    min_cluster_size : int
        Minimum number of alerts to form a cluster in HDBSCAN.
        Default 5 is conservative — appropriate for small sampled batches.
        For large batches (>5000 alerts), consider 20–50.
    min_samples : int
        HDBSCAN robustness parameter. Higher = more conservative clustering,
        more noise points. Default 3.
    pca_components : int or None
        Number of PCA components to retain before HDBSCAN. None = no PCA.
        Default 32 — retains meaningful variance while removing noise dims.
    metric : str
        Distance metric for HDBSCAN. 'cosine' is appropriate for L2-normalised
        GNN embeddings. 'euclidean' works for non-normalised.
    fallback_to_uniform : bool
        If HDBSCAN finds 0 or 1 cluster (all noise), return uniform confidence
        of 0.5 rather than crashing. This triggers maximum UF routing, which
        is the correct behaviour when the HGNN has no geometric structure.
    """

    def __init__(
        self,
        min_cluster_size: int = 5,
        min_samples: int = 3,
        pca_components: Optional[int] = 32,
        metric: str = "cosine",
        fallback_to_uniform: bool = True,
    ):
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.pca_components = pca_components
        self.metric = metric
        self.fallback_to_uniform = fallback_to_uniform
        self._pca = None
        self._clusterer = None

    def fit_score(self, embeddings: torch.Tensor) -> np.ndarray:
        """
        PCA-whiten embeddings, run HDBSCAN, return per-alert confidence.

        Args
        ----
        embeddings : torch.Tensor [N, D]
            Alert embeddings from HGNN message-passing layers (before classifier).

        Returns
        -------
        np.ndarray [N,]
            Per-alert confidence in [0, 1].
            HDBSCAN noise points → 0.0 (route to UF).
            Core cluster points → probability close to 1.0.
            Border points → intermediate probability.
        """
        try:
            import hdbscan as hdbscan_lib
        except ImportError:
            raise ImportError(
                "hdbscan is required for EmbeddingConfidenceScorer v2. "
                "Install with: pip install hdbscan"
            )
        from sklearn.decomposition import PCA

        z = F.normalize(embeddings, dim=1).detach().cpu().numpy()
        n, d = z.shape

        # -----------------------------------------------------------------
        # Diagnose over-smoothing before proceeding
        # -----------------------------------------------------------------
        if n > 1:
            # Mean pairwise cosine similarity on a sample (expensive for large N)
            sample_size = min(n, 200)
            idx = np.random.choice(n, sample_size, replace=False)
            z_sample = z[idx]
            # Cosine sim matrix (z is already L2-normalised, so dot product = cosine sim)
            sim_matrix = z_sample @ z_sample.T
            # Upper triangle only (exclude diagonal)
            upper = sim_matrix[np.triu_indices(sample_size, k=1)]
            mean_cosine_sim = float(np.mean(upper))
            if mean_cosine_sim > 0.95:
                logger.warning(
                    f"OVER-SMOOTHING DETECTED: mean pairwise cosine similarity="
                    f"{mean_cosine_sim:.4f} > 0.95. "
                    f"Embeddings have collapsed. Consider reducing num_layers "
                    f"to 1 or adding residual skip connections to MITREHeteroGNN."
                )
        else:
            mean_cosine_sim = 0.0

        # -----------------------------------------------------------------
        # PCA whitening (amplifies variance in over-smoothed embeddings)
        # -----------------------------------------------------------------
        if self.pca_components is not None and d > self.pca_components and n > self.pca_components:
            self._pca = PCA(
                n_components=self.pca_components,
                whiten=True,   # ← key: normalise variance per component
                random_state=42,
            )
            z_reduced = self._pca.fit_transform(z)
            explained_var = float(self._pca.explained_variance_ratio_.sum())
            logger.info(
                f"PCA: {d}→{self.pca_components} dims, "
                f"explained variance={explained_var:.3f}"
            )
        else:
            z_reduced = z
            logger.info(f"PCA skipped (n={n}, d={d}, pca_components={self.pca_components})")

        # -----------------------------------------------------------------
        # HDBSCAN clustering with native probability output
        # -----------------------------------------------------------------
        clusterer = hdbscan_lib.HDBSCAN(
            min_cluster_size=min(self.min_cluster_size, max(2, n // 20)),
            min_samples=self.min_samples,
            metric=self.metric if self.pca_components is None else "euclidean",
            # After PCA whitening, Euclidean distance is appropriate;
            # cosine is better for raw L2-normalised embeddings
            prediction_data=True,
            cluster_selection_method="eom",  # excess of mass: stable clusters
        )
        clusterer.fit(z_reduced)
        self._clusterer = clusterer

        n_found = len(set(clusterer.labels_)) - (1 if -1 in clusterer.labels_ else 0)
        n_noise = int((clusterer.labels_ == -1).sum())
        logger.info(
            f"HDBSCAN: found {n_found} clusters, "
            f"{n_noise}/{n} noise points ({n_noise/n:.1%})"
        )

        # -----------------------------------------------------------------
        # Extract confidence from HDBSCAN probabilities_
        # -----------------------------------------------------------------
        # clusterer.probabilities_: per-point cluster membership probability
        # Noise points → 0.0, core points → values approaching 1.0
        confidence = clusterer.probabilities_.astype(np.float32)

        # Fallback: if all noise or single cluster, return moderate uniform
        # score (0.5) to allow UF to handle everything, rather than crashing
        if n_found <= 1 and self.fallback_to_uniform:
            logger.warning(
                f"HDBSCAN found {n_found} cluster(s) — all alerts treated as "
                f"noise or single cluster. "
                f"Returning uniform confidence=0.5 → full UF routing. "
                f"This is the correct fallback when HGNN has no geometric structure."
            )
            confidence = np.full(n, 0.5, dtype=np.float32)

        return confidence

        # Removed score method alias as it is not strictly needed or we can keep it
    def score(self, embeddings: torch.Tensor) -> np.ndarray:
        """Alias for fit_score (HDBSCAN always fits and scores together)."""
        return self.fit_score(embeddings)


# ============================================================================
# HGNNCorrelationEngine — main engine with confidence-gated UF fallback (v2.1)
# ============================================================================

class HGNNCorrelationEngine:
    """
    Drop-in replacement for Union-Find correlation engine.

    Primary path: HGNN inference → cluster_logits → cluster_confidence →
                  pred_cluster assigned via argmax.

    Refinement path (new in v2.1): alerts with cluster_confidence below
    ``confidence_gate`` are re-correlated by enhanced_correlation() using
    confidence_guided_threshold() to derive the UF threshold.  The
    motivating result is the sensitivity study finding that threshold ≥ 0.7
    pushed ARI to 0.9708 — the HGNN's own confidence is the most reliable
    signal for when to apply a tighter threshold.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        hidden_dim: int = 128,
        num_heads: int = 4,
        num_layers: int = 1,
        device: str = "cuda" if torch.cuda.is_available() else "cpu",
        temperature: float = 1.0,
        confidence_gate: float = _DEFAULT_CONFIDENCE_GATE,
        uf_usernames: Optional[List[str]] = None,
        uf_addresses: Optional[List[str]] = None,
        use_geometric_confidence: bool = True,
        hdbscan_min_cluster_size: int = 5,
        hdbscan_pca_components: int = 32,
    ):
        """
        Args
        ----
        model_path : Optional[str]
            Path to a pretrained HGNN checkpoint.
        hidden_dim : int
            Hidden dimension for MITREHeteroGNN.
        num_heads : int
            Number of attention heads per GATConv layer.
        num_layers : int
            Number of layers for MITREHeteroGNN (default 1 to prevent over-smoothing).
        device : str
            Torch device string ('cuda' or 'cpu').
        temperature : float
            Initial temperature scaling value (refined via calibrate_temperature).
        confidence_gate : float
            Alerts with max-softmax confidence below this value are passed through
            the UF refinement pass.  Default: 0.6.
        uf_usernames : Optional[List[str]]
            Username columns to use in the UF refinement pass.
            Defaults to ["SourceHostName", "DeviceHostName", "DestinationHostName"].
        uf_addresses : Optional[List[str]]
            Address columns to use in the UF refinement pass.
            Defaults to ["SourceAddress", "DestinationAddress", "DeviceAddress"].
        use_geometric_confidence : bool
            Use Geometry-Aware Embedding Confidence (GAEC) instead of max-softmax.
        hdbscan_min_cluster_size : int
            Minimum cluster size for HDBSCAN.
        hdbscan_pca_components : int
            Number of PCA components for HDBSCAN preprocessing.
        """
        self.device = device
        self.converter = AlertToGraphConverter()
        self.temperature = temperature
        self.confidence_gate = confidence_gate
        self.use_geometric_confidence = use_geometric_confidence
        self.confidence_scorer = EmbeddingConfidenceScorer(
            min_cluster_size=hdbscan_min_cluster_size,
            pca_components=hdbscan_pca_components,
            min_samples=3,
            metric="cosine",
            fallback_to_uniform=True,
        ) if use_geometric_confidence else None

        # Default UF column lists (mirror correlation_indexer.py main())
        self.uf_usernames = uf_usernames or [
            "SourceHostName", "DeviceHostName", "DestinationHostName"
        ]
        self.uf_addresses = uf_addresses or [
            "SourceAddress", "DestinationAddress", "DeviceAddress"
        ]

        self.model = MITREHeteroGNN(
            hidden_dim=hidden_dim, num_heads=num_heads, num_layers=num_layers
        ).to(device)

        if model_path:
            # Let the checkpoint dictate the number of clusters if it differs
            try:
                state_dict = torch.load(model_path, map_location=device, weights_only=False)
                if "model_state_dict" in state_dict:
                    state_dict = state_dict["model_state_dict"]
                
                # Check for cluster_classifier shape mismatch
                k_weight = "cluster_classifier.3.weight"
                if k_weight in state_dict:
                    ckpt_clusters = state_dict[k_weight].shape[0]
                    model_clusters = self.model.cluster_classifier[3].weight.shape[0]
                    if ckpt_clusters != model_clusters:
                        logger.info(f"Re-initializing model with {ckpt_clusters} clusters to match checkpoint.")
                        self.model = MITREHeteroGNN(
                            hidden_dim=hidden_dim, num_heads=num_heads, num_clusters=ckpt_clusters
                        ).to(device)
            except Exception as e:
                logger.warning(f"Failed to inspect checkpoint for num_clusters: {e}")

            self._load_checkpoint(model_path)

        self.model.eval()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_checkpoint(self, model_path: str) -> None:
        try:
            state_dict = torch.load(model_path, map_location=self.device, weights_only=False)
            
            if "model_state_dict" in state_dict:
                state_dict = state_dict["model_state_dict"]
                
            model_dict = self.model.state_dict()
            filtered = {}
            for k, v in state_dict.items():
                if k in model_dict:
                    # Skip uninitialized parameters in the checkpoint itself
                    if getattr(v, "is_uninitialized", False) or "Uninitialized" in type(v).__name__:
                        continue
                    
                    param = model_dict[k]
                    is_uninit = getattr(param, "is_uninitialized", False) or "Uninitialized" in type(param).__name__
                    if is_uninit:
                        filtered[k] = v
                    elif param.shape == v.shape:
                        filtered[k] = v
            
            # Since we have lazy layers, we should use assign=True for uninitialized params in PyTorch 2+ if possible,
            # but strict=False usually handles it.
            self.model.load_state_dict(filtered, strict=False, assign=True)
            logger.info(
                f"Loaded checkpoint {model_path} "
                f"({len(state_dict) - len(filtered)} keys skipped due to shape mismatch)"
            )
        except Exception as exc:
            logger.warning(f"Could not fully load checkpoint: {exc}")

    def _apply_temperature(self, logits: torch.Tensor) -> torch.Tensor:
        return logits / max(self.temperature, 1e-6)

    def _log_confidence_diagnostics(
        self,
        confidence_scores: np.ndarray,
        source: str,
        dataset_name: str = "unknown",
    ) -> None:
        """
        Log confidence distribution statistics to help diagnose gate behavior.
        Writes to both the Python logger and a diagnostics CSV for persistence.
        """
        import json
        from pathlib import Path

        p25 = float(np.percentile(confidence_scores, 25))
        p75 = float(np.percentile(confidence_scores, 75))
        mean = float(np.mean(confidence_scores))
        std = float(np.std(confidence_scores))
        gate = self.confidence_gate

        # Mirror the exact formula used in correlation_indexer.confidence_guided_threshold()
        # so diagnostic predictions match runtime behaviour.
        adjustment = mean - 0.5
        derived_threshold = float(np.clip(0.3 + adjustment, 0.1, 0.9))

        logger.info(f"\n--- Confidence Diagnostics [{source}] ---")
        logger.info(f"  dataset    : {dataset_name}")
        logger.info(f"  mean       : {mean:.4f}")
        logger.info(f"  std        : {std:.4f}")
        logger.info(f"  p25        : {p25:.4f}")
        logger.info(f"  p75        : {p75:.4f}")
        logger.info(f"  gate       : {gate:.4f}")
        logger.info(f"  pct < gate : {(confidence_scores < gate).mean():.2%}")
        logger.info(f"  → UF threshold will be: {derived_threshold:.4f}")

        if std < 0.01:
            logger.warning(
                f"  ⚠ NEAR-ZERO VARIANCE (std={std:.4f}). "
                f"Gate sweep will be flat. "
                f"Check: (1) GAEC enabled? (2) k-means converging? "
                f"(3) Embeddings collapsing (over-smoothing)?"
            )
        if mean < 0.2:
            logger.warning(
                f"  ⚠ VERY LOW MEAN CONFIDENCE ({mean:.4f}). "
                f"If source=softmax, this means classification head is untrained. "
                f"If source=gaec, this means embeddings are highly dispersed — "
                f"increase n_centroids or check for over-smoothing."
            )

        # Persist to diagnostics log
        log_path = Path("experiments/results/confidence_diagnostics.jsonl")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps({
                "dataset": dataset_name,
                "source": source,
                "mean": mean,
                "std": std,
                "p25": p25,
                "p75": p75,
                "gate": gate,
                "pct_below_gate": float((confidence_scores < gate).mean()),
                "derived_uf_threshold": derived_threshold,
                "n_hdbscan_clusters": int(getattr(
                    getattr(self, 'confidence_scorer', None),
                    '_clusterer', None
                ).labels_.max() + 1) if (
                    self.confidence_scorer is not None and
                    self.confidence_scorer._clusterer is not None
                ) else -1,
            }) + "\n")

    def _uf_refinement_pass(
        self,
        df: pd.DataFrame,
        confidence: np.ndarray,
        cluster_offset: int,
        full_confidence: Optional[np.ndarray] = None,
    ) -> pd.DataFrame:
        """
        Run enhanced_correlation() on a subset of low-confidence alerts,
        using confidence_guided_threshold() to determine the UF threshold.

        This is the bridge between the HGNN output and the Union-Find engine
        introduced in v2.1.  It is intentionally isolated so it can be unit-
        tested independently of the full engine.

        Args
        ----
        df : pd.DataFrame
            Subset of the original alert DataFrame — only low-confidence rows.
        confidence : np.ndarray
            Per-alert confidence values for this subset, shape [M,].
        cluster_offset : int
            Integer offset added to UF cluster IDs to avoid collisions with
            the HGNN cluster IDs already assigned to high-confidence alerts.
        full_confidence : Optional[np.ndarray]
            Full per-alert confidence array for threshold computation.
            If provided, used instead of `confidence` for confidence_guided_threshold().
            This ensures the threshold is computed from the full distribution
            rather than just the low-confidence subset.

        Returns
        -------
        pd.DataFrame
            ``df`` with ``pred_cluster`` overwritten by the UF result
            (offset-adjusted) and ``cluster_confidence`` preserved.
        """
        from core.correlation_indexer import enhanced_correlation

        # Determine which UF columns are actually present in this subset
        present_usernames = [c for c in self.uf_usernames if c in df.columns]
        present_addresses = [c for c in self.uf_addresses if c in df.columns]

        if not present_addresses and not present_usernames:
            logger.warning(
                "UF refinement pass skipped: no address or username columns found in subset."
            )
            return df

        # Use full confidence array for threshold computation if available
        # This fixes the bug where only low-confidence subset was used,
        # causing threshold to always hit floor (0.1)
        threshold_confidence = full_confidence if full_confidence is not None else confidence

        uf_result = enhanced_correlation(
            data=df.reset_index(drop=True),
            usernames=present_usernames,
            addresses=present_addresses,
            use_temporal="EndDate" in df.columns,
            use_adaptive_threshold=False,   # confidence_guided_threshold takes over
            threshold_override=None,
            cluster_confidence=threshold_confidence,
        )

        # Offset UF cluster IDs to avoid collision with HGNN cluster space
        uf_result["pred_cluster"] = uf_result["pred_cluster"] + cluster_offset

        # Re-attach confidence scores (UF doesn't produce them — preserve HGNN's)
        uf_result["cluster_confidence"] = confidence

        logger.info(
            f"UF refinement pass: {len(df)} low-confidence alerts → "
            f"{uf_result['pred_cluster'].nunique()} sub-clusters "
            f"(threshold_source={uf_result['threshold_source'].iloc[0]}, "
            f"threshold={uf_result['correlation_threshold_used'].iloc[0]:.4f})"
        )

        return uf_result

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def calibrate_temperature(
        self,
        logits: torch.Tensor,
        labels: torch.Tensor,
        lr: float = 0.01,
        max_iter: int = 50,
    ) -> float:
        """
        Learn optimal temperature via NLL minimisation (Guo et al., ICML 2017).

        Args
        ----
        logits : torch.Tensor [N, C]
            Raw model logits.
        labels : torch.Tensor [N]
            Ground-truth cluster indices.
        lr : float
            Learning rate for LBFGS optimiser.
        max_iter : int
            Maximum optimisation iterations.

        Returns
        -------
        float
            Optimal temperature value (also stored as self.temperature).
        """
        temperature = nn.Parameter(torch.ones(1, device=self.device))
        optimiser = torch.optim.LBFGS([temperature], lr=lr, max_iter=max_iter)

        def eval_nll():
            optimiser.zero_grad()
            loss = F.cross_entropy(logits / temperature.clamp(min=1e-6), labels)
            loss.backward()
            return loss

        optimiser.step(eval_nll)
        self.temperature = float(temperature.item())
        logger.info(f"Temperature calibration complete: T={self.temperature:.4f}")
        return self.temperature

    def correlate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Correlate alerts using the HGNN with a confidence-gated UF refinement pass.

        Pipeline
        --------
        1. Convert ``df`` to HeteroData via AlertToGraphConverter.
        2. Run MITREHeteroGNN forward pass → cluster_logits.
        3. Apply temperature scaling → cluster_probs → cluster_confidence.
        4. Assign pred_cluster via argmax for all alerts.
        5. Identify low-confidence alerts (confidence < self.confidence_gate).
        6. For low-confidence alerts: run _uf_refinement_pass() which calls
           enhanced_correlation() with confidence_guided_threshold() driving
           the UF threshold.
        7. Merge high-confidence HGNN assignments with UF-refined assignments.

        The motivation for step 6 is the MITRE-CORE v2 sensitivity result:
        threshold ≥ 0.7 → ARI 0.9708, vs. HGNN Full ARI 0.6174.  The HGNN's
        own confidence is the best available signal for when its embedding space
        is unreliable — passing those alerts to a threshold-aware UF pass closes
        the gap without regressing on high-confidence predictions.

        Args
        ----
        df : pd.DataFrame
            Alert DataFrame. Must contain at least: AlertId, MalwareIntelAttackType,
            AttackSeverity, EndDate.  Address and hostname columns are used if present.

        Returns
        -------
        pd.DataFrame
            Copy of ``df`` with added columns:
              - pred_cluster          : integer cluster ID.
              - cluster_confidence    : HGNN max-softmax confidence [0, 1].
              - correlation_method    : 'hgnn' | 'hgnn+uf_refinement'.
        """
        logger.info(f"Building heterogeneous graph from {len(df)} alerts...")
        graph_data = self.converter.convert(df)
        graph_data = graph_data.to(self.device)

        logger.info(f"Graph: {graph_data['alert'].num_nodes} alerts, {len(graph_data.edge_types)} edge types")
        
        # Dynamically pad or truncate node features to match the loaded model's encoder expectations
        for ntype in graph_data.node_types:
            encoder_name = f"{ntype}_encoder"
            if hasattr(self.model, encoder_name):
                encoder = getattr(self.model, encoder_name)
                # Check if encoder has been initialized
                if hasattr(encoder, "in_channels") and encoder.in_channels > 0:
                    expected_dim = encoder.in_channels
                    current_dim = graph_data[ntype].x.shape[1]
                    if current_dim < expected_dim:
                        graph_data[ntype].x = torch.nn.functional.pad(graph_data[ntype].x, (0, expected_dim - current_dim))
                    elif current_dim > expected_dim:
                        graph_data[ntype].x = graph_data[ntype].x[:, :expected_dim]

        with torch.no_grad():
            # ------------------------------------------------------------------
            # Step 1–4: HGNN inference
            # ------------------------------------------------------------------
            self.model.eval()
            cluster_logits, x_dict = self.model(graph_data)
            cluster_logits = self._apply_temperature(cluster_logits)
            cluster_probs = torch.softmax(cluster_logits, dim=-1)
            cluster_preds = torch.argmax(cluster_probs, dim=-1)

            if self.use_geometric_confidence and self.confidence_scorer is not None:
                # Use geometry-aware embedding confidence (GAEC) instead of softmax.
                # alert_embeddings come from the message-passing layers directly,
                # before the classification head — no calibration required.
                alert_embeddings = x_dict["alert"]  # [N, hidden_dim] from forward()
                confidence_scores = self.confidence_scorer.fit_score(alert_embeddings)
                confidence_source = "gaec"
            else:
                # Legacy path: max-softmax from classification head
                confidence_scores = cluster_probs.max(dim=-1)[0].cpu().numpy()
                confidence_source = "softmax"

        self._log_confidence_diagnostics(
            confidence_scores,
            source=confidence_source,
            dataset_name=getattr(df, "_dataset_name", "unknown"),
        )

        result_df = df.copy()
        result_df["pred_cluster"] = cluster_preds.cpu().numpy()
        result_df["cluster_confidence"] = confidence_scores
        result_df["confidence_source"] = confidence_source
        result_df["correlation_method"] = "hgnn"

        avg_conf = float(np.mean(confidence_scores))
        n_clusters_hgnn = int(cluster_preds.unique().numel())
        logger.info(
            f"HGNN: {n_clusters_hgnn} clusters, "
            f"avg confidence={avg_conf:.3f}, "
            f"T={self.temperature:.3f}"
        )

        # ------------------------------------------------------------------
        # Step 5–7: Confidence-gated UF refinement pass
        # ------------------------------------------------------------------
        low_conf_mask = confidence_scores < self.confidence_gate
        n_low_conf = int(low_conf_mask.sum())

        if n_low_conf > 0:
            logger.info(
                f"UF refinement pass triggered: {n_low_conf}/{len(df)} alerts "
                f"below confidence_gate={self.confidence_gate}"
            )

            low_conf_df = df[low_conf_mask].copy()
            low_conf_confidence = confidence_scores[low_conf_mask]

            # Cluster offset = max HGNN cluster ID + 1 to avoid ID collision
            cluster_offset = int(result_df["pred_cluster"].max()) + 1

            uf_refined = self._uf_refinement_pass(
                df=low_conf_df,
                confidence=low_conf_confidence,
                cluster_offset=cluster_offset,
                full_confidence=confidence_scores,
            )

            # Write UF-refined assignments back into result_df
            result_df.loc[low_conf_mask, "pred_cluster"] = uf_refined["pred_cluster"].values
            result_df.loc[low_conf_mask, "correlation_method"] = "hgnn+uf_refinement"
            
            if "correlation_threshold_used" in uf_refined.columns:
                if "correlation_threshold_used" not in result_df.columns:
                    result_df["correlation_threshold_used"] = float("nan")
                result_df.loc[low_conf_mask, "correlation_threshold_used"] = uf_refined["correlation_threshold_used"].values
                
            if "threshold_source" in uf_refined.columns:
                if "threshold_source" not in result_df.columns:
                    result_df["threshold_source"] = float("nan")
                result_df.loc[low_conf_mask, "threshold_source"] = uf_refined["threshold_source"].values

            n_clusters_final = result_df["pred_cluster"].nunique()
            logger.info(
                f"After UF refinement: {n_clusters_final} total clusters "
                f"({n_clusters_hgnn} from HGNN, "
                f"{uf_refined['pred_cluster'].nunique()} from UF refinement)"
            )
        else:
            logger.info(
                f"All {len(df)} alerts above confidence_gate={self.confidence_gate} "
                f"— UF refinement pass skipped."
            )

        return result_df

    def finetune(self, df: pd.DataFrame, epochs: int = 5, lr: float = 0.0005) -> None:
        """Fine-tune on labeled data. Requires 'Category' column."""
        from .hgnn_training import HGNNTrainer, AlertGraphDataset
        from sklearn.preprocessing import LabelEncoder

        if "Category" not in df.columns:
            raise ValueError("DataFrame must contain 'Category' for supervised fine-tuning.")

        le = LabelEncoder()
        labels = le.fit_transform(df["Category"].values)
        dataset = AlertGraphDataset([df], labels=[labels], augment=True)
        trainer = HGNNTrainer(self.model, device=self.device, learning_rate=lr)
        trainer.finetune_supervised(dataset, num_epochs=epochs)
        self.model.eval()

    def get_attention_analysis(self, df: pd.DataFrame) -> Dict:
        """Analyse which edge types contributed most to clustering (interpretability)."""
        data = self.converter.convert(df).to(self.device)
        attention_weights = self.model.get_attention_weights(data)
        return {
            str(et): {
                "mean_attention": float(attn.mean()),
                "max_attention": float(attn.max()),
                "attention_std": float(attn.std()),
            }
            for et, attn in attention_weights.items()
        }

    def save_model(self, path: str) -> None:
        """Save trained model weights."""
        torch.save(self.model.state_dict(), path)
        logger.info(f"Saved HGNN model to {path}")


# ============================================================================
# Training Components (self-supervised pre-training)
# ============================================================================

class ContrastiveAlertLearner(nn.Module):
    """
    Self-supervised contrastive learning for alert embeddings.
    Based on CARLA: Self-Supervised Contrastive Representation Learning (2023-2024).
    """

    def __init__(self, hgnn: MITREHeteroGNN, temperature: float = 0.5):
        super().__init__()
        self.hgnn = hgnn
        self.temperature = temperature

    def forward(self, data1: HeteroData, data2: HeteroData) -> torch.Tensor:
        _, emb1 = self.hgnn(data1)
        _, emb2 = self.hgnn(data2)
        z1 = F.normalize(emb1["alert"], dim=1)
        z2 = F.normalize(emb2["alert"], dim=1)
        sim = torch.mm(z1, z2.t()) / self.temperature
        labels = torch.arange(z1.size(0), device=z1.device)
        return F.cross_entropy(sim, labels)


class GraphAugmenter:
    """Data augmentation for contrastive learning on alert graphs."""

    @staticmethod
    def drop_edges(data: HeteroData, drop_prob: float = 0.1) -> HeteroData:
        data_aug = data.clone()
        for et in data_aug.edge_types:
            ei = data_aug[et].edge_index
            mask = torch.rand(ei.size(1)) > drop_prob
            data_aug[et].edge_index = ei[:, mask]
        return data_aug

    @staticmethod
    def mask_features(data: HeteroData, mask_prob: float = 0.1) -> HeteroData:
        data_aug = data.clone()
        if "alert" in data_aug:
            x = data_aug["alert"].x.clone()
            x[torch.rand(x.shape) < mask_prob] = 0.0
            data_aug["alert"].x = x
        return data_aug


# ============================================================================
# Module entrypoint
# ============================================================================

if __name__ == "__main__":
    print("MITRE-CORE HGNN Module v2.1")
    print("=" * 50)
    print("Usage:")
    print("  from hgnn.hgnn_correlation import HGNNCorrelationEngine")
    print("  engine = HGNNCorrelationEngine(confidence_gate=0.6)")
    print("  result_df = engine.correlate(alert_dataframe)")
    print()
    print("Columns added to result_df:")
    print("  pred_cluster         — cluster ID (int)")
    print("  cluster_confidence   — HGNN max-softmax confidence [0,1]")
    print("  correlation_method   — 'hgnn' or 'hgnn+uf_refinement'")