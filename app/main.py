"""
MITRE-CORE Web Dashboard
Flask-based web application for cybersecurity alert correlation and visualization.
"""

import os
import sys
import json
import time
import logging
import traceback
from pathlib import Path
from werkzeug.utils import secure_filename

import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS

# Ensure project root is on the path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# New unified correlation pipeline
from core.correlation_pipeline import CorrelationPipeline
from core.correlation_indexer import calculate_adaptive_threshold
from core.postprocessing import correlation as legacy_correlation, clean_clusters, get_feature_chains
from core.output import types, Attack_stages, classify_attack_stage
from core.preprocessing import get_data  # For standard data loading

# New modules for curated graph stories
from core.cluster_filter import ClusterFilter, FilterConfig, create_cluster_filter
from core.kg_enrichment import KnowledgeGraphEnricher, create_enricher, ThreatIntelStore
from core.streaming import StreamingCorrelator, create_streaming_correlator, LazyGraphGenerator

import Testing
from siem.connectors import get_connector, CONNECTOR_REGISTRY, WebhookConnector
from siem.ingestion_engine import IngestionEngine
from utils.data_validation import validate_real_data, is_production

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")

import os
# Restrict CORS to specific origins in production
# In production, set CORS_ORIGINS env var to your trusted domains only
cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000").split(",")
# Remove any empty origins
CORS(app, resources={r"/*": {"origins": [o for o in cors_origins if o]}})
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mitre-core")

# Standard field names
ADDRESSES = ["SourceAddress", "DestinationAddress", "DeviceAddress"]
USERNAMES = ["SourceHostName", "DeviceHostName", "DestinationHostName"]

# In-memory store for the latest analysis results
_latest_results = {
    "raw_df": None,
    "correlated_df": None,
    "clusters_json": None,
    "stats": None,
    "cluster_scores": None,
    "kg_enrichments": None,
    "parquet_path": None,
}

# Cluster filter instance (lazy init)
_cluster_filter = None

# Knowledge graph enricher (lazy init)
_kg_enricher = None

# Streaming correlator (lazy init)
_streaming_correlator = None

# Lazy graph generator (lazy init)
_lazy_graph_gen = None

# Live ingestion engine (singleton)
ingestion_engine = IngestionEngine(
    poll_interval=30,
    correlation_interval=60,
    buffer_max=50000,
    correlation_window=5000,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_json(obj):
    """Convert numpy / pandas types so they are JSON-serialisable."""
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, pd.Timestamp):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    return obj


def _deep_convert(obj):
    if isinstance(obj, dict):
        return {k: _deep_convert(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_deep_convert(i) for i in obj]
    return _safe_json(obj)


def _build_cluster_summary(df):
    """Build per-cluster summary dicts from a correlated DataFrame."""
    if "pred_cluster" not in df.columns:
        return []

    summaries = []
    clusters = df.groupby("pred_cluster")

    for c_no, cluster in clusters:
        record = {
            "cluster_id": int(c_no),
            "size": int(len(cluster)),
        }

        # Dates
        if "EndDate" in cluster.columns:
            try:
                dates = pd.to_datetime(cluster["EndDate"], errors="coerce")
                record["start_date"] = str(dates.min())
                record["end_date"] = str(dates.max())
            except (ValueError, TypeError):
                record["start_date"] = str(cluster["EndDate"].iloc[0])
                record["end_date"] = str(cluster["EndDate"].iloc[-1])

        # Attack types & MITRE tactics
        if "MalwareIntelAttackType" in cluster.columns:
            attack_types = list(cluster["MalwareIntelAttackType"].dropna().unique())
            record["attack_types"] = attack_types
            tactics = list(set(types.get(a, "UNKNOWN") for a in attack_types))
            record["tactics"] = tactics
            record["stage"] = classify_attack_stage(tactics)
        else:
            # Use AttackType if available
            if "AttackType" in cluster.columns:
                record["attack_types"] = list(cluster["AttackType"].dropna().unique())
            else:
                record["attack_types"] = []
            record["tactics"] = []
            record["stage"] = "Other"

        # Addresses
        for col in ADDRESSES:
            if col in cluster.columns:
                record[col] = list(cluster[col].dropna().unique()[:10])

        # Correlation score
        if "correlation_score" in cluster.columns:
            record["avg_correlation"] = round(float(cluster["correlation_score"].mean()), 4)
        elif "correlation_threshold_used" in cluster.columns:
            record["threshold_used"] = round(float(cluster["correlation_threshold_used"].iloc[0]), 4)

        summaries.append(record)

    return summaries


def _build_graph_data(df):
    """Build nodes + edges for the interactive Plotly graph (returned as JSON)."""
    if "pred_cluster" not in df.columns:
        return {"nodes": [], "edges": []}

    nodes = []
    edges = []

    # Assign colours per cluster
    unique_clusters = sorted(df["pred_cluster"].unique())
    palette = [
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
        "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
        "#aec7e8", "#ffbb78", "#98df8a", "#ff9896", "#c5b0d5",
    ]
    color_map = {c: palette[i % len(palette)] for i, c in enumerate(unique_clusters)}

    for idx, row in df.iterrows():
        cluster_id = int(row["pred_cluster"])
        label_parts = [f"Cluster {cluster_id}"]
        if "MalwareIntelAttackType" in row:
            label_parts.append(str(row["MalwareIntelAttackType"]))
        elif "AttackType" in row:
            label_parts.append(str(row["AttackType"]))
        if "SourceAddress" in row:
            label_parts.append(f"Src: {row['SourceAddress']}")

        nodes.append({
            "id": int(idx),
            "label": " | ".join(label_parts),
            "cluster": cluster_id,
            "color": color_map.get(cluster_id, "#999"),
        })

    # Edges: connect events within the same cluster sequentially
    for c_id in unique_clusters:
        members = df[df["pred_cluster"] == c_id].index.tolist()
        for i in range(len(members) - 1):
            edges.append({"source": int(members[i]), "target": int(members[i + 1])})

    return {"nodes": nodes, "edges": edges}


def _compute_stats(df):
    """Compute high-level statistics for the dashboard."""
    stats = {
        "total_events": int(len(df)),
        "num_clusters": 0,
        "avg_cluster_size": 0,
        "attack_types": [],
        "tactics": [],
    }
    if "pred_cluster" not in df.columns:
        return stats

    cluster_counts = df["pred_cluster"].value_counts()
    stats["num_clusters"] = int(cluster_counts.shape[0])
    stats["avg_cluster_size"] = round(float(cluster_counts.mean()), 1)
    stats["max_cluster_size"] = int(cluster_counts.max())
    stats["min_cluster_size"] = int(cluster_counts.min())

    for col in ["MalwareIntelAttackType", "AttackType"]:
        if col in df.columns:
            stats["attack_types"] = list(df[col].dropna().unique())
            break

    if stats["attack_types"]:
        stats["tactics"] = list(set(types.get(a, "UNKNOWN") for a in stats["attack_types"]))

    return stats


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})


@app.route("/api/generate-synthetic", methods=["POST"])
def generate_synthetic():
    """Generate synthetic test data using Testing.py and run correlation."""
    try:
        body = request.get_json(silent=True) or {}
        n_samples = int(body.get("n_samples", 60))
        n_samples = max(10, min(500, n_samples))
        
        # Get correlation method from request
        method = body.get("method", "auto")
        model_path = body.get("model_path")
        
        logger.info(f"Generating {n_samples} synthetic events (method={method})")
        raw_df = Testing.build_data(n_samples)

        # Use new unified correlation pipeline
        pipeline = CorrelationPipeline(
            method=method,
            model_path=model_path
        )
        result = pipeline.correlate(raw_df, USERNAMES, ADDRESSES)
        result_df = result.data

        summaries = _build_cluster_summary(result_df)
        graph = _build_graph_data(result_df)
        stats = _compute_stats(result_df)
        
        # Add method info to response
        stats["correlation_method"] = result.method_used
        stats["runtime_seconds"] = result.runtime_seconds
        stats["fallback_used"] = result.fallback_used

        _latest_results["raw_df"] = raw_df
        _latest_results["correlated_df"] = result_df
        _latest_results["clusters_json"] = summaries
        _latest_results["stats"] = stats

        return jsonify(_deep_convert({
            "success": True,
            "stats": stats,
            "clusters": summaries,
            "graph": graph,
        }))
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/upload", methods=["POST"])
def upload_csv():
    """Upload a CSV file and run correlation."""
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"success": False, "error": "No file selected"}), 400
        
        # Secure filename and validate extension
        filename = secure_filename(file.filename)
        allowed_extensions = {'.csv'}
        file_ext = Path(filename).suffix.lower()
        
        if file_ext not in allowed_extensions:
            return jsonify({"success": False, "error": f"Only {', '.join(allowed_extensions)} files are supported"}), 400
        
        # Validate content type
        if file.content_type not in ['text/csv', 'application/vnd.ms-excel', 'text/plain', 'application/octet-stream']:
            logger.warning(f"Suspicious content type: {file.content_type} for file {filename}")
            return jsonify({"success": False, "error": "Invalid file content type"}), 400
        
        # Get correlation method from form data
        method = request.form.get("method", "auto")
        model_path = request.form.get("model_path")

        raw_df = pd.read_csv(file, low_memory=False)
        logger.info(f"Uploaded {filename}: {len(raw_df)} rows, columns={list(raw_df.columns)} (method={method})")

        # Detect available fields
        addresses = [c for c in ADDRESSES if c in raw_df.columns]
        usernames = [c for c in USERNAMES if c in raw_df.columns]

        if not addresses and not usernames:
            return jsonify({"success": False,
                            "error": "CSV must contain at least one of: " + ", ".join(ADDRESSES + USERNAMES)}), 400

        # Use new unified correlation pipeline
        pipeline = CorrelationPipeline(
            method=method,
            model_path=model_path
        )
        result = pipeline.correlate(raw_df, usernames, addresses)
        result_df = result.data

        summaries = _build_cluster_summary(result_df)
        graph = _build_graph_data(result_df)
        stats = _compute_stats(result_df)
        
        # Add method info to response
        stats["correlation_method"] = result.method_used
        stats["runtime_seconds"] = result.runtime_seconds
        stats["fallback_used"] = result.fallback_used

        _latest_results["raw_df"] = raw_df
        _latest_results["correlated_df"] = result_df
        _latest_results["clusters_json"] = summaries
        _latest_results["stats"] = stats

        return jsonify(_deep_convert({
            "success": True,
            "filename": filename,
            "stats": stats,
            "clusters": summaries,
            "graph": graph,
        }))
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/results")
def get_results():
    """Return the latest analysis results."""
    if _latest_results["clusters_json"] is None:
        return jsonify({"success": False, "error": "No analysis has been run yet"}), 404
    return jsonify(_deep_convert({
        "success": True,
        "stats": _latest_results["stats"],
        "clusters": _latest_results["clusters_json"],
    }))


@app.route("/api/cluster/<int:cluster_id>")
def get_cluster_detail(cluster_id):
    """Return detailed info for a single cluster."""
    if _latest_results["correlated_df"] is None:
        return jsonify({"success": False, "error": "No analysis has been run yet"}), 404

    df = _latest_results["correlated_df"]
    cluster_df = df[df["pred_cluster"] == cluster_id]
    if cluster_df.empty:
        return jsonify({"success": False, "error": f"Cluster {cluster_id} not found"}), 404

    records = cluster_df.head(200).to_dict(orient="records")
    return jsonify(_deep_convert({
        "success": True,
        "cluster_id": cluster_id,
        "size": len(cluster_df),
        "records": records,
    }))


# ---------------------------------------------------------------------------
# SIEM Routes
# ---------------------------------------------------------------------------

@app.route("/api/siem/connectors", methods=["GET"])
def list_siem_connectors():
    """List all registered SIEM connectors and their status."""
    return jsonify(_deep_convert({
        "success": True,
        "connectors": ingestion_engine.list_connectors(),
        "available_types": [
            {"name": k, "display_name": v.display_name}
            for k, v in CONNECTOR_REGISTRY.items()
        ],
    }))


@app.route("/api/siem/connectors", methods=["POST"])
def add_siem_connector():
    """Add a new SIEM connector.\n    Body: {id, type, config: {...}}"""
    try:
        body = request.get_json(force=True)
        cid = body.get("id", "").strip()
        ctype = body.get("type", "").strip()
        config = body.get("config", {})
        if not cid or not ctype:
            return jsonify({"success": False, "error": "id and type are required"}), 400
        connector = get_connector(ctype, config)
        ingestion_engine.add_connector(cid, connector)
        return jsonify({"success": True, "message": f"Connector '{cid}' added"})
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/siem/connectors/<connector_id>", methods=["DELETE"])
def remove_siem_connector(connector_id):
    """Remove a SIEM connector."""
    ok = ingestion_engine.remove_connector(connector_id)
    if ok:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Connector not found"}), 404


@app.route("/api/siem/connectors/<connector_id>/test", methods=["POST"])
def test_siem_connector(connector_id):
    """Test connectivity for a registered connector."""
    conn = ingestion_engine.get_connector(connector_id)
    if not conn:
        return jsonify({"success": False, "error": "Connector not found"}), 404
    result = conn.test_connection()
    return jsonify(_deep_convert({"success": True, "test_result": result}))


@app.route("/api/siem/engine/start", methods=["POST"])
def start_engine():
    """Start the live ingestion engine."""
    try:
        body = request.get_json(silent=True) or {}
        if "poll_interval" in body:
            poll_interval = int(body["poll_interval"])
            if poll_interval < 1 or poll_interval > 3600:
                return jsonify({"success": False, "error": "poll_interval must be between 1 and 3600 seconds"}), 400
            ingestion_engine.poll_interval = poll_interval
        if "correlation_interval" in body:
            corr_interval = int(body["correlation_interval"])
            if corr_interval < 1 or corr_interval > 3600:
                return jsonify({"success": False, "error": "correlation_interval must be between 1 and 3600 seconds"}), 400
            ingestion_engine.correlation_interval = corr_interval
        ingestion_engine.start()
        return jsonify({"success": True, "message": "Engine started"})
    except (ValueError, TypeError) as e:
        return jsonify({"success": False, "error": f"Invalid parameter value: {e}"}), 400
    except RuntimeError as e:
        return jsonify({"success": False, "error": f"Engine error: {e}"}), 500


@app.route("/api/siem/engine/stop", methods=["POST"])
def stop_engine():
    """Stop the live ingestion engine."""
    ingestion_engine.stop()
    return jsonify({"success": True, "message": "Engine stopped"})


@app.route("/api/siem/engine/status")
def engine_status():
    """Return engine stats, buffer size, connector statuses."""
    stats = ingestion_engine.get_stats()
    return jsonify(_deep_convert({"success": True, "engine": stats}))


@app.route("/api/siem/engine/correlate", methods=["POST"])
def force_correlate():
    """Trigger an immediate correlation run."""
    result = ingestion_engine.force_correlation()
    # Also update the dashboard's latest results
    corr_df = ingestion_engine.get_latest_correlation()
    if corr_df is not None and not corr_df.empty:
        _latest_results["correlated_df"] = corr_df
        _latest_results["clusters_json"] = _build_cluster_summary(corr_df)
        _latest_results["stats"] = _compute_stats(corr_df)
    return jsonify(_deep_convert(result))


@app.route("/api/siem/feed")
def live_feed():
    """Return the latest events from the ingestion buffer."""
    limit = request.args.get("limit", 100, type=int)
    if limit < 1 or limit > 10000:
        return jsonify({"success": False, "error": "limit must be between 1 and 10000"}), 400
    events = ingestion_engine.get_buffer_snapshot(last_n=limit)
    # Also include latest correlation results if available
    corr_df = ingestion_engine.get_latest_correlation()
    clusters = []
    graph = {"nodes": [], "edges": []}
    stats = {}
    if corr_df is not None and not corr_df.empty:
        clusters = _build_cluster_summary(corr_df)
        graph = _build_graph_data(corr_df)
        stats = _compute_stats(corr_df)
    return jsonify(_deep_convert({
        "success": True,
        "events": events[-limit:],
        "event_count": len(events),
        "clusters": clusters,
        "graph": graph,
        "stats": stats,
    }))


@app.route("/api/siem/alerts")
def get_alerts():
    """Return recent alerts generated by the correlation engine."""
    limit = request.args.get("limit", 50, type=int)
    if limit < 1 or limit > 1000:
        return jsonify({"success": False, "error": "limit must be between 1 and 1000"}), 400
    alerts = ingestion_engine.get_alerts(limit=limit)
    return jsonify(_deep_convert({"success": True, "alerts": alerts}))


@app.route("/api/siem/webhook/ingest", methods=["POST"])
def webhook_ingest():
    """Receive events from any SIEM via HTTP POST (webhook).

    The webhook connector must be registered first, or events are
    pushed directly into the ingestion buffer.
    """
    try:
        payload = request.get_json(force=True)
        headers = dict(request.headers)

        # Try to find a registered webhook connector
        webhook_conn = None
        for cid, conn in ingestion_engine._connectors.items():
            if isinstance(conn, WebhookConnector):
                webhook_conn = conn
                break

        if webhook_conn:
            count = webhook_conn.receive(payload, headers)
            # Also push normalised events directly into the engine buffer
            # so they are available for correlation immediately
            raw_events = payload if isinstance(payload, list) else [payload]
            df = webhook_conn.normalise(raw_events)
            ingestion_engine._ingest_dataframe(df, source="webhook")
        else:
            # No webhook connector registered — push directly to buffer
            events = payload if isinstance(payload, list) else [payload]
            count = ingestion_engine.ingest_raw(events, source="webhook-direct")

        return jsonify({"success": True, "events_ingested": count})
    except PermissionError as e:
        return jsonify({"success": False, "error": str(e)}), 403
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/siem/config/save", methods=["POST"])
def save_siem_config():
    """Persist current SIEM connector configs to disk."""
    try:
        ingestion_engine.save_config()
        return jsonify({"success": True})
    except (IOError, OSError, ValueError) as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/siem/config/load", methods=["POST"])
def load_siem_config():
    """Load SIEM connector configs from disk."""
    try:
        count = ingestion_engine.load_config()
        return jsonify({"success": True, "connectors_loaded": count})
    except (IOError, OSError, ValueError) as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# NEW: Curated Graph Stories & Cluster Filtering API
# ---------------------------------------------------------------------------

@app.route("/api/clusters/filter", methods=["POST"])
def filter_clusters():
    """
    Apply cluster filtering pipeline with scoring and semantic filters.
    
    Body: {
        top_k: int (default 20),
        strategy: str (top_k_size, top_k_severity, top_k_score, semantic, critical_assets),
        target_tactics: List[str] (optional),
        critical_assets: List[str] (optional),
        resolution: str (campaign_summary, entity_ego_net, alert_drill_down)
    }
    """
    try:
        global _cluster_filter, _latest_results
        
        if _latest_results["correlated_df"] is None:
            return jsonify({"success": False, "error": "No analysis has been run yet"}), 404
        
        body = request.get_json(silent=True) or {}
        
        # Get filter parameters
        top_k = int(body.get("top_k", 20))
        strategy = body.get("strategy", "top_k_score")
        target_tactics = body.get("target_tactics", [])
        critical_assets = body.get("critical_assets", [])
        resolution = body.get("resolution", "campaign_summary")
        
        # Create or update cluster filter
        _cluster_filter = create_cluster_filter(
            top_k=top_k,
            strategy=strategy,
            target_tactics=target_tactics,
            critical_assets=critical_assets,
            resolution=resolution
        )
        
        # Apply filtering
        df = _latest_results["correlated_df"]
        filtered_df, cluster_scores = _cluster_filter.filter_clusters(df)
        
        # Build graph at requested resolution
        graph_data = _cluster_filter.build_graph_data(filtered_df, cluster_scores)
        
        # Get summary stats for filtered-out clusters
        summary_stats = _cluster_filter.get_summary_stats(df, cluster_scores)
        
        # Update stored results
        _latest_results["correlated_df"] = filtered_df
        _latest_results["clusters_json"] = _build_cluster_summary(filtered_df)
        _latest_results["stats"] = _compute_stats(filtered_df)
        _latest_results["cluster_scores"] = [
            {
                "cluster_id": s.cluster_id,
                "size": s.size,
                "mean_severity": s.mean_severity,
                "importance_score": s.importance_score,
                "inclusion_reason": s.inclusion_reason,
                "tactics": s.tactics,
                "critical_assets": s.critical_assets
            }
            for s in cluster_scores
        ]
        
        # Add filter info to stats
        _latest_results["stats"]["filter_applied"] = True
        _latest_results["stats"]["filter_strategy"] = strategy
        _latest_results["stats"]["clusters_selected"] = len(cluster_scores)
        _latest_results["stats"]["clusters_filtered"] = summary_stats["filtered_clusters"]
        
        return jsonify(_deep_convert({
            "success": True,
            "stats": _latest_results["stats"],
            "clusters": _latest_results["clusters_json"],
            "cluster_scores": _latest_results["cluster_scores"],
            "graph": graph_data,
            "summary_stats": summary_stats
        }))
        
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/graph/view/<view_type>", methods=["POST"])
def get_graph_view(view_type):
    """
    Get multi-resolution graph view.
    
    View types:
    - campaign_summary: hosts ↔ tactics (highest level)
    - entity_ego_net: entity ego-network (drill-down)
    - alert_drill_down: raw alert details (most detailed)
    
    Body: {
        cluster_id: int (optional, for entity ego-net)
    }
    """
    try:
        global _cluster_filter, _lazy_graph_gen
        
        if _latest_results["correlated_df"] is None:
            return jsonify({"success": False, "error": "No analysis has been run yet"}), 404
        
        body = request.get_json(silent=True) or {}
        cluster_id = body.get("cluster_id")
        
        # Use lazy graph generator if parquet path exists
        if _latest_results.get("parquet_path") and _lazy_graph_gen:
            graph = _lazy_graph_gen.generate_graph(
                cluster_id=cluster_id,
                view_type=view_type,
                max_nodes=body.get("max_nodes", 100)
            )
            return jsonify(_deep_convert({
                "success": True,
                "view_type": view_type,
                "graph": graph
            }))
        
        # Otherwise use cluster filter
        if _cluster_filter is None:
            _cluster_filter = create_cluster_filter(resolution=view_type)
        
        df = _latest_results["correlated_df"]
        
        # Filter to specific cluster if requested
        if cluster_id is not None and "pred_cluster" in df.columns:
            df = df[df["pred_cluster"] == cluster_id]
        
        graph = _cluster_filter.build_graph_data(
            df, 
            resolution=view_type
        )
        
        return jsonify(_deep_convert({
            "success": True,
            "view_type": view_type,
            "cluster_id": cluster_id,
            "graph": graph
        }))
        
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# NEW: Knowledge Graph Enrichment API
# ---------------------------------------------------------------------------

@app.route("/api/enrichment/analyze", methods=["POST"])
def analyze_enrichment():
    """
    Apply knowledge graph enrichment to clusters.
    
    Enriches with:
    - MITRE ATT&CK technique matching
    - Threat intel (CVE, malware families)
    - Graph metrics (PageRank, betweenness)
    - Campaign linkage detection
    """
    try:
        global _kg_enricher, _latest_results
        
        if _latest_results["correlated_df"] is None:
            return jsonify({"success": False, "error": "No analysis has been run yet"}), 404
        
        # Initialize enricher if needed
        if _kg_enricher is None:
            _kg_enricher = create_enricher()
        
        df = _latest_results["correlated_df"]
        
        # Apply enrichment
        enriched_df, enrichments = _kg_enricher.enrich_clusters(df)
        
        # Get threat summary
        threat_summary = _kg_enricher.get_threat_summary(enrichments)
        
        # Update stored results
        _latest_results["correlated_df"] = enriched_df
        _latest_results["kg_enrichments"] = [
            {
                "cluster_id": e.cluster_id,
                "threat_score": e.combined_threat_score,
                "pagerank": e.pagerank_score,
                "betweenness": e.betweenness_score,
                "campaign_linkage": e.campaign_linkage,
                "matched_entities": [
                    {"id": ent.entity_id, "name": ent.name, "type": ent.entity_type}
                    for ent in e.matched_entities[:5]  # Top 5 matches
                ],
                "summary": e.enrichment_summary
            }
            for e in enrichments
        ]
        
        # Update clusters with enrichment data
        _latest_results["clusters_json"] = _build_cluster_summary(enriched_df)
        
        return jsonify(_deep_convert({
            "success": True,
            "threat_summary": threat_summary,
            "enrichments": _latest_results["kg_enrichments"],
            "clusters": _latest_results["clusters_json"]
        }))
        
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/enrichment/threat-intel", methods=["GET"])
def get_threat_intel():
    """Get available threat intelligence entities."""
    try:
        global _kg_enricher
        
        if _kg_enricher is None:
            _kg_enricher = create_enricher()
        
        store = _kg_enricher.threat_store
        
        # Get entities by type
        techniques = store.find_by_type("technique")
        malware = store.find_by_type("malware")
        cves = store.find_by_type("cve")
        
        return jsonify(_deep_convert({
            "success": True,
            "techniques": [{"id": e.entity_id, "name": e.name} for e in techniques],
            "malware": [{"id": e.entity_id, "name": e.name} for e in malware],
            "cves_count": len(cves)
        }))
        
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# NEW: Report Generation API
# ---------------------------------------------------------------------------

@app.route("/api/report/generate", methods=["POST"])
def generate_report():
    """
    Generate comprehensive analysis report in Markdown format.
    
    Body: {
        include_graphs: bool (default True),
        include_enrichment: bool (default True),
        format: str (default "markdown")
    }
    
    Returns report as downloadable markdown file.
    """
    try:
        if _latest_results["correlated_df"] is None:
            return jsonify({"success": False, "error": "No analysis has been run yet"}), 404
        
        body = request.get_json(silent=True) or {}
        include_graphs = body.get("include_graphs", True)
        include_enrichment = body.get("include_enrichment", True)
        
        df = _latest_results["correlated_df"]
        stats = _latest_results.get("stats", {})
        clusters = _latest_results.get("clusters_json", [])
        scores = _latest_results.get("cluster_scores", [])
        enrichments = _latest_results.get("kg_enrichments", [])
        
        # Build markdown report
        report_lines = [
            "# MITRE-CORE Analysis Report",
            "",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Executive Summary",
            "",
        ]
        
        # Stats section
        report_lines.extend([
            f"- **Total Events:** {stats.get('total_events', 0):,}",
            f"- **Clusters Identified:** {stats.get('num_clusters', 0)}",
            f"- **Correlation Method:** {stats.get('correlation_method', 'N/A')}",
            f"- **Runtime:** {stats.get('runtime_seconds', 0):.2f}s",
            ""
        ])
        
        if stats.get("filter_applied"):
            report_lines.extend([
                f"- **Filter Strategy:** {stats.get('filter_strategy', 'N/A')}",
                f"- **Clusters Selected:** {stats.get('clusters_selected', 0)}",
                f"- **Clusters Filtered:** {stats.get('clusters_filtered', 0)}",
                ""
            ])
        
        # Cluster details section
        report_lines.extend([
            "## Detected Attack Clusters",
            ""
        ])
        
        for cluster in clusters[:20]:  # Top 20 clusters
            cluster_id = cluster.get("cluster_id", 0)
            report_lines.extend([
                f"### Cluster {cluster_id}",
                "",
                f"- **Size:** {cluster.get('size', 0)} alerts",
                f"- **Attack Types:** {', '.join(cluster.get('attack_types', [])[:5])}",
                f"- **Tactics:** {', '.join(cluster.get('tactics', [])[:5])}",
                ""
            ])
            
            # Add cluster score if available
            score_info = next(
                (s for s in scores if s.get("cluster_id") == cluster_id), 
                None
            )
            if score_info:
                report_lines.extend([
                    f"- **Importance Score:** {score_info.get('importance_score', 0):.3f}",
                    f"- **Inclusion Reason:** {score_info.get('inclusion_reason', 'N/A')}",
                    ""
                ])
            
            # Add enrichment if available
            if include_enrichment:
                enrichment = next(
                    (e for e in enrichments if e.get("cluster_id") == cluster_id),
                    None
                )
                if enrichment:
                    report_lines.extend([
                        f"- **Threat Score:** {enrichment.get('threat_score', 0):.3f}",
                        f"- **Campaign Linkage:** {enrichment.get('campaign_linkage', 'None')}",
                        f"- **Matched Entities:** {', '.join(ent.get('name', '') for ent in enrichment.get('matched_entities', []))}",
                        ""
                    ])
        
        # Graph visualization section
        if include_graphs:
            report_lines.extend([
                "## Graph Visualizations",
                "",
                "Multi-resolution graph views have been generated:",
                "",
                "1. **Campaign Summary View** - Shows hosts ↔ tactics relationships",
                "2. **Entity Ego-Network** - Focused view around critical assets",
                "3. **Alert Drill-Down** - Detailed alert-level connections",
                ""
            ])
        
        # Conclusion
        report_lines.extend([
            "## Recommendations",
            "",
            "Based on the analysis:",
            ""
        ])
        
        # Add recommendations based on findings
        high_threat_clusters = [
            c for c in (enrichments or []) 
            if c.get("threat_score", 0) > 0.7
        ]
        if high_threat_clusters:
            report_lines.append(
                f"- **{len(high_threat_clusters)} high-threat clusters** detected. "
                "Immediate investigation recommended."
            )
        
        if scores:
            high_importance = [s for s in scores if s.get("importance_score", 0) > 0.7]
            report_lines.append(
                f"- **{len(high_importance)} high-importance clusters** identified "
                "for detailed review."
            )
        
        report_lines.extend([
            "",
            "---",
            "",
            "*Report generated by MITRE-CORE Threat Correlation Engine*"
        ])
        
        # Join and return
        report_content = "\n".join(report_lines)
        
        # Save to file for download
        report_filename = f"mitre_core_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
        report_path = Path("reports") / report_filename
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_content, encoding="utf-8")
        
        return jsonify({
            "success": True,
            "report": report_content,
            "filename": report_filename,
            "download_url": f"/api/report/download/{report_filename}"
        })
        
    except (ValueError, TypeError, KeyError) as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/report/download/<filename>")
def download_report(filename):
    """Download generated report file."""
    try:
        report_path = Path("reports") / filename
        if not report_path.exists():
            return jsonify({"success": False, "error": "Report not found"}), 404
        
        return send_from_directory(
            str(report_path.parent),
            report_path.name,
            as_attachment=True,
            mimetype="text/markdown"
        )
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Ensure template and static dirs exist
    os.makedirs(os.path.join(PROJECT_ROOT, "templates"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "static"), exist_ok=True)

    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "t")
    if debug_mode:
        logger.warning("Running in DEBUG mode - NOT recommended for production!")
    logger.info(f"Starting MITRE-CORE Dashboard on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
