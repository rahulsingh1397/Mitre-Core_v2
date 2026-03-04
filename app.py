"""MITRE-CORE Web Dashboard
Flask-based web application for cybersecurity alert correlation and visualization.
"""

import os
import sys
import json
import secrets
import time
import logging
import traceback
from pathlib import Path

# Load .env before anything else reads os.environ
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify, send_from_directory, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Ensure project root is on the path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.correlation_indexer import enhanced_correlation, calculate_adaptive_threshold
from core.postprocessing import correlation as legacy_correlation, clean_clusters, get_feature_chains
from core.output import types, Attack_stages, classify_attack_stage
import Testing
from siem.connectors import get_connector, CONNECTOR_REGISTRY, WebhookConnector
from siem.ingestion_engine import IngestionEngine

from security import (
    config as app_config,
    configure_logging,
    init_db,
    add_security_headers,
    require_auth,
    require_role,
    create_access_token,
    create_refresh_token,
    decode_token,
    revoke_token,
    hash_password,
    verify_password,
    audit_log,
    verify_webhook_hmac,
    encrypt_value,
    decrypt_value,
    _engine as _db_engine,
    _is_postgres,
)
from sqlalchemy import text as _sql

# ---------------------------------------------------------------------------
# Structured logging (must be before any logger usage)
# ---------------------------------------------------------------------------
configure_logging()
logger = logging.getLogger("mitre-core")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = app_config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = app_config.MAX_CONTENT_LENGTH

# --- CORS: restricted to configured origins ---
CORS(app, origins=app_config.CORS_ORIGINS, supports_credentials=True)

# --- Rate limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[app_config.RATELIMIT_DEFAULT],
    storage_uri=app_config.RATELIMIT_STORAGE_URI,
)

# --- Security headers on every response ---
app.after_request(add_security_headers)

# --- Request ID for tracing ---
@app.before_request
def _inject_request_id():
    g.request_id = secrets.token_hex(8)

# --- Initialise user database ---
init_db(app)

# Standard field names
ADDRESSES = ["SourceAddress", "DestinationAddress", "DeviceAddress"]
USERNAMES = ["SourceHostName", "DeviceHostName", "DestinationHostName"]

# In-memory store for the latest analysis results
_latest_results = {
    "raw_df": None,
    "correlated_df": None,
    "clusters_json": None,
    "stats": None,
}

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
            except Exception:
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
    db_status = "ok"
    try:
        with _db_engine.connect() as conn:
            conn.execute(_sql("SELECT 1"))
    except Exception as e:
        logger.error("Health check DB error: %s", str(e))
        db_status = "error"
        
    return jsonify({
        "status": "ok" if db_status == "ok" else "error", 
        "database": db_status,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }), 200 if db_status == "ok" else 503


@app.route("/api/generate-synthetic", methods=["POST"])
@require_auth
def generate_synthetic():
    """Generate synthetic test data using Testing.py and run correlation."""
    try:
        body = request.get_json(silent=True) or {}
        n_samples = int(body.get("n_samples", 60))
        n_samples = max(10, min(500, n_samples))

        logger.info(f"Generating {n_samples} synthetic events")
        raw_df = Testing.build_data(n_samples)

        # Run enhanced correlation
        result_df = enhanced_correlation(
            raw_df, USERNAMES, ADDRESSES,
            use_temporal=True, use_adaptive_threshold=True,
        )

        summaries = _build_cluster_summary(result_df)
        graph = _build_graph_data(result_df)
        stats = _compute_stats(result_df)

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
    except Exception as e:
        logger.error("Synthetic generation failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/upload", methods=["POST"])
@require_auth
def upload_csv():
    """Upload a CSV file and run correlation."""
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        file = request.files["file"]
        if not file.filename.endswith(".csv"):
            return jsonify({"success": False, "error": "Only CSV files are supported"}), 400

        raw_df = pd.read_csv(file, low_memory=False)
        logger.info(f"Uploaded {file.filename}: {len(raw_df)} rows, columns={list(raw_df.columns)}")

        # Detect available fields
        addresses = [c for c in ADDRESSES if c in raw_df.columns]
        usernames = [c for c in USERNAMES if c in raw_df.columns]

        if not addresses and not usernames:
            return jsonify({"success": False,
                            "error": "CSV must contain at least one of: " + ", ".join(ADDRESSES + USERNAMES)}), 400

        result_df = enhanced_correlation(
            raw_df, usernames, addresses,
            use_temporal=True, use_adaptive_threshold=True,
        )

        summaries = _build_cluster_summary(result_df)
        graph = _build_graph_data(result_df)
        stats = _compute_stats(result_df)

        _latest_results["raw_df"] = raw_df
        _latest_results["correlated_df"] = result_df
        _latest_results["clusters_json"] = summaries
        _latest_results["stats"] = stats

        return jsonify(_deep_convert({
            "success": True,
            "filename": file.filename,
            "stats": stats,
            "clusters": summaries,
            "graph": graph,
        }))
    except Exception as e:
        logger.error("Upload processing failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/results")
@require_auth
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
@require_auth
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
@require_auth
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
@require_auth
@require_role("admin")
def add_siem_connector():
    """Add a new SIEM connector.\n    Body: {id, type, config: {...}}"""
    try:
        body = request.get_json(force=True)
        cid = body.get("id", "").strip()
        ctype = body.get("type", "").strip()
        conn_config = body.get("config", {})
        if not cid or not ctype:
            return jsonify({"success": False, "error": "id and type are required"}), 400
        connector = get_connector(ctype, conn_config)
        ingestion_engine.add_connector(cid, connector)
        audit_log("siem_connector_added", f"type={ctype} id={cid}")
        return jsonify({"success": True, "message": f"Connector '{cid}' added"})
    except Exception as e:
        logger.error("Add connector failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/siem/connectors/<connector_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def remove_siem_connector(connector_id):
    """Remove a SIEM connector."""
    ok = ingestion_engine.remove_connector(connector_id)
    if ok:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Connector not found"}), 404


@app.route("/api/siem/connectors/<connector_id>/test", methods=["POST"])
@require_auth
def test_siem_connector(connector_id):
    """Test connectivity for a registered connector."""
    conn = ingestion_engine.get_connector(connector_id)
    if not conn:
        return jsonify({"success": False, "error": "Connector not found"}), 404
    result = conn.test_connection()
    return jsonify(_deep_convert({"success": True, "test_result": result}))


@app.route("/api/siem/engine/start", methods=["POST"])
@require_auth
@require_role("admin")
def start_engine():
    """Start the live ingestion engine."""
    try:
        body = request.get_json(silent=True) or {}
        if "poll_interval" in body:
            ingestion_engine.poll_interval = int(body["poll_interval"])
        if "correlation_interval" in body:
            ingestion_engine.correlation_interval = int(body["correlation_interval"])
        ingestion_engine.start()
        audit_log("engine_started")
        return jsonify({"success": True, "message": "Engine started"})
    except Exception as e:
        logger.error("Engine start failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/siem/engine/stop", methods=["POST"])
@require_auth
@require_role("admin")
def stop_engine():
    """Stop the live ingestion engine."""
    ingestion_engine.stop()
    return jsonify({"success": True, "message": "Engine stopped"})


@app.route("/api/siem/engine/status")
@require_auth
def engine_status():
    """Return engine stats, buffer size, connector statuses."""
    stats = ingestion_engine.get_stats()
    return jsonify(_deep_convert({"success": True, "engine": stats}))


@app.route("/api/siem/engine/correlate", methods=["POST"])
@require_auth
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
@require_auth
def live_feed():
    """Return the latest events from the ingestion buffer."""
    limit = request.args.get("limit", 100, type=int)
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
@require_auth
def get_alerts():
    """Return recent alerts generated by the correlation engine."""
    limit = request.args.get("limit", 50, type=int)
    alerts = ingestion_engine.get_alerts(limit=limit)
    return jsonify(_deep_convert({"success": True, "alerts": alerts}))


@app.route("/api/siem/webhook/ingest", methods=["POST"])
@limiter.limit("60 per minute")
def webhook_ingest():
    """Receive events from any SIEM via HTTP POST (webhook).

    The webhook connector must be registered first, or events are
    pushed directly into the ingestion buffer.
    Supports HMAC-SHA256 signature verification via X-Hub-Signature-256 header.
    """
    try:
        payload_bytes = request.get_data()
        payload = request.get_json(force=True)
        headers = dict(request.headers)

        # Try to find a registered webhook connector
        webhook_conn = None
        for cid, conn in ingestion_engine._connectors.items():
            if isinstance(conn, WebhookConnector):
                webhook_conn = conn
                break

        # HMAC signature verification (if connector has a secret)
        if webhook_conn and webhook_conn.secret:
            signature = headers.get("X-Hub-Signature-256", headers.get("X-Webhook-Secret", ""))
            if signature and signature.startswith("sha256="):
                if not verify_webhook_hmac(payload_bytes, signature, webhook_conn.secret):
                    logger.warning("Webhook HMAC verification failed from %s", request.remote_addr)
                    return jsonify({"success": False, "error": "Invalid signature"}), 403
            else:
                # Fall back to legacy secret comparison for backward compat
                pass

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
    except PermissionError:
        return jsonify({"success": False, "error": "Authentication failed"}), 403
    except Exception as e:
        logger.error("Webhook ingest failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/siem/config/save", methods=["POST"])
@require_auth
@require_role("admin")
def save_siem_config():
    """Persist current SIEM connector configs to disk."""
    try:
        ingestion_engine.save_config()
        audit_log("siem_config_saved")
        return jsonify({"success": True})
    except Exception as e:
        logger.error("Config save failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/siem/config/load", methods=["POST"])
@require_auth
@require_role("admin")
def load_siem_config():
    """Load SIEM connector configs from disk."""
    try:
        count = ingestion_engine.load_config()
        audit_log("siem_config_loaded", f"connectors={count}")
        return jsonify({"success": True, "connectors_loaded": count})
    except Exception as e:
        logger.error("Config load failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------------

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def auth_login():
    """Authenticate and return JWT tokens."""
    try:
        body = request.get_json(force=True)
        username = body.get("username", "").strip()
        password = body.get("password", "")
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password required"}), 400

        with _db_engine.connect() as conn:
            row = conn.execute(
                _sql("SELECT * FROM users WHERE username = :u AND active = 1"),
                {"u": username},
            ).mappings().fetchone()

        if row is None or not verify_password(password, row["password"]):
            audit_log("login_failed", f"username={username}", username=username)
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        with _db_engine.begin() as conn:
            conn.execute(
                _sql("UPDATE users SET last_login = :t WHERE id = :id"),
                {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "id": row["id"]},
            )

        access = create_access_token(username, row["role"])
        refresh = create_refresh_token(username, row["role"])
        audit_log("login_success", username=username)

        return jsonify({
            "success": True,
            "access_token": access,
            "refresh_token": refresh,
            "role": row["role"],
        })
    except Exception as e:
        logger.error("Login error: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/auth/refresh", methods=["POST"])
@limiter.limit("20 per minute")
def auth_refresh():
    """Exchange a refresh token for a new access token."""
    try:
        body = request.get_json(force=True)
        refresh_tok = body.get("refresh_token", "")
        if not refresh_tok:
            return jsonify({"success": False, "error": "Refresh token required"}), 400

        payload = decode_token(refresh_tok)
        if payload.get("type") != "refresh":
            return jsonify({"success": False, "error": "Invalid token type"}), 401

        access = create_access_token(payload["sub"], payload.get("role", "analyst"))
        return jsonify({"success": True, "access_token": access})
    except Exception:
        return jsonify({"success": False, "error": "Invalid or expired refresh token"}), 401


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def auth_logout():
    """Revoke the current access token."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:]
    try:
        payload = decode_token(token)
        revoke_token(payload.get("jti", ""))
        audit_log("logout")
    except Exception:
        pass
    return jsonify({"success": True, "message": "Logged out"})


@app.route("/api/auth/users", methods=["GET"])
@require_auth
@require_role("admin")
def list_users():
    """List all users (admin only)."""
    with _db_engine.connect() as conn:
        rows = conn.execute(
            _sql("SELECT id, username, role, active, created_at, last_login FROM users")
        ).mappings().fetchall()
    return jsonify({"success": True, "users": [dict(r) for r in rows]})


@app.route("/api/auth/users", methods=["POST"])
@require_auth
@require_role("admin")
def create_user():
    """Create a new user (admin only)."""
    try:
        body = request.get_json(force=True)
        username = body.get("username", "").strip()
        password = body.get("password", "")
        role = body.get("role", "analyst")
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password required"}), 400
        if role not in ("admin", "analyst", "viewer"):
            return jsonify({"success": False, "error": "Role must be admin, analyst, or viewer"}), 400

        try:
            with _db_engine.begin() as conn:
                conn.execute(
                    _sql("INSERT INTO users (username, password, role, created_at) VALUES (:u, :p, :r, :c)"),
                    {"u": username, "p": hash_password(password), "r": role,
                     "c": time.strftime("%Y-%m-%dT%H:%M:%SZ")},
                )
        except Exception as db_exc:
            if "unique" in str(db_exc).lower() or "duplicate" in str(db_exc).lower():
                return jsonify({"success": False, "error": "Username already exists"}), 409
            raise
        audit_log("user_created", f"username={username} role={role}")
        return jsonify({"success": True, "message": f"User '{username}' created"})
    except Exception as e:
        logger.error("Create user failed: %s", traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Ensure template and static dirs exist
    os.makedirs(os.path.join(PROJECT_ROOT, "templates"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "static"), exist_ok=True)

    port = app_config.PORT
    debug = app_config.DEBUG
    logger.info("Starting MITRE-CORE Dashboard on http://localhost:%d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
