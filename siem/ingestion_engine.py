"""
Live Ingestion Engine for MITRE-CORE
Manages SIEM connections, polls for new events on a configurable interval,
buffers them, runs correlation in near-real-time, and emits alerts.
"""

import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd

# Ensure project root is on sys.path so that absolute package imports
# (core.*, siem.*, security) work when this module is imported standalone
# (e.g. from unit tests or scripts outside the app entry point).
import sys as _sys
import os as _os
_PROJECT_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)

logger = logging.getLogger("mitre-core.ingestion")

# Avoid circular import — lazy-load correlation at runtime
_enhanced_correlation = None


def _get_correlation_fn():
    global _enhanced_correlation
    if _enhanced_correlation is None:
        from core.correlation_indexer import enhanced_correlation  # fixed: was 'from correlation_indexer'
        _enhanced_correlation = enhanced_correlation
    return _enhanced_correlation


# ---------------------------------------------------------------------------
# Alert severity levels
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"


# ---------------------------------------------------------------------------
# Ingestion Engine
# ---------------------------------------------------------------------------
class IngestionEngine:
    """Orchestrates live SIEM ingestion, buffering, and correlation."""

    # Standard MITRE-CORE field lists
    ADDRESSES = ["SourceAddress", "DestinationAddress", "DeviceAddress"]
    USERNAMES = ["SourceHostName", "DeviceHostName", "DestinationHostName"]

    def __init__(
        self,
        poll_interval: int = 30,
        correlation_interval: int = 60,
        buffer_max: int = 50000,
        correlation_window: int = 5000,
        alert_callback: Optional[Callable[[Dict], None]] = None,
    ):
        """
        Args:
            poll_interval: Seconds between SIEM polls.
            correlation_interval: Seconds between correlation runs.
            buffer_max: Maximum events kept in the rolling buffer.
            correlation_window: Number of most-recent events fed to each
                                correlation run.
            alert_callback: Optional function called with each new alert dict.
        """
        self.poll_interval = poll_interval
        self.correlation_interval = correlation_interval
        self.buffer_max = buffer_max
        self.correlation_window = correlation_window
        self.alert_callback = alert_callback

        # Active connectors  {id: connector_instance}
        self._connectors: Dict[str, Any] = {}
        self._connector_configs: Dict[str, Dict] = {}

        # Event buffer (thread-safe deque)
        self._buffer: deque = deque(maxlen=buffer_max)
        self._buffer_lock = threading.Lock()

        # Correlation results
        self._last_correlation: Optional[pd.DataFrame] = None
        self._last_correlation_time: Optional[str] = None
        self._correlation_lock = threading.Lock()

        # Alerts
        self._alerts: deque = deque(maxlen=5000)
        self._alerts_lock = threading.Lock()

        # Threads
        self._poll_thread: Optional[threading.Thread] = None
        self._corr_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self._stats = {
            "total_events_ingested": 0,
            "total_correlations_run": 0,
            "total_alerts_generated": 0,
            "engine_started": None,
            "last_poll": None,
            "last_correlation": None,
        }
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Connector management
    # ------------------------------------------------------------------

    def add_connector(self, connector_id: str, connector) -> bool:
        """Register a SIEM connector."""
        self._connectors[connector_id] = connector
        self._connector_configs[connector_id] = connector.config
        logger.info("Connector added: %s (%s)", connector_id, connector.display_name)
        return True

    def remove_connector(self, connector_id: str) -> bool:
        conn = self._connectors.pop(connector_id, None)
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass
            self._connector_configs.pop(connector_id, None)
            logger.info("Connector removed: %s", connector_id)
            return True
        return False

    def get_connector(self, connector_id: str):
        return self._connectors.get(connector_id)

    def list_connectors(self) -> List[Dict]:
        result = []
        for cid, conn in self._connectors.items():
            info = conn.status()
            info["id"] = cid
            result.append(info)
        return result

    # ------------------------------------------------------------------
    # Engine lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the polling and correlation background threads."""
        if self._poll_thread and self._poll_thread.is_alive():
            logger.warning("Engine already running")
            return

        self._stop_event.clear()

        # Connect all connectors
        for cid, conn in self._connectors.items():
            if not conn.is_connected:
                try:
                    conn.connect()
                except Exception as exc:
                    logger.error("Failed to connect %s: %s", cid, exc)

        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="siem-poll"
        )
        self._corr_thread = threading.Thread(
            target=self._correlation_loop, daemon=True, name="siem-corr"
        )
        self._poll_thread.start()
        self._corr_thread.start()

        with self._stats_lock:
            self._stats["engine_started"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Ingestion engine started (poll=%ds, corr=%ds)",
            self.poll_interval, self.correlation_interval,
        )

    def stop(self) -> None:
        """Gracefully stop the engine."""
        self._stop_event.set()
        for t in (self._poll_thread, self._corr_thread):
            if t:
                t.join(timeout=5)
        # Disconnect all
        for cid, conn in self._connectors.items():
            try:
                conn.disconnect()
            except Exception:
                pass
        logger.info("Ingestion engine stopped")

    @property
    def is_running(self) -> bool:
        return (
            self._poll_thread is not None
            and self._poll_thread.is_alive()
        )

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            for cid, conn in list(self._connectors.items()):
                if self._stop_event.is_set():
                    break
                try:
                    raw_events = conn.poll(since=self._stats.get("last_poll"), limit=2000)
                    if raw_events:
                        df = conn.normalise(raw_events)
                        self._ingest_dataframe(df, source=cid)
                except Exception as exc:
                    logger.error("Poll error [%s]: %s", cid, exc)

            with self._stats_lock:
                self._stats["last_poll"] = datetime.now(timezone.utc).isoformat()

            # Sleep in small increments so we can stop quickly
            for _ in range(self.poll_interval * 2):
                if self._stop_event.is_set():
                    return
                time.sleep(0.5)

    # ------------------------------------------------------------------
    # Correlation loop
    # ------------------------------------------------------------------

    def _correlation_loop(self) -> None:
        while not self._stop_event.is_set():
            # Wait for the interval
            for _ in range(self.correlation_interval * 2):
                if self._stop_event.is_set():
                    return
                time.sleep(0.5)

            try:
                self._run_correlation()
            except Exception as exc:
                logger.error("Correlation error: %s", exc)

    def _run_correlation(self) -> None:
        """Run enhanced_correlation on the most recent events in the buffer."""
        with self._buffer_lock:
            if len(self._buffer) < 2:
                return
            window = list(self._buffer)[-self.correlation_window:]

        df = pd.DataFrame(window)

        # Determine available fields
        addresses = [c for c in self.ADDRESSES if c in df.columns]
        usernames = [c for c in self.USERNAMES if c in df.columns]

        if not addresses and not usernames:
            logger.warning("No usable address/username fields in buffer")
            return

        correlate = _get_correlation_fn()
        result_df = correlate(
            df, usernames, addresses,
            use_temporal=True, use_adaptive_threshold=True,
        )

        now_iso = datetime.now(timezone.utc).isoformat()

        with self._correlation_lock:
            prev_clusters = set()
            if self._last_correlation is not None and "pred_cluster" in self._last_correlation.columns:
                prev_clusters = set(self._last_correlation["pred_cluster"].unique())

            self._last_correlation = result_df
            self._last_correlation_time = now_iso

        with self._stats_lock:
            self._stats["total_correlations_run"] += 1
            self._stats["last_correlation"] = now_iso

        # Detect new / changed clusters → generate alerts
        new_clusters = set(result_df["pred_cluster"].unique())
        emerging = new_clusters - prev_clusters

        for cid in emerging:
            cluster_df = result_df[result_df["pred_cluster"] == cid]
            alert = self._build_alert(cid, cluster_df)
            if alert:
                with self._alerts_lock:
                    self._alerts.appendleft(alert)
                with self._stats_lock:
                    self._stats["total_alerts_generated"] += 1
                if self.alert_callback:
                    try:
                        self.alert_callback(alert)
                    except Exception:
                        pass

        n_clusters = len(new_clusters)
        n_new = len(emerging)
        logger.info(
            "Correlation run: %d events → %d clusters (%d new)",
            len(result_df), n_clusters, n_new,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ingest_dataframe(self, df: pd.DataFrame, source: str = "") -> None:
        """Add normalised rows to the buffer."""
        records = df.to_dict(orient="records")
        for r in records:
            r["_source_connector"] = source
            r["_ingested_at"] = datetime.now(timezone.utc).isoformat()

        with self._buffer_lock:
            self._buffer.extend(records)

        with self._stats_lock:
            self._stats["total_events_ingested"] += len(records)

        logger.debug("Ingested %d events from %s (buffer: %d)",
                      len(records), source, len(self._buffer))

    def ingest_raw(self, events: List[Dict], source: str = "manual") -> int:
        """Manually push pre-normalised events into the buffer."""
        for evt in events:
            evt.setdefault("EndDate", datetime.now(timezone.utc).isoformat())
            evt["_source_connector"] = source
            evt["_ingested_at"] = datetime.now(timezone.utc).isoformat()

        with self._buffer_lock:
            self._buffer.extend(events)

        with self._stats_lock:
            self._stats["total_events_ingested"] += len(events)

        return len(events)

    def _build_alert(self, cluster_id: int, cluster_df: pd.DataFrame) -> Optional[Dict]:
        """Create an alert dict from a newly detected cluster."""
        size = len(cluster_df)
        if size < 2:
            return None

        alert: Dict[str, Any] = {
            "id": f"ALERT-{int(time.time()*1000)}-C{cluster_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cluster_id": int(cluster_id),
            "cluster_size": size,
            "severity": SEVERITY_INFO,
            "title": f"New correlated cluster detected (ID {cluster_id}, {size} events)",
            "details": {},
        }

        # Determine severity from cluster size and attack diversity
        attack_col = None
        for col in ("MalwareIntelAttackType", "AttackType"):
            if col in cluster_df.columns:
                attack_col = col
                break

        attack_types = []
        if attack_col:
            attack_types = list(cluster_df[attack_col].dropna().unique())
            alert["details"]["attack_types"] = attack_types

        n_types = len(attack_types)
        if size >= 10 and n_types >= 4:
            alert["severity"] = SEVERITY_CRITICAL
        elif size >= 5 and n_types >= 3:
            alert["severity"] = SEVERITY_HIGH
        elif size >= 3 and n_types >= 2:
            alert["severity"] = SEVERITY_MEDIUM
        elif size >= 2:
            alert["severity"] = SEVERITY_LOW

        alert["title"] = (
            f"[{alert['severity']}] Correlated cluster {cluster_id}: "
            f"{size} events, {n_types} attack type(s)"
        )

        # Add IP addresses
        for col in self.ADDRESSES:
            if col in cluster_df.columns:
                vals = list(cluster_df[col].dropna().unique()[:10])
                if vals:
                    alert["details"][col] = vals

        # Date range
        if "EndDate" in cluster_df.columns:
            try:
                dates = pd.to_datetime(cluster_df["EndDate"], errors="coerce")
                alert["details"]["start_date"] = str(dates.min())
                alert["details"]["end_date"] = str(dates.max())
            except Exception:
                pass

        return alert

    # ------------------------------------------------------------------
    # Public query methods
    # ------------------------------------------------------------------

    def get_buffer_snapshot(self, last_n: int = 100) -> List[Dict]:
        """Return the last N events from the buffer."""
        with self._buffer_lock:
            return list(self._buffer)[-last_n:]

    def get_latest_correlation(self) -> Optional[pd.DataFrame]:
        with self._correlation_lock:
            return self._last_correlation

    def get_alerts(self, limit: int = 100) -> List[Dict]:
        with self._alerts_lock:
            return list(self._alerts)[:limit]

    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            stats = dict(self._stats)
        stats["buffer_size"] = len(self._buffer)
        stats["active_connectors"] = len(self._connectors)
        stats["running"] = self.is_running
        return stats

    def force_correlation(self) -> Dict[str, Any]:
        """Trigger an immediate correlation run (outside the normal schedule)."""
        try:
            self._run_correlation()
            return {"success": True, "message": "Correlation completed"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    # Keys whose values should be encrypted at rest
    _SENSITIVE_KEYS = frozenset({
        "token", "api_key", "api_token", "password", "client_secret", "secret",
    })

    def _redact_config(self, cfg: dict) -> dict:
        """Return a copy of *cfg* with sensitive values encrypted."""
        from core.security_utils import encrypt_value  # fixed: was 'from security'
        out = {}
        for k, v in cfg.items():
            if k in self._SENSITIVE_KEYS and isinstance(v, str) and v:
                out[k] = encrypt_value(v)
            else:
                out[k] = v
        return out

    def _restore_config(self, cfg: dict) -> dict:
        """Return a copy of *cfg* with sensitive values decrypted."""
        from core.security_utils import decrypt_value  # fixed: was 'from security'
        out = {}
        for k, v in cfg.items():
            if k in self._SENSITIVE_KEYS and isinstance(v, str) and v:
                out[k] = decrypt_value(v)
            else:
                out[k] = v
        return out

    def save_config(self, path: str = "siem_config.json") -> None:
        """Save current connector configs to a JSON file (credentials encrypted)."""
        data = {}
        for cid, conn in self._connectors.items():
            data[cid] = {
                "type": conn.name,
                "config": self._redact_config(conn.config),
            }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("SIEM config saved to %s", path)

    def load_config(self, path: str = "siem_config.json") -> int:
        """Load connector configs from a JSON file and instantiate them."""
        if not os.path.exists(path):
            return 0
        from siem.connectors import get_connector
        with open(path) as f:
            data = json.load(f)
        count = 0
        for cid, entry in data.items():
            try:
                decrypted_cfg = self._restore_config(entry["config"])
                conn = get_connector(entry["type"], decrypted_cfg)
                self.add_connector(cid, conn)
                count += 1
            except Exception as exc:
                logger.error("Failed to load connector %s: %s", cid, exc)
        logger.info("Loaded %d connectors from %s", count, path)
        return count
