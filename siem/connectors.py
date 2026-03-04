"""
SIEM Connector Adapters for MITRE-CORE
Supports: Splunk, Elastic/ELK, Microsoft Sentinel, IBM QRadar, Syslog, Webhook (generic).

Each connector normalises raw SIEM events into the standard MITRE-CORE schema:
    AlertId, SourceAddress, DestinationAddress, DeviceAddress,
    SourceUserName, SourceHostName, DeviceHostName, DestinationHostName,
    MalwareIntelAttackType, AttackSeverity, EndDate
"""

import abc
import hashlib
import hmac
import json
import logging
import socket
import ssl
import struct
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import pandas as pd
import requests

logger = logging.getLogger("mitre-core.siem")

# ---------------------------------------------------------------------------
# Standard output schema
# ---------------------------------------------------------------------------
STANDARD_COLUMNS = [
    "AlertId", "SourceAddress", "DestinationAddress", "DeviceAddress",
    "SourceUserName", "SourceHostName", "DeviceHostName", "DestinationHostName",
    "MalwareIntelAttackType", "AttackSeverity", "EndDate", "CustomerName",
]


def _ts_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------
class BaseSIEMConnector(abc.ABC):
    """Abstract base for every SIEM adapter."""

    name: str = "base"
    display_name: str = "Base Connector"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._connected = False
        self._last_error: Optional[str] = None
        self._events_received: int = 0
        self._lock = threading.Lock()
        self.field_mapping: Dict[str, str] = config.get("field_mapping", {})
        self.customer_name: str = config.get("customer_name", "UNKNOWN")

    # -- lifecycle -----------------------------------------------------------
    @abc.abstractmethod
    def connect(self) -> bool:
        """Establish connection. Return True on success."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Tear down connection."""

    @abc.abstractmethod
    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        """Pull new raw events since *since* (ISO-8601). Return list of dicts."""

    def test_connection(self) -> Dict[str, Any]:
        """Quick connectivity check."""
        try:
            ok = self.connect()
            return {"success": ok, "error": self._last_error}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
        finally:
            try:
                self.disconnect()
            except Exception:
                pass

    # -- normalisation -------------------------------------------------------
    def normalise(self, raw_events: List[Dict]) -> pd.DataFrame:
        """Map raw SIEM fields → standard MITRE-CORE columns."""
        rows = []
        for evt in raw_events:
            row: Dict[str, Any] = {}
            for std_col in STANDARD_COLUMNS:
                # Check explicit mapping first, then try exact match, then case-insensitive
                src_field = self.field_mapping.get(std_col)
                if src_field and src_field in evt:
                    row[std_col] = evt[src_field]
                elif std_col in evt:
                    row[std_col] = evt[std_col]
                else:
                    # Case-insensitive fallback
                    lower_map = {k.lower(): k for k in evt}
                    if std_col.lower() in lower_map:
                        row[std_col] = evt[lower_map[std_col.lower()]]
                    else:
                        row[std_col] = None
            # Ensure CustomerName
            if not row.get("CustomerName"):
                row["CustomerName"] = self.customer_name
            # Ensure EndDate
            if not row.get("EndDate"):
                row["EndDate"] = _ts_now_iso()
            rows.append(row)

        df = pd.DataFrame(rows, columns=STANDARD_COLUMNS)
        with self._lock:
            self._events_received += len(rows)
        return df

    # -- status --------------------------------------------------------------
    @property
    def is_connected(self) -> bool:
        return self._connected

    def status(self) -> Dict[str, Any]:
        return {
            "connector": self.name,
            "display_name": self.display_name,
            "connected": self._connected,
            "events_received": self._events_received,
            "last_error": self._last_error,
            "config_keys": list(self.config.keys()),
        }


# ---------------------------------------------------------------------------
# Splunk (via REST / HEC)
# ---------------------------------------------------------------------------
class SplunkConnector(BaseSIEMConnector):
    """Connect to Splunk via the REST API (searches) or HTTP Event Collector."""

    name = "splunk"
    display_name = "Splunk Enterprise / Cloud"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "https://localhost:8089")
        self.token = config.get("token", "")
        self.search_query = config.get(
            "search_query",
            'search index=main sourcetype="syslog" | head 1000',
        )
        self.verify_ssl = config.get("verify_ssl", True)
        self._session: Optional[requests.Session] = None

    def connect(self) -> bool:
        try:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            })
            self._session.verify = self.verify_ssl
            # Quick auth check
            r = self._session.get(
                urljoin(self.base_url, "/services/authentication/current-context"),
                params={"output_mode": "json"},
                timeout=10,
            )
            r.raise_for_status()
            self._connected = True
            self._last_error = None
            logger.info("Splunk connected: %s", self.base_url)
            return True
        except Exception as exc:
            self._last_error = str(exc)
            self._connected = False
            logger.error("Splunk connection failed: %s", exc)
            return False

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
        self._connected = False

    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        if not self._session:
            self.connect()
        query = self.search_query
        if since:
            query += f' earliest="{since}"'
        # Create a one-shot search job
        try:
            r = self._session.post(
                urljoin(self.base_url, "/services/search/jobs"),
                data={"search": query, "output_mode": "json",
                      "exec_mode": "oneshot", "count": limit},
                timeout=60,
            )
            r.raise_for_status()
            data = r.json()
            results = data.get("results", [])
            logger.info("Splunk poll: %d events", len(results))
            return results
        except Exception as exc:
            self._last_error = str(exc)
            logger.error("Splunk poll error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Elastic / ELK
# ---------------------------------------------------------------------------
class ElasticConnector(BaseSIEMConnector):
    """Connect to Elasticsearch / Elastic SIEM."""

    name = "elastic"
    display_name = "Elastic SIEM / ELK Stack"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "http://localhost:9200")
        self.index_pattern = config.get("index_pattern", "filebeat-*")
        self.api_key = config.get("api_key", "")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.verify_ssl = config.get("verify_ssl", True)
        self.query_body = config.get("query", {"match_all": {}})
        self._session: Optional[requests.Session] = None

    def connect(self) -> bool:
        try:
            self._session = requests.Session()
            self._session.verify = self.verify_ssl
            if self.api_key:
                self._session.headers["Authorization"] = f"ApiKey {self.api_key}"
            elif self.username:
                self._session.auth = (self.username, self.password)
            r = self._session.get(urljoin(self.base_url, "/"), timeout=10)
            r.raise_for_status()
            info = r.json()
            logger.info("Elastic connected: %s (cluster: %s)",
                        self.base_url, info.get("cluster_name", "?"))
            self._connected = True
            self._last_error = None
            return True
        except Exception as exc:
            self._last_error = str(exc)
            self._connected = False
            logger.error("Elastic connection failed: %s", exc)
            return False

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
        self._connected = False

    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        if not self._session:
            self.connect()
        body: Dict[str, Any] = {"size": limit, "query": self.query_body}
        if since:
            body["query"] = {
                "bool": {
                    "must": [self.query_body],
                    "filter": [{"range": {"@timestamp": {"gte": since}}}],
                }
            }
        body["sort"] = [{"@timestamp": {"order": "asc"}}]
        try:
            r = self._session.post(
                urljoin(self.base_url, f"/{self.index_pattern}/_search"),
                json=body, timeout=30,
            )
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            results = [h.get("_source", {}) for h in hits]
            logger.info("Elastic poll: %d events", len(results))
            return results
        except Exception as exc:
            self._last_error = str(exc)
            logger.error("Elastic poll error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Microsoft Sentinel (via Log Analytics REST API)
# ---------------------------------------------------------------------------
class SentinelConnector(BaseSIEMConnector):
    """Connect to Microsoft Sentinel via the Log Analytics query API."""

    name = "sentinel"
    display_name = "Microsoft Sentinel"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.workspace_id = config.get("workspace_id", "")
        self.tenant_id = config.get("tenant_id", "")
        self.client_id = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")
        self.kql_query = config.get(
            "kql_query",
            "SecurityAlert | project TimeGenerated, AlertName, Severity, "
            "Entities, Tactics, ProviderName | take 1000",
        )
        self._token: Optional[str] = None
        self._session: Optional[requests.Session] = None

    def _get_token(self) -> str:
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://api.loganalytics.io/.default",
        }
        r = requests.post(url, data=data, timeout=15)
        r.raise_for_status()
        return r.json()["access_token"]

    def connect(self) -> bool:
        try:
            self._token = self._get_token()
            self._session = requests.Session()
            self._session.headers["Authorization"] = f"Bearer {self._token}"
            self._connected = True
            self._last_error = None
            logger.info("Sentinel connected: workspace %s", self.workspace_id)
            return True
        except Exception as exc:
            self._last_error = str(exc)
            self._connected = False
            logger.error("Sentinel connection failed: %s", exc)
            return False

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
        self._connected = False

    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        if not self._session:
            self.connect()
        query = self.kql_query
        if since:
            query = f'{query} | where TimeGenerated >= datetime("{since}")'
        try:
            url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
            r = self._session.post(url, json={"query": query}, timeout=30)
            r.raise_for_status()
            tables = r.json().get("tables", [])
            if not tables:
                return []
            columns = [c["name"] for c in tables[0].get("columns", [])]
            rows = tables[0].get("rows", [])
            results = [dict(zip(columns, row)) for row in rows[:limit]]
            logger.info("Sentinel poll: %d events", len(results))
            return results
        except Exception as exc:
            self._last_error = str(exc)
            logger.error("Sentinel poll error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# IBM QRadar (via REST API)
# ---------------------------------------------------------------------------
class QRadarConnector(BaseSIEMConnector):
    """Connect to IBM QRadar via the REST API."""

    name = "qradar"
    display_name = "IBM QRadar"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "https://localhost")
        self.api_token = config.get("api_token", "")
        self.verify_ssl = config.get("verify_ssl", True)
        self.aql_query = config.get(
            "aql_query",
            "SELECT * FROM events WHERE devicetime > '{}' LIMIT 1000",
        )
        self._session: Optional[requests.Session] = None

    def connect(self) -> bool:
        try:
            self._session = requests.Session()
            self._session.headers.update({
                "SEC": self.api_token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
            self._session.verify = self.verify_ssl
            r = self._session.get(
                urljoin(self.base_url, "/api/system/about"),
                timeout=10,
            )
            r.raise_for_status()
            logger.info("QRadar connected: %s", self.base_url)
            self._connected = True
            self._last_error = None
            return True
        except Exception as exc:
            self._last_error = str(exc)
            self._connected = False
            logger.error("QRadar connection failed: %s", exc)
            return False

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
        self._connected = False

    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        if not self._session:
            self.connect()
        since_str = since or "1970-01-01T00:00:00Z"
        query = self.aql_query.format(since_str)
        try:
            # Create search
            r = self._session.post(
                urljoin(self.base_url, "/api/ariel/searches"),
                params={"query_expression": query},
                timeout=30,
            )
            r.raise_for_status()
            search_id = r.json().get("search_id")
            # Poll for completion (simplified — real impl would loop)
            time.sleep(2)
            r = self._session.get(
                urljoin(self.base_url, f"/api/ariel/searches/{search_id}/results"),
                params={"Range": f"items=0-{limit - 1}"},
                timeout=30,
            )
            r.raise_for_status()
            events = r.json().get("events", r.json().get("flows", []))
            logger.info("QRadar poll: %d events", len(events))
            return events
        except Exception as exc:
            self._last_error = str(exc)
            logger.error("QRadar poll error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Syslog (UDP / TCP listener)
# ---------------------------------------------------------------------------
class SyslogConnector(BaseSIEMConnector):
    """Receive events via Syslog (UDP or TCP). Runs a listener thread."""

    name = "syslog"
    display_name = "Syslog (UDP/TCP)"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "0.0.0.0")
        self.port = int(config.get("port", 1514))
        self.protocol = config.get("protocol", "udp").lower()
        self.max_buffer = int(config.get("max_buffer", 10000))
        self._buffer: List[Dict] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            if self.protocol == "tcp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind((self.host, self.port))
                self._sock.listen(5)
                self._sock.settimeout(1.0)
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind((self.host, self.port))
                self._sock.settimeout(1.0)

            self._stop_event.clear()
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            self._connected = True
            self._last_error = None
            logger.info("Syslog listener started on %s:%d (%s)",
                        self.host, self.port, self.protocol)
            return True
        except Exception as exc:
            self._last_error = str(exc)
            self._connected = False
            logger.error("Syslog bind failed: %s", exc)
            return False

    def disconnect(self) -> None:
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        self._connected = False

    def _listen_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self.protocol == "tcp":
                    try:
                        conn, addr = self._sock.accept()
                        data = conn.recv(65535)
                        conn.close()
                    except socket.timeout:
                        continue
                else:
                    try:
                        data, addr = self._sock.recvfrom(65535)
                    except socket.timeout:
                        continue

                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    evt = self._parse_syslog(message)
                    with self._lock:
                        if len(self._buffer) >= self.max_buffer:
                            self._buffer.pop(0)
                        self._buffer.append(evt)
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.debug("Syslog recv error: %s", exc)

    @staticmethod
    def _parse_syslog(message: str) -> Dict[str, Any]:
        """Best-effort parse of a syslog line into a dict.

        Handles:
        - JSON payloads
        - CEF (Common Event Format)
        - Plain text with key=value pairs
        """
        # Try JSON first
        try:
            obj = json.loads(message)
            if isinstance(obj, dict):
                obj.setdefault("EndDate", _ts_now_iso())
                return obj
        except (json.JSONDecodeError, ValueError):
            pass

        # Try CEF: CEF:0|vendor|product|version|id|name|severity|extensions
        if message.startswith("CEF:"):
            return SyslogConnector._parse_cef(message)

        # Key=value fallback
        evt: Dict[str, Any] = {"raw": message, "EndDate": _ts_now_iso()}
        for token in message.split():
            if "=" in token:
                k, _, v = token.partition("=")
                evt[k] = v
        return evt

    @staticmethod
    def _parse_cef(message: str) -> Dict[str, Any]:
        parts = message.split("|", 7)
        evt: Dict[str, Any] = {"EndDate": _ts_now_iso()}
        if len(parts) >= 7:
            evt["DeviceVendor"] = parts[1]
            evt["DeviceProduct"] = parts[2]
            evt["AlertId"] = parts[4]
            evt["MalwareIntelAttackType"] = parts[5]
            evt["AttackSeverity"] = parts[6]
            # Parse extension key=value pairs
            if len(parts) > 7:
                for token in parts[7].split():
                    if "=" in token:
                        k, _, v = token.partition("=")
                        # Map common CEF keys
                        cef_map = {
                            "src": "SourceAddress", "dst": "DestinationAddress",
                            "dvc": "DeviceAddress", "suser": "SourceUserName",
                            "shost": "SourceHostName", "dhost": "DestinationHostName",
                        }
                        evt[cef_map.get(k, k)] = v
        return evt

    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        with self._lock:
            events = list(self._buffer[:limit])
            self._buffer = self._buffer[limit:]
        return events


# ---------------------------------------------------------------------------
# Webhook (generic HTTP receiver — any SIEM can POST here)
# ---------------------------------------------------------------------------
class WebhookConnector(BaseSIEMConnector):
    """Receives events via HTTP POST from any SIEM webhook / SOAR playbook.

    Unlike other connectors this one doesn't poll; it exposes a Flask
    endpoint that the SIEM pushes to.  Events are buffered and drained
    by the ingestion engine.
    """

    name = "webhook"
    display_name = "Webhook (Generic HTTP)"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.secret = config.get("secret", "")
        self.max_buffer = int(config.get("max_buffer", 10000))
        self._buffer: List[Dict] = []

    def connect(self) -> bool:
        self._connected = True
        self._last_error = None
        logger.info("Webhook connector ready (events accepted via POST /api/siem/webhook/ingest)")
        return True

    def disconnect(self) -> None:
        self._connected = False

    def receive(self, payload: Any, headers: Optional[Dict] = None) -> int:
        """Called by the Flask route when a POST arrives.

        Returns the number of events ingested.
        """
        # Validate secret if configured (constant-time comparison)
        if self.secret:
            provided = (headers or {}).get("X-Webhook-Secret", "")
            # Also support HMAC-SHA256 via X-Hub-Signature-256
            sig_header = (headers or {}).get("X-Hub-Signature-256", "")
            if sig_header.startswith("sha256="):
                # HMAC verification
                import json as _json
                payload_bytes = _json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
                expected = hmac.new(self.secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(f"sha256={expected}", sig_header):
                    raise PermissionError("Invalid webhook HMAC signature")
            elif not hmac.compare_digest(provided, self.secret):
                raise PermissionError("Invalid webhook secret")

        events: List[Dict] = []
        if isinstance(payload, list):
            events = payload
        elif isinstance(payload, dict):
            # Some SIEMs wrap events in a key
            for key in ("events", "alerts", "data", "records", "results"):
                if key in payload and isinstance(payload[key], list):
                    events = payload[key]
                    break
            if not events:
                events = [payload]
        else:
            raise ValueError(f"Unsupported payload type: {type(payload)}")

        # Ensure EndDate
        for evt in events:
            evt.setdefault("EndDate", _ts_now_iso())

        with self._lock:
            space = self.max_buffer - len(self._buffer)
            to_add = events[:space]
            self._buffer.extend(to_add)

        logger.info("Webhook received %d events (buffered: %d)",
                     len(to_add), len(self._buffer))
        return len(to_add)

    def poll(self, since: Optional[str] = None, limit: int = 1000) -> List[Dict]:
        with self._lock:
            events = list(self._buffer[:limit])
            self._buffer = self._buffer[limit:]
        return events


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
CONNECTOR_REGISTRY: Dict[str, type] = {
    "splunk": SplunkConnector,
    "elastic": ElasticConnector,
    "sentinel": SentinelConnector,
    "qradar": QRadarConnector,
    "syslog": SyslogConnector,
    "webhook": WebhookConnector,
}


def get_connector(name: str, config: Dict[str, Any]) -> BaseSIEMConnector:
    """Factory: instantiate a connector by name."""
    cls = CONNECTOR_REGISTRY.get(name.lower())
    if cls is None:
        raise ValueError(
            f"Unknown SIEM connector '{name}'. "
            f"Available: {', '.join(CONNECTOR_REGISTRY)}"
        )
    return cls(config)
