"""
MITRE-CORE Security Module
Provides authentication, authorization, secure configuration, and security utilities.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jwt
from flask import request, jsonify, g
from sqlalchemy import create_engine, text, event
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("mitre-core.security")

# ---------------------------------------------------------------------------
# Configuration loader (environment-based)
# ---------------------------------------------------------------------------

def _env(key: str, default: str = "") -> str:
    """Read an environment variable, falling back to default."""
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    return _env(key, str(default)).lower() in ("true", "1", "yes")


def _env_int(key: str, default: int = 0) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


class AppConfig:
    """Centralised, environment-driven application configuration."""

    # Flask
    FLASK_ENV: str = _env("FLASK_ENV", "production")
    DEBUG: bool = _env_bool("FLASK_DEBUG", False)
    SECRET_KEY: str = _env("SECRET_KEY", secrets.token_hex(32))
    PORT: int = _env_int("PORT", 5000)

    # JWT
    JWT_SECRET_KEY: str = _env("JWT_SECRET_KEY", secrets.token_hex(32))
    JWT_ACCESS_EXPIRES: int = _env_int("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", 60)
    JWT_REFRESH_EXPIRES: int = _env_int("JWT_REFRESH_TOKEN_EXPIRES_DAYS", 30)

    # CORS
    CORS_ORIGINS: List[str] = [
        o.strip()
        for o in _env("CORS_ALLOWED_ORIGINS", "http://localhost:5000").split(",")
        if o.strip()
    ]

    # Rate limiting
    RATELIMIT_DEFAULT: str = _env("RATELIMIT_DEFAULT", "200 per hour")
    RATELIMIT_STORAGE_URI: str = _env("RATELIMIT_STORAGE_URI", "memory://")

    # Database — accepts postgresql://... or sqlite:///...
    DATABASE_URI: str = _env("DATABASE_URI", "sqlite:///mitre_core.db")

    # Redis — used for token revocation when available
    REDIS_URL: str = _env("REDIS_URL", "")

    # Logging
    LOG_LEVEL: str = _env("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = _env("LOG_FORMAT", "json")

    # Admin bootstrap
    ADMIN_USERNAME: str = _env("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = _env("ADMIN_PASSWORD", "")

    # SIEM encryption
    SIEM_ENCRYPTION_KEY: str = _env("SIEM_ENCRYPTION_KEY", "")

    # Upload
    MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50 MB


config = AppConfig()


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-SHA256, no extra dependency)
# ---------------------------------------------------------------------------

_HASH_ITERATIONS = 260_000
_SALT_LENGTH = 32


def hash_password(password: str) -> str:
    """Return 'salt$hash' using PBKDF2-SHA256."""
    salt = secrets.token_hex(_SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), _HASH_ITERATIONS
    )
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored 'salt$hash'."""
    try:
        salt, expected = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), _HASH_ITERATIONS
        )
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Database engine (PostgreSQL or SQLite via SQLAlchemy)
# ---------------------------------------------------------------------------

def _build_engine():
    """Create a SQLAlchemy engine from DATABASE_URI."""
    uri = config.DATABASE_URI
    if uri.startswith("sqlite"):
        # SQLite needs special pool settings for multi-thread Flask use
        engine = create_engine(
            uri,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        # Enable WAL mode for better concurrency
        @event.listens_for(engine, "connect")
        def _set_wal(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
        return engine
    else:
        # PostgreSQL (or any other SQLAlchemy-supported DB)
        return create_engine(uri, pool_pre_ping=True, pool_size=10, max_overflow=20)


_engine = _build_engine()


def _get_db():
    """Return a SQLAlchemy connection bound to the Flask app context."""
    db = getattr(g, "_security_db", None)
    if db is None:
        db = g._security_db = _engine.connect()
    return db


# ---------------------------------------------------------------------------
# Redis client (optional — for token revocation + rate limiting)
# ---------------------------------------------------------------------------

_redis_client = None


def _get_redis():
    """Return a Redis client if REDIS_URL is configured, else None."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not config.REDIS_URL:
        return None
    try:
        import redis
        _redis_client = redis.from_url(config.REDIS_URL, decode_responses=True)
        _redis_client.ping()
        logger.info("Redis connected: %s", config.REDIS_URL)
        return _redis_client
    except Exception as exc:
        logger.warning("Redis unavailable (%s) — falling back to DB token revocation", exc)
        return None


# ---------------------------------------------------------------------------
# DDL helpers — dialect-aware
# ---------------------------------------------------------------------------

def _is_postgres() -> bool:
    return config.DATABASE_URI.startswith("postgresql") or config.DATABASE_URI.startswith("postgres")


def _ddl_autoincrement() -> str:
    return "SERIAL" if _is_postgres() else "INTEGER"


def _ddl_pk() -> str:
    return "SERIAL PRIMARY KEY" if _is_postgres() else "INTEGER PRIMARY KEY AUTOINCREMENT"


def init_db(app) -> None:
    """Create tables and bootstrap admin user if needed."""
    pk = _ddl_pk()
    with _engine.begin() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS users (
                id          {pk},
                username    TEXT    UNIQUE NOT NULL,
                password    TEXT    NOT NULL,
                role        TEXT    NOT NULL DEFAULT 'analyst',
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT    NOT NULL,
                last_login  TEXT
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          {pk},
                timestamp   TEXT    NOT NULL,
                username    TEXT,
                action      TEXT    NOT NULL,
                detail      TEXT,
                ip_address  TEXT
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                id          {pk},
                jti         TEXT    UNIQUE NOT NULL,
                revoked_at  TEXT    NOT NULL
            )
        """))

    # Bootstrap admin
    with _engine.begin() as conn:
        row = conn.execute(
            text("SELECT id FROM users WHERE username = :u"), {"u": config.ADMIN_USERNAME}
        ).fetchone()
        if row is None:
            pw = config.ADMIN_PASSWORD or secrets.token_urlsafe(16)
            conn.execute(
                text("INSERT INTO users (username, password, role, created_at) VALUES (:u, :p, :r, :c)"),
                {"u": config.ADMIN_USERNAME, "p": hash_password(pw),
                 "r": "admin", "c": datetime.now(timezone.utc).isoformat()},
            )
            if not config.ADMIN_PASSWORD:
                logger.warning(
                    "Auto-generated admin password: %s  — change it immediately!", pw
                )

    db_type = "PostgreSQL" if _is_postgres() else "SQLite"
    logger.info("Database initialised (%s)", db_type)

    @app.teardown_appcontext
    def _close_db(exc):
        db = getattr(g, "_security_db", None)
        if db is not None:
            db.close()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=config.JWT_ACCESS_EXPIRES),
        "jti": secrets.token_hex(16),
        "type": "access",
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm="HS256")


def create_refresh_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(days=config.JWT_REFRESH_EXPIRES),
        "jti": secrets.token_hex(16),
        "type": "refresh",
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT. Raises jwt.exceptions on failure."""
    return jwt.decode(token, config.JWT_SECRET_KEY, algorithms=["HS256"])


def _is_token_revoked(jti: str) -> bool:
    """Check revocation via Redis (fast path) or DB (fallback)."""
    try:
        r = _get_redis()
        if r is not None:
            return r.exists(f"revoked:{jti}") == 1
        # DB fallback
        db = _get_db()
        row = db.execute(
            text("SELECT id FROM revoked_tokens WHERE jti = :j"), {"j": jti}
        ).fetchone()
        return row is not None
    except Exception:
        return False


def revoke_token(jti: str) -> None:
    """Revoke a token in Redis (with TTL) and DB."""
    now_iso = datetime.now(timezone.utc).isoformat()
    # Redis: store with TTL matching the max token lifetime (refresh = 30 days)
    try:
        r = _get_redis()
        if r is not None:
            ttl = config.JWT_REFRESH_EXPIRES * 86400
            r.setex(f"revoked:{jti}", ttl, "1")
    except Exception as exc:
        logger.warning("Redis revoke failed: %s", exc)
    # Always persist to DB as well
    try:
        with _engine.begin() as conn:
            if _is_postgres():
                conn.execute(
                    text("INSERT INTO revoked_tokens (jti, revoked_at) VALUES (:j, :t) ON CONFLICT (jti) DO NOTHING"),
                    {"j": jti, "t": now_iso},
                )
            else:
                conn.execute(
                    text("INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (:j, :t)"),
                    {"j": jti, "t": now_iso},
                )
    except Exception as exc:
        logger.error("Failed to revoke token in DB: %s", exc)


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit_log(action: str, detail: str = "", username: str = None) -> None:
    """Write an entry to the audit log table."""
    try:
        with _engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO audit_log (timestamp, username, action, detail, ip_address) "
                    "VALUES (:ts, :u, :a, :d, :ip)"
                ),
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "u": username or getattr(g, "current_user", None),
                    "a": action,
                    "d": detail,
                    "ip": request.remote_addr if request else None,
                },
            )
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_auth(f):
    """Decorator: require a valid JWT access token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "Missing or invalid Authorization header"}), 401
        token = auth_header[7:]
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                return jsonify({"success": False, "error": "Invalid token type"}), 401
            if _is_token_revoked(payload.get("jti", "")):
                return jsonify({"success": False, "error": "Token has been revoked"}), 401
            g.current_user = payload["sub"]
            g.current_role = payload.get("role", "analyst")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Decorator: require the authenticated user to have one of the given roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = getattr(g, "current_role", None)
            if user_role not in roles:
                return jsonify({"success": False, "error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# HMAC webhook verification
# ---------------------------------------------------------------------------

def verify_webhook_hmac(payload_bytes: bytes, signature: str, secret: str) -> bool:
    """Verify an HMAC-SHA256 webhook signature (constant-time comparison)."""
    expected = hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


# ---------------------------------------------------------------------------
# Credential encryption helpers
# ---------------------------------------------------------------------------

def encrypt_value(plaintext: str) -> str:
    """Encrypt a string value using Fernet if a key is configured, else return as-is."""
    if not config.SIEM_ENCRYPTION_KEY:
        logger.warning("SIEM_ENCRYPTION_KEY not set — credentials stored in plaintext")
        return plaintext
    try:
        from cryptography.fernet import Fernet
        f = Fernet(config.SIEM_ENCRYPTION_KEY.encode())
        return f.encrypt(plaintext.encode()).decode()
    except ImportError:
        logger.warning("cryptography package not installed — credentials stored in plaintext")
        return plaintext
    except Exception as exc:
        logger.error("Encryption failed: %s", exc)
        return plaintext


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string, or return as-is if no key."""
    if not config.SIEM_ENCRYPTION_KEY:
        return ciphertext
    try:
        from cryptography.fernet import Fernet
        f = Fernet(config.SIEM_ENCRYPTION_KEY.encode())
        return f.decrypt(ciphertext.encode()).decode()
    except ImportError:
        return ciphertext
    except Exception as exc:
        logger.error("Decryption failed: %s", exc)
        return ciphertext


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

def add_security_headers(response):
    """Add production security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    if not config.DEBUG:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    # CSP: allow self + CDN resources used by the dashboard
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.plot.ly; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    # Remove server header
    response.headers.pop("Server", None)

    return response


# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Add request context if available
        try:
            if request:
                log_entry["request_id"] = getattr(g, "request_id", None)
                log_entry["remote_addr"] = request.remote_addr
                log_entry["method"] = request.method
                log_entry["path"] = request.path
        except RuntimeError:
            pass
        return json.dumps(log_entry, default=str)


def configure_logging() -> None:
    """Set up structured logging based on configuration."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    # Clear existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler()
    if config.LOG_FORMAT == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.addHandler(handler)
