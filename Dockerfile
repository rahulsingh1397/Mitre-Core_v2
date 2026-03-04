# ── Stage 1: build dependencies ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for psycopg2-binary and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install into a prefix we can copy cleanly
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Non-root user for security
RUN addgroup --system mitre && adduser --system --ingroup mitre mitre \
    && chown -R mitre:mitre /app

USER mitre

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

# Use gunicorn in production; falls back to Flask dev server if not installed
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", \
     "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
