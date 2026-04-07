# Guardance — multi-stage Docker image
#
# Stage 1: builder — installs Python dependencies into a clean prefix
# Stage 2: runtime — copies only the installed packages and source code
#
# Build:
#   docker build -t guardance:latest .
#
# Run pipeline (one-shot ingestion + detection):
#   docker run --rm --network guardance-net \
#     -e NEO4J_URI=bolt://neo4j:7687 \
#     -e NEO4J_PASSWORD=changeme \
#     -e REDPANDA_BOOTSTRAP_SERVERS=redpanda:9092 \
#     -v /path/to/pcaps:/app/data/pcaps:ro \
#     guardance:latest python -m src.main --pcap-dir data/pcaps
#
# Run web API:
#   docker run --rm --network guardance-net \
#     -e NEO4J_URI=bolt://neo4j:7687 \
#     -e NEO4J_PASSWORD=changeme \
#     -p 8000:8000 \
#     guardance:latest uvicorn src.api.app:app --host 0.0.0.0 --port 8000

FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="Guardance"
LABEL org.opencontainers.image.description="Passive OT/ICS network security monitor"
LABEL org.opencontainers.image.source="https://github.com/0mnichan/guardance"

# Non-root user for security
RUN groupadd --gid 1001 guardance \
    && useradd --uid 1001 --gid 1001 --no-create-home guardance

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source code
COPY src/ src/
COPY data/ data/

# Create directories that the app writes to
RUN mkdir -p logs data/pcaps \
    && chown -R guardance:guardance /app

USER guardance

# Default: start the web API
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

EXPOSE 8000

# Health check via /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
