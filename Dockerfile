FROM python:3.12-slim

WORKDIR /app

# System deps for playwright & tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git nmap chromium && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install playwright browsers
RUN python -m playwright install chromium --with-deps 2>/dev/null || true

# Copy backend
COPY backend/ backend/

# Create writable data directories for non-root user
RUN mkdir -p /app/data/scans /app/data/graphs /app/scan_states /app/logs \
    && chmod -R 755 /app/data /app/scan_states /app/logs

# Create non-root user
RUN groupadd -r vigilagent && useradd -r -g vigilagent -d /app -s /sbin/nologin vigilagent \
    && chown -R vigilagent:vigilagent /app

USER vigilagent

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Run
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
