# Deployment Guide — Vigilagent

> Complete guide for deploying Vigilagent to production environments.
> Covers bare-metal install, Docker Compose, distributed cluster mode,
> system topology, component integration, and operational checklists.

---

## Table of Contents

1. [System Topology](#system-topology)
2. [Prerequisites](#prerequisites)
3. [Environment Setup](#environment-setup)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Database Setup](#database-setup)
7. [Docker Deployment](#docker-deployment)
8. [Service Deployment (Bare Metal)](#service-deployment-bare-metal)
9. [CLI Modes & Distributed Cluster](#cli-modes--distributed-cluster)
10. [Integration Guide](#integration-guide)
11. [Monitoring & Logging](#monitoring--logging)
12. [Backup & Recovery](#backup--recovery)
13. [Scaling](#scaling)
14. [Troubleshooting](#troubleshooting)
15. [Deployment Checklist](#deployment-checklist)

---

## System Topology

Vigilagent is a multi-component penetration-testing platform built around
an agent-swarm architecture. The diagram below shows every runtime
component and the connections between them.

```
┌──────────────────────────────────────────────────────────────────────┐
│                         OPERATOR BROWSER                            │
│  React / Vite SPA  (src/App.jsx)                                    │
│  Pages: Dashboard · Scans · NewScan · Library · Settings            │
│  lib/api.js ──► HTTP REST  +  WebSocket /ws/live                    │
└────────────┬────────────────────────┬───────────────────────────────┘
             │ HTTPS (Nginx reverse   │ WSS (Nginx upgrade)
             │ proxy :443)            │
┌────────────▼────────────────────────▼───────────────────────────────┐
│                    FASTAPI GATEWAY  (:8000)                         │
│  backend/main.py  — Uvicorn ASGI server                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │
│  │ REST API │  │WebSocket │  │ Lifespan │  │ CSRF / Rate-Limit│    │
│  │ Routers  │  │ Manager  │  │ Boot     │  │ Middleware       │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────────────┘    │
│       └──────────────┴─────────────┘                                │
│                       │                                             │
│       ┌───────────────▼────────────────────┐                        │
│       │       HIVE CORE (backend/core/)    │                        │
│       │  EventBus / DistributedEventBus    │                        │
│       │  HiveOrchestrator · MissionPlanner │                        │
│       │  DelegationManager · ScanContext   │                        │
│       └───────────────┬────────────────────┘                        │
│                       │                                             │
│  ┌────────────────────▼──────────────────────────────────────────┐  │
│  │              SPECIALISED AGENT SWARM                           │  │
│  │  Alpha (Recon)    · Beta (Attack)     · Gamma (Forensics)     │  │
│  │  Sigma (Payload)  · Omega (Strategy)  · Kappa (Memory)        │  │
│  │  Zeta (Governor)  · Prism (Sentinel)  · Chi (Inspector)       │  │
│  │  Delta (DOM Ctrl) · NetworkServiceCommander                    │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       │                       │                       │
┌──────▼──────┐  ┌─────────────▼──────────┐  ┌────────▼────────┐
│  RECON      │  │  PERSISTENCE LAYER     │  │  EXTERNAL       │
│  PLANE      │  │                        │  │  SERVICES       │
│             │  │  SQLite + WAL          │  │                 │
│ Terminal    │  │  (scan_state.db,       │  │  Supabase (opt) │
│ Engine      │  │   FTS5 search)         │  │  Redis (opt)    │
│             │  │                        │  │  Neo4j (opt)    │
│ 34 Alpha    │  │  Persistent volumes:   │  │  OpenCTI (opt)  │
│ tools       │  │  /app/data/scans       │  │  LLM APIs       │
│ 5 Sigma     │  │  /app/data/graphs      │  │  (Gemini /      │
│ tools       │  │  /app/scan_states      │  │   OpenRouter)   │
│             │  │  /app/logs             │  │                 │
│ Local PATH  │  └────────────────────────┘  └─────────────────┘
│ or Docker   │
│ sandbox     │
└─────────────┘
```

### Component Summary

| Component | Source | Port | Purpose |
|---|---|---|---|
| **FastAPI Backend** | `backend/main.py` | 8000 | REST API, WebSocket, agent orchestration |
| **React/Vite Frontend** | `src/` | 5173 (dev) / 80 (prod via Nginx) | Operator dashboard SPA |
| **SQLite (WAL)** | `backend/core/scan_state_db.py` | — (file) | Durable scan state, FTS5 search |
| **Supabase** | `backend/core/database.py` | Remote | Cloud persistence (vulnerabilities, recon data) |
| **Redis** | External | 6379 | Distributed events, locks, caching (optional for single-node) |
| **Nginx** | System | 443/80 | TLS termination, static files, reverse proxy |
| **Docker** | System | — | Sandboxed recon tool execution (optional) |
| **Playwright** | Embedded | — | Browser-based testing (Chromium) |

### Persistent Volumes

When running via Docker Compose, the following named volumes are created:

| Volume | Container Path | Contents |
|---|---|---|
| `scan_data` | `/app/data` | Scan artifacts, graphs, reports |
| `redis_data` | `/data` | Redis AOF/RDB persistence |
| `prometheus_data` | `/prometheus` | Metrics TSDB (monitoring profile) |
| `alertmanager_data` | `/alertmanager` | Alert state (monitoring profile) |
| `grafana_data` | `/var/lib/grafana` | Dashboard state (monitoring profile) |

For bare-metal installs, the equivalent paths are:

- `/opt/vigilagent/data/` — scan artifacts and graphs
- `/opt/vigilagent/scan_states/` — scan state SQLite databases
- `/var/log/vigilagent/` — application logs

---

## Prerequisites

### System Requirements

**Minimum** (single-node, light scanning):

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB+ |
| Disk | 50 GB SSD | 100 GB+ SSD |
| OS | Ubuntu 20.04+ / Debian 11+ / RHEL 8+ | Ubuntu 22.04 LTS |

### Software Dependencies

| Dependency | Version | Required? | Purpose |
|---|---|---|---|
| Python | 3.10+ | ✅ Yes | Backend runtime |
| Node.js | 18+ | ✅ Yes | Frontend build |
| Nginx | 1.20+ | ✅ Yes | Reverse proxy & TLS |
| Playwright | Latest | ✅ Yes | Browser-based testing |
| Redis | 6+ | ⚠️ Optional | Distributed mode, event fan-out |
| Docker | 20+ | ⚠️ Optional | Sandboxed tool execution |
| PostgreSQL | 14+ | ⚠️ Optional | Only if using PG instead of SQLite |

> **Note**: Vigilagent defaults to **SQLite with WAL mode** for local persistence.
> PostgreSQL is supported but not required. Supabase provides the cloud
> persistence layer when configured.

### Recon Tool Suite (39 Tools)

Vigilagent ships with a registry of **39 recon/validation tools** split across
two agent owners. These binaries must be available in `PATH`, the project-local
`tools/recon_bin/` directory, or `ALPHA_TOOL_ROOT`.

<details>
<summary><strong>Alpha Tools (34) — Recon Commander</strong></summary>

| Phase | Tools |
|---|---|
| Passive Intelligence | subfinder, amass, assetfinder, github-subdomains, gau, waybackurls, cloudlist, spiderfoot |
| DNS & Infrastructure | dnsx, shuffledns, puredns, cdncheck, naabu, masscan, nmap, tlsx, testssl |
| HTTP & Browser Intel | httprobe, katana, gospider, hakrawler, linkfinder, secretfinder, arjun, paramspider |
| Directory & Route Discovery | feroxbuster, ffuf, dirsearch, gobuster |
| API Reconnaissance | kiterunner, inql |
| Visual Documentation | gowitness, aquatone |
| Template Validation | interactsh |

</details>

<details>
<summary><strong>Sigma Tools (5) — Validation Commander</strong></summary>

| Phase | Tools |
|---|---|
| Vulnerability Validation | nuclei, dalfox |
| Fingerprinting & WAF Detection | httpx, whatweb, wafw00f |

</details>

---

## Environment Setup

### 1. Create Deployment User

```bash
# Create a dedicated service user
sudo useradd -m -s /bin/bash vigilagent
sudo usermod -aG sudo vigilagent

# Switch to the service user
sudo su - vigilagent
```

### 2. Install System Dependencies

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    python3.10 python3.10-venv python3-pip \
    redis-server \
    nginx \
    git curl wget \
    build-essential libssl-dev libffi-dev

# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# (Optional) Install Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker vigilagent
```

### 3. Install Playwright Browsers

```bash
# Install Playwright
pip3 install playwright

# Install Chromium and its OS dependencies
playwright install chromium
playwright install-deps
```

### 4. Install Recon Tools

Most Go-based tools can be installed via `go install`:

```bash
# Example: Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Example: Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Example: Install nmap (system package)
sudo apt install -y nmap

# Verify tool availability
python backend/tools/recon/registry.py  # Prints tool availability report
```

> See the full tool list in `backend/tools/recon/registry.py` (`RECON_TOOLS`
> and `SIGMA_TOOLS` dictionaries) for binary names and resolution order.

---

## Installation

### 1. Clone Repository

```bash
cd /opt
sudo git clone https://github.com/your-org/vigilagent.git
sudo chown -R vigilagent:vigilagent vigilagent
cd vigilagent
```

### 2. Create Virtual Environment

```bash
python3.10 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
```

### 3. Install Python Dependencies

```bash
# Core backend dependencies
pip install -r backend/requirements.txt

# (Optional) Test dependencies
pip install -r tests/requirements-test.txt
```

### 4. Install Frontend Dependencies

```bash
# Install Node packages
npm install

# Build the production frontend bundle
npm run build
```

The built assets are output to `dist/` and served by Nginx.

---

## Configuration

### 1. Environment Variables

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your values
nano .env
```

#### Required Variables

```bash
# ── API Authentication ──
API_AUTH_KEY=<min-32-char-secure-key>

# ── AI Models ──
GEMINI_API_KEY=<your-gemini-api-key>
OPENROUTER_API_KEY=sk-or-...

# ── Supabase (cloud persistence) ──
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=<your-anon-key>

# ── Redis ──
REDIS_PASSWORD=<secure-redis-password>
REDIS_URL=redis://:${REDIS_PASSWORD}@localhost:6379
```

#### Optional Variables

```bash
# ── CORS Origins (comma-separated) ──
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# ── Alpha V6 Recon Engine ──
ALPHA_ENABLE_V6=true
ALPHA_TOOL_ROOT=/usr/local/bin          # Where recon binaries live
ALPHA_ARTIFACT_ROOT=data/scans          # Scan output directory
ALPHA_DEFAULT_MODE=STANDARD             # PASSIVE_ONLY | STANDARD | AGGRESSIVE
ALPHA_DEFAULT_RPS=50
ALPHA_TOOL_TIMEOUT_SECONDS=180

# ── Browser Configuration ──
ALPHA_ENABLE_PINCHTAB=true
OPENCLAW_ENABLED=true
OPENCLAW_HEADLESS=true
OPENCLAW_BROWSER=chromium
OPENCLAW_MAX_CONTEXTS=5

# ── Hybrid Browser Orchestration ──
HYBRID_BROWSER_ENABLED=true
HYBRID_DEFAULT_ENGINE=auto
HYBRID_FORENSICS_ENABLED=true

# ── Monitoring (Docker Compose monitoring profile) ──
GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=<grafana-admin-password>
SLACK_WEBHOOK_URL=<optional-slack-webhook>
ALERT_EMAIL_TO=ops@vigilagent.dev

# ── Deep System Integration Feature Flags ──
# These override config/integration.yaml for 12-factor deploys.
ENABLE_BROWSER_LEARNING=true
ENABLE_SKILL_LIBRARY_V2=true
ENABLE_BROWSER_HEALTH_MONITORING=true
ENABLE_SELF_HEALING=true
ENABLE_UNIFIED_GRAPH=true
ENABLE_INTELLIGENT_ROUTING=true
ENABLE_FORENSIC_LEARNING=true

# ── Resource Caps ──
EVENT_BATCH_SIZE=50
EVENT_BATCH_TIMEOUT_MS=200
MAX_CONCURRENT_LEARNING=8
CIRCUIT_BREAKER_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT_S=60
```

#### Environment Variable Matrix

| Variable | Required | Default | Description |
|---|---|---|---|
| `API_AUTH_KEY` | ✅ | — | API authentication key (min 32 chars) |
| `GEMINI_API_KEY` | ✅ | — | Google Gemini API key for LLM routing |
| `OPENROUTER_API_KEY` | ✅ | — | OpenRouter API key for model access |
| `SUPABASE_URL` | ✅ | — | Supabase project URL |
| `SUPABASE_KEY` | ✅ | — | Supabase anonymous key |
| `REDIS_PASSWORD` | ✅ | — | Redis server password |
| `REDIS_URL` | ⚠️ | Derived | Full Redis connection string |
| `CORS_ORIGINS` | ⚠️ | `localhost:5173` | Allowed CORS origins |
| `ALPHA_ENABLE_V6` | ⚠️ | `true` | Enable V6 recon engine |
| `ALPHA_DEFAULT_MODE` | ⚠️ | `STANDARD` | Scan aggressiveness level |
| `OPENCLAW_HEADLESS` | ⚠️ | `true` | Run browser in headless mode |
| `TESTING` | ⚠️ | `false` | Enable test mode (bypasses auth) |

### 2. Generate Secure Keys

```bash
# Generate a URL-safe secret key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate a Fernet encryption key (for forensic data)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Configure Nginx

Create `/etc/nginx/sites-available/vigilagent`:

```nginx
upstream vigilagent_backend {
    server 127.0.0.1:8000;
    keepalive 64;
}

server {
    listen 80;
    server_name your-domain.com;

    # Redirect all HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Static Files (built frontend)
    location /static/ {
        alias /opt/vigilagent/dist/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # API Proxy
    location /api/ {
        proxy_pass http://vigilagent_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts (generous for long-running scans)
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Rate Limiting
        limit_req zone=api burst=20 nodelay;
    }

    # WebSocket endpoints
    location /ws/ {
        proxy_pass http://vigilagent_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }

    # Frontend SPA (catch-all)
    location / {
        root /opt/vigilagent/dist;
        try_files $uri $uri/ /index.html;
    }
}

# Rate Limiting Zone (place in http {} block or top-level conf)
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/vigilagent /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Database Setup

### SQLite (Default — Recommended for Single Node)

SQLite with WAL mode is the default persistence tier. No setup required — the
database file is created automatically at first boot.

```bash
# The scan state database is created at:
#   data/scan_state.db  (WAL mode, FTS5 enabled)
#
# Verify after first run:
sqlite3 data/scan_state.db ".tables"
```

### Supabase (Cloud Persistence Layer)

Set `SUPABASE_URL` and `SUPABASE_KEY` in `.env`. The backend automatically
creates tables for vulnerabilities, recon results, and HTTP data on first
connection.

### PostgreSQL (Alternative — Optional)

If you prefer PostgreSQL over SQLite for local persistence:

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE vigilagent;
CREATE USER vigilagent_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE vigilagent TO vigilagent_user;
\q
```

```bash
# Run database migrations
source venv/bin/activate
python backend/db_migrate.py
```

---

## Docker Deployment

Docker Compose is the **recommended** way to deploy Vigilagent. It orchestrates
the backend, frontend, Redis, and an optional monitoring stack in a single
configuration.

### Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/your-org/vigilagent.git
cd vigilagent
cp .env.example .env
nano .env                       # Fill in required variables

# 2. Start core services (backend + frontend + Redis)
docker compose up -d

# 3. Verify
docker compose ps
curl http://localhost:8000/api/health
```

**Access points after launch**:

| Service | URL |
|---|---|
| Frontend (SPA) | `http://localhost:5173` |
| Backend API | `http://localhost:8000` |
| API Health | `http://localhost:8000/api/health` |

### Architecture of `docker-compose.yml`

The Compose file defines the following services:

```
┌─────────────────────────────────────────────────────────────────┐
│                     CORE SERVICES                               │
│                                                                 │
│  ┌──────────┐     ┌───────────┐     ┌──────────┐               │
│  │ backend  │────►│  redis    │     │ frontend │               │
│  │ :8000    │     │  :6379    │     │ :5173    │               │
│  │          │     │  (Alpine) │     │ (Nginx)  │               │
│  └──────────┘     └───────────┘     └──────────┘               │
│                                                                 │
│               MONITORING PROFILE (--profile monitoring)         │
│                                                                 │
│  ┌────────────┐  ┌──────────────┐  ┌───────────┐  ┌─────────┐ │
│  │ prometheus │  │ alertmanager │  │  grafana  │  │  redis- │ │
│  │ :9090      │  │ :9093        │  │  :3000    │  │exporter │ │
│  └────────────┘  └──────────────┘  └───────────┘  │  :9121  │ │
│                                                    └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Service Details

#### Backend (`Dockerfile`)

- **Base**: `python:3.12-slim`
- **Installs**: curl, git, nmap, chromium, Playwright browsers
- **Runs as**: Non-root `vigilagent` user
- **Health check**: `GET /api/health` every 30s
- **Volume**: `scan_data:/app/data`

#### Frontend (`Dockerfile.frontend`)

- **Build stage**: `node:20-alpine` — runs `npm ci && npm run build`
- **Runtime stage**: `nginx:alpine` — serves `dist/` with runtime env substitution
- **Runs as**: Non-root `appuser:appgroup`
- **Runtime config**: `envsubst` injects `API_AUTH_KEY` into Nginx config

#### Redis

- **Image**: `redis:7-alpine`
- **Auth**: Password required (`REDIS_PASSWORD`)
- **Health check**: `redis-cli ping` every 10s
- **Volume**: `redis_data:/data`

### Start with Monitoring Stack

```bash
# Start everything including Prometheus, Grafana, and Alertmanager
docker compose --profile monitoring up -d

# Access monitoring
#   Grafana:      http://localhost:3000  (admin / GF_ADMIN_PASSWORD)
#   Prometheus:   http://localhost:9090
#   Alertmanager: http://localhost:9093
```

### Custom Build Arguments

```bash
# Rebuild after code changes
docker compose build --no-cache backend
docker compose up -d backend

# Rebuild frontend only
docker compose build --no-cache frontend
docker compose up -d frontend
```

### Volume Management

```bash
# List volumes
docker volume ls | grep vigilagent

# Back up scan data
docker run --rm -v vigilagent_scan_data:/data -v $(pwd):/backup \
    alpine tar czf /backup/scan_data_backup.tar.gz -C /data .

# Restore scan data
docker run --rm -v vigilagent_scan_data:/data -v $(pwd):/backup \
    alpine tar xzf /backup/scan_data_backup.tar.gz -C /data
```

### Docker for Sandboxed Tool Execution

Vigilagent can run recon tools inside Docker containers for isolation. This is
configured via `backend/tools/recon/docker_runtime.py`.

```bash
# Build the recon sandbox image (contains all 39 tools)
docker build -t vigilagent/recon-sandbox -f docker/recon/Dockerfile .

# Enable Docker sandbox mode in .env
ALPHA_ENABLE_EXTERNAL_TOOLS=true
```

---

## Service Deployment (Bare Metal)

### 1. Create Systemd Service

Create `/etc/systemd/system/vigilagent.service`:

```ini
[Unit]
Description=Vigilagent Penetration Testing Platform
After=network.target redis.service

[Service]
Type=notify
User=vigilagent
Group=vigilagent
WorkingDirectory=/opt/vigilagent
Environment="PATH=/opt/vigilagent/venv/bin:/usr/local/bin:/usr/bin"
ExecStart=/opt/vigilagent/venv/bin/python backend/main.py --mode serve --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/vigilagent /opt/vigilagent/data /opt/vigilagent/scan_states

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

### 2. Enable and Start Service

```bash
# Create log directory
sudo mkdir -p /var/log/vigilagent
sudo chown vigilagent:vigilagent /var/log/vigilagent

# Reload systemd and start
sudo systemctl daemon-reload
sudo systemctl enable vigilagent
sudo systemctl start vigilagent

# Verify
sudo systemctl status vigilagent
```

### 3. Configure Log Rotation

Create `/etc/logrotate.d/vigilagent`:

```
/var/log/vigilagent/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 vigilagent vigilagent
    sharedscripts
    postrotate
        systemctl reload vigilagent > /dev/null 2>&1 || true
    endscript
}
```

---

## CLI Modes & Distributed Cluster

Vigilagent supports four execution modes via `backend/main.py`:

```bash
python backend/main.py --mode <MODE> [OPTIONS]
```

### Mode Reference

| Mode | Command | Description |
|---|---|---|
| **serve** | `--mode serve --host 0.0.0.0 --port 8000` | Single-node API gateway (default) |
| **master** | `--mode master` | Start as cluster master (coordinates workers) |
| **worker** | `--mode worker --worker-id w1` | Start as cluster worker node |
| **cluster** | `--mode cluster --num-workers 3` | Start an all-in-one cluster (1 master + N workers) |

### Single-Node Deployment (Default)

```bash
# Standard single-server deployment
python backend/main.py --mode serve --host 0.0.0.0 --port 8000
```

This is the simplest mode — the FastAPI gateway, agent swarm, and recon engine
all run in a single process.

### Distributed Cluster Deployment

For large-scale scanning, distribute work across multiple machines:

**On the master node:**
```bash
python backend/main.py --mode master
```

**On each worker node:**
```bash
python backend/main.py --mode worker --worker-id worker-east-1
```

**Local testing (all-in-one):**
```bash
# Start 1 master + 3 workers in a single process
python backend/main.py --mode cluster --num-workers 3
```

> **Requirement**: Distributed mode requires Redis for event fan-out.
> Set `REDIS_URL` in `.env` on all nodes pointing to the same Redis instance.
> The `DistributedEventBus` (in `backend/core/hive.py`) handles message
> routing between master and workers.

---

## Integration Guide

This section describes how Vigilagent's components connect and communicate.

### Data Flow Overview

```
 User Action           Backend Processing               Storage
 ───────────           ──────────────────               ───────
 Create Scan  ──────►  REST /api/scans/start  ──────►  ScanContext created
                            │                               │
                            ▼                               ▼
                       HiveOrchestrator           SQLite scan_state.db
                       bootstraps agents              (WAL mode)
                            │
                 ┌──────────┼──────────┐
                 ▼          ▼          ▼
              Alpha      Beta       Gamma        ... (agent swarm)
              (recon)    (attack)   (forensics)
                 │          │          │
                 ▼          ▼          ▼
           TerminalEngine  ExploitEng  ForensicCollector
                 │          │          │
                 ▼          ▼          ▼
            Tool stdout   Payloads   Evidence  ──────►  Supabase
                 │                                      (cloud sync)
                 ▼
           Parsed results  ──────►  WebSocket push to UI
```

### Component Integration Points

#### Frontend ↔ Backend

| Channel | Endpoint | Purpose |
|---|---|---|
| REST | `/api/*` | Scan CRUD, reports, settings, skill catalogue |
| WebSocket | `/ws/live`, `/stream` | Real-time scan progress, agent telemetry |
| Auth | `X-API-Key` header | API key authentication (`API_AUTH_KEY`) |

The frontend's `src/lib/api.js` module constructs URLs using the configured
API host. In development, Vite proxies `/api` requests to `localhost:8000`.

#### Backend ↔ Agent Swarm

The **EventBus** (`backend/core/hive.py`) is the backbone:

- **Single-node**: In-process `EventBus` with async pub/sub
- **Distributed**: `DistributedEventBus` extends the local bus with Redis
  pub/sub for cross-node event propagation

Events follow the `EventType` vocabulary (e.g., `TARGET_ACQUIRED`,
`RECON_COMPLETE`, `VULNERABILITY_FOUND`, `REPORT_READY`).

#### Backend ↔ Recon Tools

The **TerminalEngine** (`backend/core/terminal_engine.py`) executes tools:

1. Resolves binary path via `registry.py` (PATH → `tools/recon_bin` → `ALPHA_TOOL_ROOT`)
2. Spawns subprocess with timeout, rate limiting, and scope enforcement
3. Parses stdout via tool-specific parsers (`backend/parsers/`)
4. Optionally runs inside Docker sandbox (`backend/tools/recon/docker_runtime.py`)

#### Backend ↔ Persistence

| Layer | Technology | Data |
|---|---|---|
| Local state | SQLite WAL + FTS5 | Scan progress, agent decisions, search index |
| Cloud sync | Supabase | Vulnerabilities, recon results, HTTP data |
| Cache/events | Redis | Distributed locks, pub/sub events, rate-limit counters |
| Graph (optional) | Neo4j | Attack surface graph |

#### Backend ↔ LLM APIs

The **Cortex** layer (`backend/core/llm_router.py`, `backend/core/cognitive_router.py`)
routes AI requests to Gemini or OpenRouter based on task complexity:

- **Strategic** decisions (scan planning, attack strategy) → larger models
- **Tactical** decisions (output parsing, classification) → faster models

#### Configuration Cascade

```
.env                          ← Top priority (12-factor overrides)
  ↓
config/integration.yaml       ← Feature flags, rollout percentages
  ↓
backend/core/config.py        ← Settings defaults (Pydantic)
```

---

## Monitoring & Logging

### 1. Application Logging

Vigilagent emits structured JSON logs to stdout (captured by systemd journal
or Docker log driver):

```bash
# Via systemd
sudo journalctl -u vigilagent -f

# Via Docker Compose
docker compose logs -f backend

# Direct log file (if LOG_FILE is set)
tail -f /var/log/vigilagent/app.log
```

### 2. Prometheus Metrics

Available at `http://localhost:8000/metrics` (backend) or `http://localhost:9090`
(Prometheus UI when using the monitoring profile).

**Key Metrics**:

| Metric | Description |
|---|---|
| `vigilagent_requests_total` | Total API requests by endpoint/method |
| `vigilagent_request_duration_seconds` | Request latency histogram |
| `vigilagent_active_scans` | Currently active scans |
| `vigilagent_browser_contexts` | Active Playwright browser contexts |
| `vigilagent_memory_usage_bytes` | Process memory usage |
| `vigilagent_tool_executions_total` | Recon tool executions by tool name |

### 3. Grafana Dashboards

When running the monitoring profile, Grafana auto-provisions the Vigilagent
dashboard from `grafana/vigilagent-dashboard.json`:

```bash
docker compose --profile monitoring up -d

# Access: http://localhost:3000
# Default credentials: admin / <GF_ADMIN_PASSWORD from .env>
```

### 4. Health Checks

```bash
# Application health
curl http://localhost:8000/api/health

# Database health
curl http://localhost:8000/api/health/db

# Redis health
curl http://localhost:8000/api/health/redis
```

### 5. Alerting

Alertmanager routes alerts defined in `alerting/` to configured receivers:

- **Slack**: Set `SLACK_WEBHOOK_URL` in `.env`
- **Email**: Set `ALERT_EMAIL_TO` in `.env`
- **Configuration**: See `alertmanager.yml` and `docs/alerts.md`

---

## Backup & Recovery

### 1. SQLite Backup

```bash
# Create backup script
cat > /opt/vigilagent/scripts/backup_db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/vigilagent"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# SQLite online backup (safe with WAL mode)
sqlite3 /opt/vigilagent/data/scan_state.db ".backup '$BACKUP_DIR/scan_state_$DATE.db'"

# Compress
gzip "$BACKUP_DIR/scan_state_$DATE.db"

# Keep only last 7 days
find $BACKUP_DIR -name "scan_state_*.db.gz" -mtime +7 -delete
EOF

chmod +x /opt/vigilagent/scripts/backup_db.sh
```

### 2. Docker Volume Backup

```bash
# Backup scan data volume
docker run --rm \
    -v vigilagent_scan_data:/data:ro \
    -v /var/backups/vigilagent:/backup \
    alpine tar czf /backup/scan_data_$(date +%Y%m%d).tar.gz -C /data .
```

### 3. Schedule Automated Backups

```bash
# Add to crontab (daily at 2 AM)
crontab -e
0 2 * * * /opt/vigilagent/scripts/backup_db.sh
```

### 4. Restore from Backup

```bash
# Stop the application
sudo systemctl stop vigilagent          # bare metal
# docker compose down                   # Docker

# Restore SQLite
gunzip < /var/backups/vigilagent/scan_state_20260626_020000.db.gz \
    > /opt/vigilagent/data/scan_state.db

# Start the application
sudo systemctl start vigilagent         # bare metal
# docker compose up -d                  # Docker
```

---

## Scaling

### 1. Vertical Scaling

Tune resource limits for single-node deployments:

```bash
# .env tuning
ALPHA_MAX_HTTPX_THREADS=100     # Increase concurrent HTTP probes
OPENCLAW_MAX_CONTEXTS=10        # More parallel browser contexts
EVENT_BATCH_SIZE=100            # Larger event batches
MAX_CONCURRENT_LEARNING=16     # More concurrent learning tasks
```

### 2. Horizontal Scaling (Distributed Mode)

Deploy a multi-node cluster with dedicated master and workers:

**Load Balancer (HAProxy example):**

```
frontend vigilagent_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/vigilagent.pem
    default_backend vigilagent_backend

backend vigilagent_backend
    balance roundrobin
    option httpchk GET /api/health
    server app1 10.0.1.10:8000 check
    server app2 10.0.1.11:8000 check
    server app3 10.0.1.12:8000 check
```

**Requirements for distributed mode:**

- Shared Redis instance accessible from all nodes
- Shared `SUPABASE_URL` for cloud data consistency
- Each worker needs recon tools installed locally (or Docker sandbox)

### 3. Redis Clustering

For high-availability Redis:

```bash
# Redis Sentinel configuration
sentinel monitor vigilagent 10.0.1.20 6379 2
sentinel down-after-milliseconds vigilagent 5000
sentinel failover-timeout vigilagent 10000
```

---

## Troubleshooting

### Common Issues

#### 1. Application Won't Start

```bash
# Check systemd logs
sudo journalctl -u vigilagent -n 100 --no-pager

# Check Docker logs
docker compose logs --tail 100 backend

# Verify Python environment
source venv/bin/activate
python -c "from backend.core.config import settings; print('Config OK')"

# Check file permissions
ls -la /opt/vigilagent/data /opt/vigilagent/scan_states
```

#### 2. Redis Connection Errors

```bash
# Test Redis connectivity
redis-cli -a "${REDIS_PASSWORD}" ping

# Check Redis service
sudo systemctl status redis    # bare metal
docker compose ps redis        # Docker

# Verify URL format in .env
# Correct: redis://:password@localhost:6379
# Wrong:   redis://localhost:6379  (missing password)
```

#### 3. Recon Tools Not Found

```bash
# Check tool availability
python -c "from backend.tools.recon.registry import check_tool_availability; check_tool_availability()"

# Verify PATH includes tool directories
echo $PATH

# Check specific tool
which nmap
which subfinder
```

#### 4. High Memory Usage

```bash
# Check browser contexts
curl http://localhost:8000/api/debug/contexts

# Force cleanup
curl -X POST http://localhost:8000/api/debug/cleanup

# Restart the service
sudo systemctl restart vigilagent       # bare metal
docker compose restart backend          # Docker
```

#### 5. Slow Scan Performance

```bash
# Check system resources
htop

# Check Redis latency
redis-cli -a "${REDIS_PASSWORD}" --latency

# Review active scans
curl http://localhost:8000/api/scans?status=running

# Check tool execution timeouts
grep "TIMEOUT" /var/log/vigilagent/app.log
```

#### 6. Frontend Not Loading

```bash
# Verify the build output exists
ls -la /opt/vigilagent/dist/index.html

# Rebuild if needed
cd /opt/vigilagent && npm run build

# Check Nginx config
sudo nginx -t
sudo systemctl status nginx
```

For additional troubleshooting scenarios, see `docs/TROUBLESHOOTING.md`.

---

## Deployment Checklist

Use this checklist for every deployment to production.

### Pre-Deployment

- [ ] **Code**: All changes merged and tested on staging
- [ ] **Dependencies**: `pip install -r backend/requirements.txt` succeeds
- [ ] **Frontend build**: `npm run build` completes without errors
- [ ] **Environment**: `.env` populated with all required variables
- [ ] **Secrets**: All keys are unique, securely generated (≥32 chars)
- [ ] **Recon tools**: Critical tools available (`nmap`, `subfinder`, `nuclei` at minimum)
- [ ] **Playwright**: Chromium installed (`playwright install chromium`)
- [ ] **Docker** (if applicable): Images built and tagged

### Infrastructure

- [ ] **Nginx**: Config tested (`nginx -t`), TLS certificate valid
- [ ] **DNS**: Domain points to the server
- [ ] **Firewall**: Only ports 80, 443 exposed; 8000, 6379, 9090 internal only
- [ ] **Redis**: Running, password-protected, accessible from backend
- [ ] **Disk space**: ≥20 GB free for scan artifacts
- [ ] **File permissions**: `vigilagent` user owns `/opt/vigilagent`, `/var/log/vigilagent`

### Security

- [ ] Change all default passwords
- [ ] Generate unique `API_AUTH_KEY` (min 32 chars)
- [ ] Enable HTTPS with valid TLS certificate (Let's Encrypt or CA-signed)
- [ ] Configure firewall rules (UFW / iptables)
- [ ] Enable Nginx rate limiting
- [ ] Set up fail2ban for SSH and API brute-force protection
- [ ] Verify security headers (HSTS, X-Frame-Options, X-Content-Type-Options)
- [ ] Enable audit logging (`LOG_LEVEL=INFO` at minimum)
- [ ] Disable `TESTING=false` in production
- [ ] Rotate and back up encryption keys

### Post-Deployment Verification

- [ ] **Health check**: `curl https://your-domain.com/api/health` returns `200`
- [ ] **Frontend**: Dashboard loads at `https://your-domain.com`
- [ ] **WebSocket**: Live scan updates appear in the UI
- [ ] **Auth**: Unauthenticated requests to `/api/*` are rejected
- [ ] **Scan test**: Run a test scan against an authorized target
- [ ] **Logs**: Structured JSON logs appearing in journal/Docker output
- [ ] **Backups**: Cron job scheduled for daily database backup
- [ ] **Monitoring** (if enabled): Grafana dashboard showing metrics

### Ongoing Operations

- [ ] **Monitor for 24 hours**: Watch error logs, resource usage, scan success rates
- [ ] **Alerting**: Verify Slack/email alerts fire on test conditions
- [ ] **Update schedule**: Plan regular security updates for OS, Python deps, recon tools
- [ ] **Runbook**: Document custom configurations in `docs/runbooks/`
- [ ] **Incident response**: Ensure team has access to logs and restart procedures

---

## Support

For deployment issues:

- **Logs**: `/var/log/vigilagent/` (bare metal) or `docker compose logs` (Docker)
- **Docs**: See `docs/TROUBLESHOOTING.md`, `docs/CONFIGURATION.md`, `docs/ARCHITECTURE.md`
- **Runbooks**: `docs/runbooks/`

---

**Last Updated**: June 26, 2026
**Version**: 6.0
**Status**: Production Ready
**Maintained by**: Vigilagent Core Team
