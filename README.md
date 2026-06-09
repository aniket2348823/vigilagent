<p align="center">
  <img src="https://img.shields.io/badge/Version-6.1.0-blueviolet?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

# Vul-Agent — Autonomous AI-Powered Penetration Testing Platform

> A multi-agent swarm intelligence system for automated security reconnaissance, vulnerability assessment, and attack simulation — driven by LLM-powered decision making, 35+ parsers, 25+ tool integrations, and a real-time React dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Agent Swarm](#agent-swarm)
- [Recon Pipeline](#alpha-v6-recon-engine)
- [Integrated Security Tools](#integrated-security-tools)
- [Browser Automation Stack](#browser-automation-stack)
- [AI & LLM Integration](#ai--llm-integration)
- [Frontend Dashboard](#frontend-dashboard)
- [API Reference](#api-reference)
- [Export Formats](#export-formats)
- [Getting Started](#getting-started)
- [Docker Deployment](#docker-deployment)
- [Configuration](#configuration)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

---

## Overview

Vul-Agent (codename **Antigravity V6**) is a full-stack autonomous penetration testing platform that coordinates a swarm of specialized AI agents to perform end-to-end security assessments. Each agent operates with a distinct role — from reconnaissance and exploitation to forensic analysis and governance — orchestrated by a central Hive system with event-driven communication, phase-gated scan pipelines, and self-healing capabilities.

The platform combines:
- **Multi-agent AI orchestration** with 11 specialized agents
- **25+ external security tools** integrated via Docker-containerized runtimes
- **35+ output parsers** for structured finding extraction
- **Dual browser automation engines** (OpenClaw/Playwright + PinchTab) with hybrid session management
- **LLM-powered decision making** via OpenRouter (Gemini, GPT, Claude, etc.)
- **Real-time React dashboard** with WebSocket live feeds
- **Enterprise export** in SARIF, STIX 2.1, Neo4j Cypher, Maltego CSV, HackerOne, Markdown, and PDF

---

## Key Features

| Category | Capabilities |
|----------|-------------|
| **Reconnaissance** | 9-phase automated pipeline, subdomain enumeration, DNS resolution, port scanning, HTTP probing, web crawling, JS analysis, directory bruteforcing, API schema discovery |
| **Attack Simulation** | Vulnerability validation via Nuclei, out-of-band testing with Interactsh, CVSS scoring, exploit chain analysis |
| **Browser Automation** | Stealth Playwright with anti-bot bypass, headless Chrome/Firefox, session sharing, SPA-aware rendering, forensic evidence capture |
| **AI Intelligence** | LLM-powered command planning, cognitive routing, attack surface analysis, skill extraction and learning, self-improvement engine |
| **Governance** | Scope enforcement at API + tool level, rate limiting, CSRF protection, approval hooks for destructive actions, credential vault with encryption |
| **Observability** | Real-time WebSocket dashboard, structured logging, telemetry, performance tracking, decision audit trails |
| **Distributed** | Master/Worker cluster mode via Redis, distributed event bus, sharded scan state persistence |
| **Self-Healing** | Agent health monitoring, automatic restart callbacks, recovery engine with forensic learning bridge |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  React / Vite Dashboard (:5173)                                  │
│  Dashboard │ New Scan │ Scans │ Live Monitor │ Library │ Settings │
└───────────────────────────┬──────────────────────────────────────┘
                            │ REST + WebSocket (/ws/live)
┌───────────────────────────▼──────────────────────────────────────┐
│  FastAPI Backend (:8000)                                         │
│  Middleware: CORS · Rate Limiter · Scope Guard · API Key Auth    │
│                                                                  │
│  /api/health  /api/recon  /api/attack  /api/reports  /api/ai     │
│  /api/v1/recon/* (Alpha V6)  /api/defense  /api/skills           │
│  /api/scans  /api/data  /api/self-awareness  /bridge             │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│  Hive Orchestrator                                               │
│  EventBus (pub/sub) │ PhaseGate │ BroadcastThrottle              │
│  ScanLifecycleManager │ CognitiveRouter │ EndpointTracker        │
│                                                                  │
│  ┌──────────── Agent Swarm (11 Agents) ────────────┐             │
│  │ Alpha    │ Beta     │ Gamma   │ Delta   │ Omega  │             │
│  │ (Recon)  │ (Attack) │ (Fuzz)  │ (Hybrid)│ (Orch) │             │
│  │ Sigma    │ Kappa    │ Zeta    │ Chi     │ Prism  │             │
│  │ (Score)  │ (Memory) │ (Gov)   │ (Audit) │ (Def)  │             │
│  │ Lambda   │          │         │         │        │             │
│  │ (Learn)  │          │         │         │        │             │
│  └──────────────────────────────────────────────────┘             │
└───────────────────────────┬──────────────────────────────────────┘
                            │
     ┌──────────────────────┼──────────────────────┐
     ▼                      ▼                      ▼
  Supabase              Redis                  Neo4j
  (Postgres)          (Cache +              (Knowledge
  + Scan DB         Distributed Bus)          Graph)
```

---

## Agent Swarm

The platform operates 11 specialized agents, each with a distinct security role:

| Agent | Role | Responsibility |
|-------|------|----------------|
| **Alpha** | Recon Scout | Full reconnaissance pipeline — subdomain discovery, DNS, ports, HTTP probing, crawling, JS analysis, API schema discovery |
| **Beta** | Attack Breaker | Vulnerability exploitation, payload delivery, exploit chain construction |
| **Gamma** | Forensic Analyst | Fuzzing campaigns, evidence collection, deep content analysis |
| **Delta** | Hybrid Controller | Browser engine orchestration, hybrid session management between OpenClaw and PinchTab |
| **Omega** | Campaign Strategist | High-level scan strategy, agent coordination, objective planning |
| **Sigma** | Payload Smith | Vulnerability scoring (CVSS), finding normalization, severity assessment |
| **Kappa** | Memory Librarian | Knowledge persistence, skill cataloging, learning loop management |
| **Zeta** | Governance Governor | Scope enforcement, policy compliance, engagement authorization |
| **Chi** | Inspector | Code analysis, audit trail verification, scan integrity checks |
| **Prism** | Defense Sentinel | Defensive posture analysis, WAF detection, security header evaluation |
| **Lambda** | Learner | Self-improvement engine, skill extraction, performance optimization learning |

All agents communicate through a **distributed EventBus** (`backend/core/hive.py`) with typed events, priority queuing, and broadcast throttling.

---

## Alpha V6 Recon Engine

The flagship reconnaissance engine runs a **9-phase pipeline** with 25+ integrated tools:

```
Phase 1: Passive Recon       → subfinder, amass, gau, waybackurls, cloudlist, spiderfoot
Phase 2: DNS Resolution      → dnsx, shuffledns
Phase 3: Port Scanning       → naabu, nmap, masscan
Phase 4: HTTP Probing        → httpx (alive hosts, tech detection, status codes)
Phase 5: Web Crawling        → katana, hakrawler, gospider, browser engines
Phase 6: JS Analysis         → LinkFinder, SecretFinder
Phase 7: Directory Discovery → feroxbuster, ffuf, gobuster, dirsearch
Phase 8: API Recon           → kiterunner, InQL, OpenAPI/GraphQL schema discovery
Phase 9: Validation          → nuclei (templates), interactsh (OOB), gowitness (screenshots)
```

### Pipeline Features
- **Phase Gate** — Each phase must complete before the next begins; gates enforce ordering and can be overridden
- **Scope Gate** — URL/domain validation at every tool invocation prevents out-of-scope scanning
- **Deduplication** — Cross-tool finding deduplication with configurable similarity thresholds
- **Live Feed** — Real-time WebSocket events for every finding, phase transition, and agent action
- **Approval Hooks** — Human-in-the-loop confirmation for destructive or high-risk actions
- **Entity Engine** — Extracted entities (IPs, domains, emails, secrets) are linked into a knowledge graph

---

## Integrated Security Tools

| Phase | Tool | Parser |
|-------|------|--------|
| Passive Recon | subfinder, amass, gau, waybackurls, cloudlist, spiderfoot | ✅ Each has a dedicated parser |
| DNS / Infra | dnsx, shuffledns, testssl, tlsx, wafw00f, whatweb, cdncheck | ✅ |
| Port Scanning | naabu, nmap, masscan | ✅ |
| HTTP Probing | httpx, httprobe | ✅ |
| Web Crawling | katana, hakrawler, gospider, aquatone | ✅ |
| JS Analysis | LinkFinder, SecretFinder | ✅ |
| Directory Discovery | feroxbuster, ffuf, gobuster, dirsearch | ✅ |
| API Recon | kiterunner, InQL | ✅ |
| Parameter Discovery | arjun | ✅ |
| XSS Testing | dalfox | ✅ |
| Validation | nuclei, interactsh | ✅ |
| Visual | gowitness | ✅ |

**35 dedicated parsers** in `backend/parsers/recon/` transform raw tool output into normalized findings with severity, confidence, and CVSS scores.

All tools run inside **Docker containers** via the `DockerToolRuntime` (`backend/tools/recon/docker_runtime.py`), with configurable timeouts, guardrails, and scope validation.

---

## Browser Automation Stack

Vul-Agent includes a sophisticated **dual-engine browser automation** system:

| Engine | Use Case | Features |
|--------|----------|----------|
| **OpenClaw (Playwright)** | Stealth browsing, SPA rendering, JS-heavy sites | Anti-bot bypass, stealth launch args, viewport spoofing, cookie/session persistence |
| **PinchTab** | Headless browser intelligence, parallel crawling | Remote browser control, cluster-aware fuzzing, screenshot capture |

### Hybrid Session Manager
The `HybridSessionManager` (`backend/core/hybrid_session_manager.py`) provides:
- Automatic engine selection based on target characteristics
- Session sharing between OpenClaw and PinchTab
- Fallback cascading when one engine is unavailable
- Forensic evidence capture (HAR files, screenshots, DOM snapshots)

### Unified Browser Engine
The `browser_engine.py` consolidates all browser capabilities into a single module with Scrapling integration for advanced anti-detection, proxy rotation, and adaptive CSS/XPath parsing.

---

## AI & LLM Integration

| Component | File | Purpose |
|-----------|------|---------|
| **AI Cortex** | `backend/ai/cortex.py` | Central LLM interface — prompt construction, response parsing, context management |
| **Gemini Adapter** | `backend/ai/gemini.py` | Google Gemini model integration |
| **GI5 Engine** | `backend/ai/gi5.py` | Multi-model AI orchestration layer |
| **OpenRouter** | `backend/ai/openrouter.py` | OpenRouter API for model routing (GPT-4, Claude, Gemini, etc.) |
| **Cognitive Router** | `backend/core/cognitive_router.py` | Intelligent request routing to the optimal LLM based on task type |
| **Skill Library** | `backend/core/skill_library.py` | AI-extracted reusable pentest skills with learning loop |
| **Self-Improvement** | `backend/core/self_improvement_engine.py` | Performance-driven optimization of agent strategies |
| **Learning Engine** | `backend/core/learning_engine.py` | Cross-scan pattern learning and technique refinement |

---

## Frontend Dashboard

Built with **React 18 + Vite**, the dashboard provides:

| Page | Component | Features |
|------|-----------|----------|
| **Dashboard** | `Dashboard.jsx` | Scan overview, agent status cards, finding statistics, severity distribution |
| **New Scan** | `NewScan.jsx` | Target configuration, scan mode selection, engine preferences, scope settings |
| **Scans** | `Scans.jsx` | Scan history, status tracking, result browsing, export controls |
| **Live Monitor** | `LiveMonitor.jsx` | Real-time WebSocket feed of agent actions, findings, and phase transitions |
| **Library** | `Library.jsx` | Skill catalog, finding templates, reusable configurations |
| **Settings** | `Settings.jsx` | User preferences, API keys, engine configuration, authentication |
| **Login** | `Login.jsx` | Session-based authentication with TOTP support |

### UI Features
- Framer Motion animations
- Lenis smooth scrolling
- Dark mode with glassmorphism aesthetics
- Responsive layout
- Real-time severity badges and status indicators

---

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Infrastructure health check (Supabase, Redis, Alpha status) |
| `GET` | `/api/tools` | List all integrated recon tools with availability status |
| `POST` | `/api/v1/recon/start` | Start a new reconnaissance scan |
| `GET` | `/api/v1/recon/status/{id}` | Get scan status and progress |
| `POST` | `/api/v1/recon/stop/{id}` | Cancel a running scan |
| `GET` | `/api/v1/recon/scans` | List all scan history |
| `POST` | `/api/v1/recon/export` | Export findings (SARIF/STIX/Neo4j/Markdown/PDF) |
| `WS` | `/api/v1/recon/live/{id}` | Real-time scan event stream |

### Additional API Groups

| Prefix | Tag | Description |
|--------|-----|-------------|
| `/api/recon` | Recon | Legacy recon endpoints |
| `/api/attack` | Attack | Vulnerability exploitation and payload delivery |
| `/api/reports` | Reports | PDF/SARIF/STIX report generation |
| `/api/defense` | Defense | Defensive posture analysis |
| `/api/dashboard` | Dashboard | UI data aggregation |
| `/api/ai` | AI | Direct LLM interaction and prompt management |
| `/api/data` | Data | Raw scan data access |
| `/api/scans` | Scans | Scan management and lifecycle |
| `/api/skills` | Skills | Skill library CRUD |
| `/api/self-awareness` | Self-Awareness | Agent introspection and performance metrics |
| `/bridge` | Extension Bridge | Browser extension communication |
| `WS /ws/live` | WebSocket | Global real-time event stream |

---

## Export Formats

| Format | Standard | Use Case |
|--------|----------|----------|
| **SARIF v2.1.0** | OASIS | GitHub Advanced Security, Azure DevOps, VS Code |
| **STIX 2.1** | OASIS | OpenCTI, MISP, threat intelligence platforms |
| **Neo4j Cypher** | Neo4j | Graph database import for attack path analysis |
| **Maltego CSV** | Maltego | Link analysis and relationship visualization |
| **HackerOne** | HackerOne | Bug bounty submission formatting |
| **PDF** | — | Professional penetration test reports with CVSS scores |
| **Markdown** | — | Human-readable finding reports |

---

## Getting Started

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Redis** (optional — enables distributed caching and cluster mode)
- **Supabase** account (for persistent scan storage)
- **Docker** (optional — for containerized security tool execution)

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/aniket2348823/Vul-Agent.git
cd Vul-Agent

# Create environment configuration
cp .env.example .env
# Edit .env with your Supabase URL/Key, OpenRouter API key, and other settings

# Install Python dependencies
pip install -r backend/requirements.txt

# Install Playwright browsers (for browser automation)
playwright install chromium

# Start the API server
python -m backend.main --mode serve
```

### Frontend Setup

```bash
# Install Node.js dependencies
npm install

# Start the development server
npm run dev
```

The dashboard will be available at `http://localhost:5173` and the API at `http://localhost:8000`.

### Cluster Mode

```bash
# Start a full cluster (1 master + N workers)
python -m backend.main --mode cluster --num-workers 5

# Or start components individually
python -m backend.main --mode master
python -m backend.main --mode worker --worker-id worker-1
```

---

## Docker Deployment

```bash
# Production deployment with Docker Compose
docker-compose up -d
```

This starts three services:
- **Backend** (FastAPI) on port `8000`
- **Frontend** (Nginx-served React build) on port `5173`
- **Redis** on port `6379`

```yaml
# docker-compose.yml services:
# - backend: FastAPI app with scan data volume
# - frontend: Nginx-served Vite build
# - redis: Redis 7 Alpine with health checks
```

---

## Configuration

All configuration is managed through environment variables. See [`.env.example`](.env.example) for the complete reference.

### Required Variables

| Variable | Description |
|----------|-------------|
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_KEY` | Your Supabase anonymous key |
| `OPENROUTER_API_KEY` | OpenRouter API key for LLM access |

### Key Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `ALPHA_ENABLE_V6` | `true` | Enable the V6 recon engine |
| `ALPHA_DEFAULT_MODE` | `STANDARD` | Default scan mode |
| `ALPHA_DEFAULT_RPS` | `50` | Requests per second limit |
| `OPENCLAW_ENABLED` | `true` | Enable OpenClaw/Playwright browser engine |
| `HYBRID_BROWSER_ENABLED` | `true` | Enable hybrid browser orchestration |
| `ALPHA_ENABLE_NEO4J` | `false` | Enable Neo4j graph database |
| `ENABLE_SELF_HEALING` | `true` | Enable agent self-healing recovery |
| `ENABLE_UNIFIED_GRAPH` | `true` | Enable unified knowledge graph |

### Feature Flags & Rollout

The platform supports gradual rollout of advanced features:

| Feature | Flag | Rollout % |
|---------|------|-----------|
| Browser Learning | `ENABLE_BROWSER_LEARNING` | 10% |
| Skill Library V2 | `ENABLE_SKILL_LIBRARY_V2` | 25% |
| Browser Health Monitoring | `ENABLE_BROWSER_HEALTH_MONITORING` | 50% |
| Self-Healing Engine | `ENABLE_SELF_HEALING` | 75% |
| Unified Knowledge Graph | `ENABLE_UNIFIED_GRAPH` | 100% |
| Intelligent Routing | `ENABLE_INTELLIGENT_ROUTING` | 100% |

---

## Testing

```bash
# Run the full test suite
python -m pytest tests/ -v --tb=short

# Run with coverage
python -m pytest tests/ --cov=backend --cov-report=html

# Run specific test phases
python -m pytest tests/phase1_core_imports.py -v    # Core import validation
python -m pytest tests/phase2_api_health.py -v      # API health checks
python -m pytest tests/phase3_recon_pipeline.py -v  # Recon pipeline tests
python -m pytest tests/phase4_attack_pipeline.py -v # Attack pipeline tests
python -m pytest tests/phase5_ai.py -v              # AI integration tests
python -m pytest tests/phase6_dashboard.py -v       # Dashboard API tests
python -m pytest tests/phase7_reports.py -v          # Report generation tests
```

### Test Categories

| Directory | Coverage |
|-----------|----------|
| `tests/` | Unit tests for parsers, scope gates, scoring, guardrails, event schemas, deduplication |
| `tests/e2e/` | End-to-end system tests |
| `tests/integration/` | Cross-component integration tests |
| `tests/chaos/` | Chaos engineering and resilience tests |
| `tests/property/` | Property-based testing |

---

## Project Structure

```
Vul-Agent/
├── backend/
│   ├── agents/                    # 11 AI agents
│   │   ├── alpha.py               # Recon Scout
│   │   ├── beta.py                # Attack Breaker
│   │   ├── gamma.py               # Forensic Analyst
│   │   ├── delta.py               # Hybrid Controller
│   │   ├── omega.py               # Campaign Strategist
│   │   ├── sigma.py               # Payload Smith
│   │   ├── kappa.py               # Memory Librarian
│   │   ├── zeta.py                # Governance Governor
│   │   ├── chi.py                 # Inspector
│   │   ├── prism.py               # Defense Sentinel
│   │   ├── lambda_agent.py        # Learner
│   │   ├── alpha_recon/           # Alpha V6 recon subsystem (21 modules)
│   │   │   ├── alpha_orchestrator.py
│   │   │   ├── phase_controller.py
│   │   │   ├── scope_gate.py
│   │   │   ├── scoring.py
│   │   │   ├── exporters.py
│   │   │   ├── live_feed.py
│   │   │   └── ...
│   │   └── commanders/            # Delegation child runners
│   ├── ai/                        # LLM integration layer
│   │   ├── cortex.py              # Central AI cortex (113KB)
│   │   ├── gemini.py              # Google Gemini adapter
│   │   ├── gi5.py                 # Multi-model orchestration
│   │   └── openrouter.py          # OpenRouter API client
│   ├── api/                       # REST + WebSocket endpoints
│   │   ├── endpoints/             # Route handlers
│   │   ├── socket_manager.py      # WebSocket connection manager
│   │   └── defense.py             # Defense API
│   ├── core/                      # Core engine (89 modules)
│   │   ├── orchestrator.py        # Hive orchestrator (1337 lines)
│   │   ├── hive.py                # EventBus + distributed pub/sub
│   │   ├── browser_engine.py      # Unified browser engine (Scrapling)
│   │   ├── browser_orchestrator.py # Browser session orchestration
│   │   ├── learning_engine.py     # Cross-scan learning (102KB)
│   │   ├── recovery_engine.py     # Self-healing + recovery (84KB)
│   │   ├── terminal_engine.py     # Tool execution engine
│   │   ├── skill_library.py       # AI skill catalog
│   │   ├── state.py               # Scan state management
│   │   ├── config.py              # Configuration management
│   │   ├── scope.py               # Scope enforcement
│   │   ├── phase_gate.py          # Phase gate controller
│   │   ├── cognitive_router.py    # LLM request routing
│   │   ├── scan_lifecycle_manager.py
│   │   └── ...
│   ├── parsers/recon/             # 35 tool output parsers
│   ├── reporting/                 # Report generators (PDF, SARIF, STIX)
│   ├── skills/                    # Skill library framework
│   ├── tools/recon/               # Tool execution layer
│   │   ├── commands.py            # Tool command builders
│   │   ├── docker_runtime.py      # Docker container runtime
│   │   ├── registry.py            # Tool registry
│   │   └── guardrails.py          # Execution guardrails
│   ├── integrations/              # External service clients
│   ├── modules/                   # Attack modules
│   └── main.py                   # Application entry point
├── src/                           # React frontend
│   ├── components/                # UI components
│   │   ├── Dashboard.jsx
│   │   ├── NewScan.jsx
│   │   ├── Scans.jsx
│   │   ├── LiveMonitor.jsx
│   │   ├── Library.jsx
│   │   ├── Settings.jsx
│   │   └── Login.jsx
│   ├── App.jsx                    # Root component with routing
│   └── index.css                  # Global styles
├── tests/                         # Test suite
├── config/                        # Build + tool configuration
├── docker/                        # Docker build assets
├── docs/                          # Documentation
├── scripts/                       # Development scripts
├── docker-compose.yml             # Production deployment
├── Dockerfile                     # Backend container
├── Dockerfile.frontend            # Frontend container
├── nginx.conf                     # Frontend reverse proxy
├── requirements.txt               # Root Python dependencies
├── package.json                   # Frontend dependencies
└── .env.example                   # Environment variable reference
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System architecture and design principles |
| [`docs/PROJECT.md`](docs/PROJECT.md) | Project description and goals |
| [`docs/VUL_AGENT_MANIFEST.md`](docs/VUL_AGENT_MANIFEST.md) | Agent capabilities and specifications |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines |
| [`.env.example`](.env.example) | Complete environment variable reference |

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Copyright © 2026 Antigravity Security

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/aniket2348823">aniket2348823</a></sub>
</p>
