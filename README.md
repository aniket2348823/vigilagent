<p align="center">
  <img src="https://img.shields.io/badge/Version-6.1.0-blueviolet?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

# Vigilagent — Autonomous AI-Powered Penetration Testing Platform

> A multi-agent swarm intelligence system for automated security reconnaissance, vulnerability assessment, and attack simulation — driven by LLM-powered decision making, 39 recon tools, 35+ parsers, and a real-time React dashboard.

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
- [Documentation](#documentation)
- [License](#license)

---

## Overview

Vigilagent is a full-stack autonomous penetration testing platform that coordinates a swarm of specialized AI agents to perform end-to-end security assessments. Each agent operates with a distinct role — from reconnaissance and exploitation to forensic analysis and governance — orchestrated by a central Hive system with event-driven communication, phase-gated scan pipelines, and self-healing capabilities.

It models itself as a "digital organism": a **Hive Orchestrator** (`backend/core/orchestrator.py`) wakes the agents, feeds them a typed event vocabulary via the **EventBus** (`backend/core/hive.py`), and lets them collaborate to take a target from `TARGET_ACQUIRED` to `REPORT_READY`.

The platform combines:

- **Multi-agent AI orchestration** with 12 specialized agents (including a Network Service Commander for OSI L3–L7 assessment) and bounded delegation via `DelegationManager`
- **39 external security tools** integrated via Docker-containerized or local PATH runtimes
- **35+ output parsers** for structured finding extraction with CVSS scoring
- **Dual browser automation engines** (OpenClaw/Playwright + PinchTab) with hybrid session management
- **Two-LLM architecture** — strategic (GPT) + tactical (Gemini) models via OpenRouter
- **Real-time React dashboard** with WebSocket live feeds at ~50 FPS broadcast batching
- **Enterprise export** in SARIF, STIX 2.1, Neo4j Cypher, Maltego CSV, HackerOne, Markdown, and PDF
- **Graceful degradation** — runs fully local (SQLite + in-process EventBus) or distributed (Redis + Supabase)

---

## Key Features

| Category | Capabilities |
|----------|-------------|
| **Reconnaissance** | 9-phase automated pipeline, subdomain enumeration, DNS resolution, port scanning, HTTP probing, web crawling, JS analysis, directory bruteforcing, API schema discovery |
| **Attack Simulation** | Vulnerability validation via Nuclei, out-of-band testing with Interactsh, CVSS scoring, exploit chain analysis, Bayesian evidence fusion |
| **Browser Automation** | Stealth Playwright with anti-bot bypass, headless Chrome/Firefox, session sharing, SPA-aware rendering, forensic evidence capture (HAR, DOM snapshots, screenshots) |
| **AI Intelligence** | Two-LLM exclusivity (strategic + tactical), cognitive routing, attack surface analysis, skill extraction and learning, self-improvement engine |
| **Governance** | `ScopePolicy.assert_allowed()` at every tool invocation, ≥2-signal evidence requirement for confirmed vulns, rate limiting, CSRF protection, approval hooks for destructive actions |
| **Observability** | Real-time WebSocket dashboard, 4 operator dashboards (Integration Health, Learning, Skills, Browser Health), 7 alert rules, structured logging, decision audit trails |
| **Distributed** | Master/Worker cluster mode via Redis pub/sub, `DistributedEventBus`, sharded scan state, durable task leases with crash recovery |
| **Self-Healing** | Agent health monitoring, browser memory leak detection, circuit-breaker-protected cross-system learning, automatic restart with forensic learning bridge |
| **Persistence** | Dual-tier storage — SQLite WAL (durable execution state + FTS5 search) and Supabase (vulnerabilities, recon entities, HTTP exchanges) |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  React / Vite Dashboard (:5173)                                  │
│  Dashboard │ New Scan │ Scans │ Live Monitor │ Library │ Settings │
└───────────────────────────┬──────────────────────────────────────┘
                            │ REST + WebSocket (/ws/live, /stream)
┌───────────────────────────▼──────────────────────────────────────┐
│  FastAPI Backend (:8000)                                         │
│  Middleware: CORS · Rate Limiter · Scope Guard · API Key Auth    │
│                                                                  │
│  /api/health  /api/scans  /api/recon  /api/attack  /api/reports  │
│  /api/v1/recon/* (Alpha V6)  /api/defense  /api/skills           │
│  /api/ai  /api/data  /api/self-awareness  /api/integration       │
│  /api/runtime/health  /bridge                                    │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│  Hive Orchestrator (backend/core/orchestrator.py)                │
│  EventBus (pub/sub) │ PhaseGate │ GuardLayer │ DelegationManager │
│  MissionPlanner │ CognitiveRouter │ IntegrationCoordinator       │
│                                                                  │
│  ┌────────────── Agent Swarm (12 Agents) ──────────────┐          │
│  │ Alpha    │ Beta     │ Gamma    │ Delta   │ Omega    │          │
│  │ (Recon)  │ (Attack) │ (Audit)  │ (DOM)   │ (Strat)  │          │
│  │ Sigma    │ Kappa    │ Zeta     │ Chi     │ Prism    │          │
│  │ (Payload)│ (Memory) │ (Gov)    │ (Insp)  │ (Def)    │          │
│  │ Lambda   │ NetworkServiceCommander (L3-L7)          │          │
│  │ (Learn)  │ Port scan → Service ID → TLS analysis    │          │
│  └─────────────────────────────────────────────────────┘          │
│                              │                                    │
│  ┌─── Recon Plane ───────────▼───────────────────┐               │
│  │ TerminalEngine → Docker sandbox / Local PATH  │               │
│  │ 39 tools: nmap, nuclei, amass, katana, ...    │               │
│  └───────────────────────────────────────────────┘               │
└───────────────────────────┬──────────────────────────────────────┘
                            │
     ┌──────────────────────┼──────────────────────┐
     ▼                      ▼                      ▼
  SQLite WAL            Redis               Supabase
  (scan_state.db     (Distributed        (Vulnerabilities,
   + FTS5 search)     EventBus +          recon entities,
                      work queues)        HTTP exchanges)
                                              │
                                    ┌─────────▼─────────┐
                                    │  OpenRouter LLMs   │
                                    │  Strategic + Tact. │
                                    └───────────────────┘
```

The same binary degrades gracefully:
- **Local mode**: in-process `EventBus`, no Redis, all state in `scan_state.db` and `stats.json`
- **Distributed mode**: `DistributedEventBus` overlays Redis pub/sub for fan-out + work queues

---

## Agent Swarm

The platform operates 12 specialized agents, all inheriting from `BaseAgent` (`backend/core/hive.py`) and following a fixed `start → setup → lifecycle → think → execute_task → stop` shape:

| Agent | Code | Role | Responsibility |
|-------|------|------|----------------|
| **Alpha** | `backend/agents/alpha.py` | Recon Scout | Drives the 39-tool recon registry; runs the 9-phase pipeline |
| **Beta** | `backend/agents/beta.py` | Attack Breaker | Fires payloads against confirmed targets for exploit validation |
| **Gamma** | `backend/agents/gamma.py` | Forensic Auditor | Promotes candidates to confirmed findings; evidence collection |
| **Delta** | `backend/agents/delta.py` | DOM Controller | Hybrid Playwright-backed browser controller |
| **Omega** | `backend/agents/omega.py` | Campaign Strategist | Picks campaign profile (Blitzkrieg, Low-and-Slow, Browser-Deep, …) |
| **Sigma** | `backend/agents/sigma.py` | Payload Smith | Constructs payloads via `aiohttp` session with `SessionLifecycleMixin` |
| **Kappa** | `backend/agents/kappa.py` | Memory Librarian | Broadcasts learned patterns across scans |
| **Zeta** | `backend/agents/zeta.py` | Governor | Emits `CONTROL_SIGNAL` for THROTTLE / RESUME / STEALTH |
| **Chi** | `backend/agents/chi.py` | Inspector | Traffic and response analysis |
| **Prism** | `backend/agents/prism.py` | DOM Sentinel | Defensive posture analysis |
| **Lambda** | `backend/agents/lambda_agent.py` | Learner | Self-improvement engine, skill extraction, performance optimization |
| **NetworkServiceCommander** | `backend/agents/commanders/network_commander.py` | Network Service Commander | OSI L3–L7 network assessment — port scanning (naabu/nmap), service fingerprinting (nmap `-sV`), TLS/cipher analysis (tlsx), knowledge graph ingestion. Runs scope-checked via `TerminalEngine`, budgeted via `IterationBudget`, and delegates bounded child tasks through `DelegationManager.register_runner("NetworkChild")`. Subscribes to `TARGET_ACQUIRED` events and auto-assesses every in-scope host |

### Shared Behaviours (`backend/agents/_shared/agent_mixins.py`)

- **SkillRecallMixin** — per-target skill cache
- **SessionLifecycleMixin** — lazy `aiohttp.ClientSession` lifecycle
- **ControlSignalMixin** — uniform Zeta THROTTLE/RESUME/STEALTH handler
- **ScanContextRecorderMixin** — `ctx.append_event(event)` boilerplate

### Commander Delegation (`backend/agents/commanders/`)

Commander agents like `NetworkServiceCommander` can spawn **bounded child workers** through the `DelegationManager` (Architecture §5.1.2). Children receive:
- A sanitised tool allowlist (no `delegate`, `clarify`, or `memory` tools)
- An isolated `IterationBudget` (max depth 3, max concurrent 8)
- A context COPY (not a reference) for isolation

The `NetworkChild` runner is registered at module import time and executes host assessments (port scan → service fingerprint → TLS analysis) as a bounded subtask.

---

## Alpha V6 Recon Engine

The flagship reconnaissance engine runs a **9-phase pipeline** with 39 integrated tools:

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

- **Phase Gate** — Each phase must complete before the next begins (180 s hard upper bound prevents deadlocks)
- **Scope Gate** — `ScopePolicy.allows()` validation at every tool invocation prevents out-of-scope scanning
- **Deduplication** — Cross-tool finding deduplication with configurable similarity thresholds
- **Live Feed** — Real-time WebSocket events for every finding, phase transition, and agent action (~50 FPS batched broadcast)
- **Approval Hooks** — Human-in-the-loop confirmation for destructive or high-risk actions
- **Entity Engine** — Extracted entities (IPs, domains, emails, secrets) are linked into a unified knowledge graph
- **Replay Buffer** — 50-entry ring of recent broadcasts replayed on WebSocket reconnect

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

All tools run via the **TerminalEngine** (`backend/core/terminal_engine.py`) with selectable backends — `TerminalBackend.LOCAL` (PATH binaries) or `TerminalBackend.DOCKER` (containerized) — with configurable timeouts, guardrails, and scope validation.

---

## Browser Automation Stack

Vigilagent includes a sophisticated **dual-engine browser automation** system:

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

### Browser Health Monitoring

The `BrowserHealthMonitorExtension` tracks per-agent browser health scores, memory usage, error rates, and triggers automatic recovery via the `RecoveryEngine` when scores drop below threshold.

---

## AI & LLM Integration

### Two-LLM Architecture

Vigilagent enforces **Two-LLM exclusivity** — only two model slots are permitted:

| Slot | Default Model | Use Case |
|------|---------------|----------|
| **Strategic** | `openai/gpt-oss-20b` | High-level campaign planning, attack strategy, complex reasoning |
| **Tactical** | `gemini-2.5-flash` | Per-tool command generation, quick classification, parse verification |

Both are configured in `backend/core/config.py` and routed through the **Cognitive Router** (`backend/core/cognitive_router.py`).

### AI Components

| Component | File | Purpose |
|-----------|------|---------|
| **AI Cortex** | `backend/ai/cortex.py` | Central LLM interface — prompt construction, response parsing, context management |
| **Gemini Adapter** | `backend/ai/gemini.py` | Google Gemini model integration |
| **GI5 Engine** | `backend/ai/gi5.py` | Multi-model AI orchestration layer |
| **OpenRouter** | `backend/ai/openrouter.py` | OpenRouter API for model routing |
| **Cognitive Router** | `backend/core/cognitive_router.py` | Intelligent request routing to the optimal LLM based on task type |
| **Skill Library** | `backend/core/skill_library.py` | AI-extracted reusable pentest skills with capability/context/framework indexes |
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

- Framer Motion animations with micro-interactions
- Lenis smooth scrolling
- Dark mode with glassmorphism aesthetics
- Responsive layout across devices
- Real-time severity badges and status indicators
- Toast notifications via the shared `useWebSocket` bridge + `useToast`

---

## API Reference

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Infrastructure health check (Supabase, Redis, Alpha status) |
| `GET` | `/api/tools` | List all integrated recon tools with availability status |
| `POST` | `/api/scans` | Create a new scan (returns HTTP 202 with `scan_id`) |
| `GET` | `/api/scans/{id}` | Get scan status and progress |
| `DELETE` | `/api/scans/{id}` | Cancel a running scan |
| `POST` | `/api/v1/recon/start` | Start a new reconnaissance scan |
| `GET` | `/api/v1/recon/status/{id}` | Get scan status and progress |
| `POST` | `/api/v1/recon/stop/{id}` | Cancel a running scan |
| `POST` | `/api/v1/recon/export` | Export findings (SARIF/STIX/Neo4j/Markdown/PDF) |
| `WS` | `/ws/live` | Global real-time event stream (multiplexed WebSocket) |
| `WS` | `/stream` | Per-scan event stream |

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
| `/api/skills` | Skills | Skill library CRUD |
| `/api/self-awareness` | Self-Awareness | Agent introspection and performance metrics |
| `/api/integration/metrics` | Integration | Coordinator health, circuit breaker status, feature flags |
| `/api/runtime/health` | Runtime | Browser stack health, agent health scores |
| `/bridge` | Extension Bridge | Browser extension communication |

> **Full API documentation:** [`docs/API.md`](docs/API.md) · **Changelog:** [`docs/API_CHANGELOG.md`](docs/API_CHANGELOG.md)

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
- **Redis** (optional — enables distributed caching, cluster mode, and `DistributedEventBus`)
- **Supabase** account (optional — for cloud-persisted vulnerabilities and recon entities)
- **Docker** (optional — for containerized security tool execution)

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/aniket2348823/vigilagent.git
cd vigilagent

# Create environment configuration
cp .env.example .env
# Edit .env with your API keys and settings

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

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

### CLI Modes

```bash
# Default: API + Hive in-process (no Redis required)
python -m backend.main --mode serve

# Start a full cluster (1 master + N workers, requires Redis)
python -m backend.main --mode cluster --num-workers 5

# Or start components individually
python -m backend.main --mode master
python -m backend.main --mode worker --worker-id worker-1
```

| Mode | Entry | Purpose |
|------|-------|---------|
| `serve` (default) | `uvicorn.Server` | API + Hive in-process |
| `master` | `DistributedAttackCluster.start_master` | Just the Master node |
| `worker` | `DistributedAttackCluster.start_worker` | Just a Worker |
| `cluster` | `DistributedAttackCluster.start_cluster` | Master + N workers |

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
# docker-compose.yml profiles:
# default:    backend + frontend + redis
# monitoring: + prometheus + grafana + alertmanager
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
| `GEMINI_API_KEY` | Google Gemini API key |
| `API_AUTH_KEY` | API authentication key (min 32 chars) |

### Key Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL (enables distributed mode) |
| `ALPHA_ENABLE_V6` | `true` | Enable the V6 recon engine |
| `ALPHA_DEFAULT_MODE` | `STANDARD` | Default scan mode |
| `ALPHA_DEFAULT_RPS` | `50` | Requests per second limit |
| `OPENCLAW_ENABLED` | `true` | Enable OpenClaw/Playwright browser engine |
| `HYBRID_BROWSER_ENABLED` | `true` | Enable hybrid browser orchestration |
| `ALPHA_ENABLE_NEO4J` | `false` | Enable Neo4j graph database |
| `ENABLE_SELF_HEALING` | `true` | Enable agent self-healing recovery |
| `ENABLE_UNIFIED_GRAPH` | `true` | Enable unified knowledge graph |

### Feature Flags & Rollout

Advanced features ship behind flags with gradual rollout via `config/integration.yaml`:

| Feature | Flag | Rollout % | Stage |
|---------|------|-----------|-------|
| Browser Learning | `ENABLE_BROWSER_LEARNING` | 10% | 1 |
| Skill Library V2 | `ENABLE_SKILL_LIBRARY_V2` | 25% | 2 |
| Browser Health Monitoring | `ENABLE_BROWSER_HEALTH_MONITORING` | 50% | 3 |
| Self-Healing Engine | `ENABLE_SELF_HEALING` | 75% | 4 |
| Unified Knowledge Graph | `ENABLE_UNIFIED_GRAPH` | 100% | 5 |
| Intelligent Routing + Forensic Learning | `ENABLE_INTELLIGENT_ROUTING` | 100% | 5 |

Per-scan cohort decisions use consistent hashing over `scan_id` for reproducible A/B testing.

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
vigilagent/
├── backend/
│   ├── agents/                    # 12 AI agents
│   │   ├── alpha.py               # Recon Scout
│   │   ├── beta.py                # Attack Breaker
│   │   ├── gamma.py               # Forensic Auditor
│   │   ├── delta.py               # DOM Controller
│   │   ├── omega.py               # Campaign Strategist
│   │   ├── sigma.py               # Payload Smith
│   │   ├── kappa.py               # Memory Librarian
│   │   ├── zeta.py                # Governor
│   │   ├── chi.py                 # Inspector
│   │   ├── prism.py               # DOM Sentinel
│   │   ├── lambda_agent.py        # Learner
│   │   ├── factory.py             # Agent factory
│   │   ├── _shared/               # Shared mixins (Skill, Session, Control, Recorder)
│   │   ├── alpha_recon/           # Alpha V6 recon subsystem
│   │   └── commanders/            # Commander agents with bounded delegation
│   │       ├── __init__.py        # Registers NetworkChild runner with DelegationManager
│   │       └── network_commander.py  # L3-L7 network assessment (naabu, nmap -sV, tlsx)
│   ├── ai/                        # LLM integration layer
│   │   ├── cortex.py              # Central AI cortex
│   │   ├── gemini.py              # Google Gemini adapter
│   │   ├── gi5.py                 # Multi-model orchestration
│   │   └── openrouter.py          # OpenRouter API client
│   ├── api/                       # REST + WebSocket endpoints
│   │   ├── endpoints/             # Route handlers
│   │   └── socket_manager.py      # WebSocket connection manager (batched broadcast)
│   ├── core/                      # Core engine
│   │   ├── orchestrator.py        # Hive orchestrator (scan lifecycle)
│   │   ├── hive.py                # EventBus + DistributedEventBus
│   │   ├── scope.py               # ScopePolicy (authorization enforcement)
│   │   ├── scan_state_db.py       # ScanStateDB (SQLite WAL + FTS5)
│   │   ├── database.py            # EliteDBManager (Supabase client)
│   │   ├── terminal_engine.py     # Tool execution engine (Local + Docker)
│   │   ├── config.py              # Configuration management
│   │   ├── context.py             # ScanContext (per-scan execution arena)
│   │   ├── planner.py             # MissionPlanner (task DAG)
│   │   ├── delegation_manager.py  # Bounded child agent delegation
│   │   ├── integration_coordinator.py  # Cross-system event routing + circuit breakers
│   │   ├── learning_engine.py     # Cross-scan pattern learning
│   │   ├── recovery_engine.py     # Self-healing + browser recovery
│   │   ├── skill_library.py       # AI skill catalog
│   │   ├── cognitive_router.py    # LLM request routing
│   │   ├── phase_gate.py          # Phase gate controller
│   │   └── ...
│   ├── parsers/recon/             # 35 tool output parsers
│   ├── reporting/                 # Report generators (PDF, SARIF, STIX)
│   ├── skills/                    # Skill library framework
│   ├── tools/recon/               # Tool execution layer
│   │   ├── registry.py            # 39-tool registry (RECON_TOOLS)
│   │   ├── commands.py            # Tool command builders
│   │   └── guardrails.py          # Execution guardrails
│   ├── integrations/              # External service clients
│   ├── modules/                   # Attack modules
│   └── main.py                    # Application entry point (4 CLI modes)
├── src/                           # React 18 + Vite frontend
│   ├── components/                # UI components (Dashboard, NewScan, Scans, ...)
│   ├── lib/                       # API client (apiUrl + websocketUrl)
│   ├── hooks/                     # Custom hooks (useWebSocket, useToast)
│   ├── App.jsx                    # Root component with routing
│   └── index.css                  # Global styles (dark mode, glassmorphism)
├── config/                        # Runtime configuration
│   ├── scope.yaml                 # Default scope policy
│   └── integration.yaml           # Feature flags + rollout percentages
├── docs/                          # Documentation (13 files)
├── tests/                         # Test suite (unit, e2e, integration, chaos, property)
├── docker/                        # Docker build assets
├── docker-compose.yml             # Production deployment (backend + frontend + redis)
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
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System architecture blueprint with code citations — agents, event bus, concurrency model, scan lifecycle, integration coordinator |
| [`docs/API.md`](docs/API.md) | REST & WebSocket API reference — all public endpoints, request/response schemas, auth |
| [`docs/API_CHANGELOG.md`](docs/API_CHANGELOG.md) | API version history and breaking change log |
| [`docs/INTERNAL_API.md`](docs/INTERNAL_API.md) | Internal Python class reference — `StateManager`, `BrowserOrchestrator`, `EventBus`, etc. |
| [`docs/DB_SCHEMA.md`](docs/DB_SCHEMA.md) | SQLite + Supabase schema — tables, columns, indexes, migration versioning |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Full deployment guide — prerequisites, installation, systemd, Nginx, Docker, topology, scaling |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Environment variables, YAML config, feature flags, and tuning knobs |
| [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) | Operator dashboards, alert rules, and metrics reference |
| [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) | Performance benchmarks, profiling results, and optimization recommendations |
| [`docs/SECURITY_BEST_PRACTICES.md`](docs/SECURITY_BEST_PRACTICES.md) | Security guidelines — scope policy, encryption, credential management |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common issues, diagnostic commands, and resolution steps |
| [`docs/USAGE_EXAMPLES.md`](docs/USAGE_EXAMPLES.md) | End-to-end usage examples — creating scans, interpreting results, reports |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines and PR process |

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Copyright © 2026 Vigilagent

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/aniket2348823">aniket2348823</a></sub>
</p>
