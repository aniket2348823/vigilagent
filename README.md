# Antigravity V6 — Autonomous Security Reconnaissance Platform

> AI-powered multi-agent security engine with real-time dashboard, 25+ tool integrations, and enterprise export formats.

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Redis (optional, for distributed cache)
- Supabase account (for persistence)

### Backend Setup
```bash
cd "D:\Antigravity 2\API Endpoint Scanner"
cp .env.example .env
# Edit .env with your Supabase/Redis credentials

pip install -r backend/requirements.txt
python -m backend.main --mode serve
```

### Frontend Setup
```bash
npm install
npm run dev
```

### Docker (Production)
```bash
docker-compose up -d
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  React/Vite Dashboard (5173)                            │
│  Dashboard │ Recon │ Scans │ Library │ Settings          │
└────────────────────────┬────────────────────────────────┘
                         │ REST + WebSocket
┌────────────────────────▼────────────────────────────────┐
│  FastAPI Backend (8000)                                  │
│  /api/health │ /api/recon │ /api/attack │ /api/reports   │
│  /api/v1/recon/* (Alpha V6 Engine)                       │
│  /ws/live (Real-time events)                             │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  Agent Swarm                                             │
│  Alpha (Recon) │ Beta (Exploit) │ Gamma (Fuzz)           │
│  Omega (Orch)  │ Sigma (Score)  │ Chi (Analysis)         │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  Alpha V6 Recon Engine (25 modules)                      │
│  9-phase pipeline │ 24 parsers │ 25+ tool integrations   │
│  Scope Gate │ Interactsh OOB │ Schema Discovery           │
│  Playwright Fallback │ Approval Hooks │ Live Feed         │
└────────────────────────┬────────────────────────────────┘
                         │
     ┌───────────────────┼───────────────────┐
     ▼                   ▼                   ▼
  Supabase            Redis              Neo4j
  (Postgres)         (Cache)            (Graph)
```

## Integrated Tools (25+)

| Phase | Tools |
|-------|-------|
| Passive Recon | subfinder, amass, gau, waybackurls, cloudlist, spiderfoot |
| DNS/Infra | dnsx, shuffledns, naabu, nmap, tlsx |
| HTTP/Browser | httpx, katana, hakrawler, PinchTab, Playwright |
| JS Analysis | LinkFinder, SecretFinder |
| Discovery | feroxbuster, ffuf, gobuster, dirsearch |
| API Recon | kiterunner, InQL, Schema Discovery (OpenAPI/GraphQL) |
| Visual | gowitness |
| Validation | nuclei, interactsh |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Infrastructure health check |
| POST | `/api/v1/recon/start` | Start recon scan |
| GET | `/api/v1/recon/status/{id}` | Scan status |
| POST | `/api/v1/recon/stop/{id}` | Cancel scan |
| GET | `/api/v1/recon/scans` | List scans |
| POST | `/api/v1/recon/export` | Export (SARIF/STIX/Neo4j/Markdown) |
| WS | `/api/v1/recon/live/{id}` | Real-time feed |

## Export Formats

- **SARIF v2.1.0** — GitHub/Azure DevOps integration
- **STIX 2.1** — OpenCTI/MISP threat intelligence
- **Neo4j Cypher** — Graph database import
- **Maltego CSV** — Link analysis
- **HackerOne** — Bug bounty submission
- **Markdown** — Human-readable reports

## Environment Variables

See [.env.example](.env.example) for all configuration options.

## Running Tests

```bash
python -m pytest tests/ -v --tb=short
```

## Documentation

### Core Documentation
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design principles
- **[Project Overview](docs/PROJECT.md)** - Project description and goals
- **[Agent Manifest](docs/VUL_AGENT_MANIFEST.md)** - Agent capabilities and specifications
- **[Exhaustive Audit](docs/exhaustive_audit.md)** - Comprehensive system audit
- **[Cleanup Assessment](docs/cleanup_assessment_7_tracks.md)** - Code cleanup analysis

### Specifications
- **[OpenClaw Integration](.kiro/specs/openclaw-integration/)** - Browser automation integration
- **[File Consolidation](.kiro/specs/file-consolidation/)** - Project organization improvements

### Planning
- **[Roadmap](.planning/ROADMAP.md)** - Product roadmap and future plans
- **[Current State](.planning/STATE.md)** - Current project status
- **[Archived Plans](.planning/archive/)** - Historical planning documents

### Development
- **[Scripts](scripts/)** - Development and maintenance scripts ([README](scripts/README.md))
- **[Tests](testsprite_tests/)** - Comprehensive test suite ([README](testsprite_tests/README.md))

### Data & Configuration
- **[Data Files](data/)** - Runtime data and scan results
- **[Configuration](data/config/)** - User configuration files

## License

Proprietary — All rights reserved.
