# Vigilagent Documentation

Comprehensive documentation for the Vigilagent autonomous penetration testing system.

## 📚 Documentation Index

### Core Architecture & Design

| Document | Description | Audience |
| --- | --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture blueprint — agents, event bus, concurrency model, scan lifecycle, integration coordinator. Senior-engineer onboarding doc with code citations. | Developers, Architects |
| [API.md](API.md) | REST & WebSocket API reference — all public endpoints, request/response schemas, auth. | Frontend Devs, Integrators |
| [INTERNAL_API.md](INTERNAL_API.md) | Internal Python class reference — `StateManager`, `BrowserOrchestrator`, `EventBus`, etc. | Backend Developers |
| [DB_SCHEMA.md](DB_SCHEMA.md) | SQLite + Supabase schema — tables, columns, indexes, migration versioning. | Backend Developers |
| [API_CHANGELOG.md](API_CHANGELOG.md) | API version history and breaking change log. | All Developers |

---

### Operations & Deployment

| Document | Description | Audience |
| --- | --- | --- |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Full deployment guide — prerequisites, installation, systemd, Nginx, Docker, topology, scaling, backup & recovery. | DevOps, SRE |
| [CONFIGURATION.md](CONFIGURATION.md) | Environment variables, YAML config files, feature flags, and tuning knobs. | DevOps, Developers |
| [OBSERVABILITY.md](OBSERVABILITY.md) | Operator dashboards (Integration Health, Learning, Skills, Browser Health), alert rules, and metrics reference. | SRE, On-Call |
| [PERFORMANCE.md](PERFORMANCE.md) | Performance benchmarks, profiling results, and optimization recommendations. | Developers, SRE |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues, diagnostic commands, and resolution steps. | All Engineers |

---

### Security & Usage

| Document | Description | Audience |
| --- | --- | --- |
| [SECURITY_BEST_PRACTICES.md](SECURITY_BEST_PRACTICES.md) | Security guidelines — scope policy, encryption, credential management, network isolation. | All Engineers |
| [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) | End-to-end usage examples — creating scans, interpreting results, report generation. | Users, New Engineers |

---

## 🔗 Related Documentation

### Project-Level
- **[README.md](../README.md)** — Project overview and quick start
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** — Contribution guidelines and PR process
- **[.github/SECURITY.md](../.github/SECURITY.md)** — Vulnerability reporting policy

### Planning
- **[.planning/ROADMAP.md](../.planning/ROADMAP.md)** — Product roadmap
- **[.planning/STATE.md](../.planning/STATE.md)** — Current project status

### Frontend
- **[src/README.md](../src/README.md)** — React/Vite frontend setup and development

---

## 📖 Documentation Standards

### File Naming
- **UPPERCASE** for major docs (`ARCHITECTURE.md`, `DEPLOYMENT.md`)
- **lowercase_with_underscores** for supplementary docs

### Document Structure
All major documentation should include:
1. **Title and Overview** — What this document covers
2. **Table of Contents** — For documents > 100 lines
3. **Main Content** — Organized into logical sections
4. **Cross-References** — Links to related docs
5. **Metadata Footer** — Last updated date, version

---

**Last Updated:** June 26, 2026  
**Documentation Files:** 12 core documents  
**Maintained By:** Vigilagent Development Team
