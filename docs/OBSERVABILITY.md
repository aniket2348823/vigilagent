# Observability — Vigilagent

> Single-source observability reference for operators and on-call engineers.
> Covers all four operator dashboards, seven alert rules, and a consolidated
> metrics reference. All metrics originate from the
> `GET /api/integration/metrics` and `GET /api/runtime/health` endpoints
> documented in [`API.md`](API.md) §17a. Architecture context lives in
> [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## §1 Dashboards

The Vigilagent UI ships four operator dashboards. Three are existing
(Integration Health, Learning Performance, Skill Library) and one is new
with the Deep System Integration spec (Browser Health). All four read from
the same `/api/integration/metrics` and `/api/runtime/health` endpoints;
alert thresholds are mirrored in [§2 Alert Rules](#2-alert-rules) below.

### 1.1 Integration Health

**Source.** `/api/integration/metrics` → the `integration` sub-object
(`backend/api/endpoints/dashboard.py:882`).

**Panels.**

- *Events processed* — line chart of `events_processed` and
  `events_failed` over the last hour.
- *Failure rate* — gauge of `failure_rate`, color band on
  thresholds below.
- *Circuit breaker trips* — single-stat of
  `circuit_breaker_trips`, with the per-trip log line surfaced
  inline.
- *Discovery batch backlog* — line chart of `pending_discoveries`
  and `last_batch_size` (handy for spotting when batching is doing
  its job).
- *Feature matrix* — table that pivots `features_enabled` against
  the rollout percentages from `config/integration.yaml`.

**Metrics read.**

`integration.events_processed`, `integration.events_failed`,
`integration.events_skipped`, `integration.failure_rate`,
`integration.circuit_breaker_trips`, `integration.pending_discoveries`,
`integration.batches_flushed`, `integration.last_batch_size`,
`integration.features_enabled`.

**Alert thresholds.**

| Metric                                          | Warning | Critical | Page on-call |
| ----------------------------------------------- | ------- | -------- | ------------ |
| `failure_rate` (sustained 5 min)                | `> 0.05`| `> 0.10` | yes (critical) |
| `circuit_breaker_trips` (any increase)          | `+1`    | —        | warning      |
| `pending_discoveries / event_batch_size`        | `> 0.8` | `= 1.0`  | warning      |

> See [§2.1 High failure rate](#21-high-failure-rate--page) and
> [§2.7 Discovery batch saturated](#27-discovery-batch-saturated--warning)
> for runbook links.

### 1.2 Learning Performance

**Source.** `/api/integration/metrics` → the `learning` sub-object
plus `performance.report` (the `performance_optimizer` summary already
surfaced by the dashboard endpoint).

**Panels.**

- *Patterns total* — single-stat of `learning.total_patterns`.
- *HTTP vs browser patterns* — stacked bar of `learning.http_patterns`
  vs `learning.browser_patterns`.
- *Pattern acquisition rate* — line chart, derived as
  `Δlearning.total_patterns / Δt` over the last hour.
- *Skill search latency p50/p99* — read from
  `performance.report.skill_search_latency_ms` (already exported by
  `performance_optimizer.get_performance_report()`).

**Metrics read.**

`learning.total_patterns`, `learning.http_patterns`,
`learning.browser_patterns`,
`performance.skill_search_latency_ms.p50`,
`performance.skill_search_latency_ms.p99`.

**Alert thresholds.**

| Metric                                       | Warning | Critical |
| -------------------------------------------- | ------- | -------- |
| Pattern acquisition rate (per hour, sustained 4h) | `< 1`   | `< 0.1`  |
| `skill_search_latency_ms.p99`                | `> 50`  | `> 200`  |

> See [§2.3 Slow skill search](#23-slow-skill-search--warning) for the
> runbook.

### 1.3 Skill Library

**Source.** `/api/integration/metrics` → the `skills` sub-object.

**Panels.**

- *Total skills* — single-stat of `skills.total_skills`.
- *Composition* — donut of `skills.http_skills`,
  `skills.browser_skills`, `skills.hybrid_skills`.
- *Acquisition rate* — line chart of `skills.acquisition_rate` over
  time. Rate is computed server-side as
  `total_skills / max(1, total_patterns)` so the chart shows how
  efficiently patterns turn into reusable skills.
- *Deprecated skills* — table of skills marked deprecated, joined
  client-side with the per-skill metadata returned by
  `/api/skills/{id}` (deprecation_reason, migration_path).
- *Migration status* — read from the most recent
  `POST /api/skills/migrate-v2` response, cached client-side.

**Metrics read.**

`skills.total_skills`, `skills.http_skills`, `skills.browser_skills`,
`skills.hybrid_skills`, `skills.acquisition_rate`,
plus `/api/skills/` and `/api/skills/{id}` for the deprecation table.

**Alert thresholds.**

| Metric                            | Warning | Critical |
| --------------------------------- | ------- | -------- |
| `skills.acquisition_rate`         | `< 0.3` | `< 0.1`  |
| Migration `failed` count          | `> 0`   | —        |

### 1.4 Browser Health (new)

**Source.** `/api/runtime/health` → the `browser_health` sub-object
(`backend/api/endpoints/runtime.py:97`,
`BrowserHealthMonitorExtension.get_browser_health_summary` /
`get_all_browser_health`).

**Panels.**

- *Engine status* — colored chips for OpenClaw and PinchTab from
  `browser.openclaw` and `browser.pinchtab`. Click reveals
  `browser.reasons` if the engine is `unavailable`.
- *Active contexts* — single-stat of
  `browser_health.summary.total_active_contexts`.
- *Browser memory* — line chart of
  `browser_health.summary.total_browser_memory_mb`. Threshold band
  drawn at 1 GB (the per-agent alert threshold inside
  `BrowserHealthMonitorExtension.report_browser_metrics`,
  `backend/core/agent_health_monitor.py:667`).
- *Per-agent table* — one row per
  `browser_health.agents[<agent>]`: `active_contexts`,
  `context_memory_mb`, `page_load_time_ms`, `screenshot_time_ms`,
  `browser_error_rate`, `browser_health_score`.
- *Health score histogram* — distribution of
  `browser_health_score` across agents. Pages on-call when any agent
  drops below 40 (matches the existing in-process critical alert
  emitted by the health monitor).

**Metrics read.**

`browser.openclaw`, `browser.pinchtab`, `browser.reasons`,
`browser_health.summary.total_active_contexts`,
`browser_health.summary.total_browser_memory_mb`,
`browser_health.summary.avg_browser_health_score`,
`browser_health.summary.browser_alerts`,
`browser_health.agents[*].context_memory_mb`,
`browser_health.agents[*].page_load_time_ms`,
`browser_health.agents[*].screenshot_time_ms`,
`browser_health.agents[*].browser_error_rate`,
`browser_health.agents[*].browser_health_score`.

**Alert thresholds.**

| Metric                                                | Warning      | Critical |
| ----------------------------------------------------- | ------------ | -------- |
| `browser_health.summary.avg_browser_health_score`     | `< 70`       | `< 40`   |
| `browser_health.summary.total_browser_memory_mb`      | `> 1024`     | `> 4096` |
| Per-agent `context_memory_mb` growth                  | `> 100 MB/h` | —        |
| Per-agent `browser_health_score`                      | `< 70`       | `< 40`   |
| `browser.openclaw` or `browser.pinchtab` `unavailable`| any          | both     |

> See [§2.4 Browser memory leak](#24-browser-memory-leak--warning),
> [§2.5 Browser engine offline](#25-browser-engine-offline--warning--page),
> and [§2.6 Browser health score critical](#26-browser-health-score-critical--page)
> for runbook details.

---

## §2 Alert Rules

> Plain-text rule list, deliberately not a monitoring-tool DSL. Translate
> these into your alerting backend (Prometheus / OpenSearch / Datadog /
> CloudWatch — whatever you run). Every rule cites the metric source so
> the translation is mechanical.

### Conventions

- All metrics come from `GET /api/integration/metrics` and
  `GET /api/runtime/health` (see [`API.md`](API.md) §17a).
- "5 min sustained" means the rule must hold for five consecutive
  one-minute windows before the alert fires. This eats brief spikes
  during cohort bumps and dependency restarts.
- Severities:
  - **page** — wakes the on-call rotation. Reserved for production
    impact.
  - **warning** — chat / email. The next business day is fine unless it
    escalates.
- Cumulative counters (`circuit_breaker_trips`, `events_failed`) reset
  on backend restart. Compare against the per-window delta, not the
  raw value, in your alerting backend.

### 2.1 High failure rate — page

- **Source.** `integration.events_failed`, `integration.events_processed`
  from `/api/integration/metrics`.
- **Condition.**
  `events_failed / max(events_processed, 1) > 0.10`
  sustained for 5 min.
- **Severity.** page on-call.
- **Why.** A 10 % failure rate over five minutes means the coordinator
  is steadily dropping cross-system signals. Past the circuit-breaker
  threshold this becomes self-correcting; below it, signals are lost
  silently.
- **Dashboard.** See [§1.1 Integration Health](#11-integration-health)
  *Failure rate* panel.
- **Runbook.** [`runbooks/integration_ops.md`](../runbooks/integration_ops.md)
  §2.1 (circuit breaker tripped) — same root causes apply even when the
  breaker has not yet fired.

### 2.2 Circuit breaker tripped — warning

- **Source.** `integration.circuit_breaker_trips` from
  `/api/integration/metrics`.
- **Condition.** Any positive delta. Cumulative counter; alert on
  *change*, not absolute value.
- **Severity.** warning.
- **Why.** A trip means the coordinator opened a breaker for at least
  60 s (the default `circuit_breaker_timeout_s`), so cross-system
  learning was paused. Investigate the dependency named in the log
  line (`browser_vulnerability_learning` or `discovery_learning`).
- **Dashboard.** See [§1.1 Integration Health](#11-integration-health)
  *Circuit breaker trips* panel.
- **Runbook.** [`runbooks/integration_ops.md`](../runbooks/integration_ops.md)
  §2.1.

### 2.3 Slow skill search — warning

- **Source.** `performance.skill_search_latency_ms.p99` from
  `/api/integration/metrics` (`performance_optimizer.get_performance_report()`).
- **Condition.** `p99 > 50 ms` sustained for 10 min.
- **Severity.** warning.
- **Why.** The skill library promised O(1) lookups via the capability /
  context / framework indexes. A p99 above 50 ms means an index has
  been bypassed or the library has grown past the cache budget.
- **Dashboard.** See [§1.2 Learning Performance](#12-learning-performance)
  *Skill search latency p50/p99* panel.
- **Runbook.** Run `/api/skills/reload`. If the latency does not return
  to baseline within five minutes, drop the rollout for
  `skill_library_v2` to 0 in `config/integration.yaml` and restart.

### 2.4 Browser memory leak — warning

- **Source.** `browser_health.agents[<agent>].context_memory_mb`
  from `/api/runtime/health`.
- **Condition.** Per-agent `context_memory_mb` increases by more than
  100 MB over any rolling 60 min window without a corresponding
  increase in `active_contexts`.
- **Severity.** warning.
- **Why.** Steady memory growth without context growth is the
  signature of leaked browser contexts that
  `BrowserHealthMonitorExtension` couldn't reclaim. The healing engine
  will eventually close idle contexts (`heal_browser_memory`), but a
  sustained leak indicates the trigger isn't firing.
- **Dashboard.** See [§1.4 Browser Health](#14-browser-health-new)
  *Per-agent table* and *Browser memory* panels.
- **Runbook.** Confirm with the per-agent table on the Browser Health
  dashboard. If a single agent is the leaker, restart that agent's
  worker; if it's spread across agents, restart the backend. File a
  ticket if the pattern repeats within the same week — that's an
  upstream bug in `recovery_engine.heal_browser_memory`.

### Companion rules (optional)

These are not required by the spec but follow naturally from the
existing health-monitor outputs and pair well with the four above.

### 2.5 Browser engine offline — warning / page

- **Source.** `browser.openclaw`, `browser.pinchtab` from
  `/api/runtime/health`.
- **Condition.**
  - One engine `unavailable` → warning.
  - Both engines `unavailable` → page (browser stack is gone, recon
    falls back to HTTP probes only).
- **Dashboard.** See [§1.4 Browser Health](#14-browser-health-new)
  *Engine status* panel.

### 2.6 Browser health score critical — page

- **Source.** `browser_health.agents[<agent>].browser_health_score`.
- **Condition.** Any agent's score drops below 40.
- **Severity.** page.
- **Why.** Mirrors the in-process critical alert at
  `backend/core/agent_health_monitor.py:651`. The coordinator's
  recovery path takes time — paging keeps a human in the loop while
  the healing engine does its work.
- **Dashboard.** See [§1.4 Browser Health](#14-browser-health-new)
  *Health score histogram* panel.

### 2.7 Discovery batch saturated — warning

- **Source.** `integration.pending_discoveries`,
  `integration.last_batch_size` (compared to
  `IntegrationConfig.event_batch_size`).
- **Condition.** `pending_discoveries == event_batch_size` and
  `batches_flushed` does not advance for 60 s.
- **Severity.** warning.
- **Why.** The drain task has stalled.
- **Dashboard.** See [§1.1 Integration Health](#11-integration-health)
  *Discovery batch backlog* panel.
- **Runbook.** [`runbooks/integration_ops.md`](../runbooks/integration_ops.md)
  §2.2.

---

## §3 Metrics Reference

Consolidated table of every metric referenced in the dashboards and alert
rules above. All are read-only; there is no write API for metrics.

| Metric | Source Endpoint | Used By | Type |
| ------ | --------------- | ------- | ---- |
| `integration.events_processed` | `/api/integration/metrics` | [§1.1](#11-integration-health), [§2.1](#21-high-failure-rate--page) | counter |
| `integration.events_failed` | `/api/integration/metrics` | [§1.1](#11-integration-health), [§2.1](#21-high-failure-rate--page) | counter |
| `integration.events_skipped` | `/api/integration/metrics` | [§1.1](#11-integration-health) | counter |
| `integration.failure_rate` | `/api/integration/metrics` | [§1.1](#11-integration-health) | gauge |
| `integration.circuit_breaker_trips` | `/api/integration/metrics` | [§1.1](#11-integration-health), [§2.2](#22-circuit-breaker-tripped--warning) | counter |
| `integration.pending_discoveries` | `/api/integration/metrics` | [§1.1](#11-integration-health), [§2.7](#27-discovery-batch-saturated--warning) | gauge |
| `integration.batches_flushed` | `/api/integration/metrics` | [§1.1](#11-integration-health), [§2.7](#27-discovery-batch-saturated--warning) | counter |
| `integration.last_batch_size` | `/api/integration/metrics` | [§1.1](#11-integration-health), [§2.7](#27-discovery-batch-saturated--warning) | gauge |
| `integration.features_enabled` | `/api/integration/metrics` | [§1.1](#11-integration-health) | map |
| `learning.total_patterns` | `/api/integration/metrics` | [§1.2](#12-learning-performance) | gauge |
| `learning.http_patterns` | `/api/integration/metrics` | [§1.2](#12-learning-performance) | gauge |
| `learning.browser_patterns` | `/api/integration/metrics` | [§1.2](#12-learning-performance) | gauge |
| `performance.skill_search_latency_ms.p50` | `/api/integration/metrics` | [§1.2](#12-learning-performance) | gauge |
| `performance.skill_search_latency_ms.p99` | `/api/integration/metrics` | [§1.2](#12-learning-performance), [§2.3](#23-slow-skill-search--warning) | gauge |
| `skills.total_skills` | `/api/integration/metrics` | [§1.3](#13-skill-library) | gauge |
| `skills.http_skills` | `/api/integration/metrics` | [§1.3](#13-skill-library) | gauge |
| `skills.browser_skills` | `/api/integration/metrics` | [§1.3](#13-skill-library) | gauge |
| `skills.hybrid_skills` | `/api/integration/metrics` | [§1.3](#13-skill-library) | gauge |
| `skills.acquisition_rate` | `/api/integration/metrics` | [§1.3](#13-skill-library) | gauge |
| `browser.openclaw` | `/api/runtime/health` | [§1.4](#14-browser-health-new), [§2.5](#25-browser-engine-offline--warning--page) | status |
| `browser.pinchtab` | `/api/runtime/health` | [§1.4](#14-browser-health-new), [§2.5](#25-browser-engine-offline--warning--page) | status |
| `browser.reasons` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | list |
| `browser_health.summary.total_active_contexts` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | gauge |
| `browser_health.summary.total_browser_memory_mb` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | gauge |
| `browser_health.summary.avg_browser_health_score` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | gauge |
| `browser_health.summary.browser_alerts` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | list |
| `browser_health.agents[*].context_memory_mb` | `/api/runtime/health` | [§1.4](#14-browser-health-new), [§2.4](#24-browser-memory-leak--warning) | gauge |
| `browser_health.agents[*].active_contexts` | `/api/runtime/health` | [§1.4](#14-browser-health-new), [§2.4](#24-browser-memory-leak--warning) | gauge |
| `browser_health.agents[*].page_load_time_ms` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | gauge |
| `browser_health.agents[*].screenshot_time_ms` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | gauge |
| `browser_health.agents[*].browser_error_rate` | `/api/runtime/health` | [§1.4](#14-browser-health-new) | gauge |
| `browser_health.agents[*].browser_health_score` | `/api/runtime/health` | [§1.4](#14-browser-health-new), [§2.6](#26-browser-health-score-critical--page) | gauge |

---

## Cross-references

| Document | Relevance |
| -------- | --------- |
| [`API.md`](API.md) §17a | Endpoint schemas for `/api/integration/metrics` and `/api/runtime/health` |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System component diagram; coordinator, performance optimizer, browser health monitor |
| [`runbooks/integration_ops.md`](../runbooks/integration_ops.md) | Step-by-step incident response for alert rules §2.1, §2.2, §2.7 |
| `config/integration.yaml` | Feature flags, rollout percentages, `event_batch_size`, `circuit_breaker_timeout_s` |

---

<sub>
Auto-generated by merging <code>alerts.md</code> and <code>dashboards.md</code>.<br>
Last updated: 2026-06-26 · Vigilagent Deep System Integration
</sub>
