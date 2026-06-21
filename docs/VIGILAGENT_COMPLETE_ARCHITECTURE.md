# Vigilagent Complete Architecture

## 1. Product Definition

Vigilagent is an authorized autonomous security assessment platform. Its purpose is to perform real reconnaissance, validation, evidence collection, risk analysis, remediation planning, and operator-supervised security testing against explicitly approved targets.

The system must be powerful enough to operate like a senior penetration-testing team, but it must remain governed by scope, budget, approvals, audit logs, and evidence rules. Vigilagent is not designed for unauthorized access, stealthy persistence, destructive operations, or unsanctioned lateral movement.

## 2. Core Principles

1. Scope is law.
   Every network request, browser action, command execution, tool run, and extension-captured event must pass scope validation before execution or ingestion.

2. Evidence before claims.
   Findings are not accepted because an agent predicted them. A finding becomes valid only after differential evidence, repeatable behavior, and confidence scoring.

3. Real tools, controlled execution.
   Recon and validation use real CLI tools through a governed Terminal Engine, preferably Docker-isolated, with command allowlists and output parsing.

4. Hierarchical agents, not broadcast chaos.
   Omega remains the campaign commander, but specialized child agents run with isolated memory, limited toolsets, and explicit iteration budgets.

5. Two LLMs only.
   Vigilagent uses only:
   - OpenRouter `openai/gpt-oss-20b` for high-level reasoning, arbitration, planning, and report synthesis.
   - Gemini `gemini-2.5-flash` for fast tactical reasoning, payload ideation for authorized validation, summarization, and context compression.

6. Hybrid by design.
   The platform works with or without the browser extension. The extension is a session and telemetry bridge, not the core engine.

7. Self-awareness must act.
   Health, performance, cost, tool reliability, false positives, and stuck states must feed back into routing, retries, fallback choices, and campaign planning.

## 3. High-Level Architecture

```text
Vigilagent
|
+-- Operator Interface
|   +-- Web dashboard
|   +-- Scan configuration
|   +-- Approval queue
|   +-- Reports and live evidence feed
|
+-- API Gateway
|   +-- FastAPI REST endpoints
|   +-- WebSocket event stream
|   +-- Extension bridge API
|   +-- Auth, rate limit, scope validation
|
+-- Command Center
|   +-- Omega campaign commander
|   +-- Planner
|   +-- Delegation manager
|   +-- Master/worker scheduler
|   +-- Phase gate
|
+-- Agent Army
|   +-- Recon team
|   +-- Web validation team
|   +-- API validation team
|   +-- Browser team
|   +-- Network service team
|   +-- Verification team
|   +-- Reporting team
|
+-- Execution Engines
|   +-- Terminal Engine
|   +-- Docker Sandbox
|   +-- Browser Orchestrator
|   +-- HTTP Client
|   +-- Recon Command Runner
|
+-- Intelligence Layer
|   +-- Cortex LLM Router
|   +-- Knowledge graph
|   +-- Learning engine
|   +-- Skill library
|   +-- Context compressor
|   +-- Credential/session vault for authorized test credentials
|
+-- Governance Layer
|   +-- Scope policy
|   +-- Approval gates
|   +-- Iteration budget
|   +-- Command guardrails
|   +-- Audit logger
|   +-- Evidence chain of custody
|
+-- Storage
    +-- SQLite/local state
    +-- Supabase optional persistence
    +-- Artifact store
    +-- Reports
    +-- Encrypted evidence
```

## 4. Runtime Modes

### 4.1 Standalone Backend Mode

This is the default mode. The operator provides target scope, credentials if needed, scan mode, budgets, and authorization metadata through the dashboard or API.

Flow:

1. Operator creates a scan.
2. Scope policy is compiled.
3. Omega creates a campaign plan.
4. Recon team runs approved passive and active tools.
5. Knowledge graph is populated.
6. Planner selects validation paths.
7. Validation agents run governed checks.
8. Gamma verifies findings.
9. Reporting engine emits PDF, JSON, SARIF, HackerOne markdown, and graph exports.

### 4.2 Browser Extension Hybrid Mode

The extension is optional and passive-first. It improves authenticated web testing by sharing browser-observed context with the backend.

Extension captures only in-scope data:

- Cookies and session metadata where permitted by operator configuration.
- Auth headers and tokens visible to the browser context.
- XHR/fetch request metadata.
- WebSocket metadata.
- DOM snapshots.
- CSP and security headers.
- Forms, routes, and client-side paths.

The extension does not independently exploit targets. It sends observations to the backend, receives approved instructions, and displays scan status.

### 4.3 Cluster Mode

Master/worker mode is used for large scans.

Master responsibilities:

- Own scan state.
- Assign work packets.
- Enforce global budget.
- Track worker health.
- Deduplicate work.
- Aggregate results.

Worker responsibilities:

- Execute bounded task packets.
- Run assigned tools.
- Emit structured events.
- Return artifacts and parsed findings.
- Heartbeat and self-report health.

Specialized worker roles:

- `recon`
- `browser`
- `validation`
- `reporting`
- `hybrid`

## 5. Agent Hierarchy

```text
Omega Campaign Commander
|
+-- Recon Commander
|   +-- Passive Recon Agent
|   +-- DNS/Infrastructure Agent
|   +-- HTTP Surface Agent
|   +-- API Discovery Agent
|   +-- Visual Recon Agent
|
+-- Validation Commander
|   +-- SQLi Validation Agent
|   +-- Auth Validation Agent
|   +-- IDOR Validation Agent
|   +-- XSS/Client-Side Validation Agent
|   +-- Logic Validation Agent
|
+-- Browser Commander
|   +-- OpenClaw Agent
|   +-- PinchTab Agent
|   +-- Extension Bridge Agent
|
+-- Network Service Commander
|   +-- Port Scanner Agent
|   +-- TLS Analyzer Agent
|   +-- Service Fingerprint Agent
|
+-- Verification Commander
|   +-- Gamma Evidence Auditor
|   +-- Differential Analyzer
|   +-- False Positive Filter
|
+-- Reporting Commander
    +-- Executive Summary Agent
    +-- Technical Report Agent
    +-- Remediation Agent
    +-- Export Agent
```

Each child agent receives:

- Isolated memory.
- Tool allowlist.
- Iteration budget.
- Scope policy.
- Phase permission.
- Parent context summary.
- Structured output contract.

No child agent receives unrestricted global memory or unrestricted terminal access.

## 5.1 Current Agent Upgrade Map

Vigilagent should use every agent that already exists in the project. The goal is not to replace the swarm, but to make each agent more capable, more honest, and better connected.

| Current Agent | Current Role | Upgraded Vigilagent Role |
| --- | --- | --- |
| Alpha / Alpha V6 | Recon and surface discovery | Recon Commander. Runs the full real-tool recon pipeline, normalizes results, updates graph, and produces attack-surface intelligence. |
| Beta | Payload execution and mutation | Controlled Exploit Validator. Delivers payloads across query, body, header, cookie, path, browser, and API vectors under approval and scope. |
| Gamma | Forensic audit and anomaly verification | Evidence Auditor. Confirms findings using differential analysis, repeatability, timing, DOM, structural changes, and false-positive filtering. |
| Omega | Strategy and campaign coordination | Campaign Commander. Plans phases, spawns child agents, assigns budgets, adapts strategy from graph evidence, and stops unsafe paths. |
| Sigma | Arsenal/module orchestration | Tool and Technique Commander. Chooses modules, invokes Terminal Engine tools, maps vulnerabilities to validation strategies, and chains approved steps. |
| Kappa | Semantic memory | Tactical Memory Agent. Stores reusable lessons, token/session context, target patterns, and compressed scan memory. |
| Zeta | QoS/rate governance | Runtime Governor. Controls RPS, concurrency, backoff, WAF pressure, error budgets, and scan pacing. |
| Delta | Browser controller | Browser Operations Agent. Drives OpenClaw and PinchTab, extracts runtime state, handles forms, captures browser evidence, and syncs extension context. |
| Chi | Event interception and dark-pattern/timing detection | Traffic Intelligence Agent. Watches XHR, fetch, WebSocket, timing, redirect, and side-channel behavior. |
| Prism | DOM analysis and prompt-injection defense | Client-Side Intelligence Agent. Maps DOM, shadow DOM, forms, scripts, hidden inputs, routes, CSP, and client-side injection surfaces. |
| Lambda | Source/code scanner | Defensive Code Intelligence Agent. Runs SAST-style checks where source is available and links code risks to runtime findings. |
| Master | Distributed coordination | Cluster Commander. Owns global scan state, queue, budgets, dedupe, worker health, and result aggregation. |
| Worker | Distributed execution | Specialized Executor. Runs bounded recon, browser, validation, reporting, or hybrid tasks with heartbeats and scoped tool access. |

## 5.1.1 Alpha And Alpha V6 Merge

Alpha and Alpha V6 should become one unified agent family instead of two competing paths.

Target name:

```text
Alpha 
```

Merge rule:

- Keep Alpha V6 as the runtime spine because it already has phase control, parsers, entity ingestion, artifacts, scoring, dedupe, live feed, and scope gates.
- Move useful legacy Alpha behaviors into Alpha V6 as modules, adapters, or strategy plugins.
- Do not keep two separate recon orchestration paths.
- Do not duplicate parser registries.
- Do not duplicate artifact storage.
- Do not duplicate endpoint scoring.

Alpha Unified responsibilities:

- Run passive recon.
- Run active recon.
- Run LAN/private-scope discovery when explicitly authorized.
- Run browser-aware recon through Delta, Prism, Chi, OpenClaw, PinchTab, and the extension bridge.
- Run API/schema discovery.
- Normalize every output into graph entities.
- Emit live events.
- Produce recon confidence scores.
- Hand validated surface data to Omega and Sigma.

Alpha should not be artificially limited to toy behavior. It should run real tools and collect real evidence in authorized scope. Its limits should come from scope, scan mode, rate limits, approvals, and sandbox policy rather than hardcoded localhost-only behavior.

## 5.1.2 Master And Worker As Subagents

Master and worker files should not be treated as separate infrastructure only. They should function as operational subagents that help every agent scale.

Master becomes:

```text
Master Coordination Subagent
```

Master responsibilities:

- Own the global campaign queue.
- Track all child agents.
- Assign work to workers.
- Enforce global budget.
- Enforce phase gates.
- Deduplicate tasks.
- Track tool and worker health.
- Rebalance failed tasks.
- Aggregate results.
- Persist checkpoints.

Worker becomes:

```text
Worker Execution Subagent
```

Worker responsibilities:

- Receive one bounded task packet.
- Load only the required tools and memory.
- Execute recon, browser, validation, analysis, or reporting work.
- Stream progress.
- Return structured results and artifacts.
- Report heartbeat and resource usage.
- Stop immediately when scope, phase, or budget is violated.

Worker specialties:

- `worker.recon`
- `worker.browser`
- `worker.api`
- `worker.network`
- `worker.validation`
- `worker.forensics`
- `worker.reporting`
- `worker.skill`
- `worker.hybrid`

Routing pattern:

```text
Omega -> Master -> Worker pool -> Specialized agent/task -> Parsed result -> Master -> Omega/Graph
```

This allows agents to use workers as subagents without each agent inventing its own threading, subprocess, or queue model.

## 5.2 Advanced Agent Responsibilities

Alpha must remain the source of truth for real reconnaissance. It should run real tools, parse real output, and feed the graph. It should not simply produce text plans.

Beta must stop being only a query-string payload sender. It should use a Payload Delivery Engine that supports:

- Query parameters.
- JSON bodies.
- Form bodies.
- Multipart uploads where explicitly approved.
- Headers.
- Cookies.
- Path segments.
- Browser form submission.
- WebSocket messages where in scope.
- GraphQL variables and operation names where detected.

Gamma must be the final truth filter for vulnerabilities. It should reject claims that do not have enough independent evidence.

Omega must not randomly choose strategy. It should read graph state, tool results, scope, budget, WAF signals, and confirmed findings before selecting the next step.

Sigma must become the bridge between technique and tooling. It should decide whether a built-in module, browser action, or CLI tool is the right controlled validation path.

Kappa must not be passive storage only. It should provide recommendations to Omega and Sigma before planning and when the scan is stuck.

Zeta must actively slow down, pause, or reroute work when the target becomes unstable, starts returning 429/403/5xx bursts, or the scan approaches limits.

Delta, Chi, and Prism together form the browser intelligence team. They make Vigilagent capable of working with modern JavaScript apps, SPAs, session-heavy workflows, hidden routes, dynamic DOM changes, and browser-only security states.

Lambda should connect static code risk to runtime behavior. If source code shows a dangerous route, Alpha and Beta should prioritize runtime validation for that endpoint.

## 5.3 Skill Architecture From Anthropic-Cybersecurity-Skills

Vigilagent should ingest `D:\projects\Anthropic-Cybersecurity-Skills` as a first-class skill and playbook library.

The skills should not be copied blindly into agent prompts. They should be indexed, categorized, mapped to agents, mapped to ATT&CK/OWASP/NIST where available, and executed only through the same scope, sandbox, approval, budget, and evidence controls as every other capability.

Skill source:

```text
D:\projects\Anthropic-Cybersecurity-Skills
```

Important source folders:

- `skills/`
- `mappings/`
- `tools/`
- `assets/`
- `index.json`
- `ATTACK_COVERAGE.md`

### 5.3.1 Skill Ingestion Pipeline

```text
Skill repository
-> Skill scanner
-> Metadata extractor
-> Category classifier
-> Safety/risk classifier
-> Agent mapper
-> Tool dependency resolver
-> Prompt/playbook compiler
-> Skill registry
-> Runtime skill executor
```

Extract from every skill:

- Skill name.
- Goal.
- Domain.
- Required tools.
- Required files.
- Inputs.
- Outputs.
- Risk level.
- Whether it is offensive, defensive, forensic, detection, remediation, or reporting.
- Whether it requires network access.
- Whether it changes remote state.
- Whether it requires explicit approval.
- ATT&CK/OWASP/NIST mappings where present.

### 5.3.2 Skill Categories

The imported skills should be grouped into these Vigilagent domains:

| Skill Domain | Examples | Primary Agent |
| --- | --- | --- |
| Web/API testing | API auth, BOLA, mass assignment, XSS, XXE, CORS, host header, WebSocket, GraphQL | Sigma, Beta, Gamma, Prism |
| Recon and network assessment | OSINT, subfinder, nmap, DNS enumeration, TLS assessment, wireless assessment | Alpha, Network Commander |
| Active Directory assessment | BloodHound, Kerberoasting, ADCS ESC1, ACL abuse, DCSync detection/assessment | Network Commander, Sigma, Gamma |
| Cloud assessment | AWS, Azure, GCP, Kubernetes, IAM, S3, GuardDuty, CloudTrail | Cloud Skill Worker, Lambda, Gamma |
| Container and Kubernetes | Trivy, Grype, kube-bench, kubesec, RBAC, runtime drift, Falco | Lambda, Worker.skill, Gamma |
| Mobile assessment | Android, iOS, Frida, Objection, JADX, MobSF, mobile API auth | Delta, Prism, Sigma |
| Malware and reverse engineering | Ghidra, JADX, dnSpy, Volatility, Cuckoo, YARA, PDF/macro analysis | Lambda, Forensics Worker |
| Forensics and incident response | Disk, memory, logs, MFT, registry, Prefetch, Zeek, Splunk, Timesketch | Gamma, Forensics Worker |
| Detection engineering | Sigma rules, Splunk SPL, Suricata/Snort, MITRE mapping, SIEM tuning | Lambda, Reporting Commander |
| Threat intelligence | MISP, OpenCTI, STIX/TAXII, IOC enrichment, actor profiling | Kappa, Reporting Commander |
| Hardening and remediation | Zero trust, IAM, Kubernetes, Docker, WAF, TLS, endpoint hardening | Lambda, Remediation Agent |
| Reporting and governance | CVSS, SSVC, SLA, compliance, exception tracking, dashboards | Reporting Commander |

### 5.3.3 Offensive Skill Risk Model

Some skills describe real offensive techniques. Vigilagent can use them as authorized validation playbooks, but each skill must be assigned a risk class.

Risk classes:

- `analysis_only`: read artifacts, logs, code, packets, or reports.
- `passive_recon`: OSINT and public data collection.
- `active_recon`: in-scope probing and scanning.
- `controlled_validation`: bounded proof of vulnerability with non-destructive payloads.
- `intrusive_validation`: higher-risk validation requiring explicit approval.
- `disabled_by_default`: persistence, stealth, destructive, credential theft, malware deployment, or out-of-scope lateral movement.

Sandboxing is required for tool safety, reproducibility, and dependency isolation. Sandboxing is not a substitute for authorization. The architecture should not include unrestricted exploitation against arbitrary systems.

### 5.3.4 Skill Runtime Contract

Every skill execution must produce structured output:

```json
{
  "skill_id": "testing-api-for-broken-object-level-authorization",
  "agent": "Sigma",
  "risk_class": "controlled_validation",
  "scope_decision": "allowed",
  "approval_id": "APR-...",
  "inputs": {},
  "tool_runs": [],
  "evidence_ids": [],
  "findings": [],
  "confidence": 0.0,
  "recommendations": [],
  "next_actions": []
}
```

### 5.3.5 Agent Skill Routing

Skill routing rules:

- Alpha receives recon, OSINT, DNS, TLS, network scanning, asset discovery, and inventory skills.
- Beta receives controlled payload-delivery and validation skills.
- Gamma receives verification, forensic analysis, incident reconstruction, and false-positive reduction skills.
- Omega receives campaign, red-team planning, kill-chain modeling, and ATT&CK mapping skills.
- Sigma receives web/API/AD/cloud technique selection and tool orchestration skills.
- Kappa receives CTI, IOC enrichment, memory, actor profiling, and pattern library skills.
- Zeta receives rate limiting, anomaly detection, detection-of-scan, WAF pressure, and runtime governance skills.
- Delta receives browser, mobile, session, and dynamic interaction skills.
- Chi receives traffic analysis, WebSocket, XHR/fetch, timing, and side-channel skills.
- Prism receives DOM, JavaScript, CSP, XSS, client-side route, and prompt-injection skills.
- Lambda receives SAST, IaC, SBOM, cloud config, container, Kubernetes, and remediation skills.
- Master routes skill tasks to workers.
- Workers execute bounded skill jobs and return structured artifacts.

### 5.3.6 Skill Registry Design

Recommended registry:

```text
backend/skills/
+-- catalog.py
+-- loader.py
+-- classifier.py
+-- mapper.py
+-- executor.py
+-- policy.py
```

Registry features:

- Load `index.json`.
- Scan every `skills/*/SKILL.md`.
- Store normalized metadata.
- Validate skill format using the source repo validation tool.
- Map skill to agent and risk class.
- Map skill to required tools.
- Generate LLM prompt snippets only at runtime.
- Cache compiled skill metadata.
- Keep source skill files read-only.

## 5.4 Hermes-Agent Architecture Adoption

Vigilagent should adopt Hermes-agent patterns from `D:\projects\hermes-agent` where they improve reliability and autonomy.

Adopt:

- Hierarchical delegation.
- Isolated child-agent memory.
- Tool registry with cleaner discovery.
- Iteration budgets.
- Context compression.
- Terminal execution with streaming.
- Background task lifecycle management.
- Checkpoint/resume.
- Guarded command execution.
- Structured tool results.
- SQLite WAL state with FTS search.
- Session/scan handoff chains.
- Memory provider fencing.
- Streaming memory-context scrubbing.
- Skill preprocessing with template variables.
- Tool availability checks with caching.
- Concurrent tool dispatch with ordered result collection.
- Pre-tool checkpoints for risky mutations.

Do not adopt blindly:

- General-purpose coding assumptions that conflict with security evidence workflows.
- Any unrestricted tool execution path.
- Any memory sharing pattern that leaks untrusted target content into agent control prompts.

Vigilagent should be Hermes-like in orchestration quality, but specialized for authorized security assessment, evidence handling, scope enforcement, browser automation, recon parsing, and reporting.

## 5.5 Event Bus Replacement Plan

The current flat EventBus model is useful for broadcasting UI updates, but it should not be the main agent coordination model.

Problem with the current event bus:

- Every agent can hear broad events.
- Parent/child ownership is weak.
- Memory isolation is weak.
- Results are harder to aggregate.
- Budgets are not naturally enforced.
- Complex workflows become reactive instead of planned.
- Agents can duplicate work.

Vigilagent should replace the event bus as the primary control plane with Hermes-style task delegation.

New control plane:

```text
CampaignPlan
-> TaskGraph
-> Master queue
-> DelegationManager
-> Child agent / Worker subagent
-> StructuredResult
-> Verifier
-> KnowledgeGraph
-> Planner
```

What remains event-based:

- UI updates.
- WebSocket live feed.
- Audit log emission.
- Tool progress notifications.
- Worker heartbeat.
- Approval status changes.

What moves out of event bus:

- Agent-to-agent task assignment.
- Campaign planning.
- Exploit validation flow.
- Recon phase sequencing.
- Result ownership.
- Retry decisions.
- Skill execution lifecycle.

Replacement components:

- `TaskGraph`: durable DAG of scan work.
- `DelegationManager`: spawns child agents with isolated context.
- `ScanBudget`: parent and child budget tracking.
- `WorkerLease`: bounded task ownership.
- `ResultPacket`: structured child-agent return object.
- `ScanStateDB`: SQLite-backed durable state.
- `KnowledgeGraph`: long-term reasoning state.

Every agent action should have one owner, one task ID, one budget, one scope policy, one result contract, and one audit trail.

## 5.6 Hermes-State Pattern For Vigilagent

Hermes uses durable SQLite state with WAL, FTS search, schema versioning, session lineage, and jittered retries. Vigilagent should adapt that model for scans.

Vigilagent scan state tables:

- `scans`
- `scan_sessions`
- `tasks`
- `task_attempts`
- `agent_runs`
- `tool_runs`
- `messages`
- `events`
- `approvals`
- `findings`
- `evidence`
- `skills`
- `skill_runs`
- `learning_updates`
- `graph_nodes`
- `graph_edges`
- `checkpoints`

Required state features:

- WAL mode where supported.
- Fallback journal mode where WAL fails.
- Schema version table.
- FTS search over messages, tool output summaries, findings, and evidence descriptions.
- Parent scan/session chains after compression or resume.
- Jittered write retry to avoid lock convoys.
- Periodic checkpoint and maintenance.
- Durable task leases so workers can resume or reassign work after crash.

This replaces fragile JSON-only scan memory for anything that affects execution.

## 6. Existing Components To Preserve

The current project already has valuable foundations and should not be rewritten blindly.

Keep and strengthen:

- Alpha V6 recon pipeline.
- Recon parsers.
- Entity engine and dedupe.
- Forensic collector.
- Browser orchestrator.
- PinchTab/OpenClaw split.
- Guard layer.
- Content boundary.
- Scope policy.
- Approval system.
- Phase gate.
- Reporting engine.
- SARIF/HackerOne exports.
- WebSocket live feed.
- Self-healing and self-awareness modules.
- Master/worker files under `backend/core/cluster`.

Refactor only where necessary to connect these systems into one coherent runtime.

## 7. Recon Tool Architecture

Recon tools are discovered from `D:\projects` and represented through the existing Alpha V6 recon registry.

Primary recon tools:

- `subfinder`
- `amass`
- `gau`
- `waybackurls`
- `cloudlist`
- `spiderfoot`
- `dnsx`
- `shuffledns`
- `naabu`
- `nmap`
- `tlsx`
- `httpx`
- `katana`
- `hakrawler`
- `LinkFinder`
- `SecretFinder`
- `feroxbuster`
- `ffuf`
- `dirsearch`
- `gobuster`
- `kiterunner`
- `inql`
- `gowitness`
- `nuclei`
- `interactsh`

Additional supporting directories:

- `SecLists`
- `wordlists`
- `PayloadsAllTheThings`
- `graphql-voyager`
- `openclaw`
- `pinchtab_core`
- `playwright`
- `selenium`

Tool execution rules:

1. Prefer argv-based execution over shell strings.
2. Resolve binaries from PATH first, then `D:\projects`.
3. Docker execution is preferred for Linux-native tools when running on Windows.
4. Every command must have timeout, output cap, artifact path, parser hint, and scan ID.
5. Tool output is parsed into typed entities before it enters the knowledge graph.

## 8. Terminal Engine

The Terminal Engine is the governed bridge between agents and real CLI tools.

Responsibilities:

- Execute local commands where safe.
- Execute Docker-isolated commands by default for toolchains that benefit from Linux.
- Support timeouts and no-output watchdogs.
- Stream output to WebSocket.
- Capture stdout, stderr, exit code, duration, hash, and truncation status.
- Enforce command allowlists.
- Enforce scope extraction from command arguments.
- Require approval for risky or state-changing actions.
- Store command artifacts under scan-specific directories.

Execution pipeline:

```text
Agent tool request
-> Tool registry
-> Iteration budget consume
-> Command guard
-> Scope policy
-> Approval gate
-> Terminal Engine
-> Docker/local backend
-> Output watchdog
-> Parser
-> Evidence store
-> Knowledge graph
-> Event stream
```

## 9. Governance And Safety

Vigilagent must support real authorized security testing, but it must not become an unrestricted attack system.

Mandatory gates:

- Scope file required for all non-local scans.
- Explicit authorization flag required for active testing.
- Approval required for state-changing HTTP methods unless pre-approved in scan policy.
- Approval required for credential attacks, intrusive scans, destructive checks, or exploit replay.
- No persistence, log wiping, malware deployment, or covert access modules.
- No action outside target scope, even if discovered during recon.
- Private network scanning disabled unless explicitly included in scope.
- Every command and request is audit logged.

Risk levels:

- Passive: public data gathering, no target traffic or minimal target traffic.
- Standard: normal authenticated/unauthenticated web and service assessment.
- Aggressive: heavier recon, template validation, fuzzing within rate limits.
- Intrusive: disabled by default, requires explicit human approval per action.

## 10. Scope Model

Scope policy should support:

- Allowed domains.
- Allowed hosts.
- Allowed CIDRs.
- Allowed URL globs.
- Denied hosts.
- Denied URL globs.
- Allowed ports.
- Scan time windows.
- Max requests per second.
- Max concurrency.
- Active testing authorization flag.
- Extension capture allowlist.

Example:

```yaml
engagement:
  name: authorized-client-test
  authorization: explicit
  starts_at: 2026-05-29T00:00:00Z
  ends_at: 2026-06-05T00:00:00Z

scope:
  allowed_hosts:
    - example.com
    - api.example.com
  allowed_url_globs:
    - https://example.com/*
    - https://api.example.com/*
  denied_url_globs:
    - "*://*/logout"
    - "*://*/delete*"
  allow_private_networks: false

limits:
  max_rps: 25
  max_concurrency: 8
  max_runtime_minutes: 120
```

## 11. LLM Architecture

Only two external LLMs are allowed.

### 11.1 OpenRouter GPT OSS 20B

Model:

- `openai/gpt-oss-20b`

Responsibilities:

- Campaign planning.
- Final arbitration.
- Strategy reasoning.
- Report synthesis.
- Remediation explanation.
- High-level decision review.

### 11.2 Gemini 2.5 Flash

Model:

- `gemini-2.5-flash`

Responsibilities:

- Fast tactical reasoning.
- Context compression.
- Payload variant ideation for authorized validation.
- Summarization.
- Evidence narration.
- Lightweight validation support.

### 11.3 Deterministic GI5 Layer

GI5 is not treated as an LLM. It remains the deterministic rules and scoring engine.

Responsibilities:

- Fast pattern detection.
- Entropy checks.
- Evidence prefiltering.
- Offline fallback.
- False positive reduction.

### 11.4 Disallowed Model Paths

Remove or alias legacy references to:

- Ollama.
- NVIDIA models.
- Claude.
- GPT-4.
- Mistral.
- Any other model provider.

All legacy calls should route to Gemini 2.5 Flash or OpenRouter GPT OSS 20B.

## 12. Knowledge Graph

The architecture should converge duplicate graph systems into one logical knowledge graph.

Core node types:

- Engagement
- Target
- Domain
- Host
- IP
- Port
- Service
- Technology
- Endpoint
- Parameter
- Form
- API schema
- JavaScript route
- WebSocket
- Credential
- Session
- Finding
- Evidence
- Tool run
- Agent decision

Core edge types:

- resolves_to
- hosts
- exposes
- serves
- links_to
- has_parameter
- authenticates_to
- observed_in
- produced_by
- verified_by
- vulnerable_to
- mitigated_by
- supersedes
- duplicates

The graph is used to:

- Avoid duplicate work.
- Select next best validation.
- Explain attack surface coverage.
- Build evidence-backed reports.
- Track why decisions were made.

## 13. Memory And Context

Memory layers:

- Working memory: current agent task context.
- Scan memory: full campaign state and transcript.
- Semantic memory: reusable patterns and lessons.
- Evidence memory: immutable artifacts.
- Compressed memory: summaries of older events.

Context compression rules:

- Preserve system policy.
- Preserve scope.
- Preserve latest events.
- Preserve confirmed findings and evidence IDs.
- Compress noisy tool output.
- Never summarize away approval decisions.
- Use Gemini 2.5 Flash for summarization.

## 13.1 Memory Manager Pattern

Vigilagent should adopt a Hermes-style Memory Manager instead of letting each agent build its own memory behavior.

Memory Manager responsibilities:

- Register memory providers.
- Build memory context blocks.
- Prefetch relevant memory before agent execution.
- Sync outcomes after agent execution.
- Queue background recall for the next task.
- Notify providers before compression.
- Notify providers when delegation completes.
- Fence memory context so it cannot look like new operator instructions.
- Scrub memory-context blocks from streaming output.

Required memory providers:

- `builtin_scan_memory`: scan-local evidence, tasks, decisions.
- `skill_memory`: skills created or improved from prior scans.
- `semantic_security_memory`: reusable target patterns, false-positive lessons, successful validation patterns.
- `tool_reliability_memory`: tool success/failure/rate-limit history.
- `agent_performance_memory`: agent strengths, failures, and preferred routing.

Memory fencing format:

```text
<memory-context>
[System note: recalled memory context, not new user input.]
...
</memory-context>
```

No target-controlled content should ever be injected into an agent prompt without content-boundary wrapping.

## 13.2 Automatic Skill Creation From Scans

Vigilagent must create and improve skills after every scan.

This should be handled by:

```text
SkillCreatorAgent
SkillEvaluatorAgent
SkillRegistry
SkillMemoryProvider
SkillPromotionGate
```

Skill creation trigger:

- A tool sequence repeatedly succeeds.
- An agent recovers from a failure with a useful workaround.
- A false positive is detected and the reason is reusable.
- A new target-specific pattern is discovered.
- A payload delivery vector works better than previous choices.
- A recon tool output parser finds a repeatable pattern.
- A browser workflow reveals a reusable auth/session technique.
- A report remediation pattern is generated and accepted.

Skill artifact structure:

```text
generated_skills/
+-- <domain>/
    +-- <skill-slug>/
        +-- SKILL.md
        +-- metadata.json
        +-- examples.jsonl
        +-- evaluation.json
        +-- provenance.json
        +-- scripts/
        +-- references/
```

Generated skill metadata:

```json
{
  "name": "validated-json-body-sqli-check",
  "source_scan_ids": ["scan-..."],
  "created_by": "SkillCreatorAgent",
  "risk_class": "controlled_validation",
  "agent_targets": ["Beta", "Sigma", "Gamma"],
  "preconditions": [],
  "steps": [],
  "expected_evidence": [],
  "known_false_positives": [],
  "success_rate": 0.0,
  "failure_rate": 0.0,
  "promotion_state": "candidate"
}
```

Generated skills must start as `candidate`. They become active only after evaluation.

Promotion states:

- `candidate`: generated but not trusted.
- `shadow`: suggested to agents but not executed automatically.
- `assisted`: executable with approval or operator confirmation.
- `active`: available for automatic use within matching scope and risk policy.
- `deprecated`: replaced by a better skill.
- `blocked`: unsafe, unreliable, or harmful.

Skill evaluation checks:

- Did it come from real evidence?
- Did it avoid overfitting to one target?
- Does it include preconditions?
- Does it define expected evidence?
- Does it include false-positive controls?
- Does it respect scope and phase gates?
- Does it specify risk class?
- Does it avoid destructive behavior?
- Does it have at least one replayable test or dry-run example?

Skills should be rewritten and improved automatically, but production activation should pass the promotion gate.

## 13.3 Per-Scan Learning Loop

Every scan ends with a learning pass.

```text
Scan completed
-> Collect decisions, tool runs, findings, false positives, failures
-> Compare plan vs outcome
-> Identify agent mistakes
-> Identify useful new techniques
-> Update tool reliability
-> Update agent routing scores
-> Create or revise skills
-> Compress scan lessons
-> Promote safe improvements
-> Store learning update
```

Learning outputs:

- New candidate skills.
- Updated existing skills.
- Agent reliability deltas.
- Tool reliability deltas.
- Parser improvements to propose.
- Payload vector preferences.
- Better phase budgets.
- Better rate-limit defaults.
- Better false-positive filters.
- Better report templates.

The system should learn from both success and failure. A failed scan is still valuable if it teaches which tools are missing, which assumptions were wrong, or which evidence checks prevented false positives.

## 13.4 Agent Self-Improvement Loop

Every agent gets an improvement profile.

Agent profile fields:

- Capabilities.
- Tool allowlist.
- Preferred skill domains.
- Historical success rate.
- Historical false-positive rate.
- Timeout rate.
- Scope block rate.
- Average evidence quality.
- Common failure modes.
- Recovery strategies.
- Current prompt version.
- Current policy version.

After each scan, SelfAwareness and SkillCreator update:

- Agent prompts.
- Agent routing weights.
- Agent tool preferences.
- Agent budget defaults.
- Agent retry strategy.
- Agent skill recommendations.

Self-improvement must be auditable. Each change should record:

- What changed.
- Why it changed.
- Which scan caused it.
- Which evidence supports it.
- Expected benefit.
- Rollback path.

Automatic improvements that change runtime behavior should be staged first, then promoted after successful shadow evaluation.

## 14. Self-Healing Architecture

Self-healing must observe and act.

Signals:

- Agent exceptions.
- Tool failures.
- Timeouts.
- No-output stalls.
- Browser crashes.
- LLM rate limits.
- Scope violations.
- High false-positive rate.
- Duplicate work rate.
- Worker heartbeat loss.

Actions:

- Retry with bounded backoff.
- Switch tool backend.
- Reduce concurrency.
- Reassign to another worker.
- Disable unreliable tool for the scan.
- Fall back from PinchTab to Playwright.
- Fall back from OpenRouter to Gemini for non-arbitration tasks.
- Compress context.
- Pause scan for human approval.
- Mark scan degraded instead of silently failing.

## 14.1 Mistake-To-Improvement Pipeline

Every mistake should become structured training material for the system.

Mistake categories:

- False positive.
- Missed vulnerability.
- Bad tool choice.
- Bad payload vector.
- Bad parser.
- Bad timeout.
- Bad rate limit.
- Bad browser strategy.
- Bad auth/session handling.
- Bad LLM assumption.
- Duplicate work.
- Scope block.
- Worker crash.
- Report quality issue.

Pipeline:

```text
Mistake detected
-> Classify mistake
-> Attach evidence
-> Identify responsible subsystem
-> Generate improvement hypothesis
-> Create patch proposal or skill proposal
-> Run evaluation
-> Shadow-mode deployment
-> Promotion or rejection
```

Improvement targets:

- Skill content.
- Agent prompts.
- Tool selection policy.
- Budget policy.
- Retry/backoff policy.
- Parser logic.
- Verification thresholds.
- Report templates.
- Scope warning UX.

The system should not silently rewrite core code during a live scan. Core code changes should be proposed as patches, evaluated, and then promoted. Skill and routing updates can be applied automatically if they pass policy and evaluation gates.

## 15. Self-Awareness Architecture

Self-awareness tracks capability and performance.

Metrics:

- Tool availability.
- Tool success rate.
- Agent success rate.
- False-positive rate.
- Evidence quality.
- Cost and token usage.
- Time per phase.
- Coverage by endpoint/service.
- Retry count.
- Scope block count.
- Approval wait time.

Self-awareness outputs:

- Capability map.
- Health dashboard.
- Recommended next action.
- Agent/tool reliability scores.
- Scan confidence score.
- Residual risk summary.

## 15.1 Capability Evolution

Self-awareness should become the central feedback controller for agent evolution.

Inputs:

- Scan outcomes.
- Agent decisions.
- Worker telemetry.
- Tool reliability memory.
- Skill success/failure.
- Human approvals and denials.
- Findings accepted or rejected by Gamma.
- Operator feedback on reports.

Outputs:

- Better routing.
- Better task decomposition.
- Better child-agent assignment.
- Better skill recommendations.
- Better phase budgets.
- Better scan-mode defaults.
- Better fallback paths.

Example:

```text
Gamma rejects 5 SQLi candidates from Beta because only body length changed.
-> Self-awareness marks Beta's SQLi confidence too aggressive.
-> SkillCreator updates SQLi validation skill with stronger negative controls.
-> Sigma reduces priority for that payload class.
-> Gamma threshold remains strict.
-> Next scan uses improved validation automatically in shadow mode.
```

## 16. Phase Lifecycle

Every scan follows gated phases.

```text
1. Intake
2. Scope compilation
3. Passive recon
4. Active recon
5. Surface modeling
6. Planning
7. Controlled validation
8. Verification
9. Evidence capture
10. Risk scoring
11. Reporting
12. Learning
13. Cleanup
```

Agents cannot jump phases unless the phase gate explicitly allows it.

## 16.1 Real Authorized Hacker Workflow

Vigilagent should behave like a real professional tester following a disciplined kill-chain-style workflow, but every step is bounded by scope, approval, evidence, and rate limits.

### Phase 1: Plan

Omega receives:

- Target scope.
- Scan objective.
- Authorization metadata.
- Scan mode.
- Available credentials.
- Tool inventory.
- Budget.
- Extension status.

Omega produces:

- Campaign plan.
- Phase budget.
- Agent assignments.
- Toolset allowlists.
- Expected evidence requirements.

### Phase 2: LAN And Target Context

If the authorized scope includes local network or private ranges, the Network Service Commander performs LAN-aware discovery. If private networks are not explicitly in scope, this phase is skipped.

Allowed outputs:

- In-scope hosts.
- In-scope IPs.
- Open ports.
- Service fingerprints.
- TLS posture.
- Technology hints.

Disallowed by default:

- ARP spoofing.
- MITM.
- Credential theft.
- Persistence.
- Log tampering.
- Any traffic outside scope.

### Phase 3: Recon

Alpha runs real recon using the tool matrix from `D:\projects`.

Recon produces:

- Domains.
- Subdomains.
- URLs.
- Live hosts.
- Open ports.
- Services.
- Technologies.
- JavaScript files.
- API schemas.
- GraphQL endpoints.
- WebSocket endpoints.
- Forms.
- Parameters.
- Screenshots.
- Nuclei template findings.

Everything is parsed into entities and pushed into the knowledge graph.

### Phase 4: Think

Omega, Sigma, Kappa, and the LLM layer analyze the graph.

They decide:

- Which endpoints matter most.
- Which vulnerabilities are plausible.
- Which tool or module should validate each hypothesis.
- What evidence is required.
- Whether approval is needed.
- How much budget to spend.

### Phase 5: Payload Design

Payloads are generated only for authorized validation.

Payload sources:

- Built-in safe validation payload libraries.
- Gemini 2.5 Flash tactical generation.
- OpenRouter GPT OSS 20B planning review.
- Historical Kappa memory.
- Target-specific recon context.
- PayloadsAllTheThings as reference material when locally available.

Payloads must be tagged with:

- Vulnerability class.
- Injection vector.
- Expected signal.
- Risk level.
- Approval requirement.
- Rollback/cleanup requirement if applicable.

### Phase 6: Controlled Payload Delivery

Beta delivers payloads through the correct channel instead of forcing everything into a GET parameter.

Delivery paths:

- HTTP client.
- Browser form submission.
- API request.
- WebSocket frame.
- GraphQL request.
- CLI validation tool through Terminal Engine.

Every delivery records:

- Request.
- Response.
- Timestamp.
- Agent.
- Tool.
- Scope decision.
- Approval ID if used.
- Evidence artifact ID.

### Phase 7: Execute Real Tools

Sigma and Alpha can use Terminal Engine to run real tools, such as:

- `nmap`
- `naabu`
- `httpx`
- `katana`
- `ffuf`
- `feroxbuster`
- `dirsearch`
- `gobuster`
- `nuclei`
- `tlsx`
- `subfinder`
- `amass`
- `gau`
- `waybackurls`
- `gowitness`

Execution must use argv plans where possible. Shell execution is allowed only through the guarded Terminal Engine.

### Phase 8: Verify

Gamma validates results before they become findings.

Required validation pattern:

1. Baseline request.
2. Test request.
3. Negative control.
4. Repeatability check where safe.
5. Differential comparison.
6. Evidence capture.
7. Confidence score.

### Phase 9: Chain Approved Findings

Vigilagent can reason about chains, but only within authorization.

Example safe chain:

```text
Recon -> exposed API schema -> weak auth boundary candidate -> controlled IDOR validation -> confirmed finding -> report remediation
```

Dangerous post-exploitation behaviors such as persistence, stealth, lateral movement, or destructive changes are not default runtime features. If a customer engagement requires impact demonstration, Vigilagent should model it as an approval-gated, non-destructive proof with clear operator consent.

### Phase 10: Report And Learn

Reporting produces evidence-backed output. Kappa and the learning engine store reusable lessons:

- Which tool worked.
- Which payload class worked.
- Which verification signal mattered.
- Which agent made a wrong assumption.
- Which paths were false positives.
- Which targets were unstable.

## 17. Verification Model

A vulnerability requires multiple signals.

Verification signals:

- Status code divergence.
- Response body structural difference.
- Response length difference.
- Timing difference.
- DOM difference.
- Auth boundary difference.
- Sensitive data exposure.
- Repeatability.
- Baseline comparison.
- Negative control comparison.

Finding states:

- candidate
- needs_evidence
- likely
- confirmed
- false_positive
- duplicate
- out_of_scope
- accepted_risk

## 18. Reporting Architecture

Reports must be evidence-first.

Outputs:

- Executive PDF.
- Technical PDF.
- JSON.
- SARIF.
- HackerOne markdown.
- STIX where relevant.
- Neo4j/OpenCTI graph export where enabled.

Each finding includes:

- Title.
- Severity.
- Affected asset.
- Scope status.
- Evidence IDs.
- Reproduction summary.
- Business impact.
- Technical impact.
- Confidence.
- False-positive controls used.
- Remediation.
- References.

## 19. Extension Architecture

The extension is a thin bridge.

Modules:

- Background network observer.
- Content DOM observer.
- Session extractor.
- Storage observer.
- Popup configuration UI.
- WebSocket bridge client.

Design rules:

- Scope-aware capture only.
- No autonomous exploitation inside extension.
- No hidden collection outside configured scope.
- Operator-visible status.
- Backend URL configurable.
- Capture can be paused.
- Sensitive values masked in UI.

Backend bridge endpoints:

- `POST /bridge/session`
- `POST /bridge/token`
- `POST /bridge/traffic`
- `POST /bridge/dom`
- `POST /bridge/storage`
- `POST /bridge/ws`
- `GET /bridge/commands`
- `WS /bridge/live`

## 20. Data Storage

Storage layers:

- `scan_states/`: active scan state.
- `reports/`: generated reports.
- `data/scans/`: artifacts and raw recon output.
- `brain/`: learning artifacts.
- SQLite: local durable scan state and checkpointing.
- Supabase: optional remote persistence.

Checkpoint strategy:

- Checkpoint after every phase.
- Checkpoint before risky validation.
- Store graph snapshot.
- Store remaining task queue.
- Store budget counters.
- Store agent health.
- Resume from last completed safe boundary.

## 21. Configuration Files

Recommended minimal configuration:

```text
config/
+-- scope.yaml
+-- tools.yaml
+-- budgets.yaml
+-- models.yaml
+-- extension.yaml
```

`models.yaml` must allow only:

```yaml
models:
  strategic:
    provider: openrouter
    model: openai/gpt-oss-20b
  tactical:
    provider: gemini
    model: gemini-2.5-flash
```

## 22. API Surface

Primary backend APIs:

- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `POST /api/scans/{scan_id}/pause`
- `POST /api/scans/{scan_id}/resume`
- `POST /api/scans/{scan_id}/cancel`
- `GET /api/scans/{scan_id}/events`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/graph`
- `GET /api/scans/{scan_id}/report`
- `GET /api/approvals`
- `POST /api/approvals/{approval_id}/approve`
- `POST /api/approvals/{approval_id}/deny`
- `GET /api/tools`
- `GET /api/health`
- `GET /api/self-awareness`

## 23. Frontend Architecture

The frontend should be operational, not marketing-focused.

Primary views:

- Dashboard.
- New scan.
- Live scan feed.
- Knowledge graph.
- Findings.
- Evidence.
- Approvals.
- Tool inventory.
- Worker health.
- Reports.
- Settings.

The interface should prioritize:

- Dense scan status.
- Clear scope visibility.
- Approval decisions.
- Evidence traceability.
- Agent/tool health.
- Finding confidence.

## 24. Refactor Strategy

Do not rewrite everything.

Order:

1. Rename product surface from Vulagent/Vul Agent to Vigilagent.
2. Lock model routing to OpenRouter GPT OSS 20B and Gemini 2.5 Flash.
3. Create `ScanStateDB` using the Hermes `state.db` pattern: SQLite, WAL/fallback, schema versions, FTS, jittered retries.
4. Introduce `TaskGraph` and `DelegationManager`.
5. Move agent coordination out of the flat EventBus.
6. Keep WebSocket/event streaming only for UI, audit, progress, approvals, and heartbeat.
7. Add iteration budgets for parent agents, child agents, workers, and skill runs.
8. Merge Alpha and Alpha V6 into `Alpha Unified Recon Commander`.
9. Wire exploit and validation paths to `ScopePolicy`.
10. Add Terminal Engine over existing `ProcessRunner` and `DockerSandbox`.
11. Register terminal execution as a governed tool.
12. Connect Master/Worker as subagents through durable task leases.
13. Connect Omega to delegation.
14. Connect Beta/Sigma to governed tool execution.
15. Replace naive module verification with `MultiLayerVerifier`.
16. Add Hermes-style context compression.
17. Add Memory Manager with fenced memory providers and streaming scrubber.
18. Add skill ingestion from `D:\projects\Anthropic-Cybersecurity-Skills`.
19. Add automatic skill creation from scan outcomes.
20. Add skill evaluation and promotion gates.
21. Add self-improvement loop for all agents.
22. Unify graph systems.
23. Add checkpoint/resume.
24. Harden extension bridge.

## 25. What To Remove Or Rename

Remove or rename misleading concepts:

- Fake "Nash equilibrium" should become strategy weighting or LLM strategy reasoning.
- Fake "RL" should become adaptive heuristic scoring unless real Q-learning is implemented.
- Mock credentials must not be used for real validation.
- Hardcoded localhost-only exploitation must be replaced with scope policy.
- Duplicate graph state must converge into one knowledge graph abstraction.
- Flat EventBus must stop being the agent control plane.
- JSON-only scan memory must stop being the durable execution state.
- Agent self-awareness must stop being observational only; it must feed routing and skill updates.

Do not delete working recon, reporting, browser, guard, or forensic code.

## 26. MVP Architecture Slice

The first complete, useful Vigilagent version should include:

- Vigilagent branding.
- Scope YAML.
- Tool inventory from `D:\projects`.
- Terminal Engine.
- Docker/local backend selection.
- Iteration budget.
- Delegation manager.
- Alpha V6 recon execution.
- Knowledge graph ingestion.
- Controlled validation with evidence.
- Approval queue.
- Live WebSocket feed.
- PDF/JSON/SARIF reports.
- Two-model LLM policy.
- Self-awareness dashboard.
- ScanStateDB with searchable history.
- SkillCreatorAgent and SkillEvaluatorAgent.
- Generated skill registry.
- EventBus replacement with task delegation.
- Per-scan learning loop.

## 27. Final Target Architecture

Vigilagent should become a governed autonomous security command center:

- It understands target scope.
- It maps real attack surface.
- It chooses next actions based on evidence.
- It uses real tools through controlled execution.
- It verifies before reporting.
- It learns from outcomes.
- It heals failed workflows.
- It explains every decision.
- It works with or without the browser extension.
- It scales through master/worker execution.
- It remains bounded by authorization, safety, auditability, and professional security-testing rules.

## 28. Final Self-Improving Runtime

The final Vigilagent loop should look like this:

```text
Operator starts authorized scan
-> Omega plans
-> Master decomposes task graph
-> Workers execute bounded child-agent tasks
-> Alpha maps surface
-> Sigma selects techniques and skills
-> Beta performs controlled validation
-> Delta/Chi/Prism handle browser intelligence
-> Gamma verifies evidence
-> Kappa stores memory
-> Zeta adjusts runtime pressure
-> Lambda links code/config risk
-> Reports are generated
-> Scan is analyzed for mistakes
-> Skills are created or improved
-> Agent profiles are updated
-> Tool reliability is updated
-> Knowledge graph is updated
-> Next scan starts smarter
```

This is the intended Hermes-level improvement loop for Vigilagent: not a static scanner, but a system that remembers, compresses, searches, critiques itself, creates new reusable skills, evaluates them, promotes them safely, and gradually improves every agent after every scan.

## 29. Extracted Requirements From The Uploaded Gap Analysis

This section distills the most important points from the uploaded Vigilagent to Hermes-level upgrade analysis. These are the requirements that should drive implementation.

### 29.1 What Already Works And Must Be Preserved

Vigilagent should build on the strong parts of the current system instead of replacing them.

Strong existing foundations:

- Multi-agent system with Alpha, Beta, Gamma, Omega, Sigma, Kappa, Zeta, Prism, Chi, Delta, and Lambda.
- Alpha V6 recon pipeline with real CLI execution, parsers, entity ingestion, scoring, dedupe, artifacts, and live feed.
- Pydantic event schemas and structured internal models.
- Cortex with GI5 deterministic reasoning, Gemini, and OpenRouter.
- MultiLayerVerifier concept for evidence-based validation.
- Learning engine, skill extractor, and skill library foundations.
- Knowledge graph and graph engine foundations.
- OpenClaw, Playwright, PinchTab, browser orchestration, DOM analysis, and network interception.
- Guard layer and content boundary for prompt-injection resistance.
- Forensic collector with screenshot, DOM, and network evidence.
- Reporting engine with PDF, SARIF, HackerOne, STIX, Neo4j, Maltego, and JSON-style outputs.
- FastAPI, WebSocket live feed, and cluster entry modes.

### 29.2 Fatal Gaps To Fix First

The uploaded analysis repeatedly identifies these as the first implementation priorities.

1. Exploit and validation paths are hardcoded or effectively constrained to localhost.
   Fix: replace static allowed-domain checks with dynamic `ScopePolicy` and engagement config.

2. Beta, Sigma, Omega, and most agents cannot use real CLI tools.
   Fix: create a universal `TerminalEngine` over `ProcessRunner`, `DockerSandbox`, guardrails, scope, approvals, output streaming, and parsers.

3. Attack modules use naive string matching.
   Fix: route all findings through baseline comparison, negative controls, repeatability checks, `MultiLayerVerifier`, and Gamma evidence review.

4. Payload delivery is one-dimensional.
   Fix: implement `PayloadDeliveryEngine` for query, body, form, header, cookie, path, file upload where approved, browser, WebSocket, GraphQL, and API-specific vectors.

5. Skills are extracted but not applied.
   Fix: wire `SkillLibrary.get_recommendations()` and generated skills into Omega, Sigma, Beta, Gamma, and Kappa.

6. Graph systems are duplicated.
   Fix: merge `graph_engine.py` and `knowledge_graph.py` into a persistent unified knowledge graph.

7. Event bus is doing too much.
   Fix: retain it for UI/live/audit events, but replace agent control flow with Hermes-style task delegation.

### 29.3 Hermes Patterns To Adopt

Hermes-agent provides the operational architecture Vigilagent needs.

Adopt these patterns:

- Terminal tool architecture: multi-backend command execution, output streaming, timeouts, background process handling, guarded command approval, and workspace validation.
- Delegation tool architecture: parent agent spawns isolated child agents with restricted tools, separate memory, strict budgets, and structured return values.
- Iteration budget: every agent, child agent, worker, tool call, and LLM call consumes bounded budget.
- Context compression: token-aware compaction using Gemini 2.5 Flash, preserving policy, scope, active task, critical findings, and recent context.
- Memory manager: provider interface, prefetch, sync, context fencing, and streaming scrubber.
- Tool registry: first-class tool entries with schemas, handlers, toolset membership, availability checks, and safe dispatch.
- SQLite state: WAL/fallback, schema versions, FTS search, parent session chains, jittered write retries, resumable state, and searchable history.
- Checkpoints: checkpoint before risky mutation, checkpoint after every phase, resume from safe boundaries.
- Skill lifecycle: load, preprocess, map, invoke, evaluate, and promote skills through explicit states.

### 29.4 Current Agent Upgrades Required

Each existing agent should become more capable, but also more structured.

- Alpha and Alpha V6 merge into `Alpha`.
- Beta becomes a controlled multi-vector validation agent, not only a query-string payload sender.
- Gamma becomes the final evidence authority and false-positive filter.
- Omega becomes the campaign commander with LLM reasoning and graph-aware delegation, not random strategy selection.
- Sigma becomes the tool/technique commander, mapping hypotheses to modules, skills, and CLI tools.
- Kappa becomes active tactical memory and skill recall, not passive storage.
- Zeta controls runtime pressure, retries, rate, concurrency, WAF pressure, and scan stability.
- Delta drives OpenClaw and PinchTab for authenticated browser workflows.
- Chi analyzes traffic, timing, XHR/fetch, WebSocket, and side channels.
- Prism maps DOM, JS routes, shadow DOM, CSP, hidden inputs, and client-side attack surface.
- Lambda links SAST, IaC, config, dependency, and source-code findings to runtime validation.
- Master becomes durable campaign/task coordinator.
- Workers become bounded execution subagents.

### 29.5 Tooling Requirements

The architecture must make external tools first-class capabilities.

Tool classes:

- Recon: `subfinder`, `amass`, `gau`, `waybackurls`, `dnsx`, `httpx`, `katana`, `hakrawler`, `naabu`, `nmap`, `tlsx`, `nuclei`, `ffuf`, `feroxbuster`, `dirsearch`, `gobuster`, `kiterunner`, `gowitness`, `interactsh`, `cloudlist`, `spiderfoot`.
- Web/API validation: `sqlmap`, `nuclei`, `ffuf`, `nikto`, GraphQL tooling, WebSocket tooling, controlled custom modules.
- Network/service assessment: `nmap`, `masscan`, `testssl.sh`, `sslyze`, `enum4linux-ng`, `smbclient`, `ldapsearch`, Impacket-style tooling.
- Browser/mobile/client: OpenClaw, PinchTab, Playwright, extension bridge, Frida/Objection-style skill support when in scope.
- Forensics/defense: Volatility, Wireshark/tshark, Zeek, Splunk-style analysis, YARA, Trivy/Grype, kube-bench, kubesec where applicable.

Execution rules:

- Prefer argv execution over shell strings.
- Prefer Docker/Kali-style sandboxing for Linux-native tools on Windows.
- Every tool has timeout, scope check, parser hint, output cap, artifact path, and audit record.
- Agents consume tool output as parsed entities, not raw text blobs.

### 29.6 Validation And Exploit Architecture

Vigilagent should perform real authorized validation, but not blind uncontrolled exploitation.

Required validation workflow:

```text
Recon entity
-> Hypothesis
-> Skill/tool selection
-> Baseline request
-> Controlled payload/test
-> Negative control
-> Repeatability check where safe
-> Gamma verification
-> Evidence capture
-> Finding or rejection
```

Validation must support:

- Query parameters.
- POST JSON.
- POST forms.
- Multipart/file paths where explicitly approved.
- Headers.
- Cookies.
- Path segments.
- Browser actions.
- WebSocket frames.
- GraphQL requests.
- API schemas.
- Authenticated sessions.

Naive checks such as `if "admin" in text.lower()` or `if "success" in response.lower()` must be replaced by differential, structural, timing, DOM, state, and authorization-boundary evidence.

### 29.7 Network And OSI Coverage

The uploaded plan asks for coverage beyond HTTP. Vigilagent should support these as authorized assessment modules.

- Layer 7: HTTP/HTTPS, DNS, SMTP, FTP, SSH, GraphQL, WebSocket, gRPC.
- Layer 6: TLS/certificate/cipher analysis.
- Layer 5: SMB, RPC, LDAP, Kerberos, NFS, WinRM where scoped.
- Layer 4: TCP/UDP scanning, banner grabbing, service detection.
- Layer 3: ICMP, traceroute, topology mapping, packet analysis.
- Layer 2: only safe simulations or explicitly authorized lab/local assessments.

Default posture:

- Recon and validation are allowed only inside scope.
- Intrusive network techniques require explicit approval.
- Destructive, stealth, persistence, and cleanup-of-traces behavior are disabled by default and should not run automatically.

### 29.8 Browser And Extension Requirements

The browser layer is a major advantage over Hermes and should be preserved.

Requirements:

- OpenClaw and PinchTab both remain supported.
- PinchTab is used for anti-fingerprint browser profiles where appropriate.
- Playwright fallback remains available.
- Delta, Chi, and Prism share browser evidence with Alpha and Beta.
- Extension remains optional.
- Extension captures only in-scope session, DOM, traffic, storage, CSP, and WebSocket metadata.
- Extension does not independently execute attacks.
- Browser campaign planning in Omega must become live, not dead code.
- Browser sessions should support safe parallelism and resource caps.

### 29.9 Learning, Skills, And Self-Improvement

The uploaded analysis identifies the learning layer as promising but disconnected. Vigilagent must close that loop.

Required learning flow:

```text
Scan outcome
-> Evidence review
-> Mistake classification
-> Skill creation/update
-> Agent profile update
-> Tool reliability update
-> Routing update
-> Shadow evaluation
-> Promotion gate
```

Required changes:

- Skill extractor output must be consumed by Omega, Sigma, Beta, Gamma, and Kappa.
- Learning integrator must pull recommendations out of memory, not only push data in.
- Self-awareness must change routing, budgets, tool preferences, and skill recommendations.
- Self-healing must perform real recovery actions, not only log or count attempts.
- Auth recovery should use authorized stored session patterns and test credentials where configured.

### 29.10 Configuration And State Requirements

Environment-only config is not enough.

Required config files:

- `scope.yaml`
- `tools.yaml`
- `budgets.yaml`
- `models.yaml`
- `skills.yaml`
- `workers.yaml`
- `engagement.yaml`

Required state:

- Durable scan database.
- Persistent approvals.
- Persistent task graph.
- Persistent tool runs.
- Persistent graph snapshots.
- Persistent checkpoints.
- Searchable scan transcript.
- Offline fallback when Supabase or Redis is unavailable.

### 29.11 Priority Implementation Order Extracted From The Prompt

The practical order should be:

1. Dynamic scope enforcement.
2. Terminal Engine.
3. Tool registry/wrappers for real CLI tools.
4. Beta/Sigma access to governed terminal execution.
5. Iteration budget.
6. Delegation manager.
7. ScanStateDB with checkpoint/resume.
8. Context compression.
9. Memory Manager with fenced recall.
10. Alpha + Alpha V6 merge.
11. Multi-vector payload delivery.
12. Attack module verification rewrite.
13. Skill library consumption.
14. Automatic skill creation from scans.
15. Unified knowledge graph.
16. Omega strategy reasoning.
17. Browser campaign activation.
18. Credential/session vault for authorized test credentials and API-key rotation.
19. Network/service commander.
20. Reporting, CVSS, and remediation polish.

### 29.12 Decisions For Vigilagent

These decisions resolve recurring open questions in the uploaded plans.

- Docker should be the default execution backend for external security tools, especially on Windows.
- Local execution is allowed for trusted native tools and lightweight commands.
- EventBus should be preserved only for observability, not primary agent control.
- Alpha V6 should be the recon spine; legacy Alpha should merge into it.
- The graph systems should merge into one persistent graph.
- Skill recommendations should be queried before every meaningful plan, not only when stuck.
- Existing browser defense features should stay because they improve prompt-injection resistance, traffic intelligence, and client-side evidence.
- The platform should support real authorized validation, but destructive actions, persistence, stealth, and out-of-scope behavior must be disabled or approval-gated by design.

### 29.13 Hermes File Patterns To Copy Into Vigilagent

The important Hermes-Agent lessons are not its exact code, but the architecture patterns in these files.

| Hermes file | Pattern to extract | Vigilagent target |
| --- | --- | --- |
| `tools/terminal_tool.py` | Real subprocess execution, streaming output, backend selection, guarded commands, long-running process control | `backend/core/terminal_engine.py` |
| `tools/delegate_tool.py` | Parent agent spawns isolated child agents and receives structured results | `backend/core/delegation_manager.py` |
| `agent/iteration_budget.py` | Shared budget primitive that bounds loops, tools, LLM calls, and child agents | `backend/core/iteration_budget.py` |
| `agent/context_compressor.py` | Token-aware context compaction with protected head/tail and summaries | `backend/core/context_compressor.py` |
| `agent/memory_manager.py` | Provider-based memory, context fencing, prefetch/sync lifecycle, streaming scrubber | `backend/core/memory_manager.py` or upgraded `memory.py` |
| `tools/registry.py` | Tool schema registry, availability checks, toolsets, safe dispatch | upgraded `backend/core/tool_registry.py` |
| `hermes_state.py` | SQLite WAL/fallback state, schema versions, FTS search, retries, session chains | `backend/core/scan_state_db.py` |
| `agent/tool_executor.py` | Central tool execution with checkpoints, concurrency rules, progress callbacks | `backend/core/tool_executor.py` |

### 29.14 Non-Negotiable Product Boundaries

The prompt asks for a system that behaves like a real operator. In Vigilagent, that means realistic authorized assessment, not uncontrolled offensive automation.

Non-negotiable boundaries:

- Every target, host, subnet, domain, credential, and time window must come from explicit scope.
- Every command and browser action must be auditable.
- Every intrusive validation path must have budget, timeout, scope, and approval metadata.
- Payload execution must be controlled, evidence-oriented, and reversible where possible.
- Post-exploitation becomes impact demonstration, session inventory, privilege/context proof, and evidence capture inside approved labs or engagements.
- Persistence, stealth, destructive modification, log cleanup, and out-of-scope pivoting are not automatic product behavior.
- L2/L3 network techniques run only in lab/local environments or explicit engagement scope.
- The browser extension is a passive bridge by default; it captures scoped context and does not independently attack.
- Self-improvement can update routing, prompts, skills, budgets, confidence, and tool preferences, but promoted changes require evaluation gates.
- OpenRouter `openai/gpt-oss-20b` and Gemini `gemini-2.5-flash` are the only LLMs. GI5 remains deterministic fallback logic, not a third LLM.

### 29.15 Final Extracted Build Thesis

The important conclusion from the uploaded prompt is:

```text
Vigilagent should not be rebuilt from scratch.
It should preserve Vigilagent's domain-specific agents, Alpha V6 recon, browser intelligence,
forensics, reporting, learning foundations, and graph ideas,
while replacing the weak orchestration core with Hermes-style terminal execution,
hierarchical delegation, durable state, budgets, compression, and memory management.
```

That gives the clean target:

```text
Alpha V6 discovers.
Omega reasons and delegates.
Sigma maps techniques and tools.
Beta performs governed multi-vector validation.
Gamma verifies evidence.
Kappa recalls and creates skills.
Zeta controls pressure and stability.
Delta/Chi/Prism handle browser intelligence.
Master persists and coordinates.
Workers execute bounded tasks.
Hermes patterns provide the operating system underneath.
```
