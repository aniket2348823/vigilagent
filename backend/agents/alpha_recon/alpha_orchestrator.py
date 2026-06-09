"""Alpha V6 Deep Recon Orchestrator — Full Multi-Phase Pipeline."""
from __future__ import annotations
import asyncio, logging, os, re, time
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

from backend.agents.alpha_recon.artifacts import ArtifactStore
from backend.agents.alpha_recon.dedupe import SeenSet, classify_path, normalize_endpoint_key, normalize_url
from backend.agents.alpha_recon.models import (
    EndpointFinding, HTTPServiceFinding, ParameterFinding, ReconEntity,
    ReconRunResult, ReconRunSummary, ReconScope, ScanMode, SourceRef, ToolSkip, stable_id,
)
from backend.agents.alpha_recon.rag import ReconRAGPipeline
from backend.agents.alpha_recon.scoring import score_endpoint
from backend.agents.alpha_recon.phase_controller import PhaseController, PhaseState, PhaseResult
from backend.agents.alpha_recon.entity_engine import EntityEngine
from backend.agents.alpha_recon.pinchtab_intel import PinchTabIntelligence
from backend.agents.alpha_recon.scope_gate import ScopeGate, ScopeGateViolation
from backend.agents.alpha_recon.live_feed import recon_live_feed
from backend.agents.alpha_recon.interactsh_adapter import InteractshAdapter
from backend.agents.alpha_recon.approval_hooks import approval_manager
from backend.core.delegation_manager import ChildSpec, DelegationManager
from backend.agents.alpha_recon.event_schemas import (
    ReconStartedEvent, ReconCompleteEvent, PhaseStartedEvent, PhaseCompletedEvent,
    ToolCompletedEvent, VulnCandidateEvent, ScopeViolationEvent,
)
import backend.agents.alpha_recon.db_extensions  # patches db_manager
from backend.core.config import settings
from backend.core.database import db_manager
from backend.core.hive import EventType, HiveEvent
from backend.core.unified_knowledge_graph import EdgeKind, KGNode, NodeKind, knowledge_graph
from backend.core.scope import ScopePolicy, ScopeViolation
from backend.core.telemetry import telemetry
from backend.integrations.pinchtab_client import PinchTabClient
from backend.modules.tech.http_client import http_client
from backend.tools.recon import RECON_TOOLS, ReconCommandPlanner, ReconCommandRunner, check_tool_availability
from backend.parsers.recon import PARSER_REGISTRY
from backend.parsers.recon.base import ParsedEntity

logger = logging.getLogger("alpha")

class AlphaOrchestrator:
    """Production-grade multi-phase recon orchestrator."""

    def __init__(self, bus, *, agent_name: str = "agent_alpha", browser=None, browser_provider=None,
        delegation_mgr=None):
        self.bus = bus
        self.agent_name = agent_name
        self._seen_packets = SeenSet()
        self._delegation_mgr = delegation_mgr or DelegationManager()
        # Shared browser orchestrator (OpenClaw + PinchTab) for browser-aware
        # recon merged from legacy Alpha (Architecture §5.1.1). A provider
        # callable allows lazy access so browser init isn't forced at construct.
        self._browser = browser
        self._browser_provider = browser_provider

    @property
    def browser(self):
        if self._browser is None and self._browser_provider is not None:
            try:
                self._browser = self._browser_provider()
            except Exception as exc:
                logger.debug(f"[Alpha] Browser provider failed: {exc}")
                self._browser = None
        return self._browser

    async def run(self, target_url: str, *, scan_id: str = "GLOBAL",
                  mode: str | ScanMode | None = None) -> ReconRunResult:
        started = time.time()
        scan_mode = self._coerce_mode(mode or getattr(settings, "ALPHA_DEFAULT_MODE", "STANDARD"))
        scope = self._compile_scope(target_url, scan_mode)

        # Scope Gate Validation — blocks .gov/.mil, private networks, unauthorized active scans
        gate = ScopeGate(scope)
        try:
            gate.validate_target(target_url)
        except ScopeGateViolation as exc:
            logger.error(f"[SCOPE] Target rejected: {exc}")
            await recon_live_feed.on_error(scan_id, str(exc), "scope_gate")
            # Emit a RECON_COMPLETE event (failed status) so the orchestrator
            # never sits on its 180s safety timeout when scope rejects a target
            # synchronously. Downstream consumers expect a terminal event.
            try:
                await self._emit_complete(self._build_failed_result(
                    scan_id, target_url, scan_mode, started, f"scope_rejected:{exc}"))
            except Exception as emit_exc:
                logger.debug(f"[Alpha] scope rejection emit failed: {emit_exc}")
            raise

        artifacts = ArtifactStore(scan_id)
        rag = ReconRAGPipeline(scan_id, str(artifacts.root))
        planner = ReconCommandPlanner()
        runner = ReconCommandRunner()
        phases = PhaseController(scope)
        entities = EntityEngine(scan_id)
        tools_run: list[str] = []
        tools_skipped: list[ToolSkip] = []
        endpoints: list[EndpointFinding] = []
        result: ReconRunResult | None = None
        emit_done = False

        # Interactsh OOB client
        interactsh = InteractshAdapter(scan_id, artifacts.root)
        oob_url = await interactsh.start()
        phases.state.interactsh_url = oob_url

        await db_manager.initialize()
        await db_manager.create_recon_run(scan_id=scan_id, target=target_url,
            mode=scan_mode.value, scope=scope.model_dump(mode="json"),
            artifact_root=str(artifacts.root), status="running")

        await recon_live_feed.on_phase_started(scan_id, "initialization")
        await self._emit_status(scan_id, "initialized", {"target": target_url, "mode": scan_mode.value})
        await rag.ingest_tool_summary("alpha_scope", {"target": target_url, "mode": scan_mode.value})

        try:
            with telemetry.span("alpha.recon", kind="agent", scan_id=scan_id):
                # Phase: Tool Inventory
                await self._inventory_tools(scan_mode, tools_skipped, rag)

                # Phase 1: Passive Intelligence
                if phases.should_run(phases.PHASE_ORDER[1]):
                    await self._run_phase_passive(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, tools_run, tools_skipped)

                # Phase 2: DNS & Infrastructure
                if phases.should_run(phases.PHASE_ORDER[2]):
                    await self._run_phase_dns(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, tools_run, tools_skipped)

                # Phase 3: HTTP & Browser Intelligence
                if phases.should_run(phases.PHASE_ORDER[3]):
                    await self._run_phase_http(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, target_url, tools_run, tools_skipped, endpoints)

                # Phase 4: Directory & Route Discovery
                if phases.should_run(phases.PHASE_ORDER[4]):
                    await self._run_phase_discovery(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, tools_run, tools_skipped)

                # Phase 5: API Reconnaissance
                if phases.should_run(phases.PHASE_ORDER[5]):
                    await self._run_phase_api(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, tools_run, tools_skipped)

                # Phase 6: Visual Documentation
                if phases.should_run(phases.PHASE_ORDER[6]):
                    await self._run_phase_visual(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, tools_run, tools_skipped)

                # Phase 7: Template Validation
                if phases.should_run(phases.PHASE_ORDER[7]):
                    await self._run_phase_validation(phases, planner, runner, artifacts, rag,
                        entities, scan_id, scope, tools_run, tools_skipped)

                # Stop Interactsh and collect OOB findings
                oob_interactions = await interactsh.stop()
                if oob_interactions:
                    tools_run.append("interactsh")
                    oob_parsed: list[ParsedEntity] = []
                    for oob in oob_interactions:
                        oob_parsed.append(ParsedEntity(
                            kind="oob_interaction", label=oob.get("interaction_type", "unknown"),
                            confidence=0.9, source_tool="interactsh",
                            phase="template_validation",
                            properties=oob.get("raw", {})))
                    if oob_parsed:
                        try:
                            await entities.ingest_entities(oob_parsed)
                        except Exception as ie:
                            logger.warning(f"OOB ingest failed: {ie}")

                # Final: Correlation & Scoring
                endpoints = self._dedupe_and_sort(endpoints)
                summary = self._summarize(endpoints, phases.state, entities)
                result = ReconRunResult(
                    scan_id=scan_id, target=target_url, mode=scan_mode,
                    duration_seconds=int(time.time() - started), summary=summary,
                    attack_surface=endpoints, tools_run=tools_run,
                    tools_skipped=tools_skipped, raw_data_path=str(artifacts.raw_dir),
                    screenshots_path=str(artifacts.screenshots_dir),
                    artifact_manifest_path=str(artifacts.manifest_path))
        except asyncio.CancelledError:
            logger.warning("[Alpha] run cancelled for scan %s", scan_id)
            raise
        except Exception as exc:
            # A phase blew up — build a failed result so the orchestrator still
            # gets a terminal RECON_COMPLETE event with whatever entities were
            # accumulated. Without this the safety timeout would fire 180s later.
            logger.exception("[Alpha] run aborted for scan %s: %s", scan_id, exc)
            try:
                await interactsh.stop()
            except Exception as cleanup_exc:
                logger.debug(f"[Alpha] interactsh cleanup failed: {cleanup_exc}")
            result = self._build_failed_result(scan_id, target_url, scan_mode,
                started, f"orchestrator_error:{exc.__class__.__name__}:{exc}",
                tools_run=tools_run, tools_skipped=tools_skipped,
                attack_surface=endpoints, artifacts=artifacts, summary=None,
                state=phases.state, entities=entities)
        finally:
            # ALWAYS publish RECON_COMPLETE so downstream agents and the safety
            # timeout never have to guess. Best-effort across all sub-steps so a
            # late failure in artifact write or db.finish_recon_run cannot
            # swallow the event.
            try:
                if result is None:
                    result = self._build_failed_result(
                        scan_id, target_url, scan_mode, started,
                        "orchestrator_no_result",
                        tools_run=tools_run, tools_skipped=tools_skipped,
                        attack_surface=endpoints, artifacts=artifacts,
                        state=phases.state, entities=entities)
            except Exception as fb_exc:
                logger.error("[Alpha] failed to build fallback result: %s", fb_exc)
                result = None

            if result is not None:
                # Persist & broadcast best-effort. Each step is in its own
                # try/except so a single failure (e.g. db unreachable) cannot
                # block the RECON_COMPLETE publish.
                try:
                    await artifacts.write_json("exports/recon_complete.json",
                        result.model_dump(mode="json"), tool_name="alpha",
                        artifact_type="recon_complete", scan_id=scan_id)
                except Exception as exc:
                    logger.warning("[Alpha] artifact export failed: %s", exc)
                try:
                    final_status = "completed" if result.summary and \
                        result.summary.total_endpoints >= 0 and \
                        not (result.summary.attack_surface_stats or {}).get("orchestrator_error") \
                        else "completed"
                    await asyncio.wait_for(
                        db_manager.finish_recon_run(scan_id=scan_id, status=final_status),
                        timeout=15)
                except Exception as exc:
                    logger.warning("[Alpha] finish_recon_run failed/slow: %s", exc)
                try:
                    await recon_live_feed.on_scan_complete(scan_id,
                        result.summary.model_dump() if result.summary else {})
                except Exception as exc:
                    logger.warning("[Alpha] live_feed publish failed: %s", exc)
                try:
                    await self._emit_complete(result)
                    emit_done = True
                except Exception as exc:
                    logger.error("[Alpha] _emit_complete failed: %s", exc)

            # Last-resort: even if result building utterly failed, publish a
            # minimal RECON_COMPLETE so the orchestrator gets unstuck.
            if not emit_done:
                try:
                    minimal = self._build_failed_result(
                        scan_id, target_url, scan_mode, started,
                        "emit_complete_fallback")
                    await self._emit_complete(minimal)
                except Exception as exc:
                    logger.error("[Alpha] absolute fallback emit failed: %s", exc)

        return result

    # ── Phase Implementations ─────────────────────────────────────

    async def _run_phase_passive(self, phases, planner, runner, artifacts, rag,
                                  entities, scan_id, scope, tools_run, tools_skipped):
        from backend.agents.alpha_recon.models import ReconPhase
        pr = phases.start_phase(ReconPhase.PASSIVE)
        await self._emit_status(scan_id, "phase_passive_started", {})
        cmds = planner.passive_commands(scope, artifacts.raw_dir)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        phases.complete_phase(ReconPhase.PASSIVE, parsed)

    async def _run_phase_dns(self, phases, planner, runner, artifacts, rag,
                              entities, scan_id, scope, tools_run, tools_skipped):
        from backend.agents.alpha_recon.models import ReconPhase
        if not phases.state.subdomains:
            phases.skip_phase(ReconPhase.INFRA, "no_subdomains_from_passive")
            return
        pr = phases.start_phase(ReconPhase.INFRA)
        await self._emit_status(scan_id, "phase_dns_started", {"subs": len(phases.state.subdomains)})
        sub_file = phases.state.build_subdomain_file(artifacts.raw_dir)
        hosts_file = phases.state.build_hosts_file(artifacts.raw_dir)
        cmds = planner.dns_commands(scope, artifacts.raw_dir, sub_file)
        cmds += planner.port_commands(scope, artifacts.raw_dir, hosts_file)
        cmds += planner.tls_commands(scope, artifacts.raw_dir, hosts_file)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        phases.complete_phase(ReconPhase.INFRA, parsed)

    async def _run_phase_http(self, phases, planner, runner, artifacts, rag,
                               entities, scan_id, scope, target_url, tools_run,
                               tools_skipped, endpoints):
        from backend.agents.alpha_recon.models import ReconPhase
        pr = phases.start_phase(ReconPhase.HTTP)
        await self._emit_status(scan_id, "phase_http_started", {})
        # Seed the hosts file with the scoped target BEFORE building the HTTP
        # commands so httpx/whatweb/wafw00f/katana actually have something to
        # scan on single-target lab runs (localhost:8080) where no passive/DNS
        # phase ran and the discovered subdomain set is empty. Without this,
        # every Phase 3 tool gets an empty -l file and exits with 0 bytes —
        # which is exactly what produced the "0 entities" symptom.
        if not phases.state.subdomains and not phases.state.ips:
            tp = urlparse(target_url if "://" in target_url else f"http://{target_url}")
            host = (tp.hostname or "").strip().lower()
            if host:
                seed = f"{host}:{tp.port}" if tp.port else host
                phases.state.subdomains.add(seed)
                phases.state.ips.add(host)  # for the broader hosts_file
        hosts_file = phases.state.build_hosts_file(artifacts.raw_dir)
        cmds = planner.http_commands(scope, artifacts.raw_dir, hosts_file)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        # Internal HTTP probe
        http_client.scope = ScopePolicy.from_target(target_url)
        svc = await self._http_probe(target_url, scan_id)
        live_seeded: list[str] = []
        for s in svc:
            ep = score_endpoint(self._service_to_endpoint(s))
            endpoints.append(ep)
            if ep.priority_score >= 50:
                await self._emit_recon_packet(scan_id, ep)
            # Seed live HTTP services so downstream phases (directory discovery,
            # API recon, visual, validation) actually run. The internal probe is
            # the authoritative liveness signal when external httpx returns
            # nothing (e.g. single-host localhost lab targets). A service is
            # "live" if it answered with any HTTP status code.
            if getattr(s, "status_code", 0):
                live_seeded.append(s.url)
        if live_seeded:
            existing = set(phases.state.http_services)
            for u in live_seeded:
                if u not in existing:
                    phases.state.http_services.append(u)
                    phases.state.live_hosts.append(u)
                    existing.add(u)
            logger.info("[Alpha] Seeded %d live HTTP service(s) from internal probe.",
                        len(live_seeded))
        # PinchTab deep capture with Playwright fallback
        browser_used = False
        if getattr(settings, "ALPHA_ENABLE_PINCHTAB", True):
            pt = PinchTabIntelligence(scan_id, artifacts, rag)
            targets = [e.url for e in endpoints if e.priority_score >= 40][:20]
            targets += phases.state.http_services[:10]
            pt_result = await pt.full_capture(list(set(targets)))
            if pt_result.get("used"):
                tools_run.append("pinchtab")
                parsed.extend(pt_result.get("entities", []))
                browser_used = True
            elif pt_result.get("reason"):
                tools_skipped.append(ToolSkip(name="pinchtab", phase="http_browser_intelligence",
                    reason=pt_result["reason"]))
        # Delegate browser recon to Delta (SPA detection, JS routes, WebSocket discovery)
        if not browser_used and self.browser is not None:
            try:
                br_result = await self._delegation_mgr.spawn(ChildSpec(
                    agent_class="AgentDelta",
                    objective=f"Browser-aware recon on {target_url}: detect frameworks, extract JS routes, discover WebSockets, extract forms and cookies",
                    worker_specialty="browser",
                    tools=["playwright", "scrapling"],
                    budget=20,
                    timeout_s=60,
                    context={"scan_id": scan_id, "target": target_url},
                ))
                if br_result.status == "completed" and br_result.findings:
                    # Parse browser recon findings into ParsedEntity objects
                    for finding in br_result.findings:
                        if isinstance(finding, dict) and "url" in finding:
                            parsed.append(ParsedEntity(
                                kind=finding.get("kind", "endpoint"),
                                label=finding["url"],
                                source_tool="browser_recon",
                                source_ref=SourceRef(tool="browser_recon", phase="http_browser_intelligence"),
                            ))
                    tools_run.append("browser_recon")
                    browser_used = True
            except Exception as br_exc:
                logger.debug(f"Browser recon delegation skipped: {br_exc}")
                tools_skipped.append(ToolSkip(name="browser_recon", phase="http_browser_intelligence",
                    reason=str(br_exc)[:100]))
        # JS analysis
        js_files = list(set(phases.state.js_files + [e.label for e in parsed if e.kind == "js_file"]))
        if js_files:
            js_cmds = planner.js_analysis_commands(scope, artifacts.raw_dir, js_files[:50])
            js_parsed = await self._run_and_parse(js_cmds, runner, artifacts, rag, scan_id,
                tools_run, tools_skipped, pr, entities=entities)
            parsed.extend(js_parsed)
        phases.complete_phase(ReconPhase.HTTP, parsed)

    async def _run_phase_discovery(self, phases, planner, runner, artifacts, rag,
                                    entities, scan_id, scope, tools_run, tools_skipped):
        from backend.agents.alpha_recon.models import ReconPhase
        live = list(set(phases.state.http_services))[:100]
        if not live:
            phases.skip_phase(ReconPhase.DISCOVERY, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.DISCOVERY)
        await self._emit_status(scan_id, "phase_discovery_started", {"hosts": len(live)})
        # Delegate wordlist building to worker
        wl_result = await self._delegation_mgr.spawn(ChildSpec(
            agent_class="AlphaAgent",
            objective="Build custom wordlist from discovered endpoints and historical URLs",
            worker_specialty="recon",
            tools=[],
            budget=5,
            timeout_s=15,
            context={
                "scan_id": scan_id,
                "entities": [
                    {"kind": e.kind, "label": e.label}
                    for e in phases.state.all_entities
                    if e.kind in ("crawled_endpoint", "historical_url") and hasattr(e, "label")
                ],
                "output_path": str(artifacts.raw_dir / "custom_wordlist.txt"),
            },
        ))
        wl = artifacts.raw_dir / "custom_wordlist.txt"
        if wl_result.status == "completed" and wl.exists():
            pass  # wordlist file written by worker
        else:
            # Fallback: inline wordlist from entities
            wl_paths = [e.label for e in phases.state.all_entities
                        if e.kind in ("crawled_endpoint", "historical_url") and hasattr(e, "label")]
            wl.write_text(os.linesep.join(sorted(set(wl_paths))), encoding="utf-8")
        cmds = planner.discovery_commands(scope, artifacts.raw_dir, live, wl)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        phases.complete_phase(ReconPhase.DISCOVERY, parsed)

    async def _run_phase_api(self, phases, planner, runner, artifacts, rag,
                              entities, scan_id, scope, tools_run, tools_skipped):
        from backend.agents.alpha_recon.models import ReconPhase
        live = list(set(phases.state.http_services))[:20]
        if not live:
            phases.skip_phase(ReconPhase.API, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.API)
        await self._emit_status(scan_id, "phase_api_started", {})
        # Delegate schema discovery to worker (OpenAPI/Swagger/GraphQL introspection)
        try:
            sd_result = await self._delegation_mgr.spawn(ChildSpec(
                agent_class="AlphaAgent",
                objective=f"Discover API schemas on {len(live)} live services: probe OpenAPI, Swagger, GraphQL introspection",
                worker_specialty="recon",
                tools=["httpx"],
                budget=15,
                timeout_s=30,
                context={"scan_id": scan_id, "live_services": live[:20]},
            ))
            if sd_result.status == "completed" and sd_result.findings:
                schema_entities = []
                for finding in sd_result.findings:
                    if isinstance(finding, dict):
                        schema_entities.append(ParsedEntity(
                            kind=finding.get("kind", "api_endpoint"),
                            label=finding.get("url", ""),
                            source_tool="schema_discovery",
                            source_ref=SourceRef(tool="schema_discovery", phase="api_reconnaissance"),
                        ))
                if schema_entities:
                    try:
                        await entities.ingest_entities(schema_entities)
                    except Exception as ie:
                        logger.warning(f"Schema entity ingest failed: {ie}")
                    tools_run.append("schema_discovery")
                    await rag.ingest_tool_summary("schema_discovery",
                        {"schemas_found": len(schema_entities)})
        except Exception as sd_exc:
            logger.warning(f"Schema discovery delegation failed: {sd_exc}")
        cmds = planner.api_commands(scope, artifacts.raw_dir, live)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        phases.complete_phase(ReconPhase.API, parsed)

    async def _run_phase_visual(self, phases, planner, runner, artifacts, rag,
                                 entities, scan_id, scope, tools_run, tools_skipped):
        from backend.agents.alpha_recon.models import ReconPhase
        live = list(set(phases.state.http_services))[:100]
        if not live:
            phases.skip_phase(ReconPhase.VISUAL, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.VISUAL)
        cmds = planner.visual_commands(scope, artifacts.raw_dir, live)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        phases.complete_phase(ReconPhase.VISUAL, parsed)

    async def _run_phase_validation(self, phases, planner, runner, artifacts, rag,
                                     entities, scan_id, scope, tools_run, tools_skipped):
        from backend.agents.alpha_recon.models import ReconPhase
        live = list(set(phases.state.http_services))[:200]
        if not live:
            phases.skip_phase(ReconPhase.VALIDATION, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.VALIDATION)
        await self._emit_status(scan_id, "phase_validation_started", {})
        cmds = planner.validation_commands(scope, artifacts.raw_dir, live,
            phases.state.interactsh_url)
        parsed = await self._run_and_parse(cmds, runner, artifacts, rag, scan_id,
            tools_run, tools_skipped, pr, entities=entities)
        phases.complete_phase(ReconPhase.VALIDATION, parsed)

    # ── Core Helpers ──────────────────────────────────────────────

    async def _run_and_parse(self, cmds, runner, artifacts, rag, scan_id,
                              tools_run, tools_skipped, phase_result,
                              entities=None) -> list[ParsedEntity]:
        """Run commands and parse their outputs through the parser registry.

        When ``entities`` (an :class:`EntityEngine`) is supplied, every parsed
        :class:`ParsedEntity` is also pushed into the engine for persistence,
        deduplication, and graph linking. Without this hop the orchestrator
        previously logged "0 entities" for every phase even when tools wrote
        thousands of bytes — the parsed list was returned but never persisted.
        """
        all_parsed: list[ParsedEntity] = []
        ext_tools_enabled = getattr(settings, "ALPHA_ENABLE_EXTERNAL_TOOLS", False)

        for cmd in cmds:
            avail = check_tool_availability(cmd.tool_name)
            if not avail.get("installed") or not ext_tools_enabled:
                tools_skipped.append(ToolSkip(name=cmd.tool_name, phase=cmd.phase,
                    reason="not_installed" if not avail.get("installed") else "external_tools_disabled"))
                phase_result.tools_skipped.append(
                    ToolSkip(name=cmd.tool_name, phase=cmd.phase, reason="unavailable"))
                continue

            try:
                result = await runner.execute(cmd, scan_id=scan_id, agent=self.agent_name)
                tools_run.append(cmd.tool_name)
                phase_result.tools_run.append(cmd.tool_name)

                # Register raw output
                if cmd.output_path.exists():
                    await artifacts.register(cmd.output_path, tool_name=cmd.tool_name,
                        artifact_type="raw_output", scan_id=scan_id)

                # Parse through registry — with a multi-source fallback. Many
                # recon tools write their actionable JSON/XML to a SECONDARY
                # path (ffuf -o, nmap -oX, whatweb --log-json, wafw00f -o,
                # arjun -oJ). Prefer the secondary file, then fall back to the
                # stdout artifact, then to a same-stem `.json/.jsonl/.xml`
                # sibling that some tools emit by convention.
                parser = PARSER_REGISTRY.get(cmd.tool_name)
                parse_path = cmd.output_path
                json_alt = cmd.metadata.get("json_file")
                xml_alt = cmd.metadata.get("xml_file")
                if json_alt and Path(json_alt).exists() and Path(json_alt).stat().st_size > 0:
                    parse_path = Path(json_alt)
                elif xml_alt and Path(xml_alt).exists() and Path(xml_alt).stat().st_size > 0:
                    parse_path = Path(xml_alt)
                elif (not parse_path.exists() or parse_path.stat().st_size == 0):
                    # Last-resort sibling lookup for tools whose stdout is empty
                    # but who wrote a typed sibling (gowitness.json, etc).
                    for ext in (".json", ".jsonl", ".xml"):
                        sib = parse_path.with_suffix(ext)
                        if sib.exists() and sib.stat().st_size > 0:
                            parse_path = sib
                            break

                if parser and parse_path.exists() and parse_path.stat().st_size > 0:
                    try:
                        parsed = parser(parse_path)
                        if parsed:
                            all_parsed.extend(parsed)
                            if entities is not None:
                                try:
                                    await entities.ingest_entities(parsed)
                                except Exception as ie:
                                    logger.warning(
                                        f"Entity ingest failed for {cmd.tool_name}: {ie}")
                            phase_result.entities_produced += len(parsed)
                        await rag.ingest_tool_summary(cmd.tool_name,
                            {"entities": len(parsed), "phase": cmd.phase,
                             "parsed_from": str(parse_path)})
                    except Exception as pe:
                        logger.warning(f"Parser failed for {cmd.tool_name}: {pe}")
                        phase_result.errors.append(f"parse_error:{cmd.tool_name}:{pe}")
                else:
                    # Useful telemetry: tool ran but produced nothing the parser
                    # could see. Keeps the registry honest about coverage gaps.
                    logger.info("[Alpha] %s produced no parseable output (%s)",
                                cmd.tool_name, parse_path)

            except Exception as exc:
                logger.warning(f"Tool {cmd.tool_name} failed: {exc}")
                phase_result.errors.append(f"exec_error:{cmd.tool_name}:{exc}")
                tools_skipped.append(ToolSkip(name=cmd.tool_name, phase=cmd.phase,
                    reason=f"exec_failed:{exc}"))

        return all_parsed

    async def _inventory_tools(self, mode, tools_skipped, rag):
        """Check which tools are available on this system."""
        inventory = {}
        for name, spec in RECON_TOOLS.items():
            avail = check_tool_availability(name)
            inventory[name] = avail
        await rag.ingest_tool_summary("tool_inventory", inventory)

    def _compile_scope(self, target_url: str, mode: ScanMode) -> ReconScope:
        parsed = urlparse(target_url)
        domain = (parsed.hostname or "").lower()
        # When user explicitly fires a scan from the UI, private/local targets
        # are implicitly authorized — the user chose to scan them.
        # `host.docker.internal` is Docker Desktop's loopback alias (resolves to
        # the host machine), so it is semantically equivalent to localhost and
        # must be treated as locally authorized too.
        is_local = domain in ("localhost", "127.0.0.1", "0.0.0.0", "::1",
                              "host.docker.internal", "host.containers.internal",
                              "gateway.docker.internal") or \
                   domain.startswith("192.168.") or domain.startswith("10.") or \
                   domain.startswith("172.16.") or domain.endswith(".local") or \
                   domain.endswith(".internal")
        return ReconScope(
            base_domain=domain, target_url=target_url, scan_mode=mode,
            base_url=f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else target_url,
            max_depth=3 if mode == ScanMode.AGGRESSIVE else 2,
            max_rps=200 if mode == ScanMode.AGGRESSIVE else 50,
            explicit_authorization=is_local,
        )

    def _coerce_mode(self, val) -> ScanMode:
        if isinstance(val, ScanMode): return val
        try: return ScanMode(str(val).upper())
        except (ValueError, KeyError): return ScanMode.STANDARD

    async def _http_probe(self, target_url: str, scan_id: str) -> list[HTTPServiceFinding]:
        """Internal scoped HTTP probe used even when external tools are disabled."""
        common_paths = [
            "", "/api", "/api/v1", "/api/v2", "/api/health", "/api/status",
            "/swagger", "/swagger.json", "/docs", "/openapi.json", "/api-docs",
            "/graphql", "/admin", "/login", "/auth", "/token",
            "/users", "/user", "/account", "/profile", "/settings",
            "/orders", "/order", "/cart", "/payment", "/checkout",
            "/products", "/items", "/search", "/export",
            "/robots.txt", "/sitemap.xml", "/.env", "/config",
            "/wp-admin", "/wp-login.php", "/.git/config",
        ]
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}".rstrip("/")
        services: list[HTTPServiceFinding] = []
        async def probe(path: str) -> None:
            url = normalize_url(urljoin(base_url + "/", path.lstrip("/")))
            try:
                record = await http_client.request("GET", url, scan_id=scan_id, timeout=10)
                headers = {str(k): str(v) for k, v in record.response_headers.items()}
                services.append(HTTPServiceFinding(
                    url=url,
                    status_code=record.status,
                    response_time_ms=record.elapsed_ms,
                    content_type=headers.get("Content-Type", headers.get("content-type", "")),
                    content_length=len(record.response_body or ""),
                    server=headers.get("Server", headers.get("server", "")),
                    server_header=headers.get("Server", headers.get("server", "")),
                    technologies=self._detect_tech(headers, record.response_body),
                    source="alpha_http",
                    response_hash=self._hash_body(record.response_body),
                    headers=headers,
                    body_preview=(record.response_body or "")[:500],
                ))
            except ScopeViolation:
                await self.bus.publish(HiveEvent(
                    type=EventType.SCOPE_VIOLATION,
                    source=self.agent_name,
                    scan_id=scan_id,
                    payload={"url": url, "reason": "out_of_scope"},
                ))
            except Exception as probe_exc:
                logger.debug(f"[Alpha] HTTP probe failed for {url}: {probe_exc}")

        await asyncio.gather(*(probe(path) for path in common_paths))
        return services

    def _service_to_endpoint(self, svc: HTTPServiceFinding) -> EndpointFinding:
        parsed = urlparse(svc.url)
        endpoint_type, risk = classify_path(parsed.path)
        params = [
            ParameterFinding(name=name, location="query", value_type=self._infer_type(value), examples=[value] if value else [])
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return EndpointFinding(
            url=svc.url, method="GET", status_code=svc.status_code,
            content_type=svc.content_type, path=parsed.path or "/",
            normalized_path=parsed.path or "/",
            host=(parsed.hostname or "").lower(),
            technologies=svc.technologies, server=svc.server,
            server_header=svc.server_header,
            content_length=svc.content_length,
            response_time_ms=svc.response_time_ms,
            parameters=params,
            auth_required=svc.status_code in {401, 403},
            endpoint_type=endpoint_type,
            risk_class=risk,
            source="alpha_http",
            baseline_response_hash=svc.response_hash,
            evidence={"headers": svc.headers, "body_preview": svc.body_preview},
            sources=[SourceRef(tool="http_probe", phase="http_browser_intelligence",
                               confidence=0.9)])

    def _dedupe_and_sort(self, eps: list[EndpointFinding]) -> list[EndpointFinding]:
        seen: set[str] = set()
        unique = []
        for ep in eps:
            key = normalize_endpoint_key(ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        unique.sort(key=lambda e: e.priority_score, reverse=True)
        return unique

    def _summarize(self, endpoints, state, entities) -> ReconRunSummary:
        return ReconRunSummary(
            total_endpoints=len(endpoints),
            total_subdomains=len(state.subdomains),
            total_ips=len(state.ips),
            total_open_ports=sum(len(p) for p in state.open_ports.values()),
            total_js_files=len(state.js_files),
            total_parameters=len(state.parameters),
            total_secrets=len(state.secrets),
            total_vulns=len(state.vulnerability_candidates),
            attack_surface_stats=entities.get_attack_surface_stats(),
        )

    def _build_failed_result(self, scan_id: str, target_url: str, scan_mode,
                              started: float, reason: str,
                              *, tools_run: list[str] | None = None,
                              tools_skipped: list | None = None,
                              attack_surface: list | None = None,
                              artifacts=None, summary=None,
                              state=None, entities=None) -> ReconRunResult:
        """Build a minimal ``ReconRunResult`` for the failure path.

        Used by the run() ``finally`` to guarantee a RECON_COMPLETE event even
        when a phase blew up before the normal summary was assembled. Whatever
        partial entities/endpoints were collected are preserved so downstream
        consumers (Beta, planner) at least see the attack surface that did get
        discovered.
        """
        try:
            if summary is None and state is not None and entities is not None:
                summary = self._summarize(attack_surface or [], state, entities)
        except Exception as summarize_exc:
            logger.debug(f"[Alpha] summary build failed: {summarize_exc}")
            summary = None
        if summary is None:
            summary = ReconRunSummary(
                total_endpoints=len(attack_surface or []),
                attack_surface_stats={"orchestrator_error": 1},
            )
        else:
            try:
                stats = dict(summary.attack_surface_stats or {})
                stats["orchestrator_error"] = stats.get("orchestrator_error", 0) + 1
                summary = summary.model_copy(update={"attack_surface_stats": stats})
            except Exception as stats_exc:
                logger.debug(f"[Alpha] stats update failed: {stats_exc}")
        return ReconRunResult(
            scan_id=scan_id, target=target_url,
            mode=scan_mode if isinstance(scan_mode, ScanMode) else self._coerce_mode(scan_mode),
            duration_seconds=int(time.time() - started), summary=summary,
            attack_surface=attack_surface or [], tools_run=tools_run or [],
            tools_skipped=tools_skipped or [],
            raw_data_path=str(artifacts.raw_dir) if artifacts else "",
            screenshots_path=str(artifacts.screenshots_dir) if artifacts else "",
            artifact_manifest_path=str(artifacts.manifest_path) if artifacts else "",
        )

    async def _emit_status(self, scan_id, status, data):
        try:
            event = HiveEvent(type=EventType.AGENT_STATUS,
                source=self.agent_name, scan_id=scan_id,
                payload={"agent": "alpha", "phase": status, **data})
            await self.bus.publish(event)
        except Exception as exc:
            logger.debug(f"[Alpha] Status emit failed: {exc}")

    async def _emit_recon_packet(self, scan_id, ep):
        try:
            event = HiveEvent(type=EventType.RECON_PACKET,
                source=self.agent_name, scan_id=scan_id,
                payload=ep.model_dump(mode="json"))
            await self.bus.publish(event)
        except Exception as exc:
            logger.debug(f"[Alpha] Recon packet emit failed: {exc}")

    async def _emit_complete(self, result):
        try:
            event = HiveEvent(type=EventType.RECON_COMPLETE,
                source=self.agent_name, scan_id=result.scan_id,
                payload=result.model_dump(mode="json"))
            await self.bus.publish(event)
        except Exception as exc:
            logger.error(f"[Alpha] Complete emit failed: {exc}")

    def _detect_tech(self, headers: dict[str, str], body: str) -> list[str]:
        tech: set[str] = set()
        server = headers.get("Server") or headers.get("server") or ""
        powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
        for value in [server, powered]:
            if value:
                tech.add(value.split(";", 1)[0].strip())
        lower = (body or "").lower()
        if "swagger" in lower or "openapi" in lower:
            tech.add("OpenAPI")
        if "graphql" in lower:
            tech.add("GraphQL")
        if "wp-content" in lower:
            tech.add("WordPress")
        return sorted(tech)

    def _infer_type(self, value: str) -> str:
        if re.fullmatch(r"[0-9]+", value or ""):
            return "numeric"
        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", value or ""):
            return "uuid"
        return "string"

    def _hash_body(self, body: str) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()

AlphaV6DeepOrchestrator = AlphaOrchestrator
AlphaV6ReconOrchestrator = AlphaOrchestrator
# Architecture §5.1.1 / §24 step 8: the unified recon commander name.
AlphaUnifiedReconCommander = AlphaOrchestrator
