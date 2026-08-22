"""Alpha V6 Deep Recon Orchestrator — Full Multi-Phase Pipeline."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse

from backend.agents.alpha_recon.artifacts import ArtifactStore
from backend.agents.alpha_recon.dedupe import SeenSet, classify_path, normalize_endpoint_key, normalize_url
from backend.agents.alpha_recon.entity_engine import EntityEngine
from backend.agents.alpha_recon.interactsh_adapter import InteractshAdapter
from backend.agents.alpha_recon.live_feed import recon_live_feed
from backend.agents.alpha_recon.models import (
    EndpointFinding,
    HTTPServiceFinding,
    ParameterFinding,
    ReconRunResult,
    ReconRunSummary,
    ReconScope,
    ScanMode,
    SourceRef,
    ToolSkip,
)
from backend.agents.alpha_recon.phase_controller import PhaseController
from backend.agents.alpha_recon.pinchtab_intel import PinchTabIntelligence
from backend.agents.alpha_recon.rag import ReconRAGPipeline
from backend.agents.alpha_recon.scope_gate import ScopeGate, ScopeGateViolation
from backend.agents.alpha_recon.scoring import score_endpoint
from backend.core.config import settings
from backend.core.database import db_manager
from backend.core.delegation_manager import ChildSpec, DelegationManager
from backend.core.hive import EventType, HiveEvent
from backend.core.scope import ScopePolicy, ScopeViolation
from backend.core.telemetry import telemetry
from backend.modules.tech.http_client import http_client
from backend.parsers.recon import PARSER_REGISTRY
from backend.parsers.recon.base import ParsedEntity
from backend.tools.recon import RECON_TOOLS, ReconCommandPlanner, ReconCommandRunner, check_tool_availability

logger = logging.getLogger("alpha")


import functools


@functools.lru_cache(maxsize=1)
def _container_has_chrome() -> bool | None:
    """True when the recon container ships a chrome-family browser (cached).

    None = unknown (no container or probe failed) — callers then let the tool
    try rather than pre-emptively skipping it.
    """
    try:
        import subprocess as _sp

        from backend.tools.recon.docker_runtime import running_recon_container

        c = running_recon_container()
        if not c:
            return None
        p = _sp.run(
            [
                "docker", "exec", c, "sh", "-lc",
                "command -v google-chrome chromium chromium-browser >/dev/null 2>&1 && echo yes",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return p.returncode == 0 and "yes" in (p.stdout or "")
    except Exception:
        return None



class AlphaOrchestrator:
    """Production-grade multi-phase recon orchestrator."""

    def __init__(
        self, bus, *, agent_name: str = "agent_alpha", browser=None, browser_provider=None, delegation_mgr=None
    ):
        self.bus = bus
        self.agent_name = agent_name
        self._scan_mode = None
        self._enable_external_tools: bool | None = None
        self._seen_packets = SeenSet()
        self._delegation_mgr = delegation_mgr or DelegationManager()
        # Auth-first session: the seeder's authenticated Cookie, once obtained
        # after the HTTP phase, is forwarded to discovery + validation tools so
        # login-gated apps (DVWA) are enumerated authenticated instead of being
        # walled behind a 302 redirect.
        self._auth_cookie: str = ""
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

    async def run(
        self,
        target_url: str,
        *,
        scan_id: str = "GLOBAL",
        mode: str | ScanMode | None = None,
        enable_external_tools: bool | None = None,
    ) -> ReconRunResult:
        started = time.time()
        scan_mode = self._coerce_mode(mode or getattr(settings, "ALPHA_DEFAULT_MODE", "STANDARD"))
        # Expose the active mode to phase helpers (dedupe is mode-aware:
        # AGGRESSIVE runs every tool).
        self._scan_mode = scan_mode
        # Per-scan override for the external-tools gate (recon API request can
        # opt into the full 39-tool arsenal even when the env default is off).
        self._enable_external_tools = (
            enable_external_tools
            if enable_external_tools is not None
            else bool(getattr(settings, "ALPHA_ENABLE_EXTERNAL_TOOLS", False))
        )
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
                await self._emit_complete(
                    self._build_failed_result(scan_id, target_url, scan_mode, started, f"scope_rejected:{exc}")
                )
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

        # Clear stale Docker caches so availability is re-checked per scan.
        # Without this, a False result cached at import time persists forever.
        from backend.tools.recon.docker_runtime import reset_container_cache

        reset_container_cache()

        await db_manager.initialize()
        await db_manager.create_recon_run(
            scan_id=scan_id,
            target=target_url,
            mode=scan_mode.value,
            scope=scope.model_dump(mode="json"),
            artifact_root=str(artifacts.root),
            status="running",
        )
        # Local durable mirror (best-effort): Supabase is the source of truth,
        # but the local SQLite scan_state_db keeps a record even when the cloud
        # is unreachable (Architecture §5.6). Never blocks recon.
        try:
            from backend.core.scan_state_db import scan_state_db

            scan_state_db.upsert_scan(
                scan_id=scan_id,
                target=target_url,
                mode=scan_mode.value,
                phase="initialization",
                status="running",
                authorized=bool(getattr(scope, "authorized", False)),
                meta={"artifact_root": str(artifacts.root)},
            )
        except Exception as _local_db_exc:
            logger.debug("[Alpha] local scan-state persist failed: %s", _local_db_exc)

        await recon_live_feed.on_phase_started(scan_id, "initialization")
        await self._emit_status(scan_id, "initialized", {"target": target_url, "mode": scan_mode.value})
        await rag.ingest_tool_summary("alpha_scope", {"target": target_url, "mode": scan_mode.value})

        try:
            with telemetry.span("alpha.recon", kind="agent", scan_id=scan_id):
                # Phase: Tool Inventory
                await self._inventory_tools(scan_mode, tools_skipped, rag)

                # Phase 1: Passive Intelligence
                if phases.should_run(phases.PHASE_ORDER[1]):
                    await self._run_phase_passive(
                        phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
                    )

                # Phase 2: DNS & Infrastructure
                if phases.should_run(phases.PHASE_ORDER[2]):
                    await self._run_phase_dns(
                        phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped,
                        target_url=target_url,
                    )

                # Phase 3: HTTP & Browser Intelligence
                # Auth-first: authenticate the target before crawling/discovery so
                # every downstream tool (katana/gospider/feroxbuster/nuclei) sees
                # the real app instead of the login wall on login-gated targets.
                if self._enable_external_tools:
                    try:
                        from backend.core.attack_surface_seeder import authenticate_attack_session

                        self._auth_cookie = (
                            await asyncio.wait_for(
                                authenticate_attack_session(target_url, scan_id), timeout=30
                            )
                            or ""
                        )
                        if self._auth_cookie:
                            await self._emit_status(scan_id, "auth_first_authenticated", {"cookie": True})
                    except Exception as auth_exc:
                        logger.debug(f"[Alpha] auth-first failed: {auth_exc}")
                if phases.should_run(phases.PHASE_ORDER[3]):
                    await self._run_phase_http(
                        phases,
                        planner,
                        runner,
                        artifacts,
                        rag,
                        entities,
                        scan_id,
                        scope,
                        target_url,
                        tools_run,
                        tools_skipped,
                        endpoints,
                    )

                # Phase 4: Directory & Route Discovery
                if phases.should_run(phases.PHASE_ORDER[4]):
                    await self._run_phase_discovery(
                        phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
                    )

                # Phase 5: API Reconnaissance
                if phases.should_run(phases.PHASE_ORDER[5]):
                    await self._run_phase_api(
                        phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
                    )

                # Phase 6: Visual Documentation
                if phases.should_run(phases.PHASE_ORDER[6]):
                    await self._run_phase_visual(
                        phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
                    )

                # Phase 7: Template Validation
                if phases.should_run(phases.PHASE_ORDER[7]):
                    await self._run_phase_validation(
                        phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
                    )

                # Stop Interactsh and collect OOB findings
                oob_interactions = await interactsh.stop()
                if oob_interactions:
                    tools_run.append("interactsh")
                    oob_parsed: list[ParsedEntity] = []
                    for oob in oob_interactions:
                        oob_parsed.append(
                            ParsedEntity(
                                kind="oob_interaction",
                                label=oob.get("interaction_type", "unknown"),
                                confidence=0.9,
                                source_tool="interactsh",
                                phase="template_validation",
                                properties=oob.get("raw", {}),
                            )
                        )
                    if oob_parsed:
                        try:
                            await entities.ingest_entities(oob_parsed)
                        except Exception as ie:
                            logger.warning(f"OOB ingest failed: {ie}")

                # Final: Correlation & Scoring
                # Merge ALL discovered endpoints into the attack surface. Only
                # the internal-probe results made the cut before — crawler,
                # browser-engine, and API-recon discoveries (accumulated in
                # state.all_entities) were silently excluded. Convert every
                # endpoint-ish entity to a scored EndpointFinding.
                for _e in phases.state.all_entities:
                    if _e.kind in (
                        "browser_endpoint",
                        "websocket",
                        "javascript_route",
                        "api_endpoint",
                        "api_route",
                        "crawled_endpoint",
                        "discovered_path",
                        "endpoint",
                        "form",
                        "form_action",
                    ):
                        _ep = self._entity_to_endpoint(_e)
                        if _ep is not None:
                            endpoints.append(score_endpoint(_ep))
                endpoints = self._dedupe_and_sort(endpoints)
                summary = self._summarize(endpoints, phases.state, entities)
                result = ReconRunResult(
                    scan_id=scan_id,
                    target=target_url,
                    mode=scan_mode,
                    duration_seconds=int(time.time() - started),
                    summary=summary,
                    attack_surface=endpoints,
                    tools_run=tools_run,
                    tools_skipped=tools_skipped,
                    raw_data_path=str(artifacts.raw_dir),
                    screenshots_path=str(artifacts.screenshots_dir),
                    artifact_manifest_path=str(artifacts.manifest_path),
                )
        except asyncio.CancelledError:
            logger.warning("[Alpha] run cancelled for scan %s", scan_id)
            raise
        except Exception as exc:
            # A phase blew up — build a failed result so the orchestrator still
            # gets a terminal RECON_COMPLETE event with whatever entities were
            # accumulated. Without this the safety timeout would fire 180s later.
            logger.exception("[Alpha] run aborted for scan %s: %s", scan_id, exc)
            # Persist the failure durably (local scan_state_db.run_errors) so
            # it survives the terminal window that previously swallowed the
            # traceback.
            try:
                import traceback as _tb

                from backend.core.scan_state_db import scan_state_db

                scan_state_db.record_run_error(
                    scan_id,
                    phase=str(getattr(phases, "_current_phase", "") or ""),
                    error_type=exc.__class__.__name__,
                    message=str(exc),
                    traceback=_tb.format_exc(),
                )
            except Exception as _err_persist_exc:
                logger.debug("[Alpha] run-error persist failed: %s", _err_persist_exc)
            try:
                await interactsh.stop()
            except Exception as cleanup_exc:
                logger.debug(f"[Alpha] interactsh cleanup failed: {cleanup_exc}")
            result = self._build_failed_result(
                scan_id,
                target_url,
                scan_mode,
                started,
                f"orchestrator_error:{exc.__class__.__name__}:{exc}",
                tools_run=tools_run,
                tools_skipped=tools_skipped,
                attack_surface=endpoints,
                artifacts=artifacts,
                summary=None,
                state=phases.state,
                entities=entities,
            )
        finally:
            # ALWAYS publish RECON_COMPLETE so downstream agents and the safety
            # timeout never have to guess. Best-effort across all sub-steps so a
            # late failure in artifact write or db.finish_recon_run cannot
            # swallow the event.
            try:
                if result is None:
                    result = self._build_failed_result(
                        scan_id,
                        target_url,
                        scan_mode,
                        started,
                        "orchestrator_no_result",
                        tools_run=tools_run,
                        tools_skipped=tools_skipped,
                        attack_surface=endpoints,
                        artifacts=artifacts,
                        state=phases.state,
                        entities=entities,
                    )
            except Exception as fb_exc:
                logger.error("[Alpha] failed to build fallback result: %s", fb_exc)
                result = None

            if result is not None:
                # Persist & broadcast best-effort. Each step is in its own
                # try/except so a single failure (e.g. db unreachable) cannot
                # block the RECON_COMPLETE publish.
                try:
                    await artifacts.write_json(
                        "exports/recon_complete.json",
                        result.model_dump(mode="json"),
                        tool_name="alpha",
                        artifact_type="recon_complete",
                        scan_id=scan_id,
                    )
                except Exception as exc:
                    logger.warning("[Alpha] artifact export failed: %s", exc)
                try:
                    final_status = (
                        "failed"
                        if (result.summary.attack_surface_stats or {}).get("orchestrator_error")
                        else "completed"
                    )
                    await asyncio.wait_for(
                        db_manager.finish_recon_run(scan_id=scan_id, status=final_status), timeout=15
                    )
                except Exception as exc:
                    logger.warning("[Alpha] finish_recon_run failed/slow: %s", exc)
                # Mirror the terminal status to the local SQLite scan record.
                try:
                    from backend.core.scan_state_db import scan_state_db

                    scan_state_db.upsert_scan(
                        scan_id=scan_id,
                        target=target_url,
                        mode=scan_mode.value,
                        phase="completed",
                        status=final_status,
                        authorized=bool(getattr(scope, "authorized", False)),
                        meta={"artifact_root": str(artifacts.root), "error": result.error or ""},
                    )
                except Exception as _local_finish_exc:
                    logger.debug("[Alpha] local scan-state finish failed: %s", _local_finish_exc)
                try:
                    await recon_live_feed.on_scan_complete(
                        scan_id, result.summary.model_dump() if result.summary else {}
                    )
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
                        scan_id, target_url, scan_mode, started, "emit_complete_fallback"
                    )
                    await self._emit_complete(minimal)
                except Exception as exc:
                    logger.error("[Alpha] absolute fallback emit failed: %s", exc)

        return result

    # ── Phase Implementations ─────────────────────────────────────

    async def _run_phase_passive(
        self, phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
    ):
        from backend.agents.alpha_recon.models import ReconPhase

        pr = phases.start_phase(ReconPhase.PASSIVE)
        await self._emit_status(scan_id, "phase_passive_started", {})
        cmds = planner.passive_commands(scope, artifacts.raw_dir)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        phases.complete_phase(ReconPhase.PASSIVE, parsed)

    async def _run_phase_dns(
        self, phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped,
        target_url: str = "",
    ):
        from urllib.parse import urlparse

        from backend.agents.alpha_recon.models import ReconPhase

        # Local/IP lab targets (localhost, 127.0.0.1, *.local) have no subdomains,
        # but port/TLS scanning against the seeded target is still valuable
        # (nmap/naabu on a single-host lab). Mirror the HTTP phase's seeding so
        # INFRA tools get a real host; skip only the DNS-resolution tools
        # (dnsx/cdncheck), which are meaningless without subdomains.
        seeded_target = False
        explicit_port = None
        if not phases.state.subdomains and not phases.state.ips:
            tp = urlparse(target_url if "://" in target_url else f"http://{target_url}")
            host = (tp.hostname or "").strip().lower()
            if not host:
                phases.skip_phase(ReconPhase.INFRA, "no_target_seeded")
                return
            seed = f"{host}:{tp.port}" if tp.port else host
            phases.state.subdomains.add(seed)
            phases.state.ips.add(host)  # bare host for nmap/naabu -iL lists
            explicit_port = tp.port
            seeded_target = True

        pr = phases.start_phase(ReconPhase.INFRA)
        await self._emit_status(
            scan_id,
            "phase_dns_started",
            {"subs": len(phases.state.subdomains), "seeded": seeded_target, "explicit_port": explicit_port},
        )
        hosts_file = phases.state.build_hosts_file(artifacts.raw_dir)
        cmds = planner.port_commands(scope, artifacts.raw_dir, hosts_file, explicit_port=explicit_port)
        cmds += planner.tls_commands(scope, artifacts.raw_dir, hosts_file, explicit_port=explicit_port)
        if not seeded_target:
            sub_file = phases.state.build_subdomain_file(artifacts.raw_dir)
            cmds += planner.dns_commands(scope, artifacts.raw_dir, sub_file)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        phases.complete_phase(ReconPhase.INFRA, parsed)

        # Second-wave TLS audit: tlsx in the first batch ran in PARALLEL with
        # the port scanners, so it only ever saw bare hosts (80/443). Now that
        # nmap/naabu results are in state.open_ports, re-run tlsx against the
        # derived host:port targets so TLS on discovered ports (8443, 8080, ...)
        # is audited too. Cheap (tlsx is fast) and intelligence-driven. Only
        # tlsx — testssl already ran in the first wave and must NOT be doubled.
        if not seeded_target and phases.state.open_ports:
            tls2 = [
                c
                for c in planner.tls_commands(
                    scope, artifacts.raw_dir, phases.state.build_http_targets(artifacts.raw_dir)
                )
                if c.tool_name == "tlsx"
            ]
            if tls2:
                parsed += await self._run_and_parse(
                    tls2, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
                )

    async def _run_phase_http(
        self,
        phases,
        planner,
        runner,
        artifacts,
        rag,
        entities,
        scan_id,
        scope,
        target_url,
        tools_run,
        tools_skipped,
        endpoints,
    ):
        from backend.agents.alpha_recon.models import ReconPhase

        pr = phases.start_phase(ReconPhase.HTTP)
        await self._emit_status(scan_id, "phase_http_started", {})
        # The lab port must always reach httprobe — even when the INFRA phase
        # already seeded the target (localhost:8888) — otherwise httprobe
        # silently reverts to probing only 80/443 on the real pipeline.
        _tp = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        explicit_port = _tp.port
        # Seed the hosts file with the scoped target BEFORE building the HTTP
        # commands so httpx/whatweb/wafw00f/katana actually have something to
        # scan on single-target lab runs (localhost:8080) where no passive/DNS
        # phase ran and the discovered subdomain set is empty. Without this,
        # every Phase 3 tool gets an empty -l file and exits with 0 bytes —
        # which is exactly what produced the "0 entities" symptom.
        if not phases.state.subdomains and not phases.state.ips:
            host = (_tp.hostname or "").strip().lower()
            if host:
                seed = f"{host}:{_tp.port}" if _tp.port else host
                phases.state.subdomains.add(seed)
                phases.state.ips.add(host)  # for the broader hosts_file
        # Intelligence-driven targeting: the INFRA phase's nmap/naabu findings
        # (state.open_ports) become explicit host:port probes so httpx/katana/
        # gospider see services off the default web ports, not just 80/443.
        targets_file = phases.state.build_http_targets(artifacts.raw_dir)
        cmds = planner.http_commands(
            scope, artifacts.raw_dir, targets_file, explicit_port=explicit_port, cookie=getattr(self, "_auth_cookie", "")
        )
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
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
            logger.info("[Alpha] Seeded %d live HTTP service(s) from internal probe.", len(live_seeded))
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
                tools_skipped.append(
                    ToolSkip(name="pinchtab", phase="http_browser_intelligence", reason=pt_result["reason"])
                )
        # Browser-engine deep recon (ScraplingRecon via BrowserOrchestrator):
        # endpoints, network intercept, WebSockets, SPA routes, forms, cookies,
        # security headers. Runs after external tools + PinchTab on the
        # highest-value live targets. Entities flow into state + engine.
        if self.browser is not None:
            try:
                from backend.core.browser_engine import ScraplingRecon

                _br = ScraplingRecon(self.browser, scan_id, agent_name=self.agent_name)
                _br_targets = [e.url for e in endpoints if e.priority_score >= 45][:10]
                _br_targets += [u for u in phases.state.http_services[:5] if u not in _br_targets]
                _br_entities: list[ParsedEntity] = []
                for _u in list(dict.fromkeys(_br_targets))[:10]:
                    try:
                        # Bound each browser-recon pass: a hung browser (dead
                        # daemon, slow SPA) must not stall the HTTP phase.
                        for _rec in await asyncio.wait_for(_br.recon(_u), timeout=45) or []:
                            if isinstance(_rec, dict) and _rec.get("label"):
                                _br_entities.append(
                                    ParsedEntity(
                                        kind=str(_rec.get("kind", "browser_endpoint")),
                                        label=str(_rec.get("label", "")),
                                        confidence=float(_rec.get("confidence", 0.7)),
                                        properties=dict(_rec.get("properties", {}) or {}),
                                        source_tool=str(_rec.get("source_tool", "browser_recon")),
                                        phase="http_browser_intelligence",
                                    )
                                )
                    except Exception as _bre:
                        logger.debug(f"[Alpha] ScraplingRecon failed for {_u}: {_bre}")
                if _br_entities:
                    parsed.extend(_br_entities)
                    try:
                        await entities.ingest_entities(_br_entities)
                    except Exception as ie:
                        logger.warning(f"Browser recon ingest failed: {ie}")
                    tools_run.append("scrapling_recon")
                    browser_used = True
                    logger.info("[Alpha] ScraplingRecon produced %d entities.", len(_br_entities))
            except Exception as br_exc:
                logger.debug(f"[Alpha] ScraplingRecon unavailable: {br_exc}")
        # Delegate browser recon to Delta (SPA detection, JS routes, WebSocket
        # discovery) — LAST RESORT, only when the native PinchTab path AND the
        # direct ScraplingRecon engine both produced nothing.
        if not browser_used:
            try:
                br_result = await self._delegation_mgr.spawn(
                    ChildSpec(
                        agent_class="AgentDelta",
                        objective=f"Browser-aware recon on {target_url}: detect frameworks, extract JS routes, discover WebSockets, extract forms and cookies",
                        worker_specialty="browser",
                        tools=["playwright", "scrapling"],
                        budget=20,
                        timeout_s=60,
                        context={"scan_id": scan_id, "target": target_url},
                    )
                )
                if br_result.status == "completed" and br_result.findings:
                    # Parse browser recon findings into ParsedEntity objects
                    for finding in br_result.findings:
                        if isinstance(finding, dict) and "url" in finding:
                            parsed.append(
                                ParsedEntity(
                                    kind=finding.get("kind", "endpoint"),
                                    label=finding["url"],
                                    source_tool="browser_recon",
                                    source_ref=SourceRef(tool="browser_recon", phase="http_browser_intelligence"),
                                )
                            )
                    tools_run.append("browser_recon")
                    browser_used = True
            except Exception as br_exc:
                logger.debug(f"Browser recon delegation skipped: {br_exc}")
                tools_skipped.append(
                    ToolSkip(name="browser_recon", phase="http_browser_intelligence", reason=str(br_exc)[:100])
                )
        # Consolidated JS endpoint analysis — runs ONCE, after the external
        # tools AND browser engines so .js URLs found by PinchTab/ScraplingRecon
        # (network captures) also get linkfinder/secretfinder treatment.
        js_urls: list[str] = []
        for _e in parsed:
            _lab = str(getattr(_e, "label", "") or "")
            if ".js" in _lab.lower() and _lab.startswith("http"):
                js_urls.append(_lab)
            for _k in ("full_url", "url", "src", "label"):
                _v = (getattr(_e, "properties", None) or {}).get(_k, "")
                if isinstance(_v, str) and ".js" in _v.lower() and _v.startswith("http"):
                    js_urls.append(_v)
        js_cmds = planner.js_analysis_commands(scope, artifacts.raw_dir, list(dict.fromkeys(js_urls))[:50])
        if js_cmds:
            parsed += await self._run_and_parse(
                js_cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
            )
        phases.complete_phase(ReconPhase.HTTP, parsed)

    async def _run_phase_discovery(
        self, phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
    ):
        from backend.agents.alpha_recon.models import ReconPhase

        live = list(set(phases.state.http_services))[:100]
        if not live:
            phases.skip_phase(ReconPhase.DISCOVERY, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.DISCOVERY)
        # Auth-forward: the seeder cookie (auth-first) makes the content fuzzers
        # see the authenticated app instead of the 302-to-login wall.
        _cookie = getattr(self, "_auth_cookie", "")
        await self._emit_status(scan_id, "phase_discovery_started", {"hosts": len(live)})
        # Delegate wordlist building to worker
        wl_result = await self._delegation_mgr.spawn(
            ChildSpec(
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
            )
        )
        wl = artifacts.raw_dir / "custom_wordlist.txt"
        if wl_result.status == "completed" and wl.exists():
            pass  # wordlist file written by worker
        else:
            # Fallback: inline wordlist from entities
            wl_paths = [
                e.label
                for e in phases.state.all_entities
                if e.kind in ("crawled_endpoint", "historical_url") and hasattr(e, "label")
            ]
            wl.write_text(os.linesep.join(sorted(set(wl_paths))), encoding="utf-8")
        cmds = planner.discovery_commands(scope, artifacts.raw_dir, live, wl, cookie=_cookie)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        phases.complete_phase(ReconPhase.DISCOVERY, parsed)

    async def _run_phase_api(
        self, phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
    ):
        from backend.agents.alpha_recon.models import ReconPhase

        live = list(set(phases.state.http_services))[:20]
        if not live:
            phases.skip_phase(ReconPhase.API, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.API)
        await self._emit_status(scan_id, "phase_api_started", {})
        # Delegate schema discovery to worker (OpenAPI/Swagger/GraphQL introspection)
        try:
            sd_result = await self._delegation_mgr.spawn(
                ChildSpec(
                    agent_class="AlphaAgent",
                    objective=f"Discover API schemas on {len(live)} live services: probe OpenAPI, Swagger, GraphQL introspection",
                    worker_specialty="recon",
                    tools=["httpx"],
                    budget=15,
                    timeout_s=30,
                    context={"scan_id": scan_id, "live_services": live[:20]},
                )
            )
            if sd_result.status == "completed" and sd_result.findings:
                schema_entities = []
                for finding in sd_result.findings:
                    if isinstance(finding, dict):
                        schema_entities.append(
                            ParsedEntity(
                                kind=finding.get("kind", "api_endpoint"),
                                label=finding.get("url", ""),
                                source_tool="schema_discovery",
                                source_ref=SourceRef(tool="schema_discovery", phase="api_reconnaissance"),
                            )
                        )
                if schema_entities:
                    try:
                        await entities.ingest_entities(schema_entities)
                    except Exception as ie:
                        logger.warning(f"Schema entity ingest failed: {ie}")
                    tools_run.append("schema_discovery")
                    await rag.ingest_tool_summary("schema_discovery", {"schemas_found": len(schema_entities)})
        except Exception as sd_exc:
            logger.warning(f"Schema discovery delegation failed: {sd_exc}")
        cmds = planner.api_commands(scope, artifacts.raw_dir, live)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        phases.complete_phase(ReconPhase.API, parsed)

    async def _run_phase_visual(
        self, phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
    ):
        from backend.agents.alpha_recon.models import ReconPhase

        live = list(set(phases.state.http_services))[:100]
        if not live:
            phases.skip_phase(ReconPhase.VISUAL, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.VISUAL)
        cmds = planner.visual_commands(scope, artifacts.raw_dir, live)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        phases.complete_phase(ReconPhase.VISUAL, parsed)

    async def _run_phase_validation(
        self, phases, planner, runner, artifacts, rag, entities, scan_id, scope, tools_run, tools_skipped
    ):
        from backend.agents.alpha_recon.models import ReconPhase

        live = list(set(phases.state.http_services))[:200]
        if not live:
            phases.skip_phase(ReconPhase.VALIDATION, "no_live_hosts")
            return
        pr = phases.start_phase(ReconPhase.VALIDATION)
        await self._emit_status(scan_id, "phase_validation_started", {})
        cmds = planner.validation_commands(
            scope, artifacts.raw_dir, live, phases.state.interactsh_url, cookie=getattr(self, "_auth_cookie", "")
        )
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        phases.complete_phase(ReconPhase.VALIDATION, parsed)

    # ── Core Helpers ──────────────────────────────────────────────

    async def _run_and_parse(
        self, cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, phase_result, entities=None
    ) -> list[ParsedEntity]:
        """Run commands and parse their outputs through the parser registry.

        Independent tools execute in PARALLEL (bounded by ALPHA_MAX_PARALLEL_RECON)
        using the phase-local tool dependency DAG — a tool starts as soon as its
        dependencies *within the batch* complete instead of waiting for the whole
        phase to serialize (saves minutes on multi-tool phases like HTTP). Every
        tool still flows through the governed ReconCommandRunner (guardrails,
        scope, audit, artifacts), so parallelism never bypasses safety.

        When ``entities`` (an :class:`EntityEngine`) is supplied, every parsed
        :class:`ParsedEntity` is also pushed into the engine for persistence,
        deduplication, and graph linking. Without this hop the orchestrator
        previously logged "0 entities" for every phase even when tools wrote
        thousands of bytes — the parsed list was returned but never persisted.
        """
        import asyncio as _aio

        from backend.tools.recon.commands import TOOL_DEPENDENCY_GRAPH

        all_parsed: list[ParsedEntity] = []
        ext_tools_enabled = getattr(self, "_enable_external_tools", None)
        if ext_tools_enabled is None:
            ext_tools_enabled = bool(getattr(settings, "ALPHA_ENABLE_EXTERNAL_TOOLS", False))

        # 1. Keep only the tools that are actually available; record skips.
        available = []
        for cmd in cmds:
            avail = check_tool_availability(cmd.tool_name)
            if not avail.get("installed") or not ext_tools_enabled:
                reason = "not_installed" if not avail.get("installed") else "external_tools_disabled"
                tools_skipped.append(ToolSkip(name=cmd.tool_name, phase=cmd.phase, reason=reason))
                phase_result.tools_skipped.append(ToolSkip(name=cmd.tool_name, phase=cmd.phase, reason="unavailable"))
                continue
            available.append(cmd)
        if not available:
            return all_parsed

        # 2a. De-duplicate redundant tools (availability-aware keep-first-N).
        #     Same-group tools issue the SAME kind of requests; running all of
        #     them floods the target and burns budget for near-zero extra
        #     signal. Keep order is data-driven from the DVWA benchmark
        #     (e.g. gobuster out-produces ffuf on 302-redirecting apps).
        #     AGGRESSIVE mode runs EVERY tool — the user's explicit ask that
        #     all 39 arsenal tools exercise their full capabilities.
        _aggressive = getattr(self, "_scan_mode", None) == ScanMode.AGGRESSIVE
        if not _aggressive:
            _dedupe_specs = (
                ("crawler", ("katana", "gospider"), 1),
                ("dir_fuzz", ("feroxbuster", "gobuster", "ffuf"), 2),
            )
            _present = {c.tool_name for c in available}
            _keep: set[str] = set()
            for _group, _members, _n in _dedupe_specs:
                _keep.update([mm for mm in _members if mm in _present][:_n])
            _by_group = {mm: g for g, mms, _nn in _dedupe_specs for mm in mms}
            for _c in available[:]:
                if _c.tool_name in _keep or _c.tool_name not in _by_group:
                    continue
                _grp = _by_group[_c.tool_name]
                tools_skipped.append(ToolSkip(name=_c.tool_name, phase=_c.phase, reason=f"dedupe:{_grp}"))
                phase_result.tools_skipped.append(ToolSkip(name=_c.tool_name, phase=_c.phase, reason=f"dedupe:{_grp}"))
                available.remove(_c)
            if not available:
                return all_parsed

        # 2b. Chrome-gated tools (gowitness/aquatone). Skip them fast when the
        #     recon container has no chrome-family browser instead of letting
        #     each tool burn its timeout on a missing executable.
        _has_chrome = _container_has_chrome()
        if _has_chrome is False:
            for _c in available[:]:
                if _c.metadata.get("requires_chrome"):
                    tools_skipped.append(ToolSkip(name=_c.tool_name, phase=_c.phase, reason="chrome_missing"))
                    phase_result.tools_skipped.append(
                        ToolSkip(name=_c.tool_name, phase=_c.phase, reason="chrome_missing")
                    )
                    available.remove(_c)
            if not available:
                return all_parsed

        # 2. Phase-local dependency edges: a dependency on a tool NOT in this
        #    batch is already satisfied (earlier phase) and never blocks.
        names = {c.tool_name for c in available}
        deps = {
            c.tool_name: [d for d in TOOL_DEPENDENCY_GRAPH.get(c.tool_name, []) if d in names]
            for c in available
        }

        # 3. Bounded-parallel DAG scheduling.
        max_parallel = max(1, int(getattr(settings, "ALPHA_MAX_PARALLEL_RECON", "4") or "4"))
        sem = _aio.Semaphore(max_parallel)
        pending: dict[str, _aio.Task] = {}
        completed: set[str] = set()

        async def _run_one(cmd) -> list[ParsedEntity]:
            async with sem:
                return await self._execute_and_parse_one(
                    cmd, runner, artifacts, rag, scan_id, tools_run, tools_skipped, phase_result, entities
                )

        while len(completed) < len(available):
            ready = [
                c
                for c in available
                if c.tool_name not in completed
                and c.tool_name not in pending
                and all(d in completed for d in deps[c.tool_name])
            ]
            for c in ready:
                pending[c.tool_name] = _aio.create_task(_run_one(c))
            if not pending:
                # Deadlock guard — force the stragglers (should not happen).
                logger.warning("[Alpha] _run_and_parse DAG stalled; forcing remaining tools.")
                for c in available:
                    if c.tool_name not in completed and c.tool_name not in pending:
                        pending[c.tool_name] = _aio.create_task(_run_one(c))
                if not pending:
                    break
            done, _ = await _aio.wait(list(pending.values()), return_when=_aio.FIRST_COMPLETED)
            for task in done:
                name = next((n for n, t in pending.items() if t is task), None)
                if name is None:
                    continue
                try:
                    all_parsed.extend(task.result() or [])
                except Exception as exc:  # defensive — _execute_and_parse_one already guards
                    logger.warning("[Alpha] DAG task for %s raised: %s", name, exc)
                completed.add(name)
                del pending[name]

        return all_parsed

    async def _execute_and_parse_one(
        self, cmd, runner, artifacts, rag, scan_id, tools_run, tools_skipped, phase_result, entities
    ) -> list[ParsedEntity]:
        """Run one recon tool through the governed runner, then register +
        parse its output. Returns the parsed entities (possibly empty)."""
        parsed_list: list[ParsedEntity] = []
        try:
            await runner.execute(cmd, scan_id=scan_id, agent=self.agent_name)
            tools_run.append(cmd.tool_name)
            phase_result.tools_run.append(cmd.tool_name)

            # Register raw output
            if cmd.output_path.exists():
                await artifacts.register(
                    cmd.output_path, tool_name=cmd.tool_name, artifact_type="raw_output", scan_id=scan_id
                )

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
            elif not parse_path.exists() or parse_path.stat().st_size == 0:
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
                        parsed_list.extend(parsed)
                        if entities is not None:
                            try:
                                await entities.ingest_entities(parsed)
                            except Exception as ie:
                                logger.warning(f"Entity ingest failed for {cmd.tool_name}: {ie}")
                        # Promote real template-validation matches (nuclei/
                        # dalfox) to VULN_CONFIRMED so the findings API,
                        # dashboard, and report surface them — Alpha's validation
                        # phase previously produced entities only, and confirmed
                        # findings never reached the feed.
                        for _ent in parsed:
                            if _ent.kind == "vulnerability_candidate" and cmd.phase == "template_validation":
                                await self._emit_vuln_confirmed(scan_id, _ent)
                        phase_result.entities_produced += len(parsed)
                    await rag.ingest_tool_summary(
                        cmd.tool_name, {"entities": len(parsed), "phase": cmd.phase, "parsed_from": str(parse_path)}
                    )
                except Exception as pe:
                    logger.warning(f"Parser failed for {cmd.tool_name}: {pe}")
                    phase_result.errors.append(f"parse_error:{cmd.tool_name}:{pe}")
            else:
                # Useful telemetry: tool ran but produced nothing the parser
                # could see. Keeps the registry honest about coverage gaps.
                logger.info("[Alpha] %s produced no parseable output (%s)", cmd.tool_name, parse_path)

        except Exception as exc:
            logger.warning(f"Tool {cmd.tool_name} failed: {exc}")
            phase_result.errors.append(f"exec_error:{cmd.tool_name}:{exc}")
            tools_skipped.append(ToolSkip(name=cmd.tool_name, phase=cmd.phase, reason=f"exec_failed:{exc}"))

        return parsed_list

    async def _emit_vuln_confirmed(self, scan_id: str, entity: ParsedEntity) -> None:
        """Promote a real validation finding (nuclei/dalfox template match) to a
        VULN_CONFIRMED HiveEvent so the findings API, dashboard, and report
        surface it. Alpha's template-validation phase previously only produced
        recon entities — confirmed templates never reached the findings feed
        (verified on a live DVWA scan: dvwa-default-login fired in nuclei JSONL
        but the findings endpoint returned 0). Mirror the payload shape that
        Sigma's CLI validator publishes so downstream consumers are compatible.
        """
        try:
            props = entity.properties or {}
            severity = str(props.get("severity") or "high").lower()
            template_id = str(props.get("template_id") or props.get("name") or entity.label)
            matched = str(props.get("matched_at") or entity.label)
            await self.bus.publish(
                HiveEvent(
                    type=EventType.VULN_CONFIRMED,
                    source=self.agent_name,
                    scan_id=scan_id,
                    payload={
                        "type": f"ALPHA:{template_id}",
                        "url": matched,
                        "severity": severity.title(),
                        "data": {
                            "tool": "nuclei" if entity.source_tool == "nuclei" else entity.source_tool,
                            "template_id": template_id,
                            "matched_at": matched,
                            "tags": props.get("tags"),
                            "matcher_name": props.get("matcher_name"),
                        },
                        "evidence": {"raw": props.get("curl_command") or props},
                    },
                )
            )
            logger.info("[Alpha] VULN_CONFIRMED %s (%s) @ %s", template_id, severity, matched)
        except Exception as exc:
            logger.debug(f"[Alpha] VULN_CONFIRMED emit failed: {exc}")

    async def _inventory_tools(self, mode, tools_skipped, rag):
        """Check which tools are available on this system."""
        inventory = {}
        for name, _spec in RECON_TOOLS.items():
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
        is_local = (
            domain
            in (
                "localhost",
                "127.0.0.1",
                "0.0.0.0",
                "::1",
                "host.docker.internal",
                "host.containers.internal",
                "gateway.docker.internal",
            )
            or domain.startswith("192.168.")
            or domain.startswith("10.")
            or domain.startswith("172.16.")
            or domain.endswith(".local")
            or domain.endswith(".internal")
        )
        return ReconScope(
            base_domain=domain,
            target_url=target_url,
            scan_mode=mode,
            base_url=f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else target_url,
            max_depth=3 if mode == ScanMode.AGGRESSIVE else 2,
            max_rps=200 if mode == ScanMode.AGGRESSIVE else 50,
            explicit_authorization=is_local,
        )

    def _coerce_mode(self, val) -> ScanMode:
        if isinstance(val, ScanMode):
            return val
        try:
            return ScanMode(str(val).upper())
        except (ValueError, KeyError):
            return ScanMode.STANDARD

    async def _http_probe(self, target_url: str, scan_id: str) -> list[HTTPServiceFinding]:
        """Internal scoped HTTP probe used even when external tools are disabled."""
        common_paths = [
            "",
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/health",
            "/api/status",
            "/swagger",
            "/swagger.json",
            "/docs",
            "/openapi.json",
            "/api-docs",
            "/graphql",
            "/admin",
            "/login",
            "/auth",
            "/token",
            "/users",
            "/user",
            "/account",
            "/profile",
            "/settings",
            "/orders",
            "/order",
            "/cart",
            "/payment",
            "/checkout",
            "/products",
            "/items",
            "/search",
            "/export",
            "/robots.txt",
            "/sitemap.xml",
            "/.env",
            "/config",
            "/wp-admin",
            "/wp-login.php",
            "/.git/config",
        ]
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}".rstrip("/")
        services: list[HTTPServiceFinding] = []

        async def probe(path: str) -> None:
            url = normalize_url(urljoin(base_url + "/", path.lstrip("/")))
            try:
                record = await http_client.request("GET", url, scan_id=scan_id, timeout=10)
                headers = {str(k): str(v) for k, v in record.response_headers.items()}
                services.append(
                    HTTPServiceFinding(
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
                    )
                )
            except ScopeViolation:
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.SCOPE_VIOLATION,
                        source=self.agent_name,
                        scan_id=scan_id,
                        payload={"url": url, "reason": "out_of_scope"},
                    )
                )
            except Exception as probe_exc:
                logger.debug(f"[Alpha] HTTP probe failed for {url}: {probe_exc}")

        await asyncio.gather(*(probe(path) for path in common_paths))
        return services

    def _service_to_endpoint(self, svc: HTTPServiceFinding) -> EndpointFinding:
        parsed = urlparse(svc.url)
        endpoint_type, risk = classify_path(parsed.path)
        params = [
            ParameterFinding(
                name=name, location="query", value_type=self._infer_type(value), examples=[value] if value else []
            )
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return EndpointFinding(
            url=svc.url,
            method="GET",
            status_code=svc.status_code,
            content_type=svc.content_type,
            path=parsed.path or "/",
            normalized_path=parsed.path or "/",
            host=(parsed.hostname or "").lower(),
            technologies=svc.technologies,
            server=svc.server,
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
            sources=[SourceRef(tool="http_probe", phase="http_browser_intelligence", confidence=0.9)],
        )

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

    def _entity_to_endpoint(self, entity: ParsedEntity) -> EndpointFinding | None:
        """Convert a ParsedEntity (crawler / browser-engine / API discovery)
        into an attack-surface EndpointFinding. Returns None for entities
        without a usable URL."""
        props = entity.properties or {}
        url = str(entity.label or "")
        if not url.startswith(("http://", "https://", "ws://", "wss://")):
            url = str(props.get("full_url") or props.get("url") or "")
        if not url.startswith(("http://", "https://", "ws://", "wss://")):
            return None
        if url.startswith(("ws://", "wss://")):
            url = url.replace("ws://", "http://", 1) if url.startswith("ws://") else url.replace(
                "wss://", "https://", 1
            )
        parsed = urlparse(url)
        path = parsed.path or "/"
        endpoint_type, risk = classify_path(path)
        params = [
            ParameterFinding(name=n, location="query", value_type=self._infer_type(v), examples=[v] if v else [])
            for n, v in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        try:
            status = int(props.get("status_code", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        try:
            content_length = int(props.get("content_length", 0) or 0)
        except (TypeError, ValueError):
            content_length = 0
        try:
            rtime = int(props.get("response_time_ms", 0) or 0)
        except (TypeError, ValueError):
            rtime = 0
        src = str(entity.source_tool or props.get("source") or "recon")
        return EndpointFinding(
            url=url,
            method=str(props.get("method", "GET") or "GET").upper(),
            path=path,
            normalized_path=path,
            host=str(props.get("host", "") or (parsed.hostname or "")).lower(),
            status_code=status,
            content_type=str(props.get("content_type", "") or ""),
            content_length=content_length,
            response_time_ms=rtime,
            server=str(props.get("server", "") or ""),
            server_header=str(props.get("server_header", "") or ""),
            technologies=[t for t in (props.get("technologies", []) or []) if isinstance(t, str)],
            parameters=params,
            auth_required=status in {401, 403},
            endpoint_type=endpoint_type,
            risk_class=risk,
            source=src,
            sources=[
                SourceRef(tool=src, phase=entity.phase or "correlation_scoring", confidence=entity.confidence)
            ],
            evidence={"kind": entity.kind, "properties": {k: v for k, v in props.items() if k != "headers"}},
        )

    def _summarize(self, endpoints, state, entities) -> ReconRunSummary:
        api_eps = 0
        graphql = 0
        admin = 0
        for ep in endpoints:
            lower = (ep.url or "").lower()
            if ep.endpoint_type == "API_ENDPOINT" or "/api/" in lower or "/rest/" in lower:
                api_eps += 1
            if "graphql" in lower or ep.endpoint_type == "GRAPHQL_ENDPOINT":
                graphql += 1
            if ep.endpoint_type == "ADMIN_ENDPOINT" or any(k in lower for k in ("/admin", "/wp-admin", "/dashboard")):
                admin += 1
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
            subdomains_discovered=len(state.subdomains),
            live_hosts=len(state.http_services),
            open_ports=sum(len(p) for p in state.open_ports.values()),
            api_endpoints=api_eps,
            parameters_discovered=len(state.parameters),
            secrets_found=len(state.secrets),
            historical_urls=len(state.endpoints),
            graphql_endpoints=graphql,
            admin_panels=admin,
            screenshots_taken=len([e for e in state.all_entities if e.kind == "visual_artifact"]),
        )

    def _build_failed_result(
        self,
        scan_id: str,
        target_url: str,
        scan_mode,
        started: float,
        reason: str,
        *,
        tools_run: list[str] | None = None,
        tools_skipped: list | None = None,
        attack_surface: list | None = None,
        artifacts=None,
        summary=None,
        state=None,
        entities=None,
    ) -> ReconRunResult:
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
            scan_id=scan_id,
            target=target_url,
            mode=scan_mode if isinstance(scan_mode, ScanMode) else self._coerce_mode(scan_mode),
            duration_seconds=int(time.time() - started),
            summary=summary,
            error=reason or "",
            attack_surface=attack_surface or [],
            tools_run=tools_run or [],
            tools_skipped=tools_skipped or [],
            raw_data_path=str(artifacts.raw_dir) if artifacts else "",
            screenshots_path=str(artifacts.screenshots_dir) if artifacts else "",
            artifact_manifest_path=str(artifacts.manifest_path) if artifacts else "",
        )

    async def _emit_status(self, scan_id, status, data):
        try:
            event = HiveEvent(
                type=EventType.AGENT_STATUS,
                source=self.agent_name,
                scan_id=scan_id,
                payload={"agent": "alpha", "phase": status, **data},
            )
            await self.bus.publish(event)
        except Exception as exc:
            logger.debug(f"[Alpha] Status emit failed: {exc}")

    async def _emit_recon_packet(self, scan_id, ep):
        try:
            event = HiveEvent(
                type=EventType.RECON_PACKET, source=self.agent_name, scan_id=scan_id, payload=ep.model_dump(mode="json")
            )
            await self.bus.publish(event)
        except Exception as exc:
            logger.debug(f"[Alpha] Recon packet emit failed: {exc}")

    async def _emit_complete(self, result):
        try:
            # Build a COMPACT payload: the EventBus watchdog truncates any
            # event payload over 16KB into an opaque guarded_payload blob, and
            # the orchestrator reads ``payload["attack_surface"]`` to seed the
            # attack phase — a truncated RECON_COMPLETE silently loses the
            # discovered endpoint list (verified live: 150 endpoints found, 0
            # handed off). Emit the full URL list (small) + the summary object.
            summary = {}
            try:
                summary = result.summary.model_dump(mode="json") if result.summary else {}
            except Exception:
                summary = {}
            surface = []
            for ep in (result.attack_surface or []):
                if isinstance(ep, dict):
                    _u = ep.get("url")
                    _m = ep.get("method", "GET")
                    _p = ep.get("normalized_path") or ep.get("path")
                else:
                    # Pydantic coerces the list to EndpointFinding objects.
                    _u = getattr(ep, "url", "")
                    _m = getattr(ep, "method", "GET") or "GET"
                    _p = getattr(ep, "normalized_path", "") or getattr(ep, "path", "")
                if _u:
                    surface.append({"url": _u, "method": _m, "path": _p})
            # Keep the whole event under the EventBus 16KB watchdog: a larger
            # RECON_COMPLETE is truncated into an opaque guarded_payload blob
            # that downstream consumers cannot read. The surface is already
            # priority-sorted upstream, so capping the head preserves the
            # highest-value endpoints (params, auth, high-risk paths).
            if len(surface) > 160:
                surface = surface[:160]
            event = HiveEvent(
                type=EventType.RECON_COMPLETE,
                source=self.agent_name,
                scan_id=result.scan_id,
                payload={
                    "scan_id": result.scan_id,
                    "target": result.target,
                    "mode": str(result.mode),
                    "duration_seconds": result.duration_seconds,
                    "summary": summary,
                    "attack_surface": surface,
                    "tools_run": list(result.tools_run or []),
                    "tools_skipped": [s.name for s in (result.tools_skipped or [])],
                },
            )
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
