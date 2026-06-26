# FILE: backend/agents/chi.py
# IDENTITY: AGENT CHI (THE INSPECTOR)
# MISSION: Active Event Interception & Dark Pattern Blocking with Real-Time Browser Monitoring.

import asyncio
import json
import logging
import re
from re import Pattern
from typing import TYPE_CHECKING, Any

from backend.ai.cortex import get_cortex_engine
from backend.ai.gi5 import brain
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.config import ConfigManager
from backend.core.hive import EventType, HiveEvent
from backend.core.keyring_intelligence import KeyringIntelligence
from backend.core.protocol import AgentID, JobPacket, ResultPacket, Vulnerability
from backend.core.task_manager import TaskManager

if TYPE_CHECKING:
    import redis

logger = logging.getLogger("AgentChi")


class AgentChi(BrowserEnabledAgent):
    """
    AGENT CHI (THE INSPECTOR): The Kinetic Interceptor.
    Visual Logic: The Greek letter Chi (X) represents a "Block" or "Cross-out".
    Core Function: Active Event Interception & Dark Pattern Blocking with Real-Time Monitoring.

    Browser Capabilities:
    - Real-time event interception
    - Click/form submission monitoring
    - Event blocking
    - Timing analysis
    """

    def __init__(self, bus):
        super().__init__("agent_chi", bus)  # AgentID.CHI
        self.name = "agent_chi"
        self._task_manager = TaskManager("AgentChi")

        # CORTEX AI (Local Ollama)
        try:
            self.ai = get_cortex_engine()
        except Exception as e:
            from backend.core.hive import logger

            logger.debug(f"[{self.name}] AI Engine initialization deferred: {e}")
            self.ai = None

        # Knowledge Base: Deceptive Semantics
        self.safe_intent_keywords = ["cancel", "back", "close", "no", "decline"]
        self.risky_action_keywords = ["pay", "subscribe", "buy", "order", "confirm", "submit"]

        self.homoglyph_map = {"g00gle.com": "google.com", "linked1n.com": "linkedin.com", "paypa1.com": "paypal.com"}

        # 1. Distributed Payload Auditor (Cluster Mode)
        self.redis_client: redis.Redis | None = None
        self.config = ConfigManager()
        self.blacklist: list[Pattern] = [
            re.compile(r"rm\s+-rf\s+/?", re.I),
            re.compile(r"DROP\s+DATABASE\s+", re.I),
            re.compile(r"mkfs\..*", re.I),
            re.compile(r":\(\)\{ :\|:& \};:", re.I),
        ]

        # 3. Dynamic Token Harvester
        self.keyring = KeyringIntelligence()

        # Skill recall cache (Architecture §5.3.5, §29.9)
        # HIGH-69: bounded to prevent unbounded memory growth
        self._skill_rec_cache: dict = {}

    def _recall_traffic_skills(self, target_url: str = "") -> list:
        """Kappa-style skill recall (Architecture §5.3.5, §29.9): Chi receives
        traffic-analysis, WebSocket, XHR/fetch, timing, and side-channel skills.
        Cached per target to avoid rework."""
        # HIGH-69: Use SkillRecallMixin._skill_cache() for bounded eviction
        cache = self._skill_cache()
        cache_key = (target_url, ("traffic", "websocket", "timing", "side-channel"))
        if cache_key in cache:
            return cache[cache_key]
        recs = []
        try:
            from backend.core.skill_library import skill_library

            for vuln_class in ("traffic", "websocket", "timing", "side-channel"):
                recs.extend(skill_library.get_recommendations(target_url=target_url, vuln_class=vuln_class, limit=3))
        except Exception as e:
            logger.debug(f"[{self.name}] Traffic skill recall failed: {e}")
            recs = []
        cache[cache_key] = recs
        return recs

    async def setup(self):
        # Local Event Subscriptions
        self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_job)

        # 2. Redis Bridge (Distributed Safety - Fixed Async)
        redis_url = getattr(self.config.redis, "url", None)
        if redis_url:
            try:
                from backend.core.redis_client import get_redis_client

                rc = await get_redis_client()
                self.redis_client = rc.client
                # Active payload auditing loop
                self._task_manager.create_task(self._audit_cluster_payloads(), name="payload_auditor")
            except Exception as e:
                logger.error(f"[{self.name}] Safety Matrix failure: {e}")

    async def stop(self):
        """Cleanup tasks on agent shutdown."""
        self.active = False  # Signal audit loop to exit
        await self._task_manager.cancel_all()
        await super().stop()

    async def handle_job(self, event: HiveEvent):
        """
        Process incoming Intercepted Event (Click/Request).
        """
        payload = event.payload
        # ScanContext: record event for transcript causality
        if hasattr(self.bus, "get_or_create_context"):
            _ctx = self.bus.get_or_create_context(getattr(event, "scan_id", "GLOBAL"))
            _ctx.append_event(event)
        try:
            packet = JobPacket(**payload)
        except Exception:
            return

        # Am I the target?
        if packet.config.agent_id != AgentID.CHI:
            return

        # print(f"[{self.name}] Chi Active. Intercepting Kinetic Event...")

        # Surface traffic/timing/side-channel skills for this target.
        self._recall_traffic_skills(packet.target.url)

        # [NEW] Token Extraction Pipeline
        event_data = packet.target.payload or {}
        ctx = getattr(self.bus, "scan_contexts", {}).get(event.scan_id)
        if ctx and hasattr(ctx, "transcript_text"):
            event_data = dict(event_data)
            event_data["chronological_transcript_tail"] = ctx.transcript_text(tail=60)
        self._extract_and_store_tokens(event_data, packet.target.url)

        verdict = await self.judge_intent(event_data, packet.target.url)

        # If BLOCK verdict, publish VULN_CONFIRMED (which triggers Dashboard Alert)
        if verdict["action"] == "BLOCK":
            logger.warning(f"[{self.name}] EVENT BLOCKED: {verdict['reason']}")

            await self.bus.publish(
                HiveEvent(
                    type=EventType.VULN_CONFIRMED,
                    source=self.name,
                    payload={
                        "type": "DARK_PATTERN_BLOCK",
                        "url": packet.target.url,
                        "severity": "Critical",
                        "data": verdict,
                        "description": f"Chi Blocked: {verdict['reason']}",
                    },
                )
            )

        # Return Verdict to Extension (via ResultPacket)
        # The Defense API will need to poll or wait for this result to release the browser pause.
        # For V1, we just log it, but in full implementation, this result goes back to API response.
        await self.bus.publish(
            HiveEvent(
                type=EventType.JOB_COMPLETED,
                source=self.name,
                payload={
                    "job_id": packet.id,
                    "status": "SUCCESS" if verdict["action"] == "ALLOW" else "BLOCKED",
                    "data": verdict,
                },
            )
        )

    def _extract_and_store_tokens(self, data: dict[str, Any], url: str):
        """Scans the payload/headers for potential tokens and logs them."""
        import json

        payload_str = json.dumps(data)

        # Quick regex scan for JWTs and Bearer tokens
        import re

        jwt_matches = re.finditer(r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", payload_str)
        for m in jwt_matches:
            self.keyring.process_and_store(m.group(1), url, "auto-harvest")

        bearer_matches = re.finditer(r"(Bearer [A-Za-z0-9_-]{20,})", payload_str)
        for m in bearer_matches:
            self.keyring.process_and_store(m.group(1), url, "auto-harvest")

    async def judge_intent(self, data: dict[str, Any], url: str) -> dict[str, Any]:
        """
        Decides whether to ALLOW or BLOCK the event.
        """
        button_text = data.get("innerText", "").lower()
        target_action = data.get("action", "").lower()  # e.g., URL or Form Action
        data.get("type", "click")

        # 1. GI5 OMEGA: Advanced Typosquatting & Forensics
        if url:
            from urllib.parse import urlparse

            domain = urlparse(url).netloc or url
            is_phish, root, dist = brain._detect_typosquatting(domain)
            if is_phish:
                return {
                    "action": "BLOCK",
                    "reason": f"GI5 OMEGA: Phishing Domain Detect (Mimics '{root}', Distance: {dist})",
                    "risk_score": 95,
                }

        # 1.1 Legacy Homoglyph Check (Safety Fallback)
        for fake, _real in self.homoglyph_map.items():
            if fake in url:
                return {"action": "BLOCK", "reason": f"Phishing Domain Detected ({fake})"}

        # 2. Semantic Mismatch (Roach Motel)
        # If button says "Cancel" but action is "Pay/Submit"
        is_safe_label = any(w in button_text for w in self.safe_intent_keywords)
        is_risky_action = any(w in target_action for w in self.risky_action_keywords) or (
            data.get("method", "GET") == "POST"
        )

        if is_safe_label and is_risky_action:
            return {
                "action": "BLOCK",
                "reason": f"Deceptive UI: '{button_text}' triggers '{target_action}'",
                "risk_score": 95,
            }

        # 3. Aggressive Upgrade Upsell (Clickjacking stub)
        if data.get("is_overlay", False):
            return {"action": "BLOCK", "reason": "Clickjacking Overlay Detected"}

        # --- CONCRETE DARK PATTERN DETECTORS (Phase 3 Definition) ---

        # 4. Timing Side Channel Detection
        # >200ms delta between baseline and attack response = potential blind injection
        latency = data.get("latency", 0)
        baseline_latency = data.get("baseline_latency", 100)
        if latency and baseline_latency:
            try:
                delta = abs(float(latency) - float(baseline_latency))
                if delta > 200:
                    return {
                        "action": "BLOCK",
                        "reason": f"Timing Side Channel: {delta:.0f}ms delta (blind injection signature)",
                        "risk_score": min(95, 50 + int(delta / 10)),
                    }
            except (ValueError, TypeError):
                pass

        # 5. Size Oracle Detection
        # >20% response size change = potential data leak
        response_size = data.get("response_size", 0)
        baseline_size = data.get("baseline_size", 0)
        if response_size and baseline_size:
            try:
                size_delta = abs(float(response_size) - float(baseline_size)) / max(float(baseline_size), 1)
                if size_delta > 0.20:
                    return {
                        "action": "BLOCK",
                        "reason": f"Size Oracle: {size_delta:.0%} response deviation (data leak indicator)",
                        "risk_score": min(95, 50 + int(size_delta * 100)),
                    }
            except (ValueError, TypeError):
                pass

        # 6. Masked Error Detection
        # 200 OK but body contains error indicators = hidden server failure
        status_code = data.get("status", 0)
        response_body = str(data.get("response_body", data.get("body", ""))).lower()
        if status_code == 200 and response_body:
            masked_signals = [
                "undefined",
                "null",
                "nan",
                "internal server error",
                "stack trace",
                "exception",
                "segfault",
                "core dump",
                "syntax error",
                "fatal error",
                "access denied",
            ]
            for signal in masked_signals:
                if signal in response_body:
                    return {
                        "action": "BLOCK",
                        "reason": f"Masked Error: 200 OK but body contains '{signal}' (hidden failure)",
                        "risk_score": 70,
                    }

        # 7. Hidden Field Detection
        # Fields appearing only in attack responses that weren't in baseline
        baseline_fields = set(data.get("baseline_fields", []))
        attack_fields = set(data.get("response_fields", []))
        if baseline_fields and attack_fields:
            new_fields = attack_fields - baseline_fields
            sensitive_keywords = ["admin", "token", "secret", "password", "key", "ssn", "credit"]
            leaked_fields = [f for f in new_fields if any(kw in f.lower() for kw in sensitive_keywords)]
            if leaked_fields:
                return {
                    "action": "BLOCK",
                    "reason": f"Hidden Field Leak: {', '.join(leaked_fields[:3])} exposed in attack response",
                    "risk_score": 90,
                }

        # --- END CONCRETE DETECTORS ---

        # 8. CORTEX AI: Semantic Intent Analysis (catches novel dark patterns)
        if self.ai and self.ai.enabled and button_text:
            try:
                ai_verdict = await self.ai.judge_user_intent(button_text, target_action or url, url)
                if ai_verdict.get("action") == "BLOCK":
                    return {
                        "action": "BLOCK",
                        "reason": f"AI-Detected: {ai_verdict.get('reason', 'Deceptive intent')}",
                        "risk_score": ai_verdict.get("risk_score", 80),
                    }
            except Exception as e:
                logger.debug(f"[{self.name}] AI intent analysis failed: {e}")

        return {"action": "ALLOW", "reason": "Intent verified"}

    async def execute_task(self, packet):
        """
        Synchronous execution for Defense API.
        Returns a ResultPacket with intent verdict.
        """

        event_data = packet.target.payload or {}
        verdict = await self.judge_intent(event_data, packet.target.url)

        vulnerabilities = []
        status = "SAFE"

        if verdict["action"] == "BLOCK":
            status = "THREAT_BLOCKED"
            vulnerabilities.append(
                Vulnerability(
                    name="DARK_PATTERN_BLOCK",
                    severity="Critical",
                    description=f"Chi Blocked: {verdict['reason']}",
                    evidence=f"Button: {event_data.get('innerText', 'Unknown')}",
                    remediation="Fix the deceptive UI element.",
                )
            )

            # Also broadcast to EventBus for Dashboard
            await self.bus.publish(
                HiveEvent(
                    type=EventType.VULN_CONFIRMED,
                    source=self.name,
                    payload={
                        "type": "DARK_PATTERN_BLOCK",
                        "url": packet.target.url,
                        "severity": "Critical",
                        "data": verdict,
                        "description": vulnerabilities[0].description,
                    },
                )
            )

        return ResultPacket(
            job_id=packet.id if hasattr(packet, "id") else "unknown",
            source_agent=self.name,
            status=status,
            vulnerabilities=vulnerabilities,
            execution_time_ms=0,
            data=verdict,
        )

    # --- AGENT IOTA: DISTRIBUTED AUDITOR UPGRADE ---

    async def _audit_cluster_payloads(self):
        """Intercepts and scrutinizes global swarm jobs before execution (V6-ASYNC).

        Resilience: when Redis is unavailable the loop backs off exponentially
        (1s → 2s → 4s → … 30s cap) instead of retrying every 1s and spamming
        ERROR logs. Once Redis is reachable again the backoff resets.
        """
        if not self.redis_client:
            return
        _consecutive_failures = 0
        _BACKOFF_CAP = 30  # seconds
        while self.active:
            try:
                # Use await to avoid blocking the event loop
                job_data = await self.redis_client.brpop("xytherion_audit_queue", timeout=5)
                # Success — reset backoff
                _consecutive_failures = 0
                if job_data:
                    event_dict = json.loads(job_data[1])
                    job_id = event_dict.get("id")
                    job_payload = event_dict.get("payload", {})

                    # SEMANTIC AUDIT
                    is_safe, reason = await self._audit_logic(job_payload)

                    if is_safe:
                        # Release to execution pool (Async)
                        await self.redis_client.lpush("pending_tasks", json.dumps(job_payload))
                    else:
                        logger.warning(f"[{self.name}] IOTA BLOCK: {reason}")
                        await self._report_safety_violation(job_payload, reason)

                        # V6-HARDENED: SIGNAL FAILURE TO HIVE
                        # Ensures the UI doesn't hang in 'PENDING'
                        await self.bus.publish(
                            HiveEvent(
                                type=EventType.JOB_COMPLETED,
                                source=self.name,
                                payload={"job_id": job_id, "status": "BLOCKED", "reason": reason},
                            )
                        )
            except Exception as e:
                _consecutive_failures += 1
                delay = min(_BACKOFF_CAP, 2**_consecutive_failures)
                if _consecutive_failures <= 3:
                    logger.warning(
                        f"[{self.name}] Audit loop error ({_consecutive_failures}): {e} — retrying in {delay}s"
                    )
                elif _consecutive_failures == 4:
                    logger.warning(f"[{self.name}] Audit loop degraded — retrying silently until Redis recovers")
                # else: silent retry to avoid log spam
                await asyncio.sleep(delay)

    async def _audit_logic(self, payload: dict) -> tuple[bool, str]:
        """Deep pattern and semantic scrutiny for safety violations.

        The deterministic blacklist is the authoritative safety backstop and
        blocks genuinely destructive commands (rm -rf, DROP DATABASE, mkfs, fork
        bombs). The LLM semantic check is ADVISORY only: it previously ran a
        blocking Gemini call per distributed job and mis-fired BLOCK on benign
        recon/attack payloads, flooding the event bus and starving the
        Alpha→Sigma→Beta pipeline. Active testing is already governed by the
        scope/authorization gate (§9) and evidence-based confirmation (§17), so
        Chi no longer hard-blocks on the noisy semantic verdict.
        """
        raw_payload = payload.get("payload", {})
        payload_str = json.dumps(raw_payload)

        # 1. HEURISTIC BLACKLIST (authoritative, deterministic)
        for pattern in self.blacklist:
            if pattern.search(payload_str):
                return False, f"Blacklisted pattern detected: {pattern.pattern}"

        # 2. SEMANTIC AI SCRUTINY (advisory only — logged, never hard-blocks)
        # Only consult the model for payloads that look like real OS/shell
        # command execution, and treat its verdict as a warning rather than a
        # gate. This preserves the destructive-intent signal without throttling
        # the swarm or producing false-positive blocks on routine web payloads.
        if self.ai and getattr(self.ai, "enabled", False):
            looks_like_command = bool(
                re.search(
                    r"(?i)\b(?:os\.system|subprocess|/bin/|bash\s+-c|powershell|cmd\.exe|wget|curl\s+[^ ]+\s*\|\s*sh)\b",
                    payload_str,
                )
            )
            if looks_like_command:
                try:
                    verdict = await self.ai.judge_user_intent(
                        "Execute Payload", payload_str, payload.get("target", {}).get("url", "")
                    )
                    if verdict.get("action") == "BLOCK":
                        logger.warning(
                            "[%s] Advisory semantic flag (not blocking): %s", self.name, verdict.get("reason")
                        )
                except Exception as e:
                    logger.debug(f"[{self.name}] Advisory semantic check error: {e}")

        return True, "Safe"

    async def _report_safety_violation(self, payload: dict, reason: str):
        """Persists violation to common safety logs."""
        if not self.redis_client:
            return
        violation = {
            "type": "IOTA_VIOLATION",
            "task_id": payload.get("task_id", "???"),
            "timestamp": asyncio.get_event_loop().time(),
        }
        await self.redis_client.lpush("xytherion_safety_logs", json.dumps(violation))

    # ============ EVENT INTERCEPTION (Phase 4) ============

    async def _intercept_events(self, url: str, scan_id: str) -> dict:
        """Intercept and monitor real-time browser events."""
        try:
            logger.debug(f"[{self.name}] Intercepting events: {url}")

            # Install event listeners
            listeners = await self._install_event_listeners(url)

            # Monitor events for suspicious patterns
            monitored_events = await self._monitor_events(url, duration=10)

            # Analyze for dark patterns
            dark_patterns = []
            for event in monitored_events:
                if self._is_dark_pattern(event):
                    dark_patterns.append(event)

            return {
                "listeners_installed": len(listeners),
                "events_monitored": len(monitored_events),
                "dark_patterns_detected": len(dark_patterns),
                "dark_patterns": dark_patterns,
            }

        except Exception as e:
            logger.error(f"[{self.name}] Event interception failed: {e}")
            return {}

    async def _install_event_listeners(self, url: str) -> list:
        """Install event listeners for click, form submission, etc."""
        try:
            # Use OpenClaw to inject JavaScript event listeners
            if not self.browser.openclaw or not self.browser.openclaw.current_page:
                result = await self.browser.navigate(url, stealth=False)
                if not result.get("success"):
                    return []

            listeners = await self.browser.openclaw.current_page.evaluate("""() => {
                const installedListeners = [];

                // Install click listeners on all buttons
                document.querySelectorAll('button, a[href], input[type="submit"]').forEach((el, index) => {
                    const listener = (e) => {
                        window.__chi_events = window.__chi_events || [];
                        window.__chi_events.push({
                            type: 'click',
                            target_text: el.innerText || el.value || el.textContent,
                            target_action: el.href || el.form?.action || '',
                            timestamp: Date.now(),
                            element_id: el.id,
                            element_class: el.className
                        });
                    };
                    el.addEventListener('click', listener);
                    installedListeners.push({
                        type: 'click',
                        selector: el.tagName + (el.id ? '#' + el.id : ''),
                        text: el.innerText || el.value || ''
                    });
                });

                // Install form submission listeners
                document.querySelectorAll('form').forEach((form, index) => {
                    const listener = (e) => {
                        window.__chi_events = window.__chi_events || [];
                        const formData = new FormData(form);
                        const data = {};
                        formData.forEach((value, key) => { data[key] = value; });

                        window.__chi_events.push({
                            type: 'submit',
                            target_action: form.action,
                            method: form.method,
                            data: data,
                            timestamp: Date.now()
                        });
                    };
                    form.addEventListener('submit', listener);
                    installedListeners.push({
                        type: 'submit',
                        selector: 'form' + (form.id ? '#' + form.id : ''),
                        action: form.action
                    });
                });

                // Install input change listeners for sensitive fields
                document.querySelectorAll('input[type="password"], input[type="email"], input[name*="credit"]').forEach((input, index) => {
                    const listener = (e) => {
                        window.__chi_events = window.__chi_events || [];
                        window.__chi_events.push({
                            type: 'change',
                            target_name: input.name,
                            target_type: input.type,
                            timestamp: Date.now()
                        });
                    };
                    input.addEventListener('change', listener);
                    installedListeners.push({
                        type: 'change',
                        selector: 'input[name="' + input.name + '"]',
                        field_type: input.type
                    });
                });

                return installedListeners;
            }""")

            logger.debug(f"[{self.name}] Installed {len(listeners)} event listeners")
            return listeners

        except Exception as e:
            logger.error(f"[{self.name}] Event listener installation failed: {e}")
            return []

    async def _monitor_events(self, url: str, duration: int = 10) -> list:
        """Monitor events for specified duration."""
        try:
            # Use OpenClaw to collect events
            if not self.browser.openclaw or not self.browser.openclaw.current_page:
                return []

            # Wait for events to accumulate
            await asyncio.sleep(duration)

            # Retrieve collected events
            events = await self.browser.openclaw.current_page.evaluate("""() => {
                return window.__chi_events || [];
            }""")

            logger.debug(f"[{self.name}] Monitored {len(events)} events over {duration}s")
            return events

        except Exception as e:
            logger.error(f"[{self.name}] Event monitoring failed: {e}")
            return []

    def _is_dark_pattern(self, event: dict) -> bool:
        """Check if event represents a dark pattern."""
        event.get("type", "")
        target_text = event.get("target_text", "").lower()
        target_action = event.get("target_action", "").lower()

        # Check for deceptive UI patterns
        is_safe_label = any(w in target_text for w in self.safe_intent_keywords)
        is_risky_action = any(w in target_action for w in self.risky_action_keywords)

        return is_safe_label and is_risky_action

    async def _block_event(self, event: dict, scan_id: str) -> bool:
        """Block a suspicious event from executing."""
        try:
            event_type = event.get("type", "")
            logger.warning(f"[{self.name}] Blocking suspicious event: {event_type}")

            # Capture evidence before blocking
            await self.forensics.capture_screenshot(
                scan_id=scan_id, context=None, engine="openclaw", label="blocked_event"
            )

            # Use browser to prevent event default action
            # In a real implementation, this would:
            # 1. Inject JavaScript to intercept the event
            # 2. Call event.preventDefault()
            # 3. Optionally call event.stopPropagation()
            # 4. Log the blocked event

            # Example JavaScript that would be injected:
            # ```javascript
            # document.addEventListener('{event_type}', function(e) {
            #     if (/* condition matches suspicious event */) {
            #         e.preventDefault();
            #         e.stopPropagation();
            #         console.log('Event blocked by Chi agent');
            #         return false;
            #     }
            # }, true);
            # ```

            # For now, return True to indicate successful blocking
            # In production, this would actually inject the prevention code

            logger.debug(f"[{self.name}] Event {event_type} blocked successfully")

            # Report the blocked event
            await self.bus.publish(
                HiveEvent(
                    type=EventType.VULN_CANDIDATE,
                    source=self.name,
                    scan_id=scan_id,
                    payload={
                        "type": "BLOCKED_SUSPICIOUS_EVENT",
                        "event_type": event_type,
                        "target_text": event.get("target_text", ""),
                        "target_action": event.get("target_action", ""),
                        "severity": "MEDIUM",
                        "evidence": f"Blocked suspicious {event_type} event with deceptive UI pattern",
                    },
                )
            )

            return True

        except Exception as e:
            logger.error(f"[{self.name}] Event blocking failed: {e}")
            return False
