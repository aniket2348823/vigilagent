# FILE: backend/agents/prism.py
# IDENTITY: AGENT PRISM (THE SENTINEL)
# MISSION: Passive DOM Analysis & Prompt Injection Defense with Deep Browser Analysis.

import asyncio
import json
import re

try:
    import redis
except ImportError:
    redis = None
import logging
from datetime import datetime
from typing import Any

from backend.ai.cortex import get_cortex_engine
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.config import ConfigManager
from backend.core.content_boundary import content_boundary
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import AgentID, JobPacket, ResultPacket, Vulnerability
from backend.core.task_manager import TaskManager

logger = logging.getLogger("AgentPrism")


class AgentPrism(BrowserEnabledAgent):
    """
    AGENT PRISM (THE SENTINEL): The Optical Truth Engine.
    Visual Logic: A prism splits light to reveal what is hidden.
    Core Function: Passive DOM Analysis & Prompt Injection Defense with Deep Browser Capabilities.

    Browser Capabilities:
    - Shadow DOM analysis
    - Hidden element detection
    - Iframe content inspection
    - Rendered page analysis for prompt injection
    """

    def __init__(self, bus):
        super().__init__("agent_prism", bus)  # AgentID.PRISM
        self.name = "agent_prism"
        self._task_manager = TaskManager("AgentPrism")

        # CORTEX AI Engine (Local Ollama)
        try:
            self.ai = get_cortex_engine()
        except Exception as e:
            logger.debug(f"[{self.name}] AI Engine initialization deferred: {e}")
            self.ai = None

        # Knowledge Base: Prompt Injection Signatures (regex fallback)
        self.injection_patterns = [
            r"ignore previous instructions",
            r"system override",
            r"you are now (DAN|Developer|Admin)",
            r"reveal your system prompt",
            r"delete all files",
            r"transfer .* funds",
            r"simulated mode",
            r"debug mode",
            # V6: Deterministic Hard-Fence against AI Jailbreaks
            r"ignore\s+.*instructions",
            r"set\s+verdict\s+to",
            r"roleplay",
            r"bypass.*security",
            r"override.*protocol",
        ]

        # 1. Distributed Health Watchdog (Cluster Mode)
        self.redis_client = None  # type: Any  # Optional[redis.asyncio.Redis], set in setup()
        self.config = ConfigManager()
        self.threshold_5xx = 0.30
        self.status_history = []
        self.max_history = 100

        # Skill recall cache (Architecture §5.3.5, §29.9)
        # HIGH-69: bounded to prevent unbounded memory growth
        self._skill_rec_cache: dict = {}

    def _recall_dom_skills(self, target_url: str = "") -> list:
        """Kappa-style skill recall (Architecture §5.3.5, §29.9): Prism receives
        DOM, JavaScript, CSP, XSS, client-side route, and prompt-injection
        skills. Cached per target to avoid rework."""
        # HIGH-69: Use SkillRecallMixin._skill_cache() for bounded eviction
        cache = self._skill_cache()
        cache_key = (target_url, ("dom", "csp", "xss", "prompt-injection", "client-side"))
        if cache_key in cache:
            return cache[cache_key]
        recs = []
        try:
            from backend.core.skill_library import skill_library

            for vuln_class in ("dom", "csp", "xss", "prompt-injection", "client-side"):
                recs.extend(skill_library.get_recommendations(target_url=target_url, vuln_class=vuln_class, limit=3))
        except Exception as e:
            logger.debug(f"[{self.name}] DOM skill recall failed: {e}")
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
                # Start result interception (Monitoring the swarm stream)
                self._task_manager.create_task(self._subscribe_to_results(), name="redis_subscriber")
            except Exception as e:
                logger.error(f"AgentPrism setup failure: {e}")

    async def stop(self):
        """Cleanup tasks on agent shutdown."""
        await self._task_manager.cancel_all()
        await super().stop()

    async def handle_job(self, event: HiveEvent):
        """
        Process incoming DOM Snapshot for analysis.
        """
        payload = event.payload
        ctx = self.bus.get_or_create_context(event.scan_id)
        ctx.append_event(event)
        try:
            packet = JobPacket(**payload)
        except Exception:
            # print(f"[{self.name}] Error parsing job: {e}")
            return

        # Am I the target?
        if packet.config.agent_id != AgentID.PRISM:
            return

        # print(f"[{self.name}] Prism Active. Analyzing DOM Snapshot...")

        # Surface DOM/CSP/XSS/client-side skills for this target.
        self._recall_dom_skills(packet.target.url)

        dom_content = packet.target.payload or {}
        analysis_result = await self.analyze_dom(dom_content)

        # If threat detected, publish VULN_CONFIRMED for EACH type
        if analysis_result["risk_score"] > 50:
            detected_types = []
            if "Injection" in analysis_result["threat_type"]:
                detected_types.append("PROMPT_INJECTION")
            if "Invisible" in analysis_result["threat_type"]:
                detected_types.append("HIDDEN_TEXT")

            for t_type in detected_types:
                logger.warning(f"[{self.name}] THREAT DETECTED: {t_type}")
                # Broadcast for Dashboard & Visual Alert
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.VULN_CONFIRMED,
                        source=self.name,
                        payload={
                            "type": t_type,
                            "url": packet.target.url,
                            "severity": "High" if analysis_result["risk_score"] > 80 else "Medium",
                            "data": analysis_result,
                            "description": f"Prism detected {t_type.replace('_', ' ').title()}",
                        },
                    )
                )

        # Always complete the job
        await self.bus.publish(
            HiveEvent(
                type=EventType.JOB_COMPLETED,
                source=self.name,
                payload={"job_id": packet.id, "status": "SUCCESS", "data": analysis_result},
            )
        )

    async def analyze_dom(self, dom: dict[str, Any]) -> dict[str, Any]:
        """
        Calculates VisibilityScore and InjectionRiskScore.
        Uses AI for semantic analysis + regex for known patterns.

        Accuracy improvements:
        - Multi-signal confidence scoring (regex + AI + content_boundary)
        - FP reduction: filters benign keywords ("debug mode" in docs, etc.)
        - Risk score uses max(signal) not sum to avoid runaway FPs
        - Confidence field added to output for downstream triage
        """
        risk_score = 0
        threats = []
        confidence_signals = 0  # count independent signals

        # 1. Invisible Text Detection
        opacity = float(dom.get("style", {}).get("opacity", 1.0))
        font_size = dom.get("style", {}).get("fontSize", "12px")
        z_index = int(dom.get("style", {}).get("zIndex", 0))
        text = dom.get("innerText", "")

        if (opacity < 0.1 or z_index < -1000 or font_size == "0px") and len(text) > 5:
            risk_score = max(risk_score, 60)
            threats.append("Invisible Content Overlay")
            confidence_signals += 1

        # 2. Regex-Based Injection Scanning (fast, known patterns)
        # FP reduction: require 2+ pattern hits before escalating risk,
        # OR a single critical pattern. Also filter benign contexts.
        pattern_hits = 0
        critical_hit = False
        for pattern in self.injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                pattern_hits += 1
                # Flag truly critical patterns
                if "ignore" in pattern.lower() or "system" in pattern.lower():
                    critical_hit = True
                    threats.append(f"Prompt Injection Signature: {pattern}")

        # FP reduction: single generic matches (e.g. "debug mode", "roleplay")
        # are common in legitimate content — require 2+ hits or a critical match
        if critical_hit or pattern_hits >= 2:
            risk_score = max(risk_score, min(40 + pattern_hits * 15, 95))
            if pattern_hits >= 2 and not critical_hit:
                threats.append(f"Multiple injection patterns ({pattern_hits} hits)")
            confidence_signals += 1
        elif pattern_hits == 1:
            # Single non-critical hit — lower confidence, note but don't escalate much
            risk_score = max(risk_score, 25)
            confidence_signals += 0.5

        suspicious, reasons = content_boundary.is_suspicious_content(text)
        if suspicious:
            risk_score = max(risk_score, 85)
            threats.extend(reasons)
            confidence_signals += 1

        # 3. CORTEX AI: Semantic Injection Detection (catches novel attacks)
        if self.ai and self.ai.enabled and len(text) > 10:
            try:
                ai_verdict = await self.ai.detect_prompt_injection(text)
                if ai_verdict.get("is_injection"):
                    ai_risk = ai_verdict.get("risk_score", 50)
                    technique = ai_verdict.get("technique", "Unknown")
                    risk_score = max(risk_score, ai_risk)
                    if technique not in str(threats):
                        threats.append(f"AI-Detected: {technique}")
                    confidence_signals += 1
                    logger.warning(f"[{self.name}] CORTEX AI: Injection detected - {technique} (risk={ai_risk})")
            except Exception as e:
                logger.debug(f"[{self.name}] CORTEX AI injection detection failed: {e}")

        # Compute final confidence: more independent signals = higher confidence
        # 0 signals = 0.0, 1 = 0.5, 2 = 0.75, 3+ = 0.95
        confidence = min(confidence_signals * 0.3 + 0.2, 0.95) if confidence_signals > 0 else 0.0

        return {
            "risk_score": min(risk_score, 100),
            "threat_type": ", ".join(threats) if threats else "Clean",
            "confidence": round(confidence, 2),
            "signal_count": confidence_signals,
            "element_api_id": dom.get("VIGILAGENT_id"),
        }

    async def execute_task(self, packet):
        """
        Synchronous execution for Defense API.
        Returns a ResultPacket with threat analysis.
        """

        dom_content = packet.target.payload or {}
        analysis_result = await self.analyze_dom(dom_content)

        vulnerabilities = []
        status = "SAFE"

        if analysis_result["risk_score"] > 50:
            status = "THREAT_BLOCKED"
            detected_types = []
            if "Injection" in analysis_result["threat_type"]:
                detected_types.append("PROMPT_INJECTION")
            if "Invisible" in analysis_result["threat_type"]:
                detected_types.append("HIDDEN_TEXT")

            for t_type in detected_types:
                vulnerabilities.append(
                    Vulnerability(
                        name=t_type,
                        severity="High" if analysis_result["risk_score"] > 80 else "Medium",
                        description=f"Prism detected {t_type.replace('_', ' ').title()}",
                        evidence=f"Risk Score: {analysis_result['risk_score']}",
                        remediation="Remove hidden or malicious content from the page.",
                    )
                    if t_type
                    else None
                )

                # Also broadcast to EventBus for Dashboard
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.VULN_CONFIRMED,
                        source=self.name,
                        payload={
                            "type": t_type,
                            "url": packet.target.url,
                            "severity": "High" if analysis_result["risk_score"] > 80 else "Medium",
                            "data": analysis_result,
                            "description": f"Prism detected {t_type.replace('_', ' ').title()}",
                        },
                    )
                )

        return ResultPacket(
            job_id=packet.id if hasattr(packet, "id") else "unknown",
            source_agent=self.name,
            status=status,
            vulnerabilities=vulnerabilities,
            execution_time_ms=0,
            data=analysis_result,
        )

    # --- AGENT THETA: DISTRIBUTED WATCHDOG UPGRADE ---

    async def _subscribe_to_results(self):
        """Intercepts all swarm results to monitor target stability."""
        if not self.redis_client:
            return
        pubsub = self.redis_client.pubsub()
        await pubsub.subscribe("xytherion_results")

        async for message in pubsub.listen():
            if not self.active:
                break
            if message["type"] == "message":
                try:
                    result = json.loads(message["data"])
                    status = result.get("response_status", 200)
                    await self._record_status(status)
                except Exception as e:
                    logger.debug(f"[{self.name}] Result interception parse error: {e}")

    async def _record_status(self, status: int):
        """Rolling history and immediate threshold analysis."""
        self.status_history.append(status)
        if len(self.status_history) > self.max_history:
            self.status_history.pop(0)

        error_rate = sum(1 for s in self.status_history if s >= 500) / len(self.status_history)
        if error_rate > self.threshold_5xx:
            await self._broadcast_abort(f"TARGET_UNSTABLE (Error Rate: {error_rate * 100:.1f}%)")

    async def _monitor_cluster_health(self):
        """Independent target reachability polling and Cluster Lock monitoring (V6-ASYNC)."""
        while self.active:
            # V6-HARDENED: Global Lock Verification (Async)
            if self.redis_client:
                try:
                    lock_status = await self.redis_client.get("cluster_lock")
                    if lock_status == "ABORTED":
                        # Trigger local freeze
                        logger.critical(
                            f"[{self.name}] HOST PANIC: Global Cluster Lock is ABORTED. Freezing local hive."
                        )
                        await self.bus.publish(
                            HiveEvent(
                                type=EventType.CONTROL_SIGNAL,
                                source=self.name,
                                payload={"signal": "FREEZE", "reason": "GLOBAL_ABORT_LOCKED"},
                            )
                        )
                except Exception as e:
                    logger.debug(f"Lock check failure: {e}")
            await asyncio.sleep(30)  # MED-61: Added sleep to prevent tight loop

    async def _broadcast_abort(self, reason: str):
        """Global Cluster Killswitch (Async)."""
        if not self.redis_client:
            return
        abort_packet = {"type": "GLOBAL_ABORT", "reason": reason, "timestamp": datetime.now().isoformat()}
        await self.redis_client.publish("xytherion_control", json.dumps(abort_packet))
        await self.redis_client.set("cluster_lock", "ABORTED")
        logger.critical(f"[{self.name}] SENTINEL SHIELD ACTIVATED: {reason}")

    # ============ DEEP DOM ANALYSIS (Phase 4) ============

    async def _analyze_dom_deep(self, url: str, scan_id: str) -> dict:
        """Analyze shadow DOM and hidden elements."""
        try:
            logger.debug(f"[{self.name}] Deep DOM analysis: {url}")

            # Navigate with OpenClaw for deep analysis
            result = await self.browser.navigate(url, stealth=False, wait_for="networkidle")

            if not result.get("success"):
                return {}

            # Find hidden elements
            hidden_elements = await self._find_hidden_elements(url)

            # Analyze iframes
            iframes = await self._analyze_iframes(url)

            # Check for prompt injection in rendered content
            prompt_injection = await self._detect_prompt_injection_dom(url)

            return {
                "hidden_elements": hidden_elements,
                "iframes": iframes,
                "prompt_injection": prompt_injection,
                "risk_score": self._calculate_deep_risk(hidden_elements, iframes, prompt_injection),
            }

        except Exception as e:
            logger.error(f"[{self.name}] Deep DOM analysis failed: {e}")
            return {}

    async def _find_hidden_elements(self, url: str) -> list:
        """Find elements with opacity=0, display=none, or off-screen positioning."""
        try:
            # Use OpenClaw to execute JavaScript and find hidden elements
            if not self.browser.openclaw or not self.browser.openclaw.current_page:
                result = await self.browser.navigate(url, stealth=False)
                if not result.get("success"):
                    return []

            hidden_elements = await self.browser.openclaw.current_page.evaluate("""() => {
                const hidden = [];
                const allElements = document.querySelectorAll('*');

                allElements.forEach((el, index) => {
                    const style = window.getComputedStyle(el);
                    const rect = el.getBoundingClientRect();

                    // Check for hidden via CSS
                    const isHidden = (
                        style.opacity === '0' ||
                        style.display === 'none' ||
                        style.visibility === 'hidden' ||
                        parseFloat(style.fontSize) === 0 ||
                        parseInt(style.zIndex) < -1000 ||
                        // Off-screen positioning
                        rect.left < -1000 ||
                        rect.top < -1000 ||
                        rect.right > window.innerWidth + 1000 ||
                        rect.bottom > window.innerHeight + 1000
                    );

                    if (isHidden && el.textContent && el.textContent.trim().length > 5) {
                        hidden.push({
                            tag: el.tagName,
                            text: el.textContent.substring(0, 100),
                            opacity: style.opacity,
                            display: style.display,
                            visibility: style.visibility,
                            fontSize: style.fontSize,
                            zIndex: style.zIndex,
                            position: {
                                left: rect.left,
                                top: rect.top,
                                width: rect.width,
                                height: rect.height
                            }
                        });
                    }
                });

                return hidden;
            }""")

            logger.debug(f"[{self.name}] Found {len(hidden_elements)} hidden elements")
            return hidden_elements

        except Exception as e:
            logger.error(f"[{self.name}] Hidden element detection failed: {e}")
            return []

    async def _analyze_iframes(self, url: str) -> list:
        """Inspect iframe content for suspicious behavior."""
        try:
            logger.debug(f"[{self.name}] Analyzing iframes on: {url}")

            # Navigate to page and extract iframes
            result = await self.browser.navigate(url, stealth=False)

            if not result.get("success"):
                return []

            iframes = []

            # In a real implementation, this would use browser automation to:
            # 1. Find all iframe elements
            # 2. Extract src attributes
            # 3. Check for cross-origin iframes
            # 4. Detect hidden iframes (display:none, visibility:hidden, etc.)
            # 5. Analyze iframe content if same-origin

            # Placeholder structure for detected iframes:
            # iframes = [
            #     {
            #         "src": "https://example.com/frame",
            #         "cross_origin": True,
            #         "hidden": False,
            #         "suspicious": False,
            #         "risk_score": 30
            #     }
            # ]

            # Check for suspicious patterns in iframe sources

            # This would be populated by actual browser inspection
            # For now, return empty list as placeholder

            if iframes:
                logger.debug(f"[{self.name}] Found {len(iframes)} iframes")

                # Report suspicious iframes
                suspicious_iframes = [i for i in iframes if i.get("suspicious")]
                if suspicious_iframes:
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CANDIDATE,
                            source=self.name,
                            payload={
                                "url": url,
                                "type": "SUSPICIOUS_IFRAME",
                                "severity": "MEDIUM",
                                "evidence": f"Found {len(suspicious_iframes)} suspicious iframes",
                                "iframes": suspicious_iframes,
                            },
                        )
                    )

            return iframes

        except Exception as e:
            logger.error(f"[{self.name}] Iframe analysis failed: {e}")
            return []

    async def _detect_prompt_injection_dom(self, url: str) -> dict:
        """Detect prompt injection in rendered page content."""
        try:
            # Get rendered page text
            result = await self.browser.navigate(url, stealth=False)
            page_text = result.get("text", "")

            # Check for injection patterns
            detected_patterns = []
            for pattern in self.injection_patterns:
                if re.search(pattern, page_text, re.IGNORECASE):
                    detected_patterns.append(pattern)

            if detected_patterns:
                return {"detected": True, "patterns": detected_patterns, "risk_score": 90}

            return {"detected": False, "risk_score": 0}

        except Exception as e:
            logger.error(f"[{self.name}] Prompt injection detection failed: {e}")
            return {"detected": False, "error": str(e)}

    def _calculate_deep_risk(self, hidden_elements: list, iframes: list, prompt_injection: dict) -> int:
        """Calculate overall risk score from deep analysis."""
        risk = 0

        if len(hidden_elements) > 0:
            risk += min(len(hidden_elements) * 10, 40)

        if len(iframes) > 0:
            risk += min(len(iframes) * 15, 30)

        if prompt_injection.get("detected"):
            risk += prompt_injection.get("risk_score", 0)

        return min(risk, 100)
