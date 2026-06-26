import difflib
import logging
import re

from backend.agents._shared import ScanContextRecorderMixin, SkillRecallMixin

# Hybrid AI Engine
from backend.ai.cortex import get_cortex_engine
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.hive import EventType, HiveEvent

logger = logging.getLogger("AgentGamma")


class GammaAgent(SkillRecallMixin, ScanContextRecorderMixin, BrowserEnabledAgent):
    """
    AGENT GAMMA: THE AUDITOR
    Role: Logic Verification & Bayesian Signal Classifier with Browser Verification.
    Capabilities:
    - Deep heuristic signal processing (Leak, Oracle, Timing, Size, Logic).
    - Bayesian fusion equation for confidence grading.
    - AI Hybrid Fallback functionality.
    - Browser-based exploit verification
    - Visual evidence collection
    - DOM mutation detection
    """

    def __init__(self, bus):
        super().__init__("agent_gamma", bus)

        # Arsenal stripped. Gamma is now purely a tactical router.
        self.cortex = get_cortex_engine()

        # Bayesian Signal Matrix mapping
        self.SIGNALS = {
            "data_leak": {"func": self._check_data_leak, "weight": 0.30},
            "error_oracle": {"func": self._check_error_oracle, "weight": 0.25},
            "size_anomaly": {"func": self._check_size_anomaly, "weight": 0.15},
            "timing_delta": {"func": self._check_timing, "weight": 0.10},
            "status_logic": {"func": self._check_status_logic, "weight": 0.10},
            "reflection": {"func": self._check_reflection, "weight": 0.10},
        }

    async def setup(self):
        self.bus.subscribe(EventType.VULN_CANDIDATE, self.audit_candidate)

    # --- FORENSIC SIGNALS ---

    def _check_data_leak(self, payload: dict) -> float:
        """Detects presence of sensitive unmasked data structures."""
        evidence = str(payload.get("data", "") + payload.get("evidence", "")).lower()
        if not evidence:
            return 0.0

        score = 0.0
        patterns = [
            (r"BEGIN[A-Z\s]*PRIVATE KEY", 1.0),  # RSA/SSH Key
            (r"aws_access_key_id", 0.9),  # AWS
            (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0.8),  # JWT
            (r"\"password\"\s*:\s*\"[^\"]+\"", 0.7),  # JSON password
            (r"[a-z0-9_]{10,}@[a-z0-9_]{3,}\.[a-z]{2,5}", 0.2),  # High density emails
        ]

        for pattern, weight in patterns:
            if re.search(pattern, evidence, re.IGNORECASE):
                score = max(score, weight)
        return score

    def _check_error_oracle(self, payload: dict) -> float:
        """Flags verbose server-side stack traces."""
        evidence = str(payload.get("data", "") + payload.get("evidence", "")).lower()
        if not evidence:
            return 0.0

        keywords = [
            "syntax error",
            "mysql_fetch",
            "stack trace",
            "java.sql.SQLException",
            "Exception in thread",
            "pg_query",
        ]
        return 1.0 if any(k in evidence for k in keywords) else 0.0

    def _check_size_anomaly(self, payload: dict) -> float:
        """Measures drastic response length changes from baseline."""
        try:
            baseline_len = float(payload.get("baseline_length", 0))
            attack_len = float(len(str(payload.get("data", payload.get("evidence", "")))))
            if baseline_len == 0:
                return 0.0

            delta = abs(attack_len - baseline_len) / baseline_len
            if delta > 0.5:  # > 50% change is highly anomalous
                return min((delta - 0.5) * 2, 1.0)  # Scale to 0.0 -> 1.0
        except (ValueError, TypeError):
            pass
        return 0.0

    def _check_timing(self, payload: dict) -> float:
        """Identifies time-based vulnerability signatures."""
        try:
            req_latency = float(payload.get("latency", 0))
            expected_latency = float(payload.get("baseline_latency", 100))  # assume 100ms baseline if not provided

            # If latency exceeds 2000ms AND is 5x the baseline
            if req_latency > 2000 and req_latency > (expected_latency * 5):
                return min(req_latency / 10000.0, 1.0)  # Caps at 10s = 1.0
        except (ValueError, TypeError):
            pass
        return 0.0

    def _check_status_logic(self, payload: dict) -> float:
        """Looks for improper auth/state transitions."""
        status = int(payload.get("status", 0))
        baseline_status = int(payload.get("baseline_status", 0))

        if baseline_status in [401, 403] and status in [200, 201]:
            # Bypassed auth!
            return 1.0
        if status == 500:
            # Induced server crash
            return 0.6
        return 0.0

    def _check_reflection(self, payload: dict) -> float:
        """Verifies direct reflection of the attack vector in the response."""
        attack_vector = str(payload.get("attack_payload", "")).lower()
        evidence = str(payload.get("data", "") + payload.get("evidence", "")).lower()

        if not attack_vector or len(attack_vector) < 3:
            return 0.0

        if attack_vector in evidence:
            return 1.0
        return 0.0

    # --- FUSION ENGINE ---

    def _calculate_bayesian_fusion(self, payload: dict) -> tuple[float, list[str]]:
        """
        Combines individual signals using a weighted naive approach.
        Returns final confidence score and a list of triggered signals.
        """
        total_confidence = 0.0
        triggers = []

        for name, config in self.SIGNALS.items():
            func = config["func"]
            weight = config["weight"]

            signal_score = func(payload)
            if signal_score > 0:
                triggers.append(f"{name}({signal_score:.2f})")

            total_confidence += signal_score * weight

        return total_confidence, triggers

    async def audit_candidate(self, event: HiveEvent):
        """
        Vigilagent: The Forensic Truth Kernel Audit
        Gamma evaluates candidate payloads generated by Beta.
        """
        payload = event.payload
        # ScanContext: record event for transcript causality (shared mixin).
        self.record(event)
        url = payload.get("url", "Unknown")
        ctx = getattr(self.bus, "scan_contexts", {}).get(event.scan_id)
        if ctx and hasattr(ctx, "transcript_text"):
            payload = dict(payload)
            payload["transcript_tail"] = ctx.transcript_text(tail=40)

        logger.info(f"[{self.name}] Auditing Candidate Exploit on {url}")

        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                scan_id=event.scan_id,
                payload={
                    "url": url,
                    "arsenal": "Forensic Audit",
                    "action": "Auditing Candidate",
                    "payload": str(payload.get("type", "Unknown"))[:50],
                },
            )
        )

        # 1. APPLY HEURISTIC SIGNAL FUSION
        heuristic_conf, triggers = self._calculate_bayesian_fusion(payload)

        # Architecture §17 evidence-based confirmation: require AT LEAST 2
        # independent triggered signals AND a confidence above threshold.
        # A lone reflection (substring match) or a single noisy signal is NOT
        # enough — that was the prior false-positive door we explicitly want
        # closed. The signal count is enforced here so a single 1.0 trigger
        # cannot tip is_real_heuristic on its own even when the weighted score
        # accidentally clears the threshold.
        is_real_heuristic = heuristic_conf >= 0.65 and len(triggers) >= 2

        # Consume skill-derived false-positive controls for this vuln class
        # (Architecture §29.9: skills consumed by Gamma). Known FP patterns
        # raise the bar before a candidate is accepted.
        try:
            from backend.core.skill_library import skill_library

            vclass = str(payload.get("vuln_type") or payload.get("type") or "")
            fp_skills = [
                s
                for s in skill_library.get_recommendations(vuln_class=vclass, limit=5)
                if "recovery" not in s.get("skill_id", "") and s.get("success_rate", 0) >= 0.7
            ]
            if fp_skills:
                logger.debug(
                    f"[{self.name}] [SKILLS] {len(fp_skills)} validation skill(s) inform FP filtering for {vclass}"
                )
        except Exception as e:
            logger.debug(f"[{self.name}] Skill recall failed: {e}")

        logger.debug(
            f"[{self.name}] [SIGNALS] Confidence: {heuristic_conf:.2f} | Triggers: {', '.join(triggers) if triggers else 'None'}"
        )

        # Determine strict reject vs hybrid verification
        confidence = heuristic_conf
        is_real = is_real_heuristic
        reason = f"Heuristics Triggered: {', '.join(triggers)}" if triggers else "Insufficient logic deviation."

        # 2. HYBRID AI FALLBACK
        # If signals are ambiguous (between 0.3 and 0.65) or absent but AI is enabled, let Cortex check
        if (self.cortex and self.cortex.enabled) and (0.3 < heuristic_conf < 0.65 or heuristic_conf == 0.0):
            logger.debug(f"[{self.name}] Ambiguous or missing signals. Escalating to CORTEX ENGINE...")
            try:
                verdict = await self.cortex.audit_candidate(payload)
                ai_confidence = verdict.get("confidence", 0.5)
                is_real = verdict.get("is_real", True)
                reason = verdict.get("reasoning", reason)

                # Blend the AI confidence with the heuristic confidence
                confidence = max(heuristic_conf, ai_confidence)

                logger.debug(f"[{self.name}] [AI AUDIT] Real={is_real} Confidence={confidence:.1f} Reason={reason}")
            except Exception as e:
                logger.warning(f"[{self.name}] [AI AUDIT] CortexEngine error: {e}")

        # 3. VERDICT
        if not is_real and confidence > 0.7:
            logger.info(f"[{self.name}] [VERDICT] FALSE POSITIVE suppressed.")
            # Feed the false-positive back to the self-improvement engine so the
            # source agent's confidence/routing is tuned (Architecture §15.1):
            # "Gamma rejects candidates -> self-awareness marks the source agent
            # too aggressive -> routing/skill updates."
            try:
                from backend.core.self_improvement_engine import self_improvement_engine

                source_agent = payload.get("source") or event.source or "agent_beta"
                vuln_type = str(payload.get("vuln_type") or payload.get("type") or "unknown")
                self_improvement_engine.record_false_positive(
                    agent_id=source_agent, vuln_class=vuln_type, scan_id=event.scan_id, reason=reason
                )
            except Exception as e:
                logger.debug(f"[{self.name}] Self-improvement record failed: {e}")
            await self.bus.publish(
                HiveEvent(
                    type=EventType.LIVE_ATTACK,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "url": url,
                        "arsenal": "False Positive Filter",
                        "action": "Suppressed",
                        "payload": reason[:50],
                    },
                )
            )
            return

        # If verified, trigger VULN_CONFIRMED for Kappa to archive
        if is_real:
            # Final hard floor (Architecture §17, requirement 6): refuse to
            # mark substring-only matches as confirmed. A confirmation must
            # have at least two distinct triggered signals (reflection alone
            # is too noisy to count as a finding by itself) — even when the
            # AI hybrid path returned is_real=True.
            distinct_signals = len(triggers)
            reflection_only = distinct_signals == 1 and any(t.startswith("reflection(") for t in triggers)
            if distinct_signals < 2 or reflection_only:
                logger.info(
                    f"[{self.name}] [VERDICT] Suppressed weak verdict — "
                    f"need >=2 signals, got {distinct_signals} ({triggers})."
                )
                return

            payload["confidence"] = confidence
            payload["audit_reasoning"] = reason
            payload["signals_triggered"] = triggers

            await self.bus.publish(
                HiveEvent(type=EventType.VULN_CONFIRMED, source=self.name, scan_id=event.scan_id, payload=payload)
            )
            await self.bus.publish(
                HiveEvent(
                    type=EventType.LIVE_ATTACK,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "url": url,
                        "arsenal": "Vulnerability Confirmed",
                        "action": f"Confirmed ({confidence:.0%})",
                        "payload": str(payload.get("type", ""))[:50],
                    },
                )
            )

    # ============ BROWSER VERIFICATION METHODS (Phase 3) ============

    async def _verify_exploit_browser(self, payload: dict, scan_id: str) -> dict:
        """Verify exploit visually in browser with screenshot evidence."""
        try:
            url = payload.get("url", "")
            attack_payload = payload.get("attack_payload", payload.get("payload", ""))

            logger.debug(f"[{self.name}] Verifying exploit in browser: {url}")

            # Navigate to URL with payload
            result = await self.browser.test_payload(url, attack_payload, param="test")

            if result.get("triggered"):
                # Capture before/after screenshots
                screenshot_path = await self.forensics.capture_screenshot(
                    scan_id=scan_id,
                    context=result.get("context"),
                    engine="openclaw",
                    label="exploit_verified",
                    full_page=True,
                )

                # Capture DOM snapshot
                dom_path = await self.forensics.capture_dom_snapshot(
                    scan_id=scan_id, context=result.get("context"), engine="openclaw", label="exploit_dom"
                )

                # Capture console logs
                console_logs = result.get("console_logs", [])
                if console_logs:
                    await self.forensics.capture_console_logs(
                        scan_id=scan_id, console_messages=console_logs, label="exploit_console"
                    )

                return {
                    "verified": True,
                    "screenshot": screenshot_path,
                    "dom_snapshot": dom_path,
                    "console_logs": len(console_logs),
                    "confidence": 0.95,
                }

            return {"verified": False, "confidence": 0.0}

        except Exception as e:
            logger.error(f"[{self.name}] Browser verification failed: {e}")
            return {"verified": False, "error": str(e)}

    async def _detect_dom_mutation(self, url: str, payload: str, scan_id: str) -> dict:
        """Detect DOM changes caused by payload execution."""
        try:
            logger.debug(f"[{self.name}] Detecting DOM mutations...")

            # Get baseline DOM
            baseline_result = await self.browser.navigate(url, stealth=False)
            baseline_dom = baseline_result.get("dom", "")

            # Execute payload
            attack_result = await self.browser.test_payload(url, payload, param="test")
            attack_dom = attack_result.get("dom", "")

            # Compare DOMs
            if baseline_dom and attack_dom:
                # Calculate similarity
                similarity = difflib.SequenceMatcher(None, baseline_dom, attack_dom).ratio()
                mutation_detected = similarity < 0.95  # >5% change

                if mutation_detected:
                    logger.debug(f"[{self.name}] DOM mutation detected: {(1 - similarity) * 100:.1f}% change")

                    return {
                        "mutation_detected": True,
                        "similarity": similarity,
                        "change_percentage": (1 - similarity) * 100,
                    }

            return {"mutation_detected": False}

        except Exception as e:
            logger.error(f"[{self.name}] DOM mutation detection failed: {e}")
            return {"mutation_detected": False, "error": str(e)}

    async def _detect_alert(self, url: str, payload: str, scan_id: str) -> bool:
        """Detect if payload triggers alert/prompt/confirm dialogs."""
        try:
            result = await self.browser.test_payload(url, payload, param="test")
            return result.get("alert_detected", False)
        except Exception as e:
            logger.error(f"[{self.name}] Alert detection failed: {e}")
            return False

    async def _analyze_network_traffic(self, url: str, payload: str, scan_id: str) -> dict:
        """Analyze network traffic to verify exploit behavior."""
        try:
            logger.debug(f"[{self.name}] Analyzing network traffic for: {url}")

            # Use network interceptor to capture traffic

            network_events = []
            suspicious_requests = []

            # In a real implementation, this would:
            # 1. Enable network interception in browser
            # 2. Navigate to URL with payload
            # 3. Capture all network requests/responses
            # 4. Analyze for suspicious patterns

            # Analyze captured network events for suspicious patterns
            suspicious_patterns = [
                r"169\.254\.169\.254",  # AWS metadata
                r"metadata\.google\.internal",  # GCP metadata
                r"admin",  # Admin endpoints
                r"api/v\d+/users",  # User API endpoints
                r"\.env",  # Environment files
                r"/etc/passwd",  # System files
            ]

            # Check each network event for suspicious patterns
            for event in network_events:
                request_url = event.get("url", "")

                for pattern in suspicious_patterns:
                    if re.search(pattern, request_url, re.IGNORECASE):
                        suspicious_requests.append(
                            {
                                "url": request_url,
                                "pattern": pattern,
                                "method": event.get("method", "GET"),
                                "status": event.get("status", 0),
                            }
                        )
                        break

            # Capture network logs if we have events
            if network_events:
                await self.forensics.capture_network_logs(
                    scan_id=scan_id, network_events=network_events, label="exploit_network"
                )

            # Report suspicious network activity
            if suspicious_requests:
                logger.info(f"[{self.name}] Found {len(suspicious_requests)} suspicious network requests")

                await self.bus.publish(
                    HiveEvent(
                        type=EventType.VULN_CANDIDATE,
                        source=self.name,
                        scan_id=scan_id,
                        payload={
                            "url": url,
                            "type": "SUSPICIOUS_NETWORK_ACTIVITY",
                            "severity": "HIGH",
                            "evidence": f"Detected {len(suspicious_requests)} suspicious network requests",
                            "requests": suspicious_requests[:5],  # Limit to first 5
                        },
                    )
                )

            return {"requests_count": len(network_events), "suspicious_requests": suspicious_requests}

        except Exception as e:
            logger.error(f"[{self.name}] Network traffic analysis failed: {e}")
            return {}
