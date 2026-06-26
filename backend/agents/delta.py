import asyncio
import logging
import os
import re
import subprocess

from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import JobPacket
from backend.core.sandbox import TempWorkspace

logger = logging.getLogger("AgentDelta")


class AgentDelta(BrowserEnabledAgent):
    """
    AGENT DELTA: HYBRID BROWSER CONTROLLER (Unified Browser Management)
    Role: Control browser operations via unified orchestrator, execute client-side workflows, and extract live DOM evidence.
    Now uses BrowserOrchestrator for intelligent routing between OpenClaw and PinchTab.
    """

    def __init__(self, bus):
        super().__init__("agent_delta", bus)

        self._last_session_id = ""
        self._skill_rec_cache: dict = {}  # HIGH-69: bounded via eviction in recall

    async def setup(self):
        # Triggered by Recon/Orchestrator when navigating routes
        self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_hybrid_request)

    def _recall_browser_skills(self, target_url: str = "") -> list:
        """Kappa-style skill recall (Architecture §5.3.5, §29.9): Delta receives
        browser, mobile, session, and dynamic-interaction skills. Cached per
        target to avoid rework."""
        # HIGH-69: Use SkillRecallMixin._skill_cache() for bounded eviction
        cache = self._skill_cache()
        cache_key = (target_url, ("browser", "session", "mobile", "dynamic-interaction"))
        if cache_key in cache:
            return cache[cache_key]
        recs = []
        try:
            from backend.core.skill_library import skill_library

            for vuln_class in ("browser", "session", "mobile", "dynamic-interaction"):
                recs.extend(skill_library.get_recommendations(target_url=target_url, vuln_class=vuln_class, limit=3))
        except Exception as e:
            logger.debug(f"[{self.name}] Skill recall failed: {e}")
            recs = []
        cache[cache_key] = recs
        return recs

    async def _safe_kill(self, proc):
        if not proc or proc.returncode is not None:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except Exception as term_exc:
            logger.debug(f"[{self.name}] Process terminate failed: {term_exc}")
            try:
                if os.name == "nt":
                    # Windows Hard-Kill fallback for zombie Chromium processes
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True,
                        timeout=5,
                    )
                else:
                    proc.kill()
            except Exception as e2:
                logger.debug(f"Delta kill fallback failed: {e2}")

    async def _pinch_nav(self, session, url):
        """Navigate using unified browser orchestrator (auto-selects engine)."""
        try:
            result = await self.browser.navigate(url, stealth=False, wait_for="networkidle")

            if result.get("success"):
                # Save session for later use
                self._last_session_id = f"delta_{url}"
                await self.session_manager.save_session(
                    session_id=self._last_session_id,
                    engine="auto",  # Let orchestrator decide
                    session_data=result.get("session_data", {}),
                    metadata={"url": url, "agent": "delta"},
                )
                return True

            return False

        except Exception as e:
            logger.error(f"[{self.name}] Browser navigation error: {e}")
            return False

    async def _pinch_text(self, session):
        """Extract text and DOM data using unified browser API."""
        try:
            if not self._last_session_id:
                return {}

            # Restore session if needed
            session_data = await self.session_manager.restore_session(session_id=self._last_session_id, engine="auto")

            # Extract tokens using fast engine (PinchTab)
            tokens_result = await self.browser.extract_tokens(session_data.get("url", ""))

            # Get page text
            text = tokens_result.get("text", "")

            return {
                "text": text,
                "snapshot": tokens_result.get("dom", {}),
                "inputs": tokens_result.get("inputs", []),
                "buttons": tokens_result.get("buttons", []),
                "forms": tokens_result.get("forms", []),
                "tokens": tokens_result.get("tokens", []),
            }

        except Exception as e:
            logger.error(f"[{self.name}] Text extraction error: {e}")
            return {}

    def _semantic_refine(self, dom_data: dict) -> dict:
        classification = "unknown"
        text_content = str(dom_data.get("text", "")).lower()
        if "password" in text_content or "login" in text_content:
            classification = "login"
        elif "checkout" in text_content or "card" in text_content:
            classification = "payment"
        elif "search" in text_content:
            classification = "search"

        actions = []
        for inp in dom_data.get("inputs", []):
            name = inp.get("name", inp.get("id", "unknown"))
            actions.append({"type": "input", "target": name, "intent": classification})
        for btn in dom_data.get("buttons", []):
            actions.append({"type": "click", "target": btn.get("text", "submit"), "intent": classification})

        return {"ui_type": classification, "actions_mapped": actions}

    async def handle_hybrid_request(self, event: HiveEvent):
        packet_dict = event.payload
        # ScanContext: record event for transcript causality
        if hasattr(self.bus, "get_or_create_context"):
            _ctx = self.bus.get_or_create_context(getattr(event, "scan_id", "GLOBAL"))
            _ctx.append_event(event)
        try:
            packet = JobPacket(**packet_dict)
            if packet.config.module_id == "delta_pinch_extract":
                await self.execute_pinchtab_flow(packet)
        except Exception as e:
            logger.debug(f"Delta error: {e}")

    async def execute_pinchtab_flow(self, packet: JobPacket):
        target_url = packet.target.url
        # Surface browser/session skills for this target before driving the browser.
        self._recall_browser_skills(target_url)
        async with TempWorkspace(prefix="delta-pinchtab") as workspace:
            success = await self._pinch_nav(None, target_url)
            if not success:
                return
            dom_data = await self._pinch_text(None)
            workspace.write_file("dom_text.txt", dom_data.get("text", ""))
            workspace.write_file("snapshot.json", str(dom_data.get("snapshot", {})))
            semantic_state = self._semantic_refine(dom_data)
            token = self._extract_token(dom_data.get("text", ""))

            if token or semantic_state.get("actions_mapped"):
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.JOB_COMPLETED,
                        source=self.name,
                        payload={
                            "job_id": packet.id,
                            "status": "SUCCESS",
                            "data": {
                                "dom_token": token,
                                "source_url": target_url,
                                "semantic_state": semantic_state,
                                "raw_dom_evidence": True,
                            },
                        },
                    )
                )

    def _extract_token(self, dom_text: str) -> str:
        match = re.search(
            r"(?:token|auth|session|bearer)['\"]?\s*[:=]\s*['\"]([^'\"]{20,})['\"]", dom_text, re.IGNORECASE
        )
        return match.group(1) if match else None

    # ============ HYBRID BROWSER METHODS (Phase 3) ============

    async def _extract_tokens_hybrid(self, url: str, scan_id: str) -> dict:
        """Extract tokens using both engines for maximum coverage."""
        try:
            logger.debug(f"[{self.name}] Hybrid token extraction: {url}")

            # Fast extraction with PinchTab
            fast_result = await self.browser.extract_tokens(url)
            fast_tokens = fast_result.get("tokens", [])

            # Deep extraction with OpenClaw (if needed)
            deep_tokens = []
            if len(fast_tokens) < 3:  # If fast extraction didn't find much
                deep_result = await self.browser.extract_endpoints(url, deep=True)
                deep_tokens = deep_result.get("tokens", [])

            # Merge and deduplicate
            all_tokens = fast_tokens + deep_tokens
            unique_tokens = []
            seen = set()

            for token in all_tokens:
                token_value = token.get("value", "")
                if token_value and token_value not in seen:
                    seen.add(token_value)
                    unique_tokens.append(token)

            logger.debug(
                f"[{self.name}] Extracted {len(unique_tokens)} unique tokens (fast: {len(fast_tokens)}, deep: {len(deep_tokens)})"
            )

            return {
                "tokens": unique_tokens,
                "fast_count": len(fast_tokens),
                "deep_count": len(deep_tokens),
                "total_count": len(unique_tokens),
            }

        except Exception as e:
            logger.error(f"[{self.name}] Hybrid token extraction failed: {e}")
            return {"tokens": [], "error": str(e)}

    async def _coordinate_engines(self, url: str, task_type: str, scan_id: str) -> dict:
        """Coordinate task distribution between OpenClaw and PinchTab."""
        try:
            logger.debug(f"[{self.name}] Coordinating engines for task: {task_type}")

            results = {}

            if task_type == "full_recon":
                # Fast recon with PinchTab
                fast_result = await self.browser.navigate(url, stealth=False)
                results["fast"] = fast_result

                # Deep recon with OpenClaw if SPA detected
                if fast_result.get("is_spa"):
                    deep_result = await self.browser.extract_endpoints(url, deep=True)
                    results["deep"] = deep_result

            elif task_type == "token_extraction":
                results = await self._extract_tokens_hybrid(url, scan_id)

            elif task_type == "xss_testing":
                # Use OpenClaw for XSS (needs real browser)
                results = await self.browser.test_payload(url, "<script>alert(1)</script>", "q")

            return results

        except Exception as e:
            logger.error(f"[{self.name}] Engine coordination failed: {e}")
            return {"error": str(e)}
