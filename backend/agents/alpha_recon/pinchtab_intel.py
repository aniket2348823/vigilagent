"""
Alpha V6 Deep PinchTab Integration.

Full browser intelligence layer using PinchTab as the primary browser
control plane with comprehensive data extraction.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlparse

from backend.agents.alpha_recon.dedupe import SeenSet, classify_path
from backend.integrations.pinchtab_client import PinchTabClient
from backend.parsers.recon.base import ParsedEntity

if TYPE_CHECKING:
    from backend.agents.alpha_recon.artifacts import ArtifactStore
    from backend.agents.alpha_recon.rag import ReconRAGPipeline

logger = logging.getLogger("alpha.pinchtab")


class PinchTabIntelligence:
    """Deep browser intelligence extraction through PinchTab."""

    def __init__(self, scan_id: str, artifacts: ArtifactStore, rag: ReconRAGPipeline):
        self.scan_id = scan_id
        self.artifacts = artifacts
        self.rag = rag
        self.client = PinchTabClient()
        self._seen = SeenSet()

    async def is_available(self) -> tuple[bool, str]:
        """Check whether the PinchTab control plane is reachable.

        Uses the client's cached availability probe so we don't spam the network
        when the control plane is offline. Returns ``(True, "")`` when the
        daemon is online, otherwise ``(False, reason)`` where ``reason`` is
        one of:
          - ``"pinchtab_daemon_not_running"`` — control plane not reachable
            (the common case in local labs that don't ship the daemon).
          - ``"pinchtab_unavailable:<ExcType>"`` — probe raised unexpectedly.
        """
        try:
            ok = await self.client.is_available()
        except Exception as exc:
            return False, f"pinchtab_unavailable:{type(exc).__name__}"
        if ok:
            return True, ""
        return False, "pinchtab_daemon_not_running"

    async def full_capture(
        self, targets: list[str], *, max_targets: int = 20, profile_name: str = ""
    ) -> dict[str, Any]:
        """Run full browser intelligence on target URLs."""
        available, reason = await self.is_available()
        if not available:
            return {"used": False, "reason": reason, "entities": []}

        profile_id = ""
        instance_id = ""
        all_entities: list[ParsedEntity] = []
        captured = 0

        # Create profile
        try:
            pname = profile_name or f"alpha-{self.scan_id[:12]}"
            profile = await self.client.create_profile(pname, "Alpha V6 deep recon profile")
            profile_id = str(profile.get("id", profile.get("profileId", "")))
        except Exception as exc:
            logger.debug(f"[PinchTab] Profile creation failed: {exc}")

        # Start instance
        try:
            instance = await self.client.start_instance(profile_id or None, mode="headless")
            instance_id = str(instance.get("id", instance.get("instanceId", "")))
        except Exception as exc:
            return {"used": False, "reason": f"instance_failed:{exc}", "profile_id": profile_id, "entities": []}

        try:
            for url in targets[:max_targets]:
                try:
                    entities = await self._capture_single(url)
                    all_entities.extend(entities)
                    captured += 1
                except Exception as exc:
                    logger.warning(f"PinchTab capture failed for {url}: {exc}")
                    continue
        finally:
            # Cleanup instance
            try:
                if instance_id:
                    await self.client.stop_instance(instance_id)
            except Exception as exc:
                logger.debug(f"[PinchTab] Instance cleanup failed: {exc}")

        return {
            "used": captured > 0,
            "profile_id": profile_id,
            "instance_id": instance_id,
            "captured_count": captured,
            "entities_count": len(all_entities),
            "entities": all_entities,
            "reason": "" if captured else "no_pages_captured",
        }

    async def _capture_single(self, url: str) -> list[ParsedEntity]:
        """Capture full browser intelligence for a single URL."""
        entities: list[ParsedEntity] = []
        prefix = re.sub(r"[^A-Za-z0-9_.-]+", "_", url)[:120]

        # Navigate
        nav = await self.client.navigate(url)
        tab_id = str(nav.get("tabId", nav.get("id", nav.get("targetId", ""))))
        if not tab_id:
            return entities

        try:
            # Wait for full page load
            try:
                await self.client.wait_for_load(tab_id, timeout_ms=15000)
            except Exception as exc:
                logger.debug(f"[PinchTab] wait_for_load fallback: {exc}")
                await asyncio.sleep(2)

            # 1. Screenshot
            screenshot_path = self.artifacts.screenshots_dir / f"{prefix}.png"
            try:
                await self.client.screenshot(tab_id, screenshot_path)
                await self.artifacts.register(
                    screenshot_path, tool_name="pinchtab", artifact_type="screenshot", scan_id=self.scan_id
                )
                entities.append(
                    ParsedEntity(
                        kind="visual_artifact",
                        label=url,
                        confidence=0.95,
                        properties={"screenshot_path": str(screenshot_path)},
                        source_tool="pinchtab",
                        phase="http_browser_intelligence",
                    )
                )
            except Exception as exc:
                logger.debug(f"[PinchTab] Screenshot failed for {url}: {exc}")

            # 2. DOM Snapshot (interactive elements, forms, links)
            try:
                snapshot = await self.client.snapshot(tab_id, max_tokens=3000)
                await self.artifacts.write_json(
                    f"browser/{prefix}_snapshot.json",
                    snapshot,
                    tool_name="pinchtab",
                    artifact_type="snapshot",
                    scan_id=self.scan_id,
                )
                if isinstance(snapshot, dict):
                    entities.extend(self._extract_from_snapshot(snapshot, url))
            except Exception as exc:
                logger.debug(f"[PinchTab] DOM snapshot failed for {url}: {exc}")

            # 3. Page Text Content
            try:
                text = await self.client.text(tab_id, max_chars=50000)
                text_str = str(text) if not isinstance(text, str) else text
                await self.artifacts.write_text(
                    f"browser/{prefix}_text.txt",
                    text_str,
                    tool_name="pinchtab",
                    artifact_type="text",
                    scan_id=self.scan_id,
                )
                entities.extend(self._extract_from_text(text_str, url))
            except Exception as exc:
                logger.debug(f"[PinchTab] Text extraction failed for {url}: {exc}")

            # 4. Network Requests (critical for endpoint discovery)
            try:
                network = await self.client.network(tab_id, limit=500)
                await self.artifacts.write_json(
                    f"browser/{prefix}_network.json",
                    network,
                    tool_name="pinchtab",
                    artifact_type="network",
                    scan_id=self.scan_id,
                )
                entities.extend(self._extract_from_network(network, url))
            except Exception as exc:
                logger.debug(f"[PinchTab] Network capture failed for {url}: {exc}")

            # 5. Console output (error messages, debug info)
            try:
                console = await self.client.console(tab_id, limit=200)
                await self.artifacts.write_json(
                    f"browser/{prefix}_console.json",
                    console,
                    tool_name="pinchtab",
                    artifact_type="console",
                    scan_id=self.scan_id,
                )
                entities.extend(self._extract_from_console(console, url))
            except Exception as exc:
                logger.debug(f"[PinchTab] Console capture failed for {url}: {exc}")

            # 6. Browser Errors
            try:
                errors = await self.client.errors(tab_id, limit=200)
                await self.artifacts.write_json(
                    f"browser/{prefix}_errors.json",
                    errors,
                    tool_name="pinchtab",
                    artifact_type="errors",
                    scan_id=self.scan_id,
                )
            except Exception as exc:
                logger.debug(f"[PinchTab] Errors capture failed for {url}: {exc}")

            # 7. Cookies (session, auth tokens)
            try:
                cookies = await self.client.cookies(tab_id)
                await self.artifacts.write_json(
                    f"browser/{prefix}_cookies.json",
                    cookies,
                    tool_name="pinchtab",
                    artifact_type="cookies",
                    scan_id=self.scan_id,
                )
                entities.extend(self._extract_from_cookies(cookies, url))
            except Exception as exc:
                logger.debug(f"[PinchTab] Cookies capture failed for {url}: {exc}")

            # 8. Try to discover additional network requests by scrolling
            try:
                await self.client.action(tab_id, "scroll", selector="body")
                await asyncio.sleep(1)
                network2 = await self.client.network(tab_id, limit=500)
                entities.extend(self._extract_from_network(network2, url))
            except Exception as exc:
                logger.debug(f"[PinchTab] Scroll network failed for {url}: {exc}")

        finally:
            try:
                await self.client.close_tab(tab_id)
            except Exception as exc:
                logger.debug(f"[PinchTab] Tab close failed: {exc}")

        return entities

    def _extract_from_network(self, network: Any, parent_url: str) -> list[ParsedEntity]:
        """Extract endpoints from browser network requests."""
        entities: list[ParsedEntity] = []
        rows = []
        if isinstance(network, dict):
            rows = network.get("requests", network.get("items", network.get("entries", [])))
        elif isinstance(network, list):
            rows = network
        if not isinstance(rows, list):
            return entities

        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url", row.get("request", {}).get("url", "")))
            if not url.startswith(("http://", "https://")):
                continue
            key = f"net:{url}"
            if not self._seen.add(key):
                continue

            parsed = urlparse(url)
            method = str(row.get("method", row.get("request", {}).get("method", "GET"))).upper()
            status = int(row.get("status", row.get("response", {}).get("status", 0)) or 0)
            mime = str(row.get("mimeType", row.get("response", {}).get("mimeType", "")))
            resource_type = str(row.get("resourceType", row.get("type", "")))

            # Skip static resources
            if resource_type in ("Image", "Stylesheet", "Font", "Media"):
                continue
            if any(url.lower().endswith(ext) for ext in [".png", ".jpg", ".gif", ".css", ".woff", ".ico", ".svg"]):
                continue

            endpoint_type, risk = classify_path(parsed.path)
            params = [{"name": n, "value": v} for n, v in parse_qsl(parsed.query, keep_blank_values=True)]

            props = {
                "full_url": url,
                "method": method,
                "status_code": status,
                "mime_type": mime,
                "resource_type": resource_type,
                "path": parsed.path or "/",
                "host": (parsed.hostname or "").lower(),
                "parameters": params,
                "endpoint_type": endpoint_type,
                "risk": risk,
                "discovered_from": parent_url,
            }

            # Check for API calls
            is_api = bool(re.search(r"/api/|/rest/|/v[0-9]+/|/graphql", url, re.I))
            is_xhr = resource_type in ("XHR", "Fetch", "xmlhttprequest", "fetch")
            props["is_api_call"] = is_api or is_xhr

            kind = "browser_endpoint"
            conf = 0.9 if (is_api or is_xhr) else 0.75
            entities.append(
                ParsedEntity(
                    kind=kind,
                    label=url,
                    confidence=conf,
                    properties=props,
                    source_tool="pinchtab",
                    phase="http_browser_intelligence",
                )
            )

        return entities

    def _extract_from_snapshot(self, snapshot: dict, parent_url: str) -> list[ParsedEntity]:
        """Extract forms, links, and interactive elements from DOM snapshot."""
        entities: list[ParsedEntity] = []
        # Look for forms in snapshot
        content = str(snapshot)
        forms = re.findall(r'action=["\']([^"\']+)["\']', content, re.I)
        for action in forms:
            if action and not action.startswith("#"):
                key = f"form:{action}"
                if self._seen.add(key):
                    entities.append(
                        ParsedEntity(
                            kind="form_action",
                            label=action,
                            confidence=0.8,
                            properties={"parent_url": parent_url, "type": "form"},
                            source_tool="pinchtab",
                            phase="http_browser_intelligence",
                        )
                    )
        return entities

    def _extract_from_text(self, text: str, parent_url: str) -> list[ParsedEntity]:
        """Extract potential secrets or interesting patterns from page text."""
        entities: list[ParsedEntity] = []
        # Look for API keys, tokens in page content
        patterns = {
            "api_key_in_page": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9]{20,})', re.I),
            "bearer_token": re.compile(r"Bearer\s+([A-Za-z0-9._-]{20,})", re.I),
            "jwt_in_page": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        }
        for stype, pattern in patterns.items():
            matches = pattern.findall(text[:10000])
            for match in matches[:3]:
                key = f"text_secret:{stype}:{str(match)[:20]}"
                if self._seen.add(key):
                    entities.append(
                        ParsedEntity(
                            kind="secret",
                            label=f"page_secret:{stype}",
                            confidence=0.7,
                            properties={
                                "secret_type": stype,
                                "redacted_value": str(match)[:4] + "****",
                                "source_url": parent_url,
                            },
                            source_tool="pinchtab",
                            phase="http_browser_intelligence",
                        )
                    )
        return entities

    def _extract_from_console(self, console: Any, parent_url: str) -> list[ParsedEntity]:
        """Extract interesting findings from browser console output."""
        entities: list[ParsedEntity] = []
        entries = []
        if isinstance(console, dict):
            entries = console.get("entries", console.get("messages", console.get("items", [])))
        elif isinstance(console, list):
            entries = console
        if not isinstance(entries, list):
            return entities

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            level = str(entry.get("level", entry.get("type", ""))).lower()
            text = str(entry.get("text", entry.get("message", "")))
            if level == "error" and any(kw in text.lower() for kw in ["api", "cors", "auth", "token", "forbidden"]):
                key = f"console_err:{text[:50]}"
                if self._seen.add(key):
                    entities.append(
                        ParsedEntity(
                            kind="browser_error",
                            label=f"console_error:{parent_url}",
                            confidence=0.6,
                            properties={"message": text[:500], "level": level, "source_url": parent_url},
                            source_tool="pinchtab",
                            phase="http_browser_intelligence",
                        )
                    )
        return entities

    def _extract_from_cookies(self, cookies: Any, parent_url: str) -> list[ParsedEntity]:
        """Extract security-relevant cookie information."""
        entities: list[ParsedEntity] = []
        cookie_list = []
        if isinstance(cookies, dict):
            cookie_list = cookies.get("cookies", cookies.get("items", []))
        elif isinstance(cookies, list):
            cookie_list = cookies
        if not isinstance(cookie_list, list):
            return entities

        for cookie in cookie_list:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get("name", ""))
            secure = bool(cookie.get("secure", False))
            httponly = bool(cookie.get("httpOnly", False))
            samesite = str(cookie.get("sameSite", ""))
            domain = str(cookie.get("domain", ""))

            # Flag security-sensitive cookies
            is_session = any(kw in name.lower() for kw in ["session", "token", "auth", "jwt", "csrf"])
            if is_session:
                issues = []
                if not secure:
                    issues.append("missing_secure_flag")
                if not httponly:
                    issues.append("missing_httponly_flag")
                if not samesite or samesite.lower() == "none":
                    issues.append("weak_samesite")

                if issues:
                    key = f"cookie:{name}:{domain}"
                    if self._seen.add(key):
                        entities.append(
                            ParsedEntity(
                                kind="vulnerability_candidate",
                                label=f"insecure_cookie:{name}",
                                confidence=0.7,
                                properties={
                                    "cookie_name": name,
                                    "domain": domain,
                                    "issues": issues,
                                    "secure": secure,
                                    "httponly": httponly,
                                    "samesite": samesite,
                                    "source_url": parent_url,
                                    "vuln_type": "insecure_cookie",
                                },
                                source_tool="pinchtab",
                                phase="http_browser_intelligence",
                            )
                        )
        return entities
