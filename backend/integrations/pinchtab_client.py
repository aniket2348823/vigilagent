from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import Any, TypeAlias

import aiohttp

from backend.core.config import settings

JSONDict: TypeAlias = dict[str, Any]
PinchTabPayload: TypeAlias = JSONDict | list[Any] | str | bytes

logger = logging.getLogger(__name__)


class PinchTabUnavailable(RuntimeError):
    """Raised by PinchTabClient when the control plane is offline."""


class PinchTabClient:
    """HTTP client for the PinchTab browser control plane.

    Includes a process-wide availability cache so callers don't spam logs and
    network when PinchTab is offline. The first failed call flips the cache to
    "unavailable" and subsequent calls raise ``PinchTabUnavailable`` immediately
    until ``reset_availability`` is called or ``recheck_interval`` elapses.
    """

    # Class-level cache shared by every client instance.
    _available: bool | None = None
    _last_check: float = 0.0
    _recheck_interval: float = 60.0  # seconds before re-probing /health
    _logged_unavailable: bool = False

    def __init__(self, base_url: str | None = None, timeout: int = 30):
        self.base_url = (base_url or getattr(settings, "PINCHTAB_BASE_URL", "http://127.0.0.1:9867")).rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        # Short timeout specifically for the cheap availability probe so we
        # never block 30s when nothing is listening.
        self._probe_timeout = aiohttp.ClientTimeout(total=2)

    # ── availability ────────────────────────────────────────────────────────

    @classmethod
    def reset_availability(cls) -> None:
        """Force the availability cache to re-probe on next call."""
        cls._available = None
        cls._last_check = 0.0
        cls._logged_unavailable = False

    @classmethod
    def is_known_available(cls) -> bool | None:
        """Return cached availability state without doing network I/O.

        ``True``  - last probe succeeded
        ``False`` - last probe failed (within recheck interval)
        ``None``  - never probed yet
        """
        return cls._available

    async def is_available(self) -> bool:
        """Return True iff the PinchTab control plane is reachable.

        Uses a 2-second probe timeout. Result is cached for ``_recheck_interval``
        seconds. The first time we observe unavailability we emit a single
        INFO log; further failures are silent.
        """
        cls = type(self)
        now = asyncio.get_event_loop().time()
        if cls._available is not None and (now - cls._last_check) < cls._recheck_interval:
            return cls._available

        try:
            async with aiohttp.ClientSession(timeout=self._probe_timeout) as session:
                async with session.get(f"{self.base_url}/health") as resp:
                    cls._available = 200 <= resp.status < 500
        except Exception as exc:
            cls._available = False
            # Probe-time unavailability is logged at DEBUG: the orchestrator
            # already emits a single INFO line summarising the engine state, so
            # logging here as INFO would just duplicate it. We still flip
            # ``_logged_unavailable`` so the higher-traffic ``_request`` path
            # also stays quiet on the same boot cycle.
            logger.debug(
                "[PinchTabClient] availability probe at %s failed (%s)",
                self.base_url,
                type(exc).__name__,
            )
            cls._logged_unavailable = True
        else:
            if cls._available and cls._logged_unavailable:
                logger.info("[PinchTabClient] control plane back online at %s", self.base_url)
            cls._logged_unavailable = not cls._available
        finally:
            cls._last_check = now

        return cls._available

    # ── public API ──────────────────────────────────────────────────────────

    async def health(self) -> JSONDict:
        return await self._request_json("GET", "/health")

    async def create_profile(self, name: str, description: str = "") -> JSONDict:
        return await self._request_json("POST", "/profiles", json={"name": name, "description": description})

    async def start_instance(self, profile_id: str | None = None, *, mode: str = "headless") -> JSONDict:
        payload: JSONDict = {"mode": mode}
        if profile_id:
            payload["profileId"] = profile_id
        return await self._request_json("POST", "/instances/start", json=payload)

    async def stop_instance(self, instance_id: str) -> JSONDict:
        return await self._request_json("POST", f"/instances/{instance_id}/stop")

    async def navigate(self, url: str, *, tab_id: str | None = None, wait_for: str = "networkidle") -> JSONDict:
        payload: JSONDict = {"url": url, "waitFor": wait_for, "blockMedia": True}
        if tab_id:
            payload["tabId"] = tab_id
        return await self._request_json("POST", "/navigate", json=payload)

    async def snapshot(self, tab_id: str, *, max_tokens: int = 1200) -> PinchTabPayload:
        return await self._request(
            "GET", f"/tabs/{tab_id}/snapshot?interactive=true&compact=true&maxTokens={max_tokens}"
        )

    async def text(self, tab_id: str, *, max_chars: int = 20000) -> PinchTabPayload:
        return await self._request("GET", f"/tabs/{tab_id}/text?format=text&maxChars={max_chars}")

    async def network(self, tab_id: str, *, limit: int = 200) -> JSONDict:
        return await self._request_json("GET", f"/tabs/{tab_id}/network?limit={limit}")

    async def network_detail(self, tab_id: str, request_id: str, *, body: bool = False) -> JSONDict:
        include_body = "true" if body else "false"
        return await self._request_json("GET", f"/tabs/{tab_id}/network/{request_id}?body={include_body}")

    async def console(self, tab_id: str, *, limit: int = 100) -> JSONDict:
        return await self._request_json("GET", f"/console?tabId={tab_id}&limit={limit}")

    async def errors(self, tab_id: str, *, limit: int = 100) -> JSONDict:
        return await self._request_json("GET", f"/errors?tabId={tab_id}&limit={limit}")

    async def cookies(self, tab_id: str) -> JSONDict:
        return await self._request_json("GET", f"/tabs/{tab_id}/cookies")

    async def wait_for_load(self, tab_id: str, *, timeout_ms: int = 30000) -> JSONDict:
        return await self._request_json(
            "POST", f"/tabs/{tab_id}/wait", json={"load": "networkidle", "timeout": timeout_ms}
        )

    async def action(
        self,
        tab_id: str,
        kind: str,
        *,
        selector: str | None = None,
        text: str | None = None,
        value: str | None = None,
        wait_nav: bool = False,
    ) -> JSONDict:
        payload: JSONDict = {"kind": kind, "tabId": tab_id}
        if selector:
            payload["selector"] = selector
        if text is not None:
            payload["text"] = text
        if value is not None:
            payload["value"] = value
        if wait_nav:
            payload["waitNav"] = True
        return await self._request_json("POST", f"/tabs/{tab_id}/action", json=payload)

    async def screenshot(self, tab_id: str, output_path: str | Path) -> str:
        result = await self._request("GET", f"/tabs/{tab_id}/screenshot?format=png")
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(result, dict):
            data = result.get("data") or result.get("base64") or result.get("content")
            if data:
                path.write_bytes(base64.b64decode(str(data).split(",", 1)[-1]))
            else:
                path.write_text(str(result), encoding="utf-8")
        elif isinstance(result, bytes):
            path.write_bytes(result)
        else:
            path.write_text(str(result), encoding="utf-8")
        return str(path)

    async def close_tab(self, tab_id: str) -> JSONDict:
        return await self._request_json("POST", f"/tabs/{tab_id}/close")

    # ── internals ───────────────────────────────────────────────────────────

    async def _request_json(self, method: str, path: str, **kwargs: Any) -> JSONDict:
        result = await self._request(method, path, **kwargs)
        if isinstance(result, dict):
            return result
        return {"raw": result}

    async def _request(self, method: str, path: str, **kwargs: Any) -> PinchTabPayload:
        # Short-circuit when we already know the control plane is offline. We
        # still allow periodic re-probing through ``is_available``.
        cls = type(self)
        if cls._available is False:
            now = asyncio.get_event_loop().time()
            if (now - cls._last_check) < cls._recheck_interval:
                raise PinchTabUnavailable(f"PinchTab control plane offline at {self.base_url}")

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.request(method, f"{self.base_url}{path}", **kwargs) as resp:
                    # Mark as available on any HTTP response.
                    cls._available = True
                    cls._last_check = asyncio.get_event_loop().time()
                    content_type = resp.headers.get("content-type", "")
                    if "application/json" in content_type:
                        return await resp.json()
                    if content_type.startswith("image/") or content_type == "application/octet-stream":
                        return await resp.read()
                    return await resp.text()
        except aiohttp.ClientConnectorError as exc:
            cls._available = False
            cls._last_check = asyncio.get_event_loop().time()
            if not cls._logged_unavailable:
                logger.info(
                    "[PinchTabClient] control plane offline at %s (%s); "
                    "browser stack will use OpenClaw/Playwright instead",
                    self.base_url,
                    type(exc).__name__,
                )
                cls._logged_unavailable = True
            raise PinchTabUnavailable(f"PinchTab control plane offline at {self.base_url}") from exc
        except (TimeoutError, aiohttp.ServerTimeoutError) as exc:
            cls._available = False
            cls._last_check = asyncio.get_event_loop().time()
            if not cls._logged_unavailable:
                logger.info(
                    "[PinchTabClient] control plane timed out at %s (%s); "
                    "browser stack will use OpenClaw/Playwright instead",
                    self.base_url,
                    type(exc).__name__,
                )
                cls._logged_unavailable = True
            raise PinchTabUnavailable(f"PinchTab control plane timed out at {self.base_url}") from exc
