"""
BASE ARSENAL MODULE
Role: Template for all attack/scan modules (weapons).
Extracted from base.py to eliminate the duplicate BaseAgent class.
The canonical BaseAgent lives in hive.py.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

logger = logging.getLogger(__name__)


class BaseArsenalModule(ABC):
    """
    The Weapon Template.
    All attack/scan modules inherit from this class.
    """

    def __init__(self):
        self.name = "Unknown Module"
        self.description = "Generic Module"

    @abstractmethod
    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        """INPUT -> PAYLOADS. Must be pure, no execution."""
        pass

    @abstractmethod
    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """OBSERVE. Pure string evaluation of all generated payloads."""
        pass

    @property
    def cortex(self):
        """Lazy-load CortexEngine for hybrid AI in arsenal modules."""
        if not hasattr(self, "_cortex") or self._cortex is None:
            from backend.ai.cortex import get_cortex_engine

            self._cortex = get_cortex_engine()
        return self._cortex

    async def think(self, context: Any):
        """
        The AI Integration Slot.
        Override this with specific logic (LLM, Heuristic, etc).
        All agents/modules have access to self.cortex (CortexEngine) for hybrid AI.
        """
        pass

    async def async_fetch(self, url: str, timeout: int = 5):
        """Helper to fetch content from HTTP or local FILE protocol."""
        if url.startswith("file:///"):
            path = url.replace("file:///", "").replace("%20", " ")
            try:
                with open(path, encoding="utf-8") as f:
                    return await asyncio.wait_for(asyncio.to_thread(f.read), timeout=10)
            except Exception as e:
                return f"Error reading file: {e}"
        else:
            import aiohttp

            from backend.core.content_boundary import content_boundary
            from backend.core.proxy import network_interceptor

            try:
                async with aiohttp.ClientSession() as session:
                    response = await network_interceptor.fetch("GET", url, session=session, timeout=timeout)
                    body = response.body[: 5 * 1024 * 1024]
                    return content_boundary.wrap_http_response(response.status, response.headers, body, response.url)
            except TimeoutError:
                return f"Error: Request timed out after {timeout}s (Possible Tarpit)"
            except Exception as e:
                return f"Error: Request failed {e}"

    @staticmethod
    def safe_json_parse(raw_text: str, max_depth: int = 100):
        """
        Safe JSON parser with depth limiter.
        Prevents RecursionError from deeply nested JSON bombs.
        """
        depth = 0
        max_seen = 0
        for char in raw_text[:10000]:
            if char in ("{", "["):
                depth += 1
                if depth > max_seen:
                    max_seen = depth
            elif char in ("}", "]"):
                depth -= 1

        if max_seen > max_depth:
            return {"error": f"JSON depth {max_seen} exceeds limit {max_depth}", "truncated": True}

        try:
            return json.loads(raw_text)
        except (json.JSONDecodeError, RecursionError) as e:
            return {"error": f"JSON parse failed: {e}", "raw_preview": raw_text[:200]}

    def log(self, msg):
        logging.info(f"[{self.name}] {msg}")
