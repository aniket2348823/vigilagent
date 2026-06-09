"""
Unified Browser Automation Engine
==================================
Deeply integrated with Scrapling library.

Source files merged:
  - openclaw_engine.py      -> ScrapplingPlaywrightEngine
  - pinchtab_engine.py       -> ScrapplingPinchTabEngine
  - pinchtab_client.py       -> ScrapplingPinchTabClient
  - cluster/pinchtab.py      -> ScrapplingFuzzer
  - pinchtab_intel.py        -> ScraplingIntel
  - playwright_fallback.py   -> (merged into PlaywrightEngine)
  - browser_recon.py         -> ScraplingRecon
  - browser_orchestrator.py  -> Scrappling

Scrapling features deeply integrated:
  - Selector/Selectors      -> Adaptive CSS/XPath parsing
  - StealthyFetcher         -> Anti-bot bypass
  - DynamicFetcher           -> Dynamic content loading
  - Fetcher                  -> Fast HTTP with TLS impersonation
  - FetcherSession           -> Persistent HTTP sessions
  - ProxyRotator             -> Proxy rotation
  - Spider framework         -> Deep crawling with concurrency
  - LinkExtractor            -> Link discovery
  - TextHandler              -> Enhanced text processing
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import time
import uuid
import base64
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qsl, urljoin

from backend.core.config import settings

logger = logging.getLogger(__name__)

# --- Scrapling lazy imports ---
try:
    from scrapling.fetchers import (
        Fetcher, AsyncFetcher, FetcherSession,
        DynamicFetcher, StealthyFetcher,
        AsyncDynamicSession, AsyncStealthySession, DynamicSession, StealthySession,
    )
    from scrapling.engines.toolbelt import ProxyRotator
    from scrapling.parser import Selector, Selectors, Adaptor, Adaptors, SequenceMatcher
    from scrapling.core.custom_types import TextHandler, TextHandlers, AttributesHandler
    _SCRAPLING_AVAILABLE = True
except ImportError:
    _SCRAPLING_AVAILABLE = False
    Fetcher = AsyncFetcher = FetcherSession = None
    DynamicFetcher = StealthyFetcher = ProxyRotator = None
    AsyncDynamicSession = AsyncStealthySession = DynamicSession = StealthySession = None
    Selector = Selectors = TextHandler = TextHandlers = AttributesHandler = None
    Adaptor = Adaptors = SequenceMatcher = None

try:
    from scrapling.spiders import (
        Spider as ScraplingBaseSpider,
        CrawlerEngine as ScraplingCrawlerEngine,
        SessionManager as ScraplingSessionManager,
        LinkExtractor as ScraplingLinkExtractor,
        Request as ScraplingRequest,
        CrawlSpider as ScraplingCrawlSpider,
        SitemapSpider as ScraplingSitemapSpider,
        Scheduler as ScraplingScheduler,
    )
    _SCRAPLING_SPIDERS_AVAILABLE = True
except ImportError:
    _SCRAPLING_SPIDERS_AVAILABLE = False
    ScraplingBaseSpider = ScraplingRequest = None
    ScraplingCrawlSpider = ScraplingSitemapSpider = ScraplingScheduler = None

# Stealth constants
_STEALTH_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-default-apps",
]

_STEALTH_INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
window.chrome = window.chrome || { runtime: {} };
const origQuery = window.navigator.permissions && window.navigator.permissions.query;
if (origQuery) {
  window.navigator.permissions.query = (p) => (
    p && p.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : origQuery(p)
  );
}
"""

_SPA_FRAMEWORKS = {"react", "vue", "angular", "svelte"}

_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

class ScrapplingUnavailable(RuntimeError):
    """Raised when no browser engine can serve the request."""
    pass

class PinchTabUnavailable(RuntimeError):
    """Raised when the PinchTab control plane is offline."""
    pass

class ScrapplingEngine(Enum):
    PLAYWRIGHT = "playwright"
    PINCHTAB = "pinchtab"
    SCRAPLING_STEALTH = "scrapling_stealth"
    SCRAPLING_DYNAMIC = "scrapling_dynamic"
    AUTO = "auto"


class ScraplingSpider:
    """Pentest spider deeply integrated with Scrapling spider framework.
    
    Uses Scrapling Spider, CrawlerEngine, Request, SessionManager for:
    - Concurrent crawling with throttling
    - Proxy rotation via ProxyRotator
    - Pause/resume with checkpointing
    - Per-domain rate limiting
    - robots.txt compliance
    """
    def __init__(self, start_urls: List[str], parse_callback: Optional[Callable] = None,
                 scan_id: str = "", crawl_dir: str = "./crawl_checkpoints",
                 proxy_list: Optional[List[str]] = None,
                 allowed_domains: Optional[List[str]] = None):
        self.start_urls = start_urls
        self.parse_callback = parse_callback
        self.scan_id = scan_id
        self.crawl_dir = crawl_dir
        self.proxy_list = proxy_list or []
        self.allowed_domains = allowed_domains or []
        self._entities: List[Any] = []
        self._spider: Any = None
        self._proxy_rotator: Any = None

    def _build_spider(self) -> Any:
        """Build a Scrapling Spider subclass for pentest crawling."""
        if not _SCRAPLING_SPIDERS_AVAILABLE:
            logger.warning("[ScraplingSpider] scrapling.spiders not available; using lightweight fallback")
            return None

        parent = self

        class _PentestSpider(ScraplingBaseSpider):
            name = "pentest_crawl"
            start_urls = parent.start_urls
            concurrent_requests = 8
            download_delay = 0.5
            robots_txt_obey = False
            fp_include_kwargs = False
            fp_include_headers = False

            def configure_sessions(self, manager):
                from scrapling.fetchers import FetcherSession
                session = FetcherSession(
                    impersonate="chrome",
                    retries=2,
                    retry_delay=0.5,
                    stealthy_headers=True,
                )
                if parent.proxy_list:
                    try:
                        from scrapling.engines.toolbelt import ProxyRotator
                        parent._proxy_rotator = ProxyRotator(parent.proxy_list)
                        session.proxies = parent._proxy_rotator
                    except Exception as e:
                        logger.error(f"[ScraplingSpider] Failed to set proxy rotator: {e}")
                manager.add("default", session)

            async def parse(self, response):
                """Extract pentest entities from each page using Scrapling Selector for adaptive parsing."""
                try:
                    if _SCRAPLING_AVAILABLE and Selector is not None:
                        sel = Selector(content=response.text, url=str(response.url))
                    else:
                        sel = None

                    links = []
                    forms = []
                    scripts = []

                    if sel is not None:
                        links = [a.attrib.get("href", "") for a in sel.css("a[href]")]
                        forms = [f.attrib.get("action", "") for f in sel.css("form[action]")]
                        scripts = [s.attrib.get("src", "") for s in sel.css("script[src]")]
                    else:
                        text = response.text or ""
                        links = [a.get('href', '') for a in re.findall(r'<a[^>]+', text)]
                        forms = [m.group(1) for m in re.finditer(r'action=([^">]+)', text)]
                        scripts = [m.group(1) for m in re.finditer(r'src=([^">]+)', text)]

                    parsed_url = urlparse(response.url)
                    base_uri = f"{parsed_url.scheme}://{parsed_url.netloc}"

                    resolved_links = []
                    for href in links:
                        if not href:
                            continue
                        if href.startswith("/"):
                            resolved_links.append(urljoin(base_uri, href))
                        elif href.startswith(("http://", "https://")):
                            resolved_links.append(href)
                        else:
                            resolved_links.append(urljoin(response.url, href))

                    if parent.allowed_domains:
                        resolved_links = [l for l in resolved_links if urlparse(l).netloc in parent.allowed_domains]

                    result_data = {
                        "url": response.url,
                        "status_code": response.status,
                        "links": resolved_links,
                        "forms": [urljoin(response.url, f) for f in forms if f],
                        "scripts": [urljoin(response.url, s) for s in scripts if s],
                        "text": response.text,
                    }

                    if parent.parse_callback:
                        if asyncio.iscoroutinefunction(parent.parse_callback):
                            await parent.parse_callback(result_data)
                        else:
                            parent.parse_callback(result_data)

                    for link in resolved_links:
                        yield ScraplingRequest(url=link, callback=self.parse)

                except Exception as e:
                    logger.error(f"[ScraplingSpider] Error parsing {response.url}: {e}")

        return _PentestSpider()

    async def _lightweight_crawl(self):
        """Fallback crawl mode when Scrapling is not available."""
        logger.info("[ScraplingSpider] Running lightweight fallback crawl")
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for url in self.start_urls:
                try:
                    async with session.get(url, ssl=False, timeout=10) as resp:
                        text = await resp.text()
                        links = [m[1] for m in re.findall(r'href=["\']([^"\']+)["\']', text)]
                        parsed_url = urlparse(url)
                        base_uri = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        resolved_links = [urljoin(base_uri, l) if l.startswith("/") else l for l in links if l.startswith(("/", "http"))]
                        
                        result_data = {
                            "url": url,
                            "status_code": resp.status,
                            "links": resolved_links,
                            "forms": [],
                            "scripts": [],
                            "text": text,
                        }
                        if self.parse_callback:
                            if asyncio.iscoroutinefunction(self.parse_callback):
                                await self.parse_callback(result_data)
                            else:
                                self.parse_callback(result_data)
                except Exception as e:
                    logger.error(f"[ScraplingSpider] Fallback crawl failed for {url}: {e}")

    async def crawl(self):
        """Run the spider crawl."""
        spider_inst = self._build_spider()
        if spider_inst is None:
            await self._lightweight_crawl()
            return

        try:
            engine = ScraplingCrawlerEngine(spider_inst)
            await engine.start()
        except Exception as e:
            logger.error(f"[ScraplingSpider] CrawlerEngine failed: {e}; using fallback")
            await self._lightweight_crawl()


JSONDict = Dict[str, Any]
PinchTabPayload = Union[JSONDict, List[Any], str, bytes]

class ScrapplingPinchTabClient:
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
        self.base_url = (base_url or getattr(settings, "PINCHTAB_BASE_URL",
                                              "http://127.0.0.1:9867")).rstrip("/")
        try:
            import aiohttp
            self.timeout = aiohttp.ClientTimeout(total=timeout)
            self._probe_timeout = aiohttp.ClientTimeout(total=2)
            self._aiohttp_available = True
        except ImportError:
            self.timeout = None
            self._probe_timeout = None
            self._aiohttp_available = False

    # ── availability ────────────────────────────────────────────────────────

    @classmethod
    def reset_availability(cls) -> None:
        """Force the availability cache to re-probe on next call."""
        cls._available = None
        cls._last_check = 0.0
        cls._logged_unavailable = False

    @classmethod
    def is_known_available(cls) -> bool | None:
        """Return cached availability state without doing network I/O."""
        return cls._available

    async def is_available(self) -> bool:
        """Return True iff the PinchTab control plane is reachable."""
        cls = type(self)
        now = asyncio.get_event_loop().time()
        if cls._available is not None and (now - cls._last_check) < cls._recheck_interval:
            return cls._available

            if not self._aiohttp_available:
                cls = type(self)
                cls._available = False
                cls._last_check = asyncio.get_event_loop().time()
                return False
                return False
            import aiohttp
        try:
            async with aiohttp.ClientSession(timeout=self._probe_timeout) as session:
                async with session.get(f"{self.base_url}/health") as resp:
                    cls._available = 200 <= resp.status < 500
        except Exception as exc:
            cls._available = False
            logger.debug(
                "[PinchTabClient] availability probe at %s failed (%s)",
                self.base_url, type(exc).__name__,
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
        return await self._request_json("POST", "/profiles",
                                        json={"name": name, "description": description})

    async def start_instance(self, profile_id: str | None = None,
                             *, mode: str = "headless") -> JSONDict:
        payload: JSONDict = {"mode": mode}
        if profile_id:
            payload["profileId"] = profile_id
        return await self._request_json("POST", "/instances/start", json=payload)

    async def stop_instance(self, instance_id: str) -> JSONDict:
        return await self._request_json("POST", f"/instances/{instance_id}/stop")

    async def navigate(self, url: str, *, tab_id: str | None = None,
                       wait_for: str = "networkidle") -> JSONDict:
        payload: JSONDict = {"url": url, "waitFor": wait_for, "blockMedia": True}
        if tab_id:
            payload["tabId"] = tab_id
        return await self._request_json("POST", "/navigate", json=payload)

    async def snapshot(self, tab_id: str, *, max_tokens: int = 1200) -> PinchTabPayload:
        return await self._request("GET",
            f"/tabs/{tab_id}/snapshot?interactive=true&compact=true&maxTokens={max_tokens}")

    async def text(self, tab_id: str, *, max_chars: int = 20000) -> PinchTabPayload:
        return await self._request("GET",
            f"/tabs/{tab_id}/text?format=text&maxChars={max_chars}")

    async def network(self, tab_id: str, *, limit: int = 200) -> JSONDict:
        return await self._request_json("GET", f"/tabs/{tab_id}/network?limit={limit}")

    async def network_detail(self, tab_id: str, request_id: str,
                             *, body: bool = False) -> JSONDict:
        include_body = "true" if body else "false"
        return await self._request_json("GET",
            f"/tabs/{tab_id}/network/{request_id}?body={include_body}")

    async def console(self, tab_id: str, *, limit: int = 100) -> JSONDict:
        return await self._request_json("GET", f"/console?tabId={tab_id}&limit={limit}")

    async def errors(self, tab_id: str, *, limit: int = 100) -> JSONDict:
        return await self._request_json("GET", f"/errors?tabId={tab_id}&limit={limit}")

    async def cookies(self, tab_id: str) -> JSONDict:
        return await self._request_json("GET", f"/tabs/{tab_id}/cookies")

    async def wait_for_load(self, tab_id: str, *, timeout_ms: int = 30000) -> JSONDict:
        return await self._request_json("POST", f"/tabs/{tab_id}/wait",
                                        json={"load": "networkidle", "timeout": timeout_ms})

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
        if not self._aiohttp_available:
            raise PinchTabUnavailable("aiohttp not installed")
        import aiohttp
        cls = type(self)
        if cls._available is False:
            now = asyncio.get_event_loop().time()
            if (now - cls._last_check) < cls._recheck_interval:
                raise PinchTabUnavailable(
                    f"PinchTab control plane offline at {self.base_url}")

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.request(method, f"{self.base_url}{path}", **kwargs) as resp:
                    cls._available = True
                    cls._last_check = asyncio.get_event_loop().time()
                    content_type = resp.headers.get("content-type", "")
                    if "application/json" in content_type:
                        return await resp.json()
                    if (content_type.startswith("image/") or
                            content_type == "application/octet-stream"):
                        return await resp.read()
                    return await resp.text()
        except aiohttp.ClientConnectorError as exc:
            cls._available = False
            cls._last_check = asyncio.get_event_loop().time()
            if not cls._logged_unavailable:
                logger.info(
                    "[PinchTabClient] control plane offline at %s (%s); "
                    "browser stack will use OpenClaw/Playwright instead",
                    self.base_url, type(exc).__name__,
                )
                cls._logged_unavailable = True
            raise PinchTabUnavailable(
                f"PinchTab control plane offline at {self.base_url}") from exc
        except (asyncio.TimeoutError, aiohttp.ServerTimeoutError) as exc:
            cls._available = False
            cls._last_check = asyncio.get_event_loop().time()
            if not cls._logged_unavailable:
                logger.info(
                    "[PinchTabClient] control plane timed out at %s (%s); "
                    "browser stack will use OpenClaw/Playwright instead",
                    self.base_url, type(exc).__name__,
                )
                cls._logged_unavailable = True
            raise PinchTabUnavailable(
                f"PinchTab control plane timed out at {self.base_url}") from exc


class ScrapplingPinchTabEngine:
    """Fast browser operations using PinchTab (degrades silently when offline)."""

    def __init__(self) -> None:
        self.client = ScrapplingPinchTabClient()
        self.last_tab_id: str | None = None
        self.last_url: str | None = None
        self._available: bool = False
        self._session = FetcherSession() if _SCRAPLING_AVAILABLE and FetcherSession is not None else None

    async def initialize(self) -> bool:
        """Probe the control plane. Returns True iff PinchTab is reachable."""
        try:
            self._available = await self.client.is_available()
        except Exception as exc:
            logger.info(
                "[PinchTabEngine] availability probe failed: %s: %s",
                type(exc).__name__, str(exc)[:120],
            )
            self._available = False

        if self._available:
            logger.info("[PinchTabEngine] control plane online at %s", self.client.base_url)
        return self._available

    def is_available(self) -> bool:
        """Synchronous accessor used by the orchestrator and intel modules."""
        return bool(self._available)

    async def _ensure_available(self) -> bool:
        """Recheck availability lazily so the engine can recover if PinchTab
        comes online mid-scan, but never spams the network."""
        if self._available:
            return True
        self._available = await self.client.is_available()
        return self._available

    def _parse_with_scrapling(self, content: str) -> Optional[Selector]:
        if _SCRAPLING_AVAILABLE and Selector is not None:
            try:
                return Selector(content=content)
            except Exception as e:
                logger.debug("[ScrapplingPinchTabEngine] Scrapling Selector parse failed: %s", e)
        return None

    # ── public API ──────────────────────────────────────────────────────────

    async def navigate(self, url: str) -> Dict[str, Any]:
        """Fast navigation to URL."""
        if not await self._ensure_available():
            return {"tab_id": None, "url": url, "success": False, "error": "pinchtab_offline"}
        try:
            result = await self.client.navigate(url)
            self.last_tab_id = result.get("tabId") or result.get("id") or result.get("targetId")
            self.last_url = url
            return {"tab_id": self.last_tab_id, "url": url, "success": True}
        except PinchTabUnavailable as exc:
            self._available = False
            return {"tab_id": None, "url": url, "success": False, "error": str(exc)}
        except Exception as exc:
            logger.debug("[PinchTabEngine] navigate(%s) failed: %s", url, exc)
            return {"tab_id": None, "url": url, "success": False, "error": str(exc)}

    async def extract_endpoints_fast(self, url: str) -> List[str]:
        """Fast endpoint extraction using Scrapling Selector with regex fallback."""
        if not await self._ensure_available():
            return []
        nav = await self.navigate(url)
        if not nav.get("success") or not self.last_tab_id:
            return []
        try:
            text = await self.client.text(self.last_tab_id)
            text_str = str(text)
            endpoints: set[str] = set()

            # Scrapling integration
            sel = self._parse_with_scrapling(text_str)
            if sel:
                for a in sel.css("a[href]"):
                    href = a.attrib.get("href", "")
                    if href.startswith(("/", "http")):
                        endpoints.add(href)
                for f in sel.css("form[action]"):
                    action = f.attrib.get("action", "")
                    if action:
                        endpoints.add(action)

            # Regex fallback
            patterns = [
                r"['\"](/(?:api|v\d+)/[^'\"]+)['\"]",
                r"['\"](/(?:graphql|rest|rpc)[^'\"]*)['\"]",
                r"fetch\(['\"]([^'\"]+)['\"]",
                r"axios\.[a-z]+\(['\"]([^'\"]+)['\"]",
            ]
            for pattern in patterns:
                for match in re.findall(pattern, text_str, re.IGNORECASE):
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    if match:
                        endpoints.add(match.strip("'\""))
            return list(endpoints)
        except PinchTabUnavailable:
            self._available = False
            return []
        except Exception as exc:
            logger.debug("[PinchTabEngine] extract_endpoints_fast failed: %s", exc)
            return []

    async def extract_tokens(self, url: str) -> List[str]:
        """Fast token extraction (JWT / Bearer / API keys)."""
        if not await self._ensure_available():
            return []
        nav = await self.navigate(url)
        if not nav.get("success") or not self.last_tab_id:
            return []
        try:
            text = await self.client.text(self.last_tab_id)
            text_str = str(text)
            tokens: set[str] = set()
            tokens.update(re.findall(
                r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text_str))
            tokens.update(re.findall(
                r"Bearer\s+([A-Za-z0-9_-]{20,})", text_str, re.IGNORECASE))
            tokens.update(re.findall(
                r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{20,})['\"]",
                text_str, re.IGNORECASE))
            return list(tokens)
        except PinchTabUnavailable:
            self._available = False
            return []
        except Exception as exc:
            logger.debug("[PinchTabEngine] extract_tokens failed: %s", exc)
            return []

    async def test_injection(self, url: str, payload: str,
                             method: str = "GET") -> Dict[str, Any]:
        """Fast injection test — checks if payload is reflected in response."""
        if not await self._ensure_available():
            return {"reflected": False, "error": "pinchtab_offline"}
        test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
        nav = await self.navigate(test_url)
        if not nav.get("success") or not self.last_tab_id:
            return {"reflected": False, "error": nav.get("error", "navigation_failed")}
        try:
            text = await self.client.text(self.last_tab_id)
            text_str = str(text)
            reflected = False
            sel = self._parse_with_scrapling(text_str)
            if sel:
                reflected = payload in text_str or len(sel.xpath(f"//*[contains(text(), '{payload}')]")) > 0
            else:
                reflected = payload in text_str
            return {"reflected": reflected, "payload": payload, "url": test_url}
        except PinchTabUnavailable:
            self._available = False
            return {"reflected": False, "error": "pinchtab_offline"}
        except Exception as exc:
            return {"reflected": False, "error": str(exc)}

    async def analyze_dom(self, url: str) -> Dict[str, Any]:
        """Analyze DOM structure using Scrapling Selector with regex fallback."""
        if not await self._ensure_available():
            return {}
        nav = await self.navigate(url)
        if not nav.get("success") or not self.last_tab_id:
            return {}
        try:
            text = await self.client.text(self.last_tab_id)
            snapshot = await self.client.snapshot(self.last_tab_id)
            text_str = str(text)

            forms = []
            inputs = []
            buttons = []

            sel = self._parse_with_scrapling(text_str)
            if sel:
                for f in sel.css("form"):
                    action = f.attrib.get("action", "")
                    forms.append({"action": action})
                for i in sel.css("input"):
                    name = i.attrib.get("name", "")
                    itype = i.attrib.get("type", "text")
                    inputs.append({"name": name, "type": itype})
                for b in sel.css("button"):
                    buttons.append({"text": b.text})
            else:
                forms = [{"action": a} for a in re.findall(
                    r'<form[^>]*action=["\']([^"\']+)["\']', text_str, re.IGNORECASE)]
                inputs = [{"name": n, "type": t} for n, t in re.findall(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']([^"\']+)["\']',
                    text_str, re.IGNORECASE)]
                buttons = [{"text": b} for b in re.findall(
                    r'<button[^>]*>([^<]+)</button>', text_str, re.IGNORECASE)]

            return {
                "forms": forms,
                "inputs": inputs,
                "buttons": buttons,
                "text": text_str[:1000],
                "snapshot": snapshot,
            }
        except PinchTabUnavailable:
            self._available = False
            return {}
        except Exception as exc:
            logger.debug("[PinchTabEngine] analyze_dom failed: %s", exc)
            return {}

    async def get_page_text(self) -> str:
        """Get page text content for the last opened tab."""
        if not self._available or not self.last_tab_id:
            return ""
        try:
            return str(await self.client.text(self.last_tab_id))
        except PinchTabUnavailable:
            self._available = False
            return ""
        except Exception as exc:
            logger.debug("[PinchTabEngine] get_page_text failed: %s", exc)
            return ""

    async def close(self) -> None:
        """Cleanup references."""
        self.last_tab_id = None
        self.last_url = None

PinchTabEngine = ScrapplingPinchTabEngine


class ScrapplingPlaywrightEngine:
    """Deep browser automation backed by Playwright Chromium."""

    def __init__(self) -> None:
        self.client: Any = None
        self.workflow_engine: Any = None
        self.active_contexts: Dict[str, Any] = {}
        self.current_page: Any = None
        self.current_context: Any = None
        self.last_init_error: str = ""
        self._playwright: Any = None
        self._browser: Any = None
        self._network_log: List[Dict[str, Any]] = []
        self._init_lock = asyncio.Lock()

    async def initialize(self) -> bool:
        """Launch headless Chromium. Returns True on success, False otherwise."""
        async with self._init_lock:
            if self._browser is not None:
                return True
            try:
                from playwright.async_api import async_playwright
            except ImportError as exc:
                self.last_init_error = (
                    f"playwright_not_installed: {exc}. "
                    "Install with: pip install playwright"
                )
                logger.warning(
                    "[ScrapplingPlaywrightEngine] Playwright Python package not installed: %s. "
                    "Run: pip install playwright",
                    exc,
                )
                return False
            except Exception as exc:
                self.last_init_error = f"playwright_import_failed: {type(exc).__name__}: {exc}"
                logger.warning(
                    "[ScrapplingPlaywrightEngine] Playwright import failed (%s: %s); engine disabled",
                    type(exc).__name__, exc,
                )
                return False

            try:
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=getattr(settings, "OPENCLAW_HEADLESS", True),
                    args=_STEALTH_LAUNCH_ARGS,
                )
                _probe_ctx = await self._browser.new_context()
                await _probe_ctx.close()

                self.client = self._browser
                self.last_init_error = ""
                logger.info(
                    "[ScrapplingPlaywrightEngine] Playwright Chromium launched headless=%s",
                    getattr(settings, "OPENCLAW_HEADLESS", True),
                )
                return True
            except Exception as exc:
                try:
                    if self._playwright:
                        await self._playwright.stop()
                except Exception:
                    logger.debug("[] error", exc_info=True)
                self._playwright = None
                self._browser = None
                self.client = None

                msg = str(exc)
                if "Executable doesn't exist" in msg or "playwright install" in msg:
                    self.last_init_error = (
                        "playwright_browsers_not_installed: "
                        "run `python -m playwright install chromium` "
                        f"({type(exc).__name__}: {msg[:200]})"
                    )
                    logger.warning(
                        "[ScrapplingPlaywrightEngine] Chromium binary missing. "
                        "Run: python -m playwright install chromium  (full error: %s)",
                        msg[:300],
                    )
                else:
                    self.last_init_error = f"{type(exc).__name__}: {msg[:200]}"
                    logger.warning(
                        "[ScrapplingPlaywrightEngine] Chromium launch failed (%s: %s); engine disabled",
                        type(exc).__name__, msg[:300],
                    )
                return False

    async def is_truly_available(self) -> bool:
        """Probe whether the engine can actually serve work right now."""
        if not self._browser:
            return False
        try:
            ctx = await self._browser.new_context()
            await ctx.close()
            return True
        except Exception as exc:
            logger.info(
                "[ScrapplingPlaywrightEngine] is_truly_available probe failed: %s: %s",
                type(exc).__name__, str(exc)[:200],
            )
            return False

    async def _ensure_context(self, *, stealth: bool = False) -> Any:
        """Create (or return existing) browser context + page."""
        if not self._browser:
            raise RuntimeError("ScrapplingPlaywrightEngine not initialized")

        if self.current_context and self.current_page:
            return self.current_context

        viewport = {
            "width": int(getattr(settings, "OPENCLAW_VIEWPORT_WIDTH", 1440) or 1440),
            "height": int(getattr(settings, "OPENCLAW_VIEWPORT_HEIGHT", 900) or 900),
        }
        ctx_kwargs: Dict[str, Any] = {
            "viewport": viewport,
            "ignore_https_errors": True,
        }
        ua = getattr(settings, "OPENCLAW_USER_AGENT", "")
        if ua:
            ctx_kwargs["user_agent"] = ua

        context = await self._browser.new_context(**ctx_kwargs)
        if stealth or getattr(settings, "OPENCLAW_STEALTH_MODE", True):
            try:
                await context.add_init_script(_STEALTH_INIT_SCRIPT)
            except Exception as exc:
                logger.debug("[ScrapplingPlaywrightEngine] Stealth init script failed: %s", exc)

        page = await context.new_page()
        self._network_log = []

        def _on_request(request):
            try:
                self._network_log.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "resource_type": request.resource_type,
                    "post_data": request.post_data,
                })
            except Exception:
                logger.debug("[_on_request] error", exc_info=True)

        page.on("request", _on_request)
        self.current_context = context
        self.current_page = page
        return context

    async def navigate(self, url: str, *, stealth: bool = False,
                       wait_for: str = "networkidle") -> Dict[str, Any]:
        """Navigate to URL, returning a structured result with success flag."""
        if not self._browser:
            raise RuntimeError("ScrapplingPlaywrightEngine not initialized")

        await self._ensure_context(stealth=stealth)
        page = self.current_page
        try:
            try:
                resp = await page.goto(url, wait_until=wait_for, timeout=30000)
            except Exception:
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            status_code = resp.status if resp else 0
            return {
                "context": self.current_context,
                "page": page,
                "url": url,
                "status_code": status_code,
                "success": True,
            }
        except Exception as exc:
            logger.info("[ScrapplingPlaywrightEngine] navigate(%s) failed: %s: %s",
                        url, type(exc).__name__, str(exc)[:200])
            return {
                "context": self.current_context,
                "page": page,
                "url": url,
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
            }

    async def extract_endpoints_deep(self, url: str) -> List[Dict[str, Any]]:
        """Deep endpoint extraction using Scrapling Selector DOM parsing and network interception."""
        result = await self.navigate(url)
        if not result.get("success"):
            return []
        page = result["page"]

        try:
            await page.wait_for_timeout(800)
        except Exception:
            logger.debug("[extract_endpoints_deep] error", exc_info=True)

        endpoints: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for req in list(self._network_log):
            u = req.get("url") or ""
            if u and u not in seen:
                seen.add(u)
                endpoints.append({
                    "url": u,
                    "method": req.get("method", "GET"),
                    "source": "network",
                    "headers": req.get("headers", {}),
                })

        try:
            content = await page.content()
            if _SCRAPLING_AVAILABLE and Selector is not None:
                sel = Selector(content=content)
                for a in sel.css("a[href]"):
                    href = a.attrib.get("href", "")
                    if href and href not in seen:
                        seen.add(href)
                        endpoints.append({"url": href, "method": "GET", "source": "dom_scrapling"})
                for f in sel.css("form[action]"):
                    action = f.attrib.get("action", "")
                    if action and action not in seen:
                        seen.add(action)
                        endpoints.append({"url": action, "method": "POST", "source": "dom_scrapling"})
        except Exception as exc:
            logger.debug("[ScrapplingPlaywrightEngine] Scrapling DOM parsing failed: %s", exc)

        try:
            extracted = await page.evaluate(
                """() => {
                    const out = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {
                        const h = a.getAttribute('href');
                        if (h) out.add(h);
                    });
                    document.querySelectorAll('form[action]').forEach(f => {
                        const h = f.getAttribute('action');
                        if (h) out.add(h);
                    });
                    document.querySelectorAll('script').forEach(s => {
                        const t = s.textContent || '';
                        const re = /["'](\\/[A-Za-z0-9_./?=&%-]+)["']/g;
                        let m; while ((m = re.exec(t)) !== null) { out.add(m[1]); }
                    });
                    if (window.__REACT_ROUTER__ && window.__REACT_ROUTER__.routes) {
                        window.__REACT_ROUTER__.routes.forEach(r => { if (r.path) out.add(r.path); });
                    }
                    if (window.$router && window.$router.options) {
                        (window.$router.options.routes || []).forEach(r => {
                            if (r.path) out.add(r.path);
                        });
                    }
                    return Array.from(out);
                }"""
            )
            for href in extracted or []:
                if href and href not in seen:
                    seen.add(href)
                    endpoints.append({"url": href, "method": "GET", "source": "dom"})
        except Exception as exc:
            logger.debug("[ScrapplingPlaywrightEngine] DOM endpoint extraction failed: %s", exc)

        return endpoints

    async def execute_workflow(self, workflow: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
        """Execute multi-step workflow."""
        if not self.current_page:
            await self._ensure_context()
        page = self.current_page
        results: List[Dict[str, Any]] = []

        for step in workflow.get("steps", []):
            action = step.get("action")
            try:
                if action == "navigate":
                    await page.goto(step["url"])
                    results.append({"step": action, "success": True})
                elif action == "fill":
                    await page.fill(step["selector"], step["value"])
                    results.append({"step": action, "selector": step["selector"], "success": True})
                elif action == "click":
                    await page.click(step["selector"])
                    results.append({"step": action, "selector": step["selector"], "success": True})
                elif action == "wait":
                    condition = step.get("condition", "networkidle")
                    if condition in ("networkidle", "load", "domcontentloaded"):
                        await page.wait_for_load_state(condition)
                    else:
                        await asyncio.sleep(step.get("duration", 1))
                    results.append({"step": action, "success": True})
                elif action == "extract":
                    el = await page.query_selector(step["selector"])
                    text = await el.text_content() if el else None
                    results.append({"step": action, "selector": step["selector"],
                                    "data": text, "success": True})
                else:
                    results.append({"step": action, "success": False,
                                    "error": f"unknown_action:{action}"})
            except Exception as exc:
                results.append({"step": action, "success": False, "error": str(exc)})
                if not step.get("continue_on_error", False):
                    break

        return {"workflow": workflow.get("name", "unnamed"), "results": results}

    async def test_xss_payload(self, url: str, payload: str) -> Dict[str, Any]:
        """Test XSS payload in real browser context."""
        result = await self.navigate(url)
        if not result.get("success"):
            return {"alert_triggered": False, "dom_modified": False, "exploited": False,
                    "payload": payload, "error": result.get("error", "navigation_failed")}
        page = result["page"]

        await page.evaluate("""() => {
            window.__alertFired = false;
            const orig = window.alert;
            window.alert = function() { window.__alertFired = true; return orig.apply(this, arguments); };
        }""")

        dom_before = await page.content()
        try:
            await page.evaluate(
                "(p) => { document.body.innerHTML += p; }",
                payload,
            )
        except Exception:
            logger.debug("[test_xss_payload] error", exc_info=True)

        alert_fired = bool(await page.evaluate("window.__alertFired || false"))
        dom_after = await page.content()
        dom_modified = dom_before != dom_after and payload in dom_after

        return {
            "alert_triggered": alert_fired,
            "dom_modified": dom_modified,
            "console_errors": [],
            "exploited": alert_fired or dom_modified,
            "payload": payload,
        }

    async def detect_framework(self, url: str) -> Optional[str]:
        """Detect JavaScript framework on the page."""
        result = await self.navigate(url)
        if not result.get("success"):
            return None
        page = result["page"]
        try:
            return await page.evaluate("""() => {
                if (window.React || document.querySelector('[data-reactroot]')) return 'React';
                if (window.Vue || document.querySelector('[data-v-]')) return 'Vue';
                if (window.angular || document.querySelector('[ng-app]')) return 'Angular';
                if (window.Ember) return 'Ember';
                if (window.Backbone) return 'Backbone';
                return null;
            }""")
        except Exception as exc:
            logger.debug("[ScrapplingPlaywrightEngine] framework detection failed: %s", exc)
            return None

    async def intercept_network(self, url: str) -> List[Dict[str, Any]]:
        """Navigate and return the captured network log for the page."""
        result = await self.navigate(url)
        if not result.get("success"):
            return []
        try:
            await result["page"].wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            logger.debug("[intercept_network] error", exc_info=True)
        return list(self._network_log)

    async def find_websockets(self, url: str) -> List[str]:
        """Find WebSocket URLs initiated by the page."""
        await self._ensure_context()
        page = self.current_page
        try:
            await page.add_init_script("""
                (() => {
                    if (!window.__wsCapturing) {
                        window.__capturedWS = [];
                        const Orig = window.WebSocket;
                        window.WebSocket = function(u, p) {
                            window.__capturedWS.push(u);
                            return new Orig(u, p);
                        };
                        window.__wsCapturing = true;
                    }
                })();
            """)
        except Exception:
            logger.debug("[find_websockets] error", exc_info=True)
        result = await self.navigate(url)
        if not result.get("success"):
            return []
        try:
            captured = await page.evaluate("window.__capturedWS || []")
            return list(captured or [])
        except Exception:
            return []

    async def extract_tokens(self, url: str) -> List[str]:
        """Extract auth tokens from page content + localStorage."""
        result = await self.navigate(url)
        if not result.get("success"):
            return []
        page = result["page"]

        content = await page.content()
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
        tokens = set(re.findall(jwt_pattern, content))
        try:
            local_storage = await page.evaluate("() => Object.entries(localStorage)")
            for entry in local_storage or []:
                if not isinstance(entry, list) or len(entry) < 2:
                    continue
                key, value = entry[0], entry[1]
                if isinstance(key, str) and ("token" in key.lower() or "auth" in key.lower()):
                    tokens.add(str(value))
        except Exception:
            logger.debug("[extract_tokens] error", exc_info=True)
        return list(tokens)

    async def capture_screenshot(self, scan_id: str, label: str) -> Optional[Path]:
        """Capture screenshot of the current page."""
        if not self.current_page:
            return None
        screenshot_dir = Path("reports/forensics")
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{scan_id}_{label}_{timestamp}.png"
        filepath = screenshot_dir / filename
        try:
            await self.current_page.screenshot(path=str(filepath), full_page=True)
            return filepath
        except Exception as exc:
            logger.debug("[ScrapplingPlaywrightEngine] screenshot failed: %s", exc)
            return None

    async def capture_dom(self, scan_id: str, label: str) -> Optional[Path]:
        """Capture DOM snapshot of the current page."""
        if not self.current_page:
            return None
        dom_dir = Path("reports/forensics")
        dom_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{scan_id}_{label}_{timestamp}.html"
        filepath = dom_dir / filename
        try:
            content = await self.current_page.content()
            filepath.write_text(content, encoding="utf-8")
            return filepath
        except Exception as exc:
            logger.debug("[ScrapplingPlaywrightEngine] capture_dom failed: %s", exc)
            return None

    async def get_network_log(self) -> List[Dict[str, Any]]:
        """Return captured network requests for the current page."""
        return list(self._network_log)

    async def get_page_text(self) -> str:
        """Return body text content of current page."""
        if not self.current_page:
            return ""
        try:
            return await self.current_page.text_content("body") or ""
        except Exception:
            return ""

    async def close(self) -> None:
        """Close all contexts and tear down Playwright cleanly."""
        for ctx in list(self.active_contexts.values()):
            try:
                await ctx.close()
            except Exception as exc:
                logger.debug("[ScrapplingPlaywrightEngine] active context close failed: %s", exc)
        self.active_contexts.clear()

        if self.current_context:
            try:
                await self.current_context.close()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self.current_context = None
            self.current_page = None

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self._browser = None
            self.client = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self._playwright = None

OpenClawEngine = ScrapplingPlaywrightEngine
PlaywrightFallback = ScrapplingPlaywrightEngine


class ScrapplingFuzzer:
    """Isolated browser execution for complex DOM fuzzing and IDOR detection."""

    def __init__(self, worker_id: str, port: int):
        self.worker_id = worker_id
        self.port = port
        self.profile_path = os.path.join(tempfile.gettempdir(), "pinchtab_profiles", worker_id)
        self.browser = None
        self.context = None
        self.page = None
        self.client = ScrapplingPinchTabClient()
        self.instance_id = ""
        self.profile_id = ""
        self.tab_id = ""
        self.using_control_plane = False
        self._lifecycle_lock = asyncio.Lock()
        os.makedirs(self.profile_path, exist_ok=True)

    async def start(self):
        async with self._lifecycle_lock:
            try:
                await self.client.health()
                profile = await self.client.create_profile(f"worker-{self.worker_id}", "Vulagent worker browser profile")
                self.profile_id = str(profile.get("id") or profile.get("profileId") or "")
                instance = await self.client.start_instance(self.profile_id or None, mode="headless")
                self.instance_id = str(instance.get("id") or instance.get("instanceId") or "")
                self.using_control_plane = bool(self.instance_id)
                if self.using_control_plane:
                    print(f"PinchTab control-plane instance online (Worker: {self.worker_id}, Instance: {self.instance_id})")
                    return
            except Exception as e:
                print(f"PinchTab control-plane unavailable for worker {self.worker_id}; using local Playwright fallback: {e}")

            try:
                from playwright.async_api import async_playwright
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        f"--user-data-dir={self.profile_path}",
                        f"--remote-debugging-port={self.port}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage"
                    ]
                )
                self.context = await self.browser.new_context()
                self.page = await self.context.new_page()
                print(f"PinchTab Playwright fallback online (Worker: {self.worker_id}, Port: {self.port})")
            except Exception as e:
                print(f"PinchTab failed to initialize: {e}")

    async def execute_flow(self, flow_config: Dict) -> Dict:
        results = {"steps": [], "findings": []}
        try:
            for step in flow_config.get("actions_mapped", []):
                step_result = await self._execute_semantic_step(step, flow_config.get("target_url"))
                if step_result:
                    results["steps"].append(step_result)

                if step_result and step_result.get("success"):
                    vulnerabilities = await self._check_vulnerabilities(step_result)
                    results["findings"].extend(vulnerabilities)
            results["post_state"] = await self._extract_state()
        except Exception as e:
            results["error"] = str(e)
        return results

    async def _execute_semantic_step(self, step: Dict, target_url: str) -> Optional[Dict]:
        result = {"action": step["type"], "target": step["target"], "success": False}
        try:
            if self.using_control_plane:
                if target_url and not self.tab_id:
                    nav = await self.client.navigate(target_url)
                    self.tab_id = str(nav.get("tabId") or nav.get("id") or nav.get("targetId") or "")
                    if self.tab_id:
                        await self.client.wait_for_load(self.tab_id)
                if not self.tab_id:
                    result["error"] = "pinchtab_tab_unavailable"
                    return result

                target_str = str(step["target"])
                selector = None
                if _SCRAPLING_AVAILABLE and Selector is not None:
                    try:
                        html = await self.client.text(self.tab_id)
                        sel = Selector(content=str(html))
                        if step["type"] == "input":
                            match = sel.css(f"input[name='{target_str}'], input[id='{target_str}']")
                            if match:
                                selector = f"input[name='{target_str}']"
                    except Exception as e:
                        logger.debug("[ScrapplingFuzzer] Scrapling Selector matching failed: %s", e)

                if step["type"] == "input":
                    if not selector:
                        selector = f"input[name='{target_str}'], input[id='{target_str}'], *[placeholder*='{target_str}' i]"
                    await self.client.action(self.tab_id, "fill", selector=selector, value="xytherion_fuzz_payload")
                    result["success"] = True
                elif step["type"] == "click":
                    await self.client.action(self.tab_id, "click", selector=f"text:{target_str}", wait_nav=True)
                    result["success"] = True
                return result

            target_str = str(step["target"])
            if step["type"] == "input":
                selector = f"input[name='{target_str}'], input[id='{target_str}'], *[placeholder*='{target_str}' i]"
                if await self.page.locator(selector).count() > 0:
                    await self.page.fill(selector, "xytherion_fuzz_payload")
                    result["success"] = True
            elif step["type"] == "click":
                selector = f"button:text-matches('(?i){target_str}'), input[type='submit'][value*='(?i){target_str}']"
                if await self.page.locator(selector).count() > 0:
                    await self.page.click(selector)
                    result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        return result

    async def _extract_state(self) -> Dict:
        state = {"cookies": [], "tokens": {}}
        try:
            if self.using_control_plane and self.tab_id:
                state["cookies"] = await self.client.cookies(self.tab_id)
                state["text"] = await self.client.text(self.tab_id)
                state["network"] = await self.client.network(self.tab_id)
                return state

            state["cookies"] = await self.context.cookies()
            local_storage = await self.page.evaluate("() => JSON.stringify(window.localStorage)")
            session_storage = await self.page.evaluate("() => JSON.stringify(window.sessionStorage)")
            state["tokens"]["local"] = json.loads(local_storage)
            state["tokens"]["session"] = json.loads(session_storage)
        except Exception:
            logger.debug("[_extract_state] error", exc_info=True)
        return state

    async def _check_vulnerabilities(self, step_result: Dict) -> List[Dict]:
        vulns = []
        if self.using_control_plane and self.tab_id:
            content = str(await self.client.text(self.tab_id))
            if "<script>alert(1)</script>" in content:
                vulns.append({"type": "xss", "severity": "HIGH", "desc": "Reflected payload text detected."})
            return vulns

        content = await self.page.content()
        if "<script>alert(1)</script>" in content:
            vulns.append({"type": "xss", "severity": "HIGH", "desc": "Reflected Payload detected."})
        return vulns

    async def stop(self):
        async with self._lifecycle_lock:
            try:
                if self.using_control_plane and self.instance_id:
                    await self.client.stop_instance(self.instance_id)
                    self.using_control_plane = False
                    return

                if self.browser:
                    await self.browser.close()
                if hasattr(self, 'playwright'):
                    await self.playwright.stop()
                if os.path.exists(self.profile_path):
                    shutil.rmtree(self.profile_path, ignore_errors=True)
            except Exception:
                logger.debug("[stop] error", exc_info=True)

PinchTabInstance = ScrapplingFuzzer


class ScraplingIntel:
    """Deep browser intelligence extraction through PinchTab."""

    def __init__(self, browser, scan_id: str, *, agent_name: str = "agent_alpha"):
        self.browser = browser
        self.scan_id = scan_id
        self.agent_name = agent_name
        self.client = ScrapplingPinchTabClient()
        self._seen: set[str] = set()

    async def is_available(self) -> tuple[bool, str]:
        """Check whether the PinchTab control plane is reachable."""
        try:
            ok = await self.client.is_available()
        except Exception as exc:
            return False, f"pinchtab_unavailable:{type(exc).__name__}"
        if ok:
            return True, ""
        return False, "pinchtab_daemon_not_running"

    async def full_capture(self, targets: list[str], *, max_targets: int = 20,
                            profile_name: str = "") -> dict[str, Any]:
        """Run full browser intelligence on target URLs."""
        available, reason = await self.is_available()
        if not available:
            return {"used": False, "reason": reason, "entities": []}

        profile_id = ""
        instance_id = ""
        all_entities: list[dict[str, Any]] = []
        captured = 0

        try:
            pname = profile_name or f"alpha-{self.scan_id[:12]}"
            profile = await self.client.create_profile(pname, "Alpha V6 deep recon profile")
            profile_id = str(profile.get("id", profile.get("profileId", "")))
        except Exception:
            logger.debug("[full_capture] error", exc_info=True)

        try:
            instance = await self.client.start_instance(profile_id or None, mode="headless")
            instance_id = str(instance.get("id", instance.get("instanceId", "")))
        except Exception as exc:
            return {"used": False, "reason": f"instance_failed:{exc}",
                    "profile_id": profile_id, "entities": []}

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
            try:
                if instance_id:
                    await self.client.stop_instance(instance_id)
            except Exception:
                logger.debug("[] error", exc_info=True)

        return {
            "used": captured > 0,
            "profile_id": profile_id,
            "instance_id": instance_id,
            "captured_count": captured,
            "entities_count": len(all_entities),
            "entities": all_entities,
            "reason": "" if captured else "no_pages_captured",
        }

    async def _capture_single(self, url: str) -> list[dict[str, Any]]:
        """Capture full browser intelligence for a single URL."""
        entities: list[dict[str, Any]] = []
        prefix = re.sub(r"[^A-Za-z0-9_.-]+", "_", url)[:120]

        nav = await self.client.navigate(url)
        tab_id = str(nav.get("tabId", nav.get("id", nav.get("targetId", ""))))
        if not tab_id:
            return entities

        try:
            try:
                await self.client.wait_for_load(tab_id, timeout_ms=15000)
            except Exception:
                await asyncio.sleep(2)

            # 1. Screenshot
            screenshot_dir = Path("reports/forensics")
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"{prefix}.png"
            try:
                await self.client.screenshot(tab_id, screenshot_path)
                entities.append({
                    "kind": "visual_artifact",
                    "label": url,
                    "confidence": 0.95,
                    "properties": {"screenshot_path": str(screenshot_path)},
                    "source_tool": "pinchtab",
                    "phase": "http_browser_intelligence"
                })
            except Exception:
                logger.debug("[] error", exc_info=True)

            # 2. DOM Snapshot
            try:
                snapshot = await self.client.snapshot(tab_id, max_tokens=3000)
                if isinstance(snapshot, dict):
                    entities.extend(self._extract_from_snapshot(snapshot, url))
            except Exception:
                logger.debug("[] error", exc_info=True)

            # 3. Page Text Content
            try:
                text = await self.client.text(tab_id, max_chars=50000)
                text_str = str(text) if not isinstance(text, str) else text
                entities.extend(self._extract_from_text(text_str, url))
            except Exception:
                logger.debug("[] error", exc_info=True)

            # 4. Network Requests
            try:
                network = await self.client.network(tab_id, limit=500)
                entities.extend(self._extract_from_network(network, url))
            except Exception:
                logger.debug("[] error", exc_info=True)

            # 5. Console output
            try:
                console = await self.client.console(tab_id, limit=200)
                entities.extend(self._extract_from_console(console, url))
            except Exception:
                logger.debug("[] error", exc_info=True)

            # 6. Cookies
            try:
                cookies = await self.client.cookies(tab_id)
                entities.extend(self._extract_from_cookies(cookies, url))
            except Exception:
                logger.debug("[] error", exc_info=True)

            # 7. Scroll
            try:
                await self.client.action(tab_id, "scroll", selector="body")
                await asyncio.sleep(1)
                network2 = await self.client.network(tab_id, limit=500)
                entities.extend(self._extract_from_network(network2, url))
            except Exception:
                logger.debug("[] error", exc_info=True)

        finally:
            try:
                await self.client.close_tab(tab_id)
            except Exception:
                logger.debug("[] error", exc_info=True)

        return entities

    def _extract_from_network(self, network: Any, parent_url: str) -> list[dict[str, Any]]:
        """Extract endpoints from browser network requests."""
        entities: list[dict[str, Any]] = []
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
            if key in self._seen:
                continue
            self._seen.add(key)

            parsed = urlparse(url)
            method = str(row.get("method", row.get("request", {}).get("method", "GET"))).upper()
            status = int(row.get("status", row.get("response", {}).get("status", 0)) or 0)
            mime = str(row.get("mimeType", row.get("response", {}).get("mimeType", "")))
            resource_type = str(row.get("resourceType", row.get("type", "")))

            if resource_type in ("Image", "Stylesheet", "Font", "Media"):
                continue
            if any(url.lower().endswith(ext) for ext in [".png", ".jpg", ".gif", ".css", ".woff", ".ico", ".svg"]):
                continue

            is_api = bool(re.search(r'/api/|/rest/|/v[0-9]+/|/graphql', url, re.I))
            is_xhr = resource_type in ("XHR", "Fetch", "xmlhttprequest", "fetch")

            props = {
                "full_url": url, "method": method, "status_code": status,
                "mime_type": mime, "resource_type": resource_type,
                "path": parsed.path or "/", "host": (parsed.hostname or "").lower(),
                "parameters": [{"name": n, "value": v} for n, v in parse_qsl(parsed.query, keep_blank_values=True)],
                "discovered_from": parent_url,
                "is_api_call": is_api or is_xhr,
            }

            kind = "browser_endpoint"
            conf = 0.9 if (is_api or is_xhr) else 0.75
            entities.append({
                "kind": kind, "label": url, "confidence": conf, "properties": props,
                "source_tool": "pinchtab", "phase": "http_browser_intelligence"
            })

        return entities

    def _extract_from_snapshot(self, snapshot: dict, parent_url: str) -> list[dict[str, Any]]:
        """Extract forms, links, and interactive elements from DOM snapshot."""
        entities: list[dict[str, Any]] = []
        content = str(snapshot)
        forms = re.findall(r'action=["\']([^"\']+)["\']', content, re.I)
        for action in forms:
            if action and not action.startswith("#"):
                key = f"form:{action}"
                if key not in self._seen:
                    self._seen.add(key)
                    entities.append({
                        "kind": "form_action", "label": action, "confidence": 0.8,
                        "properties": {"parent_url": parent_url, "type": "form"},
                        "source_tool": "pinchtab", "phase": "http_browser_intelligence"
                    })
        return entities

    def _extract_from_text(self, text: str, parent_url: str) -> list[dict[str, Any]]:
        """Extract potential secrets or interesting patterns from page text."""
        entities: list[dict[str, Any]] = []
        patterns = {
            "api_key_in_page": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9]{20,})', re.I),
            "bearer_token": re.compile(r'Bearer\s+([A-Za-z0-9._-]{20,})', re.I),
            "jwt_in_page": re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
        }
        for stype, pattern in patterns.items():
            matches = pattern.findall(text[:10000])
            for match in matches[:3]:
                key = f"text_secret:{stype}:{str(match)[:20]}"
                if key not in self._seen:
                    self._seen.add(key)
                    entities.append({
                        "kind": "secret", "label": f"page_secret:{stype}", "confidence": 0.7,
                        "properties": {"secret_type": stype, "redacted_value": str(match)[:4] + "****", "source_url": parent_url},
                        "source_tool": "pinchtab", "phase": "http_browser_intelligence"
                    })
        return entities

    def _extract_from_console(self, console: Any, parent_url: str) -> list[dict[str, Any]]:
        """Extract interesting findings from browser console output."""
        entities: list[dict[str, Any]] = []
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
                if key not in self._seen:
                    self._seen.add(key)
                    entities.append({
                        "kind": "browser_error", "label": f"console_error:{parent_url}", "confidence": 0.6,
                        "properties": {"message": text[:500], "level": level, "source_url": parent_url},
                        "source_tool": "pinchtab", "phase": "http_browser_intelligence"
                    })
        return entities

    def _extract_from_cookies(self, cookies: Any, parent_url: str) -> list[dict[str, Any]]:
        """Extract security-relevant cookie information."""
        entities: list[dict[str, Any]] = []
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

            is_session = any(kw in name.lower() for kw in ["session", "token", "auth", "jwt", "csrf"])
            if is_session:
                issues = []
                if not secure: issues.append("missing_secure_flag")
                if not httponly: issues.append("missing_httponly_flag")
                if not samesite or samesite.lower() == "none":
                    issues.append("weak_samesite")

                if issues:
                    key = f"cookie:{name}:{domain}"
                    if key not in self._seen:
                        self._seen.add(key)
                        entities.append({
                            "kind": "vulnerability_candidate", "label": f"insecure_cookie:{name}", "confidence": 0.7,
                            "properties": {"cookie_name": name, "domain": domain, "issues": issues, "secure": secure,
                                           "httponly": httponly, "samesite": samesite, "source_url": parent_url,
                                           "vuln_type": "insecure_cookie"},
                            "source_tool": "pinchtab", "phase": "http_browser_intelligence"
                        })
        return entities

PinchTabIntelligence = ScraplingIntel


class ScraplingRecon:
    """Browser-aware recon, normalized into dict-based ParsedEntity records."""

    def __init__(self, browser, scan_id: str, *, agent_name: str = "agent_alpha"):
        self.browser = browser
        self.scan_id = scan_id
        self.agent_name = agent_name

    async def recon(self, url: str) -> list[dict[str, Any]]:
        """Run browser recon for ``url``; return normalized entities."""
        entities: list[dict[str, Any]] = []
        if self.browser is None:
            return entities

        is_spa = False
        nav_ok = False
        try:
            result = await self.browser.navigate(url, stealth=False, wait_for="networkidle")
            nav_ok = bool(result.get("success"))
        except Exception as exc:
            logger.info("[BrowserRecon] navigate(%s) failed: %s: %s",
                         url, type(exc).__name__, str(exc)[:200])

        if nav_ok:
            try:
                framework = await self.browser.detect_framework(url)
                is_spa = str(framework or "").lower() in _SPA_FRAMEWORKS
            except Exception:
                is_spa = False

        endpoints = await self._extract_endpoints(url)
        network = await self._intercept_network(url)
        js_routes = await self._extract_js_routes(url)
        websockets = await self._find_websockets(url)

        merged = self._merge(endpoints, network, js_routes, websockets)
        for ep in merged:
            kind = "browser_endpoint"
            src = ep.get("source", "browser")
            if ep.get("method") == "WS" or src == "websocket_monitor":
                kind = "websocket"
            elif "router" in src:
                kind = "javascript_route"
            entities.append({
                "kind": kind,
                "label": str(ep.get("url", "")),
                "confidence": 0.7,
                "source_tool": src,
                "phase": "http_browser_intelligence",
                "properties": {"method": ep.get("method", "GET"), "source": src,
                            "spa": is_spa, "headers": ep.get("headers", {}),
                            "scan_id": self.scan_id},
            })

        if nav_ok:
            entities.extend(await self._extract_forms(url))
            entities.extend(await self._extract_cookies(url))
            entities.extend(await self._extract_security_headers(url))

        logger.info("[BrowserRecon] %s: %d browser entities (spa=%s, nav_ok=%s)",
                     url, len(entities), is_spa, nav_ok)
        return entities

    # ── Browser primitives (delegated to the shared orchestrator) ─────────────

    async def _extract_endpoints(self, url: str) -> list[dict[str, Any]]:
        try:
            eps = await self.browser.extract_endpoints(url, deep=True)
            return [{"url": e.get("url"), "method": e.get("method", "GET"),
                     "source": e.get("source", "browser")} for e in (eps or [])
                    if isinstance(e, dict) and e.get("url")]
        except Exception as exc:
            logger.debug("[BrowserRecon] _extract_endpoints failed: %s", exc)
            return []

    async def _intercept_network(self, url: str) -> list[dict[str, Any]]:
        try:
            evts = await self.browser.intercept_network(url)
            out: list[dict[str, Any]] = []
            for e in (evts or []):
                if not isinstance(e, dict):
                    continue
                u = e.get("url")
                if not u:
                    continue
                out.append({
                    "url": u,
                    "method": e.get("method", "GET"),
                    "source": "network_intercept",
                    "headers": e.get("headers", {}),
                })
            return out
        except Exception as exc:
            logger.debug("[BrowserRecon] _intercept_network failed: %s", exc)
            return []

    async def _find_websockets(self, url: str) -> list[dict[str, Any]]:
        try:
            ws_urls = await self.browser.find_websockets(url)
            return [{"url": w, "method": "WS", "source": "websocket_monitor"}
                    for w in (ws_urls or []) if w]
        except Exception:
            return []

    async def _extract_js_routes(self, url: str) -> list[dict[str, Any]]:
        try:
            framework = await self.browser.detect_framework(url)
            page = getattr(getattr(self.browser, "openclaw", None), "current_page", None)
            if page is None:
                return []
            fw = str(framework or "").lower()
            if fw == "react":
                js = """() => { const r=[]; if(window.__REACT_ROUTER__&&window.__REACT_ROUTER__.routes){window.__REACT_ROUTER__.routes.forEach(x=>{if(x.path)r.push({url:x.path,method:'GET',source:'react_router'})})} document.querySelectorAll('[data-route]').forEach(e=>{const p=e.getAttribute('data-route'); if(p)r.push({url:p,method:'GET',source:'react_dom'})}); return r; }"""
            elif fw == "vue":
                js = """() => { const r=[]; if(window.$router&&window.$router.options){(window.$router.options.routes||[]).forEach(x=>{if(x.path)r.push({url:x.path,method:'GET',source:'vue_router'})})} return r; }"""
            elif fw == "angular":
                js = """() => { const r=[]; if(window.ng&&window.ng.probe){(window.ng.probe.getAllRoutes?.()||[]).forEach(x=>{if(x.path)r.push({url:x.path,method:'GET',source:'angular_router'})})} return r; }"""
            else:
                return []
            routes = await page.evaluate(js)
            return [r for r in (routes or []) if isinstance(r, dict) and r.get("url")]
        except Exception:
            return []

    async def _extract_forms(self, url: str) -> list[dict[str, Any]]:
        """Pull <form> action/method/inputs from the current page."""
        page = getattr(getattr(self.browser, "openclaw", None), "current_page", None)
        if page is None:
            return []
        try:
            forms = await page.eval_on_selector_all(
                "form",
                """elements => elements.map(f => ({
                    action: f.getAttribute('action') || '',
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                        .map(i => ({
                            name: i.getAttribute('name') || '',
                            type: i.getAttribute('type') || i.tagName.toLowerCase(),
                            id: i.id || ''
                        }))
                }))""",
            )
        except Exception as exc:
            logger.debug("[BrowserRecon] form extraction failed: %s", exc)
            return []

        entities: list[dict[str, Any]] = []
        for form in forms or []:
            if not isinstance(form, dict):
                continue
            action = form.get("action", "") or url
            entities.append({
                "kind": "form",
                "label": action or url,
                "confidence": 0.85,
                "source_tool": "openclaw",
                "phase": "http_browser_intelligence",
                "properties": {
                    "action": action,
                    "method": form.get("method", "GET"),
                    "inputs": form.get("inputs", []),
                    "source_url": url,
                    "scan_id": self.scan_id,
                },
            })
        return entities

    async def _extract_cookies(self, url: str) -> list[dict[str, Any]]:
        """Pull cookies set on the current browser context."""
        ctx = getattr(getattr(self.browser, "openclaw", None), "current_context", None)
        if ctx is None:
            return []
        try:
            cookies = await ctx.cookies()
        except Exception as exc:
            logger.debug("[BrowserRecon] cookie extraction failed: %s", exc)
            return []

        entities: list[dict[str, Any]] = []
        for c in cookies or []:
            if not isinstance(c, dict):
                continue
            name = c.get("name", "")
            httponly = bool(c.get("httpOnly", False))
            secure = bool(c.get("secure", False))
            samesite = str(c.get("sameSite", ""))
            kind = "cookie"
            confidence = 0.7
            if not httponly or not secure:
                kind = "insecure_cookie"
                confidence = 0.8
            entities.append({
                "kind": kind,
                "label": f"{name}@{c.get('domain', '')}",
                "confidence": confidence,
                "source_tool": "openclaw_cookies",
                "phase": "http_browser_intelligence",
                "properties": {
                    "name": name,
                    "domain": c.get("domain", ""),
                    "path": c.get("path", "/"),
                    "httpOnly": httponly,
                    "secure": secure,
                    "sameSite": samesite,
                    "source_url": url,
                    "scan_id": self.scan_id,
                },
            })
        return entities

    async def _extract_security_headers(self, url: str) -> list[dict[str, Any]]:
        """Inspect response headers captured during navigation."""
        page = getattr(getattr(self.browser, "openclaw", None), "current_page", None)
        if page is None:
            return []
        try:
            headers = await page.evaluate(
                """async (u) => {
                    try {
                        const r = await fetch(u, { method: 'HEAD', credentials: 'include' });
                        const out = {};
                        r.headers.forEach((v, k) => { out[k.toLowerCase()] = v; });
                        return out;
                    } catch (e) {
                        return {};
                    }
                }""",
                url,
            )
        except Exception as exc:
            logger.debug("[BrowserRecon] security header probe failed: %s", exc)
            return []

        if not isinstance(headers, dict) or not headers:
            return []

        entities: list[dict[str, Any]] = []
        present = {h: headers[h] for h in _SECURITY_HEADERS if h in headers}
        missing = [h for h in _SECURITY_HEADERS if h not in headers]

        if present or missing:
            entities.append({
                "kind": "security_headers",
                "label": url,
                "confidence": 0.8,
                "source_tool": "openclaw",
                "phase": "http_browser_intelligence",
                "properties": {
                    "url": url,
                    "present": present,
                    "missing": missing,
                    "all_headers": headers,
                    "scan_id": self.scan_id,
                },
            })
        return entities

    @staticmethod
    def _merge(*lists) -> list[dict[str, Any]]:
        seen: set[str] = set()
        merged: list[dict[str, Any]] = []
        for lst in lists:
            for ep in lst:
                u = ep.get("url", "")
                if u and u not in seen:
                    seen.add(u)
                    merged.append(ep)
        return merged

BrowserReconModule = ScraplingRecon



# --- Scrapling CrawlSpider Integration ---


class PentestCrawlSpider:
    """CrawlSpider specialized for pentest crawling with rule-based link following."""

    def __init__(self, start_urls=None, allowed_domains=None,
                 concurrent_requests=5, download_delay=1.0):
        self.start_urls_list = start_urls or []
        self.allowed_domains = allowed_domains or []
        self.concurrent_requests = concurrent_requests
        self.download_delay = download_delay
        self._entities = []
        self._spider = None
        if _SCRAPLING_SPIDERS_AVAILABLE and ScraplingCrawlSpider is not None:
            try:
                self._spider = ScraplingCrawlSpider()
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    async def start(self):
        """Start the pentest crawl."""
        if self._spider:
            try:
                self._spider.start()
            except Exception as exc:
                logger.debug('[PentestCrawlSpider] start failed: %s', exc)

    def on_start(self):
        """Called when crawl starts."""
        for url in self.start_urls_list:
            yield ScraplingRequest(url) if ScraplingRequest else None

    def parse(self, response):
        """Parse response and extract pentest entities."""
        pass

    def get_entities(self):
        """Return collected pentest entities."""
        return self._entities


# --- Scrapling SitemapSpider Integration ---


class PentestSitemapSpider:
    """SitemapSpider for discovering endpoints from sitemap.xml files."""

    def __init__(self, start_urls=None, sitemap_urls=None):
        self.start_urls_list = start_urls or []
        self.sitemap_urls = sitemap_urls or []
        self._discovered_urls = []
        self._spider = None
        if _SCRAPLING_SPIDERS_AVAILABLE and ScraplingSitemapSpider is not None:
            try:
                self._spider = ScraplingSitemapSpider()
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    async def start(self):
        """Start sitemap crawl."""
        if self._spider:
            try:
                self._spider.start()
            except Exception as exc:
                logger.debug('[PentestSitemapSpider] start failed: %s', exc)

    def get_discovered_urls(self):
        """Return discovered URLs from sitemaps."""
        return self._discovered_urls


# --- Scrapling Scheduler Integration ---


class PentestScheduler:
    """Request scheduler using Scrapling Scheduler for crawl rate control."""

    def __init__(self, include_kwargs=False, include_headers=False, keep_fragments=False):
        self._scheduler = None
        if _SCRAPLING_SPIDERS_AVAILABLE and ScraplingScheduler is not None:
            try:
                self._scheduler = ScraplingScheduler(
                    include_kwargs=include_kwargs,
                    include_headers=include_headers,
                    keep_fragments=keep_fragments,
                )
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    def enqueue(self, request):
        """Add a request to the queue."""
        if self._scheduler:
            self._scheduler.enqueue(request)

    def dequeue(self):
        """Remove and return the next request from the queue."""
        if self._scheduler:
            return self._scheduler.dequeue()
        return None

    def snapshot(self):
        """Return a snapshot of the current queue."""
        if self._scheduler:
            return self._scheduler.snapshot()
        return []


# --- Scrapling Session Classes Integration ---


class PentestDynamicSession:
    """Dynamic browser session for JS-heavy pentest targets."""

    def __init__(self, max_pages=5, headless=True, **kwargs):
        self._session = None
        if _SCRAPLING_AVAILABLE and DynamicSession is not None:
            try:
                self._session = DynamicSession(max_pages=max_pages, headless=headless, **kwargs)
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    async def start(self):
        if self._session:
            try:
                await self._session.start()
            except Exception as exc:
                logger.debug('[PentestDynamicSession] start failed: %s', exc)

    async def fetch(self, url, **kwargs):
        if self._session:
            return await self._session.fetch(url, **kwargs)
        return None

    async def close(self):
        if self._session:
            try:
                await self._session.close()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self._session = None


class PentestStealthySession:
    """Stealthy browser session for anti-bot protected targets."""

    def __init__(self, max_pages=5, headless=True, **kwargs):
        self._session = None
        if _SCRAPLING_AVAILABLE and StealthySession is not None:
            try:
                self._session = StealthySession(max_pages=max_pages, headless=headless, **kwargs)
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    async def start(self):
        if self._session:
            try:
                await self._session.start()
            except Exception as exc:
                logger.debug('[PentestStealthySession] start failed: %s', exc)

    async def fetch(self, url, **kwargs):
        if self._session:
            return await self._session.fetch(url, **kwargs)
        return None

    async def close(self):
        if self._session:
            try:
                await self._session.close()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self._session = None


class PentestAsyncDynamicSession:
    """Async dynamic session for concurrent JS-heavy pentest operations."""

    def __init__(self, max_pages=5, headless=True, **kwargs):
        self._session = None
        if _SCRAPLING_AVAILABLE and AsyncDynamicSession is not None:
            try:
                self._session = AsyncDynamicSession(max_pages=max_pages, headless=headless, **kwargs)
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    async def start(self):
        if self._session:
            try:
                await self._session.start()
            except Exception as exc:
                logger.debug('[PentestAsyncDynamicSession] start failed: %s', exc)

    async def fetch(self, url, **kwargs):
        if self._session:
            return await self._session.fetch(url, **kwargs)
        return None

    async def close(self):
        if self._session:
            try:
                await self._session.close()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self._session = None


class PentestAsyncStealthySession:
    """Async stealthy session for concurrent anti-bot pentest operations."""

    def __init__(self, max_pages=5, headless=True, **kwargs):
        self._session = None
        if _SCRAPLING_AVAILABLE and AsyncStealthySession is not None:
            try:
                self._session = AsyncStealthySession(max_pages=max_pages, headless=headless, **kwargs)
            except Exception:
                logger.debug("[__init__] error", exc_info=True)

    async def start(self):
        if self._session:
            try:
                await self._session.start()
            except Exception as exc:
                logger.debug('[PentestAsyncStealthySession] start failed: %s', exc)

    async def fetch(self, url, **kwargs):
        if self._session:
            return await self._session.fetch(url, **kwargs)
        return None

    async def close(self):
        if self._session:
            try:
                await self._session.close()
            except Exception:
                logger.debug("[close] error", exc_info=True)
            self._session = None


# --- Scrapling Adaptor / Adaptors Integration ---


class PentestAdaptor:
    """Adaptor wrapper for pentest-specific HTML parsing."""

    @staticmethod
    def parse(html, encoding=None):
        """Parse HTML using Scrapling Adaptor for robust extraction."""
        if _SCRAPLING_AVAILABLE and Adaptor is not None:
            try:
                return Adaptor(html, encoding=encoding)
            except Exception:
                logger.debug("[parse] error", exc_info=True)
        return None

    @staticmethod
    def parse_all(html_list, encoding=None):
        """Parse multiple HTML documents using Scrapling Adaptors."""
        if _SCRAPLING_AVAILABLE and Adaptors is not None:
            try:
                return [Adaptor(html, encoding=encoding) for html in html_list if html]
            except Exception:
                logger.debug("[parse_all] error", exc_info=True)
        return []


# --- Scrapling SequenceMatcher Integration ---


class PentestSequenceMatcher:
    """Content similarity matching using Scrapling SequenceMatcher."""

    @staticmethod
    def match(seq1, seq2):
        """Compare two sequences and return similarity metrics."""
        if _SCRAPLING_AVAILABLE and SequenceMatcher is not None:
            try:
                matcher = SequenceMatcher(None, seq1, seq2)
                return {
                    'ratio': matcher.ratio(),
                    'opcodes': matcher.get_opcodes() if hasattr(matcher, 'get_opcodes') else [],
                    'matching_blocks': matcher.get_matching_blocks() if hasattr(matcher, 'get_matching_blocks') else [],
                }
            except Exception:
                logger.debug("[match] error", exc_info=True)
        return {'ratio': 0.0, 'opcodes': [], 'matching_blocks': []}

    @staticmethod
    def find_longest_match(alo, ahi, blo, bhi, seq1, seq2):
        """Find the longest matching block between two sequences."""
        if _SCRAPLING_AVAILABLE and SequenceMatcher is not None:
            try:
                matcher = SequenceMatcher(None, seq1, seq2)
                return matcher.find_longest_match(alo, ahi, blo, bhi)
            except Exception:
                logger.debug("[find_longest_match] error", exc_info=True)
        return None



class Scrappling:
    """
    Unified browser interface that routes between OpenClaw and PinchTab.
    Provides a single API for all agents to use browser capabilities.
    Includes context isolation for security between scans.
    """
    
    def __init__(self):
        self.openclaw = None
        self.pinchtab = None
        self.session_manager = None
        self.forensics = None
        self._initialized = False
        
        # Context isolation tracking
        self._active_contexts: Dict[str, Dict[str, Any]] = {}
        self._context_lock = asyncio.Lock()
        self._max_contexts = 10
        
        # Resource management
        self._context_pool: List[str] = []
        self._pool_lock = asyncio.Lock()
        self._max_pool_size = 5
        
        # Memory monitoring
        self._memory_threshold_mb = 500
        self._last_memory_check = 0
        self._memory_check_interval = 60
        
        # Lazy initialization flags
        self._openclaw_initialized = False
        self._pinchtab_initialized = False

        self._openclaw_last_reason: str = ""
        self._openclaw_last_hint: str = ""
        self._pinchtab_last_reason: str = ""
        self._pinchtab_last_hint: str = ""
        self._proxy_rotator: Any = None
        

    # --- New Scrapling Feature Methods ---

    async def start_dynamic_session(self, max_pages=5, headless=True):
        """Start a DynamicSession for JS-heavy page crawling."""
        session = PentestDynamicSession(max_pages=max_pages, headless=headless)
        await session.start()
        return session

    async def start_stealthy_session(self, max_pages=5, headless=True):
        """Start a StealthySession for anti-bot protected pages."""
        session = PentestStealthySession(max_pages=max_pages, headless=headless)
        await session.start()
        return session

    async def start_async_dynamic_session(self, max_pages=5, headless=True):
        """Start an AsyncDynamicSession for concurrent JS page crawling."""
        session = PentestAsyncDynamicSession(max_pages=max_pages, headless=headless)
        await session.start()
        return session

    async def start_async_stealthy_session(self, max_pages=5, headless=True):
        """Start an AsyncStealthySession for concurrent anti-bot crawling."""
        session = PentestAsyncStealthySession(max_pages=max_pages, headless=headless)
        await session.start()
        return session

    def create_crawl_spider(self, start_urls=None, allowed_domains=None, **kwargs):
        """Create a CrawlSpider for rule-based pentest crawling."""
        return PentestCrawlSpider(
            start_urls=start_urls, allowed_domains=allowed_domains, **kwargs)

    def create_sitemap_spider(self, start_urls=None, sitemap_urls=None, **kwargs):
        """Create a SitemapSpider for sitemap-based endpoint discovery."""
        return PentestSitemapSpider(
            start_urls=start_urls, sitemap_urls=sitemap_urls)

    def create_scheduler(self, **kwargs):
        """Create a Scheduler for crawl rate control."""
        return PentestScheduler(**kwargs)

    def parse_with_adaptor(self, html, encoding=None):
        """Parse HTML using Scrapling Adaptor."""
        return PentestAdaptor.parse(html, encoding=encoding)

    def parse_all_with_adaptor(self, html_list, encoding=None):
        """Parse multiple HTML documents using Scrapling Adaptors."""
        return PentestAdaptor.parse_all(html_list, encoding=encoding)

    def match_content(self, seq1, seq2):
        """Compare content similarity using SequenceMatcher."""
        return PentestSequenceMatcher.match(seq1, seq2)

    def find_longest_match(self, alo, ahi, blo, bhi, seq1, seq2):
        """Find longest matching block between two sequences."""
        return PentestSequenceMatcher.find_longest_match(alo, ahi, blo, bhi, seq1, seq2)

    async def initialize(self, lazy: bool = False):
        """Initialize both browser engines."""
        if self._initialized:
            return
            
        logger.info("[Scrappling] Initializing hybrid browser stack...")
        
        if lazy:
            logger.info("[Scrappling] Lazy initialization mode enabled")
        else:
            await self._lazy_init_openclaw()
            await self._lazy_init_pinchtab()
        
        from backend.core.hybrid_session_manager import HybridSessionManager
        self.session_manager = HybridSessionManager()
        
        from backend.core.forensic_collector import ForensicCollector
        self.forensics = ForensicCollector()
        
        await self._init_scrapling_proxy_rotator()

        self._initialized = True
        logger.info("[Scrappling] Hybrid browser stack ready")
    
    async def create_isolated_context(self, scan_id: str, context_name: Optional[str] = None) -> str:
        """Create an isolated browser context for a scan."""
        async with self._context_lock:
            if len(self._active_contexts) >= self._max_contexts:
                logger.warning(f"[Scrappling] Context limit reached ({self._max_contexts}), cleaning up old contexts")
                await self._cleanup_idle_contexts()
            
            context_id = context_name or f"{scan_id}_{uuid.uuid4().hex[:8]}"
            
            context_data = {
                "scan_id": scan_id,
                "context_id": context_id,
                "created_at": asyncio.get_event_loop().time(),
                "last_activity": asyncio.get_event_loop().time(),
                "engine": None,
                "context_handle": None
            }
            
            self._active_contexts[context_id] = context_data
            logger.info(f"[Scrappling] Created isolated context: {context_id} for scan: {scan_id}")
            return context_id
    
    async def get_context(self, context_id: str) -> Optional[Dict[str, Any]]:
        """Get context data by ID."""
        async with self._context_lock:
            context = self._active_contexts.get(context_id)
            if context:
                context["last_activity"] = asyncio.get_event_loop().time()
            return context
    
    async def close_context(self, context_id: str):
        """Close and cleanup an isolated context."""
        async with self._context_lock:
            context = self._active_contexts.get(context_id)
            if not context:
                return
            
            if context.get("context_handle"):
                try:
                    pass
                except Exception as e:
                    logger.error(f"[Scrappling] Failed to close context {context_id}: {e}")
            
            del self._active_contexts[context_id]
            logger.info(f"[Scrappling] Closed isolated context: {context_id}")
    
    async def _cleanup_idle_contexts(self, max_idle_seconds: int = 300):
        """Cleanup contexts that have been idle for too long."""
        current_time = asyncio.get_event_loop().time()
        idle_contexts = []
        
        for context_id, context in self._active_contexts.items():
            idle_time = current_time - context["last_activity"]
            if idle_time > max_idle_seconds:
                idle_contexts.append(context_id)
        
        for context_id in idle_contexts:
            await self.close_context(context_id)
        
        logger.info(f"[Scrappling] Cleaned up {len(idle_contexts)} idle contexts")
    
    def get_active_context_count(self) -> int:
        return len(self._active_contexts)
    
    def get_context_stats(self) -> Dict[str, Any]:
        current_time = asyncio.get_event_loop().time()
        stats = {
            "total_contexts": len(self._active_contexts),
            "max_contexts": self._max_contexts,
            "contexts_by_scan": {},
            "idle_contexts": 0
        }
        for context_id, context in self._active_contexts.items():
            scan_id = context["scan_id"]
            stats["contexts_by_scan"][scan_id] = stats["contexts_by_scan"].get(scan_id, 0) + 1
            idle_time = current_time - context["last_activity"]
            if idle_time > 60:
                stats["idle_contexts"] += 1
        return stats
        
    async def navigate(self, url: str, engine: ScrapplingEngine = ScrapplingEngine.AUTO,
                      stealth: bool = False, wait_for: str = "networkidle",
                      scan_id: Optional[str] = None, context_id: Optional[str] = None):
        """Navigate to URL using best engine for the task with context isolation."""
        await self._ensure_initialized()
        if scan_id and not context_id:
            context_id = await self.create_isolated_context(scan_id)

        await self._lazy_init_openclaw()
        await self._lazy_init_pinchtab()

        selected_engine = self._select_engine(engine, stealth, url)
        logger.info(
            "[Scrappling] Navigating to %s via %s (context: %s)",
            url, selected_engine.value, context_id,
        )

        if selected_engine == ScrapplingEngine.PINCHTAB:
            candidates = [ScrapplingEngine.PINCHTAB, ScrapplingEngine.PLAYWRIGHT]
        else:
            candidates = [ScrapplingEngine.PLAYWRIGHT, ScrapplingEngine.PINCHTAB]

        last_error: Optional[str] = None
        for candidate in candidates:
            try:
                if candidate == ScrapplingEngine.PINCHTAB:
                    if self.pinchtab is None or not getattr(self.pinchtab, "is_available", lambda: False)():
                        continue
                    result = await self.pinchtab.navigate(url)
                    if result.get("success"):
                        return result
                    last_error = result.get("error") or "PinchTab navigation failed"
                else:  # PLAYWRIGHT
                    if self.openclaw is None:
                        continue
                    return await self.openclaw.navigate(url, stealth=stealth, wait_for=wait_for)
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "[Scrappling] %s navigation failed: %s",
                    candidate.value, last_error,
                )

        raise ScrapplingUnavailable(
            f"No browser engine could navigate to {url}: "
            f"{last_error or 'OpenClaw and PinchTab both offline'}"
        )
                
    async def extract_endpoints(self, url: str, deep: bool = False, scan_id: Optional[str] = None):
        """Extract API endpoints from page."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        await self._lazy_init_pinchtab()

        if deep and self.openclaw:
            try:
                logger.info("[Scrappling] Deep endpoint extraction on %s", url)
                eps = await self.openclaw.extract_endpoints_deep(url)
                if eps and isinstance(eps[0], str):
                    eps = [{"url": u, "method": "GET", "source": "openclaw"} for u in eps]
                return eps or []
            except Exception as exc:
                logger.warning(
                    "[Scrappling] Deep extraction failed, trying fast mode: %s", exc,
                )

        if self.pinchtab and self.pinchtab.is_available():
            logger.info("[Scrappling] Fast endpoint extraction on %s", url)
            urls = await self.pinchtab.extract_endpoints_fast(url)
            return [{"url": u, "method": "GET", "source": "pinchtab"} for u in (urls or [])]

        return []
            
    async def execute_workflow(self, workflow: Dict, scan_id: str):
        """Execute multi-step workflow (OpenClaw only)."""
        await self._ensure_initialized()
        if not self.openclaw:
            raise RuntimeError("ScrapplingPlaywrightEngine required for workflow execution")
        logger.info(f"[Scrappling] Executing workflow: {workflow.get('name', 'unnamed')}")
        return await self.openclaw.execute_workflow(workflow, scan_id)
        
    async def extract_tokens(self, url: str, scan_id: Optional[str] = None):
        """Extract auth tokens."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        await self._lazy_init_pinchtab()

        if self._pinchtab_ready():
            logger.info(f"[Scrappling] Extracting tokens from {url}")
            return await self.pinchtab.extract_tokens(url)
        elif self.openclaw:
            return await self.openclaw.extract_tokens(url)
        else:
            return []
            
    async def test_payload(self, url: str, payload: str, method: str = "GET",
                          scan_id: Optional[str] = None):
        """Test payload in browser context."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        await self._lazy_init_pinchtab()

        if any(x in payload.lower() for x in ["<script", "onerror", "onclick", "onload", "alert"]):
            if self.openclaw:
                logger.info("[Scrappling] Testing XSS payload in OpenClaw")
                return await self.openclaw.test_xss_payload(url, payload)
                
        if self._pinchtab_ready():
            logger.info("[Scrappling] Testing injection in PinchTab")
            return await self.pinchtab.test_injection(url, payload, method)
        elif self.openclaw:
            return await self.openclaw.test_xss_payload(url, payload)
        else:
            return {"tested": False, "error": "No engines available"}
            
    async def detect_framework(self, url: str):
        """Detect JavaScript framework."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        if self.openclaw:
            try:
                return await self.openclaw.detect_framework(url)
            except Exception as exc:
                logger.warning("[Scrappling] Framework detection failed: %s", exc)
        return None
        
    async def intercept_network(self, url: str):
        """Intercept network requests."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        if self.openclaw:
            return await self.openclaw.intercept_network(url)
        return []
        
    async def find_websockets(self, url: str):
        """Find WebSocket connections."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        if self.openclaw:
            return await self.openclaw.find_websockets(url)
        return []
        
    async def capture_screenshot(self, scan_id: str, label: str = "screenshot"):
        """Capture screenshot."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        if self.openclaw:
            return await self.openclaw.capture_screenshot(scan_id, label)
        return None
        
    async def capture_dom(self, scan_id: str, label: str = "dom"):
        """Capture DOM snapshot."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        if self.openclaw:
            return await self.openclaw.capture_dom(scan_id, label)
        return None
        
    async def get_network_log(self):
        """Get network request log."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        if self.openclaw:
            return await self.openclaw.get_network_log()
        return []
        
    async def analyze_dom(self, url: str):
        """Analyze DOM structure."""
        await self._ensure_initialized()
        await self._lazy_init_pinchtab()
        if self._pinchtab_ready():
            return await self.pinchtab.analyze_dom(url)
        return {}
        
    async def get_page_text(self):
        """Get page text content."""
        await self._ensure_initialized()
        await self._lazy_init_openclaw()
        await self._lazy_init_pinchtab()
        if self._pinchtab_ready():
            return await self.pinchtab.get_page_text()
        elif self.openclaw:
            return await self.openclaw.get_page_text()
        return ""
        
    def _pinchtab_ready(self) -> bool:
        if self.pinchtab is None:
            return False
        try:
            return bool(self.pinchtab.is_available())
        except Exception:
            return False

    def _select_engine(self, requested: ScrapplingEngine, stealth: bool, url: str) -> ScrapplingEngine:
        pinch_ready = self._pinchtab_ready()
        if requested != ScrapplingEngine.AUTO:
            if requested in (ScrapplingEngine.PLAYWRIGHT, ScrapplingEngine.PLAYWRIGHT.value) and self.openclaw:
                return ScrapplingEngine.PLAYWRIGHT
            elif requested in (ScrapplingEngine.PINCHTAB, ScrapplingEngine.PINCHTAB.value) and pinch_ready:
                return ScrapplingEngine.PINCHTAB
                
        if stealth:
            return ScrapplingEngine.PLAYWRIGHT if self.openclaw else ScrapplingEngine.PINCHTAB
            
        if any(keyword in url.lower() for keyword in ["login", "auth", "signin", "oauth"]):
            return ScrapplingEngine.PLAYWRIGHT if self.openclaw else ScrapplingEngine.PINCHTAB
            
        prefer_speed = getattr(settings, "BROWSER_PREFER_SPEED", False)
        if prefer_speed and pinch_ready:
            return ScrapplingEngine.PINCHTAB
            
        if self.openclaw:
            return ScrapplingEngine.PLAYWRIGHT
        elif pinch_ready:
            return ScrapplingEngine.PINCHTAB
        else:
            return ScrapplingEngine.PLAYWRIGHT
            
    async def _ensure_initialized(self):
        if not self._initialized:
            await self.initialize()
            
    async def get_pooled_context(self, scan_id: str) -> str:
        """Get context from pool."""
        async with self._pool_lock:
            if self._context_pool:
                context_id = self._context_pool.pop(0)
                logger.info(f"[Scrappling] Reusing pooled context: {context_id}")
                async with self._context_lock:
                    if context_id in self._active_contexts:
                        self._active_contexts[context_id]["scan_id"] = scan_id
                        self._active_contexts[context_id]["last_activity"] = asyncio.get_event_loop().time()
                return context_id
        return await self.create_isolated_context(scan_id)
    
    async def return_context_to_pool(self, context_id: str):
        """Return context to pool."""
        async with self._pool_lock:
            if len(self._context_pool) < self._max_pool_size:
                self._context_pool.append(context_id)
                logger.info(f"[Scrappling] Context {context_id} returned to pool")
                return True
        await self.close_context(context_id)
        return False
    
    async def monitor_memory(self) -> Dict[str, Any]:
        """Monitor memory usage."""
        import time
        current_time = time.time()
        if current_time - self._last_memory_check < self._memory_check_interval:
            return {"skipped": True, "reason": "rate_limited"}
        
        self._last_memory_check = current_time
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            stats = {
                "memory_mb": round(memory_mb, 2),
                "threshold_mb": self._memory_threshold_mb,
                "threshold_exceeded": memory_mb > self._memory_threshold_mb,
                "active_contexts": len(self._active_contexts),
                "pooled_contexts": len(self._context_pool)
            }
            if stats["threshold_exceeded"]:
                logger.warning(
                    f"[Scrappling] Memory threshold exceeded: {memory_mb:.1f}MB > {self._memory_threshold_mb}MB"
                )
                await self._cleanup_idle_contexts(max_idle_seconds=180)
                async with self._pool_lock:
                    pool_size = len(self._context_pool)
                    self._context_pool.clear()
                    logger.info(f"[Scrappling] Cleared {pool_size} pooled contexts")
                stats["cleanup_triggered"] = True
            return stats
        except Exception as e:
            logger.error(f"[Scrappling] Memory monitoring failed: {e}")
            return {"error": str(e)}
    
    async def _lazy_init_openclaw(self):
        if self._openclaw_initialized or self.openclaw:
            return
        if not getattr(settings, "OPENCLAW_ENABLED", True):
            self._openclaw_initialized = True
            return
        try:
            engine = ScrapplingPlaywrightEngine()
            ok = await engine.initialize()
            if not ok and "playwright_browsers_not_installed" in (getattr(engine, "last_init_error", "") or ""):
                if self._auto_install_browsers_enabled():
                    logger.info("[Scrappling] Chromium binary missing, auto-installing...")
                    if await self._install_playwright_chromium():
                        ok = await engine.initialize()
                else:
                    logger.warning("[Scrappling] Chromium binary missing. Set ALPHA_AUTO_INSTALL_BROWSERS=true or install manually.")

            self._openclaw_initialized = True
            if ok:
                self.openclaw = engine
                logger.info("[Scrappling] Playwright engine ready")
            else:
                self.openclaw = None
                reason = getattr(engine, "last_init_error", "") or "unknown"
                hint = self._remediation_hint_openclaw(reason)
                logger.warning("[Scrappling] Playwright engine offline: %s | hint: %s", reason, hint)
                self._openclaw_last_reason = reason
                self._openclaw_last_hint = hint
        except Exception as exc:
            self.openclaw = None
            self._openclaw_initialized = True
            self._openclaw_last_reason = f"{type(exc).__name__}: {exc}"
            self._openclaw_last_hint = "Re-run with ALPHA_DEBUG=1 to see the full traceback"
            logger.warning("[Scrappling] Playwright lazy-init crashed (%s: %s)", type(exc).__name__, exc, exc_info=True)

    @staticmethod
    def _auto_install_browsers_enabled() -> bool:
        return os.getenv("ALPHA_AUTO_INSTALL_BROWSERS", "").lower() == "true"

    @staticmethod
    async def _install_playwright_chromium() -> bool:
        import sys
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "playwright", "install", "chromium",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                logger.info("[Scrappling] playwright install chromium succeeded")
                return True
            logger.warning("[Scrappling] playwright install chromium failed: %s", (stderr or stdout).decode()[:300])
            return False
        except Exception as exc:
            logger.warning("[Scrappling] playwright install chromium failed (%s: %s)", type(exc).__name__, exc)
            return False

    @staticmethod
    def _remediation_hint_openclaw(reason: str) -> str:
        r = (reason or "").lower()
        if "playwright_not_installed" in r or "playwright_import_failed" in r:
            return "pip install playwright"
        if "playwright_browsers_not_installed" in r or "executable doesn't exist" in r:
            return "python -m playwright install chromium (or set ALPHA_AUTO_INSTALL_BROWSERS=true)"
        return "Set OPENCLAW_ENABLED=false to silence, or check playwright Chromium install"

    async def _lazy_init_pinchtab(self):
        if self._pinchtab_initialized or self.pinchtab:
            return
        if not getattr(settings, "PINCHTAB_ENABLED", getattr(settings, "ALPHA_ENABLE_PINCHTAB", True)):
            self._pinchtab_initialized = True
            return
        try:
            engine = ScrapplingPinchTabEngine()
            ok = await engine.initialize()
            self._pinchtab_initialized = True
            if ok:
                self.pinchtab = engine
                logger.info("[Scrappling] PinchTab engine ready")
            else:
                self.pinchtab = None
                base_url = getattr(getattr(engine, "client", None), "base_url", "http://127.0.0.1:9867")
                reason = f"pinchtab_daemon_unreachable at {base_url}"
                hint = f"PinchTab base URL {base_url} unreachable; set ALPHA_ENABLE_PINCHTAB=false to silence"
                logger.warning("[Scrappling] PinchTab engine offline: %s | hint: %s", reason, hint)
                self._pinchtab_last_reason = reason
                self._pinchtab_last_hint = hint
        except Exception as exc:
            self.pinchtab = None
            self._pinchtab_initialized = True
            self._pinchtab_last_reason = f"{type(exc).__name__}: {exc}"
            self._pinchtab_last_hint = "Inspect backend.integrations.pinchtab_client; set ALPHA_ENABLE_PINCHTAB=false to silence"
            logger.warning("[Scrappling] PinchTab lazy-init crashed (%s: %s)", type(exc).__name__, exc, exc_info=True)
    
    def get_resource_stats(self) -> Dict[str, Any]:
        return {
            "active_contexts": len(self._active_contexts),
            "pooled_contexts": len(self._context_pool),
            "max_contexts": self._max_contexts,
            "max_pool_size": self._max_pool_size,
            "openclaw_initialized": self._openclaw_initialized,
            "pinchtab_initialized": self._pinchtab_initialized,
            "memory_threshold_mb": self._memory_threshold_mb
        }

    def is_ready(self) -> bool:
        if not self._initialized and not (self._openclaw_initialized or self._pinchtab_initialized):
            return False
        if self.openclaw is not None:
            return True
        return self.pinchtab is not None and self._pinchtab_ready()

    def get_engine_status(self) -> Dict[str, Any]:
        openclaw_status = {"available": self.openclaw is not None, "initialized": self._openclaw_initialized}
        if self.openclaw is None and self._openclaw_initialized:
            openclaw_status["reason"] = "see warning log"
        elif self.openclaw is not None:
            err = getattr(self.openclaw, "last_init_error", "")
            if err:
                openclaw_status["last_init_error"] = err

        pinchtab_status = {"available": self.pinchtab is not None and self._pinchtab_ready(), "initialized": self._pinchtab_initialized}
        if self.pinchtab is None and self._pinchtab_initialized:
            pinchtab_status["reason"] = "pinchtab_daemon_not_running"

        return {"openclaw": openclaw_status, "pinchtab": pinchtab_status}

    async def health_check(self) -> Dict[str, Any]:
        if not self._openclaw_initialized:
            await self._lazy_init_openclaw()
        if not self._pinchtab_initialized:
            await self._lazy_init_pinchtab()

        openclaw_state = "unavailable"
        if self.openclaw is not None:
            try:
                probe = await self.openclaw.is_truly_available()
                openclaw_state = "ok" if probe else "degraded"
            except Exception:
                openclaw_state = "degraded"

        pinchtab_state = "ok" if (self.pinchtab is not None and self._pinchtab_ready()) else "unavailable"

        reasons = {}
        if openclaw_state != "ok":
            if self._openclaw_last_reason:
                reasons["openclaw"] = self._openclaw_last_reason
            if self._openclaw_last_hint:
                reasons["openclaw_hint"] = self._openclaw_last_hint
        if pinchtab_state != "ok":
            if self._pinchtab_last_reason:
                reasons["pinchtab"] = self._pinchtab_last_reason
            if self._pinchtab_last_hint:
                reasons["pinchtab_hint"] = self._pinchtab_last_hint

        return {"openclaw": openclaw_state, "pinchtab": pinchtab_state, "reasons": reasons}
    
    async def cleanup_all_resources(self):
        logger.info("[Scrappling] Starting comprehensive resource cleanup...")
        async with self._context_lock:
            context_ids = list(self._active_contexts.keys())
        for context_id in context_ids:
            try:
                await self.close_context(context_id)
            except Exception as e:
                logger.error(f"[Scrappling] Failed to close context {context_id}: {e}")
        async with self._pool_lock:
            pool_size = len(self._context_pool)
            self._context_pool.clear()
            logger.info(f"[Scrappling] Cleared {pool_size} pooled contexts")
        logger.info("[Scrappling] Resource cleanup complete")
    
    async def close(self):
        logger.info("[Scrappling] Closing browser engines...")
        await self.cleanup_all_resources()
        if self.openclaw:
            await self.openclaw.close()
        if self.pinchtab:
            await self.pinchtab.close()
        self._initialized = False
        logger.info("[Scrappling] Closed")

    # Scrapling specific methods
    async def stealth_fetch(self, url, **kwargs):
        """Fetch using Scrapling StealthyFetcher with anti-bot bypass."""
        if not _SCRAPLING_AVAILABLE or StealthyFetcher is None:
            raise ScrapplingUnavailable("Scrapling StealthyFetcher is not available")
        if hasattr(self, "_proxy_rotator") and self._proxy_rotator:
            kwargs.setdefault("proxy", self._proxy_rotator)
        try:
            fetcher = StealthyFetcher()
            response = fetcher.fetch(url, **kwargs)
            sel = Selector(content=response.text, url=str(response.url)) if Selector is not None else None
            return {"success": True, "status_code": response.status, "text": response.text, "selector": sel, "url": response.url}
        except Exception as e:
            logger.error("[Scrappling] stealth_fetch failed for %s: %s", url, e)
            return {"success": False, "error": str(e)}

    async def fast_fetch(self, url, impersonate='chrome', **kwargs):
        """Fetch using Scrapling Fetcher with TLS impersonation."""
        if not _SCRAPLING_AVAILABLE or Fetcher is None:
            raise ScrapplingUnavailable("Scrapling Fetcher is not available")
        if hasattr(self, "_proxy_rotator") and self._proxy_rotator:
            kwargs.setdefault("proxy", self._proxy_rotator)
        try:
            fetcher = Fetcher()
            response = fetcher.get(url, impersonate=impersonate, **kwargs)
            sel = Selector(content=response.text, url=str(response.url)) if Selector is not None else None
            return {"success": True, "status_code": response.status, "text": response.text, "selector": sel, "url": response.url}
        except Exception as e:
            logger.error("[Scrappling] fast_fetch failed for %s: %s", url, e)
            return {"success": False, "error": str(e)}

    async def dynamic_fetch(self, url, **kwargs):
        """Fetch using Scrapling DynamicFetcher for JS-heavy pages."""
        if not _SCRAPLING_AVAILABLE or DynamicFetcher is None:
            raise ScrapplingUnavailable("Scrapling DynamicFetcher is not available")
        if hasattr(self, "_proxy_rotator") and self._proxy_rotator:
            kwargs.setdefault("proxy", self._proxy_rotator)
        try:
            fetcher = DynamicFetcher()
            response = fetcher.fetch(url, **kwargs)
            sel = Selector(content=response.text, url=str(response.url)) if Selector is not None else None
            return {"success": True, "status_code": response.status, "text": response.text, "selector": sel, "url": response.url}
        except Exception as e:
            logger.error("[Scrappling] dynamic_fetch failed for %s: %s", url, e)
            return {"success": False, "error": str(e)}

    async def batch_fetch(self, urls, max_concurrent=5, **kwargs):
        """Batch fetch multiple URLs using Scrapling fetchers."""
        if not _SCRAPLING_AVAILABLE or AsyncFetcher is None:
            raise ScrapplingUnavailable("Scrapling AsyncFetcher is not available")
        sem = asyncio.Semaphore(max_concurrent)
        async def _fetch(url):
            async with sem:
                try:
                    fetcher = AsyncFetcher()
                    response = await fetcher.get(url, **kwargs)
                    return {"url": url, "success": True, "status_code": response.status, "text": response.text}
                except Exception as e:
                    return {"url": url, "success": False, "error": str(e)}
        tasks = [_fetch(u) for u in urls]
        return await asyncio.gather(*tasks)

    async def scrape_with_selector(self, url, css_selector, **fetch_kwargs):
        """Fetch a URL and extract data using Scrapling adaptive CSS selector."""
        res = await self.fast_fetch(url, **fetch_kwargs)
        if not res.get("success") or not res.get("selector"):
            return []
        sel = res.get("selector")
        results = []
        try:
            for elem in sel.css(css_selector):
                results.append({
                    "tag": getattr(elem, "tag", ""),
                    "text": elem.text,
                    "attributes": elem.attrib,
                    "html": getattr(elem, "html", "")
                })
        except Exception as e:
            logger.error("[Scrappling] scrape_with_selector failed: %s", e)
        return results


# Backward-compatible aliases
BrowserEngine = ScrapplingEngine
OpenClawEngine = ScrapplingPlaywrightEngine
PinchTabEngine = ScrapplingPinchTabEngine
PinchTabInstance = ScrapplingFuzzer
PinchTabClient = ScrapplingPinchTabClient
BrowserOrchestrator = Scrappling

_browser_orchestrator = None

def get_browser_orchestrator() -> Scrappling:
    """Get global BrowserOrchestrator instance"""
    global _browser_orchestrator
    if _browser_orchestrator is None:
        _browser_orchestrator = Scrappling()
    return _browser_orchestrator


