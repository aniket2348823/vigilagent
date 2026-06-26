from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProxyEnvSnapshot:
    """Captures all proxy-related environment variables in a frozen snapshot."""

    http_proxy: str | None
    https_proxy: str | None
    HTTP_PROXY: str | None
    HTTPS_PROXY: str | None
    no_proxy: str | None
    NO_PROXY: str | None
    VIGILAGENT_PROXY_ACTIVE: str | None
    VIGILAGENT_PROXY_LOOPBACK_MODE: str | None


@dataclass
class ProxyValidationCheck:
    kind: str
    url: str
    ok: bool
    status: int | None = None
    error: str | None = None


@dataclass
class ProxyValidationResult:
    ok: bool
    proxy_url: str
    checks: list[ProxyValidationCheck] = field(default_factory=list)


class NoProxyMatcher:
    """
    Implements NO_PROXY semantic matching equivalent to Node.js Undici.
    """

    def matches(self, target_url: str, no_proxy_string: str) -> bool:
        if not no_proxy_string:
            return False

        parsed = urlparse(target_url)
        host = parsed.hostname
        if not host:
            return False

        host = host.lower()
        port = str(parsed.port) if parsed.port else ""

        entries = [e.strip().lower() for e in re.split(r"[,\s]+", no_proxy_string) if e.strip()]

        if "*" in entries:
            return True

        target_ip = self._parse_ipv4(host)

        for entry in entries:
            # Exact match or port match
            if entry == host or entry == f"{host}:{port}":
                return True

            # Leading dot match (.example.com matches foo.example.com)
            if entry.startswith(".") and host.endswith(entry):
                return True

            # Wildcard subdomain match (*.example.com)
            if entry.startswith("*.") and host.endswith(entry[1:]):
                return True

            # IPv4 CIDR match (10.0.0.0/8)
            if target_ip and "/" in entry and self._matches_cidr(target_ip, entry):
                return True

            # IPv4 octet wildcard (10.0.*)
            if target_ip and entry.endswith(".*"):
                prefix = entry[:-2]
                if host.startswith(prefix + "."):
                    return True

        return False

    def _parse_ipv4(self, host: str) -> ipaddress.IPv4Address | None:
        try:
            return ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            return None

    def _matches_cidr(self, target_ip: ipaddress.IPv4Address, cidr_entry: str) -> bool:
        try:
            network = ipaddress.IPv4Network(cidr_entry, strict=False)
            return target_ip in network
        except ValueError:
            return False


class ProxyLifecycleManager:
    """
    High-level lifecycle management for the operator-managed network proxy routing.
    Mirrors OpenClaw's proxy-lifecycle.ts and proxy-env.ts.
    """

    def __init__(self):
        self._active_proxy_url: str | None = None
        self._loopback_mode: str = "gateway-only"
        self._base_env_snapshot: ProxyEnvSnapshot | None = None
        self._bypassed_urls: set[str] = set()
        self._active_handles = 0

    @property
    def is_active(self) -> bool:
        return self._active_handles > 0

    @property
    def active_proxy_url(self) -> str | None:
        return self._active_proxy_url

    def start_proxy(self, proxy_url: str = None, loopback_mode: str = "gateway-only") -> bool:
        candidate_url = proxy_url or os.environ.get("OPENCLAW_PROXY_URL") or os.environ.get("VIGILAGENT_PROXY_URL")
        if not candidate_url:
            return False

        parsed = urlparse(candidate_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Proxy URL must be http:// or https://")

        if self._active_handles == 0:
            self._base_env_snapshot = ProxyEnvSnapshot(
                http_proxy=os.environ.get("http_proxy"),
                https_proxy=os.environ.get("https_proxy"),
                HTTP_PROXY=os.environ.get("HTTP_PROXY"),
                HTTPS_PROXY=os.environ.get("HTTPS_PROXY"),
                no_proxy=os.environ.get("no_proxy"),
                NO_PROXY=os.environ.get("NO_PROXY"),
                VIGILAGENT_PROXY_ACTIVE=os.environ.get("VIGILAGENT_PROXY_ACTIVE"),
                VIGILAGENT_PROXY_LOOPBACK_MODE=os.environ.get("VIGILAGENT_PROXY_LOOPBACK_MODE"),
            )

        self._active_proxy_url = candidate_url
        self._loopback_mode = loopback_mode
        self._active_handles += 1

        for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
            os.environ[key] = candidate_url

        os.environ["VIGILAGENT_PROXY_ACTIVE"] = "1"
        os.environ["VIGILAGENT_PROXY_LOOPBACK_MODE"] = loopback_mode

        self._update_no_proxy()
        logger.info(f"Proxy lifecycle: Activated process-wide routing via {self._redact_proxy_url(candidate_url)}")
        return True

    def stop_proxy(self) -> None:
        if self._active_handles <= 0:
            return

        self._active_handles -= 1
        if self._active_handles > 0:
            return

        self._restore_env()
        self._active_proxy_url = None
        self._bypassed_urls.clear()
        logger.info("Proxy lifecycle: Deactivated, restored original environment.")

    def kill(self, signal: int = 0) -> None:
        """Synchronous env restore for hard process exit"""
        self._restore_env()
        self._active_handles = 0

    def _restore_env(self) -> None:
        if not self._base_env_snapshot:
            return

        snapshot_dict = self._base_env_snapshot.__dict__
        for k, v in snapshot_dict.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _update_no_proxy(self) -> None:
        if not self._bypassed_urls:
            if self._base_env_snapshot and self._base_env_snapshot.no_proxy:
                os.environ["no_proxy"] = self._base_env_snapshot.no_proxy
                os.environ["NO_PROXY"] = self._base_env_snapshot.NO_PROXY or self._base_env_snapshot.no_proxy
            else:
                os.environ.pop("NO_PROXY", None)
                os.environ.pop("no_proxy", None)
            return

        base_no_proxy = ""
        if self._base_env_snapshot and self._base_env_snapshot.no_proxy:
            base_no_proxy = self._base_env_snapshot.no_proxy + ","

        no_proxy_str = base_no_proxy + ",".join(self._bypassed_urls)
        os.environ["NO_PROXY"] = no_proxy_str
        os.environ["no_proxy"] = no_proxy_str

    def _is_loopback_host(self, hostname: str) -> bool:
        normalized = hostname.lower().strip().rstrip(".")
        if normalized == "localhost":
            return True
        try:
            socket.inet_pton(socket.AF_INET, hostname)
            if hostname.startswith("127."):
                return True
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            if hostname == "::1":
                return True
        except OSError:
            pass
        return False

    def _redact_proxy_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.password:
            return url.replace(f":{parsed.password}@", ":***@")
        return url

    def register_browser_cdp_bypass(self, url: str) -> Callable[[], None] | None:
        return self._register_bypass(url, "Browser loopback CDP")

    def register_gateway_loopback_bypass(self, url: str) -> Callable[[], None] | None:
        return self._register_bypass(url, "Gateway loopback")

    def _register_bypass(self, url: str, context: str) -> Callable[[], None] | None:
        parsed = urlparse(url)
        if not parsed.hostname or not self._is_loopback_host(parsed.hostname):
            return None

        if self._loopback_mode == "block":
            raise PermissionError(f"{context} connections are blocked by proxy.loopbackMode")
        if self._loopback_mode == "proxy":
            return None

        authority = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
        self._bypassed_urls.add(authority)
        self._update_no_proxy()

        def unregister():
            if authority in self._bypassed_urls:
                self._bypassed_urls.remove(authority)
                self._update_no_proxy()

        return unregister


class NetworkInterceptor:
    """
    Transport layer interception pipeline mimicking Undici dispatchers.
    Dynamically randomizes User-Agent, injects jitter delays, and rotates
    headers silently before the payload hits the wire.
    """

    def __init__(self):
        self._user_agents = [
            # Chrome Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Chrome Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            # Firefox Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
            # Firefox Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
            # Safari Mac
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            # Edge Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
            # Linux Chrome
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            # Linux Firefox
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        ]

        self._languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9,en-US;q=0.8",
            "en-US,en;q=0.9,es;q=0.8",
            "en-US,en;q=0.9,fr;q=0.8",
        ]

    def rotate_accept_language(self) -> str:
        return random.choice(self._languages)

    def generate_realistic_referer(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    def get_tls_fingerprint_headers(self) -> dict[str, str]:
        # Simple simulation of modern browser TLS/HTTP2 pseudo-headers
        # In a real environment, this might interface with a specialized TLS client (e.g. curl-impersonate)
        return {
            "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "upgrade-insecure-requests": "1",
        }

    def inject_spoofed_headers(self, request_headers: dict[str, str]) -> dict[str, str]:
        spoofed = {k.lower(): v for k, v in request_headers.items()}

        if "user-agent" not in spoofed:
            spoofed["user-agent"] = random.choice(self._user_agents)

        spoofed.setdefault("accept-language", self.rotate_accept_language())
        spoofed.setdefault("accept-encoding", "gzip, deflate, br")
        spoofed.setdefault("sec-fetch-dest", "document")
        spoofed.setdefault("sec-fetch-mode", "navigate")
        spoofed.setdefault("sec-fetch-site", "none")
        spoofed.setdefault("sec-fetch-user", "?1")

        # Merge TLS pseudo headers if not already heavily customized
        if "sec-ch-ua" not in spoofed:
            spoofed.update(self.get_tls_fingerprint_headers())

        # Restore original casing for custom headers (optional, standard HTTP is case-insensitive)
        return spoofed

    async def inject_timing_jitter(self, min_ms: int = 50, max_ms: int = 500) -> None:
        """Injects random async sleep to evade WAF rate detection."""
        jitter = random.uniform(min_ms, max_ms) / 1000.0
        await asyncio.sleep(jitter)

    async def fetch(
        self,
        method: str,
        url: str,
        *,
        session: Any = None,
        headers: dict[str, str] | None = None,
        timeout: int | float = 10,
        jitter: tuple[int, int] = (50, 500),
        **kwargs: Any,
    ) -> InterceptedHTTPResponse:
        """Execute an outbound HTTP request through the interceptor pipeline."""
        import time

        import aiohttp

        from backend.core.queue import command_lane

        spoofed_headers = self.inject_spoofed_headers(headers or {})
        await self.inject_timing_jitter(*jitter)
        start = time.time()

        async def _request(active_session):
            async with active_session.request(
                method,
                url,
                headers=spoofed_headers,
                timeout=timeout,
                **kwargs,
            ) as resp:
                body = await resp.text(errors="replace")
                return InterceptedHTTPResponse(
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    elapsed_ms=int((time.time() - start) * 1000),
                    url=str(resp.url),
                )

        async with command_lane.slot():
            if session is not None:
                return await _request(session)

            client_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=client_timeout) as transient_session:
                return await _request(transient_session)


@dataclass
class InterceptedHTTPResponse:
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    url: str


class ProxyValidation:
    @staticmethod
    async def validate_proxy(proxy_url: str, test_urls: list[str] = None) -> ProxyValidationResult:
        import aiohttp

        if test_urls is None:
            test_urls = ["https://example.com/"]

        checks = []
        all_ok = True

        # LOW-77: Enable SSL verification for proxy validation
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            for url in test_urls:
                try:
                    async with session.get(url, proxy=proxy_url, timeout=10) as resp:
                        checks.append(ProxyValidationCheck("allowed", url, True, resp.status))
                except Exception as e:
                    all_ok = False
                    checks.append(ProxyValidationCheck("denied", url, False, None, str(e)))

        return ProxyValidationResult(ok=all_ok, proxy_url=proxy_url, checks=checks)


# Global singleton instances
proxy_lifecycle = ProxyLifecycleManager()
network_interceptor = NetworkInterceptor()
no_proxy_matcher = NoProxyMatcher()
