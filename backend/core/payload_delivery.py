"""
Vigilagent Payload Delivery Engine + Bandit (Architecture §5.2, §6, §29.6)
================================================================================
Beta must stop being only a query-string payload sender (Architecture §5.2). The
PayloadDeliveryEngine delivers an authorized validation payload across the
correct channel instead of forcing everything into a GET parameter.

Delivery vectors (Architecture §5.2, §29.6):
  query, json_body, form_body, header, cookie, path  (core HTTP, via deliver())
  graphql, multipart                                 (API vectors, via deliver())
  websocket                                          (via deliver_websocket())
  (browser-form submission is delivered by the browser agents.)

PayloadBandit (Architecture §6 "real, not fake"): an epsilon-greedy multi-armed
bandit keyed by (vuln_class, vector, payload_family). The reward is the REAL
verification outcome from the MultiLayerVerifier — not a log line.

Every delivery records request/response/timestamp/vector for evidence
(Architecture §6 Phase 6).
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlparse, urlunparse

from backend.core.proxy import network_interceptor
from backend.core.scope import ScopePolicy, ScopeViolation, scope_guard

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger("vigilagent.payload_delivery")

HTTP_VECTORS = ("query", "json_body", "form_body", "header", "cookie", "path")
# Extended API vectors (Architecture §5.2, §29.6). multipart/file requires
# explicit approval; graphql targets a /graphql endpoint; websocket uses ws/wss.
API_VECTORS = ("graphql", "multipart")
ALL_HTTP_VECTORS = HTTP_VECTORS + API_VECTORS


def payload_family(payload: str) -> str:
    """Classify a payload into a coarse family for bandit keying."""
    p = payload.lower()
    if any(t in p for t in ("select", "union", "' or", "1=1", "--", "/*")):
        return "sqli"
    if any(t in p for t in ("<script", "onerror", "onload", "alert(", "svg/")):
        return "xss"
    if any(t in p for t in ("{{", "}}", "${", "<%", "#{")):
        return "ssti"
    if any(t in p for t in ("../", "..\\", "/etc/passwd", "%2e%2e")):
        return "traversal"
    if any(t in p for t in (";", "|", "`", "$(", "&&")):
        return "cmdi"
    return "generic"


@dataclass
class DeliveryResult:
    vector: str
    payload: str
    family: str
    status: int
    body: str
    latency_ms: float
    request_url: str
    timestamp: float = field(default_factory=time.time)
    error: str = ""

    def evidence(self) -> dict[str, Any]:
        return {
            "vector": self.vector,
            "payload": self.payload[:200],
            "family": self.family,
            "status": self.status,
            "latency_ms": round(self.latency_ms, 2),
            "request_url": self.request_url,
            "timestamp": self.timestamp,
            "response_len": len(self.body or ""),
            "error": self.error,
        }


class PayloadBandit:
    """Epsilon-greedy bandit over (vuln_class, vector, payload_family) (§6)."""

    def __init__(self, epsilon: float = 0.15) -> None:
        self.epsilon = epsilon
        # key -> {"tries": int, "hits": int}
        self._arms: dict[tuple[str, str, str], dict[str, int]] = {}

    @staticmethod
    def _key(vuln_class: str, vector: str, family: str) -> tuple[str, str, str]:
        return (vuln_class.lower(), vector, family)

    def hit_rate(self, vuln_class: str, vector: str, family: str) -> float:
        arm = self._arms.get(self._key(vuln_class, vector, family))
        if not arm or arm["tries"] == 0:
            return 0.0
        return arm["hits"] / arm["tries"]

    def select_vector(self, vuln_class: str, family: str, vectors: Iterable[str] | None = None) -> str:
        """Choose a delivery vector: explore with prob epsilon, else exploit the
        best historical hit-rate for this (vuln_class, family)."""
        candidates = list(vectors) if vectors else list(HTTP_VECTORS)
        if random.random() < self.epsilon:
            return random.choice(candidates)
        scored = sorted(candidates, key=lambda v: self.hit_rate(vuln_class, v, family), reverse=True)
        # If nothing has history yet, scored order is arbitrary; that's fine.
        return scored[0]

    def update(self, vuln_class: str, vector: str, family: str, success: bool) -> None:
        """Update arm statistics with the REAL verification outcome."""
        arm = self._arms.setdefault(self._key(vuln_class, vector, family), {"tries": 0, "hits": 0})
        arm["tries"] += 1
        if success:
            arm["hits"] += 1

    def snapshot(self) -> dict[str, dict[str, int]]:
        return {f"{k[0]}|{k[1]}|{k[2]}": dict(v) for k, v in self._arms.items()}


class PayloadDeliveryEngine:
    """Delivers a payload across multiple HTTP vectors (Architecture §5.2, §29.6)."""

    def __init__(self, scope: ScopePolicy | None = None) -> None:
        self.scope = scope or scope_guard

    async def deliver(
        self,
        target_url: str,
        payload: str,
        *,
        vectors: Iterable[str] = HTTP_VECTORS,
        param: str = "q",
        header_name: str = "X-Vigilagent-Test",
        cookie_name: str = "va_test",
        session=None,
        base_headers: dict[str, str] | None = None,
        action: str = "validate",
    ) -> list[DeliveryResult]:
        """Deliver ``payload`` to ``target_url`` over each requested vector.

        Every request is scope-checked first (Architecture §9). ``action`` of
        validate/attack requires an authorized engagement."""
        try:
            self.scope.assert_allowed(target_url, action=action)
        except ScopeViolation as exc:
            logger.warning("[Delivery] scope blocked %s: %s", target_url, exc)
            return []

        family = payload_family(payload)
        results: list[DeliveryResult] = []
        for vector in vectors:
            res = await self._deliver_one(
                target_url,
                payload,
                vector,
                family,
                param,
                header_name,
                cookie_name,
                session,
                base_headers or {},
            )
            if res:
                results.append(res)
        return results

    async def _deliver_one(
        self,
        url: str,
        payload: str,
        vector: str,
        family: str,
        param: str,
        header_name: str,
        cookie_name: str,
        session,
        base_headers: dict[str, str],
    ) -> DeliveryResult | None:
        method = "GET"
        kwargs: dict[str, Any] = {"timeout": 10}
        if session is not None:
            kwargs["session"] = session
        headers = dict(base_headers)
        request_url = url
        parsed = urlparse(url)

        try:
            if vector == "query":
                sep = "&" if parsed.query else "?"
                request_url = f"{url}{sep}{urlencode({param: payload})}"
            elif vector == "path":
                # Append payload as a path segment (encoded).
                new_path = parsed.path.rstrip("/") + "/" + payload
                request_url = urlunparse(parsed._replace(path=new_path))
            elif vector == "json_body":
                method = "POST"
                kwargs["json"] = {param: payload}
            elif vector == "form_body":
                method = "POST"
                kwargs["data"] = {param: payload}
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif vector == "header":
                headers[header_name] = payload
            elif vector == "cookie":
                existing = headers.get("Cookie", "")
                headers["Cookie"] = (existing + "; " if existing else "") + f"{cookie_name}={payload}"
            elif vector == "graphql":
                # GraphQL: deliver the payload inside a query variable (Architecture §5.2).
                method = "POST"
                kwargs["json"] = {
                    "query": "query($v:String){__typename}",
                    "variables": {"v": payload},
                }
                headers["Content-Type"] = "application/json"
            elif vector == "multipart":
                # Multipart/file upload (Architecture §5.2 — approved scope only).
                method = "POST"
                kwargs["data"] = {param: payload, "filename": f"va_{param}.txt"}
            else:
                return None

            if headers:
                kwargs["headers"] = headers

            start = time.perf_counter()
            response = await network_interceptor.fetch(method, request_url, **kwargs)
            latency = (time.perf_counter() - start) * 1000
            return DeliveryResult(
                vector=vector,
                payload=payload,
                family=family,
                status=getattr(response, "status", 0),
                body=getattr(response, "body", ""),
                latency_ms=latency,
                request_url=request_url,
            )
        except Exception as exc:
            return DeliveryResult(
                vector=vector,
                payload=payload,
                family=family,
                status=0,
                body="",
                latency_ms=0.0,
                request_url=request_url,
                error=str(exc),
            )

    async def baseline(self, target_url: str, *, session=None) -> DeliveryResult | None:
        """Fetch a clean baseline for differential comparison (Architecture §17)."""
        try:
            self.scope.assert_allowed(target_url, action="request")
        except ScopeViolation:
            return None
        kwargs: dict[str, Any] = {"timeout": 10}
        if session is not None:
            kwargs["session"] = session
        try:
            start = time.perf_counter()
            response = await network_interceptor.fetch("GET", target_url.split("?")[0], **kwargs)
            latency = (time.perf_counter() - start) * 1000
            return DeliveryResult(
                vector="baseline",
                payload="",
                family="baseline",
                status=getattr(response, "status", 0),
                body=getattr(response, "body", ""),
                latency_ms=latency,
                request_url=target_url,
            )
        except Exception as exc:
            return DeliveryResult("baseline", "", "baseline", 0, "", 0.0, target_url, error=str(exc))

    # Benign/sham values used as negative controls (Architecture §17, §29.6).
    _NEGATIVE_CONTROLS = {
        "sqli": "vigilagent_benign_value_123",
        "xss": "vigilagent_plain_text_123",
        "ssti": "vigilagent_no_template_123",
        "traversal": "vigilagent_normal_path",
        "cmdi": "vigilagent_safe_token",
        "generic": "vigilagent_control_value",
    }

    async def negative_control(
        self,
        target_url: str,
        payload: str,
        vector: str,
        *,
        param: str = "q",
        header_name: str = "X-Vigilagent-Test",
        cookie_name: str = "va_test",
        session=None,
        base_headers: dict[str, str] | None = None,
    ) -> DeliveryResult | None:
        """Deliver a BENIGN value over the SAME vector as the test payload.

        If this benign request triggers the same divergence the malicious payload
        did, the divergence is environmental noise, not a vulnerability
        (Architecture §17 negative control)."""
        family = payload_family(payload)
        control_value = self._NEGATIVE_CONTROLS.get(family, self._NEGATIVE_CONTROLS["generic"])
        try:
            self.scope.assert_allowed(target_url, action="validate")
        except ScopeViolation:
            return None
        return await self._deliver_one(
            target_url, control_value, vector, "control", param, header_name, cookie_name, session, base_headers or {}
        )

    async def repeat(
        self,
        target_url: str,
        payload: str,
        vector: str,
        *,
        times: int = 2,
        param: str = "q",
        header_name: str = "X-Vigilagent-Test",
        cookie_name: str = "va_test",
        session=None,
        base_headers: dict[str, str] | None = None,
    ) -> list[DeliveryResult]:
        """Re-deliver the SAME test payload N times for a repeatability check
        (Architecture §17). Stability across repeats raises confidence."""
        family = payload_family(payload)
        results: list[DeliveryResult] = []
        try:
            self.scope.assert_allowed(target_url, action="validate")
        except ScopeViolation:
            return results
        for _ in range(max(1, times)):
            res = await self._deliver_one(
                target_url, payload, vector, family, param, header_name, cookie_name, session, base_headers or {}
            )
            if res:
                results.append(res)
        return results

    async def deliver_websocket(self, ws_url: str, payload: str, *, timeout: float = 10.0) -> DeliveryResult:
        """Deliver a payload over a WebSocket frame (Architecture §5.2, §29.6).

        Scope-checked like every other vector. Uses aiohttp's WS client; returns
        the first received frame as the response body for differential analysis."""
        family = payload_family(payload)
        try:
            self.scope.assert_allowed(ws_url, action="validate")
        except ScopeViolation as exc:
            return DeliveryResult("websocket", payload, family, 0, "", 0.0, ws_url, error=str(exc))
        try:
            import aiohttp

            start = time.perf_counter()
            async with aiohttp.ClientSession() as s, s.ws_connect(ws_url, timeout=timeout) as ws:
                await ws.send_str(payload)
                body = ""
                try:
                    msg = await ws.receive(timeout=timeout)
                    body = str(getattr(msg, "data", ""))
                except Exception as exc:
                    logger.debug("[Delivery] WebSocket receive failed: %s", exc)
            latency = (time.perf_counter() - start) * 1000
            return DeliveryResult("websocket", payload, family, 101, body, latency, ws_url)
        except Exception as exc:
            return DeliveryResult("websocket", payload, family, 0, "", 0.0, ws_url, error=str(exc))


# Global instances.
payload_bandit = PayloadBandit()
payload_delivery_engine = PayloadDeliveryEngine(scope=scope_guard)
