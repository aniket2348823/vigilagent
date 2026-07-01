"""
CRLF Injection / HTTP Response Splitting Probe (Architecture §5.2, §17).

Tests for CRLF injection by injecting %0d%0a (\\r\\n) sequences into parameters
and checking if the server splits the response headers. A successful CRLF
injection can lead to XSS (via Location header injection), cache poisoning,
or session fixation.

Uses verification methods from backend.core.verification:
  - Method 30: HTTP request splitting (CRLF injection detection)
  - Method 3: Negative proof
  - Method 14: Response entropy analysis
"""

from __future__ import annotations

import re
import urllib.parse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

# CRLF injection payloads
_CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:%20VIGILAGENT_PROBE",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aSet-Cookie:%20injected=1",
    "%0d%0aLocation:%20https://evil.com",
    "\r\nInjected-Header: VIGILAGENT_PROBE",
    "%0d%0aX-Injected:%20true%0d%0aContent-Length:%200",
    "%E5%98%8A%E5%98%8DInjected-Header:%20VIGILAGENT_PROBE",  # Unicode CRLF
]

_CRLF_MARKER = "Injected-Header: VIGILAGENT_PROBE"
_LOCATION_MARKER = "https://evil.com"

# Parameter names commonly targeted for header injection
_INJECT_PARAMS = (
    "name", "q", "search", "input", "redirect", "url", "next",
    "return", "goto", "forward", "ref", "referer", "callback",
    "data", "value", "text", "message", "comment", "page",
)


class CRLFInjectionProbe(BaseArsenalModule):
    """CRLF injection probe. Confirms with injected-header detection."""

    def __init__(self):
        super().__init__()
        self.name = "CRLF Injection Probe"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        targets = []
        url = packet.target.url
        headers = dict(packet.target.headers or {})

        # Baseline (index 0)
        targets.append(TaskTarget(
            url=url,
            method=packet.target.method or "GET",
            headers=headers,
            payload=packet.target.payload,
        ))

        if "?" not in url:
            return targets

        base, query = url.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        if not params:
            return targets

        target_params = [p for p in params if p.lower() in _INJECT_PARAMS] or list(params.keys())

        for param in target_params:
            for payload in _CRLF_PAYLOADS:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param] = [payload]
                attack_url = f"{base}?{urllib.parse.urlencode(mutated, doseq=True)}"
                targets.append(TaskTarget(
                    url=attack_url,
                    method="GET",
                    headers=dict(headers),
                    payload=packet.target.payload,
                ))

        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        from backend.modules.evidence import differential
        from backend.core.verification import (
            detect_crlf_injection,
            negative_proof_check,
            entropy_delta,
            calculate_final_confidence,
        )

        vulns = []
        if not interactions:
            return vulns

        baseline_target, baseline_text = interactions[0]
        baseline_text = baseline_text if isinstance(baseline_text, str) else ""

        seen = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue

            signals = []

            # Method 30: Check for CRLF injection markers in response
            confirmed, evidence = detect_crlf_injection({}, text)
            if confirmed:
                signals.append("crlf_header_injected")
            elif _CRLF_MARKER in text:
                signals.append("crlf_marker_in_body")
            elif _LOCATION_MARKER in text:
                signals.append("location_header_injected")

            if not signals:
                continue

            # Differential check
            ev = differential(baseline_text, text)
            if ev.signals >= 1 or ev.verified:
                signals.append("response_differential")

            # Negative proof
            is_genuine, reasons = negative_proof_check(text, baseline_text, "CRLF")
            if not is_genuine:
                continue

            key = target.url
            if key in seen:
                continue
            seen.add(key)

            # Confidence
            confidence = calculate_final_confidence(
                base_confidence=0.85,
                has_negative_proof_pass=is_genuine,
                has_side_channel=ev.signals >= 1,
            )

            vulns.append(Vulnerability(
                name="CRLF Injection (HTTP Response Splitting)",
                severity="HIGH",
                description=(
                    "Injected CRLF sequences caused header injection in the HTTP "
                    f"response. Signals: {', '.join(signals)}."
                ),
                evidence=(
                    f"Target: {target.url}\n"
                    f"Signals: {', '.join(signals)}\n"
                    f"Evidence: {evidence}\n"
                    f"Differential: {ev.summary}"
                ),
                remediation=(
                    "Sanitize all user input before including it in HTTP headers. "
                    "Reject any input containing CR (\\r) or LF (\\n) characters. "
                    "Use encoding functions for header values."
                ),
                confidence=confidence,
            ))
            break

        return vulns
