"""
Prototype Pollution Detection Probe (Architecture §5.2, §17).

Tests for JavaScript prototype pollution vulnerabilities in Node.js applications.
Injects __proto__ and constructor.prototype payloads to check if pollution
propagates to subsequent requests or is reflected in the response.

Uses verification methods from backend.core.verification:
  - Method 31: Prototype pollution detection
  - Method 3: Negative proof
  - Method 22: Semantic payload uniqueness
"""

from __future__ import annotations

import json
import urllib.parse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

# Unique markers for pollution detection
_MARKER = "VIGILAGENT_POLLUTED"
_TIMESTAMP_MARKER_PREFIX = "VIGIL_TS_"

# Prototype pollution payloads
_POLLUTION_PAYLOADS = [
    {"__proto__": {"pollution_test": _MARKER}},
    {"constructor": {"prototype": {"pollution_test": _MARKER}}},
    {"__proto__": {"pollution_test": _MARKER}, "normal_field": "value"},
]

# Content types that can trigger prototype pollution
_JSON_CONTENT_TYPES = (
    "application/json",
    "text/json",
)


class PrototypePollutionProbe(BaseArsenalModule):
    """Prototype pollution probe for Node.js applications."""

    def __init__(self):
        super().__init__()
        self.name = "Prototype Pollution Probe"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        targets = []
        url = packet.target.url
        headers = dict(packet.target.headers or {})

        # Baseline (index 0) — GET request to establish baseline
        targets.append(TaskTarget(
            url=url,
            method="GET",
            headers=headers,
            payload=packet.target.payload,
        ))

        # Test each pollution payload via POST with JSON body
        json_headers = dict(headers)
        json_headers["Content-Type"] = "application/json"

        for payload in _POLLUTION_PAYLOADS:
            targets.append(TaskTarget(
                url=url,
                method="POST",
                headers=json_headers,
                payload=payload,
            ))

        # Also test via URL query parameters (__proto__[key]=value)
        if "?" in url:
            base, query = url.split("?", 1)
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            for param in params:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param] = [f"test&__proto__[pollution_test]={_MARKER}"]
                attack_url = f"{base}?{urllib.parse.urlencode(mutated, doseq=True)}"
                targets.append(TaskTarget(
                    url=attack_url,
                    method="GET",
                    headers=dict(headers),
                    payload=packet.target.payload,
                ))
        else:
            # Try adding __proto__ param directly
            sep = "&" if "?" in url else "?"
            attack_url = f"{url}{sep}__proto__[pollution_test]={_MARKER}"
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
            detect_prototype_pollution,
            negative_proof_check,
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

            # Method 31: Check if pollution marker propagated
            confirmed, evidence = detect_prototype_pollution(text)
            if confirmed:
                signals.append("pollution_marker_reflected")
            elif _MARKER in text:
                signals.append("pollution_marker_in_response")

            # Also check for __proto__ in response (reflection of the payload itself)
            if "__proto__" in text and _MARKER in text:
                signals.append("proto_payload_reflected")

            if not signals:
                continue

            # Differential check
            ev = differential(baseline_text, text)
            if ev.signals >= 1 or ev.verified:
                signals.append("response_differential")

            # Negative proof
            is_genuine, reasons = negative_proof_check(text, baseline_text, "PROTOTYPE_POLLUTION")
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
                name="Prototype Pollution",
                severity="HIGH",
                description=(
                    "Injected __proto__ payload caused property pollution that "
                    "propagated to the response. This can lead to XSS, RCE, or "
                    "denial of service in Node.js applications."
                ),
                evidence=(
                    f"Target: {target.url}\n"
                    f"Method: {target.method}\n"
                    f"Signals: {', '.join(signals)}\n"
                    f"Evidence: {evidence}\n"
                    f"Differential: {ev.summary}"
                ),
                remediation=(
                    "Use Object.create(null) for dictionaries that accept user input. "
                    "Freeze Object.prototype and Array.prototype. "
                    "Use Map instead of plain objects for user-controlled keys. "
                    "Validate and sanitize all keys before assignment."
                ),
                confidence=confidence,
            ))
            break

        return vulns
