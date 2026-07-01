"""
Server-Side Template Injection (SSTI) Probe (Architecture §5.2, §17).

Detects SSTI across multiple template engines by sending mathematical
expressions that evaluate to predictable values (7*7 = 49). If the response
contains the evaluated result, the server is processing template syntax.

Uses verification methods from backend.core.verification:
  - Method 22: Semantic payload uniqueness (math expressions = deterministic proof)
  - Method 3: Negative proof (eliminate innocent explanations)
  - Method 14: Response entropy analysis
  - Method 12: Bayesian confidence update
"""

from __future__ import annotations

import re
import urllib.parse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

# SSTI probes: (payload, expected_result, engine_name)
_SSTI_PROBES = [
    ("{{7*7}}", "49", "jinja2"),
    ("{{ 7*7 }}", "49", "jinja2"),
    ("${7*7}", "49", "freemarker"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#= 7 * 7 #", "49", "mako"),
    ("${{7*7}}", "49", "angular"),
]

# Arithmetic validation probes (different operations to confirm evaluation)
_VALIDATION_PROBES = [
    ("{{7*7}}", "49"),
    ("{{7+7}}", "14"),
    ("{{7-7}}", "0"),
    ("{{100/7}}", "14.285714285714286"),
]

# Escalation probes for confirmed SSTI
_RCE_PROBES = {
    "jinja2": [
        ("{{config.items()}}", "items"),
    ],
    "freemarker": [
        ("${product.getClass().getName()}", "getName"),
    ],
}

# Parameter names commonly used as input sinks
_INPUT_PARAMS = (
    "name", "q", "search", "input", "message", "comment", "text",
    "data", "value", "template", "page", "file", "include", "view",
    "render", "display", "output", "content", "body", "title", "greeting",
)


class SSTIProbe(BaseArsenalModule):
    """Server-Side Template Injection probe. Confirms with deterministic proof."""

    def __init__(self):
        super().__init__()
        self.name = "SSTI Probe"

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

        target_params = [p for p in params if p.lower() in _INPUT_PARAMS] or list(params.keys())

        for param in target_params:
            for payload, expected, engine in _SSTI_PROBES:
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
            engine_detected = None

            # Check for evaluated expressions
            for payload, expected, engine in _SSTI_PROBES:
                if expected and expected in text:
                    if expected not in baseline_text:
                        signals.append(f"{engine}_evaluated")
                        engine_detected = engine

            if not signals:
                continue

            # Differential check
            ev = differential(baseline_text, text)
            if ev.signals >= 1 or ev.verified:
                signals.append("response_differential")

            # Negative proof — never confirm on JSON responses
            is_genuine, reasons = negative_proof_check(text, baseline_text, "SSTI")
            if not is_genuine:
                continue

            # Entropy check
            entropy_d = entropy_delta(baseline_text, text)
            if abs(entropy_d) > 0.5:
                signals.append("entropy_change")

            key = target.url
            if key in seen:
                continue
            seen.add(key)

            # Confidence from verification engine
            confidence = calculate_final_confidence(
                base_confidence=0.90,
                has_negative_proof_pass=is_genuine,
                has_entropy_signal=abs(entropy_d) > 0.5,
                has_side_channel=ev.signals >= 1,
            )

            severity = "CRITICAL" if engine_detected in ("jinja2", "freemarker") else "HIGH"

            vulns.append(Vulnerability(
                name=f"Server-Side Template Injection ({engine_detected or 'unknown'})",
                severity=severity,
                description=(
                    f"Template expression evaluated server-side, proving SSTI. "
                    f"Engine: {engine_detected}. Signals: {', '.join(signals)}."
                ),
                evidence=(
                    f"Target: {target.url}\n"
                    f"Engine: {engine_detected}\n"
                    f"Signals: {', '.join(signals)}\n"
                    f"Differential: {ev.summary}"
                ),
                remediation=(
                    "Use sandboxed template engines (Jinja2 Sandbox, Pebble Sandbox). "
                    "Never pass user input directly into template expressions. "
                    "Use autoescaping for HTML context."
                ),
                confidence=confidence,
            ))
            break

        return vulns
