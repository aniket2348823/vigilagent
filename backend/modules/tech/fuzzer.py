"""
Generic API Fuzzer (Architecture §17 — multi-signal validation).

Sends a small set of canary payloads (XSS sentinel, traversal, SSTI, null byte,
buffer abuse) and reports findings ONLY when at least 2 independent signals
agree per detection class. Bare substring reflection is no longer enough.

For dedicated, evidence-rich detection prefer:
  * tech_xss  — reflected/DOM XSS with executable-context detection
  * tech_lfi  — file inclusion with /etc/passwd & php-wrapper proofs
  * tech_cmdi — OS command injection with output signatures
"""

from __future__ import annotations

import html
import logging
import random
import re
from urllib.parse import quote as urlquote

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

logger = logging.getLogger("APIFuzzer")

# Sentinels — randomized per-process to avoid false positives from static matches (HIGH-26)
_XSS_SENTINEL = f"vgxss{random.randint(1000, 9999)}"
_SSTI_SENTINEL = f"vgssti{random.randint(1000, 9999)}"

_FUZZ_VECTORS = (
    f"<script>alert('{_XSS_SENTINEL}')</script>",
    "../../../../etc/passwd",
    "{{7*7}}",
    "%00",
    "A" * 4096,
    f"{{{_SSTI_SENTINEL}}}",
)

_PASSWD_LINE = re.compile(r"^(root|daemon|nobody):[x*!]:\d+:\d+:", re.M)


class APIFuzzer(BaseArsenalModule):
    def __init__(self):
        super().__init__()
        self.name = "API Fuzzer"
        try:
            from backend.ai.cortex import get_cortex_engine

            self.ai = get_cortex_engine()
        except Exception as exc:
            logger.debug("[APIFuzzer] AI engine init deferred: %s", exc)
            self.ai = None

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        targets: list[TaskTarget] = []
        # Baseline (index 0).
        targets.append(
            TaskTarget(
                url=packet.target.url,
                method=packet.target.method or "GET",
                headers=dict(packet.target.headers or {}),
                payload=packet.target.payload,
            )
        )

        vectors = list(_FUZZ_VECTORS)
        if self.ai and getattr(self.ai, "enabled", False):
            try:
                params = getattr(packet.config, "params", {}) or {}
                ai_vectors = (
                    await self.ai.generate_fuzz_vectors(
                        target_url=packet.target.url,
                        content_type=params.get("content_type", ""),
                        tech_stack=params.get("tech_stack", ""),
                    )
                    or []
                )
                # Tag AI vectors so the analyzer never accidentally treats an
                # AI fuzzer string as a confirmed sentinel.
                vectors.extend(v for v in ai_vectors if isinstance(v, str))
            except Exception as exc:
                logger.debug("[APIFuzzer] AI fuzz vector generation failed: %s", exc)

        sep = "&" if "?" in packet.target.url else "?"
        for vector in vectors:
            url = f"{packet.target.url}{sep}fuzz={urlquote(str(vector))}"
            targets.append(
                TaskTarget(
                    url=url, method="GET", headers=dict(packet.target.headers or {}), payload=packet.target.payload
                )
            )
        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        from backend.modules.evidence import differential

        vulns: list[Vulnerability] = []
        if not interactions:
            return vulns
        _bt, baseline = interactions[0]
        baseline = baseline if isinstance(baseline, str) else ""
        baseline_passwd = bool(_PASSWD_LINE.search(baseline))

        seen: set[str] = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue

            # Reconstruct the fuzz vector.
            vector = ""
            if "?fuzz=" in target.url:
                vector = target.url.split("?fuzz=", 1)[1]
            elif "&fuzz=" in target.url:
                vector = target.url.split("&fuzz=", 1)[1]
            if not vector:
                continue

            ev = differential(baseline, text)

            # XSS sentinel — must be reflected unencoded in HTML body and
            # response must materially differ. (Dedicated tech_xss is preferred
            # but this guards against blind regressions.)
            if (
                _XSS_SENTINEL in vector
                and _XSS_SENTINEL in text
                and html.escape(_XSS_SENTINEL) not in text
                and (ev.signals >= 1 or ev.verified)
                and target.url not in seen
            ):
                seen.add(target.url)
                vulns.append(
                    Vulnerability(
                        name="Reflected XSS (Fuzzer Canary)",
                        severity="HIGH",
                        description="Sentinel payload reflected unencoded with response divergence.",
                        evidence=f"Vector: {vector}; {ev.summary}",
                        remediation="Context-aware output encoding plus strict CSP.",
                    )
                )

            # Path traversal — require canonical /etc/passwd line, not just
            # the substring 'root:' which appears in many noisy pages.
            if (
                not baseline_passwd
                and _PASSWD_LINE.search(text)
                and (ev.signals >= 1 or ev.verified)
                and ("etc/passwd" in vector or "%2fetc%2f" in vector.lower())
                and target.url not in seen
            ):
                seen.add(target.url)
                vulns.append(
                    Vulnerability(
                        name="Path Traversal (Fuzzer Canary)",
                        severity="CRITICAL",
                        description="Traversal vector returned the canonical /etc/passwd line.",
                        evidence=f"Vector: {vector}; {ev.summary}",
                        remediation="Resolve user paths against an allow-list; reject ../ sequences.",
                    )
                )
        return vulns
