"""Parser for SecretFinder output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, redact_secret, safe_lines

if TYPE_CHECKING:
    from pathlib import Path

_SECRET_PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[bpors]-[0-9a-zA-Z]{10,}"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[ps]_[0-9a-zA-Z]{36}"),
    "heroku_api": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "generic_secret": re.compile(
        r'(?:secret|password|token|api_key|apikey|auth)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{16,})', re.I
    ),
}

# Native SecretFinder ``[TYPE] value`` line format — hoisted to module scope.
_SF_NATIVE_RE = re.compile(r"\[([^\]]+)\]\s*(.*)")


def parse_secretfinder_output(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        line = line.strip()
        if not line:
            continue
        for secret_type, pattern in _SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                value = match.group(0)
                key = f"{secret_type}:{value[:20]}"
                if key in seen:
                    continue
                seen.add(key)
                entities.append(
                    ParsedEntity(
                        kind="secret",
                        label=f"secret:{secret_type}",
                        confidence=0.85,
                        properties={
                            "secret_type": secret_type,
                            "redacted_value": redact_secret(value),
                            "source_line": line[:200],
                            "line_number": 0,
                        },
                        source_tool="secretfinder",
                        phase="http_browser_intelligence",
                    )
                )
                break
        else:
            # SecretFinder native output format: [TYPE] value
            m = _SF_NATIVE_RE.match(line)
            if m:
                stype = m.group(1).strip()
                val = m.group(2).strip()
                key = f"{stype}:{val[:20]}"
                if key in seen:
                    continue
                seen.add(key)
                entities.append(
                    ParsedEntity(
                        kind="secret",
                        label=f"secret:{stype}",
                        confidence=0.75,
                        properties={
                            "secret_type": stype,
                            "redacted_value": redact_secret(val),
                            "source_line": line[:200],
                        },
                        source_tool="secretfinder",
                        phase="http_browser_intelligence",
                    )
                )
    return entities
