"""
Base types and utilities shared by all recon parsers.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse, parse_qsl

# Module-level regex cache — base.is_valid_domain / is_ip_address are called
# from every recon parser per emitted host/IP, so compiling these once shaves
# real time off bulk parses.
# FIX: Require minimum 2 chars per label to reject 'a.com' as valid domain,
# but still accept 2-label domains like example.com
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_IPV6_HEX_RE = re.compile(r'^[0-9a-fA-F:]+$')


@dataclass
class ParsedEntity:
    """Normalized output entity from any parser."""
    kind: str  # subdomain, ip, endpoint, port, service, parameter, secret, cloud_asset, certificate, vulnerability_candidate, oob_interaction, visual_artifact
    label: str
    confidence: float = 0.5
    properties: dict[str, Any] = field(default_factory=dict)
    source_tool: str = ""
    phase: str = ""
    raw_line: str = ""

    @property
    def dedup_key(self) -> str:
        return f"{self.kind}:{self.label}".lower().strip()


def safe_json_lines(path: Path | str) -> Iterator[dict[str, Any]]:
    """Yield each valid JSON object from a JSONL file, skipping bad lines.

    FIX: Uses a streaming file reader instead of read_text().splitlines()
    to avoid loading the entire file into memory. For 100MB+ nmap/nuclei
    outputs this prevents OOM.
    """
    p = Path(path)
    if not p.exists():
        return
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue


def safe_json_file(path: Path | str) -> dict[str, Any] | list[Any]:
    """Read a whole JSON file, returning empty on failure."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return {}


def safe_lines(path: Path | str) -> list[str]:
    """Read non-empty lines from a text file."""
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def extract_host(url_or_host: str) -> str:
    """Extract hostname from a URL or bare hostname."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        return (parsed.hostname or "").lower().strip()
    return url_or_host.lower().strip().split(":")[0].split("/")[0]


def extract_query_params(url: str) -> list[dict[str, str]]:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    params = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        params.append({"name": name, "value": value})
    return params


def is_valid_domain(domain: str) -> bool:
    """Basic domain format validation."""
    return bool(_DOMAIN_RE.match(domain))


def is_ip_address(value: str) -> bool:
    """Check if a string looks like an IPv4 or IPv6 address."""
    # IPv4
    if _IPV4_RE.match(value):
        return True
    # IPv6 simplified
    if ":" in value and _IPV6_HEX_RE.match(value):
        return True
    return False


def redact_secret(value: str, visible_chars: int = 8) -> str:
    """Redact a secret value, keeping first N chars visible."""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)
