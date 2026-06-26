"""Parser for httprobe line output (one live URL per line)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from backend.parsers.recon.base import ParsedEntity, safe_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_httprobe_lines(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        url = line.strip()
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        entities.append(
            ParsedEntity(
                kind="live_host",
                label=url,
                confidence=0.85,
                properties={
                    "host": (parsed.hostname or "").lower(),
                    "scheme": parsed.scheme,
                    "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                },
                source_tool="httprobe",
                phase="http_browser_intelligence",
            )
        )
    return entities
