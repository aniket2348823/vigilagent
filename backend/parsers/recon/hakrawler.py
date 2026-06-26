"""Parser for hakrawler line output."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from backend.parsers.recon.base import ParsedEntity, safe_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_hakrawler_lines(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        url = line.strip()
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        is_js = url.lower().endswith((".js", ".mjs"))
        kind = "js_file" if is_js else "crawled_endpoint"
        entities.append(
            ParsedEntity(
                kind=kind,
                label=url,
                confidence=0.8,
                properties={"path": parsed.path or "/", "host": (parsed.hostname or "").lower()},
                source_tool="hakrawler",
                phase="http_browser_intelligence",
            )
        )
    return entities
