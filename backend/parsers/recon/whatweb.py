"""Parser for whatweb JSON output (--log-json).

whatweb emits a JSON array, one object per target:
  [{"target":"http://host","http_status":200,"plugins":{"Apache":{"version":["2.4"]},...}}]
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path


def parse_whatweb_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        target = str(row.get("target", "")).strip()
        if not target or target in seen:
            continue
        seen.add(target)
        plugins = row.get("plugins", {}) or {}
        technologies = sorted(plugins.keys()) if isinstance(plugins, dict) else []
        host = (urlparse(target).hostname or "").lower()
        entities.append(
            ParsedEntity(
                kind="technology",
                label=target,
                confidence=0.8,
                properties={
                    "host": host,
                    "http_status": row.get("http_status", 0),
                    "technologies": technologies,
                    "technology_count": len(technologies),
                },
                source_tool="whatweb",
                phase="http_browser_intelligence",
            )
        )
    return entities
