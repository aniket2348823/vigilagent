"""Parser for arjun JSON output (-oJ).

arjun emits a JSON object keyed by URL:
  {"http://host/api": {"params":["id","token"], "method":"GET"}}
or a list-of-params variant depending on version.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path


def parse_arjun_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    if not isinstance(data, dict):
        return entities
    seen: set[str] = set()
    for url, info in data.items():
        params: list[str] = []
        method = "GET"
        if isinstance(info, dict):
            params = info.get("params", []) or []
            method = str(info.get("method", "GET"))
        elif isinstance(info, list):
            params = info
        host = (urlparse(url).hostname or "").lower()
        for p in params:
            key = f"{url}:{p}"
            if key in seen:
                continue
            seen.add(key)
            entities.append(
                ParsedEntity(
                    kind="parameter",
                    label=str(p),
                    confidence=0.8,
                    properties={
                        "url": url,
                        "host": host,
                        "method": method,
                        "location": "query",
                        "discovered_via": "arjun",
                    },
                    source_tool="arjun",
                    phase="http_browser_intelligence",
                )
            )
    return entities
