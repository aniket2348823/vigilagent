"""Parser for wafw00f JSON output (-o file -f json).

wafw00f emits a JSON array:
  [{"url":"http://host","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare"}]
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path


def parse_wafw00f_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url", "")).strip()
        if not url or url in seen:
            continue
        seen.add(url)
        detected = bool(row.get("detected", False))
        firewall = str(row.get("firewall", "")) if detected else ""
        host = (urlparse(url).hostname or "").lower()
        entities.append(
            ParsedEntity(
                kind="waf_detection",
                label=url,
                confidence=0.85,
                properties={
                    "host": host,
                    "detected": detected,
                    "firewall": firewall,
                    "manufacturer": str(row.get("manufacturer", "")),
                    "behind_waf": detected,
                },
                source_tool="wafw00f",
                phase="http_browser_intelligence",
            )
        )
    return entities
