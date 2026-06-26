"""Parser for aquatone session JSON output.

aquatone writes aquatone_session.json with a "pages" map:
  {"pages": {"http__host__443": {"url":"https://host","hostname":"host",
     "status":200,"screenshotPath":"screenshots/..png","tags":[...]}}}
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path


def parse_aquatone_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    if not isinstance(data, dict):
        return entities
    pages = data.get("pages", {}) or {}
    items = pages.values() if isinstance(pages, dict) else pages if isinstance(pages, list) else []
    seen: set[str] = set()
    for page in items:
        if not isinstance(page, dict):
            continue
        url = str(page.get("url", "")).strip()
        if not url or url in seen:
            continue
        seen.add(url)
        tags = page.get("tags", []) or []
        tech = [t.get("text", "") for t in tags if isinstance(t, dict)] if tags else []
        entities.append(
            ParsedEntity(
                kind="visual_artifact",
                label=url,
                confidence=0.8,
                properties={
                    "hostname": str(page.get("hostname", "")),
                    "status_code": page.get("status", 0),
                    "screenshot": str(page.get("screenshotPath", "")),
                    "title": str(page.get("pageTitle", "")),
                    "technologies": [t for t in tech if t],
                },
                source_tool="aquatone",
                phase="visual_documentation",
            )
        )
    return entities
