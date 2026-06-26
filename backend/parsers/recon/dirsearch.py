"""Parser for dirsearch JSON output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path


def parse_dirsearch_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    seen: set[str] = set()
    # dirsearch JSON: {"results": [...]} or {url: [{status, ...}]}
    results = []
    if isinstance(data, dict):
        if "results" in data:
            results = data["results"]
        else:
            for url_key, entries in data.items():
                if isinstance(entries, list):
                    for e in entries:
                        if isinstance(e, dict):
                            e.setdefault("url", url_key + e.get("path", ""))
                            results.append(e)
    elif isinstance(data, list):
        results = data

    for r in results:
        url = str(r.get("url", r.get("path", ""))).strip()
        if not url or url in seen:
            continue
        seen.add(url)
        status = int(r.get("status", 0) or 0)
        length = int(r.get("content-length", r.get("content_length", 0)) or 0)
        redir = str(r.get("redirect", r.get("location", "")))
        entities.append(
            ParsedEntity(
                kind="discovered_path",
                label=url,
                confidence=0.8,
                properties={"status_code": status, "content_length": length, "redirect": redir},
                source_tool="dirsearch",
                phase="directory_route_discovery",
            )
        )
    return entities
