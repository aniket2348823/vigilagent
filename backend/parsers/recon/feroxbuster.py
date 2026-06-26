"""Parser for feroxbuster JSONL output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_feroxbuster_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        url = str(row.get("url", "")).strip()
        if not url or url in seen:
            continue
        if row.get("type", "") == "response" or "status" in row:
            seen.add(url)
            status = int(row.get("status", row.get("status_code", 0)) or 0)
            length = int(row.get("content_length", row.get("length", 0)) or 0)
            lines = int(row.get("line_count", row.get("lines", 0)) or 0)
            words = int(row.get("word_count", row.get("words", 0)) or 0)
            method = str(row.get("method", "GET"))
            redir = str(row.get("redirect_url", row.get("location", "")))
            entities.append(
                ParsedEntity(
                    kind="discovered_path",
                    label=url,
                    confidence=0.85,
                    properties={
                        "status_code": status,
                        "content_length": length,
                        "lines": lines,
                        "words": words,
                        "method": method,
                        "redirect": redir,
                    },
                    source_tool="feroxbuster",
                    phase="directory_route_discovery",
                )
            )
    return entities
