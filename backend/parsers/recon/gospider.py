"""Parser for gospider JSONL output (--json).

gospider emits one JSON object per discovered item:
  {"input":"http://host","source":"href","output":"http://host/path","type":"url","status":200}
"""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse

from backend.parsers.recon.base import ParsedEntity, safe_json_lines


def parse_gospider_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        url = str(row.get("output", row.get("url", ""))).strip()
        if not url.startswith(("http://", "https://")):
            continue
        # FIX: Normalize URL to prevent duplicates from casing/trailing slashes
        url = url.lower().rstrip("/")
        if url in seen:
            continue
        seen.add(url)
        item_type = str(row.get("type", "url")).lower()
        is_js = url.lower().endswith((".js", ".mjs")) or item_type == "javascript"
        kind = "js_file" if is_js else "crawled_endpoint"
        parsed = urlparse(url)
        entities.append(ParsedEntity(
            kind=kind, label=url, confidence=0.78,
            properties={"path": parsed.path or "/", "host": (parsed.hostname or "").lower(),
                        "source": str(row.get("source", "")), "type": item_type,
                        "status": row.get("status", 0)},
            source_tool="gospider", phase="http_browser_intelligence"))
    return entities
