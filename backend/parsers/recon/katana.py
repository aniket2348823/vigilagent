"""Parser for katana JSONL output."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlparse

from backend.parsers.recon.base import ParsedEntity, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_katana_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        req = row.get("request", {}) if isinstance(row.get("request"), dict) else {}
        url = str(row.get("endpoint") or row.get("url") or req.get("endpoint") or req.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        source_url = str(row.get("source", "") or req.get("source", ""))
        method = str(row.get("method") or req.get("method") or "GET").upper()
        tag = str(row.get("tag", ""))
        attr = str(row.get("attribute", ""))
        status = int(row.get("status_code", row.get("response", {}).get("status_code", 0)) or 0)
        body = str(row.get("body", row.get("response", {}).get("body", "")))[:500]
        params = [{"name": n, "value": v} for n, v in parse_qsl(parsed.query, keep_blank_values=True)]

        props = {
            "full_url": url,
            "source_url": source_url,
            "method": method,
            "tag": tag,
            "attribute": attr,
            "path": parsed.path or "/",
            "host": (parsed.hostname or "").lower(),
            "status_code": status,
            "parameters": params,
            "body_preview": body,
        }

        entities.append(
            ParsedEntity(
                kind="crawled_endpoint",
                label=url,
                confidence=0.85,
                properties=props,
                source_tool="katana",
                phase="http_browser_intelligence",
            )
        )

        if url.lower().endswith(".js") or tag == "script":
            entities.append(
                ParsedEntity(
                    kind="js_file",
                    label=url,
                    confidence=0.9,
                    properties={"source_page": source_url},
                    source_tool="katana",
                    phase="http_browser_intelligence",
                )
            )
    return entities
