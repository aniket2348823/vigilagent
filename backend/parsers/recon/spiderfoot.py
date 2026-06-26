"""Parser for SpiderFoot JSON/CSV output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path


def parse_spiderfoot_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    results = (
        data if isinstance(data, list) else data.get("results", data.get("data", [])) if isinstance(data, dict) else []
    )
    seen: set[str] = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        etype = str(r.get("type", r.get("event_type", "")))
        edata = str(r.get("data", r.get("event_data", "")))
        module = str(r.get("module", r.get("source_module", "")))
        if not edata:
            continue
        key = f"{etype}:{edata[:100]}"
        if key in seen:
            continue
        seen.add(key)
        kind_map = {
            "INTERNET_NAME": "subdomain",
            "IP_ADDRESS": "ip",
            "EMAILADDR": "email",
            "TCP_PORT_OPEN": "open_port",
            "WEBSERVER_TECHNOLOGY": "technology",
            "URL_FORM": "endpoint",
            "URL_JAVASCRIPT": "js_file",
        }
        kind = kind_map.get(etype, "osint_finding")
        entities.append(
            ParsedEntity(
                kind=kind,
                label=edata[:500],
                confidence=0.7,
                properties={"spiderfoot_type": etype, "module": module},
                source_tool="spiderfoot",
                phase="passive_intelligence",
            )
        )
    return entities
