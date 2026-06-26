"""
Parser for Subfinder JSONL output.

Subfinder emits one JSON object per line with fields like:
  {"host": "sub.example.com", "source": "certspotter", "ip": "1.2.3.4"}
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, is_ip_address, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_subfinder_jsonl(path: Path | str) -> list[ParsedEntity]:
    """Parse subfinder -json output into normalized subdomain entities."""
    entities: list[ParsedEntity] = []
    seen: set[str] = set()

    for row in safe_json_lines(path):
        host = str(row.get("host", "")).strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)

        source = str(row.get("source", row.get("sources", "subfinder")))
        ip = str(row.get("ip", row.get("input", "")))

        props: dict = {
            "source_engine": source,
            "input": str(row.get("input", "")),
        }
        if ip and is_ip_address(ip):
            props["resolved_ip"] = ip

        entities.append(
            ParsedEntity(
                kind="subdomain",
                label=host,
                confidence=0.85,
                properties=props,
                source_tool="subfinder",
                phase="passive_intelligence",
            )
        )

        # If we got an IP resolution, also emit an IP entity
        if ip and is_ip_address(ip) and ip not in seen:
            seen.add(ip)
            entities.append(
                ParsedEntity(
                    kind="ip",
                    label=ip,
                    confidence=0.8,
                    properties={"resolved_from": host, "source_engine": source},
                    source_tool="subfinder",
                    phase="passive_intelligence",
                )
            )

    return entities
