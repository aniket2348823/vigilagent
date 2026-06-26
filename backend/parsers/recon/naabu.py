"""Parser for naabu JSONL output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_lines, safe_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_naabu_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()

    # Try JSONL first
    for row in safe_json_lines(path):
        host = str(row.get("host", row.get("ip", ""))).strip()
        port = int(row.get("port", 0) or 0)
        if not host or not port:
            continue
        key = f"{host}:{port}"
        if key in seen:
            continue
        seen.add(key)
        protocol = str(row.get("protocol", row.get("scheme", "tcp")))
        entities.append(
            ParsedEntity(
                kind="open_port",
                label=key,
                confidence=0.95,
                properties={"host": host, "port": port, "protocol": protocol, "tls": bool(row.get("tls", False))},
                source_tool="naabu",
                phase="dns_infrastructure",
            )
        )

    # Fallback to line-based output (host:port)
    if not entities:
        for line in safe_lines(path):
            parts = line.strip().rsplit(":", 1)
            if len(parts) == 2:
                host, port_str = parts
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                key = f"{host}:{port}"
                if key in seen:
                    continue
                seen.add(key)
                entities.append(
                    ParsedEntity(
                        kind="open_port",
                        label=key,
                        confidence=0.9,
                        properties={"host": host, "port": port, "protocol": "tcp"},
                        source_tool="naabu",
                        phase="dns_infrastructure",
                    )
                )
    return entities
