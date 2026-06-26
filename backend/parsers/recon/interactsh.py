"""Parser for Interactsh JSONL output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_interactsh_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        uid = str(row.get("unique-id", row.get("correlation-id", row.get("full-id", ""))))
        protocol = str(row.get("protocol", "unknown"))
        raddr = str(row.get("remote-address", ""))
        raw_req = str(row.get("raw-request", ""))[:2000]
        raw_resp = str(row.get("raw-response", ""))[:2000]
        timestamp = str(row.get("timestamp", ""))
        qtype = str(row.get("q-type", ""))
        key = f"{uid}:{protocol}:{raddr}"
        if key in seen:
            continue
        seen.add(key)
        entities.append(
            ParsedEntity(
                kind="oob_interaction",
                label=f"oob:{protocol}:{uid[:20]}",
                confidence=0.9,
                properties={
                    "unique_id": uid,
                    "protocol": protocol,
                    "remote_address": raddr,
                    "raw_request_preview": raw_req[:500],
                    "raw_response_preview": raw_resp[:500],
                    "timestamp": timestamp,
                    "q_type": qtype,
                },
                source_tool="interactsh",
                phase="template_validation",
            )
        )
    return entities
