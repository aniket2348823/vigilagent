"""Parser for Cloudlist line output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, is_ip_address, safe_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_cloudlist_lines(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        asset = line.strip()
        if not asset or asset in seen:
            continue
        seen.add(asset)
        kind = "ip" if is_ip_address(asset) else "cloud_asset"
        entities.append(
            ParsedEntity(
                kind=kind,
                label=asset,
                confidence=0.8,
                properties={"source": "cloudlist"},
                source_tool="cloudlist",
                phase="passive_intelligence",
            )
        )
    return entities
