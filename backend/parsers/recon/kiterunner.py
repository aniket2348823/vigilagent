"""Parser for Kiterunner line output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_lines

if TYPE_CHECKING:
    from pathlib import Path

# Hoisted to module scope so we don't recompile on every input line.
_KITE_LINE_RE = re.compile(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\d+)\s+\[\s*(\d+)[^\]]*\]\s+(https?://\S+)")


def parse_kiterunner_lines(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        # Kiterunner: METHOD STATUS_CODE LENGTH URL
        m = _KITE_LINE_RE.match(line)
        if m:
            method, status, length, url = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
        else:
            parts = line.split()
            if len(parts) >= 2 and parts[-1].startswith("http"):
                url = parts[-1]
                method = "GET"
                status = 0
                length = 0
            else:
                continue
        if url in seen:
            continue
        seen.add(url)
        entities.append(
            ParsedEntity(
                kind="api_route",
                label=url,
                confidence=0.85,
                properties={"method": method, "status_code": status, "content_length": length},
                source_tool="kiterunner",
                phase="api_reconnaissance",
            )
        )
    return entities
