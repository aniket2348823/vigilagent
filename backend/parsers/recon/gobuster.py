"""Parser for gobuster line output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_lines

if TYPE_CHECKING:
    from pathlib import Path

# Hoisted to module scope so we don't recompile on every input line.
_GOBUSTER_LINE_RE = re.compile(r"^(https?://\S+|/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)])?")


def parse_gobuster_lines(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        # Gobuster format: /path (Status: 200) [Size: 1234]
        m = _GOBUSTER_LINE_RE.match(line)
        if m:
            url = m.group(1)
            status = int(m.group(2))
            size = int(m.group(3) or 0)
        else:
            # Simple URL per line
            url = line.split()[0] if line.split() else ""
            status = 0
            size = 0
        if not url or url in seen:
            continue
        seen.add(url)
        entities.append(
            ParsedEntity(
                kind="discovered_path",
                label=url,
                confidence=0.8,
                properties={"status_code": status, "content_length": size},
                source_tool="gobuster",
                phase="directory_route_discovery",
            )
        )
    return entities
