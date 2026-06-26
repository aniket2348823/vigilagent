"""Parser for gowitness output.

gowitness v3 emits ``--write-jsonl`` records (one JSON per line). Old gowitness
(< v3) wrote a single JSON array via ``--json``. Handle both forms: prefer
JSONL if the file has multiple lines, fall back to whole-file JSON.
"""

from __future__ import annotations

from pathlib import Path

from backend.parsers.recon.base import ParsedEntity, safe_json_file, safe_json_lines


def parse_gowitness_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return entities
    rows: list[dict] = []
    # JSONL first (gowitness v3+).
    for r in safe_json_lines(p):
        if isinstance(r, dict):
            rows.append(r)
    if not rows:
        data = safe_json_file(p)
        if isinstance(data, list):
            rows = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict):
            rows = [r for r in data.get("results", [data]) if isinstance(r, dict)]
    for r in rows:
        url = str(r.get("url", r.get("final_url", r.get("input_url", ""))))
        if not url:
            continue
        screenshot = str(r.get("filename", r.get("screenshot", r.get("screenshot_path", ""))))
        title = str(r.get("title", r.get("page_title", "")))
        status = int(r.get("response_code", r.get("status_code", r.get("status", 0))) or 0)
        entities.append(
            ParsedEntity(
                kind="visual_artifact",
                label=url,
                confidence=0.9,
                properties={"screenshot_file": screenshot, "title": title, "status_code": status},
                source_tool="gowitness",
                phase="visual_documentation",
            )
        )
    return entities
