"""Parser for ffuf JSON output."""
from __future__ import annotations
import json
from pathlib import Path
from backend.parsers.recon.base import ParsedEntity, safe_json_file, safe_json_lines


def parse_ffuf_json(path: Path | str) -> list[ParsedEntity]:
    """Parse ffuf output. Handles BOTH the canonical JSON file (-o ...json)
    where ffuf writes ``{"results":[...]}`` and the JSON-Lines stream that
    ``-json`` emits to stdout (one record per line). Many real runs end up
    writing JSONL to the stdout artifact when ffuf exits via -maxtime, so the
    parser falls back to per-line parsing if the whole-file JSON load returns
    nothing useful."""
    entities: list[ParsedEntity] = []
    p = Path(path)
    if not p.exists():
        return entities
    data = safe_json_file(p)
    results: list[dict] = []
    if isinstance(data, dict):
        results = data.get("results", []) or []
    elif isinstance(data, list):
        results = data
    if not results:
        # Stream of JSONL records (ffuf -json on stdout) — yield each obj.
        for row in safe_json_lines(p):
            if isinstance(row, dict) and (row.get("url") or row.get("input")):
                results.append(row)
    seen: set[str] = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url", r.get("input", {}).get("FUZZ", "") if isinstance(r.get("input"), dict) else ""))
        if not url or url in seen: continue
        seen.add(url)
        status = int(r.get("status", 0) or 0)
        length = int(r.get("length", 0) or 0)
        words = int(r.get("words", 0) or 0)
        lines = int(r.get("lines", 0) or 0)
        redir = str(r.get("redirectlocation", ""))
        ct = str(r.get("content-type", r.get("content_type", "")))
        duration = r.get("duration", 0)
        host = str(r.get("host", ""))
        fuzz_input = str(r.get("input", {}).get("FUZZ", "")) if isinstance(r.get("input"), dict) else ""
        entities.append(ParsedEntity(kind="discovered_path", label=url, confidence=0.85,
            properties={"status_code": status, "content_length": length, "words": words,
                         "lines": lines, "redirect": redir, "content_type": ct,
                         "duration_ns": duration, "host": host, "fuzz_input": fuzz_input},
            source_tool="ffuf", phase="directory_route_discovery"))
    return entities

class FfufParser:
    """Parser wrapper for backward compatibility."""
    @staticmethod
    def parse_ffuf_json(*args, **kwargs):
        return parse_ffuf_json(*args, **kwargs)

