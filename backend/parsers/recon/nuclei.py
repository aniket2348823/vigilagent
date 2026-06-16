"""Parser for Nuclei JSONL output."""
from __future__ import annotations
from pathlib import Path
from backend.parsers.recon.base import ParsedEntity, safe_json_lines


def parse_nuclei_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        template_id = str(row.get("template-id", row.get("templateID", "")))
        matched = str(row.get("matched-at", row.get("matched", row.get("host", ""))))
        severity = str(row.get("info", {}).get("severity", row.get("severity", "info"))).lower()
        name = str(row.get("info", {}).get("name", row.get("name", template_id)))
        tags = row.get("info", {}).get("tags", row.get("tags", []))
        if isinstance(tags, str): tags = [t.strip() for t in tags.split(",")]
        matcher_name = str(row.get("matcher-name", row.get("matcher_name", "")))
        extracted = row.get("extracted-results", row.get("extracted_results", []))
        curl_cmd = str(row.get("curl-command", ""))
        _type = str(row.get("type", "http"))
        ip = str(row.get("ip", ""))
        timestamp = str(row.get("timestamp", ""))
        interaction = row.get("interaction", {})

        key = f"{template_id}:{matched}:{matcher_name}"
        if key in seen: continue
        seen.add(key)

        props = {"template_id": template_id, "matched_at": matched, "severity": severity,
                 "name": name, "tags": tags, "matcher_name": matcher_name,
                 "extracted_results": extracted, "curl_command": curl_cmd,
                 "type": _type, "ip": ip, "timestamp": timestamp}
        if interaction:
            props["oob_protocol"] = str(interaction.get("protocol", ""))
            props["oob_full_id"] = str(interaction.get("full-id", ""))
            props["oob_type"] = str(interaction.get("type", ""))

        kind = "vulnerability_candidate"
        if severity in ("critical", "high"): conf = 0.9
        elif severity == "medium": conf = 0.75
        elif severity == "low": conf = 0.6
        else: conf = 0.5

        entities.append(ParsedEntity(kind=kind, label=f"nuclei:{template_id}:{matched}",
            confidence=conf, properties=props, source_tool="nuclei", phase="template_validation"))
    return entities

class NucleiParser:
    """Parser wrapper for backward compatibility."""
    @staticmethod
    def parse_nuclei_jsonl(*args, **kwargs):
        return parse_nuclei_jsonl(*args, **kwargs)

