"""Parser for cdncheck JSONL output.

cdncheck emits one JSON object per host with CDN/WAF/cloud classification:
  {"input":"host","ip":"1.2.3.4","cdn":true,"cdn_name":"cloudflare",
   "waf":true,"waf_name":"cloudflare","cloud":false}
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_lines, safe_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_cdncheck_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        host = str(row.get("input", row.get("host", ""))).strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        is_cdn = bool(row.get("cdn", False))
        is_waf = bool(row.get("waf", False))
        is_cloud = bool(row.get("cloud", False))
        entities.append(
            ParsedEntity(
                kind="cdn_classification",
                label=host,
                confidence=0.9,
                properties={
                    "ip": str(row.get("ip", "")),
                    "cdn": is_cdn,
                    "cdn_name": str(row.get("cdn_name", "")),
                    "waf": is_waf,
                    "waf_name": str(row.get("waf_name", "")),
                    "cloud": is_cloud,
                    "cloud_name": str(row.get("cloud_name", "")),
                    "behind_edge": is_cdn or is_waf,
                },
                source_tool="cdncheck",
                phase="dns_infrastructure",
            )
        )
    # Fallback: plain "host [cdn] [name]" lines
    if not entities:
        for line in safe_lines(path):
            host = line.split("[")[0].strip().lower()
            if host and host not in seen:
                seen.add(host)
                entities.append(
                    ParsedEntity(
                        kind="cdn_classification",
                        label=host,
                        confidence=0.7,
                        properties={"raw": line, "behind_edge": "[" in line},
                        source_tool="cdncheck",
                        phase="dns_infrastructure",
                    )
                )
    return entities
