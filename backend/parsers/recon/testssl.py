"""Parser for testssl.sh JSON output (--jsonfile).

testssl emits a flat JSON array of findings:
  [{"id":"BEAST","severity":"LOW","finding":"...","ip":"host/1.2.3.4"}, ...]
Only findings at MEDIUM or above become vulnerability candidates; everything
else is captured as a TLS attribute on the host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_file

if TYPE_CHECKING:
    from pathlib import Path

_RISK = {"CRITICAL", "HIGH", "MEDIUM"}


def parse_testssl_json(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    data = safe_json_file(path)
    findings = data if isinstance(data, list) else data.get("scanResult", []) if isinstance(data, dict) else []
    seen: set[str] = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id", "")).strip()
        sev = str(f.get("severity", "")).strip().upper()
        target = str(f.get("ip", f.get("host", ""))).strip()
        finding = str(f.get("finding", ""))
        if not fid:
            continue
        if sev in _RISK:
            key = f"{target}:{fid}"
            if key in seen:
                continue
            seen.add(key)
            entities.append(
                ParsedEntity(
                    kind="vulnerability_candidate",
                    label=f"{fid} ({target})",
                    confidence=0.75,
                    properties={
                        "tls_check": fid,
                        "severity": sev,
                        "finding": finding,
                        "host": target,
                        "source": "testssl",
                    },
                    source_tool="testssl",
                    phase="dns_infrastructure",
                )
            )
    return entities
