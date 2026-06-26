"""
Parser for Amass JSON output.

Amass enum -json produces one JSON object per line with fields:
  {"name": "sub.example.com", "domain": "example.com", "addresses": [{"ip": "1.2.3.4", "cidr": "..."}], "sources": ["CertSpotter"], "tag": "cert"}
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from backend.parsers.recon.base import ParsedEntity, is_ip_address, safe_json_file, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_amass_json(path: Path | str) -> list[ParsedEntity]:
    """Parse amass enum -json output into normalized entities."""
    entities: list[ParsedEntity] = []
    seen_hosts: set[str] = set()
    seen_ips: set[str] = set()

    # Amass can output as JSONL or single JSON file
    rows: list[dict[str, Any]] = []
    data = safe_json_file(path)
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = [data]
    else:
        rows = list(safe_json_lines(path))

    for row in rows:
        name = str(row.get("name", "")).strip().lower()
        domain = str(row.get("domain", "")).strip().lower()
        tag = str(row.get("tag", ""))
        sources = row.get("sources", row.get("source", []))
        if isinstance(sources, str):
            sources = [sources]

        if name and name not in seen_hosts:
            seen_hosts.add(name)
            props: dict[str, Any] = {
                "domain": domain,
                "tag": tag,
                "sources": sources,
            }

            addresses = row.get("addresses", [])
            if isinstance(addresses, list):
                ips = []
                cidrs = []
                for addr in addresses:
                    if isinstance(addr, dict):
                        ip = str(addr.get("ip", ""))
                        cidr = str(addr.get("cidr", ""))
                        asn = addr.get("asn", "")
                        desc = addr.get("desc", "")
                        if ip:
                            ips.append(ip)
                        if cidr:
                            cidrs.append(cidr)
                        if ip and is_ip_address(ip) and ip not in seen_ips:
                            seen_ips.add(ip)
                            entities.append(
                                ParsedEntity(
                                    kind="ip",
                                    label=ip,
                                    confidence=0.85,
                                    properties={
                                        "resolved_from": name,
                                        "cidr": cidr,
                                        "asn": str(asn),
                                        "asn_desc": str(desc),
                                    },
                                    source_tool="amass",
                                    phase="passive_intelligence",
                                )
                            )
                    elif isinstance(addr, str) and is_ip_address(addr):
                        ips.append(addr)
                        if addr not in seen_ips:
                            seen_ips.add(addr)
                            entities.append(
                                ParsedEntity(
                                    kind="ip",
                                    label=addr,
                                    confidence=0.8,
                                    properties={"resolved_from": name},
                                    source_tool="amass",
                                    phase="passive_intelligence",
                                )
                            )
                props["ips"] = ips
                props["cidrs"] = cidrs

            entities.append(
                ParsedEntity(
                    kind="subdomain",
                    label=name,
                    confidence=0.9 if tag == "cert" else 0.85,
                    properties=props,
                    source_tool="amass",
                    phase="passive_intelligence",
                )
            )

    return entities
