"""Parser for tlsx JSONL output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_tlsx_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        host = str(row.get("host", row.get("address", ""))).strip()
        port = int(row.get("port", 443) or 443)
        if not host:
            continue
        # FIX: Include serial in dedup key to preserve multiple certs per host (SNI)
        serial = str(row.get("serial", ""))
        key = f"{host}:{port}:{serial}" if serial else f"{host}:{port}"
        if key in seen:
            continue
        seen.add(key)

        san = row.get("san", row.get("subject_an", []))
        if isinstance(san, str):
            san = [san]
        issuer = str(row.get("issuer_org", row.get("issuer_cn", row.get("issuer", ""))))
        subject = str(row.get("subject_cn", row.get("subject", "")))
        version = str(row.get("version", row.get("tls_version", "")))
        cipher = str(row.get("cipher", ""))
        expired = bool(row.get("expired", False))
        self_signed = bool(row.get("self_signed", False))
        mismatched = bool(row.get("mismatched", False))
        not_before = str(row.get("not_before", ""))
        not_after = str(row.get("not_after", ""))
        serial = str(row.get("serial", ""))
        fingerprint = str(row.get("fingerprint_hash", row.get("hash", {}).get("sha256", "")))
        jarm = str(row.get("jarm_hash", row.get("jarm", "")))
        wildcard = bool(row.get("wildcard_certificate", any("*" in s for s in san)))

        props = {
            "host": host,
            "port": port,
            "san": san,
            "issuer": issuer,
            "subject_cn": subject,
            "tls_version": version,
            "cipher": cipher,
            "expired": expired,
            "self_signed": self_signed,
            "mismatched": mismatched,
            "not_before": not_before,
            "not_after": not_after,
            "serial": serial,
            "fingerprint_sha256": fingerprint,
            "jarm": jarm,
            "wildcard": wildcard,
        }

        conf = 0.95
        if expired or self_signed or mismatched:
            conf = 0.5

        entities.append(
            ParsedEntity(
                kind="certificate",
                label=key,
                confidence=conf,
                properties=props,
                source_tool="tlsx",
                phase="dns_infrastructure",
            )
        )

        # Emit SAN domains as subdomains
        for name in san:
            name = name.strip().lower().lstrip("*.")
            if name and name not in seen:
                seen.add(name)
                entities.append(
                    ParsedEntity(
                        kind="subdomain",
                        label=name,
                        confidence=0.8,
                        properties={"discovered_via": "tls_san", "cert_host": host},
                        source_tool="tlsx",
                        phase="dns_infrastructure",
                    )
                )

        if expired:
            entities.append(
                ParsedEntity(
                    kind="vulnerability_candidate",
                    label=f"expired_cert:{host}:{port}",
                    confidence=0.7,
                    properties={"vuln_type": "expired_certificate", "host": host, "not_after": not_after},
                    source_tool="tlsx",
                    phase="dns_infrastructure",
                )
            )
        if self_signed:
            entities.append(
                ParsedEntity(
                    kind="vulnerability_candidate",
                    label=f"self_signed:{host}:{port}",
                    confidence=0.6,
                    properties={"vuln_type": "self_signed_certificate", "host": host},
                    source_tool="tlsx",
                    phase="dns_infrastructure",
                )
            )
    return entities
