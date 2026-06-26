"""Parser for httpx JSONL output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, safe_json_lines

if TYPE_CHECKING:
    from pathlib import Path


def parse_httpx_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for row in safe_json_lines(path):
        url = str(row.get("url", row.get("input", ""))).strip()
        if not url or url in seen:
            continue
        seen.add(url)
        status = int(row.get("status_code", row.get("status-code", 0)) or 0)
        title = str(row.get("title", ""))
        tech = row.get("tech", row.get("technologies", []))
        if isinstance(tech, str):
            tech = [tech]
        server = str(row.get("webserver", row.get("server", "")))
        ct = str(row.get("content_type", row.get("content-type", "")))
        cl = int(row.get("content_length", row.get("content-length", 0)) or 0)
        resp_time = str(row.get("response_time", row.get("time", "")))
        location = str(row.get("location", ""))
        favicon_hash = str(row.get("favicon", row.get("favicon-hash", "")))
        cnames = row.get("cname", row.get("cnames", []))
        if isinstance(cnames, str):
            cnames = [cnames]
        host = str(row.get("host", row.get("input", "")))
        method = str(row.get("method", "GET")).upper()
        scheme = str(row.get("scheme", ""))
        tls_data = row.get("tls", row.get("tls-grab", {}))
        jarm = str(row.get("jarm", ""))
        cdn_name = str(row.get("cdn_name", row.get("cdn-name", "")))
        cdn_type = str(row.get("cdn_type", row.get("cdn-type", "")))

        props = {
            "status_code": status,
            "title": title,
            "technologies": tech,
            "server": server,
            "content_type": ct,
            "content_length": cl,
            "response_time": resp_time,
            "location": location,
            "favicon_hash": favicon_hash,
            "cnames": cnames,
            "host": host,
            "method": method,
            "scheme": scheme,
            "jarm": jarm,
            "cdn_name": cdn_name,
            "cdn_type": cdn_type,
        }
        if isinstance(tls_data, dict) and tls_data:
            props["tls_version"] = str(tls_data.get("version", ""))
            props["tls_cipher"] = str(tls_data.get("cipher", ""))
            props["tls_issuer"] = str(tls_data.get("issuer_org", tls_data.get("issuer", "")))
            props["tls_subject_cn"] = str(tls_data.get("subject_cn", ""))
            props["tls_san"] = tls_data.get("subject_an", tls_data.get("san", []))

        # Headers extraction
        headers = row.get("header", row.get("headers", {}))
        if isinstance(headers, dict):
            sec_headers = {}
            for h in [
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "x-xss-protection",
                "permissions-policy",
            ]:
                if h in headers:
                    sec_headers[h] = headers[h]
            props["security_headers"] = sec_headers
            props["missing_security_headers"] = [
                h
                for h in [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                ]
                if h not in headers
            ]

        entities.append(
            ParsedEntity(
                kind="http_service",
                label=url,
                confidence=0.95,
                properties=props,
                source_tool="httpx",
                phase="http_browser_intelligence",
            )
        )

        if favicon_hash and favicon_hash != "0":
            entities.append(
                ParsedEntity(
                    kind="favicon",
                    label=favicon_hash,
                    confidence=0.7,
                    properties={"url": url, "hash": favicon_hash},
                    source_tool="httpx",
                    phase="http_browser_intelligence",
                )
            )

    return entities
