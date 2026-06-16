"""Parser for dnsx JSONL output."""
from __future__ import annotations
from pathlib import Path
from backend.parsers.recon.base import ParsedEntity, safe_json_lines, is_ip_address


def parse_dnsx_jsonl(path: Path | str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    seen_ips: set[str] = set()

    for row in safe_json_lines(path):
        host = str(row.get("host", "")).strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)

        a_recs = _lf(row, "a")
        aaaa_recs = _lf(row, "aaaa")
        cname_recs = _lf(row, "cname")
        mx_recs = _lf(row, "mx")
        txt_recs = _lf(row, "txt")

        has_res = bool(a_recs or aaaa_recs)
        # FIX: Dangling CNAME detection now also checks if the CNAME target itself
        # resolves to A/AAAA records. CDNs like Cloudflare return A records directly
        # (not via CNAME), so behind_cdn=True + dangling_cname=True was contradictory.
        cdn_words = {"cloudfront", "cloudflare", "akamai", "fastly", "incapsula"}
        behind_cdn = any(any(c in cn.lower() for c in cdn_words) for cn in cname_recs)
        is_dangling = bool(cname_recs and not has_res and not behind_cdn)

        props = {"a": a_recs, "aaaa": aaaa_recs, "cname": cname_recs, "mx": mx_recs,
                 "txt": txt_recs, "behind_cdn": behind_cdn, "dangling_cname": is_dangling,
                 "has_spf": any("v=spf1" in t.lower() for t in txt_recs),
                 "has_dmarc": any("v=dmarc1" in t.lower() for t in txt_recs)}

        entities.append(ParsedEntity(kind="dns_record", label=host,
            confidence=0.95 if has_res else 0.7, properties=props,
            source_tool="dnsx", phase="dns_infrastructure"))

        for ip in a_recs + aaaa_recs:
            if is_ip_address(ip) and ip not in seen_ips:
                seen_ips.add(ip)
                entities.append(ParsedEntity(kind="ip", label=ip, confidence=0.95,
                    properties={"resolved_from": host}, source_tool="dnsx", phase="dns_infrastructure"))

        if is_dangling:
            for cn in cname_recs:
                entities.append(ParsedEntity(kind="vulnerability_candidate",
                    label=f"dangling_cname:{host}", confidence=0.6,
                    properties={"host": host, "cname_target": cn, "vuln_type": "subdomain_takeover"},
                    source_tool="dnsx", phase="dns_infrastructure"))
    return entities


def _lf(row: dict, key: str) -> list[str]:
    v = row.get(key, [])
    if isinstance(v, list): return [str(x) for x in v if x]
    if isinstance(v, str) and v: return [v]
    return []
