"""Parser for one-subdomain-per-line tools (assetfinder, github-subdomains, puredns)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.parsers.recon.base import ParsedEntity, extract_host, is_valid_domain, safe_lines

if TYPE_CHECKING:
    from pathlib import Path


def _parse_subdomain_lines(path: Path | str, tool: str) -> list[ParsedEntity]:
    entities: list[ParsedEntity] = []
    seen: set[str] = set()
    for line in safe_lines(path):
        host = extract_host(line.strip())
        if not host or host in seen:
            continue
        if not is_valid_domain(host):
            continue
        seen.add(host)
        entities.append(
            ParsedEntity(
                kind="subdomain",
                label=host,
                confidence=0.8,
                properties={"discovered_via": tool},
                source_tool=tool,
                phase="passive_intelligence",
            )
        )
    return entities


def parse_assetfinder_lines(path: Path | str) -> list[ParsedEntity]:
    return _parse_subdomain_lines(path, "assetfinder")


def parse_github_subdomains_lines(path: Path | str) -> list[ParsedEntity]:
    return _parse_subdomain_lines(path, "github-subdomains")


def parse_puredns_lines(path: Path | str) -> list[ParsedEntity]:
    out = _parse_subdomain_lines(path, "puredns")
    # puredns only emits resolvable names, so bump confidence.
    for e in out:
        e.confidence = 0.92
        e.phase = "dns_infrastructure"
    return out


def parse_shuffledns_lines(path: Path | str) -> list[ParsedEntity]:
    out = _parse_subdomain_lines(path, "shuffledns")
    # shuffledns emits mass-DNS-resolved names, so they are confirmed live.
    for e in out:
        e.confidence = 0.9
        e.phase = "dns_infrastructure"
    return out
