"""
Parser for URL line-based outputs (gau, waybackurls, etc).

These tools emit one URL per line. We extract:
- Historical URLs with path classification
- Subdomains discovered from URL hostnames
- Parameters from query strings
- Path patterns for wordlist enrichment
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlparse

from backend.parsers.recon.base import ParsedEntity, extract_host, safe_lines

if TYPE_CHECKING:
    from pathlib import Path

# Path classification patterns
_SENSITIVE_PATTERNS = {
    "api": re.compile(r"/api/|/rest/|/v[0-9]+/", re.I),
    "admin": re.compile(r"/admin|/dashboard|/manage|/panel|/console|/control", re.I),
    "auth": re.compile(r"/login|/auth|/token|/oauth|/session|/signin|/signup|/register|/password|/forgot|/reset", re.I),
    "config": re.compile(r"\.env|\.config|\.ini|\.yml|\.yaml|\.toml|\.xml|\.properties|\.cfg|/config|/settings", re.I),
    "backup": re.compile(r"\.bak|\.backup|\.old|\.orig|\.save|\.swp|\.copy|~$|\.sql$|\.tar|\.zip|\.gz|\.rar", re.I),
    "debug": re.compile(r"/debug|/trace|/test|/phpinfo|/_profiler|/actuator|/health|/status|/metrics|/info", re.I),
    "upload": re.compile(r"/upload|/import|/file|/attachment|/media|/image|/document", re.I),
    "graphql": re.compile(r"/graphql|/graphiql|/gql|/playground", re.I),
    "git_exposed": re.compile(r"\.git/|\.svn/|\.hg/|\.bzr/|\.gitignore|\.gitattributes", re.I),
    "payment": re.compile(r"/pay|/checkout|/billing|/invoice|/order|/cart|/stripe|/braintree", re.I),
    "data_export": re.compile(r"/export|/download|/csv|/report|/dump|/backup", re.I),
    "user_data": re.compile(r"/user|/account|/profile|/me$|/member|/customer", re.I),
    "js_source": re.compile(r"\.js$|\.mjs$|\.ts$|\.jsx$", re.I),
    "static": re.compile(r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|ttf|eot|mp4|webm|pdf)$", re.I),
}

_RISK_MAP = {
    "api": "HIGH",
    "admin": "CRITICAL",
    "auth": "HIGH",
    "config": "CRITICAL",
    "backup": "CRITICAL",
    "debug": "HIGH",
    "upload": "HIGH",
    "graphql": "HIGH",
    "git_exposed": "CRITICAL",
    "payment": "CRITICAL",
    "data_export": "HIGH",
    "user_data": "MEDIUM",
    "js_source": "LOW",
    "static": "INFO",
}


def parse_url_lines(path: Path | str) -> list[ParsedEntity]:
    """Parse one-URL-per-line output from gau/waybackurls into entities."""
    entities: list[ParsedEntity] = []
    seen_urls: set[str] = set()
    seen_hosts: set[str] = set()

    for line in safe_lines(path):
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        normalized = url.lower().split("#")[0].rstrip("/")
        if normalized in seen_urls:
            continue
        seen_urls.add(normalized)

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path_str = parsed.path or "/"
        category, risk = _classify_single_path(path_str)

        props = {
            "full_url": url,
            "host": host,
            "path": path_str,
            "category": category,
            "risk": risk,
        }

        # Extract query params
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if params:
            props["parameters"] = [{"name": n, "value": v} for n, v in params]
            props["param_count"] = len(params)

        entities.append(
            ParsedEntity(
                kind="historical_url",
                label=url,
                confidence=0.7,
                properties=props,
                source_tool="url_lines",
                phase="passive_intelligence",
            )
        )

        # Emit subdomain entity
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            entities.append(
                ParsedEntity(
                    kind="subdomain",
                    label=host,
                    confidence=0.6,
                    properties={"discovered_via": "historical_url"},
                    source_tool="url_lines",
                    phase="passive_intelligence",
                )
            )

    return entities


def extract_subdomains_from_urls(path: Path | str) -> list[ParsedEntity]:
    """Extract unique subdomains from URL list."""
    seen: set[str] = set()
    entities: list[ParsedEntity] = []

    for line in safe_lines(path):
        host = extract_host(line.strip())
        if host and host not in seen:
            seen.add(host)
            entities.append(
                ParsedEntity(
                    kind="subdomain",
                    label=host,
                    confidence=0.6,
                    properties={"discovered_via": "historical_url"},
                    source_tool="url_extraction",
                    phase="passive_intelligence",
                )
            )

    return entities


def extract_params_from_urls(path: Path | str) -> list[ParsedEntity]:
    """Extract unique parameter names and their locations from URL list."""
    param_hosts: dict[str, set[str]] = {}  # param_name -> set of hosts
    param_values: dict[str, list[str]] = {}  # param_name -> sample values

    for line in safe_lines(path):
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            param_hosts.setdefault(name, set()).add(host)
            if len(param_values.get(name, [])) < 5:
                param_values.setdefault(name, []).append(value)

    entities: list[ParsedEntity] = []
    for name, hosts in param_hosts.items():
        entities.append(
            ParsedEntity(
                kind="parameter",
                label=name,
                confidence=0.65,
                properties={
                    "hosts": sorted(hosts),
                    "host_count": len(hosts),
                    "sample_values": param_values.get(name, []),
                    "location": "query",
                },
                source_tool="param_extraction",
                phase="passive_intelligence",
            )
        )

    return entities


def classify_historical_paths(path: Path | str) -> list[ParsedEntity]:
    """Classify all paths from URL list by security relevance."""
    path_categories: Counter = Counter()
    category_urls: dict[str, list[str]] = {}

    for line in safe_lines(path):
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        parsed = urlparse(url)
        path_str = parsed.path or "/"
        category, risk = _classify_single_path(path_str)
        if category != "general":
            path_categories[category] += 1
            if len(category_urls.get(category, [])) < 10:
                category_urls.setdefault(category, []).append(url)

    entities: list[ParsedEntity] = []
    for category, count in path_categories.most_common():
        entities.append(
            ParsedEntity(
                kind="path_pattern",
                label=f"historical_{category}",
                confidence=0.6,
                properties={
                    "category": category,
                    "count": count,
                    "risk": _RISK_MAP.get(category, "LOW"),
                    "sample_urls": category_urls.get(category, []),
                },
                source_tool="path_classification",
                phase="passive_intelligence",
            )
        )

    return entities


def _classify_single_path(path: str) -> tuple[str, str]:
    """Classify a single URL path into a security category."""
    for category, pattern in _SENSITIVE_PATTERNS.items():
        if pattern.search(path):
            return category, _RISK_MAP.get(category, "LOW")
    return "general", "INFO"
