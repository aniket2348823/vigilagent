"""
Pre-Scan Tech Stack Fingerprinting & WAF Detection (Method 18, 21).

Runs BEFORE any vulnerability module to determine:
  1. The target's technology stack (language, framework, database, server)
  2. Whether a WAF/CDN is present
  3. Which detection modules are applicable
  4. WAF bypass strategies if needed

Uses verification methods from backend.core.verification:
  - Method 18: Technology stack fingerprinting
  - Method 21: WAF/CDN bypass detection

Architecture: This module is called by the orchestrator before spawning
any detection modules. Its output (TechFingerprint) is passed to each
module so they can self-adjust their detection strategy.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from backend.core.verification import (
    TechFingerprint,
    fingerprint_tech_stack,
    detect_waf,
    generate_waf_bypass_payloads,
)

logger = logging.getLogger("TechFingerprint")


# Stack-specific module enablement rules
_STACK_MODULE_MAP = {
    "php": ["sqli", "xss", "lfi", "cmdi", "ssti", "crlf"],
    "java": ["sqli", "xss", "ssti", "deserialization"],
    "python": ["sqli", "xss", "lfi", "ssti", "prototype_pollution"],
    "nodejs": ["sqli", "xss", "prototype_pollution", "ssti"],
    "dotnet": ["sqli", "xss", "lfi", "ssti"],
    "unknown": ["sqli", "xss", "lfi", "cmdi", "ssti", "crlf", "prototype_pollution"],
}

# Database-specific error signatures for enhanced SQLi detection
_DB_ERROR_MAP = {
    "mysql": ["sql syntax", "mysql", "warning: mysql", "mysql_fetch", "mysql_num_rows"],
    "postgres": ["psql", "pg_query", "pgsql", "pg_exec", "postgresql"],
    "mssql": ["sqlstate", "mssql", "microsoft sql", "unclosed quotation", "odbc"],
    "oracle": ["ora-0", "oracle", "oci_", "ora-"],
    "sqlite": ["sqlite", "sqlite3", "sqlites"],
}


@dataclass
class PreScanResult:
    """Result of the pre-scan fingerprinting phase."""
    fingerprint: TechFingerprint
    waf_detected: str
    waf_confidence: float
    enabled_modules: list[str]
    disabled_modules: list[str]
    bypass_payloads: list[str]
    db_specific_markers: list[str]
    recommendations: list[str]


async def run_pre_scan(
    make_request,
    url: str,
) -> PreScanResult:
    """Execute the pre-scan fingerprinting phase.

    Sends a single probe request to the target and analyzes the response
    headers and body to determine the technology stack and WAF presence.

    Args:
        make_request: Async function that sends a request and returns (status, headers, body)
        url: The target URL to fingerprint

    Returns:
        PreScanResult with all fingerprinting data
    """
    try:
        status, headers, body = await make_request(url)
    except Exception as exc:
        logger.debug("Pre-scan request failed: %s", exc)
        return PreScanResult(
            fingerprint=TechFingerprint(),
            waf_detected="none",
            waf_confidence=0.0,
            enabled_modules=_STACK_MODULE_MAP["unknown"],
            disabled_modules=[],
            bypass_payloads=[],
            db_specific_markers=[],
            recommendations=["Pre-scan failed — enabling all modules"],
        )

    # Method 18: Technology stack fingerprinting
    fp = fingerprint_tech_stack(headers, body or "")

    # Method 21: WAF/CDN detection
    waf_name, waf_conf = detect_waf(headers, status)

    # Determine which modules to enable based on detected stack
    lang = fp.language if fp.language != "unknown" else "unknown"
    enabled = list(_STACK_MODULE_MAP.get(lang, _STACK_MODULE_MAP["unknown"]))
    disabled = [m for m in _STACK_MODULE_MAP["unknown"] if m not in enabled]

    # Always enable sqli and xss regardless of stack
    for m in ("sqli", "xss"):
        if m not in enabled:
            enabled.append(m)
    disabled = [m for m in disabled if m not in enabled]

    # DB-specific markers for enhanced detection
    db_markers = []
    if fp.database in _DB_ERROR_MAP:
        db_markers = _DB_ERROR_MAP[fp.database]

    # Generate WAF bypass payloads if WAF detected
    bypass_payloads = []
    if waf_name != "none":
        bypass_payloads = generate_waf_bypass_payloads("' OR 1=1--")
        bypass_payloads.extend(generate_waf_bypass_payloads("<script>alert(1)</script>"))

    # Build recommendations
    recommendations = []
    if waf_name != "none":
        recommendations.append(f"WAF detected ({waf_name}) — using bypass payloads")
    if fp.database != "unknown":
        recommendations.append(f"Database detected: {fp.database} — using stack-specific error markers")
    if fp.language == "php":
        recommendations.append("PHP detected — enabling LFI and SSTI modules")
    if fp.language == "nodejs":
        recommendations.append("Node.js detected — enabling prototype pollution module")
    if fp.has_csp:
        recommendations.append("CSP detected — XSS exploitation may be limited")
    if not fp.has_csp:
        recommendations.append("No CSP detected — XSS exploitation likely possible")

    return PreScanResult(
        fingerprint=fp,
        waf_detected=waf_name,
        waf_confidence=waf_conf,
        enabled_modules=enabled,
        disabled_modules=disabled,
        bypass_payloads=bypass_payloads,
        db_specific_markers=db_markers,
        recommendations=recommendations,
    )


def should_enable_module(module_name: str, pre_scan: PreScanResult) -> bool:
    """Check if a module should be enabled based on pre-scan results."""
    return module_name in pre_scan.enabled_modules


def get_db_markers(pre_scan: PreScanResult) -> list[str]:
    """Get database-specific error markers for SQLi detection."""
    return pre_scan.db_specific_markers


def get_bypass_payloads(pre_scan: PreScanResult) -> list[str]:
    """Get WAF bypass payloads if a WAF was detected."""
    return pre_scan.bypass_payloads
