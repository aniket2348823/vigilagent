"""
CVSS v4.0 Base Score Engine (Architecture §18, §29.11)
================================================================================
Production CVSS 4.0 base-score implementation using the official ``cvss``
Python package (Red Hat, pip install cvss) for exact NVD-parity scoring.

The ``cvss`` package implements the full CVSS v4.0 specification including
EQ1–EQ4 equations, environmental uplift, and threat-adjusted scoring.
This replaces the earlier simplified product-approximation formula.

Per-vulnerability-class metric profiles map each vuln type to a canonical
CVSS 4.0 vector string.  The vector is passed to ``CVSS4()`` which computes
the authoritative base score and severity rating.

Severity bands (CVSS 4.0 spec):
  9.0-10.0 = CRITICAL
  7.0-8.9  = HIGH
  4.0-6.9  = MEDIUM
  0.1-3.9  = LOW
  0.0      = NONE
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("CVSSEngine")

# Lazy-init: import at call time to avoid blocking app startup (HIGH-49)
_cortex = None


def _get_cortex():
    global _cortex
    if _cortex is None:
        from backend.ai.cortex import get_cortex_engine

        _cortex = get_cortex_engine()
    return _cortex


# ══════════════════════════════════════════════════════════════════════════════
# OFFICIAL CVSS 4.0 CALCULATION VIA ``cvss`` PACKAGE
# ══════════════════════════════════════════════════════════════════════════════


def score_for_vector(vector: str) -> tuple[float, str]:
    """Compute the CVSS 4.0 base score for a concrete vector string.

    Used when a finding record already carries the exact vector it was scored
    with — scoring THAT vector (NVD parity) is strictly more accurate than
    re-deriving from the vuln-class profile.
    """
    return _cvss4_calculate(str(vector or "").strip())


def _cvss4_calculate(vector: str) -> tuple[float, str]:
    """Compute CVSS 4.0 base score using the official ``cvss`` package.

    Returns ``(score, clean_vector)``.  On any error, returns ``(0.0, vector)``.
    """
    try:
        from cvss import CVSS4

        c = CVSS4(vector)
        return float(c.base_score), c.clean_vector()
    except Exception as exc:
        logger.warning("[CVSSEngine] CVSS4 calculation failed for %s: %s", vector, exc)
        return 0.0, vector


def _cvss4_severity(score: float) -> str:
    """CVSS 4.0 qualitative severity rating."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# ══════════════════════════════════════════════════════════════════════════════
# PER-VULNERABILITY-TYPE CVSS 4.0 METRIC PROFILES
# Each vulnerability class maps to a canonical CVSS 4.0 vector string.
# Format: CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}
# ══════════════════════════════════════════════════════════════════════════════

_VULN_CVSS40_VECTORS: dict[str, str] = {
    # ── Injection ──────────────────────────────────────────────────────────
    "SQL_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "SQLI": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "TECH_SQLI": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "SQLI_BLIND": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "COMMAND_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:H",
    "RCE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:H",
    "CODE_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N",
    "SSTI": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:H",
    "LDAP_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "XML_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "XPATH_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "NOSQL_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "HEADER_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    # ── XSS ────────────────────────────────────────────────────────────────
    "XSS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N",
    "CROSS_SITE_SCRIPTING": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N",
    "REFLECTED_XSS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N",
    "STORED_XSS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:H/SA:N",
    "DOM_XSS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N",
    # ── Authentication & Authorization ──────────────────────────────────────
    "BROKEN_AUTH": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "AUTH_BYPASS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N",
    "JWT_BYPASS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "SESSION_FIXATION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "CREDENTIAL_STUFFING": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "BRUTE_FORCE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N",
    "WEAK_PASSWORD": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    # ── IDOR & Access Control ──────────────────────────────────────────────
    "IDOR": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "BOLA": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "LOGIC_ESCALATOR": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "PRIVILEGE_ESCALATION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N",
    "UNAUTHORIZED_ACCESS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "FORCED_BROWSING": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    # ── Path & File Manipulation ───────────────────────────────────────────
    "PATH_TRAVERSAL": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "LFI": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "RFI": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "FILE_INCLUSION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
    "FILE_UPLOAD": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "LOCAL_FILE_READ": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    # ── Server-Side Request Forgery ────────────────────────────────────────
    "SSRF": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:H/SI:L/SA:N",
    "SERVER_SIDE_REQUEST_FORGERY": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:H/SI:L/SA:N",
    # ── Open Redirect ──────────────────────────────────────────────────────
    "OPEN_REDIRECT": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
    "REDIRECT": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
    # ── CSRF ───────────────────────────────────────────────────────────────
    "CSRF": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
    # ── Information Disclosure ─────────────────────────────────────────────
    "DATA_LEAK": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "INFORMATION_DISCLOSURE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "SENSITIVE_DATA_EXPOSURE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "VERBOSE_ERROR": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DIRECTORY_LISTING": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "SOURCE_CODE_DISCLOSURE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "STACK_TRACE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    # ── Business Logic ─────────────────────────────────────────────────────
    "RACE_CONDITION": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "BUSINESS_LOGIC": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "FINANCIAL_MANIPULATION": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N",
    "NEGATIVE_QUANTITY": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "PRICE_MANIPULATION": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    # ── Crypto ─────────────────────────────────────────────────────────────
    "WEAK_CRYPTO": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "SIGNED_COOKIES": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "INSECURE_DESERIALIZATION": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    # ── Server Configuration ───────────────────────────────────────────────
    "MISCONFIG": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DEFAULT_CONFIG": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "DEBUG_MODE": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CORS_MISCONFIG": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "CORS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "SECURITY_HEADER_MISSING": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "DEFAULT_CREDENTIALS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:H",
    # ── Prompt Injection (AI) ──────────────────────────────────────────────
    "PROMPT_INJECTION": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:H/SA:N",
    # ── Denial of Service ──────────────────────────────────────────────────
    "DOS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    "DDOS": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    "RESOURCE_EXHAUSTION": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    # ── Out-of-Band ────────────────────────────────────────────────────────
    "OOB_INTERACTSH": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "OOB": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    # ── Supply Chain ───────────────────────────────────────────────────────
    "SUPPLY_CHAIN": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "DEPENDENCY_VULN": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    # ── Catch-all ──────────────────────────────────────────────────────────
    "UNKNOWN": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
}

# Fallback vector for unknown vuln types
_DEFAULT_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"


def severity_band(score: float) -> str:
    """CVSS 4.0 qualitative severity rating."""
    return _cvss4_severity(score)


def score_for_vuln_class(vuln_type: str, *, data_leak: bool = False) -> tuple[float, str]:
    """Deterministic CVSS 4.0 base score for a known vuln class.

    Uses the official ``cvss`` package for exact NVD-parity scoring.
    Returns ``(score, vector_string)``.
    """
    key = (vuln_type or "").upper().replace(" ", "_").replace("-", "_")

    # Try exact match first, then fuzzy match
    vector = _VULN_CVSS40_VECTORS.get(key)
    if not vector:
        for vuln_key in _VULN_CVSS40_VECTORS:
            if vuln_key in key or key in vuln_key:
                vector = _VULN_CVSS40_VECTORS[vuln_key]
                break
    if not vector:
        vector = _DEFAULT_VECTOR

    # If data leak detected, elevate confidentiality impact to H
    if data_leak and "/VC:L/" in vector:
        vector = vector.replace("/VC:L/", "/VC:H/")
    elif data_leak and "/VC:N/" in vector:
        vector = vector.replace("/VC:N/", "/VC:H/")

    score, clean_vector = _cvss4_calculate(vector)
    return score, clean_vector


# ══════════════════════════════════════════════════════════════════════════════
# CWE MAPPING — Single source of truth
# Import from finding_normalizer to avoid duplication
# ══════════════════════════════════════════════════════════════════════════════


def generate_cwe(vuln_type: str) -> str:
    """Map a vulnerability type to its CWE identifier (delegates to finding_normalizer)."""
    try:
        from backend.reporting.finding_normalizer import _lookup_cwe

        cwe_data = _lookup_cwe(vuln_type)
        return cwe_data.get("cwe", "CWE-200")
    except Exception:
        return "CWE-200"


# ══════════════════════════════════════════════════════════════════════════════
# EVIDENCE & REMEDIATION GENERATION
# ══════════════════════════════════════════════════════════════════════════════

_EVIDENCE_TEMPLATES: dict[str, dict[str, Any]] = {
    "SQL_INJECTION": {
        "description": "SQL injection vulnerability detected. User-controlled input is directly concatenated into SQL queries, allowing an attacker to manipulate the database query logic.",
        "http_request": "GET {url}?id=1'+OR+1=1-- HTTP/1.1\nHost: {host}",
        "http_response": "Response contained database error messages or altered data indicating SQL query manipulation.",
        "steps_to_reproduce": [
            "1. Navigate to the vulnerable endpoint",
            "2. Append a single quote (') to the parameter value",
            "3. Observe SQL error messages or changed response behavior",
            "4. Inject UNION SELECT to extract data from other tables",
            "5. Use time-based blind techniques to extract data without error messages",
        ],
        "remediation": (
            "Use parameterized queries (prepared statements) for all database interactions. "
            "Never concatenate user input into SQL strings. Apply strict input validation with "
            "allowlisting. Implement least-privilege database accounts. Deploy a WAF with "
            "SQL injection rules. Use stored procedures where appropriate."
        ),
    },
    "TECH_SQLI": {
        "description": "SQL injection vulnerability detected via automated probe. User-controlled input is directly concatenated into SQL queries.",
        "http_request": "GET {url}?id=1'+OR+1=1-- HTTP/1.1\nHost: {host}",
        "http_response": "Response contained database error messages or altered data.",
        "steps_to_reproduce": [
            "1. Navigate to the vulnerable endpoint",
            "2. Append a single quote (') to the parameter value",
            "3. Observe SQL error messages or changed response behavior",
            "4. Inject UNION SELECT to extract data from other tables",
            "5. Use time-based blind techniques for data extraction",
        ],
        "remediation": (
            "Use parameterized queries (prepared statements) for all database interactions. "
            "Never concatenate user input into SQL strings. Apply strict input validation with "
            "allowlisting. Implement least-privilege database accounts. Deploy a WAF."
        ),
    },
    "XSS": {
        "description": "Cross-Site Scripting (XSS) vulnerability detected. User input is reflected in the page without proper sanitization, allowing execution of arbitrary JavaScript in the victim's browser context.",
        "http_request": "GET {url}?name=<script>alert('XSS')</script> HTTP/1.1\nHost: {host}",
        "http_response": "Response body contained the unescaped script tag, confirming reflected XSS.",
        "steps_to_reproduce": [
            "1. Navigate to the vulnerable endpoint",
            "2. Inject <script>alert(document.cookie)</script> in the parameter",
            "3. Observe the JavaScript executing in the browser context",
            "4. Craft a malicious URL to steal session cookies",
        ],
        "remediation": (
            "Encode all user output using context-appropriate HTML entity encoding. "
            "Implement Content-Security-Policy (CSP) headers with nonce-based script loading. "
            "Use HTTPOnly and Secure flags on session cookies. Validate and sanitize all input."
        ),
    },
    "CROSS_SITE_SCRIPTING": {
        "description": "Cross-Site Scripting (XSS) vulnerability detected. User input is reflected in the page without proper sanitization.",
        "http_request": "GET {url}?name=<script>alert('XSS')</script> HTTP/1.1\nHost: {host}",
        "http_response": "Response body contained the unescaped script tag.",
        "steps_to_reproduce": [
            "1. Navigate to the vulnerable endpoint",
            "2. Inject <script>alert(document.cookie)</script> in the parameter",
            "3. Observe the JavaScript executing in the browser context",
        ],
        "remediation": (
            "Encode all user output using context-appropriate HTML entity encoding. "
            "Implement Content-Security-Policy (CSP) headers. Use HTTPOnly cookies."
        ),
    },
    "COMMAND_INJECTION": {
        "description": "OS Command Injection vulnerability detected. User input is passed to system command execution, allowing an attacker to run arbitrary commands on the host system.",
        "http_request": "POST {url} with payload: ; cat /etc/passwd",
        "http_response": "Response contained output from the injected system command.",
        "steps_to_reproduce": [
            "1. Navigate to the command execution endpoint",
            "2. Inject a semicolon followed by a system command",
            "3. Observe command output in the response",
            "4. Craft a reverse shell payload for remote access",
        ],
        "remediation": (
            "Never pass user input to system commands. Use language-native APIs instead of "
            "shell commands. If shell execution is unavoidable, use parameterized execution "
            "(e.g., subprocess with argument lists). Apply strict input validation and sandboxing."
        ),
    },
    "LOGIC_ESCALATOR": {
        "description": "Business Logic Vulnerability detected. The application's authorization and access control logic can be bypassed, allowing privilege escalation or unauthorized resource access.",
        "http_request": "GET {url} HTTP/1.1\nHost: {host}\nCookie: [session without proper role validation]",
        "http_response": "Response returned privileged content or functionality without proper authorization checks.",
        "steps_to_reproduce": [
            "1. Access the endpoint with a standard user session",
            "2. Modify request parameters to access privileged functions",
            "3. Observe that the application does not validate authorization",
            "4. Escalate to admin-level operations",
        ],
        "remediation": (
            "Implement proper server-side authorization checks for every endpoint. "
            "Validate user roles and permissions before processing requests. "
            "Use deny-by-default access control. Never rely solely on client-side access control."
        ),
    },
    "SSRF": {
        "description": "Server-Side Request Forgery (SSRF) detected. The application can be tricked into making requests to internal services, potentially exposing internal infrastructure.",
        "http_request": "POST {url} with url=http://169.254.169.254/latest/meta-data/",
        "http_response": "Response contained data from the internal metadata service.",
        "steps_to_reproduce": [
            "1. Identify a parameter that fetches URLs",
            "2. Set the URL to an internal resource (e.g., 169.254.169.254)",
            "3. Observe internal service data in the response",
        ],
        "remediation": (
            "Validate and sanitize all URLs before making server-side requests. "
            "Maintain an allowlist of permitted domains/IPs. Block requests to internal "
            "networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). "
            "Use a dedicated proxy for external requests."
        ),
    },
    "BROKEN_AUTH": {
        "description": "Broken Authentication vulnerability detected. The application does not properly protect authentication mechanisms, enabling credential enumeration or session hijacking.",
        "http_request": "POST /login with username=admin&password=wrong",
        "http_response": "Response indicated different behavior for valid vs invalid usernames.",
        "steps_to_reproduce": [
            "1. Submit login requests with various credentials",
            "2. Observe different error messages for valid/invalid usernames",
            "3. Use enumeration to identify valid accounts",
            "4. Brute force passwords for identified accounts",
        ],
        "remediation": (
            "Implement multi-factor authentication (MFA). Use secure session management "
            "(HTTPOnly, Secure, SameSite cookies). Implement account lockout after failed "
            "attempts. Hash passwords with bcrypt/scrypt/Argon2. Use rate limiting."
        ),
    },
    "AUTH_BYPASS": {
        "description": "Authentication Bypass vulnerability detected. The application can be accessed without proper authentication, exposing protected functionality.",
        "http_request": "GET {url} (without authentication headers)",
        "http_response": "Response returned protected content without authentication.",
        "steps_to_reproduce": [
            "1. Access protected endpoint without credentials",
            "2. Observe that the endpoint responds with data",
        ],
        "remediation": (
            "Enforce authentication on every protected endpoint using middleware. "
            "Implement deny-by-default access control. Validate authentication tokens "
            "server-side. Use role-based access control (RBAC) for authorization."
        ),
    },
    "IDOR": {
        "description": "Insecure Direct Object Reference (IDOR) detected. The application exposes internal object references without proper access control, allowing unauthorized data access.",
        "http_request": "GET {url} with modified object ID parameter",
        "http_response": "Response returned another user's data.",
        "steps_to_reproduce": [
            "1. Access a resource with your own ID",
            "2. Change the ID parameter to another user's ID",
            "3. Observe that the application returns the other user's data",
        ],
        "remediation": (
            "Never expose internal object references (IDs, keys) directly. "
            "Use indirect references (e.g., UUIDs mapped server-side). "
            "Validate that the authenticated user owns the requested resource."
        ),
    },
    "PATH_TRAVERSAL": {
        "description": "Path Traversal vulnerability detected. User input can be used to access files outside the intended directory, potentially exposing sensitive system files.",
        "http_request": "GET {url}?file=../../../../etc/passwd",
        "http_response": "Response contained contents of /etc/passwd.",
        "steps_to_reproduce": [
            "1. Identify a file parameter",
            "2. Inject ../ sequences to traverse directories",
            "3. Read sensitive files like /etc/passwd or application config",
        ],
        "remediation": (
            "Validate and sanitize all file path inputs. Use a chroot jail or container "
            "to limit filesystem access. Normalize paths and reject '..' sequences. "
            "Use a mapping layer between user input and filesystem paths."
        ),
    },
    "OPEN_REDIRECT": {
        "description": "Open Redirect vulnerability detected. The application redirects users to attacker-controlled URLs, enabling phishing attacks.",
        "http_request": "GET {url}?redirect=http://evil.com",
        "http_response": "Response contained a 302 redirect to the attacker-controlled URL.",
        "steps_to_reproduce": [
            "1. Identify a redirect parameter",
            "2. Set it to an external URL",
            "3. Observe the application redirects to the external domain",
        ],
        "remediation": (
            "Maintain a strict allowlist of permitted redirect targets. "
            "Never redirect to user-supplied URLs without validation. "
            "Use relative URLs for redirects."
        ),
    },
    "CSRF": {
        "description": "Cross-Site Request Forgery (CSRF) vulnerability detected. State-changing operations can be triggered from a malicious page without the user's knowledge.",
        "http_request": "POST {url} from cross-origin context without CSRF token",
        "http_response": "Request was processed successfully without CSRF token validation.",
        "steps_to_reproduce": [
            "1. Identify a state-changing endpoint",
            "2. Create a malicious HTML page with a form targeting the endpoint",
            "3. Trick a logged-in user into visiting the page",
            "4. Observe the action is performed on their behalf",
        ],
        "remediation": (
            "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing "
            "forms. Use SameSite cookie attribute. Verify the Origin/Referer header on "
            "server side. Require re-authentication for sensitive operations."
        ),
    },
    "FILE_INCLUSION": {
        "description": "File Inclusion vulnerability detected. User input controls which file is loaded by the application, potentially leading to code execution.",
        "http_request": "GET {url}?page=../../../../etc/passwd",
        "http_response": "Response contained contents of the included file.",
        "steps_to_reproduce": [
            "1. Identify a file inclusion parameter",
            "2. Inject path traversal sequences",
            "3. Read local files or include remote scripts",
        ],
        "remediation": (
            "Use a file mapping system that maps integer IDs to files, never user-supplied "
            "paths. Validate and sanitize all file path input. Use chroot/container sandboxing. "
            "Disable remote file inclusion."
        ),
    },
}

_DEFAULT_EVIDENCE: dict[str, Any] = {
    "description": "A security vulnerability was detected at this endpoint. The vulnerability allows an attacker to compromise the confidentiality, integrity, or availability of the application.",
    "http_request": "HTTP request with malicious payload sent to {url}",
    "http_response": "Response indicated successful exploitation of the vulnerability.",
    "steps_to_reproduce": [
        "1. Navigate to the vulnerable endpoint",
        "2. Inject the malicious payload",
        "3. Observe the vulnerable behavior",
    ],
    "remediation": (
        "Apply the OWASP recommended security controls for this vulnerability class. "
        "Implement input validation, output encoding, and proper access control. "
        "Consult OWASP Testing Guide and Cheat Sheet Series for specific guidance."
    ),
}


def generate_evidence(vuln_type: str, url: str = "", host: str = "") -> dict[str, Any]:
    """Generate structured evidence + remediation for a finding."""
    key = (vuln_type or "").upper().replace(" ", "_").replace("-", "_")
    template = _EVIDENCE_TEMPLATES.get(key)
    if not template:
        for tkey in _EVIDENCE_TEMPLATES:
            if tkey in key or key in tkey:
                template = _EVIDENCE_TEMPLATES[tkey]
                break
    if not template:
        template = _DEFAULT_EVIDENCE
    return {
        "type": "scan-output",
        "description": template["description"],
        "http_request": template["http_request"].format(url=url, host=host or "target"),
        "http_response": template["http_response"],
        "steps_to_reproduce": template["steps_to_reproduce"],
        "remediation": template["remediation"],
        "collected_at": datetime.now(UTC).isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# CALCULATOR CLASS (Backward Compatible API — CVSS 4.0 only)
# ══════════════════════════════════════════════════════════════════════════════


def cvss31_base(av: str = "N") -> tuple[float, str]:
    """Backward-compatible alias. Computes a base score for the given AV metric.

    Uses CVSS 4.0 internally but returns (score, vector) matching the old CVSS 3.1 API.
    """
    # Map AV values to a standard CVSS 4.0 vector with the requested AV
    av = (av or "N").upper()
    vector = f"CVSS:4.0/AV:{av}/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    score, clean_vector = _cvss4_calculate(vector)
    return score, clean_vector


def _roundup(value: float) -> float:
    """Round up to nearest 0.1 (legacy CVSS 3.1 compatibility)."""
    import math

    return math.ceil(value * 10) / 10


class CVSSCalculator:
    """CVSS 4.0 calculator with backward-compatible API."""

    def __init__(self, success_count: int = 0, body_content: str = "", target_url: str = "", vuln_type: str = ""):
        self.success_count = success_count
        self.body_content = body_content.lower()
        self.target_url = target_url
        self.vuln_type = vuln_type

    def calculate(self) -> tuple[float, str]:
        """Calculate CVSS 4.0 score using the official ``cvss`` package."""
        sensitive_keywords = ["token", "key", "password", "secret", "admin"]
        data_leak = any(k in self.body_content for k in sensitive_keywords)
        return score_for_vuln_class(self.vuln_type or "UNKNOWN", data_leak=data_leak)

    async def calculate_hybrid(self) -> tuple[float, str]:
        """Calculate CVSS 4.0 with AI-powered contextual adjustment."""
        score, vector = self.calculate()
        if self.target_url and self.vuln_type:
            try:
                adjusted = await _get_cortex().adjust_cvss_score(score, self.vuln_type, self.target_url)
                return adjusted, vector
            except Exception as exc:
                logger.debug("[CVSSEngine] AI hybrid CVSS adjustment failed: %s", exc)
        return score, vector
