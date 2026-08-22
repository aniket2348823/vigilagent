"""
Finding normalizer for the PDF report builder (Sub-Agent A) and the live UI.

Goal: turn whatever shape a finding happens to be persisted in (orchestrator
event payloads, ``StateManager.add_finding`` rows, late ``results`` rows)
into a single, stable dict the renderer can consume without conditionals.

Hard rule: never invent URLs, payloads, or HTTP traffic. If the raw evidence
did not supply them we leave the field empty so the renderer can emit a
deterministic placeholder ("<no captured traffic>"). Cortex enrichment is
only allowed for narrative fields (description, impact, explanation,
remediation, code fix) — not for technical evidence.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


# Hosts that are aliases of the same local machine/container. Findings that
# only differ by these hostnames (e.g. ``host.docker.internal:8888`` vs
# ``127.0.0.1:8888``) are the SAME service — the PDF/API must not report the
# same vulnerability 2-3 times just because Docker NAT or loopback aliasing
# surfaced it under different host strings.
_LOCAL_HOST_ALIASES = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "host.docker.internal",
        "gateway.docker.internal",
        "docker.for.mac.localhost",
        "docker.for.win.localhost",
        # Docker Desktop gateway IPs (Linux VM on Windows/macOS) — appear
        # when tools run inside the recon container and resolve the target
        # via the bridge network instead of loopback.
        "192.168.65.254",
        "192.168.65.1",
        "172.17.0.1",
        "172.18.0.1",
        "172.19.0.1",
    }
)


def _is_loopback_host(host: str) -> bool:
    h = (host or "").lower().strip(".")
    if h in _LOCAL_HOST_ALIASES:
        return True
    return h.startswith("127.") or h == "::1"


def canonical_finding_key(
    url: str,
    vuln_type: str,
    target_url: str = "",
) -> tuple[str, ...] | None:
    """Return a dedup key for a finding, collapsing local-host aliases.

    Two findings are the SAME finding when they share the vulnerability type
    and the same service endpoint (scheme, port, path) — even if one was
    captured via ``127.0.0.1:8888`` and another via ``host.docker.internal``
    or the docker gateway IP. Keeps distinct hosts distinct for real-world
    multi-host engagements: only loopback / docker-internal aliases (and the
    scan target's own host when the target is itself local) collapse.

    Returns ``None`` when the finding carries no usable URL or type.
    """
    t = str(vuln_type or "").strip().upper()
    if not t:
        return None
    for prefix in (
        "ALPHA:", "NUCLEI:", "SIGMA:", "BETA:", "OMEGA:", "DELTA:",
        "GAMMA:", "KAPPA:", "PRISM:", "CHI:",
    ):
        if t.startswith(prefix):
            t = t[len(prefix):]
            break
    from urllib.parse import urlparse

    try:
        u = urlparse(str(url or ""))
        host = (u.hostname or "").lower().strip(".")
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/").rstrip("/") or "/"
    except Exception:
        return (t, str(url or "").lower())
    if not host:
        return (t, str(url or "").lower())

    # Normalise the host: loopback/docker aliases (and the target's own host
    # when the target is local) all become one canonical token.
    target_is_local = _is_loopback_host(urlparse(target_url).hostname or "")
    if _is_loopback_host(host) or (target_is_local and host and u.port == urlparse(target_url).port):
        host = "<local>"
    return (t, u.scheme or "http", str(port), host, path)


# ── Lightweight CWE lookup (mirror of backend.core.reporting.SecurityReportPDF.CWE_MAP) ──
_CWE_MAP: dict[str, dict[str, Any]] = {
    "SQL_INJECTION": {"cwe": "CWE-89", "base_cvss": 9.8},
    "SQLI": {"cwe": "CWE-89", "base_cvss": 9.8},
    "TECH_SQLI": {"cwe": "CWE-89", "base_cvss": 9.8},
    "SQLI_BLIND": {"cwe": "CWE-89", "base_cvss": 8.1},
    "NOSQL_INJECTION": {"cwe": "CWE-943", "base_cvss": 9.3},
    "CROSS_SITE_SCRIPTING": {"cwe": "CWE-79", "base_cvss": 6.1},
    "XSS": {"cwe": "CWE-79", "base_cvss": 6.1},
    "REFLECTED_XSS": {"cwe": "CWE-79", "base_cvss": 6.1},
    "STORED_XSS": {"cwe": "CWE-79", "base_cvss": 7.6},
    "DOM_XSS": {"cwe": "CWE-79", "base_cvss": 6.5},
    "UNAUTHORIZED_ACCESS": {"cwe": "CWE-284", "base_cvss": 7.5},
    "IDOR": {"cwe": "CWE-639", "base_cvss": 8.6},
    "BOLA": {"cwe": "CWE-639", "base_cvss": 8.6},
    "LOGIC_IDOR": {"cwe": "CWE-639", "base_cvss": 8.6},
    "LOGIC_ESCALATOR": {"cwe": "CWE-269", "base_cvss": 7.2},
    "PRIVILEGE_ESCALATION": {"cwe": "CWE-269", "base_cvss": 9.3},
    "FORCED_BROWSING": {"cwe": "CWE-284", "base_cvss": 6.5},
    "COMMAND_INJECTION": {"cwe": "CWE-78", "base_cvss": 9.8},
    "RCE": {"cwe": "CWE-78", "base_cvss": 9.8},
    "CODE_INJECTION": {"cwe": "CWE-94", "base_cvss": 8.8},
    "SSTI": {"cwe": "CWE-1336", "base_cvss": 9.8},
    "PATH_TRAVERSAL": {"cwe": "CWE-22", "base_cvss": 7.5},
    "LFI": {"cwe": "CWE-22", "base_cvss": 7.5},
    "RFI": {"cwe": "CWE-98", "base_cvss": 8.8},
    "FILE_INCLUSION": {"cwe": "CWE-98", "base_cvss": 8.1},
    "FILE_UPLOAD": {"cwe": "CWE-434", "base_cvss": 9.8},
    "SSRF": {"cwe": "CWE-918", "base_cvss": 8.6},
    "SERVER_SIDE_REQUEST_FORGERY": {"cwe": "CWE-918", "base_cvss": 8.6},
    "OPEN_REDIRECT": {"cwe": "CWE-601", "base_cvss": 5.4},
    "INFORMATION_DISCLOSURE": {"cwe": "CWE-200", "base_cvss": 6.5},
    "DATA_LEAK": {"cwe": "CWE-200", "base_cvss": 8.1},
    "SENSITIVE_DATA_EXPOSURE": {"cwe": "CWE-200", "base_cvss": 8.1},
    "BROKEN_AUTH": {"cwe": "CWE-287", "base_cvss": 8.1},
    "AUTH_BYPASS": {"cwe": "CWE-287", "base_cvss": 9.3},
    "JWT_BYPASS": {"cwe": "CWE-287", "base_cvss": 9.3},
    "SESSION_FIXATION": {"cwe": "CWE-384", "base_cvss": 8.1},
    "CSRF": {"cwe": "CWE-352", "base_cvss": 6.8},
    "PROMPT_INJECTION": {"cwe": "CWE-77", "base_cvss": 7.5},
    "ARITHMETIC_OVERFLOW": {"cwe": "CWE-190", "base_cvss": 7.5},
    "RACE_CONDITION": {"cwe": "CWE-362", "base_cvss": 6.5},
    "BUSINESS_LOGIC": {"cwe": "CWE-840", "base_cvss": 6.5},
    "FINANCIAL_MANIPULATION": {"cwe": "CWE-840", "base_cvss": 7.2},
    "WEAK_CRYPTO": {"cwe": "CWE-327", "base_cvss": 5.9},
    "INSECURE_DESERIALIZATION": {"cwe": "CWE-502", "base_cvss": 9.8},
    "MISCONFIG": {"cwe": "CWE-16", "base_cvss": 6.5},
    "DEBUG_MODE": {"cwe": "CWE-489", "base_cvss": 6.5},
    "DEFAULT_CREDENTIALS": {"cwe": "CWE-798", "base_cvss": 9.8},
    "DIRECTORY_LISTING": {"cwe": "CWE-548", "base_cvss": 6.5},
    "VERBOSE_ERROR": {"cwe": "CWE-209", "base_cvss": 6.5},
}


_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("Injection & Fuzzing", ("SQL", "INJECTION", "FUZZ", "XSS", "SSTI", "COMMAND", "TEMPLATE")),
    ("Authentication Gates", ("AUTH", "JWT", "TOKEN", "LOGIN", "SESSION", "CREDENTIAL", "CSRF")),
    ("Object References (IDOR)", ("IDOR", "BOLA", "OBJECT_REF")),
    ("Privilege Escalation", ("PRIVILEGE", "ADMIN", "ROLE", "ESCALAT", "UNAUTHORIZED")),
    ("Information Disclosure", ("DISCLOSURE", "LEAK", "EXPOSURE", "TRAVERSAL", "LFI", "SSRF", "REDIRECT")),
    ("Concurrency & Timing", ("RACE", "TIMING", "TOCTOU")),
    ("Workflow Integrity", ("WORKFLOW", "STEP", "LOGIC", "BUSINESS")),
]


_PLACEHOLDER = "<no captured traffic>"


def _lookup_cwe(vuln_type: str) -> dict[str, Any]:
    key = (vuln_type or "").upper().replace(" ", "_").replace("-", "_")
    if key in _CWE_MAP:
        return _CWE_MAP[key]
    for k, v in _CWE_MAP.items():
        if k in key or key in k:
            return v
    return {"cwe": "CWE-200", "base_cvss": 5.0}


def _category_for(vuln_type: str) -> str:
    vt = (vuln_type or "").upper()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(k in vt for k in keywords):
            return category
    return "Uncategorized"


def _severity_band(cvss: float) -> str:
    if cvss is None:
        return "LOW"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "INFO"


def _coerce_bullets(value: Any) -> list[str]:
    """Accept a list, a string with newlines/bullets, or empty -> ``list[str]``."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        bits = [b.strip(" \t-•*") for b in value.replace("\r", "").split("\n")]
        return [b for b in bits if b]
    return [str(value)]


def _first_present(raw: dict, *keys: str) -> Any:
    for k in keys:
        if k in raw and raw[k] not in (None, "", [], {}):
            return raw[k]
    return None


def _compute_cvss(raw: dict, vuln_type: str) -> tuple[float, str]:
    """Compute CVSS via :class:`CVSSCalculator` if missing in raw."""
    explicit = raw.get("cvss_score")
    if isinstance(explicit, (int, float)) and explicit > 0:
        score = float(explicit)
        return score, _severity_band(score)
    try:
        from backend.reporting.cvss_engine import CVSSCalculator

        body = ""
        ev = raw.get("evidence")
        if isinstance(ev, dict):
            body = str(ev.get("response_body") or ev.get("response") or "")
        body = body or str(raw.get("data", "") or raw.get("response", ""))
        calc = CVSSCalculator(
            success_count=1,
            body_content=body,
            target_url=str(raw.get("url") or ""),
            vuln_type=vuln_type or "",
        )
        score, _vector = calc.calculate()
        return float(score), _severity_band(float(score))
    except Exception as exc:
        logger.debug("CVSS calculation fell back to CWE base score: %s", exc)
        base = float(_lookup_cwe(vuln_type).get("base_cvss", 5.0))
        return base, _severity_band(base)


def _enrich_with_cortex(vuln_type: str, url: str, payload: str) -> dict[str, Any]:
    """Fetch narrative fields from Cortex. Returns ``{}`` on any error."""
    try:
        from backend.ai.cortex import get_cortex_engine

        cortex = get_cortex_engine()
    except Exception as exc:
        logger.debug("Cortex unavailable for normalizer: %s", exc)
        return {}

    try:
        coro = cortex.generate_vulnerability_summary(vuln_type or "Unknown", payload or "", url or "")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # Caller is already inside an event loop; do not block. The PDF
            # builder explicitly invokes the async path, so this branch only
            # fires from sync callers (CLI/smoke test) and gracefully
            # degrades to the deterministic fallback below.
            return {}
        return asyncio.run(coro) or {}
    except Exception as exc:
        logger.debug("Cortex enrichment skipped: %s", exc)
        return {}


def normalize_finding(raw: dict, scan_record: dict) -> dict:
    """Return a stable, renderer-friendly dict for ``raw`` finding.

    The shape is pinned — every key is always present, even when empty —
    so the PDF template can address fields by name without ``getattr``-style
    conditionals on every section.
    """
    raw = raw or {}
    scan_record = scan_record or {}

    vuln_type = str(_first_present(raw, "type", "vuln_type", "name") or "Unknown")
    url = str(_first_present(raw, "url", "endpoint", "target_url") or scan_record.get("target_url") or "")
    payload = str(_first_present(raw, "payload", "data", "vector") or "")

    cwe_data = _lookup_cwe(vuln_type)
    cwe = str(_first_present(raw, "cwe") or cwe_data.get("cwe", "CWE-200"))

    cvss_score, cvss_severity = _compute_cvss(raw, vuln_type)
    severity = str(_first_present(raw, "severity", "cvss_severity") or cvss_severity).upper()
    threat_score = max(0, min(100, int(round(cvss_score * 10))))

    # Narrative bullets — use raw if present, else enrich (only when called
    # synchronously from outside an event loop). Either way we never fabricate
    # technical evidence here.
    description_bullets = _coerce_bullets(_first_present(raw, "description", "description_bullets"))
    impact_bullets = _coerce_bullets(_first_present(raw, "impact", "impact_bullets", "business_impact"))
    remediation_bullets = _coerce_bullets(_first_present(raw, "remediation", "remediation_bullets"))
    explanation = str(_first_present(raw, "explanation", "exploitability") or "")
    forensic = str(_first_present(raw, "forensic", "forensic_narrative") or "")
    code_fix_secure = str(_first_present(raw, "code_fix", "code_fix_secure") or "")
    code_fix_vulnerable = str(_first_present(raw, "code_fix_vulnerable", "vulnerable_code") or "")

    needs_enrichment = not (description_bullets and impact_bullets and remediation_bullets and code_fix_secure)
    if needs_enrichment:
        enrichment = _enrich_with_cortex(vuln_type, url, payload)
        if enrichment:
            description_bullets = description_bullets or _coerce_bullets(enrichment.get("description"))
            impact_bullets = impact_bullets or _coerce_bullets(enrichment.get("impact"))
            remediation_bullets = remediation_bullets or _coerce_bullets(enrichment.get("remediation"))
            explanation = explanation or str(enrichment.get("exploitability") or "")
            code_fix_secure = code_fix_secure or str(enrichment.get("code_fix") or "")

    # Evidence — captured traffic only. Never invent.
    evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
    http_request = str(_first_present(raw, "http_request", "request") or evidence.get("request") or "")
    http_response = str(_first_present(raw, "http_response", "response") or evidence.get("response") or "")
    reproduction_curl = str(_first_present(raw, "reproduction_curl", "curl", "poc") or evidence.get("curl") or "")
    payload_specs = _first_present(raw, "payload_specs", "payloads")
    if payload_specs is None:
        payload_specs = [payload] if payload else []

    return {
        "name": str(_first_present(raw, "name") or vuln_type.replace("_", " ").title()),
        "severity": severity,
        "cwe": cwe,
        "cvss_score": round(float(cvss_score), 1),
        "cvss_severity": cvss_severity,
        "threat_score": threat_score,
        "category": _category_for(vuln_type),
        "description": description_bullets,
        "impact_bullets": impact_bullets,
        "explanation": explanation,
        "forensic": forensic,
        "payload_specs": payload_specs if isinstance(payload_specs, list) else [str(payload_specs)],
        "reproduction_curl": reproduction_curl or _PLACEHOLDER,
        "http_request": http_request or _PLACEHOLDER,
        "http_response": http_response or _PLACEHOLDER,
        "remediation_bullets": remediation_bullets,
        "code_fix_vulnerable": code_fix_vulnerable,
        "code_fix_secure": code_fix_secure,
        "agent_confirmed": str(_first_present(raw, "agent_confirmed", "agent", "validated_by", "source") or ""),
        "timestamp": str(_first_present(raw, "timestamp", "created_at", "ts") or ""),
    }
