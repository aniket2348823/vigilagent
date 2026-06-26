"""
Alpha V6 Endpoint & Entity Scoring — Full production taxonomy.

Scores endpoints based on:
- Path classification (admin, auth, API, payment, upload, etc.)
- Authentication state (no auth = higher risk)
- HTTP method danger level
- Technology-specific risk factors
- Historical resurfacing bonus
- Source reliability weighting
- CDN/WAF penalty
- Parameter type analysis (IDOR, file upload, redirect)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.agents.alpha_recon.models import EndpointFinding

# ── Base Scores by Endpoint Classification ────────────────────

BASE_SCORES: dict[str, int] = {
    "ADMIN_ENDPOINT": 92,
    "AUTH_ENDPOINT": 87,
    "PAYMENT_ENDPOINT": 85,
    "API_ID_ENDPOINT": 82,
    "UPLOAD_ENDPOINT": 80,
    "FILE_ENDPOINT": 78,
    "DATA_ENDPOINT": 72,
    "GRAPHQL_ENDPOINT": 75,
    "DEBUG_ENDPOINT": 90,
    "CONFIG_ENDPOINT": 88,
    "INTERNAL_ENDPOINT": 85,
    "REDIRECT_ENDPOINT": 65,
    "SEARCH_ENDPOINT": 60,
    "WEBHOOK_ENDPOINT": 70,
    "API_ENDPOINT": 55,
    "FORM_ENDPOINT": 50,
    "JS_FILE": 22,
    "STATIC": 8,
    "MEDIA": 5,
    "UNKNOWN": 18,
}


# ── Parameter Risk Analysis ───────────────────────────────────

PARAM_RISK_BOOSTS: dict[str, int] = {
    "id": 12,  # Potential IDOR
    "user_id": 15,  # Direct object reference
    "account_id": 15,
    "file": 18,  # File inclusion
    "path": 18,
    "url": 20,  # SSRF
    "redirect": 18,  # Open redirect
    "callback": 16,  # SSRF/XSS
    "template": 14,  # SSTI
    "query": 12,  # SQLi
    "search": 10,  # SQLi/XSS
    "sort": 8,  # SQLi
    "order": 8,
    "filter": 8,
    "page": 5,
    "limit": 5,
    "offset": 5,
    "token": 10,  # Token exposure
    "key": 10,  # Key exposure
    "secret": 14,  # Secret exposure
    "password": 15,  # Password in URL
    "email": 8,  # Enumeration
    "username": 8,
    "admin": 12,  # Privilege escalation
    "role": 12,
    "debug": 14,  # Debug mode
    "cmd": 20,  # Command injection
    "exec": 20,
    "eval": 20,
}

# ── Technology Risk Factors ───────────────────────────────────

TECH_RISK_MAP: dict[str, int] = {
    "wordpress": 10,
    "joomla": 10,
    "drupal": 8,
    "php": 8,
    "asp.net": 6,
    "java": 5,
    "spring": 5,
    "struts": 12,  # Known for vulns
    "tomcat": 8,
    "jenkins": 12,
    "graphql": 8,
    "swagger": 6,
    "elasticsearch": 10,
    "kibana": 10,
    "phpmyadmin": 15,
    "adminer": 15,
    "webmin": 12,
    "redis": 10,
    "mongodb": 10,
    "couchdb": 10,
}

# ── Source Reliability Weights ────────────────────────────────

SOURCE_WEIGHTS: dict[str, float] = {
    "openapi": 1.0,
    "swagger": 1.0,
    "postman": 0.95,
    "graphql_introspection": 1.0,
    "crawled": 0.85,
    "browser_network": 0.9,
    "js_extraction": 0.8,
    "historical": 0.6,
    "brute_force": 0.5,
    "nuclei": 0.95,
    "manual": 1.0,
}


def score_endpoint(endpoint: EndpointFinding) -> EndpointFinding:
    """Score an endpoint with full production taxonomy."""
    reasons: list[str] = []
    lower_url = endpoint.url.lower()
    lower_path = (endpoint.normalized_path or endpoint.url).lower()

    # 1. Classify endpoint type
    endpoint_type = _classify_endpoint(lower_url, lower_path, endpoint)
    if endpoint_type != endpoint.endpoint_type:
        endpoint.endpoint_type = endpoint_type

    # 2. Base score
    score = BASE_SCORES.get(endpoint_type, BASE_SCORES["UNKNOWN"])
    reasons.append(f"base:{endpoint_type}:{score}")

    # 3. Authentication state
    # Low-value public asset types (static/media) are expected to be
    # unauthenticated, so the "no auth" signal carries no risk meaning for them.
    _low_value_types = {"STATIC", "MEDIA"}
    if endpoint_type in _low_value_types:
        pass
    elif not endpoint.auth_required and endpoint.status_code not in {401, 403}:
        score += 20
        reasons.append("no_auth_observed:+20")
    elif endpoint.status_code in {401, 403}:
        score += 8  # Still interesting — broken access control testing
        reasons.append("auth_required_confirmable:+8")

    # 4. Parameter risk analysis
    param_boost = 0
    for param in endpoint.parameters:
        pname = param.name.lower()
        for risk_param, boost in PARAM_RISK_BOOSTS.items():
            if risk_param in pname:
                param_boost = max(param_boost, boost)
                reasons.append(f"risky_param:{param.name}:+{boost}")
                break
        if param.value_type in {"numeric", "uuid"} and param_boost < 12:
            param_boost = 12
            reasons.append(f"id_param:{param.name}:+12")
    score += param_boost

    # 5. Schema-backed endpoints
    source_lower = endpoint.source.lower()
    for src_key, weight in SOURCE_WEIGHTS.items():
        if src_key in source_lower:
            if weight >= 0.9:
                bonus = 15
                score += bonus
                reasons.append(f"high_confidence_source:{src_key}:+{bonus}")
            elif weight >= 0.7:
                bonus = 8
                score += bonus
                reasons.append(f"medium_confidence_source:{src_key}:+{bonus}")
            break

    # 6. Historical resurfacing
    if "historical" in source_lower:
        score += 15
        reasons.append("historical_resurfaced:+15")

    # 7. Dangerous HTTP methods
    method = endpoint.method.upper()
    if method in {"PUT", "DELETE", "PATCH"}:
        score += 8
        reasons.append(f"dangerous_method:{method}:+8")
    elif method == "POST":
        score += 3
        reasons.append("post_method:+3")
    elif method == "OPTIONS":
        score += 2
        reasons.append("options_method:+2")

    # 8. Technology risk boost
    tech_boost = 0
    for tech in endpoint.technologies:
        tech_lower = tech.lower()
        for tech_key, boost in TECH_RISK_MAP.items():
            if tech_key in tech_lower:
                tech_boost = max(tech_boost, boost)
    if tech_boost:
        score += tech_boost
        reasons.append(f"technology_risk:+{tech_boost}")

    # 9. CDN/WAF penalty
    waf_detected = any(
        waf in tech.lower()
        for tech in endpoint.technologies
        for waf in ("cloudflare", "akamai", "incapsula", "imperva", "aws waf", "sucuri", "barracuda", "f5")
    )
    if waf_detected:
        score -= 12
        reasons.append("waf_detected:-12")

    # 10. Response indicators
    if endpoint.status_code == 200 and endpoint.content_length and endpoint.content_length > 0:
        score += 3
        reasons.append("valid_response:+3")
    elif endpoint.status_code in {500, 502, 503}:
        score += 5
        reasons.append(f"server_error:{endpoint.status_code}:+5")

    # 11. Multiple sources bonus
    if hasattr(endpoint, "sources") and len(getattr(endpoint, "sources", [])) > 1:
        multi_bonus = min(10, len(endpoint.sources) * 3)
        score += multi_bonus
        reasons.append(f"multi_source_confirmed:+{multi_bonus}")

    # Clamp
    endpoint.priority_score = max(0, min(100, score))
    endpoint.score_reasons = reasons
    return endpoint


def _classify_endpoint(lower_url: str, lower_path: str, endpoint: EndpointFinding) -> str:
    """Classify endpoint type from URL patterns."""
    # Debug/config endpoints (highest risk)
    if any(
        p in lower_path
        for p in ["/debug", "/trace", "/actuator", "/health", "/metrics", "/info", "/_debug", "/__debug"]
    ):
        return "DEBUG_ENDPOINT"
    if any(
        p in lower_path for p in [".env", ".config", "/config", "/.git", "/wp-config", "/settings", "/configuration"]
    ):
        return "CONFIG_ENDPOINT"
    if any(p in lower_path for p in ["/internal", "/_internal", "/private", "/__"]):
        return "INTERNAL_ENDPOINT"

    # Admin endpoints
    if any(
        p in lower_path
        for p in ["/admin", "/dashboard", "/manage", "/console", "/panel", "/backoffice", "/cpanel", "/wp-admin"]
    ):
        return "ADMIN_ENDPOINT"

    # Auth endpoints
    if any(
        p in lower_path
        for p in [
            "/login",
            "/auth",
            "/token",
            "/oauth",
            "/session",
            "/signin",
            "/signup",
            "/register",
            "/logout",
            "/password",
            "/reset",
            "/verify",
            "/2fa",
            "/mfa",
        ]
    ):
        return "AUTH_ENDPOINT"

    # Payment endpoints
    if any(
        p in lower_path
        for p in ["/payment", "/checkout", "/billing", "/invoice", "/subscription", "/stripe", "/paypal"]
    ):
        return "PAYMENT_ENDPOINT"

    # Upload endpoints
    if any(p in lower_path for p in ["/upload", "/import", "/attach", "/media/add", "/file/new"]):
        return "UPLOAD_ENDPOINT"

    # GraphQL
    if any(p in lower_path for p in ["/graphql", "/graphiql", "/gql"]):
        return "GRAPHQL_ENDPOINT"

    # Webhooks
    if any(p in lower_path for p in ["/webhook", "/callback", "/hook", "/notify"]):
        return "WEBHOOK_ENDPOINT"

    # Redirect
    if any(p in lower_path for p in ["/redirect", "/goto", "/return", "/next", "/continue"]):
        return "REDIRECT_ENDPOINT"

    # Search
    if any(p in lower_path for p in ["/search", "/find", "/lookup", "/query"]):
        return "SEARCH_ENDPOINT"

    # API with ID parameter
    has_id_param = any(param.value_type in {"numeric", "uuid"} for param in endpoint.parameters)
    if re.search(r"/api/|/rest/|/v[0-9]+/", lower_path):
        if has_id_param:
            return "API_ID_ENDPOINT"
        return "API_ENDPOINT"

    # Data endpoints
    if any(p in lower_path for p in ["/user", "/account", "/order", "/customer", "/profile", "/settings"]):
        return "DATA_ENDPOINT"

    # File endpoints
    if lower_path.endswith((".json", ".xml", ".yaml", ".yml", ".env", ".config", ".bak", ".sql", ".log", ".csv")):
        return "FILE_ENDPOINT"

    # JS files
    if lower_path.endswith((".js", ".mjs", ".jsx")):
        return "JS_FILE"

    # Static assets
    if any(p in lower_path for p in ["/static", "/assets", "/images", "/css", "/fonts", "/icons"]):
        return "STATIC"

    # Media
    if lower_path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".mp4", ".webp", ".ico")):
        return "MEDIA"

    return "UNKNOWN"


def score_entity_priority(kind: str, confidence: float, properties: dict[str, Any]) -> float:
    """Score a generic entity's priority for downstream processing."""
    kind_weights = {
        "vulnerability_candidate": 1.0,
        "secret": 0.95,
        "api_schema": 0.9,
        "graphql_endpoint": 0.9,
        "admin_panel": 0.85,
        "insecure_cookie": 0.7,
        "api_endpoint": 0.7,
        "crawled_endpoint": 0.6,
        "http_service": 0.55,
        "subdomain": 0.5,
        "open_port": 0.45,
        "ip": 0.4,
        "js_file": 0.35,
        "historical_url": 0.3,
        "certificate": 0.25,
        "dns_record": 0.2,
        "visual_artifact": 0.15,
        "favicon": 0.1,
    }
    base = kind_weights.get(kind, 0.3)
    return round(base * confidence, 3)
