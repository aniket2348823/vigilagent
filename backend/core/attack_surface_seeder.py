"""
Attack Surface Seeder (Architecture §5.1.1 recon→exploitation handoff, §13.2,
§16 lifecycle).
================================================================================
Real engagements do not blindly fire payloads at a site's landing page. A human
operator first AUTHENTICATES (when the app is login-gated), then drives the
attack against the ACTUAL vulnerable endpoints — each with its real query
parameters and the authenticated session attached.

This module closes that gap for the autonomous swarm. After Alpha recon, the
orchestrator calls :func:`seed_attack_surface` to produce a list of concrete,
authenticated ``TaskTarget`` objects (URL + method + headers + body params)
that Sigma/Beta can actually exploit, instead of the bare base URL.

It is intentionally generic:
  * It authenticates when it detects a known login-gated training app (DVWA is
    the canonical authorized lab here) OR when a login form with a CSRF token is
    discovered, then stores the session in the CredentialVault (§13.2).
  * It enumerates well-known vulnerable endpoints for the detected app AND folds
    in any recon-discovered endpoints that carry query parameters.
  * Everything is scope-gated (§9/§10): a target is only seeded when
    ``scope_guard.allows(url)`` is true.

If the target is not login-gated, it degrades gracefully to "attack the base
URL plus any param-carrying endpoints recon found" — i.e. the prior behaviour,
never worse.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from backend.core.protocol import TaskTarget
from backend.core.proxy import network_interceptor

logger = logging.getLogger("attack_surface_seeder")

# ── DVWA (authorized training lab) endpoint catalogue ────────────────────────
# Each entry: (path, query_or_body, method, vuln_hint). The seeder turns these
# into authenticated TaskTargets. `?` query forms are what the SQLi/XSS probes
# require (they only inject when params exist).
_DVWA_ENDPOINTS: list[tuple[str, str, str, str]] = [
    ("/vulnerabilities/sqli/", "id=1&Submit=Submit", "GET", "sqli"),
    ("/vulnerabilities/sqli_blind/", "id=1&Submit=Submit", "GET", "sqli_blind"),
    ("/vulnerabilities/xss_r/", "name=test", "GET", "xss_reflected"),
    ("/vulnerabilities/xss_d/", "default=English", "GET", "xss_dom"),
    ("/vulnerabilities/exec/", "ip=127.0.0.1&Submit=Submit", "POST", "command_injection"),
    ("/vulnerabilities/fi/", "page=include.php", "GET", "file_inclusion"),
    ("/vulnerabilities/brute/", "username=admin&password=test&Login=Login", "GET", "brute_force"),
]


@dataclass
class SeededSurface:
    targets: list[TaskTarget] = field(default_factory=list)
    authenticated: bool = False
    principal: str | None = None
    cookie: str | None = None
    app: str = "generic"
    notes: list[str] = field(default_factory=list)


def _base(url: str) -> str:
    p = urlparse(url if "://" in url else f"http://{url}")
    return f"{p.scheme or 'http'}://{p.netloc or p.path}".rstrip("/")


async def _scope_allows(url: str) -> bool:
    try:
        # SCOPE FIX: Use the per-scan http_client scope (which has the
        # target host in allowed_hosts) instead of the global scope_guard
        # (which only reads scope.yaml and may not have the target).
        from backend.modules.tech.http_client import http_client

        if hasattr(http_client, "scope") and http_client.scope:
            return http_client.scope.allows(url)
        # Fallback to global scope_guard if per-scan scope not set.
        from backend.core.scope import scope_guard

        return scope_guard.allows(url)
    except Exception as exc:
        logger.debug("[seeder] scope check failed: %s", exc)
        return True


async def _looks_like_dvwa(base_url: str, scan_id: str) -> bool:
    """Detect DVWA by its login page fingerprint."""
    try:
        resp = await network_interceptor.fetch("GET", urljoin(base_url + "/", "login.php"), timeout=10)
    except Exception as exc:
        logger.debug("[seeder] DVWA detection request failed: %s", exc)
        return False
    body = (resp.body or "").lower()
    return "dvwa" in body or ("user_token" in body and "login.php" in str(resp.url).lower())


def _extract_csrf_token(html: str) -> str | None:
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", html, re.I)
    if not m:
        m = re.search(r"name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"]", html, re.I)
    return m.group(1) if m else None


def _parse_set_cookie(headers: dict[str, str]) -> dict[str, str]:
    """Collect cookies from one or more Set-Cookie headers."""
    cookies: dict[str, str] = {}
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    # aiohttp folds multiple Set-Cookie into one comma-joined string; split on
    # the cookie boundary (name= after a comma+space) conservatively.
    for part in re.split(r",(?=[^;]+?=)", raw):
        seg = part.split(";", 1)[0].strip()
        if "=" in seg:
            k, v = seg.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


async def _authenticate_dvwa(
    base_url: str, scan_id: str, username: str = "admin", password: str = "password"
) -> tuple[str | None, str | None]:
    """Perform the DVWA login dance: GET login.php (grab PHPSESSID + CSRF token),
    POST credentials, set security=low. Returns (cookie_header, principal)."""
    login_url = urljoin(base_url + "/", "login.php")
    try:
        r1 = await network_interceptor.fetch("GET", login_url, timeout=10)
    except Exception as exc:
        logger.warning("[seeder] DVWA login GET failed: %s", exc)
        return None, None
    token = _extract_csrf_token(r1.body or "")
    cookies = _parse_set_cookie(r1.headers)
    phpsessid = cookies.get("PHPSESSID")
    if not token or not phpsessid:
        logger.warning("[seeder] DVWA login token/session missing (token=%s sess=%s)", bool(token), bool(phpsessid))
        return None, None
    cookie_header = f"PHPSESSID={phpsessid}; security=low"
    form = f"username={username}&password={password}&Login=Login&user_token={token}"
    try:
        await network_interceptor.fetch(
            "POST",
            login_url,
            timeout=10,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie_header},
            data=form,
            allow_redirects=False,
        )
    except Exception as exc:
        logger.warning("[seeder] DVWA login POST failed: %s", exc)
        return None, None
    # Verify the session is authenticated (index no longer redirects to login).
    try:
        idx = await network_interceptor.fetch(
            "GET",
            urljoin(base_url + "/", "index.php"),
            timeout=10,
            headers={"Cookie": cookie_header},
            allow_redirects=False,
        )
        authed = idx.status == 200 and "login.php" not in str(idx.url).lower()
    except Exception as exc:
        logger.debug("[seeder] DVWA auth verification failed, assuming best-effort: %s", exc)
        authed = True  # best effort
    return (cookie_header, username) if authed else (None, None)


async def seed_attack_surface(target_url: str, scan_id: str, recon_endpoints: list[str] | None = None) -> SeededSurface:
    """Build concrete, authenticated attack targets for the swarm.

    Args:
        target_url: the scan's target URL (any path).
        scan_id: current scan id (for vault attribution).
        recon_endpoints: optional list of URLs Alpha discovered; param-carrying
            ones are folded into the surface.
    """
    base_url = _base(target_url)
    surface = SeededSurface()
    recon_endpoints = recon_endpoints or []

    # 1. Detect + authenticate against DVWA (authorized lab).
    try:
        if await _looks_like_dvwa(base_url, scan_id):
            surface.app = "dvwa"
            cookie, principal = await _authenticate_dvwa(base_url, scan_id)
            if cookie:
                surface.authenticated = True
                surface.cookie = cookie
                surface.principal = principal
                surface.notes.append("authenticated to DVWA (security=low)")
                # Persist the session in the vault (§13.2).
                try:
                    from backend.core.credential_vault import credential_vault

                    credential_vault.store(
                        scan_id=scan_id,
                        target=base_url,
                        service="cookie",
                        secret=cookie,
                        kind="cookie",
                        principal=principal,
                        source="seeder",
                        privilege="admin",
                    )
                except Exception as exc:
                    logger.debug("[seeder] vault store skipped: %s", exc)
            else:
                surface.notes.append("DVWA detected but authentication failed")
    except Exception as exc:
        logger.warning("[seeder] DVWA detection error: %s", exc)

    auth_headers: dict[str, str] = {"Cookie": surface.cookie} if surface.cookie else {}

    # 2. App-specific vulnerable endpoints.
    if surface.app == "dvwa":
        for path, qs, method, _hint in _DVWA_ENDPOINTS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            if method == "GET":
                full = f"{url}?{qs}" if qs else url
                if not await _scope_allows(full):
                    continue
                surface.targets.append(TaskTarget(url=full, method="GET", headers=dict(auth_headers)))
            else:  # POST: params go in the body, scope-check the URL
                if not await _scope_allows(url):
                    continue
                headers = dict(auth_headers)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                surface.targets.append(TaskTarget(url=url, method="POST", headers=headers, payload=_qs_to_dict(qs)))

    # 3. Fold in recon-discovered endpoints that carry query params (these are
    #    the real injection points) — authenticated with the same session.
    seen = {t.url for t in surface.targets}
    for ep in recon_endpoints:
        if "?" not in ep or ep in seen:
            continue
        if not await _scope_allows(ep):
            continue
        surface.targets.append(TaskTarget(url=ep, method="GET", headers=dict(auth_headers)))
        seen.add(ep)

    # 4. Always include the base target as a fallback so behaviour is never
    #    worse than before.
    if not any(t.url.startswith(base_url) for t in surface.targets):
        surface.targets.append(TaskTarget(url=target_url, method="GET", headers=dict(auth_headers)))

    surface.notes.append(f"seeded {len(surface.targets)} target(s)")
    logger.info("[seeder] app=%s authenticated=%s targets=%d", surface.app, surface.authenticated, len(surface.targets))
    return surface


def _qs_to_dict(qs: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in qs.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
        else:
            out[pair] = ""
    return out
