"""
JWT Token Cracker (Architecture §17 — evidence-based validation).

Tightened to only fire when an ACTUAL JWT is present. Previous behaviour:
the AI weakness analysis was called on any URL containing the substring
``token=`` and even on bare query strings, which produced "JWT weakness"
findings on /xss_r/?name=test and /sqli/?id=1. That was pure noise.

Now:
  * We only inspect the ``Authorization`` header, ``Cookie`` header (jwt/access_token/auth_token)
    and explicit ``token=``/``jwt=``/``access_token=`` URL parameters.
  * Whatever string is found must structurally parse as a JWT (3 base64url
    parts, header decodes to JSON with an ``alg`` field) before any further
    analysis runs.
  * The AI weakness pass only fires once a real JWT has been confirmed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

logger = logging.getLogger("JWTCracker")


def _b64url_decode(value: str) -> bytes:
    value = value.strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode())


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


# Strict JWT shape (3 base64url segments). The header MUST start with the
# canonical ``eyJ`` prefix — that is the base64url encoding of ``{"`` which
# every JWT header begins with. Without that anchor the regex matched random
# foo.bar.baz tokens (DVWA's user_token CSRF, generic short-id paths) and
# fed them into the AI weakness path which then hallucinated risk.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{0,})\b")


def parse_jwt(token: str) -> dict:
    parts = (token or "").split(".")
    if len(parts) < 2:
        return {"valid": False, "error": "JWT must have at least header and payload"}
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        if not isinstance(header, dict) or "alg" not in header:
            return {"valid": False, "error": "Header missing alg"}
        return {
            "valid": True,
            "header": header,
            "payload": payload,
            "signature": parts[2] if len(parts) > 2 else "",
            "alg": header.get("alg", ""),
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def forge_alg_none(token: str, claim_overrides: dict | None = None) -> str:
    parsed = parse_jwt(token)
    if not parsed.get("valid"):
        raise ValueError(parsed.get("error", "Invalid JWT"))
    header = dict(parsed["header"])
    payload = dict(parsed["payload"])
    header["alg"] = "none"
    payload.update(claim_overrides or {})
    return (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}."
    )


def forge_hs256(token: str, secret: str, claim_overrides: dict | None = None) -> str:
    parsed = parse_jwt(token)
    if not parsed.get("valid"):
        raise ValueError(parsed.get("error", "Invalid JWT"))
    header = dict(parsed["header"])
    payload = dict(parsed["payload"])
    header["alg"] = "HS256"
    payload.update(claim_overrides or {})
    signing_input = ".".join(
        [
            _b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
            _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
        ]
    )
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def crack_hs256_secret(token: str, candidates: list[str]) -> str | None:
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = parts[2]
    for secret in candidates:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(_b64url_encode(sig), expected):
            return secret
    return None


def _extract_jwts(target: TaskTarget) -> list[tuple[str, str]]:
    """Yield (location, token) tuples for every JWT found on this target.

    Locations:
      - "Authorization" header (Bearer X)
      - "Cookie" header (jwt=, access_token=, auth_token=)
      - URL query (?token=, ?jwt=, ?access_token=)

    Tokens that don't structurally parse as a JWT are skipped.
    """
    out: list[tuple[str, str]] = []
    headers = target.headers or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth.split(None, 1)[1].strip()
        out.append(("authorization_header", token))

    cookie = headers.get("Cookie") or headers.get("cookie") or ""
    for kv in cookie.split(";"):
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        if k.strip().lower() in ("jwt", "access_token", "auth_token", "id_token"):
            out.append(("cookie", v.strip()))

    url = target.url or ""
    if "?" in url:
        _, query = url.split("?", 1)
        for kv in query.split("&"):
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k.lower() in ("token", "jwt", "access_token", "id_token"):
                out.append(("url_query", v))

    # Filter to tokens that actually parse as JWTs.
    valid: list[tuple[str, str]] = []
    for loc, t in out:
        if _JWT_RE.search(t) and parse_jwt(t).get("valid"):
            valid.append((loc, t))
    return valid


def _response_carries_jwt(text: str) -> bool:
    """Detect a JWT in a response body or wrapped Content-Type/Set-Cookie/
    Authorization preamble. The content_boundary wrapper prefixes the body
    with the response headers, so a Set-Cookie carrying a JWT or an
    ``Authorization: Bearer eyJ...`` echo will show up here."""
    if not isinstance(text, str) or not text:
        return False
    # Fast structural check first — anything starting with the canonical
    # JWT header prefix ``eyJ`` (base64 of ``{"``) is a candidate.
    if "eyJ" not in text:
        return False
    for m in _JWT_RE.finditer(text):
        candidate = m.group(0)
        if parse_jwt(candidate).get("valid"):
            return True
    return False


def _has_any_jwt(interactions: list[tuple[TaskTarget, str]]) -> bool:
    """True iff a real JWT is observable in EITHER the request side
    (Authorization header / Cookie / URL query) of any TaskTarget OR the
    response body / wrapped headers of any captured response."""
    for target, text in interactions:
        if _extract_jwts(target):
            return True
        if isinstance(text, str) and _response_carries_jwt(text):
            return True
    return False


class JWTTokenCracker(BaseArsenalModule):
    def __init__(self):
        super().__init__()
        self.name = "JWT Token Cracker"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        return [packet.target]

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        # PRECONDITION GATE (Architecture §17, §25): JWTTokenCracker must only
        # confirm when an ACTUAL JWT is present somewhere we can see — request
        # headers/cookies/url, response Authorization header, response body, or
        # a Set-Cookie carrying a JWT-named cookie. No JWT in sight ⇒ this
        # endpoint is not in scope for this module and we return zero
        # vulnerabilities. JWTTokenCracker MUST NOT emit VULN_CONFIRMED on
        # bare /xss_r/?name=test, /sqli/?id=1, /exec/, /fi/, /brute/, etc.
        if not _has_any_jwt(interactions):
            return []

        vulns: list[Vulnerability] = []
        seen_tokens: set[str] = set()

        for target, _text in interactions:
            for location, token in _extract_jwts(target):
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                parsed = parse_jwt(token)
                if not parsed.get("valid"):
                    continue

                # Signal 1: token transported in URL (always exposed via logs/referrer).
                if location == "url_query":
                    vulns.append(
                        Vulnerability(
                            name="JWT Exposed in URL",
                            severity="HIGH",
                            description="JWT carried as a query parameter — leaks via logs, "
                            "referrers, browser history, and bookmarks.",
                            evidence=f"Token in URL: {target.url}",
                            remediation="Move JWT to the Authorization header or HttpOnly cookie.",
                        )
                    )

                # Signal 2: alg=none accepted (tested by forging and submitting).
                alg = str(parsed.get("alg", "")).lower()
                if alg == "none":
                    vulns.append(
                        Vulnerability(
                            name="JWT alg=none Accepted",
                            severity="CRITICAL",
                            description="Token advertises alg=none — server must NEVER accept this "
                            "for an authenticated session.",
                            evidence=f"JWT header: {parsed.get('header')}",
                            remediation="Reject unsigned JWTs. Pin accepted algorithms server-side.",
                        )
                    )

                # Signal 3: weak HMAC secret cracked offline.
                weak = crack_hs256_secret(
                    token,
                    [
                        "secret",
                        "password",
                        "admin",
                        "jwt",
                        "changeme",
                        "123456",
                        "default",
                        "test",
                        "key",
                        "vigilagent",
                    ],
                )
                if weak:
                    vulns.append(
                        Vulnerability(
                            name="Weak JWT HS256 Secret",
                            severity="HIGH",
                            description="JWT signature validated against a common weak HMAC secret.",
                            evidence=f"Recovered weak secret candidate: {weak}",
                            remediation="Rotate JWT signing keys to high-entropy secrets or asymmetric signing.",
                        )
                    )

                # AI weakness pass: only when we actually have a real JWT.
                try:
                    from backend.ai.cortex import get_cortex_engine

                    cortex = get_cortex_engine()
                    jwt_analysis = await cortex.analyze_jwt_weakness(token=token, url=target.url)
                except Exception as exc:
                    logger.debug("[JWTCracker] AI JWT weakness analysis failed: %s", exc)
                    jwt_analysis = None

                weaknesses = (jwt_analysis or {}).get("weaknesses") or []
                # Require AI to return at least 2 distinct named weaknesses AND
                # a risk score above 60 — this gates out the noisy single-line
                # "missing_claims"-style false positives the LLM emits on any
                # token shape it sees.
                risk = int((jwt_analysis or {}).get("risk_score", 0) or 0)
                if len(set(weaknesses)) >= 2 and risk >= 60:
                    summary = ", ".join(sorted(set(weaknesses)))
                    recs = (jwt_analysis or {}).get("recommendations") or []
                    vulns.append(
                        Vulnerability(
                            name=f"JWT Weakness: {summary}",
                            severity="HIGH" if risk > 75 else "MEDIUM",
                            description=f"AI-confirmed JWT weaknesses (risk={risk}): {summary}.",
                            evidence=f"Weaknesses: {weaknesses}; risk_score={risk}",
                            remediation=recs[0] if recs else "Implement RS256 JWT validation.",
                        )
                    )

        # WRONG-CLASS SUPPRESSION (Architecture §17, §25): if any captured
        # response body clearly belongs to ANOTHER vulnerability class
        # (SQL error, /etc/passwd line, executable XSS reflection, CMDI
        # output) and DOESN'T also carry a JWT marker, drop the JWT findings
        # rather than confirming. The token we saw is then almost certainly
        # the seeder's auth cookie — not the vuln of the page.
        if vulns:
            from backend.modules.evidence import classify_response_evidence

            wrong_class = False
            for _t, text in interactions:
                if not isinstance(text, str):
                    continue
                classes = classify_response_evidence(text)
                if classes and "JWT" not in classes:
                    wrong_class = True
                    break
            if wrong_class:
                return []

        return vulns
