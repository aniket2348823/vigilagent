"""
Differential Evidence Helper for arsenal modules (Architecture §9, §17, §29.6)
================================================================================
Replaces naive substring detection (e.g. `if "admin" in text.lower()`) with
differential analysis requiring multiple independent signals to agree, via the
MultiLayerVerifier. A finding is only emitted when >= 2 signals agree
(Architecture §9.3, §17 verification model).

Modules receive `interactions: list[tuple[TaskTarget, str]]`. By convention the
FIRST interaction is the baseline/original request and subsequent ones are the
injected/test requests (this matches how Doppelganger and the workers build
their target lists). When a richer object with a status code is available we use
it; otherwise we compare response bodies structurally.

Also exposes ``looks_like_class`` and ``classify_response_evidence``: a shared
"wrong-class suppression" guard. Each arsenal module declares the
vulnerability class it is supposed to confirm (SQLI, XSS, CMDI, LFI, JWT, ...).
If the response body's evidence signature CLEARLY belongs to a different class
(e.g. an SQL error pattern or a `/etc/passwd` line in a body the JWT module is
inspecting), the finding is dropped rather than confirmed. This implements
Architecture §17 (evidence-based) and §25 ("no fake intelligence: false
positives suppress, never fabricate").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from backend.core.exploit_engine import MultiLayerVerifier


@dataclass
class DiffEvidence:
    verified: bool
    confidence: int
    signals: int
    summary: str = ""


def _status_of(obj: Any) -> int:
    if isinstance(obj, dict):
        return int(obj.get("status", obj.get("status_code", 0)) or 0)
    return int(getattr(obj, "status", getattr(obj, "status_code", 0)) or 0)


def differential(
    baseline_text: str, test_text: str, *, baseline_status: int = 200, test_status: int = 200
) -> DiffEvidence:
    """Compare a baseline response against a test response.

    Returns DiffEvidence; ``verified`` is True only when the MultiLayerVerifier
    finds >= 2 independent signals (status divergence, length delta, Jaccard
    < 0.85, new sensitive keyword, JSON structural diff)."""
    verified, confidence, signals = MultiLayerVerifier.verify(
        {"status": baseline_status, "response": baseline_text or ""},
        {"status": test_status, "body": test_text or ""},
    )
    summary = (
        f"differential signals={signals} confidence={confidence}% "
        f"(status {baseline_status}->{test_status}, "
        f"len {len(baseline_text or '')}->{len(test_text or '')})"
    )
    return DiffEvidence(verified=verified, confidence=confidence, signals=signals, summary=summary)


def first_baseline(interactions: list[tuple[Any, str]]) -> tuple[Any, str] | None:
    """Return the baseline (first) interaction, or None if empty."""
    return interactions[0] if interactions else None


def confirm_against_baseline(interactions: list[tuple[Any, str]], index: int) -> DiffEvidence:
    """Confirm the interaction at ``index`` differs materially from the baseline
    (index 0). Returns an unverified DiffEvidence when there's no baseline or the
    index is the baseline itself."""
    if not interactions or index <= 0 or index >= len(interactions):
        return DiffEvidence(False, 0, 0, "no baseline to compare")
    _btarget, btext = interactions[0]
    _ttarget, ttext = interactions[index]
    return differential(btext if isinstance(btext, str) else "", ttext if isinstance(ttext, str) else "")


# ── Logic-flaw confirmation (Architecture §9.3, §17) ──────────────────────────
# Logic modules (mass assignment, workflow bypass, financial) often lack a clean
# baseline. We still require >= 2 independent signals to agree before confirming:
#   (1) a positive/success marker is present,
#   (2) NO denial/error marker is present,
#   (3) optionally, the injected payload value is reflected in the response.

_DENIAL_MARKERS = [
    "denied",
    "forbidden",
    "unauthorized",
    "not allowed",
    "error",
    "invalid",
    "failed",
    "must be",
    "cannot",
    "login required",
    "403",
    "401",
    "validation",
    "exception",
    "bad request",
]


def logic_confirm(text: str, *, positive_markers: list[str], reflected: str | None = None) -> DiffEvidence:
    """Confirm a logic-flaw response using >= 2 independent signals."""
    low = (text or "").lower()
    signals = 0
    detail = []

    has_positive = any(m in low for m in positive_markers)
    if has_positive:
        signals += 1
        detail.append("positive_marker")

    no_denial = not any(m in low for m in _DENIAL_MARKERS)
    if no_denial:
        signals += 1
        detail.append("no_denial_marker")

    if reflected and str(reflected).lower() in low:
        signals += 1
        detail.append("payload_reflected")

    verified = has_positive and signals >= 2
    confidence = min(signals * 30, 100)
    return DiffEvidence(
        verified=verified,
        confidence=confidence,
        signals=signals,
        summary=f"logic signals={signals} [{', '.join(detail)}]",
    )


# ── Wrong-class suppression (Architecture §17, §25) ──────────────────────────
# When a module is dispatched against an endpoint whose response evidence
# clearly belongs to a different vuln class, do NOT let the module confirm.
# This is the cheap, deterministic guard that catches the false-positive
# class confusions ("TECH_JWT confirmed on /sqli/", "LOGIC_SKIPPER confirmed
# on /brute/", ...). Each module passes its declared class via
# ``looks_like_class``; if the response body looks like another class we drop
# the finding.

# Stable canonical class strings (Architecture §18, §29.6). Modules and the
# orchestrator share this vocabulary; do NOT introduce parallel synonyms.
VULN_CLASSES: tuple[str, ...] = (
    "SQLI",
    "XSS",
    "CMDI",
    "LFI",
    "BRUTE_FORCE",
    "JWT",
    "IDOR",
    "AUTH_BYPASS",
    "MASS_ASSIGNMENT",
    "WORKFLOW_BYPASS",
    "RACE_CONDITION",
    "FINANCIAL",
    "GENERIC",
)

# Module-id (lowercase) → declared class. Used by the orchestrator/Sigma when
# stamping events and by ``looks_like_class`` to validate that the module is
# allowed to confirm given the response evidence.
MODULE_TO_CLASS: dict[str, str] = {
    "tech_sqli": "SQLI",
    "tech_xss": "XSS",
    "tech_fuzzer": "XSS",  # the legacy fuzzer mainly fires on XSS-style reflection
    "tech_cmdi": "CMDI",
    "tech_lfi": "LFI",
    "tech_jwt": "JWT",
    "tech_auth_bypass": "AUTH_BYPASS",
    "logic_doppelganger": "IDOR",
    "logic_escalator": "MASS_ASSIGNMENT",
    "logic_skipper": "WORKFLOW_BYPASS",
    "logic_chronomancer": "RACE_CONDITION",
    "logic_tycoon": "FINANCIAL",
}

# Signatures that strongly indicate a SPECIFIC class is present. These are
# deterministic regex matches; anything matched here is "definitely class X"
# and short-circuits any confirmation by a module of a DIFFERENT class.
_CLASS_SIGNATURES: dict[str, tuple[re.Pattern[str], ...]] = {
    "SQLI": (
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"sqlstate\[", re.I),
        re.compile(r"warning:\s*mysql_", re.I),
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"ora-\d{4,}", re.I),
        re.compile(r"odbc.*driver", re.I),
        re.compile(r"sqlite3?::", re.I),
        re.compile(r"native client.*sql", re.I),
    ),
    "XSS": (
        # Sentinel reflected verbatim inside an executable HTML context
        re.compile(r"<script[^>]*>[^<]*vgvg789", re.I),
        re.compile(r"on[a-z]+\s*=\s*['\"][^'\"]*vgvg789", re.I),
        re.compile(r"<svg[^>]*onload[^>]*vgvg789", re.I),
    ),
    "CMDI": (
        re.compile(r"uid=\d+\([a-z_][a-z0-9_-]*\)"),
        re.compile(
            r"\bLinux\s+\S+\s+\S+",
        ),
        re.compile(r"VIGIL49ECHO"),
        re.compile(r"(?i)\bnt authority\\\\system\b"),
    ),
    "LFI": (
        re.compile(r"^(root|daemon|nobody):[x*!]:\d+:\d+:", re.M),
        re.compile(r"\[(boot\s*loader|fonts|extensions)\]", re.I),
        re.compile(r"failed to open stream.*\.\./", re.I),
        re.compile(r"<\?php\s", re.I),  # raw PHP source via wrapper
    ),
    "JWT": (
        # Real JWT shape (header.payload.signature, base64url-decodable header)
        re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{0,})\b"),
    ),
}


def classify_response_evidence(text: str) -> set[str]:
    """Return the set of vuln classes whose deterministic signatures match in
    ``text``. Empty set means "no class-specific evidence visible"."""
    if not text:
        return set()
    found: set[str] = set()
    for cls, patterns in _CLASS_SIGNATURES.items():
        for p in patterns:
            if p.search(text):
                found.add(cls)
                break
    return found


def looks_like_class(text: str, *, declared_class: str, compatible_classes: tuple[str, ...] = ()) -> bool:
    """Return True iff the response evidence does NOT clearly belong to a
    different vuln class than ``declared_class``.

    Behaviour:
      * If no class-specific evidence is visible, return True (module may
        confirm based on its own signals).
      * If the evidence matches ``declared_class`` (or one of the
        ``compatible_classes`` allow-listed by the caller), return True.
      * If the evidence matches ANOTHER class only, return False — the module
        has been pointed at the wrong endpoint type and must drop its finding
        rather than fabricate one (Architecture §25).
    """
    if not declared_class:
        return True
    found = classify_response_evidence(text)
    if not found:
        return True
    allow = {declared_class.upper(), *(c.upper() for c in compatible_classes)}
    return bool(found & allow)


# URL-shape preconditions used by logic modules. The seeder dispatches every
# module against every authenticated endpoint, so the modules MUST self-gate
# on URL shape to avoid Skipper firing on /brute/ etc.
_URL_HINTS: dict[str, tuple[str, ...]] = {
    "WORKFLOW_BYPASS": (
        "checkout",
        "payment",
        "confirm",
        "complete",
        "order",
        "review",
        "wizard",
        "step",
        "thank",
        "summary",
        "finalize",
    ),
    "FINANCIAL": (
        "checkout",
        "payment",
        "order",
        "purchase",
        "billing",
        "invoice",
        "price",
        "cart",
        "amount",
        "currency",
        "transfer",
    ),
    "RACE_CONDITION": (
        "redeem",
        "coupon",
        "claim",
        "withdraw",
        "transfer",
        "buy",
        "purchase",
        "vote",
        "like",
        "follow",
        "checkout",
    ),
    "MASS_ASSIGNMENT": (
        "user",
        "users",
        "profile",
        "account",
        "register",
        "signup",
        "settings",
        "role",
        "admin",
    ),
    "IDOR": (
        "user",
        "users",
        "account",
        "profile",
        "order",
        "invoice",
        "document",
        "doc",
        "record",
        "id=",
        "uid=",
        "user_id=",
    ),
    "BRUTE_FORCE": (
        "login",
        "signin",
        "auth",
        "logon",
        "/brute",
    ),
}


def url_matches_class(url: str, *, declared_class: str) -> bool:
    """URL-shape gate for logic modules. Returns True when the URL contains
    at least one hint associated with ``declared_class``. For tech modules
    (SQLI/XSS/CMDI/LFI/JWT) the response evidence gate is the right tool;
    for logic modules the URL shape is often the only honest signal we have
    before issuing requests."""
    hints = _URL_HINTS.get((declared_class or "").upper())
    if not hints:
        # Unknown class → no URL gate (fall back to evidence-only checks).
        return True
    low = (url or "").lower()
    return any(h in low for h in hints)
