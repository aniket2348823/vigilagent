"""
FORENSIC LEARNING BRIDGE
Connects forensic evidence collection with the continuous learning engine.

Responsibilities (deep-system-integration spec §8 / §13.6-13.10):
  • analyze_evidence_quality   — score the completeness of an evidence bundle
                                 against a per-vuln-type requirement map
  • learn_evidence_requirements — record which evidence types accompany
                                 confirmed findings, building per-vuln-type
                                 value scores in the learning engine
  • adapt_evidence_collection  — return a tiered collection strategy
                                 (required / recommended / optional) by
                                 querying learned requirements

Architecture invariants honoured here:
  §9   scope-is-law      — vuln targets/hosts pulled from evidence are
                            stored as advisory metadata only; nothing in
                            this bridge ever issues a scope grant.
  §11  two-LLM exclusivity — no LLM calls. Quality scoring + adaptation
                              are pure rules + learned-pattern recall.
  §17  ≥2-signal evidence  — this bridge does NOT re-verify findings. It
                              consumes evidence the caller already gathered.
  §29.13 non-blocking      — every persistence write is dispatched via
                              ``asyncio.to_thread`` so the event loop stays
                              responsive under burst load.

Phase-1 default: ``learning_engine`` and ``forensic_collector`` may both be
``None``. The class degrades gracefully: read methods return safe defaults,
write methods become no-ops returning ``False``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger("ForensicLearningBridge")


# ----------------------------------------------------------------------
# Per-vuln-type evidence requirement map (§8.2)
# ----------------------------------------------------------------------
# Spec contract: keys are the canonical lower-case vuln_type strings used
# across the codebase; values are the set of evidence-type tokens that must
# be present for an evidence bundle to be considered "complete" for that
# vulnerability class.
#
# Lookup is case-insensitive (we lower the incoming vuln_type). Unknown
# vuln_types fall back to the ``_DEFAULT`` entry — we still expect at least
# a request/response pair so the finding is reproducible.
# ----------------------------------------------------------------------
_EVIDENCE_TYPE_MAP: dict[str, set[str]] = {
    "xss": {"screenshot", "dom_snapshot", "console_log"},
    "sqli": {"request_response", "differential", "timing"},
    "_DEFAULT": {"request_response"},
}


def _required_types_for(vuln_type: str | None) -> set[str]:
    """Return the required evidence-type set for ``vuln_type`` (case-insensitive)."""
    if not isinstance(vuln_type, str) or not vuln_type.strip():
        return set(_EVIDENCE_TYPE_MAP["_DEFAULT"])
    return set(_EVIDENCE_TYPE_MAP.get(vuln_type.strip().lower(), _EVIDENCE_TYPE_MAP["_DEFAULT"]))


class ForensicLearningBridge:
    """Bridge between forensic evidence collection and the learning engine.

    The bridge is a thin coordinator. It owns no pattern store of its own —
    every learned signal is written through ``learning_engine.patterns``
    using the ``pattern_type="evidence_requirement"`` row schema. This keeps
    the learning surface unified (§14: shared memory and knowledge stores).
    """

    # Quality scoring weights — exposed as a class attribute so tests /
    # operators can introspect the metric without monkey-patching.
    EVIDENCE_QUALITY_METRICS: dict[str, float] = {
        # Base score = (# present required types) / (# required types)
        "completeness_weight": 1.0,
        # Per-extra-type bonus capped so completeness still dominates.
        "extra_type_bonus": 0.05,
        "extra_type_bonus_cap": 0.20,
    }

    def __init__(
        self,
        learning_engine: Any = None,
        forensic_collector: Any = None,
    ) -> None:
        # Both dependencies may be ``None`` in Phase-1; methods degrade
        # gracefully rather than raising at import or call time.
        self.learning_engine = learning_engine
        self.forensic_collector = forensic_collector
        # Local cache of the requirement map so callers can introspect it
        # (e.g. from /api/dashboard/evidence). Mirrors module-level constant.
        self.evidence_type_map: dict[str, set[str]] = {k: set(v) for k, v in _EVIDENCE_TYPE_MAP.items()}

    # ------------------------------------------------------------------
    # Task 8.2 — analyze_evidence_quality
    # ------------------------------------------------------------------
    def analyze_evidence_quality(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Score an evidence bundle against the per-vuln-type requirement map.

        Accepts two shapes for ``evidence``:
            • flat:    ``{"vuln_type": "xss", "screenshot": "...", "dom_snapshot": "..."}``
            • nested:  ``{"vuln_type": "xss", "evidence": {"screenshot": "...", ...}}``

        Returns:
            ``{"score": float in [0,1],
               "missing": List[str],   # required types not found
               "present": List[str]}`` # required types found
        """
        if not isinstance(evidence, dict):
            return {"score": 0.0, "missing": [], "present": []}

        vuln_type = evidence.get("vuln_type") or evidence.get("type")
        required = _required_types_for(vuln_type)

        # Build the set of evidence-type tokens present. We accept either
        # nested ``evidence.evidence[type]`` keys or flat ``evidence[type]``
        # keys so callers don't have to reshape upstream payloads.
        present_pool: set[str] = set()
        nested = evidence.get("evidence")
        if isinstance(nested, dict):
            present_pool.update(k for k, v in nested.items() if v)
        for key, value in evidence.items():
            if key in {"vuln_type", "type", "evidence", "scan_id"}:
                continue
            if value:
                present_pool.add(key)

        present = sorted(required & present_pool)
        missing = sorted(required - present_pool)
        extras = present_pool - required

        # Score: completeness ratio + capped bonus for extra evidence types.
        # No required types -> treat as fully satisfied (score 1.0) so we
        # don't penalise vuln classes we haven't mapped yet.
        completeness = len(present) / len(required) if required else 1.0

        bonus = min(
            self.EVIDENCE_QUALITY_METRICS["extra_type_bonus"] * len(extras),
            self.EVIDENCE_QUALITY_METRICS["extra_type_bonus_cap"],
        )
        score = max(0.0, min(1.0, completeness * self.EVIDENCE_QUALITY_METRICS["completeness_weight"] + bonus))

        return {
            "score": round(score, 4),
            "missing": missing,
            "present": present,
        }

    # ------------------------------------------------------------------
    # Task 8.4 — learn_evidence_requirements
    # ------------------------------------------------------------------
    async def learn_evidence_requirements(
        self,
        vuln_type: str,
        evidence: dict[str, Any],
        scan_id: str,
    ) -> bool:
        """Record which evidence types accompanied a finding, per vuln_type.

        For every evidence-type token present in ``evidence``, this method
        either creates or reinforces a ``pattern_type="evidence_requirement"``
        row in ``learning_engine.patterns`` keyed by ``(vuln_type, evidence_type)``.
        Each row's ``success_count`` increments on every observation so the
        resulting confidence/success_rate doubles as a value score.

        Returns ``True`` if at least one pattern row was written or
        reinforced; ``False`` on invalid input or when no learning_engine is
        attached (Phase-1 default).
        """
        if self.learning_engine is None:
            return False
        if not isinstance(vuln_type, str) or not vuln_type.strip():
            return False
        if not isinstance(evidence, dict):
            return False

        vuln_norm = vuln_type.strip().lower()

        # Collect evidence-type tokens (same dual-shape handling as
        # analyze_evidence_quality so callers can pass the same dict).
        evidence_types: set[str] = set()
        nested = evidence.get("evidence")
        if isinstance(nested, dict):
            evidence_types.update(k for k, v in nested.items() if v)
        for key, value in evidence.items():
            if key in {"vuln_type", "type", "evidence", "scan_id"}:
                continue
            if value:
                evidence_types.add(key)

        if not evidence_types:
            return False

        # Lazy import — keeps this module importable even in environments
        # where learning_engine's heavy deps (memory_store, knowledge_graph)
        # are stubbed or unavailable.
        try:
            from backend.core.learning_engine import LearningPattern
        except Exception as e:  # pragma: no cover - import path issue
            logger.warning("[ForensicBridge] LearningPattern import failed: %s", e)
            return False

        patterns_store = getattr(self.learning_engine, "patterns", None)
        if not isinstance(patterns_store, dict):
            return False

        now = time.time()
        wrote_any = False
        required_set = _required_types_for(vuln_type)

        for ev_type in sorted(evidence_types):
            pattern_data = {
                "vuln_type": vuln_norm,
                "evidence_type": ev_type,
                # Tag whether this evidence type is "required" by the static
                # map — useful when adapt_evidence_collection wants to split
                # learned signals from baseline requirements.
                "is_required_by_map": ev_type in required_set,
                "scan_id": scan_id,
                "source": "evidence_requirement",
            }
            pattern_id = self._generate_pattern_id(
                "evidence_requirement",
                {"vuln_type": vuln_norm, "evidence_type": ev_type},
            )

            existing = patterns_store.get(pattern_id)
            if existing is not None:
                existing.success_count += 1
                existing.scan_count += 1
                existing.last_seen = now
                existing.pattern_data["scan_id"] = scan_id
                if hasattr(existing, "update_confidence"):
                    existing.update_confidence()
                wrote_any = True
            else:
                pattern = LearningPattern(
                    pattern_id=pattern_id,
                    pattern_type="evidence_requirement",
                    pattern_data=pattern_data,
                    confidence=0.5,
                    success_count=1,
                    failure_count=0,
                    last_seen=now,
                    first_seen=now,
                    scan_count=1,
                )
                if hasattr(pattern, "update_confidence"):
                    pattern.update_confidence()
                patterns_store[pattern_id] = pattern
                wrote_any = True

        # Persist off the event loop (§29.13). Persistence failure is
        # logged but not propagated — learning is best-effort.
        if wrote_any:
            saver = getattr(self.learning_engine, "_save_patterns", None)
            if callable(saver):
                try:
                    await asyncio.wait_for(asyncio.to_thread(saver), timeout=15)
                except Exception as e:  # pragma: no cover - disk hiccup
                    logger.warning("[ForensicBridge] persist failed: %s", e)

        return wrote_any

    # ------------------------------------------------------------------
    # Task 8.6 — adapt_evidence_collection
    # ------------------------------------------------------------------
    def adapt_evidence_collection(self, vuln_type: str) -> dict[str, list[str]]:
        """Return a tiered evidence-collection strategy for ``vuln_type``.

        The strategy splits evidence-type tokens into three buckets:
          ``required``    — types in the static map for this vuln_type
                            (always collected)
          ``recommended`` — types with high learned value (success_rate > 0.6
                            AND success_count >= 3)
          ``optional``    — types with at least one observation but below
                            the recommended threshold

        Each bucket is sorted, de-duplicated, and disjoint (a type promoted
        to a higher tier won't reappear in a lower tier).
        """
        required = sorted(_required_types_for(vuln_type))
        recommended: list[str] = []
        optional: list[str] = []

        # Phase-1 fallback: no learning_engine -> just emit baseline required.
        patterns_store = getattr(self.learning_engine, "patterns", None) if self.learning_engine is not None else None
        if not isinstance(patterns_store, dict):
            return {"required": required, "recommended": [], "optional": []}

        vuln_norm = (vuln_type or "").strip().lower()
        seen: set[str] = set(required)

        for pattern in patterns_store.values():
            if getattr(pattern, "pattern_type", None) != "evidence_requirement":
                continue
            data = getattr(pattern, "pattern_data", {}) or {}
            if data.get("vuln_type") != vuln_norm:
                continue
            ev_type = data.get("evidence_type")
            if not ev_type or ev_type in seen:
                continue

            success_count = int(getattr(pattern, "success_count", 0) or 0)
            success_rate = float(getattr(pattern, "success_rate", 0.0) or 0.0)

            if success_rate > 0.6 and success_count >= 3:
                recommended.append(ev_type)
            elif success_count >= 1:
                optional.append(ev_type)
            seen.add(ev_type)

        recommended.sort()
        optional.sort()
        return {
            "required": required,
            "recommended": recommended,
            "optional": optional,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_pattern_id(pattern_type: str, key_data: dict[str, Any]) -> str:
        """Deterministic SHA-256-based id matching learning_engine.py's scheme."""
        import hashlib
        import json

        data_str = json.dumps(key_data, sort_keys=True, default=str)
        digest = hashlib.sha256(f"{pattern_type}:{data_str}".encode()).hexdigest()[:16]
        return f"{pattern_type}_{digest}"
