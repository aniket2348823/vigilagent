"""
INTELLIGENT ROUTER
Routes scan work between HTTP-only, browser-only, and hybrid execution
methods, and selects the appropriate browser engine for browser tasks.

Responsibilities (deep-system-integration spec §9 / §13.1-13.5):
  • recommend_method        — return "http_only" | "browser_only" | "hybrid"
                              based on target characteristics + learned
                              method-effectiveness patterns
  • select_browser_engine   — return "openclaw" | "pinchtab" based on task
                              complexity / multi-step / stealth flags
  • learn_method_effectiveness — record (target_chars, method, success)
                              tuples in the learning engine so future
                              recommend_method calls become evidence-driven

Architecture invariants honoured here:
  §9   scope-is-law       — target characteristics (framework, content-type,
                            api hints) are advisory ONLY. They influence
                            how we scan, never what we're allowed to scan.
                            Nothing in this module emits or persists a
                            scope grant.
  §11  two-LLM exclusivity — routing is pure rule-based + learned-pattern
                              recall. No LLM calls here.
  §17  ≥2-signal evidence  — recommendations are advisory; the caller is
                              responsible for the ≥2-signal verification
                              gate before declaring a finding.
  §29.13 non-blocking      — persistence writes go through
                              ``asyncio.to_thread`` so the event loop stays
                              responsive under burst load.

Phase-1 default: ``learning_engine`` and ``browser_orchestrator`` may both
be ``None``. Read methods fall back to pure rule-based decisions; the
write method becomes a no-op returning ``False``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger("IntelligentRouter")


# ----------------------------------------------------------------------
# Static rule constants
# ----------------------------------------------------------------------
# Frameworks whose presence on a target biases us toward browser execution.
# All comparisons are case-insensitive.
_BROWSER_LEANING_FRAMEWORKS = frozenset({"react", "vue", "angular", "svelte", "next", "nuxt"})

# Content-Type tokens that imply a rendered DOM is needed.
_BROWSER_CONTENT_TYPES = ("text/html", "application/xhtml", "application/javascript", "text/javascript")

# Content-Type tokens that imply a pure HTTP/JSON API.
_HTTP_CONTENT_TYPES = ("application/json", "application/xml", "text/xml", "application/grpc")

# Complexity threshold above which OpenClaw is selected.
_OPENCLAW_COMPLEXITY_THRESHOLD = 3

# Engine constants (centralised to keep Result strings stable across tests).
ENGINE_OPENCLAW = "openclaw"
ENGINE_PINCHTAB = "pinchtab"

METHOD_HTTP_ONLY = "http_only"
METHOD_BROWSER_ONLY = "browser_only"
METHOD_HYBRID = "hybrid"


class IntelligentRouter:
    """Decision surface for HTTP-vs-browser routing and engine selection.

    The router owns no persistent state. Every learned signal is written
    through ``learning_engine.patterns`` using
    ``pattern_type="method_effectiveness"`` rows, keyed by a stable
    ``(framework, has_js, content_type)`` triple. This keeps the learning
    surface unified (§14: shared memory and knowledge stores) and avoids a
    second pattern store.
    """

    def __init__(
        self,
        learning_engine: Any = None,
        browser_orchestrator: Any = None,
    ) -> None:
        # Both deps may be ``None`` in Phase-1; methods degrade gracefully.
        self.learning_engine = learning_engine
        self.browser_orchestrator = browser_orchestrator

    # ------------------------------------------------------------------
    # Task 9.2 / 13.2 — recommend_method
    # ------------------------------------------------------------------
    def recommend_method(self, target: dict[str, Any]) -> str:
        """Recommend an execution method for ``target``.

        Returns one of ``"http_only"``, ``"browser_only"``, ``"hybrid"``.

        Decision matrix (first match wins):
          1. Learned ``method_effectiveness`` patterns with success_rate
             ≥ 0.7 and ≥ 3 observations override rules.
          2. Explicit ``no_js=True`` or framework absent + JSON content-type
             + ``api_endpoint=True``  → ``http_only``.
          3. Framework in {React, Vue, Angular, ...} OR Content-Type signals
             rendered HTML/JS                              → ``browser_only``.
          4. Has-JS but unclassified content                → ``hybrid``.
          5. Otherwise (no signals)                         → ``http_only``.
        """
        if not isinstance(target, dict):
            return METHOD_HTTP_ONLY

        chars = self._extract_target_characteristics(target)

        # 1. Learned-pattern override.
        learned = self._lookup_learned_method(chars)
        if learned is not None:
            return learned

        # 2. Pure HTTP signal: no JS, JSON API.
        if chars["no_js"]:
            return METHOD_HTTP_ONLY
        if chars["api_endpoint"] and chars["content_type_class"] == "http":
            return METHOD_HTTP_ONLY

        # 3. Browser-leaning signals.
        framework_lower = (chars["framework"] or "").lower()
        if framework_lower in _BROWSER_LEANING_FRAMEWORKS:
            return METHOD_BROWSER_ONLY
        if chars["content_type_class"] == "browser":
            return METHOD_BROWSER_ONLY

        # 4. Mixed signal — JS detected but no strong framework/content hint.
        if chars["has_js"]:
            return METHOD_HYBRID

        # 5. No signal — default to the cheapest path.
        return METHOD_HTTP_ONLY

    # ------------------------------------------------------------------
    # Task 9.4 / 13.4 — select_browser_engine
    # ------------------------------------------------------------------
    def select_browser_engine(self, task: dict[str, Any]) -> str:
        """Return ``"openclaw"`` or ``"pinchtab"`` for a browser task.

        Decision matrix (first match wins):
          1. ``stealth`` / ``stealth_required`` truthy   → ``openclaw``
          2. ``complexity`` ≥ 3                          → ``openclaw``
          3. ``multi_step`` truthy OR ``len(steps) > 1`` → ``openclaw``
          4. action in {"navigate", "token_extract",
             "screenshot", "simple_click"}              → ``pinchtab``
          5. otherwise                                   → ``pinchtab``
        """
        if not isinstance(task, dict):
            return ENGINE_PINCHTAB

        # 1. Stealth always wins — PinchTab has no stealth toolkit.
        if task.get("stealth") or task.get("stealth_required"):
            return ENGINE_OPENCLAW

        # 2. Numeric complexity.
        try:
            complexity = int(task.get("complexity", 0) or 0)
        except (TypeError, ValueError):
            complexity = 0
        if complexity >= _OPENCLAW_COMPLEXITY_THRESHOLD:
            return ENGINE_OPENCLAW

        # 3. Multi-step workflows.
        if task.get("multi_step"):
            return ENGINE_OPENCLAW
        steps = task.get("steps")
        if isinstance(steps, (list, tuple)) and len(steps) > 1:
            return ENGINE_OPENCLAW

        # 4 / 5. Simple navigation / token extraction → PinchTab.
        # We don't gate on the action whitelist explicitly — anything that
        # didn't trip the OpenClaw conditions above is by definition simple
        # enough for PinchTab. Logging the action helps diagnostics.
        action = task.get("action") or task.get("type") or "unknown"
        logger.debug("[Router] selecting PinchTab for simple action=%s", action)
        return ENGINE_PINCHTAB

    # ------------------------------------------------------------------
    # Task 9.6 — learn_method_effectiveness
    # ------------------------------------------------------------------
    async def learn_method_effectiveness(
        self,
        target_chars: dict[str, Any],
        method: str,
        success: bool,
        scan_id: str,
    ) -> bool:
        """Record an outcome for ``(target_chars, method)`` in the learning engine.

        Creates or reinforces a ``pattern_type="method_effectiveness"`` row
        keyed by a stable ``(framework, has_js, content_type_class)`` triple
        plus the method itself. Successive successes raise ``success_count``;
        failures raise ``failure_count``. Confidence is recomputed via the
        engine's ``update_confidence`` helper, so future
        ``recommend_method`` calls become evidence-driven once
        ``success_rate ≥ 0.7`` with ``success_count ≥ 3``.

        Returns ``True`` if a row was written; ``False`` on invalid input or
        when no learning_engine is attached (Phase-1 default).
        """
        if self.learning_engine is None:
            return False
        if not isinstance(target_chars, dict):
            return False
        if method not in (METHOD_HTTP_ONLY, METHOD_BROWSER_ONLY, METHOD_HYBRID):
            return False

        # Lazy import — keeps the module importable when learning_engine
        # heavy deps (memory_store, knowledge_graph) are unavailable.
        try:
            from backend.core.learning_engine import LearningPattern
        except Exception as e:  # pragma: no cover - import path issue
            logger.warning("[Router] LearningPattern import failed: %s", e)
            return False

        patterns_store = getattr(self.learning_engine, "patterns", None)
        if not isinstance(patterns_store, dict):
            return False

        chars = self._extract_target_characteristics(target_chars)
        key_triple = self._effectiveness_key(chars)
        pattern_data = {
            "framework": key_triple[0],
            "has_js": key_triple[1],
            "content_type_class": key_triple[2],
            "method": method,
            "scan_id": scan_id,
            "source": "method_effectiveness",
        }
        pattern_id = self._generate_pattern_id(
            "method_effectiveness",
            {
                "framework": key_triple[0],
                "has_js": key_triple[1],
                "content_type_class": key_triple[2],
                "method": method,
            },
        )

        now = time.time()
        existing = patterns_store.get(pattern_id)
        if existing is not None:
            if success:
                existing.success_count += 1
            else:
                existing.failure_count += 1
            existing.scan_count += 1
            existing.last_seen = now
            existing.pattern_data["scan_id"] = scan_id
            if hasattr(existing, "update_confidence"):
                existing.update_confidence()
        else:
            pattern = LearningPattern(
                pattern_id=pattern_id,
                pattern_type="method_effectiveness",
                pattern_data=pattern_data,
                confidence=0.5,
                success_count=1 if success else 0,
                failure_count=0 if success else 1,
                last_seen=now,
                first_seen=now,
                scan_count=1,
            )
            if hasattr(pattern, "update_confidence"):
                pattern.update_confidence()
            patterns_store[pattern_id] = pattern

        # Persist off the event loop (§29.13). Failure is logged, not raised.
        saver = getattr(self.learning_engine, "_save_patterns", None)
        if callable(saver):
            try:
                await asyncio.wait_for(asyncio.to_thread(saver), timeout=15)
            except Exception as e:  # pragma: no cover - disk hiccup
                logger.warning("[Router] persist failed: %s", e)

        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_target_characteristics(target: dict[str, Any]) -> dict[str, Any]:
        """Normalise a target dict into the canonical characteristic shape.

        Output keys (always present):
          framework            — Optional[str], original case preserved
          has_js               — bool
          no_js                — bool (explicit "no JS detected" signal)
          content_type_class   — "browser" | "http" | "other"
          api_endpoint         — bool
        """
        if not isinstance(target, dict):
            target = {}

        framework = target.get("framework")
        if framework is not None and not isinstance(framework, str):
            framework = str(framework)

        # has_js handling: prefer explicit signal, else infer from framework.
        has_js_raw = target.get("has_js")
        no_js_raw = target.get("no_js")
        if has_js_raw is None and no_js_raw is None and framework:
            has_js = True
            no_js = False
        else:
            has_js = bool(has_js_raw) if has_js_raw is not None else not bool(no_js_raw)
            no_js = bool(no_js_raw) if no_js_raw is not None else not has_js
            # Reconcile when both supplied and contradict — explicit wins.
            if has_js_raw is not None:
                no_js = not bool(has_js_raw)

        # Content-Type classification.
        ct_raw = target.get("content_type") or target.get("Content-Type") or ""
        ct = ct_raw.lower() if isinstance(ct_raw, str) else ""
        if any(tok in ct for tok in _BROWSER_CONTENT_TYPES):
            content_type_class = "browser"
        elif any(tok in ct for tok in _HTTP_CONTENT_TYPES):
            content_type_class = "http"
        else:
            content_type_class = "other"

        api_endpoint = bool(target.get("api_endpoint") or target.get("is_api"))
        # Strong heuristic: JSON content-type → API endpoint.
        if content_type_class == "http" and "json" in ct:
            api_endpoint = True

        return {
            "framework": framework,
            "has_js": has_js,
            "no_js": no_js,
            "content_type_class": content_type_class,
            "api_endpoint": api_endpoint,
        }

    @staticmethod
    def _effectiveness_key(chars: dict[str, Any]) -> tuple[str, bool, str]:
        """Build the stable ``(framework, has_js, content_type)`` triple.

        Framework is lower-cased and empty-string normalised so e.g. "React"
        and "react" collide on the same row. ``content_type_class`` is
        used (not raw Content-Type) so trivial drift in mime parameters
        doesn't fragment the learning store.
        """
        fw = (chars.get("framework") or "").strip().lower()
        return (fw, bool(chars.get("has_js")), chars.get("content_type_class") or "other")

    def _lookup_learned_method(self, chars: dict[str, Any]) -> str | None:
        """Return the best-supported learned method for ``chars`` or None.

        Selection rule:
          • Among ``method_effectiveness`` rows matching the characteristic
            triple, pick the one with the highest ``success_rate``.
          • Require ``success_rate ≥ 0.7`` AND ``success_count ≥ 3`` before
            overriding the rule-based decision — keeps noisy early data
            from skewing routing.
        """
        if self.learning_engine is None:
            return None
        patterns_store = getattr(self.learning_engine, "patterns", None)
        if not isinstance(patterns_store, dict):
            return None

        target_triple = self._effectiveness_key(chars)
        best: tuple[float, int, str] | None = None  # (success_rate, count, method)

        for pattern in patterns_store.values():
            if getattr(pattern, "pattern_type", None) != "method_effectiveness":
                continue
            data = getattr(pattern, "pattern_data", {}) or {}
            row_triple = (
                (data.get("framework") or "").strip().lower(),
                bool(data.get("has_js")),
                data.get("content_type_class") or "other",
            )
            if row_triple != target_triple:
                continue
            method = data.get("method")
            if method not in (METHOD_HTTP_ONLY, METHOD_BROWSER_ONLY, METHOD_HYBRID):
                continue
            success_count = int(getattr(pattern, "success_count", 0) or 0)
            success_rate = float(getattr(pattern, "success_rate", 0.0) or 0.0)
            if success_rate < 0.7 or success_count < 3:
                continue
            candidate = (success_rate, success_count, method)
            if best is None or candidate > best:
                best = candidate

        return best[2] if best is not None else None

    @staticmethod
    def _generate_pattern_id(pattern_type: str, key_data: dict[str, Any]) -> str:
        """Deterministic SHA-256-based id matching learning_engine.py's scheme."""
        import hashlib
        import json

        data_str = json.dumps(key_data, sort_keys=True, default=str)
        digest = hashlib.sha256(f"{pattern_type}:{data_str}".encode()).hexdigest()[:16]
        return f"{pattern_type}_{digest}"
