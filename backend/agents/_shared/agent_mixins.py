"""Behaviour-preserving mixins shared by the agent family.

Every helper here was extracted *verbatim* from the duplicated pattern that
already existed in alpha/beta/gamma/sigma/omega/kappa/chi/zeta/delta/prism.
The intent of this module is to remove duplication WITHOUT changing behaviour:

* ``SkillRecallMixin``     — the per-target skill cache + ``skill_library``
  lookup pattern (originally re-implemented per agent as
  ``_recall_traffic_skills`` / ``_recall_browser_skills`` /
  ``_recall_dom_skills`` / ``_recall_governance_skills`` /
  ``_skill_recommendations``).
* ``SessionLifecycleMixin`` — the lazy ``aiohttp.ClientSession`` create + clean
  close pattern Sigma uses for high-concurrency network tasks; available now
  for any agent that needs a long-lived HTTP session.
* ``ControlSignalMixin``    — the uniform ``THROTTLE`` / ``STEALTH_MODE`` /
  ``RESUME`` handler that toggles ``self._throttled`` (and
  ``self._stealth_mode``) on Zeta's ``CONTROL_SIGNAL`` events.
* ``ScanContextRecorderMixin`` — the ``self.bus.get_or_create_context(...)
  .append_event(event)`` boilerplate every event handler repeated.

The mixins make NO assumptions about the agent's base class beyond what
``BaseAgent`` already provides (``self.name``, ``self.bus``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger("AgentMixins")


# ---------------------------------------------------------------------------
# Skill recall
# ---------------------------------------------------------------------------

class SkillRecallMixin:
    """Per-target skill recall with a small per-instance cache.

    Replaces the variations that lived in chi (``_recall_traffic_skills``),
    delta (``_recall_browser_skills``), prism (``_recall_dom_skills``), zeta
    (``_recall_governance_skills``) and beta (``_skill_recommendations``).
    The unified signature accepts a ``vuln_classes`` list so a single helper
    covers both the "single class" (Beta) and "multi-class fan-out" (Chi /
    Delta / Prism / Zeta) call sites.

    Subclasses don't need to do anything; the mixin lazily allocates its cache
    on first use, so it never collides with an existing ``__init__``.
    """

    # Default per-class limit, mirrors the original hand-written helpers.
    _SKILL_DEFAULT_LIMIT = 3

    # HIGH-69: Bound per-target skill cache to prevent unbounded memory growth.
    _SKILL_CACHE_MAX = 500

    def _skill_cache(self) -> dict:
        cache = getattr(self, "_skill_rec_cache", None)
        if cache is None:
            cache = {}
            # Use the standard attribute name the hand-written agents used so
            # any incidental introspection or test fixture continues to work.
            self._skill_rec_cache = cache  # type: ignore[attr-defined]
        elif len(cache) > self._SKILL_CACHE_MAX:
            # FIFO eviction: drop oldest 25% of entries
            evict_count = max(1, len(cache) // 4)
            for _ in range(evict_count):
                cache.pop(next(iter(cache)), None)
        return cache

    def recall_skills(
        self,
        target_url: str = "",
        vuln_classes: Iterable[str] | None = None,
        *,
        limit: int | None = None,
    ) -> list:
        """Return cached skill recommendations for ``target_url``.

        Parameters
        ----------
        target_url:
            The target URL the recommendations should be scoped to. May be
            empty for global recommendations (matching the legacy behaviour).
        vuln_classes:
            One or more vuln classes to fan out across. ``None`` means "ask
            for general recommendations" (matches Beta's old single-class
            shape when only one class is supplied; matches Chi/Delta/Prism/
            Zeta's multi-class shape when several are supplied).
        limit:
            Per-class limit. Defaults to 3 (the value all migrated agents
            used). When a single class is supplied with a higher limit
            (Beta used 5), pass it explicitly.
        """
        classes = tuple(vuln_classes or ())
        # Cache key matches Beta's original (target, class_tuple) shape so the
        # migrated and unmigrated paths share the cache cleanly.
        cache_key = (target_url, classes)
        cache = self._skill_cache()
        if cache_key in cache:
            return cache[cache_key]

        per_class_limit = limit if limit is not None else self._SKILL_DEFAULT_LIMIT
        recs: list = []
        try:
            from backend.core.skill_library import skill_library
            if classes:
                for vuln_class in classes:
                    recs.extend(skill_library.get_recommendations(
                        target_url=target_url, vuln_class=vuln_class,
                        limit=per_class_limit))
            else:
                recs = skill_library.get_recommendations(
                    target_url=target_url, limit=per_class_limit)
        except Exception as e:
            logger.debug("Skill recall failed: %s", e)
            recs = []

        cache[cache_key] = recs
        return recs


# ---------------------------------------------------------------------------
# Aiohttp session lifecycle
# ---------------------------------------------------------------------------

class SessionLifecycleMixin:
    """Manages a lazy persistent ``aiohttp.ClientSession``.

    Mirrors Sigma's existing pattern (``self._session = None`` -> create on
    first use -> close on stop) without changing the timeout, options, or any
    of the hot-path behaviour.
    """

    # The default Sigma uses (10s total).
    _SESSION_DEFAULT_TIMEOUT_SECONDS: float = 10.0

    async def _get_session(self):
        """Return a live ``aiohttp.ClientSession``, creating it on demand."""
        import aiohttp  # local import keeps this dependency optional
        session = getattr(self, "_session", None)
        if session is None or session.closed:
            timeout = aiohttp.ClientTimeout(total=self._SESSION_DEFAULT_TIMEOUT_SECONDS)
            session = aiohttp.ClientSession(timeout=timeout)
            self._session = session  # type: ignore[attr-defined]
        return session

    async def _close_session(self) -> None:
        """Close the persistent session if one was opened."""
        session = getattr(self, "_session", None)
        if session is not None and not session.closed:
            try:
                await session.close()
            except Exception as e:
                # Closing must never raise during agent shutdown.
                logger.debug("Session close failed (non-fatal): %s", e)
        # Leave the attribute as None so a later call creates a fresh session.
        self._session = None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Zeta control-signal handling
# ---------------------------------------------------------------------------

class ControlSignalMixin:
    """Uniform handler for Zeta's ``CONTROL_SIGNAL`` events.

    Behaviour matches the inline handler that previously lived on Alpha, Beta
    and Sigma: ``THROTTLE`` and ``STEALTH_MODE`` set ``self._throttled = True``
    (and ``STEALTH_MODE`` additionally sets ``self._stealth_mode = True``);
    ``RESUME`` clears both flags. The verbose log messages match the existing
    formatting so dashboards/grep heuristics keep working.
    """

    async def handle_control_signal(self, event) -> None:
        """Toggle throttle / stealth flags on a ``CONTROL_SIGNAL`` event."""
        signal = ""
        try:
            signal = event.payload.get("signal", "")
        except Exception as e:
            logger.debug("Control signal extraction failed: %s", e)
            signal = ""

        if signal in ("THROTTLE", "STEALTH_MODE"):
            self._throttled = True  # type: ignore[attr-defined]
            if signal == "STEALTH_MODE":
                self._stealth_mode = True  # type: ignore[attr-defined]
            logger.info(
                "[%s] Governance: %s received. Throttling activity.",
                getattr(self, 'name', 'agent'), signal
            )
        elif signal == "RESUME":
            self._throttled = False  # type: ignore[attr-defined]
            self._stealth_mode = False  # type: ignore[attr-defined]
            logger.info(
                "[%s] Governance: RESUME received. Activity unpaused.",
                getattr(self, 'name', 'agent')
            )

    def subscribe_control(self, bus) -> None:
        """Subscribe ``handle_control_signal`` to ``CONTROL_SIGNAL`` events.

        Equivalent to the explicit ``bus.subscribe(EventType.CONTROL_SIGNAL,
        self.handle_control_signal)`` line each migrated agent used to write
        in ``setup``.
        """
        # Local import keeps this module side-effect-free at import time.
        from backend.core.hive import EventType
        bus.subscribe(EventType.CONTROL_SIGNAL, self.handle_control_signal)


# ---------------------------------------------------------------------------
# ScanContext recording
# ---------------------------------------------------------------------------

class ScanContextRecorderMixin:
    """Encapsulates the ``get_or_create_context().append_event()`` boilerplate.

    Every event handler that wanted transcript causality used to write three
    lines (``hasattr`` guard, ``get_or_create_context``, ``append_event``).
    ``record(event)`` collapses that to a single call and is a true no-op when
    the bus does not expose ``get_or_create_context`` (for tests/stubs).
    """

    def record(self, event: Any) -> None:
        bus = getattr(self, "bus", None)
        if bus is None or not hasattr(bus, "get_or_create_context"):
            return
        try:
            scan_id = getattr(event, "scan_id", "GLOBAL") or "GLOBAL"
            ctx = bus.get_or_create_context(scan_id)
            if ctx is not None and hasattr(ctx, "append_event"):
                ctx.append_event(event)
        except Exception as e:
            # Recording must never raise — original inline blocks were also
            # wrapped behind a hasattr-guard that swallowed context errors.
            logger.debug("ScanContext recording failed: %s", e)
