from __future__ import annotations
import logging
"""
Vigilagent Iteration Budget (Architecture §5, §29.3, §29.13)
================================================================================
A thread-safe budget primitive that bounds loops, tool calls, LLM calls, and
child agents. Adopted from the Hermes `agent/iteration_budget.py` pattern.

Core rules (Architecture §5, §29.14):
  - Every agent, child agent, worker, tool call, and skill run consumes budget.
  - A child budget is INDEPENDENT: a child can never drain the parent's budget.
  - When exhausted, consume() returns False so callers stop instead of looping.

Per-role defaults are loaded from config/budgets.yaml.
"""

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml  # type: ignore
except Exception as _yaml_exc:  # pragma: no cover - yaml is a standard dependency
    import logging as _log
    _log.getLogger(__name__).debug("PyYAML not available: %s", _yaml_exc)
    yaml = None  # type: ignore


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUDGETS_FILE = _PROJECT_ROOT / "config" / "budgets.yaml"

# Fallback defaults if config/budgets.yaml is missing (Architecture §3.5).
_DEFAULT_BUDGETS: dict[str, int] = {
    "campaign": 200,
    "commander": 90,
    "child": 50,
    "skill_run": 20,
    "tool_run": 1,
}


class IterationBudget:
    """Thread-safe consumable budget with independent child budgets."""

    def __init__(self, max_total: int, *, label: str = "budget") -> None:
        if max_total < 0:
            raise ValueError("max_total must be >= 0")
        self._max_total = int(max_total)
        self._remaining = int(max_total)
        self._label = label
        self._lock = threading.Lock()
        self._consumed_total = 0

    @property
    def label(self) -> str:
        return self._label

    @property
    def max_total(self) -> int:
        return self._max_total

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._remaining

    @property
    def consumed(self) -> int:
        with self._lock:
            return self._consumed_total

    def consume(self, n: int = 1) -> bool:
        """Consume ``n`` units. Returns False (without going negative) if the
        budget cannot satisfy the request."""
        if n <= 0:
            return True
        with self._lock:
            if self._remaining < n:
                return False
            self._remaining -= n
            self._consumed_total += n
            return True

    def refund(self, n: int = 1) -> None:
        """Refund units (e.g. for LLM-only / no-op turns), capped at max_total."""
        if n <= 0:
            return
        with self._lock:
            self._remaining = min(self._max_total, self._remaining + n)
            self._consumed_total = max(0, self._consumed_total - n)

    def exhausted(self) -> bool:
        with self._lock:
            return self._remaining <= 0

    def child(self, max_total: int, *, label: str | None = None) -> "IterationBudget":
        """Create an INDEPENDENT child budget. Consuming the child never affects
        this (parent) budget (Architecture §5, Property: budget boundedness)."""
        return IterationBudget(max_total, label=label or f"{self._label}.child")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "label": self._label,
                "max_total": self._max_total,
                "remaining": self._remaining,
                "consumed": self._consumed_total,
            }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        snap = self.snapshot()
        return (
            f"IterationBudget(label={snap['label']!r}, "
            f"remaining={snap['remaining']}/{snap['max_total']})"
        )


@dataclass
class BudgetConfig:
    """Loaded per-role budget configuration."""

    roles: dict[str, int] = field(default_factory=lambda: dict(_DEFAULT_BUDGETS))
    phases: dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "BudgetConfig":
        cfg_path = Path(path) if path else _BUDGETS_FILE
        roles = dict(_DEFAULT_BUDGETS)
        phases: dict[str, int] = {}
        if yaml is not None and cfg_path.exists():
            try:
                data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                roles.update({k: int(v) for k, v in (data.get("budgets") or {}).items()})
                phases.update({k: int(v) for k, v in (data.get("phases") or {}).items()})
            except Exception as exc:
                # Fail safe to defaults; never crash on a malformed config.
                import logging as _log
                _log.getLogger('IterationBudget').debug('yaml config fallback: %s', exc)
        return cls(roles=roles, phases=phases)

    def for_role(self, role: str) -> int:
        return int(self.roles.get(role, self.roles.get("child", 50)))

    def make(self, role: str, *, label: str | None = None) -> IterationBudget:
        return IterationBudget(self.for_role(role), label=label or role)


# Module-level loaded configuration (Architecture §21).
budget_config = BudgetConfig.load()


def campaign_budget(label: str = "campaign") -> IterationBudget:
    """Convenience factory for an Omega campaign-level budget."""
    return budget_config.make("campaign", label=label)
