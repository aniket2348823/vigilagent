"""
AGENT HEALTH MONITOR
Tracks real-time health metrics for all agents in the hive.

This monitor:
1. Tracks performance metrics (response time, success rate, error rate)
2. Monitors resource usage (memory, CPU, task queue depth)
3. Detects anomalies (sudden performance drops, crashes)
4. Calculates health scores (0-100 scale)
5. Provides historical health trends
"""

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger("AgentHealthMonitor")

# Dedup / downgrade windows (seconds). Tuned so that when the event loop is
# stalled (Architecture §29.13) the same critical condition logs at most once
# per minute per (agent, category) and, after 120s of sustained critical
# state, downgrades to a single summary WARN per minute instead of a
# never-ending CRITICAL stream.
_CRITICAL_DEDUP_WINDOW_S = 60.0
_CRITICAL_SUSTAINED_THRESHOLD_S = 120.0
_CRITICAL_SUSTAINED_LOG_INTERVAL_S = 60.0


@dataclass
class HealthMetrics:
    """Health metrics for a single agent."""

    agent_name: str
    timestamp: float

    # Performance metrics
    response_time_ms: float = 0.0
    success_rate: float = 1.0
    error_rate: float = 0.0
    tasks_completed: int = 0
    tasks_failed: int = 0

    # Resource metrics
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    task_queue_depth: int = 0

    # Status
    is_active: bool = True
    last_heartbeat: float = 0.0
    consecutive_failures: int = 0

    # Health score (0-100)
    health_score: float = 100.0

    def calculate_health_score(self) -> float:
        """Calculate overall health score based on metrics."""
        score = 100.0

        # Penalize high error rate (max -40 points)
        if self.error_rate > 0:
            score -= min(40, self.error_rate * 100)

        # Penalize slow response time (max -20 points)
        if self.response_time_ms > 1000:
            score -= min(20, (self.response_time_ms - 1000) / 100)

        # Penalize high memory usage (max -15 points)
        if self.memory_mb > 500:
            score -= min(15, (self.memory_mb - 500) / 50)

        # Penalize high CPU usage (max -15 points)
        if self.cpu_percent > 80:
            score -= min(15, (self.cpu_percent - 80) / 2)

        # Penalize consecutive failures (max -10 points)
        score -= min(10, self.consecutive_failures * 2)

        self.health_score = max(0.0, score)
        return self.health_score


@dataclass
class BrowserHealthMetrics:
    """Browser-specific health metrics (deep-system-integration §4.1).

    Shape is fixed by the spec — extra fields would break callers that round-trip
    via :func:`asdict`. The legacy 0..100 score (used by the older
    ``BrowserHealthMonitorExtension``) is now computed by
    :func:`_legacy_browser_score_100` instead of an instance method.
    """

    active_contexts: int = 0
    context_memory_mb: float = 0.0
    page_load_time_ms: float = 0.0
    screenshot_time_ms: float = 0.0
    browser_error_rate: float = 0.0  # 0..1
    timestamp: float = field(default_factory=time.time)


def _legacy_browser_score_100(m: "BrowserHealthMetrics") -> float:
    """Legacy 0..100 browser health score for ``BrowserHealthMonitorExtension``.

    Preserved verbatim from the previous instance method so the older
    per-agent extension (and its alert thresholds at 40 / 70) keeps behaving
    identically after the dataclass shape was tightened to the §4.1 spec.
    """
    score = 100.0
    if m.active_contexts > 10:
        score -= min(30, (m.active_contexts - 10) * 3)
    if m.context_memory_mb > 1000:
        score -= min(25, (m.context_memory_mb - 1000) / 40)
    if m.page_load_time_ms > 3000:
        score -= min(20, (m.page_load_time_ms - 3000) / 200)
    if m.browser_error_rate > 0:
        score -= min(25, m.browser_error_rate * 100)
    return max(0.0, score)


@dataclass
class HealthAlert:
    """Alert for health issues."""

    agent_name: str
    severity: str  # "warning", "critical"
    issue: str
    timestamp: float
    metrics: dict[str, Any]


class AgentHealthMonitor:
    """
    Monitors health of all agents in the hive.
    Detects issues and triggers alerts for self-healing.
    """

    def __init__(self, brain_dir: str = "brain"):
        self.brain_dir = Path(brain_dir)
        self.health_dir = self.brain_dir / "health"
        self.health_dir.mkdir(parents=True, exist_ok=True)

        # Current health metrics per agent
        self.current_metrics: dict[str, HealthMetrics] = {}

        # Browser health metrics per agent
        self.browser_metrics: dict[str, BrowserHealthMetrics] = {}

        # Historical metrics (last 100 per agent)
        self.history: dict[str, deque] = {}
        self.browser_history: dict[str, deque] = {}

        # Active alerts
        self.alerts: list[HealthAlert] = []
        self._max_alerts = 2000

        # Dedup / downgrade state per (agent_name, category) key. Prevents the
        # flood of duplicate "[HealthMonitor] CRITICAL: agent_X - Critical
        # response time: ...ms" lines that appears when the event loop is
        # stalled and an agent's response_time keeps tripping the threshold.
        # Each entry tracks:
        #   first_critical_ts: when this (agent, category) first went critical
        #   last_log_ts:       last time we actually emitted a log line
        #   downgraded:        True once we've switched from per-minute
        #                      CRITICAL spam to per-minute summary WARN
        self._critical_state: dict[tuple[str, str], dict[str, float]] = {}

        # Thresholds for alerts.
        # NOTE: heartbeat_timeout is the *only* mechanism for declaring an
        # agent CRITICAL/unresponsive — see report_metrics() docstring. Keep
        # it generous (3x the agent loop's 10s heartbeat) so a single missed
        # cycle on a busy host never trips a false positive (Architecture
        # §29.13: do not starve agents with monitoring overhead).
        self.thresholds = {
            "error_rate_warning": 0.1,  # 10% error rate
            "error_rate_critical": 0.3,  # 30% error rate
            "response_time_warning": 2000,  # 2 seconds (per-task only)
            "response_time_critical": 5000,  # 5 seconds (per-task only)
            "memory_warning": 500,  # 500 MB
            "memory_critical": 1000,  # 1 GB
            "health_score_warning": 70,
            "health_score_critical": 40,
            "heartbeat_timeout": 90,  # 90s — agents heartbeat every 10s
        }

        # Process handle for resource monitoring
        self.process = psutil.Process()

    def report_metrics(self, agent_name: str, metrics: dict[str, Any]):
        """
        Report metrics from an agent.
        Called by agents periodically.

        NOTE on response_time_ms (Architecture §29.15): callers may pass
        either a real per-task response time OR a "time since last task"
        idle measurement (the BaseAgent._health_reporting_loop currently
        reports idle time as response_time_ms every 10s). To suppress the
        false-positive CRITICAL spam this caused, we only escalate
        response-time alerts when the caller explicitly opts in
        (``per_task_latency=True``) OR when we observed a real task
        completion since the last sample. Idle/keep-alive samples are
        recorded for diagnostics but never alert. Genuine unresponsiveness
        is still detected by ``check_heartbeats``.
        """
        current_time = time.time()

        # Get or create metrics
        if agent_name not in self.current_metrics:
            self.current_metrics[agent_name] = HealthMetrics(
                agent_name=agent_name, timestamp=current_time, last_heartbeat=current_time
            )
            self.history[agent_name] = deque(maxlen=100)

        agent_metrics = self.current_metrics[agent_name]
        prior_completed = agent_metrics.tasks_completed
        prior_failed = agent_metrics.tasks_failed

        # Update metrics
        agent_metrics.timestamp = current_time
        agent_metrics.last_heartbeat = current_time

        # Distinguish real per-task latency from idle "time since last task"
        # samples coming from the periodic health-reporting loop.
        explicit_idle = bool(metrics.get("idle"))
        explicit_per_task = bool(metrics.get("per_task_latency"))
        if "idle_time_ms" in metrics:
            explicit_idle = True

        if "response_time_ms" in metrics and not explicit_idle:
            agent_metrics.response_time_ms = metrics["response_time_ms"]

        if "success" in metrics:
            if metrics["success"]:
                agent_metrics.tasks_completed += 1
                agent_metrics.consecutive_failures = 0
            else:
                agent_metrics.tasks_failed += 1
                agent_metrics.consecutive_failures += 1

        if "memory_mb" in metrics:
            agent_metrics.memory_mb = metrics["memory_mb"]

        if "cpu_percent" in metrics:
            agent_metrics.cpu_percent = metrics["cpu_percent"]

        if "task_queue_depth" in metrics:
            agent_metrics.task_queue_depth = metrics["task_queue_depth"]

        # Calculate rates
        total_tasks = agent_metrics.tasks_completed + agent_metrics.tasks_failed
        if total_tasks > 0:
            agent_metrics.success_rate = agent_metrics.tasks_completed / total_tasks
            agent_metrics.error_rate = agent_metrics.tasks_failed / total_tasks

        # Calculate health score
        agent_metrics.calculate_health_score()

        # Store in history
        self.history[agent_name].append(asdict(agent_metrics))

        # Decide whether response-time alerts apply to this sample. Treat as
        # idle/keep-alive when:
        #   1) caller marked it idle, OR
        #   2) the legacy reporter passed success=True but we never saw a real
        #      task completion (BaseAgent's loop calls
        #      report_task_result -> tasks_completed++ for genuine work).
        observed_real_task = (
            agent_metrics.tasks_completed > prior_completed + 1  # +1 for the loop's success=True
            or agent_metrics.tasks_failed > prior_failed
        )
        suppress_response = explicit_idle or (not explicit_per_task and not observed_real_task)
        self._check_alerts(agent_name, agent_metrics, suppress_response_time=suppress_response)

    def report_heartbeat(self, agent_name: str):
        """Report heartbeat from agent (still alive)."""
        current_time = time.time()

        # Create metrics if they don't exist
        if agent_name not in self.current_metrics:
            self.current_metrics[agent_name] = HealthMetrics(
                agent_name=agent_name, timestamp=current_time, last_heartbeat=current_time
            )
            self.history[agent_name] = deque(maxlen=100)

        # Update heartbeat
        self.current_metrics[agent_name].last_heartbeat = current_time
        self.current_metrics[agent_name].is_active = True

    def _check_alerts(self, agent_name: str, metrics: HealthMetrics, *, suppress_response_time: bool = False):
        """Check if metrics trigger any alerts.

        suppress_response_time: when the latest sample is an idle/heartbeat
        observation (no real task happened), skip response-time alerting.
        We still track the value for diagnostics.
        """
        time.time()

        # Check error rate
        if metrics.error_rate >= self.thresholds["error_rate_critical"]:
            self._create_alert(
                agent_name,
                "critical",
                f"Critical error rate: {metrics.error_rate:.1%}",
                {"error_rate": metrics.error_rate},
                category="error_rate",
            )
        elif metrics.error_rate >= self.thresholds["error_rate_warning"]:
            self._create_alert(
                agent_name,
                "warning",
                f"High error rate: {metrics.error_rate:.1%}",
                {"error_rate": metrics.error_rate},
                category="error_rate",
            )

        # Check response time (only on real per-task samples)
        if not suppress_response_time:
            if metrics.response_time_ms >= self.thresholds["response_time_critical"]:
                self._create_alert(
                    agent_name,
                    "critical",
                    f"Critical response time: {metrics.response_time_ms:.0f}ms",
                    {"response_time_ms": metrics.response_time_ms},
                    category="response_time",
                )
            elif metrics.response_time_ms >= self.thresholds["response_time_warning"]:
                self._create_alert(
                    agent_name,
                    "warning",
                    f"Slow response time: {metrics.response_time_ms:.0f}ms",
                    {"response_time_ms": metrics.response_time_ms},
                    category="response_time",
                )

        # Check memory usage
        if metrics.memory_mb >= self.thresholds["memory_critical"]:
            self._create_alert(
                agent_name,
                "critical",
                f"Critical memory usage: {metrics.memory_mb:.0f}MB",
                {"memory_mb": metrics.memory_mb},
                category="memory",
            )
        elif metrics.memory_mb >= self.thresholds["memory_warning"]:
            self._create_alert(
                agent_name,
                "warning",
                f"High memory usage: {metrics.memory_mb:.0f}MB",
                {"memory_mb": metrics.memory_mb},
                category="memory",
            )

        # Check health score
        if metrics.health_score <= self.thresholds["health_score_critical"]:
            self._create_alert(
                agent_name,
                "critical",
                f"Critical health score: {metrics.health_score:.0f}/100",
                {"health_score": metrics.health_score},
                category="health_score",
            )
        elif metrics.health_score <= self.thresholds["health_score_warning"]:
            self._create_alert(
                agent_name,
                "warning",
                f"Low health score: {metrics.health_score:.0f}/100",
                {"health_score": metrics.health_score},
                category="health_score",
            )

        # Check consecutive failures
        if metrics.consecutive_failures >= 5:
            self._create_alert(
                agent_name,
                "critical",
                f"Agent failing repeatedly: {metrics.consecutive_failures} consecutive failures",
                {"consecutive_failures": metrics.consecutive_failures},
                category="consecutive_failures",
            )

    def _create_alert(
        self, agent_name: str, severity: str, issue: str, metrics: dict[str, Any], *, category: str | None = None
    ):
        """Create a new alert with rate-limited logging.

        Dedup behavior (Architecture §29.13: monitoring must not amplify
        backend stalls):
          - Identical (agent, category, severity) alerts log at most once
            per ``_CRITICAL_DEDUP_WINDOW_S`` (60s). The alert object is
            still appended on the *first* hit and refreshed on subsequent
            hits, so dashboards see latest metrics without log spam.
          - When a CRITICAL (agent, category) condition has persisted for
            more than ``_CRITICAL_SUSTAINED_THRESHOLD_S`` (120s), we stop
            re-logging at CRITICAL and emit a single summary WARN every
            ``_CRITICAL_SUSTAINED_LOG_INTERVAL_S`` (60s) instead. This
            avoids escalating noise once an operator has been notified.

        Falls back to issue-text dedup (legacy behavior) when no category
        is provided.
        """
        now = time.time()
        # Stable dedup key: derive from explicit category when available so
        # variations like "Critical response time: 300000ms" vs
        # "...300050ms" collapse onto a single entry. Otherwise fall back
        # to the full issue string (legacy behavior).
        cat_key = category or issue
        state_key = (agent_name, cat_key)

        alert = HealthAlert(
            agent_name=agent_name,
            severity=severity,
            issue=issue,
            timestamp=now,
            metrics=metrics,
        )

        if severity == "critical":
            state = self._critical_state.get(state_key)
            if state is None:
                # First time we've seen this critical condition — log it
                # and seed dedup state.
                self._critical_state[state_key] = {
                    "first_critical_ts": now,
                    "last_log_ts": now,
                    "downgraded": 0.0,
                }
                self.alerts.append(alert)
                logger.warning(f"[HealthMonitor] {severity.upper()}: {agent_name} - {issue}")
                return

            sustained_for = now - state["first_critical_ts"]
            since_last_log = now - state["last_log_ts"]

            if sustained_for >= _CRITICAL_SUSTAINED_THRESHOLD_S:
                # Persistent critical state: downgrade to a per-minute
                # summary WARN. Don't keep escalating.
                if since_last_log >= _CRITICAL_SUSTAINED_LOG_INTERVAL_S:
                    state["last_log_ts"] = now
                    state["downgraded"] = 1.0
                    self.alerts.append(alert)
                    logger.warning(f"[HealthMonitor] WARN (sustained {sustained_for:.0f}s): {agent_name} - {issue}")
                # else: silently absorb — alert object isn't appended to
                # avoid alerts list bloat under stall conditions.
                return

            # Within the first 120s of critical state: emit at most once
            # per dedup window.
            if since_last_log >= _CRITICAL_DEDUP_WINDOW_S:
                state["last_log_ts"] = now
                self.alerts.append(alert)
                # Bound alerts list to prevent unbounded growth
                if len(self.alerts) > self._max_alerts:
                    self.alerts = self.alerts[-self._max_alerts :]
                logger.warning(f"[HealthMonitor] {severity.upper()}: {agent_name} - {issue}")
            # else: dedup'd, drop the log.
            return

        # Non-critical (warning) path: condition cleared if previously critical.
        # Resetting state lets a future critical event log immediately
        # instead of being suppressed by stale dedup state.
        if state_key in self._critical_state:
            del self._critical_state[state_key]

        # Legacy 60s issue-text dedup for warnings (preserves prior behavior).
        recent_alerts = [
            a
            for a in self.alerts
            if a.agent_name == agent_name and a.issue == issue and now - a.timestamp < _CRITICAL_DEDUP_WINDOW_S
        ]

        if not recent_alerts:
            self.alerts.append(alert)
            if len(self.alerts) > self._max_alerts:
                self.alerts = self.alerts[-self._max_alerts :]
            logger.warning(f"[HealthMonitor] {severity.upper()}: {agent_name} - {issue}")

    def check_heartbeats(self) -> list[str]:
        """
        Check for agents that haven't sent heartbeat recently.
        Returns list of potentially crashed agents.
        """
        current_time = time.time()
        timeout = self.thresholds["heartbeat_timeout"]
        crashed_agents = []

        for agent_name, metrics in self.current_metrics.items():
            if metrics.is_active:
                time_since_heartbeat = current_time - metrics.last_heartbeat
                if time_since_heartbeat > timeout:
                    metrics.is_active = False
                    crashed_agents.append(agent_name)
                    self._create_alert(
                        agent_name,
                        "critical",
                        f"Agent unresponsive for {time_since_heartbeat:.0f}s",
                        {"time_since_heartbeat": time_since_heartbeat},
                        category="heartbeat",
                    )

        return crashed_agents

    def get_agent_health(self, agent_name: str) -> dict[str, Any] | None:
        """Get current health metrics for an agent."""
        if agent_name in self.current_metrics:
            return asdict(self.current_metrics[agent_name])
        return None

    def get_all_health(self) -> dict[str, dict[str, Any]]:
        """Get health metrics for all agents."""
        return {name: asdict(metrics) for name, metrics in self.current_metrics.items()}

    def get_agent_history(self, agent_name: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get historical metrics for an agent."""
        if agent_name in self.history:
            history_list = list(self.history[agent_name])
            return history_list[-limit:]
        return []

    def get_alerts(self, severity: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent alerts."""
        alerts = self.alerts[-limit:]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return [asdict(a) for a in alerts]

    def clear_alerts(self, agent_name: str | None = None):
        """Clear alerts for an agent or all alerts."""
        if agent_name:
            self.alerts = [a for a in self.alerts if a.agent_name != agent_name]
        else:
            self.alerts = []

    def get_system_health_summary(self) -> dict[str, Any]:
        """Get overall system health summary."""
        if not self.current_metrics:
            return {
                "total_agents": 0,
                "active_agents": 0,
                "avg_health_score": 0.0,
                "critical_alerts": 0,
                "warning_alerts": 0,
            }

        active_agents = sum(1 for m in self.current_metrics.values() if m.is_active)
        avg_health = sum(m.health_score for m in self.current_metrics.values()) / len(self.current_metrics)

        critical_alerts = sum(1 for a in self.alerts if a.severity == "critical")
        warning_alerts = sum(1 for a in self.alerts if a.severity == "warning")

        return {
            "total_agents": len(self.current_metrics),
            "active_agents": active_agents,
            "avg_health_score": round(avg_health, 1),
            "critical_alerts": critical_alerts,
            "warning_alerts": warning_alerts,
            "timestamp": time.time(),
        }

    async def save_health_snapshot(self):
        """Save current health state to disk."""
        try:
            snapshot = {
                "timestamp": time.time(),
                "metrics": self.get_all_health(),
                "alerts": self.get_alerts(),
                "summary": self.get_system_health_summary(),
            }

            def _write_snapshot():
                snapshot_file = self.health_dir / f"snapshot_{int(time.time())}.json"
                snapshot_file.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
                snapshots = sorted(self.health_dir.glob("snapshot_*.json"))
                for old_snapshot in snapshots[:-10]:
                    old_snapshot.unlink()

            await asyncio.to_thread(_write_snapshot)

        except Exception as e:
            logger.error(f"[HealthMonitor] Failed to save snapshot: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # BROWSER HEALTH (deep-system-integration §4.1 / §4.2 / §4.4 / §4.5)
    # Architecture invariants honored:
    #   §9   scope-is-law       — purely metric reporting; no scope decisions.
    #   §11  two-LLM exclusivity — no LLM calls.
    #   §17  no re-verification — recovery is upstream; we only score & alert.
    #   §29.13 non-blocking     — pure-CPU scoring; no I/O on this hot path.
    # ══════════════════════════════════════════════════════════════════════
    # Latest spec-shape browser metrics, keyed by reporting host/agent. Stored
    # alongside the legacy per-agent ``browser_metrics`` map so existing
    # ``BrowserHealthMonitorExtension`` consumers keep working.
    _LAST_BROWSER_KEY = "__global__"

    def report_browser_metrics(self, metrics: "BrowserHealthMetrics") -> None:
        """Record the latest browser metrics, score them, and alert on poor health.

        deep-system-integration §4.2: store last metrics, compute the §4.5
        weighted score in [0,1], and emit a single ``critical`` alert via the
        existing alert hook when the score falls below 0.4. The 0.4 threshold
        is fixed by the spec; it is *not* the legacy 0..100 threshold used by
        ``BrowserHealthMonitorExtension``.
        """
        if not isinstance(metrics, BrowserHealthMetrics):
            raise TypeError(f"report_browser_metrics expects BrowserHealthMetrics, got {type(metrics).__name__}")
        if not hasattr(self, "_last_browser_metrics"):
            self._last_browser_metrics: BrowserHealthMetrics | None = None
        self._last_browser_metrics = metrics
        score = self.calculate_browser_health_score(metrics)
        self._last_browser_score = score
        if score < 0.4:
            # Alert via the existing hook so dashboards / coordinator pick this up
            # like any other critical condition. category="browser_health" lets
            # the dedup machinery (§29.13) collapse spam under sustained stress.
            self._create_alert(
                self._LAST_BROWSER_KEY,
                "critical",
                f"Critical browser health score: {score:.2f}",
                {
                    "browser_health_score": score,
                    "active_contexts": metrics.active_contexts,
                    "context_memory_mb": metrics.context_memory_mb,
                    "page_load_time_ms": metrics.page_load_time_ms,
                    "screenshot_time_ms": metrics.screenshot_time_ms,
                    "browser_error_rate": metrics.browser_error_rate,
                },
                category="browser_health",
            )

    def get_browser_health(self) -> dict[str, Any]:
        """Return the latest browser metrics dict + computed score + alert level.

        deep-system-integration §4.4. ``alert_level`` is derived from the same
        thresholds the alert hook uses so dashboards can render a status pill
        without re-implementing scoring rules.
        """
        last = getattr(self, "_last_browser_metrics", None)
        if last is None:
            return {
                "metrics": None,
                "browser_health_score": 1.0,
                "alert_level": "ok",
            }
        score = self.calculate_browser_health_score(last)
        if score < 0.4:
            alert_level = "critical"
        elif score < 0.7:
            alert_level = "warning"
        else:
            alert_level = "ok"
        return {
            "metrics": asdict(last),
            "browser_health_score": score,
            "alert_level": alert_level,
        }

    def calculate_browser_health_score(self, m: "BrowserHealthMetrics") -> float:
        """Weighted browser health score in [0, 1] (deep-system-integration §4.5).

        Weights (sum = 1.00):
          0.25  context-pressure  — 1 - min(active_contexts / 20, 1)
          0.25  memory-pressure   — 1 - min(context_memory_mb / 2048, 1)
          0.20  page-load-latency — 1 - min(page_load_time_ms / 5000, 1)
          0.10  screenshot-latency — 1 - min(screenshot_time_ms / 2000, 1)
          0.20  error-budget      — 1 - browser_error_rate

        ``browser_error_rate`` is clamped to [0,1] before subtraction so callers
        passing legacy 0..100 values (a common foot-gun) can't drive the score
        negative. Final result is clamped to [0,1].
        """
        # Defensive clamps — the spec contract is the formula; anything outside
        # the documented domain (negative values, error rate > 1) is squashed
        # to the boundary so the score stays well-defined.
        ac = max(0, int(m.active_contexts))
        mem = max(0.0, float(m.context_memory_mb))
        plt_ = max(0.0, float(m.page_load_time_ms))
        sst = max(0.0, float(m.screenshot_time_ms))
        err = min(1.0, max(0.0, float(m.browser_error_rate)))

        score = (
            0.25 * (1.0 - min(ac / 20.0, 1.0))
            + 0.25 * (1.0 - min(mem / 2048.0, 1.0))
            + 0.20 * (1.0 - min(plt_ / 5000.0, 1.0))
            + 0.10 * (1.0 - min(sst / 2000.0, 1.0))
            + 0.20 * (1.0 - err)
        )
        # Clamp into [0, 1] — float arithmetic can drift a hair outside.
        if score < 0.0:
            return 0.0
        if score > 1.0:
            return 1.0
        return score


# Global health monitor instance
health_monitor = AgentHealthMonitor()


# ============================================================================
# BROWSER HEALTH MONITOR EXTENSION
# ============================================================================


class BrowserHealthMonitorExtension:
    """Extension for browser-specific health monitoring"""

    def __init__(self, health_monitor: AgentHealthMonitor):
        self.monitor = health_monitor

    def report_browser_metrics(self, agent_name: str, metrics: dict[str, Any]):
        """
        Report browser-specific metrics from an agent.
        """
        current_time = time.time()

        # Get or create browser metrics
        if agent_name not in self.monitor.browser_metrics:
            self.monitor.browser_metrics[agent_name] = BrowserHealthMetrics(timestamp=current_time)
            self.monitor.browser_history[agent_name] = deque(maxlen=100)

        browser_metrics = self.monitor.browser_metrics[agent_name]

        # Update metrics
        browser_metrics.timestamp = current_time

        if "active_contexts" in metrics:
            browser_metrics.active_contexts = metrics["active_contexts"]

        if "context_memory_mb" in metrics:
            browser_metrics.context_memory_mb = metrics["context_memory_mb"]

        if "page_load_time_ms" in metrics:
            browser_metrics.page_load_time_ms = metrics["page_load_time_ms"]

        if "screenshot_time_ms" in metrics:
            browser_metrics.screenshot_time_ms = metrics["screenshot_time_ms"]

        if "browser_error_rate" in metrics:
            browser_metrics.browser_error_rate = metrics["browser_error_rate"]

        # Calculate browser health score (0..100 legacy scale for this extension's alerts)
        legacy_score = _legacy_browser_score_100(browser_metrics)

        # Store in history
        history_entry = asdict(browser_metrics)
        history_entry["agent_name"] = agent_name
        history_entry["browser_health_score"] = legacy_score
        self.monitor.browser_history[agent_name].append(history_entry)

        # Check if browser operations impact system health
        if legacy_score < 40:
            self._create_browser_alert(
                agent_name, "critical", f"Critical browser health: {legacy_score:.0f}/100", history_entry
            )
        elif legacy_score < 70:
            self._create_browser_alert(
                agent_name, "warning", f"Low browser health: {legacy_score:.0f}/100", history_entry
            )

        # Alert on high memory usage
        if browser_metrics.context_memory_mb > 1000:
            self._create_browser_alert(
                agent_name,
                "critical",
                f"High browser memory usage: {browser_metrics.context_memory_mb:.0f}MB",
                {"context_memory_mb": browser_metrics.context_memory_mb},
            )

        # Alert on too many contexts
        if browser_metrics.active_contexts > 15:
            self._create_browser_alert(
                agent_name,
                "warning",
                f"Too many browser contexts: {browser_metrics.active_contexts}",
                {"active_contexts": browser_metrics.active_contexts},
            )

    def get_browser_health(self, agent_name: str) -> dict[str, Any] | None:
        """Get current browser health metrics for an agent."""
        if agent_name in self.monitor.browser_metrics:
            d = asdict(self.monitor.browser_metrics[agent_name])
            d["agent_name"] = agent_name
            d["browser_health_score"] = _legacy_browser_score_100(self.monitor.browser_metrics[agent_name])
            return d
        return None

    def calculate_browser_health_score(self, agent_name: str) -> float:
        """Calculate legacy 0..100 browser health score for an agent."""
        if agent_name in self.monitor.browser_metrics:
            return _legacy_browser_score_100(self.monitor.browser_metrics[agent_name])
        return 100.0

    def _create_browser_alert(self, agent_name: str, severity: str, issue: str, metrics: dict[str, Any]):
        """Create a browser-specific alert."""
        alert = HealthAlert(
            agent_name=agent_name, severity=severity, issue=issue, timestamp=time.time(), metrics=metrics
        )

        # Avoid duplicate alerts
        recent_alerts = [
            a
            for a in self.monitor.alerts
            if a.agent_name == agent_name and a.issue == issue and time.time() - a.timestamp < 60
        ]

        if not recent_alerts:
            self.monitor.alerts.append(alert)
            logger.warning(f"[BrowserHealth] {severity.upper()}: {agent_name} - {issue}")

    def get_all_browser_health(self) -> dict[str, dict[str, Any]]:
        """Get browser health metrics for all agents."""
        out: dict[str, dict[str, Any]] = {}
        for name, metrics in self.monitor.browser_metrics.items():
            d = asdict(metrics)
            d["agent_name"] = name
            d["browser_health_score"] = _legacy_browser_score_100(metrics)
            out[name] = d
        return out

    def get_browser_health_summary(self) -> dict[str, Any]:
        """Get overall browser health summary."""
        if not self.monitor.browser_metrics:
            return {
                "total_agents_with_browser": 0,
                "total_active_contexts": 0,
                "total_browser_memory_mb": 0.0,
                "avg_browser_health_score": 0.0,
                "browser_alerts": 0,
            }

        total_contexts = sum(m.active_contexts for m in self.monitor.browser_metrics.values())
        total_memory = sum(m.context_memory_mb for m in self.monitor.browser_metrics.values())
        avg_health = sum(_legacy_browser_score_100(m) for m in self.monitor.browser_metrics.values()) / len(
            self.monitor.browser_metrics
        )

        browser_alerts = sum(
            1 for a in self.monitor.alerts if "browser" in a.issue.lower() or "context" in a.issue.lower()
        )

        return {
            "total_agents_with_browser": len(self.monitor.browser_metrics),
            "total_active_contexts": total_contexts,
            "total_browser_memory_mb": round(total_memory, 1),
            "avg_browser_health_score": round(avg_health, 1),
            "browser_alerts": browser_alerts,
            "timestamp": time.time(),
        }


# Create global browser health monitor extension
browser_health_monitor = BrowserHealthMonitorExtension(health_monitor)
