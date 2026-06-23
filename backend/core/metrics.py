"""
Prometheus-compatible metrics for Vigilagent backend.

Provides counters, gauges, and histograms for monitoring Redis health,
WebSocket connections, scan lifecycle, agent performance, and Docker readiness.

Usage:
    from backend.core.metrics import metrics
    metrics.scans_started.inc()
    metrics.ws_connections.set(42)
    metrics.record_scan_duration(120.5)
"""

import time
import threading
from typing import Dict, Any


class _Counter:
    """Thread-safe counter for tracking cumulative values."""

    def __init__(self, name: str, help_text: str = ""):
        self.name = name
        self.help = help_text
        self._value = 0.0
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0):
        with self._lock:
            self._value += amount

    def get(self) -> float:
        with self._lock:
            return self._value

    def set_value(self, value: float):
        """Overwrite counter value (used for syncing external counters)."""
        with self._lock:
            self._value = value

    def reset(self):
        with self._lock:
            self._value = 0.0


class _Gauge:
    """Thread-safe gauge that can go up and down."""

    def __init__(self, name: str, help_text: str = ""):
        self.name = name
        self.help = help_text
        self._value = 0.0
        self._lock = threading.Lock()

    def set(self, value: float):
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0):
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1.0):
        with self._lock:
            self._value -= amount

    def get(self) -> float:
        with self._lock:
            return self._value


class _Histogram:
    """Simple histogram with fixed buckets for latency tracking."""

    BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)

    def __init__(self, name: str, help_text: str = ""):
        self.name = name
        self.help = help_text
        self._count = 0
        self._sum = 0.0
        self._bucket_counts = [0] * (len(self.BUCKETS) + 1)
        self._lock = threading.Lock()

    def observe(self, value: float):
        with self._lock:
            self._count += 1
            self._sum += value
            for i, boundary in enumerate(self.BUCKETS):
                if value <= boundary:
                    self._bucket_counts[i] += 1
                    return
            self._bucket_counts[-1] += 1

    def get(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "count": self._count,
                "sum": round(self._sum, 4),
                "buckets": {
                    f"le_{b}": c
                    for b, c in zip(self.BUCKETS, self._bucket_counts[:-1])
                } | {"le_inf": self._bucket_counts[-1]},
            }


class VigilagentMetrics:
    """Central metrics registry for the Vigilagent backend."""

    def __init__(self):
        # --- Redis ---
        self.redis_connected = _Gauge("vigilagent_redis_connected", "1 if Redis is reachable")
        self.redis_reconnect_total = _Counter("vigilagent_redis_reconnect_total", "Redis reconnection attempts")
        self.redis_pool_size = _Gauge("vigilagent_redis_pool_size", "Active Redis connection pool size")
        self.redis_latency_ms = _Histogram("vigilagent_redis_latency_ms", "Redis operation latency")
        # Pool utilization
        self.redis_pool_active = _Gauge("vigilagent_redis_pool_active", "In-use Redis connections")
        self.redis_pool_idle = _Gauge("vigilagent_redis_pool_idle", "Idle Redis connections in pool")
        self.redis_pool_max = _Gauge("vigilagent_redis_pool_max", "Max Redis connections configured")
        self.redis_pool_overflow_total = _Counter("vigilagent_redis_pool_overflow_total", "Pool overflow events (connections exceeded max)")

        # --- WebSocket ---
        self.ws_ui_connections = _Gauge("vigilagent_ws_ui_connections", "Active UI WebSocket connections")
        self.ws_spy_connections = _Gauge("vigilagent_ws_spy_connections", "Active spy WebSocket connections")
        self.ws_messages_sent_total = _Counter("vigilagent_ws_messages_sent_total", "Total WebSocket messages sent")
        self.ws_send_errors_total = _Counter("vigilagent_ws_send_errors_total", "WebSocket send failures")

        # --- Scans ---
        self.scans_started_total = _Counter("vigilagent_scans_started_total", "Total scans initiated")
        self.scans_completed_total = _Counter("vigilagent_scans_completed_total", "Total scans completed")
        self.scans_failed_total = _Counter("vigilagent_scans_failed_total", "Total scans that failed")
        self.scans_active = _Gauge("vigilagent_scans_active", "Currently active scans")
        self.scan_duration_seconds = _Histogram("vigilagent_scan_duration_seconds", "Scan lifecycle duration")

        # --- Agents ---
        self.agents_active = _Gauge("vigilagent_agents_active", "Currently active agents")
        self.agent_tasks_total = _Counter("vigilagent_agent_tasks_total", "Total agent tasks executed")
        self.agent_task_errors_total = _Counter("vigilagent_agent_task_errors_total", "Agent task errors")
        self.event_handler_errors_total = _Counter("vigilagent_event_handler_errors_total", "Event bus handler failures (dead letters)")
        self.agent_restart_total = _Counter("vigilagent_agent_restart_total", "Agent restart attempts (zombie sweep)")

        # --- Docker ---
        self.docker_probe_duration_seconds = _Histogram("vigilagent_docker_probe_seconds", "Docker readiness probe duration")
        self.docker_ready = _Gauge("vigilagent_docker_ready", "1 if Docker daemon is reachable")
        self.docker_tools_available = _Gauge("vigilagent_docker_tools_available", "Number of Docker recon tools available")

        # --- Vulnerabilities ---
        self.vulns_confirmed_total = _Counter("vigilagent_vulns_confirmed_total", "Total confirmed vulnerabilities")
        self.vulns_by_severity = {
            "CRITICAL": _Counter("vigilagent_vulns_critical_total", "Critical vulnerabilities"),
            "HIGH": _Counter("vigilagent_vulns_high_total", "High vulnerabilities"),
            "MEDIUM": _Counter("vigilagent_vulns_medium_total", "Medium vulnerabilities"),
            "LOW": _Counter("vigilagent_vulns_low_total", "Low vulnerabilities"),
        }

        # --- LLM / Cortex ---
        self.llm_calls_total = _Counter("vigilagent_llm_calls_total", "Total LLM API calls")
        self.llm_errors_total = _Counter("vigilagent_llm_errors_total", "LLM API call errors")
        self.llm_latency_seconds = _Histogram("vigilagent_llm_latency_seconds", "LLM API call latency")
        self.circuit_breaker_trips_total = _Counter("vigilagent_circuit_breaker_trips_total", "Circuit breaker trips")

        # --- Uptime ---
        self._start_time = time.time()

    def record_scan_duration(self, seconds: float):
        self.scan_duration_seconds.observe(seconds)

    def record_redis_latency(self, ms: float):
        self.redis_latency_ms.observe(ms / 1000.0)

    def record_llm_latency(self, seconds: float):
        self.llm_latency_seconds.observe(seconds)

    def record_vuln(self, severity: str):
        self.vulns_confirmed_total.inc()
        key = severity.upper()
        if key in self.vulns_by_severity:
            self.vulns_by_severity[key].inc()

    def render_prometheus(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        lines = []
        lines.append("# HELP vigilagent_up Uptime in seconds")
        lines.append("# TYPE vigilagent_up gauge")
        lines.append(f"vigilagent_up {round(time.time() - self._start_time, 1)}")
        lines.append("")

        all_metrics = [
            # Gauges
            self.redis_connected, self.redis_pool_size,
            self.redis_pool_active, self.redis_pool_idle, self.redis_pool_max,
            self.ws_ui_connections, self.ws_spy_connections,
            self.scans_active, self.agents_active,
            self.docker_ready, self.docker_tools_available,
            # Counters
            self.redis_reconnect_total, self.redis_pool_overflow_total,
            self.ws_messages_sent_total, self.ws_send_errors_total,
            self.scans_started_total, self.scans_completed_total,
            self.scans_failed_total, self.agent_tasks_total,
            self.agent_task_errors_total, self.agent_restart_total,
            self.vulns_confirmed_total,
            self.event_handler_errors_total,
            self.llm_calls_total, self.llm_errors_total,
            self.circuit_breaker_trips_total,
        ] + list(self.vulns_by_severity.values())

        # Gauges
        for g in all_metrics:
            if isinstance(g, _Gauge):
                lines.append(f"# HELP {g.name} {g.help}")
                lines.append(f"# TYPE {g.name} gauge")
                lines.append(f"{g.name} {g.get()}")
                lines.append("")

        # Counters
        for c in all_metrics:
            if isinstance(c, _Counter):
                lines.append(f"# HELP {c.name} {c.help}")
                lines.append(f"# TYPE {c.name} counter")
                lines.append(f"{c.name}_total {c.get()}")
                lines.append("")

        # Histograms
        for h in [self.scan_duration_seconds, self.redis_latency_ms,
                   self.docker_probe_duration_seconds, self.llm_latency_seconds]:
            lines.append(f"# HELP {h.name} {h.help}")
            lines.append(f"# TYPE {h.name} histogram")
            data = h.get()
            lines.append(f"{h.name}_count {data['count']}")
            lines.append(f"{h.name}_sum {data['sum']}")
            for bucket, count in data["buckets"].items():
                le = bucket.replace("le_", "").replace("le_inf", "+Inf")
                lines.append(f'{h.name}_bucket{{le="{le}"}} {count}')
            lines.append("")

        return "\n".join(lines)


# Module-level singleton
metrics = VigilagentMetrics()
