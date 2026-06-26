"""
PERFORMANCE TRACKER
Monitors agent performance and resource usage.

This tracker:
1. Records action execution metrics
2. Monitors resource usage (CPU, memory, API calls)
3. Detects stuck states (3+ consecutive failures)
4. Provides performance summaries
5. Implements batched database persistence
"""

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

import psutil

from backend.core.database import db_manager
from backend.core.self_awareness_config import SelfAwarenessConfig
from backend.core.task_manager import TaskManager
from backend.core.tracing import get_tracer, trace_span

logger = logging.getLogger("PerformanceTracker")
tracer = get_tracer()


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ActionRecord:
    """Record of a single action execution"""
    tracking_id: str
    agent_id: str
    action_type: str
    start_time: datetime
    end_time: datetime | None = None
    success: bool | None = None
    cpu_usage: float = 0.0
    memory_mb: float = 0.0
    api_calls: int = 0
    error_message: str | None = None


@dataclass
class ResourceMetrics:
    """Current resource usage metrics"""
    cpu_percent: float
    memory_mb: float
    api_calls_per_minute: int
    timestamp: float


@dataclass
class StuckStateInfo:
    """Information about a stuck state"""
    action_type: str
    consecutive_failures: int
    first_failure_time: datetime
    last_failure_time: datetime


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics"""
    agent_id: str
    timestamp: float

    # Success metrics
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    success_rate: float = 0.0

    # Timing metrics
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0

    # Resource metrics
    avg_cpu_percent: float = 0.0
    avg_memory_mb: float = 0.0
    total_api_calls: int = 0

    # Stuck state
    is_stuck: bool = False
    stuck_action_type: str | None = None


# ============================================================================
# PERFORMANCE TRACKER
# ============================================================================

class PerformanceTracker:
    """
    Tracks agent performance and resource usage.

    Features:
    - Action execution tracking
    - Resource usage monitoring
    - Stuck state detection
    - Batched database persistence
    - In-memory metrics aggregation
    """

    def __init__(
        self,
        agent_id: str,
        config: SelfAwarenessConfig
    ):
        """
        Initialize performance tracker.

        Args:
            agent_id: ID of the agent being tracked
            config: Self-awareness configuration
        """
        self.agent_id = agent_id
        self.config = config

        # In-memory action records
        self._active_actions: dict[str, ActionRecord] = {}
        self._completed_actions: deque = deque(maxlen=1000)

        # Failure tracking for stuck state detection
        self._failure_counts: dict[str, int] = defaultdict(int)
        self._last_success: dict[str, datetime] = {}
        self._first_failure: dict[str, datetime] = {}

        # Pending database writes
        self._pending_writes: deque = deque(maxlen=10000)

        # Batch flush task
        self._flush_task: asyncio.Task | None = None
        self._running = False

        # Process handle for resource monitoring
        self._process = psutil.Process()

        # API call counter
        self._api_calls = 0
        self._api_call_timestamps: deque = deque(maxlen=1000)

        # Task manager for background tasks
        self._task_manager = TaskManager(f"PerformanceTracker-{agent_id}")

        logger.info(f"[PerformanceTracker] Initialized for agent {agent_id}")

    async def start(self):
        """Start the performance tracker"""
        if self._running:
            return

        self._running = True

        # Start batch flush task
        self._flush_task = self._task_manager.create_task(self._batch_flush_loop(), name="batch_flush_loop")

        logger.info(f"[PerformanceTracker] Started for agent {self.agent_id}")

    async def stop(self):
        """Stop the performance tracker"""
        self._running = False

        # Cancel all tracked tasks
        await self._task_manager.cancel_all()

        # Flush remaining data
        await self.flush()

        logger.info(f"[PerformanceTracker] Stopped for agent {self.agent_id}")

    def record_action_start(self, action: Any) -> str:
        """
        Record action start.

        Args:
            action: The action being started

        Returns:
            tracking_id for this action
        """
        tracking_id = str(uuid.uuid4())

        # Get current resource usage
        cpu_usage = self._process.cpu_percent(interval=0.1)
        memory_mb = self._process.memory_info().rss / 1024 / 1024

        # Create action record
        record = ActionRecord(
            tracking_id=tracking_id,
            agent_id=self.agent_id,
            action_type=action.action_type.value if hasattr(action, 'action_type') else str(action),
            start_time=datetime.utcnow(),
            cpu_usage=cpu_usage,
            memory_mb=memory_mb
        )

        self._active_actions[tracking_id] = record

        logger.debug(f"[PerformanceTracker] Started tracking action {tracking_id}")

        return tracking_id

    async def record_action_end(
        self,
        action: Any,
        result: Any
    ) -> None:
        """
        Record action completion.

        Args:
            action: The action that completed
            result: The action result
        """
        with trace_span(
            "performance_tracker.record_action_end",
            {
                "agent_id": self.agent_id,
                "action_type": getattr(action, 'action_type', 'unknown'),
                "success": getattr(result, 'success', True)
            }
        ):
            # Find the tracking record
            tracking_id = getattr(action, 'action_id', None)

            if not tracking_id or tracking_id not in self._active_actions:
                # Create a new record if not found
                tracking_id = self.record_action_start(action)

            record = self._active_actions.pop(tracking_id, None)
            if not record:
                logger.warning(f"[PerformanceTracker] No record found for action {tracking_id}")
                return

            # Update record with completion data
            record.end_time = datetime.utcnow()
            record.success = result.success if hasattr(result, 'success') else True

            if hasattr(result, 'error') and result.error:
                record.error_message = str(result.error)[:500]  # Truncate long errors

            # Update resource usage
            record.cpu_usage = self._process.cpu_percent(interval=0.1)
            record.memory_mb = self._process.memory_info().rss / 1024 / 1024

            # Track API calls if available
            if hasattr(result, 'resource_usage') and result.resource_usage:
                api_calls = result.resource_usage.get('api_calls', 0)
                record.api_calls = api_calls
                self._api_calls += api_calls
                self._api_call_timestamps.append(time.time())

            # Update failure tracking
            action_type = record.action_type
            if record.success:
                self._failure_counts[action_type] = 0
                self._last_success[action_type] = record.end_time
                if action_type in self._first_failure:
                    del self._first_failure[action_type]
            else:
                self._failure_counts[action_type] += 1
                if action_type not in self._first_failure:
                    self._first_failure[action_type] = record.end_time

            # Add to completed actions
            self._completed_actions.append(record)

            # Queue for database write
            self._pending_writes.append(record)

            logger.debug(
                f"[PerformanceTracker] Completed action {tracking_id}: "
                f"success={record.success}, duration={(record.end_time - record.start_time).total_seconds():.2f}s"
            )

    def get_success_rate(
        self,
        action_type: str,
        window_minutes: int = 60
    ) -> float:
        """
        Get success rate for action type in time window.

        Args:
            action_type: Type of action to analyze
            window_minutes: Time window in minutes

        Returns:
            Success rate (0.0 to 1.0)
        """
        cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)

        # Filter actions in time window
        relevant_actions = [
            action for action in self._completed_actions
            if action.action_type == action_type and action.end_time >= cutoff_time
        ]

        if not relevant_actions:
            return 0.0

        successful = sum(1 for action in relevant_actions if action.success)
        return successful / len(relevant_actions)

    def get_resource_usage(self) -> ResourceMetrics:
        """
        Get current resource usage metrics.

        Returns:
            ResourceMetrics with current usage
        """
        # Calculate API calls per minute
        current_time = time.time()
        recent_calls = [
            ts for ts in self._api_call_timestamps
            if current_time - ts < 60
        ]
        api_calls_per_minute = len(recent_calls)

        return ResourceMetrics(
            cpu_percent=self._process.cpu_percent(interval=0.1),
            memory_mb=self._process.memory_info().rss / 1024 / 1024,
            api_calls_per_minute=api_calls_per_minute,
            timestamp=current_time
        )

    async def detect_stuck_state(self) -> StuckStateInfo | None:
        """
        Detect if agent is stuck (3+ consecutive failures).

        Returns:
            StuckStateInfo if stuck, None otherwise
        """
        with trace_span(
            "performance_tracker.detect_stuck_state",
            {"agent_id": self.agent_id}
        ) as span:
            for action_type, failure_count in self._failure_counts.items():
                if failure_count >= self.config.stuck_state_threshold:
                    stuck_info = StuckStateInfo(
                        action_type=action_type,
                        consecutive_failures=failure_count,
                        first_failure_time=self._first_failure.get(action_type, datetime.utcnow()),
                        last_failure_time=datetime.utcnow()
                    )
                    if span:
                        span.set_attribute("stuck_detected", True)
                        span.set_attribute("action_type", action_type)
                        span.set_attribute("consecutive_failures", failure_count)
                    return stuck_info

            if span:
                span.set_attribute("stuck_detected", False)
            return None

    async def get_metrics_summary(self) -> dict[str, Any]:
        """
        Get comprehensive performance summary.

        Returns:
            Dictionary with performance metrics
        """
        # Calculate metrics from completed actions
        total_actions = len(self._completed_actions)

        if total_actions == 0:
            return {
                "agent_id": self.agent_id,
                "timestamp": time.time(),
                "total_actions": 0,
                "success_rate": 0.0,
                "avg_response_time_ms": 0.0
            }

        successful = sum(1 for action in self._completed_actions if action.success)
        failed = total_actions - successful
        success_rate = successful / total_actions if total_actions > 0 else 0.0

        # Calculate timing metrics
        response_times = []
        for action in self._completed_actions:
            if action.end_time:
                duration_ms = (action.end_time - action.start_time).total_seconds() * 1000
                response_times.append(duration_ms)

        avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0
        min_response_time = min(response_times) if response_times else 0.0
        max_response_time = max(response_times) if response_times else 0.0

        # Calculate resource metrics
        cpu_values = [action.cpu_usage for action in self._completed_actions]
        memory_values = [action.memory_mb for action in self._completed_actions]

        avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0.0
        avg_memory = sum(memory_values) / len(memory_values) if memory_values else 0.0

        # Check stuck state
        stuck_info = await self.detect_stuck_state()

        return {
            "agent_id": self.agent_id,
            "timestamp": time.time(),
            "total_actions": total_actions,
            "successful_actions": successful,
            "failed_actions": failed,
            "success_rate": success_rate,
            "avg_response_time_ms": avg_response_time,
            "min_response_time_ms": min_response_time,
            "max_response_time_ms": max_response_time,
            "avg_cpu_percent": avg_cpu,
            "avg_memory_mb": avg_memory,
            "total_api_calls": self._api_calls,
            "is_stuck": stuck_info is not None,
            "stuck_action_type": stuck_info.action_type if stuck_info else None
        }

    async def _batch_flush_loop(self):
        """Background task that flushes pending writes periodically"""
        while self._running:
            try:
                await asyncio.sleep(self.config.metrics_batch_interval_seconds)
                await self.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[PerformanceTracker] Flush loop error: {e}")

    async def flush(self):
        """Flush pending writes to database"""
        if not self._pending_writes:
            return

        # Get batch of records to write
        batch = []
        while self._pending_writes and len(batch) < 100:
            batch.append(self._pending_writes.popleft())

        if not batch:
            return

        try:
            await self._write_batch_to_db(batch)
            logger.debug(f"[PerformanceTracker] Flushed {len(batch)} records to database")
        except Exception as e:
            logger.error(f"[PerformanceTracker] Database write failed: {e}")
            # Re-queue failed writes
            for record in batch:
                if len(self._pending_writes) < 10000:  # Prevent unbounded growth
                    self._pending_writes.append(record)

    async def _write_batch_to_db(self, batch: list[ActionRecord]):
        """
        Write batch of action records to database.

        Args:
            batch: List of ActionRecord to write
        """
        if not batch:
            return

        try:
            # Ensure database is initialized
            await db_manager.initialize()

            # Build insert query
            query = """
                INSERT INTO agent_performance (
                    agent_id, tracking_id, action_type,
                    start_time, end_time, success,
                    cpu_usage, memory_mb, api_calls, error_message
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """

            # Execute batch insert
            async with db_manager.pool.acquire() as conn:
                await conn.executemany(
                    query,
                    [
                        (
                            record.agent_id,
                            record.tracking_id,
                            record.action_type,
                            record.start_time,
                            record.end_time,
                            record.success,
                            record.cpu_usage,
                            record.memory_mb,
                            record.api_calls,
                            record.error_message
                        )
                        for record in batch
                    ]
                )

        except Exception as e:
            logger.error(f"[PerformanceTracker] Database write error: {e}")
            raise

    def increment_api_calls(self, count: int = 1):
        """
        Increment API call counter.

        Args:
            count: Number of API calls to add
        """
        self._api_calls += count
        current_time = time.time()
        for _ in range(count):
            self._api_call_timestamps.append(current_time)

    def get_action_history(
        self,
        action_type: str | None = None,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """
        Get recent action history.

        Args:
            action_type: Filter by action type (optional)
            limit: Maximum number of actions to return

        Returns:
            List of action records as dictionaries
        """
        actions = list(self._completed_actions)

        # Filter by action type if specified
        if action_type:
            actions = [a for a in actions if a.action_type == action_type]

        # Limit results
        actions = actions[-limit:]

        return [asdict(action) for action in actions]
