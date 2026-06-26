"""
Task Manager: Proper async task tracking and cleanup.

Prevents fire-and-forget tasks that cause race conditions and resource leaks.
"""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any


class TaskManager:
    """
    Manages async tasks with proper tracking, error handling, and cleanup.

    Usage:
        manager = TaskManager("MyComponent")
        task = manager.create_task(my_coroutine(), name="my_task")

        # Later, cleanup all tasks
        await manager.cancel_all()
    """

    def __init__(self, name: str = "TaskManager"):
        self.name = name
        self._tasks: set[asyncio.Task] = set()
        self._logger = logging.getLogger(f"TaskManager.{name}")

    def create_task(self, coro: Coroutine[Any, Any, Any], name: str | None = None) -> asyncio.Task:
        """
        Create a tracked task with automatic cleanup and error handling.

        Args:
            coro: The coroutine to run
            name: Optional name for the task (for debugging)

        Returns:
            The created task
        """
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)

        def cleanup(t: asyncio.Task):
            """Cleanup callback - removes task and logs errors."""
            self._tasks.discard(t)

            # Don't log cancelled tasks as errors
            if t.cancelled():
                self._logger.debug(f"Task {name or 'unnamed'} was cancelled")
                return

            # Log any exceptions
            try:
                exc = t.exception()
                if exc:
                    self._logger.error(f"Task {name or 'unnamed'} failed with exception: {exc}", exc_info=exc)
            except asyncio.CancelledError:
                pass  # Already handled above
            except Exception as e:
                self._logger.error(f"Error getting task exception: {e}")

        task.add_done_callback(cleanup)
        return task

    async def cancel_all(self, timeout: float = 5.0):
        """
        Cancel all tracked tasks and wait for them to finish.

        Args:
            timeout: Maximum time to wait for tasks to cancel (seconds)
        """
        if not self._tasks:
            return

        tasks = list(self._tasks)
        self._logger.info(f"Cancelling {len(tasks)} tasks...")

        # Cancel all tasks
        for task in tasks:
            if not task.done():
                task.cancel()

        # Wait for all tasks to finish (with timeout)
        try:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
        except TimeoutError:
            self._logger.warning(f"Timeout waiting for {len(tasks)} tasks to cancel")
        except Exception as e:
            self._logger.error(f"Error cancelling tasks: {e}")

        self._tasks.clear()
        self._logger.info("All tasks cancelled")

    def __len__(self):
        """Return number of active tasks."""
        return len(self._tasks)

    def __repr__(self):
        return f"TaskManager({self.name}, {len(self._tasks)} tasks)"

    @property
    def active_count(self) -> int:
        """Return number of active (not done) tasks."""
        return sum(1 for task in self._tasks if not task.done())

    def get_task_names(self) -> list[str]:
        """Get names of all active tasks (for debugging)."""
        return [task.get_name() for task in self._tasks if not task.done()]
