"""
Browser Optimization Module

Provides performance optimizations for browser operations:
- Singleton pattern for BrowserOrchestrator
- Context pooling
- Framework detection caching
- Lazy initialization
- Resource cleanup
"""

import asyncio
import logging
from datetime import datetime

try:
    import psutil as _psutil

    _PSUTIL_AVAILABLE = True
except ImportError:
    _psutil = None
    _PSUTIL_AVAILABLE = False

from backend.core.browser_orchestrator import BrowserOrchestrator
from backend.core.task_manager import TaskManager

logger = logging.getLogger("BrowserOptimization")


class BrowserContextPool:
    """
    Connection pool for browser contexts.
    Reuses contexts to reduce memory overhead and initialization time.
    """

    def __init__(self, max_contexts: int = 5):
        self.max_contexts = max_contexts
        self._available_contexts = []
        self._active_contexts = {}
        self._context_metadata = {}
        self._lock = asyncio.Lock()

    async def acquire(self, scan_id: str = None) -> dict:
        """Acquire a browser context from the pool."""
        async with self._lock:
            # Try to reuse an available context
            if self._available_contexts:
                context = self._available_contexts.pop()
                if scan_id:
                    self._active_contexts[scan_id] = context
                logger.debug(f"[BrowserContextPool] Reused context (available: {len(self._available_contexts)})")
                return context

            # Create new context if under limit
            if len(self._active_contexts) < self.max_contexts:
                # Would create actual browser context here
                context = {
                    "id": f"ctx_{len(self._active_contexts)}",
                    "created_at": datetime.now(),
                    "last_used": datetime.now(),
                }
                if scan_id:
                    self._active_contexts[scan_id] = context
                logger.debug(f"[BrowserContextPool] Created new context (active: {len(self._active_contexts)})")
                return context

            # Wait for a context to become available (bounded retry to prevent infinite recursion)
            logger.warning("[BrowserContextPool] Pool exhausted, waiting for available context...")
        # Release lock before sleeping so release() can return contexts
        await asyncio.sleep(1)
        # Retry once after waiting — if still full, return None instead of recursing
        async with self._lock:
            if self._available_contexts:
                context = self._available_contexts.pop()
                if scan_id:
                    self._active_contexts[scan_id] = context
                return context
            logger.error("[BrowserContextPool] No context available after wait")
            return None

    async def release(self, context: dict, scan_id: str = None):
        """Release a context back to the pool."""
        async with self._lock:
            if scan_id and scan_id in self._active_contexts:
                del self._active_contexts[scan_id]

            # Update last used time
            context["last_used"] = datetime.now()

            # Add back to available pool if under limit
            if len(self._available_contexts) < self.max_contexts:
                self._available_contexts.append(context)
                logger.debug(f"[BrowserContextPool] Released context (available: {len(self._available_contexts)})")
            else:
                # Close context if pool is full
                await self._close_context(context)

    async def cleanup_idle(self, idle_timeout: int = 300):
        """Close contexts that have been idle for too long."""
        async with self._lock:
            now = datetime.now()
            to_remove = []

            for context in self._available_contexts:
                last_used = context.get("last_used", now)
                if (now - last_used).total_seconds() > idle_timeout:
                    to_remove.append(context)

            for context in to_remove:
                self._available_contexts.remove(context)
                await self._close_context(context)

            if to_remove:
                logger.debug(f"[BrowserContextPool] Cleaned up {len(to_remove)} idle contexts")

    async def _close_context(self, context: dict):
        """Close a browser context."""
        # Would close actual browser context here
        logger.debug(f"[BrowserContextPool] Closed context {context.get('id')}")

    async def close_all(self):
        """Close all contexts in the pool."""
        async with self._lock:
            for context in self._available_contexts:
                await self._close_context(context)
            self._available_contexts.clear()

            for context in self._active_contexts.values():
                await self._close_context(context)
            self._active_contexts.clear()

            logger.debug("[BrowserContextPool] Closed all contexts")


class FrameworkDetectionCache:
    """
    Cache for framework detection results.
    Avoids re-detecting frameworks for the same domain.
    """

    def __init__(self, cache_ttl: int = 3600):
        self.cache_ttl = cache_ttl  # seconds
        self._cache: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def get(self, domain: str) -> str | None:
        """Get cached framework detection result."""
        async with self._lock:
            if domain in self._cache:
                entry = self._cache[domain]
                cached_at = entry.get("cached_at")

                # Check if cache is still valid
                if (datetime.now() - cached_at).total_seconds() < self.cache_ttl:
                    logger.debug(f"[FrameworkCache] Cache hit for {domain}: {entry.get('framework')}")
                    return entry.get("framework")
                else:
                    # Cache expired
                    del self._cache[domain]

            return None

    async def set(self, domain: str, framework: str):
        """Cache framework detection result."""
        async with self._lock:
            self._cache[domain] = {"framework": framework, "cached_at": datetime.now()}
            logger.debug(f"[FrameworkCache] Cached {domain}: {framework}")

    async def clear(self):
        """Clear all cached results."""
        async with self._lock:
            self._cache.clear()
            logger.debug("[FrameworkCache] Cache cleared")

    def get_stats(self) -> dict:
        """Get cache statistics."""
        return {"size": len(self._cache), "domains": list(self._cache.keys())}


class BrowserResourceMonitor:
    """
    Monitor browser resource usage and trigger cleanup when needed.
    """

    def __init__(self, memory_threshold_mb: int = 500):
        self.memory_threshold_mb = memory_threshold_mb
        self._monitoring = False
        self._monitor_task = None
        self._task_manager = TaskManager("BrowserResourceMonitor")

    async def start_monitoring(self, context_pool: BrowserContextPool):
        """Start resource monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_task = self._task_manager.create_task(self._monitor_loop(context_pool), name="resource_monitor")
        logger.info(f"[BrowserResourceMonitor] Started monitoring (threshold: {self.memory_threshold_mb}MB)")

    async def stop_monitoring(self):
        """Stop resource monitoring."""
        self._monitoring = False
        await self._task_manager.cancel_all()
        self._monitor_task = None
        logger.info("[BrowserResourceMonitor] Stopped monitoring")

    async def _monitor_loop(self, context_pool: BrowserContextPool):
        """Monitor resource usage and trigger cleanup."""
        while self._monitoring:
            try:
                # Check memory usage (would use actual metrics in production)
                memory_usage_mb = await self._get_memory_usage()

                if memory_usage_mb > self.memory_threshold_mb:
                    logger.warning(f"[BrowserResourceMonitor] Memory threshold exceeded: {memory_usage_mb}MB")
                    await context_pool.cleanup_idle(idle_timeout=60)

                # Check every 30 seconds
                await asyncio.sleep(30)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[BrowserResourceMonitor] Monitoring error: {e}")
                await asyncio.sleep(30)

    async def _get_memory_usage(self) -> int:
        """Get current memory usage in MB."""
        if not _PSUTIL_AVAILABLE or _psutil is None:
            return 0
        try:
            process = _psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            return int(memory_mb)
        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return 0


class OptimizedBrowserOrchestrator:
    """
    Singleton wrapper for BrowserOrchestrator with optimizations.
    """

    _instance: BrowserOrchestrator | None = None
    _context_pool: BrowserContextPool | None = None
    _framework_cache: FrameworkDetectionCache | None = None
    _resource_monitor: BrowserResourceMonitor | None = None
    _lock = asyncio.Lock()

    @classmethod
    async def get_instance(cls) -> BrowserOrchestrator:
        """Get singleton instance of BrowserOrchestrator."""
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = BrowserOrchestrator()
                    await cls._instance.initialize()

                    # Initialize optimizations
                    cls._context_pool = BrowserContextPool(max_contexts=5)
                    cls._framework_cache = FrameworkDetectionCache(cache_ttl=3600)
                    cls._resource_monitor = BrowserResourceMonitor(memory_threshold_mb=500)

                    # Start resource monitoring
                    await cls._resource_monitor.start_monitoring(cls._context_pool)

                    logger.info("[OptimizedBrowserOrchestrator] Singleton instance created with optimizations")

        return cls._instance

    @classmethod
    async def detect_framework_cached(cls, url: str) -> str | None:
        """Detect framework with caching."""
        from urllib.parse import urlparse

        domain = urlparse(url).netloc

        # Check cache first
        cached = await cls._framework_cache.get(domain)
        if cached:
            return cached

        # Detect framework
        orchestrator = await cls.get_instance()
        framework = await orchestrator.detect_framework(url)

        # Cache result
        if framework:
            await cls._framework_cache.set(domain, framework)

        return framework

    @classmethod
    async def acquire_context(cls, scan_id: str = None) -> dict:
        """Acquire a browser context from the pool."""
        return await cls._context_pool.acquire(scan_id)

    @classmethod
    async def release_context(cls, context: dict, scan_id: str = None):
        """Release a browser context back to the pool."""
        await cls._context_pool.release(context, scan_id)

    @classmethod
    async def cleanup(cls):
        """Cleanup all resources."""
        try:
            if cls._resource_monitor:
                await cls._resource_monitor.stop_monitoring()
        except RuntimeError as e:
            if "Event loop is closed" not in str(e):
                raise

        try:
            if cls._context_pool:
                await cls._context_pool.close_all()
        except RuntimeError as e:
            if "Event loop is closed" not in str(e):
                raise

        try:
            if cls._framework_cache:
                await cls._framework_cache.clear()
        except RuntimeError as e:
            if "Event loop is closed" not in str(e):
                raise

        try:
            if cls._instance:
                await cls._instance.close()
                cls._instance = None
        except RuntimeError as e:
            if "Event loop is closed" not in str(e):
                raise

        logger.info("[OptimizedBrowserOrchestrator] Cleanup complete")

    @classmethod
    def get_stats(cls) -> dict:
        """Get optimization statistics."""
        stats = {
            "singleton_initialized": cls._instance is not None,
            "context_pool": {
                "available": len(cls._context_pool._available_contexts) if cls._context_pool else 0,
                "active": len(cls._context_pool._active_contexts) if cls._context_pool else 0,
            },
            "framework_cache": cls._framework_cache.get_stats() if cls._framework_cache else {},
        }
        return stats


# Convenience function for agents
async def get_optimized_browser() -> BrowserOrchestrator:
    """Get optimized browser orchestrator instance."""
    return await OptimizedBrowserOrchestrator.get_instance()
