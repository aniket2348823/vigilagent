"""
Redis client configuration with distributed locking support.

This module provides a centralized Redis client with connection pooling,
health checks, and distributed locking capabilities for the integration system.
"""

import os
import logging
from typing import Optional
from contextlib import asynccontextmanager
import asyncio

from backend.core.task_manager import TaskManager

logger = logging.getLogger(__name__)

# Try to import Redis, but make it optional
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available - distributed features disabled")


class RedisConfig:
    """Configuration for Redis client"""
    
    def __init__(self):
        self.url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.max_connections = int(os.getenv("REDIS_MAX_CONNECTIONS", "50"))
        self.socket_timeout = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
        self.socket_connect_timeout = int(os.getenv("REDIS_CONNECT_TIMEOUT", "5"))
        self.decode_responses = True
        self.health_check_interval = int(os.getenv("REDIS_HEALTH_CHECK_INTERVAL", "30"))


class RedisClient:
    """
    Redis client with connection pooling and distributed locking.
    
    Provides:
    - Connection pooling for performance
    - Health checks for reliability
    - Distributed locking for race condition prevention
    - Graceful degradation when Redis unavailable
    """
    
    def __init__(self, config: Optional[RedisConfig] = None):
        self.config = config or RedisConfig()
        self._client: Optional[aioredis.Redis] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._is_healthy = False
        self._task_manager = TaskManager("RedisClient")
    
    async def initialize(self) -> None:
        """Initialize Redis client with connection pooling"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available - using in-memory fallback")
            return
        
        try:
            self._client = aioredis.from_url(
                self.config.url,
                max_connections=self.config.max_connections,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                decode_responses=self.config.decode_responses,
                retry_on_timeout=True,
                health_check_interval=self.config.health_check_interval,
            )
            
            # Test connection
            await self._client.ping()
            self._is_healthy = True
            
            # Start health check loop
            self._health_check_task = self._task_manager.create_task(self._health_check_loop(), name="health_check_loop")
            
            logger.info(f"Redis client initialized: {self.config.url}")
        except Exception as e:
            logger.error(f"Failed to initialize Redis client: {e}")
            self._is_healthy = False
    
    async def _health_check_loop(self) -> None:
        """Background task to check Redis health periodically"""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                if self._client:
                    await self._client.ping()
                    if not self._is_healthy:
                        logger.info("Redis connection restored")
                    self._is_healthy = True
            except Exception as e:
                if self._is_healthy:
                    logger.error(f"Redis health check failed: {e}")
                self._is_healthy = False
                # HIGH-40: Attempt reconnection on health check failure
                try:
                    if self._client:
                        await self._client.close()
                    self._client = aioredis.from_url(
                        self.config.url,
                        max_connections=self.config.max_connections,
                        socket_timeout=self.config.socket_timeout,
                        socket_connect_timeout=self.config.socket_connect_timeout,
                        decode_responses=self.config.decode_responses,
                        retry_on_timeout=True,
                    )
                except Exception as reconnect_err:
                    logger.debug(f"Redis reconnect attempt failed: {reconnect_err}")
    
    async def shutdown(self) -> None:
        """Shutdown Redis client and cleanup resources"""
        # Cancel all tracked tasks
        await self._task_manager.cancel_all()
        
        if self._client:
            await self._client.close()
            logger.info("Redis client shutdown complete")
    
    @property
    def is_healthy(self) -> bool:
        """Check if Redis connection is healthy"""
        return self._is_healthy
    
    @property
    def client(self) -> Optional[aioredis.Redis]:
        """Get the underlying Redis client"""
        return self._client
    
    @asynccontextmanager
    async def distributed_lock(
        self, 
        key: str, 
        ttl_seconds: int = 300,
        blocking: bool = True,
        timeout: Optional[int] = None
    ):
        """
        Distributed lock context manager using Redis.
        
        Args:
            key: Lock key
            ttl_seconds: Lock TTL in seconds (auto-release after this time)
            blocking: If True, wait for lock. If False, raise if lock unavailable.
            timeout: Max time to wait for lock (only if blocking=True)
            
        Example:
            async with redis_client.distributed_lock("my_lock", ttl_seconds=60):
                # Critical section - only one process can execute this
                await do_work()
        
        Raises:
            LockNotAcquiredError: If lock cannot be acquired (non-blocking mode)
        """
        if not self._is_healthy or not self._client:
            # Graceful degradation - no locking if Redis unavailable
            logger.warning(f"Redis unavailable - lock '{key}' not acquired")
            yield False
            return
        
        lock_acquired = False
        lock_value = f"{os.getpid()}_{asyncio.current_task().get_name()}"
        
        try:
            # Try to acquire lock
            if blocking:
                start_time = asyncio.get_event_loop().time()
                while True:
                    lock_acquired = await self._client.set(
                        key, 
                        lock_value, 
                        nx=True,  # Only set if not exists
                        ex=ttl_seconds  # Expiry time
                    )
                    
                    if lock_acquired:
                        break
                    
                    # Check timeout
                    if timeout and (asyncio.get_event_loop().time() - start_time) > timeout:
                        raise LockNotAcquiredError(f"Timeout waiting for lock: {key}")
                    
                    # Wait before retry
                    await asyncio.sleep(0.1)
            else:
                lock_acquired = await self._client.set(
                    key, 
                    lock_value, 
                    nx=True, 
                    ex=ttl_seconds
                )
                
                if not lock_acquired:
                    raise LockNotAcquiredError(f"Lock not available: {key}")
            
            logger.debug(f"Lock acquired: {key}")
            yield True
            
        finally:
            # Release lock only if we acquired it
            if lock_acquired and self._client:
                try:
                    # Use Lua script to ensure we only delete our own lock
                    lua_script = """
                    if redis.call("get", KEYS[1]) == ARGV[1] then
                        return redis.call("del", KEYS[1])
                    else
                        return 0
                    end
                    """
                    await self._client.eval(lua_script, 1, key, lock_value)
                    logger.debug(f"Lock released: {key}")
                except Exception as e:
                    logger.error(f"Failed to release lock {key}: {e}")
    
    async def acquire_lock(self, key: str, ttl_seconds: int = 300) -> bool:
        """
        Acquire a distributed lock (non-blocking).
        
        Args:
            key: Lock key
            ttl_seconds: Lock TTL in seconds
            
        Returns:
            True if lock acquired, False otherwise
        """
        if not self._is_healthy or not self._client:
            return False
        
        try:
            return bool(await self._client.set(key, "1", nx=True, ex=ttl_seconds))
        except Exception as e:
            logger.error(f"Failed to acquire lock {key}: {e}")
            return False
    
    async def release_lock(self, key: str, owner: str | None = None) -> None:
        """
        Release a distributed lock.

        SECURITY FIX (C-5): Owner is now REQUIRED for safe release. Without
        ownership verification, a stale ``release_lock`` call from a previous
        holder could destroy a new holder's lock after TTL expiry.
        
        Args:
            key: Lock key
            owner: Owner value to verify before deleting. If None, the lock
                   is NOT deleted (safe default).
        """
        if not self._is_healthy or not self._client:
            return
        
        try:
            if owner:
                # Atomic check-and-delete via Lua script
                lua_script = """
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
                """
                await self._client.eval(lua_script, 1, key, owner)
            else:
                # SECURITY: Refuse to delete without owner verification.
                # Log a warning so callers know they need to pass owner.
                logger.warning("release_lock called without owner for key '%s' — refusing unsafe delete", key)
        except Exception as e:
            logger.error(f"Failed to release lock {key}: {e}")


class LockNotAcquiredError(Exception):
    """Raised when a distributed lock cannot be acquired"""
    pass


# Global Redis client instance
_redis_client: Optional[RedisClient] = None


async def get_redis_client() -> RedisClient:
    """Get global Redis client instance"""
    global _redis_client
    
    if _redis_client is None:
        _redis_client = RedisClient()
        await _redis_client.initialize()
    
    return _redis_client


async def shutdown_redis_client() -> None:
    """Shutdown global Redis client"""
    global _redis_client
    
    if _redis_client is not None:
        await _redis_client.shutdown()
        _redis_client = None


# ============================================================
# Synchronous Redis access wrapper (FIX: async/sync bridge)
# ============================================================
_sync_redis_instance = None

def get_sync_redis():
    """Get a synchronous Redis connection for use in sync code."""
    global _sync_redis_instance
    if _sync_redis_instance is not None:
        try:
            _sync_redis_instance.ping()
            return _sync_redis_instance
        except Exception:
            pass
    try:
        import redis as _redis_mod
        url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
        _sync_redis_instance = _redis_mod.Redis.from_url(url, decode_responses=True)
        _sync_redis_instance.ping()
        return _sync_redis_instance
    except Exception as e:
        logger.warning(f"Sync Redis unavailable: {e}")
        return None
