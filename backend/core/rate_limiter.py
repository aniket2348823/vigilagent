"""
Rate Limiting Utility for API Endpoints
Prevents abuse and DoS attacks with configurable limits per endpoint.

#8 SECURITY FIX: Uses Redis-backed distributed rate limiting when Redis is
available (supports multi-instance deployments), falling back to in-memory
token bucket for single-instance or when Redis is offline.
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict
from functools import wraps

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter with per-IP tracking.

    #8: When Redis is available, uses a sliding window counter for distributed
    rate limiting that works across multiple backend instances. Falls back to
    in-memory token bucket for single-instance deployments.
    """

    MAX_BUCKETS = 50000
    _REDIS_CHECK_INTERVAL = 10  # seconds between Redis health checks

    def __init__(self):
        # In-memory fallback structure: {ip: {endpoint: (tokens, last_refill)}}
        self._buckets: dict[str, dict[str, tuple[float, float]]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._redis_healthy = False
        # Cached Redis client with short-lived TTL to avoid per-request overhead
        self._cached_redis = None
        self._redis_check_ts: float = 0.0

        # Default limits (requests per minute)
        self._limits = {
            "default": 60,
            "/api/dashboard/stats": 120,
            "/api/reports/pdf": 10,
            "/api/reports/consolidated": 5,
            "/api/attack/fire": 30,
            "/api/recon": 60,
            "/api/ai": 20,
        }

    def configure_limit(self, endpoint_pattern: str, requests_per_minute: int):
        """Configure custom rate limit for an endpoint pattern."""
        self._limits[endpoint_pattern] = requests_per_minute
        logger.info("Rate limit configured: %s = %d req/min", endpoint_pattern, requests_per_minute)

    def _get_limit(self, endpoint: str) -> int:
        """Get the rate limit for an endpoint (matches patterns)."""
        if endpoint in self._limits:
            return self._limits[endpoint]
        for pattern, limit in self._limits.items():
            if pattern != "default" and endpoint.startswith(pattern):
                return limit
        return self._limits["default"]

    async def _get_redis(self):
        """Try to get Redis client; returns cached instance if still healthy.

        Caches the result for _REDIS_CHECK_INTERVAL seconds to avoid
        get_redis_client() + is_healthy checks on every API request.
        """
        now = time.monotonic()
        if self._cached_redis and (now - self._redis_check_ts) < self._REDIS_CHECK_INTERVAL:
            try:
                if self._cached_redis.is_healthy:
                    return self._cached_redis
            except Exception:
                pass
            self._cached_redis = None
        try:
            from backend.core.redis_client import get_redis_client
            client = await get_redis_client()
            if client and client.is_healthy:
                self._redis_healthy = True
                self._cached_redis = client
                self._redis_check_ts = now
                return client
        except Exception:
            pass
        self._redis_healthy = False
        self._cached_redis = None
        return None

    async def check_rate_limit(self, client_ip: str, endpoint: str) -> bool:
        """
        Check if request is within rate limit.
        Returns True if allowed, raises HTTPException if rate limited.

        #8: Uses Redis sliding window when available, in-memory token bucket otherwise.
        """
        limit = self._get_limit(endpoint)

        # Try Redis-backed distributed rate limiting first
        redis = await self._get_redis()
        if redis:
            try:
                return await self._check_redis_rate_limit(redis, client_ip, endpoint, limit)
            except Exception as exc:
                logger.debug("Redis rate limit failed, falling back to in-memory: %s", exc)

        # Fallback to in-memory token bucket
        return self._check_inmemory_rate_limit(client_ip, endpoint, limit)

    async def _check_redis_rate_limit(self, redis, client_ip: str, endpoint: str, limit: int) -> bool:
        """Redis-backed sliding window rate limiter (#8)."""
        key = f"vigil:ratelimit:{client_ip}:{endpoint}"
        now = time.time()
        window_start = now - 60  # 1-minute sliding window

        # Use a Redis pipeline for atomic operations
        pipe = redis.pipeline()
        # Remove entries outside the window
        pipe.zremrangebyscore(key, 0, window_start)
        # Count current window entries
        pipe.zcard(key)
        # Add current request
        pipe.zadd(key, {f"{now}:{client_ip}:{endpoint}:{time.monotonic_ns()}": now})
        # Set expiry on the key
        pipe.expire(key, 61)
        results = await pipe.execute()

        current_count = results[1]

        if current_count >= limit:
            retry_after = 60 - (now - window_start)
            logger.warning(
                "[SECURITY] Rate limit exceeded (Redis): ip=%s endpoint=%s count=%d limit=%d",
                client_ip, endpoint, current_count, limit,
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Try again in {int(retry_after) + 1} seconds.",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        return True

    def _check_inmemory_rate_limit(self, client_ip: str, endpoint: str, limit: int) -> bool:
        """In-memory token bucket rate limiter (fallback)."""
        refill_rate = limit / 60.0
        capacity = limit
        current_time = time.time()

        with self._lock:
            if endpoint not in self._buckets[client_ip]:
                self._buckets[client_ip][endpoint] = (capacity, current_time)

            tokens, last_refill = self._buckets[client_ip][endpoint]
            time_elapsed = current_time - last_refill
            tokens = min(capacity, tokens + time_elapsed * refill_rate)

            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[client_ip][endpoint] = (tokens, current_time)
                return True
            else:
                retry_after = int((1.0 - tokens) / refill_rate) + 1
                logger.warning(
                    "Rate limit exceeded (in-memory): %s on %s (limit: %d req/min)",
                    client_ip, endpoint, limit,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

    async def cleanup_old_buckets(self, max_age_seconds: int = 1800):
        """Remove stale rate limit data."""
        # Clean Redis keys older than max_age — scan in small batches to avoid
        # blocking the event loop on high-traffic deployments.
        redis = await self._get_redis()
        if redis:
            try:
                cursor = 0
                cleaned = 0
                _SCAN_BATCH = 50
                while True:
                    cursor, keys = await redis.scan(cursor=cursor, match="vigil:ratelimit:*", count=_SCAN_BATCH)
                    if keys:
                        pipe = redis.pipeline()
                        for key in keys:
                            pipe.ttl(key)
                        ttls = await pipe.execute()
                        delete_keys = [k for k, ttl in zip(keys, ttls) if ttl <= 0]
                        if delete_keys:
                            await redis.delete(*delete_keys)
                            cleaned += len(delete_keys)
                    if cursor == 0:
                        break
                if cleaned:
                    logger.info("Cleaned up %d stale Redis rate limit keys", cleaned)
            except Exception as exc:
                logger.debug("Redis rate limit cleanup failed: %s", exc)

        # Also clean in-memory buckets
        current_time = time.time()
        ips_to_remove = []
        with self._lock:
            total_buckets = sum(len(eps) for eps in self._buckets.values())
            if total_buckets > self.MAX_BUCKETS:
                all_entries = []
                for ip, endpoints in self._buckets.items():
                    for endpoint, (_tokens, last_refill) in endpoints.items():
                        all_entries.append((last_refill, ip, endpoint))
                all_entries.sort(key=lambda x: x[0])
                evict_count = len(all_entries) // 4
                for _, ip, endpoint in all_entries[:evict_count]:
                    self._buckets.get(ip, {}).pop(endpoint, None)
                ips_to_remove = [ip for ip, eps in self._buckets.items() if not eps]
                for ip in ips_to_remove:
                    del self._buckets[ip]
                ips_to_remove = []

            for ip, endpoints in self._buckets.items():
                endpoints_to_remove = []
                for endpoint, (_tokens, last_refill) in endpoints.items():
                    if current_time - last_refill > max_age_seconds:
                        endpoints_to_remove.append(endpoint)
                for endpoint in endpoints_to_remove:
                    del endpoints[endpoint]
                if not endpoints:
                    ips_to_remove.append(ip)

            for ip in ips_to_remove:
                del self._buckets[ip]

        if ips_to_remove:
            logger.info("Cleaned up %d stale in-memory rate limit buckets", len(ips_to_remove))


# Global rate limiter instance
rate_limiter = RateLimiter()


def rate_limit(endpoint_override: str = None):
    """
    Decorator for FastAPI endpoints to apply rate limiting.

    Usage:
        @router.get("/expensive")
        @rate_limit()
        async def expensive_endpoint(request: Request):
            ...
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")

            if request:
                client_ip = request.client.host if request.client else "unknown"
                forwarded = request.headers.get("x-forwarded-for")
                if forwarded:
                    client_ip = forwarded.split(",")[0].strip()
                elif client_ip in ("127.0.0.1", "::1", ""):
                    real_ip = request.headers.get("x-real-ip")
                    if real_ip:
                        client_ip = real_ip.strip()
                endpoint = endpoint_override or request.url.path
                await rate_limiter.check_rate_limit(client_ip, endpoint)

            return await func(*args, **kwargs)

        return wrapper

    return decorator


async def start_cleanup_task():
    """Background task to periodically clean up old rate limit buckets."""
    while True:
        try:
            await asyncio.sleep(3600)
            await rate_limiter.cleanup_old_buckets()
        except Exception as e:
            logger.error("Rate limiter cleanup error: %s", e)
