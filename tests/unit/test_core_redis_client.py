"""Tests for backend.core.redis_client — RedisClient, locking, health, pool stats."""
import asyncio
import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


class TestRedisConfig:
    def test_defaults(self):
        from backend.core.redis_client import RedisConfig

        cfg = RedisConfig()
        assert cfg.max_connections == 50
        assert cfg.socket_timeout == 5
        assert cfg.decode_responses is True

    @patch.dict(os.environ, {"REDIS_MAX_CONNECTIONS": "10", "REDIS_SOCKET_TIMEOUT": "2"})
    def test_env_overrides(self):
        from backend.core.redis_client import RedisConfig

        cfg = RedisConfig()
        assert cfg.max_connections == 10
        assert cfg.socket_timeout == 2


class TestRedisClient:
    @pytest.fixture
    def client(self):
        from backend.core.redis_client import RedisClient

        return RedisClient()

    def test_init(self, client):
        assert client._client is None
        assert client._is_healthy is False

    def test_pool_stats_when_no_client(self, client):
        stats = client.get_pool_stats()
        assert stats["active"] == 0
        assert stats["idle"] == 0
        assert stats["max"] == 50
        assert stats["overflow"] == 0

    @pytest.mark.asyncio
    async def test_initialize_graceful_degradation(self, client):
        """When aioredis is unavailable, initialize should not raise."""
        with patch("backend.core.redis_client.REDIS_AVAILABLE", False):
            await client.initialize()
        assert client._is_healthy is False

    @pytest.mark.asyncio
    async def test_shutdown_without_client(self, client):
        """shutdown should not raise when client was never initialized."""
        await client.shutdown()
        assert client._client is None

    def test_is_healthy_property(self, client):
        assert client.is_healthy is False

    def test_client_property(self, client):
        assert client.client is None


class TestDistributedLock:
    @pytest.fixture
    def client(self):
        from backend.core.redis_client import RedisClient

        return RedisClient()

    @pytest.mark.asyncio
    async def test_lock_yields_false_when_redis_unavailable(self, client):
        """Distributed lock should yield False (degraded) when Redis is down."""
        async with client.distributed_lock("test:lock") as acquired:
            assert acquired is False

    @pytest.mark.asyncio
    async def test_acquire_lock_when_unhealthy(self, client):
        result = await client.acquire_lock("test:lock")
        assert result is False

    @pytest.mark.asyncio
    async def test_release_lock_without_owner_warns(self, client):
        """release_lock without owner should not raise, just warn."""
        await client.release_lock("test:lock")


class TestGlobalSingleton:
    @pytest.mark.asyncio
    async def test_get_redis_client_creates_instance(self):
        from backend.core.redis_client import get_redis_client, RedisClient

        with patch("backend.core.redis_client._redis_client", None):
            with patch("backend.core.redis_client.REDIS_AVAILABLE", False):
                client = await get_redis_client()
                assert isinstance(client, RedisClient)

    @pytest.mark.asyncio
    async def test_shutdown_redis_client(self):
        from backend.core.redis_client import shutdown_redis_client

        with patch("backend.core.redis_client._redis_client", None):
            await shutdown_redis_client()


class TestSyncRedis:
    def test_get_sync_redis_returns_none_when_unavailable(self):
        with patch("backend.core.redis_client._sync_redis_instance", None):
            with patch.dict("sys.modules", {"redis": None}):
                from backend.core.redis_client import get_sync_redis

                result = get_sync_redis()
                assert result is None
