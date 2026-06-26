"""
Dashboard API Endpoint
Handles authentication, 2FA, settings, and learning metrics.

SECURITY FIXES:
- #5:  Sessions stored in Redis (falls back to in-memory if Redis unavailable)
- #9:  Absolute session timeout enforced (24h max regardless of activity)
- #17: Session rotation on login and sensitive operations
- Sessions use cryptographically secure random tokens (secrets.token_urlsafe)
"""

import asyncio
import json
import logging
import secrets
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from backend.core.auth import authenticate_user

router = APIRouter()
logger = logging.getLogger(__name__)

# Session config
_RELATIVE_TTL = 3600       # 1 hour sliding window (reset on activity)
_ABSOLUTE_TTL = 86400      # 24 hours absolute max — #9 security fix
_CLEANUP_INTERVAL = 300     # 5 minutes
_SESSION_KEY_PREFIX = "vigil:session:"
_USER_SESSIONS_PREFIX = "vigil:user_sessions:"  # secondary index: SET of tokens per user

# In-memory fallback (when Redis is unavailable)
_sessions: dict[str, dict[str, Any]] = {}


async def _get_redis():
    """Try to get Redis client; returns None if unavailable."""
    try:
        from backend.core.redis_client import get_redis_client
        client = await get_redis_client()
        if client and client.is_healthy:
            return client
    except Exception:
        pass
    return None


async def _store_session(token: str, data: dict[str, Any]) -> None:
    """Store session in Redis with TTL and secondary user index, falling back to in-memory."""
    redis = await _get_redis()
    session_data = json.dumps(data)
    if redis:
        try:
            pipe = redis.pipeline()
            pipe.set(
                f"{_SESSION_KEY_PREFIX}{token}",
                session_data,
                ex=_ABSOLUTE_TTL,  # #9: hard 24h expiry on the key itself
            )
            # Maintain secondary index for O(1) user session lookup
            user_id = data.get("user_id")
            if user_id:
                pipe.sadd(f"{_USER_SESSIONS_PREFIX}{user_id}", token)
                pipe.expire(f"{_USER_SESSIONS_PREFIX}{user_id}", _ABSOLUTE_TTL)
            await pipe.execute()
            return
        except Exception as exc:
            logger.warning("Redis session store failed, using in-memory: %s", exc)
    _sessions[token] = data


async def _get_session(token: str) -> dict[str, Any] | None:
    """Retrieve session from Redis (with sliding refresh) or in-memory."""
    redis = await _get_redis()
    if redis:
        try:
            raw = await redis.get(f"{_SESSION_KEY_PREFIX}{token}")
            if raw:
                return json.loads(raw)
            return None
        except Exception:
            pass
    return _sessions.get(token)


async def _delete_session(token: str) -> None:
    """Delete session from Redis and in-memory, including secondary index."""
    redis = await _get_redis()
    if redis:
        try:
            # Read session data to find user_id before deleting
            raw = await redis.get(f"{_SESSION_KEY_PREFIX}{token}")
            pipe = redis.pipeline()
            pipe.delete(f"{_SESSION_KEY_PREFIX}{token}")
            if raw:
                data = json.loads(raw)
                user_id = data.get("user_id")
                if user_id:
                    pipe.srem(f"{_USER_SESSIONS_PREFIX}{user_id}", token)
            await pipe.execute()
        except Exception:
            pass
    _sessions.pop(token, None)


async def _refresh_session_ttl(token: str, data: dict[str, Any]) -> None:
    """Refresh sliding TTL without exceeding absolute TTL. #9 + #17."""
    redis = await _get_redis()
    now = time.time()
    created_at = data.get("created_at", now)
    remaining_absolute = _ABSOLUTE_TTL - (now - created_at)
    refresh_ttl = min(_RELATIVE_TTL, max(int(remaining_absolute), 60))
    if redis:
        try:
            await redis.set(
                f"{_SESSION_KEY_PREFIX}{token}",
                json.dumps(data),
                ex=refresh_ttl,
            )
            return
        except Exception:
            pass
    _sessions[token] = data


@router.post("/login")
async def login(request: Request):
    """Authenticate user and return session token.

    SECURITY (#17): Generates a cryptographically secure token using
    secrets.token_urlsafe(32) instead of uuid4. Old sessions for the
    same user are invalidated to prevent session fixation.
    """
    body = await request.json()
    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    user = await authenticate_user(username, password)
    if not user:
        logger.warning("[AUTH] Failed login attempt for username=%s", username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # #17: Generate cryptographically secure session token
    session_token = secrets.token_urlsafe(32)
    now = time.time()
    session_data = {
        "user_id": user["id"],
        "username": user["username"],
        "created_at": now,
        "expires_at": now + _RELATIVE_TTL,
        "absolute_expires_at": now + _ABSOLUTE_TTL,
        "last_accessed": now,
    }

    # #17: Invalidate any existing sessions for this user (prevent fixation)
    await _invalidate_user_sessions(user["id"])

    await _store_session(session_token, session_data)

    logger.info("[AUTH] Successful login: user=%s", user["username"])
    return {"token": session_token, "user": {"id": user["id"], "username": user["username"]}}


async def _invalidate_user_sessions(user_id: str) -> None:
    """Remove all sessions for a given user ID. #17 security fix.

    Uses a secondary Redis SET index (vigil:user_sessions:{user_id}) for O(1)
    lookup instead of scanning all vigil:session:* keys.
    """
    redis = await _get_redis()
    if redis:
        try:
            index_key = f"{_USER_SESSIONS_PREFIX}{user_id}"
            raw_tokens = await redis.smembers(index_key)
            if raw_tokens:
                pipe = redis.pipeline()
                for tok in raw_tokens:
                    tok_str = tok.decode("utf-8") if isinstance(tok, bytes) else tok
                    pipe.delete(f"{_SESSION_KEY_PREFIX}{tok_str}")
                pipe.delete(index_key)
                await pipe.execute()
            return
        except Exception:
            pass
    # In-memory fallback
    to_remove = [
        t for t, s in list(_sessions.items())
        if s.get("user_id") == user_id
    ]
    for t in to_remove:
        _sessions.pop(t, None)


@router.get("/me")
async def get_current_user(request: Request):
    """Get current authenticated user."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = auth_header[7:]
    session = await _get_session(token)

    now = time.time()

    # #9: Check BOTH relative and absolute expiry
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    if session.get("expires_at", 0) < now:
        await _delete_session(token)
        raise HTTPException(status_code=401, detail="Session expired (relative)")
    if session.get("absolute_expires_at", 0) < now:
        await _delete_session(token)
        raise HTTPException(status_code=401, detail="Session expired (absolute 24h limit)")

    # Sliding expiry: extend on use (but never past absolute limit)
    session["last_accessed"] = now
    new_relative = now + _RELATIVE_TTL
    session["expires_at"] = min(new_relative, session.get("absolute_expires_at", now + _ABSOLUTE_TTL))
    await _refresh_session_ttl(token, session)

    return {"user_id": session["user_id"], "username": session["username"]}


@router.post("/logout")
async def logout(request: Request):
    """Logout and invalidate session."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        await _delete_session(token)
    return {"message": "Logged out successfully"}


async def start_session_cleanup():
    """Background coroutine that periodically cleans up expired sessions.

    Managed by the caller (main.py lifespan) via TaskManager.
    """
    while True:
        try:
            await asyncio.sleep(_CLEANUP_INTERVAL)
            now = time.time()
            # In-memory cleanup (Redis handles its own TTL)
            expired = [t for t, s in list(_sessions.items())
                       if s.get("expires_at", 0) < now or s.get("absolute_expires_at", 0) < now]
            for token in expired:
                _sessions.pop(token, None)
            if expired:
                logger.info("Cleaned up %d expired in-memory session(s)", len(expired))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("Session cleanup error: %s", e)


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        from backend.ai.cortex import get_cortex_engine
        cortex = get_cortex_engine()
        cache_stats = cortex.get_cache_stats()
    except Exception:
        cache_stats = {}
    redis = await _get_redis()
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "active_sessions": len(_sessions),
        "session_backend": "redis" if redis else "in-memory",
        "cache": cache_stats,
    }
