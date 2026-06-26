"""
CSRF (Cross-Site Request Forgery) Protection
Implements token-based CSRF protection for state-changing endpoints.
"""

import asyncio
import logging
import secrets
import time
from functools import wraps

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class CSRFProtection:
    """
    Token-based CSRF protection with session tracking.
    Generates and validates CSRF tokens for state-changing operations.
    """

    # Maximum number of tokens to prevent unbounded memory growth
    MAX_TOKENS = 10000

    def __init__(self, token_expiry_seconds: int = 3600):
        # Structure: {token: (session_id, expiry_time)}
        self._tokens: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()
        self.token_expiry_seconds = token_expiry_seconds

    async def generate_token(self, session_id: str) -> str:
        """
        Generate a new CSRF token for a session.

        Args:
            session_id: Unique session identifier

        Returns:
            CSRF token string
        """
        async with self._lock:
            # SECURITY: Enforce hard cap to prevent memory exhaustion
            if len(self._tokens) >= self.MAX_TOKENS:
                await self.cleanup_expired_tokens()
                # If still at cap after cleanup, force-evict oldest 20%
                if len(self._tokens) >= self.MAX_TOKENS:
                    sorted_tokens = sorted(self._tokens.items(), key=lambda x: x[1][1])
                    evict_count = len(sorted_tokens) // 5
                    for token, _ in sorted_tokens[:evict_count]:
                        del self._tokens[token]

            # Generate cryptographically secure token
            token = secrets.token_urlsafe(32)
            expiry = time.time() + self.token_expiry_seconds

            self._tokens[token] = (session_id, expiry)

            logger.debug(f"Generated CSRF token for session {session_id}")
            return token

    async def validate_token(self, token: str | None, session_id: str, consume: bool = True) -> bool:
        """
        Validate a CSRF token.

        Args:
            token: The CSRF token to validate
            session_id: Expected session ID
            consume: Whether to consume (delete) the token after validation

        Returns:
            True if valid, False otherwise
        """
        if not token:
            logger.warning("CSRF validation failed: No token provided")
            return False

        async with self._lock:
            if token not in self._tokens:
                logger.warning("CSRF validation failed: Unknown token")
                return False

            stored_session_id, expiry = self._tokens[token]

            # Check expiry
            if time.time() > expiry:
                logger.warning("CSRF validation failed: Token expired")
                del self._tokens[token]
                return False

            # Check session match
            if stored_session_id != session_id:
                logger.warning(
                    f"CSRF validation failed: Session mismatch (expected {session_id}, got {stored_session_id})"
                )
                return False

            # Valid token
            if consume:
                del self._tokens[token]
                logger.debug(f"CSRF token validated and consumed for session {session_id}")
            else:
                logger.debug(f"CSRF token validated (not consumed) for session {session_id}")

            return True

    async def cleanup_expired_tokens(self):
        """Remove expired tokens from storage."""
        async with self._lock:
            current_time = time.time()
            expired_tokens = [token for token, (_, expiry) in self._tokens.items() if current_time > expiry]

            for token in expired_tokens:
                del self._tokens[token]

            if expired_tokens:
                logger.info(f"Cleaned up {len(expired_tokens)} expired CSRF tokens")


# Global CSRF protection instance
csrf_protection = CSRFProtection()


def get_session_id(request: Request) -> str:
    """
    Extract session ID from request.
    Uses client IP + User-Agent as fallback if no session cookie.
    """
    # Try to get session from cookie or header
    session_cookie = request.cookies.get("session_id")
    if session_cookie:
        return session_cookie

    # Fallback: use client IP + User-Agent
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    return f"{client_ip}:{user_agent}"


def csrf_protect(consume_token: bool = True):
    """
    Decorator to protect endpoints with CSRF validation.

    Usage:
        @router.post("/sensitive")
        @csrf_protect()
        async def sensitive_endpoint(request: Request):
            ...

    Args:
        consume_token: Whether to consume the token after validation (default: True)
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request object
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")

            if not request:
                raise HTTPException(status_code=500, detail="CSRF protection requires Request object")

            # Get CSRF token from header or form data
            csrf_token = request.headers.get("X-CSRF-Token")
            if not csrf_token:
                # Try to get from query params (less secure, but supported)
                csrf_token = request.query_params.get("csrf_token")

            # Get session ID
            session_id = get_session_id(request)

            # Validate token
            is_valid = await csrf_protection.validate_token(csrf_token, session_id, consume=consume_token)

            if not is_valid:
                raise HTTPException(status_code=403, detail="CSRF validation failed. Invalid or missing token.")

            # Call original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


async def start_csrf_cleanup_task():
    """Background task to periodically clean up expired CSRF tokens."""
    while True:
        try:
            await asyncio.sleep(600)  # Run every 10 minutes
            await csrf_protection.cleanup_expired_tokens()
        except Exception as e:
            logger.error(f"CSRF cleanup error: {e}")
