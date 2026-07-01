"""
Authentication and session management utilities.

Provides session cleanup functionality for WebSocket authentication.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SESSION_FILE = Path(__file__).resolve().parents[2] / "data" / "session.json"


def load_config() -> dict[str, Any]:
    """Load dashboard configuration from file."""
    config_path = Path(__file__).resolve().parents[2] / "data" / "config.json"
    try:
        if config_path.exists():
            return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("config load failed: %s", exc)
    return {}


def load_session() -> dict[str, Any]:
    """Load session data from file."""
    try:
        if SESSION_FILE.exists():
            return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("session load failed: %s", exc)
    return {}


async def start_session_cleanup() -> None:
    """Background task to clean up expired sessions."""
    logger.info("[SESSION] Expiry cleanup task started (no-op stub)")
    # This is a stub - in a full implementation, this would periodically
    # clean up expired session files from the data/ directory
    while True:
        try:
            import asyncio
            await asyncio.sleep(3600)  # Run once per hour
            # Cleanup logic would go here
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.debug("Session cleanup error: %s", exc)


async def authenticate_user(username: str, password: str) -> dict | None:
    """Authenticate a user against the API_AUTH_KEY.

    In Vigilagent's single-operator model the only valid credential is
    the API_AUTH_KEY set in the environment. Any username is accepted as
    long as the password matches the key.

    Returns a user dict on success, None on failure.
    """
    api_key = os.getenv("API_AUTH_KEY", "")
    if not api_key:
        logger.warning("[AUTH] API_AUTH_KEY not set — authentication disabled")
        return None
    if password == api_key:
        return {"id": "admin", "username": username or "operator"}
    return None