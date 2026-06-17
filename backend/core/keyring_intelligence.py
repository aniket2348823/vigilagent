"""
PROBLEM 11 FIX: KeyringIntelligence — Token classifier, deduplicator, and expiry detector.
Replaces raw unstructured keyring.json dump with classified, deduplicated intelligence.
"""

import re
import json
import time
import hashlib
import base64
import logging
from enum import Enum



def _read_json_file(path: str) -> dict:
    """Read and parse a JSON file (sync helper for use with asyncio.to_thread)."""
    with open(path, "r") as f:
        return json.load(f)

logger = logging.getLogger("KeyringIntelligence")


class TokenType(Enum):
    JWT = "jwt"
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SESSION_COOKIE = "session_cookie"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    UNKNOWN = "unknown"


class KeyringIntelligence:
    KEYRING_FILE = "keyring.json"

    JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
    API_KEY_PATTERNS = [
        re.compile(r'^sk-[A-Za-z0-9]{32,}$'),       # OpenAI style
        re.compile(r'^Bearer [A-Za-z0-9_-]{20,}$'),
        re.compile(r'^[A-Za-z0-9]{32}$'),             # generic 32-char key
        re.compile(r'^[A-Za-z0-9]{40}$'),             # generic 40-char key
    ]

    def classify(self, token: str) -> TokenType:
        """Classify a token into its type based on pattern matching."""
        token = token.strip()
        if self.JWT_PATTERN.match(token):
            return TokenType.JWT
        if token.startswith("Bearer "):
            return TokenType.BEARER_TOKEN
        if token.startswith("Basic "):
            return TokenType.BASIC_AUTH
        for pat in self.API_KEY_PATTERNS:
            if pat.match(token):
                return TokenType.API_KEY
        return TokenType.UNKNOWN

    def is_expired_jwt(self, token: str) -> bool:
        """Check if a JWT token has expired based on the exp claim."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return False
            # Add padding for base64 decoding
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload = base64.b64decode(payload_b64)
            data = json.loads(payload)
            exp = data.get("exp", 0)
            return time.time() > exp if exp else False
        except Exception as exc:
            logger.debug("KeyringIntelligence: JWT expiry check failed: %s", exc)
            return False

    def fingerprint(self, token: str) -> str:
        """Generate a short unique fingerprint for deduplication."""
        return hashlib.sha256(token.encode()).hexdigest()[:16]

    async def process_and_store(self, token: str, url: str, context: str = "") -> dict:
        """Classify, deduplicate, and store a captured token."""
        fp = self.fingerprint(token)
        token_type = self.classify(token)
        expired = False
        if token_type == TokenType.JWT:
            expired = self.is_expired_jwt(token)

        entry = {
            "fingerprint": fp,
            "type": token_type.value,
            "token_preview": token[:8] + "****" + token[-4:] if len(token) > 12 else "****",
            # FIX: Do NOT persist the full token to disk. Only store the
            # preview and fingerprint. This prevents secret leakage if the
            # keyring.json file is exfiltrated.
            "source_url": url,
            "context": context,
            "expired": expired,
            "captured_at": time.time()
        }

        try:
            with open(self.KEYRING_FILE, "r") as f:
                keyring = json.load(f)
        except Exception as exc:
            logger.debug("KeyringIntelligence: keyring file load failed: %s", exc)
            keyring = {"tokens": [], "stats": {"total": 0, "deduplicated": 0}}

        # Deduplicate by fingerprint
        existing_fps = {t["fingerprint"] for t in keyring.get("tokens", [])}
        if fp not in existing_fps:
            keyring.setdefault("tokens", []).append(entry)
            keyring["stats"] = keyring.get("stats", {})
            keyring["stats"]["total"] = len(keyring["tokens"])
            def _write_sync():
                with open(self.KEYRING_FILE, "w") as f:
                    json.dump(keyring, f, indent=2)

            await asyncio.to_thread(_write_sync)

        else:
            keyring["stats"]["deduplicated"] = keyring["stats"].get("deduplicated", 0) + 1

        return entry

    async def get_active_tokens(self) -> list:
        """Return only non-expired, classified tokens."""
        active = []
        for t in keyring.get("tokens", []):
            if not t.get("expired", False):
                active.append(t)
        return active

    async def get_stats(self) -> dict:
        """Return keyring statistics."""
        tokens = keyring.get("tokens", [])
        by_type = {}
        expired_count = 0
        for t in tokens:
            ttype = t.get("type", "unknown")
            by_type[ttype] = by_type.get(ttype, 0) + 1
            if t.get("expired"):
                expired_count += 1

        return {
            "total": len(tokens),
            "by_type": by_type,
            "expired": expired_count,
            "active": len(tokens) - expired_count
        }
