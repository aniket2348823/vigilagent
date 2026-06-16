"""
Vigilagent Credential / Session Vault (Architecture §2 (Intelligence Layer),
§13.2, §25, §29.11(18))
================================================================================
Encrypted, deduplicated store for AUTHORIZED test credentials and sessions. It
replaces the hardcoded `MOCK_USER_B_TOKEN` used by the Doppelganger IDOR module
(Architecture §25) and is queried before authentication attempts and during
auth recovery (Architecture §14, RecoveryEngine).

Security:
  - Secrets are encrypted at rest with Fernet, reusing the forensic_collector
    encryption pattern (PBKDF2-HMAC-SHA256 key derivation).
  - Each credential gets a stable cred_id = sha256(target|service|principal) so
    the same credential is never stored twice (Architecture §9 idempotent dedup).
  - Sensitive values are never logged.

This vault holds ONLY credentials an operator has provided or that were captured
inside an authorized engagement scope. It is not a credential-theft tool.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger("vigilagent.vault")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    _CRYPTO_OK = False

CredKind = Literal["password", "token", "jwt", "cookie", "api_key", "session"]
Privilege = Literal["unknown", "user", "admin"]

_VAULT_DIR = Path("scan_states") / "vault"
# HIGH-18: Derive per-installation salt from environment or persisted random
# value. platform.node()/machine() are identical inside Docker/K8s containers
# (same image), so we prefer os.getenv("HOSTNAME") which can be overridden
# via Docker --hostname or Kubernetes downward API.
_VAULT_SALT = b"vigilagent-credential-vault-v1"  # static fallback
try:
    _hostname = os.getenv("HOSTNAME", "")
    if _hostname.strip():
        _VAULT_SALT = hashlib.sha256(_hostname.encode()).digest()[:16]
    else:
        # Persist a random salt on first run so it stays stable across restarts
        _VAULT_DIR.mkdir(parents=True, exist_ok=True)
        _salt_file = _VAULT_DIR / ".vault_salt"
        if _salt_file.exists():
            _VAULT_SALT = _salt_file.read_bytes().strip()[:16]
        else:
            _VAULT_SALT = os.urandom(16)
            try:
                _salt_file.write_bytes(_VAULT_SALT)
            except Exception:
                pass  # best-effort; falls back to static salt next time
except Exception:
    pass  # use static fallback


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Credential:
    cred_id: str
    scan_id: str
    target: str
    service: str           # http, jwt, api, cookie, session...
    principal: Optional[str]
    kind: CredKind
    source: str            # recon | browser | response | manual
    privilege: Privilege = "unknown"
    captured_at: str = field(default_factory=_now)
    # secret is stored encrypted; never serialized in cleartext
    _secret: str = ""

    def public_dict(self) -> dict:
        """Serializable view WITHOUT the secret value (safe to log/export)."""
        return {
            "cred_id": self.cred_id,
            "scan_id": self.scan_id,
            "target": self.target,
            "service": self.service,
            "principal": self.principal,
            "kind": self.kind,
            "source": self.source,
            "privilege": self.privilege,
            "captured_at": self.captured_at,
        }


def make_cred_id(target: str, service: str, principal: str | None) -> str:
    raw = f"{(target or '').lower()}|{(service or '').lower()}|{(principal or '').lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CredentialVault:
    """Encrypted, deduplicated credential/session store (Architecture §13.2)."""

    def __init__(self, storage_dir: str | Path | None = None, encryption_key: str | None = None) -> None:
        self.storage_dir = Path(storage_dir) if storage_dir else _VAULT_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._creds: dict[str, Credential] = {}
        self._init_encryption(encryption_key)
        self._load()

    # ── Encryption (forensic_collector pattern) ───────────────────────────────

    def _init_encryption(self, encryption_key: str | None) -> None:
        self.encryption_enabled = False
        self.cipher = None
        if not _CRYPTO_OK:
            logger.warning("[Vault] cryptography unavailable; secrets stored obfuscated only.")
            return
        try:
            key_material = (
                encryption_key
                or os.getenv("VIGILAGENT_VAULT_KEY")
                or os.getenv("VAULT_ENCRYPTION_KEY")
                or os.getenv("FORENSIC_ENCRYPTION_KEY")
            )
            if not key_material:
                # No env-provided key: use a persisted local key so the vault is
                # stable across restarts (dev). Production should set
                # VIGILAGENT_VAULT_KEY. This is INFO, not WARNING — it is an
                # expected dev fallback, not a fault (keeps stderr clean).
                self.cipher = Fernet(self._load_or_create_local_key())
                self.encryption_enabled = True
                logger.info("[Vault] Using persisted local dev key "
                            "(set VIGILAGENT_VAULT_KEY to override in production).")
                return
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_VAULT_SALT, iterations=100000)
            key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
            self.cipher = Fernet(key)
            self.encryption_enabled = True
        except Exception as exc:  # pragma: no cover
            logger.error("[Vault] encryption init failed: %s", exc)
            self.encryption_enabled = False

    def _load_or_create_local_key(self) -> bytes:
        """Load (or create once) a persisted local Fernet key for dev use.

        Stored under the vault dir with owner-only permissions where supported.
        This keeps the vault stable across restarts when no VIGILAGENT_VAULT_KEY
        is set, instead of regenerating an ephemeral key each run. The key file
        is gitignored via the scan_states/ data path."""
        import platform

        try:
            import fcntl
        except ImportError:
            fcntl = None
        try:
            import msvcrt
        except ImportError:
            msvcrt = None

        key_path = self.storage_dir / ".vault_key"
        try:
            # FIX-019: Atomic file creation to prevent TOCTOU race
            lock_path = self.storage_dir / ".vault_key.lock"
            with open(lock_path, "w") as lock_file:
                if fcntl:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                elif msvcrt:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                # On other platforms, file is already exclusive via 'x' mode
                try:
                    if key_path.exists():
                        data = key_path.read_bytes().strip()
                        if data:
                            return data
                    key = Fernet.generate_key()
                    # Atomic write: write to temp, then rename
                    tmp_path = self.storage_dir / ".vault_key.tmp"
                    tmp_path.write_bytes(key)
                    tmp_path.rename(key_path)
                    try:
                        os.chmod(key_path, 0o600)
                    except Exception as exc:
                        logger.debug("[Vault] chmod failed (non-POSIX?): %s", exc)  # best-effort on platforms without POSIX perms
                    return key
                finally:
                    if fcntl:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    elif msvcrt:
                        try:
                            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                        except Exception:
                            pass
        except Exception as exc:  # pragma: no cover - fall back to in-memory key
            logger.debug("[Vault] local key persistence unavailable (%s); using in-memory key.", exc)
            return Fernet.generate_key()

    def _encrypt(self, secret: str) -> str:
        if self.encryption_enabled and self.cipher:
            try:
                return self.cipher.encrypt(secret.encode("utf-8")).decode("ascii")
            except Exception as exc:
                logger.error("[Vault] Fernet encrypt failed: %s", exc)
        # FIX-017: Base64 is NOT encryption — refuse to store if proper encryption unavailable
        raise RuntimeError(
            "Credential vault encryption is unavailable. "
            "Install 'cryptography' or set VIGILAGENT_VAULT_KEY."
        )

    def _decrypt(self, blob: str) -> str:
        if blob.startswith("b64:"):
            try:
                return base64.b64decode(blob[4:]).decode("utf-8")
            except Exception as exc:
                logger.debug("[Vault] b64 decode failed: %s", exc)
                return ""
        if self.encryption_enabled and self.cipher:
            try:
                return self.cipher.decrypt(blob.encode("ascii")).decode("utf-8")
            except Exception as exc:
                logger.debug("[Vault] Fernet decrypt failed: %s", exc)
                return ""
        return ""

    # ── Persistence ────────────────────────────────────────────────────────────

    def _store_file(self) -> Path:
        return self.storage_dir / "credentials.json"

    def _load(self) -> None:
        path = self._store_file()
        if not path.exists():
            return
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("[Vault] Failed to load credential store: %s", exc)
            return
        with self._lock:
            for r in rows:
                cred = Credential(
                    cred_id=r["cred_id"], scan_id=r.get("scan_id", ""), target=r.get("target", ""),
                    service=r.get("service", ""), principal=r.get("principal"),
                    kind=r.get("kind", "token"), source=r.get("source", "manual"),
                    privilege=r.get("privilege", "unknown"), captured_at=r.get("captured_at", _now()),
                )
                cred._secret = r.get("secret_enc", "")
                self._creds[cred.cred_id] = cred

    def _save(self) -> None:
        rows = []
        for cred in self._creds.values():
            row = cred.public_dict()
            row["secret_enc"] = cred._secret
            rows.append(row)
        tmp = self._store_file().with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(rows, indent=2), encoding="utf-8")
            os.replace(tmp, self._store_file())
        except Exception as exc:
            logger.error("[Vault] save failed: %s", exc)

    # ── Public API ──────────────────────────────────────────────────────────────

    def store(self, *, scan_id: str, target: str, service: str, secret: str,
              kind: CredKind = "token", principal: str | None = None,
              source: str = "manual", privilege: Privilege = "unknown") -> Credential:
        """Store (or update) a credential. Dedup by stable cred_id (§9)."""
        cred_id = make_cred_id(target, service, principal)
        with self._lock:
            existing = self._creds.get(cred_id)
            if existing:
                # Update secret/privilege but keep one entry (idempotent dedup).
                existing._secret = self._encrypt(secret)
                if privilege != "unknown":
                    existing.privilege = privilege
                existing.captured_at = _now()
                self._save()
                return existing
            cred = Credential(
                cred_id=cred_id, scan_id=scan_id, target=target, service=service,
                principal=principal, kind=kind, source=source, privilege=privilege,
            )
            cred._secret = self._encrypt(secret)
            self._creds[cred_id] = cred
            self._save()
            logger.info("[Vault] stored credential %s (%s/%s, priv=%s)", cred_id[:12], service, kind, privilege)
            return cred

    def get_secret(self, cred_id: str) -> str | None:
        with self._lock:
            cred = self._creds.get(cred_id)
        return self._decrypt(cred._secret) if cred else None

    def find(self, *, target: str | None = None, service: str | None = None,
             privilege: Privilege | None = None, kind: CredKind | None = None) -> list[Credential]:
        with self._lock:
            results = list(self._creds.values())
        if target:
            t = target.lower()
            results = [c for c in results if t in c.target.lower()]
        if service:
            results = [c for c in results if c.service == service]
        if privilege:
            results = [c for c in results if c.privilege == privilege]
        if kind:
            results = [c for c in results if c.kind == kind]
        return results

    def get_fresh_credential(self, target: str, *, service: str = "http",
                             privilege: Privilege | None = None) -> tuple[Credential, str] | None:
        """Return the most recent matching (credential, secret) for re-auth
        (Architecture §14 RecoveryEngine auth recovery)."""
        matches = self.find(target=target, service=service, privilege=privilege)
        if not matches:
            matches = self.find(target=target)
        if not matches:
            return None
        matches.sort(key=lambda c: c.captured_at, reverse=True)
        cred = matches[0]
        secret = self.get_secret(cred.cred_id) or ""
        return (cred, secret) if secret else None

    def get_alternate_identity(self, target: str, exclude_principal: str | None = None) -> tuple[Credential, str] | None:
        """Return a different identity for IDOR/privilege tests (replaces
        MOCK_USER_B_TOKEN — Architecture §25)."""
        matches = self.find(target=target)
        for cred in sorted(matches, key=lambda c: c.captured_at, reverse=True):
            if exclude_principal and cred.principal == exclude_principal:
                continue
            secret = self.get_secret(cred.cred_id)
            if secret:
                return cred, secret
        return None

    def stats(self) -> dict:
        with self._lock:
            return {
                "total": len(self._creds),
                "by_privilege": {
                    p: sum(1 for c in self._creds.values() if c.privilege == p)
                    for p in ("unknown", "user", "admin")
                },
                "encryption_enabled": self.encryption_enabled,
            }


# Global vault instance.
credential_vault = CredentialVault()
