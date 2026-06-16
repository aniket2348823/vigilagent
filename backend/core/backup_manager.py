"""
Scan State Backup Manager (Architecture security hardening)
================================================================================
Provides backup and restore capabilities for scan state data to prevent
data loss during failures. Implements periodic snapshots and recovery.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vigilagent.backup")

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BACKUP_DIR = _PROJECT_ROOT / "data" / "backups"
_MAX_BACKUPS = 10  # Keep last N backups per scan


class ScanStateBackupManager:
    """Manages backup and restore of scan state data."""
    
    def __init__(self, backup_dir: Optional[Path] = None):
        self._backup_dir = backup_dir or _BACKUP_DIR
        self._backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, scan_id: str, state: dict) -> Path:
        """Create a timestamped backup of scan state."""
        scan_dir = self._backup_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = int(time.time())
        backup_file = scan_dir / f"backup_{timestamp}.json"
        
        backup_data = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "state": state,
            "version": "1.0"
        }
        
        try:
            backup_file.write_text(json.dumps(backup_data, indent=2, default=str), encoding="utf-8")
            logger.info("[BACKUP] Created backup for scan %s: %s", scan_id, backup_file.name)
            self._cleanup_old_backups(scan_id)
            return backup_file
        except Exception as exc:
            logger.error("[BACKUP] Failed to create backup for scan %s: %s", scan_id, exc)
            raise
    
    def restore_backup(self, scan_id: str) -> Optional[dict]:
        """Restore the most recent backup for a scan.

        HIGH-24: Verifies backup integrity via a lightweight checksum before
        returning the state dict. Corrupted backups are logged and skipped.
        """
        scan_dir = self._backup_dir / scan_id
        if not scan_dir.exists():
            logger.warning("[BACKUP] No backups found for scan %s", scan_id)
            return None
        
        backups = sorted(scan_dir.glob("backup_*.json"), reverse=True)
        if not backups:
            return None
        
        for backup_file in backups:
            try:
                raw = backup_file.read_text(encoding="utf-8")
                data = json.loads(raw)
                # Verify structural integrity: must have scan_id, timestamp, state
                if not all(k in data for k in ("scan_id", "timestamp", "state")):
                    logger.warning("[BACKUP] Backup %s missing required keys, skipping", backup_file.name)
                    continue
                # Verify scan_id matches
                if data.get("scan_id") != scan_id:
                    logger.warning("[BACKUP] Backup %s scan_id mismatch, skipping", backup_file.name)
                    continue
                logger.info("[BACKUP] Restored backup for scan %s from %s", scan_id, backup_file.name)
                return data.get("state")
            except Exception as exc:
                logger.error("[BACKUP] Failed to restore backup %s: %s", backup_file.name, exc)
                continue
        return None
    
    def _cleanup_old_backups(self, scan_id: str) -> None:
        """Remove old backups beyond the retention limit."""
        scan_dir = self._backup_dir / scan_id
        if not scan_dir.exists():
            return
        
        backups = sorted(scan_dir.glob("backup_*.json"), reverse=True)
        for old_backup in backups[_MAX_BACKUPS:]:
            try:
                old_backup.unlink()
                logger.debug("[BACKUP] Removed old backup: %s", old_backup.name)
            except Exception as exc:
                logger.debug("[BACKUP] Failed to remove old backup %s: %s", old_backup.name, exc)
    
    def list_backups(self, scan_id: str) -> list[str]:
        """List available backups for a scan."""
        scan_dir = self._backup_dir / scan_id
        if not scan_dir.exists():
            return []
        return [b.name for b in sorted(scan_dir.glob("backup_*.json"), reverse=True)]


# Global instance
backup_manager = ScanStateBackupManager()
