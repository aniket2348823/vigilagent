"""
Forensic Evidence Collector for Browser-Based Testing
Captures screenshots, DOM snapshots, network logs, and console output.
Supports encryption for sensitive forensic data.
"""

import json
import gzip
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
import base64
import asyncio
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)


class ForensicCollector:
    """
    Collects and stores forensic evidence from browser-based security testing.
    Supports both OpenClaw and PinchTab engines.
    Includes encryption for sensitive forensic data.
    """
    
    def __init__(self, storage_dir: str = "scan_states/forensics", encryption_key: Optional[str] = None):
        """
        Initialize the forensic collector.
        
        Args:
            storage_dir: Directory to store forensic evidence
            encryption_key: Optional encryption key for sensitive data (uses env var if not provided)
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_cache: Dict[str, List[Dict[str, Any]]] = {}
        
        # Initialize encryption
        self._init_encryption(encryption_key)
    
    def _init_encryption(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption for forensic data.
        
        Args:
            encryption_key: Optional encryption key (uses env var FORENSIC_ENCRYPTION_KEY if not provided)
        """
        try:
            # Get encryption key from parameter or environment
            key_material = encryption_key or os.getenv("FORENSIC_ENCRYPTION_KEY")
            
            if not key_material:
                # Generate a new key if none provided (for development only)
                logger.warning("[ForensicCollector] No encryption key provided, generating temporary key")
                self.cipher = Fernet(Fernet.generate_key())
                self.encryption_enabled = True
                return
            
            # Derive encryption key from password using PBKDF2
            # HIGH-18: Use per-installation salt from env or persisted random,
            # not a static constant that's the same across all deployments.
            salt = os.getenv("FORENSIC_SALT")
            if not salt:
                salt_file = self.storage_dir / ".forensic_salt"
                try:
                    if salt_file.exists():
                        salt = salt_file.read_bytes().strip().decode()
                    else:
                        salt = os.urandom(16).hex()
                        salt_file.write_text(salt)
                except Exception:
                    salt = "forensic_salt_v1"  # last resort
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt.encode() if isinstance(salt, str) else salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
            self.cipher = Fernet(key)
            self.encryption_enabled = True
            logger.info("[ForensicCollector] Encryption initialized successfully")
            
        except Exception as e:
            logger.error(f"[ForensicCollector] Failed to initialize encryption: {e}")
            self.cipher = None
            self.encryption_enabled = False
    
    def _write_bytes(self, filepath: Path, data: bytes) -> None:
        """Synchronous file write helper — called via asyncio.to_thread (§29.13)."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(data)

    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data if encryption is enabled.
        
        Args:
            data: Raw data to encrypt
            
        Returns:
            Encrypted data or original data if encryption disabled
        """
        if self.encryption_enabled and self.cipher:
            try:
                return self.cipher.encrypt(data)
            except Exception as e:
                logger.error(f"[ForensicCollector] Encryption failed: {e}")
                return data
        return data
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """
        Decrypt data if encryption is enabled.
        
        Args:
            data: Encrypted data
            
        Returns:
            Decrypted data or original data if encryption disabled
        """
        if self.encryption_enabled and self.cipher:
            try:
                return self.cipher.decrypt(data)
            except Exception as e:
                logger.error(f"[ForensicCollector] Decryption failed: {e}")
                return data
        return data
        
    async def capture_screenshot(
        self,
        scan_id: str,
        context,
        engine: str,
        label: str = "screenshot",
        full_page: bool = True
    ) -> Optional[str]:
        """
        Capture a screenshot from the browser.
        
        Args:
            scan_id: Scan identifier
            context: Browser context (OpenClaw page or PinchTab client)
            engine: Engine type ("openclaw" or "pinchtab")
            label: Label for the screenshot
            full_page: Whether to capture full page or viewport only
            
        Returns:
            Path to saved screenshot, or None if failed
        """
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            ext = ".png.enc" if self.encryption_enabled else ".png"
            filename = f"{scan_id}_{label}_{timestamp}{ext}"
            filepath = self.storage_dir / scan_id / "screenshots" / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            if engine == "openclaw":
                # OpenClaw/Playwright screenshot
                screenshot_bytes = await context.screenshot(full_page=full_page)
                
                # Encrypt if enabled
                encrypted_data = self._encrypt_data(screenshot_bytes)        # Write in a thread to avoid blocking the event loop (§29.13)
        await asyncio.to_thread(self._write_bytes, filepath, encrypted_data)
                    
            elif engine == "pinchtab":
                # PinchTab screenshot (placeholder - depends on PinchTab API)
                # screenshot_data = await context.screenshot()
                # encrypted_data = self._encrypt_data(screenshot_data)
                # with open(filepath, 'wb') as f:
                #     f.write(encrypted_data)
                pass
            
            # Store metadata
            self._add_evidence(scan_id, {
                "type": "screenshot",
                "label": label,
                "filepath": str(filepath),
                "timestamp": timestamp,
                "engine": engine,
                "full_page": full_page,
                "encrypted": self.encryption_enabled
            })
            
            return str(filepath)
            
        except Exception as e:
            logger.error(f"[ForensicCollector] Screenshot capture failed: {e}")
            return None
    
    async def capture_dom_snapshot(
        self,
        scan_id: str,
        context,
        engine: str,
        label: str = "dom",
        compress: bool = True
    ) -> Optional[str]:
        """
        Capture a DOM snapshot (HTML source).
        
        Args:
            scan_id: Scan identifier
            context: Browser context
            engine: Engine type
            label: Label for the snapshot
            compress: Whether to gzip compress the snapshot
            
        Returns:
            Path to saved snapshot, or None if failed
        """
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            
            # Determine file extension based on compression and encryption
            if self.encryption_enabled:
                ext = ".html.gz.enc" if compress else ".html.enc"
            else:
                ext = ".html.gz" if compress else ".html"
                
            filename = f"{scan_id}_{label}_{timestamp}{ext}"
            filepath = self.storage_dir / scan_id / "dom" / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Get HTML content
            if engine == "openclaw":
                html_content = await context.content()
            elif engine == "pinchtab":
                # PinchTab DOM extraction (placeholder)
                html_content = ""  # await context.get_html()
            else:
                return None
            
            # Prepare data (compress if needed)
            if compress:
                data = gzip.compress(html_content.encode('utf-8'))
            else:
                data = html_content.encode('utf-8')
            
            # Encrypt if enabled
            encrypted_data = self._encrypt_data(data)
            
            # Save (async file write to avoid blocking event loop)
            await asyncio.to_thread(self._write_bytes, filepath, encrypted_data)
            
            # Store metadata
            self._add_evidence(scan_id, {
                "type": "dom_snapshot",
                "label": label,
                "filepath": str(filepath),
                "timestamp": timestamp,
                "engine": engine,
                "compressed": compress,
                "encrypted": self.encryption_enabled,
                "size_bytes": len(html_content)
            })
            
            return str(filepath)
            
        except Exception as e:
            logger.error(f"[ForensicCollector] DOM snapshot failed: {e}")
            return None
    
    async def capture_network_logs(
        self,
        scan_id: str,
        network_events: List[Dict[str, Any]],
        label: str = "network",
        compress: bool = True
    ) -> Optional[str]:
        """
        Save network traffic logs.
        
        Args:
            scan_id: Scan identifier
            network_events: List of network events (requests/responses)
            label: Label for the logs
            compress: Whether to gzip compress the logs
            
        Returns:
            Path to saved logs, or None if failed
        """
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            
            # Determine file extension
            if self.encryption_enabled:
                ext = ".json.gz.enc" if compress else ".json.enc"
            else:
                ext = ".json.gz" if compress else ".json"
                
            filename = f"{scan_id}_{label}_{timestamp}{ext}"
            filepath = self.storage_dir / scan_id / "network" / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Serialize network events
            json_data = json.dumps(network_events, indent=2)
            
            # Prepare data (compress if needed)
            if compress:
                data = gzip.compress(json_data.encode('utf-8'))
            else:
                data = json_data.encode('utf-8')
            
            # Encrypt if enabled
            encrypted_data = self._encrypt_data(data)
            
            # Save (async file write)
            await asyncio.to_thread(self._write_bytes, filepath, encrypted_data)
            
            # Store metadata
            self._add_evidence(scan_id, {
                "type": "network_logs",
                "label": label,
                "filepath": str(filepath),
                "timestamp": timestamp,
                "compressed": compress,
                "encrypted": self.encryption_enabled,
                "event_count": len(network_events)
            })
            
            return str(filepath)
            
        except Exception as e:
            logger.error(f"[ForensicCollector] Network log capture failed: {e}")
            return None
    
    async def capture_console_logs(
        self,
        scan_id: str,
        console_messages: List[Dict[str, Any]],
        label: str = "console",
        compress: bool = False
    ) -> Optional[str]:
        """
        Save console output logs.
        
        Args:
            scan_id: Scan identifier
            console_messages: List of console messages
            label: Label for the logs
            compress: Whether to gzip compress the logs
            
        Returns:
            Path to saved logs, or None if failed
        """
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            
            # Determine file extension
            if self.encryption_enabled:
                ext = ".json.gz.enc" if compress else ".json.enc"
            else:
                ext = ".json.gz" if compress else ".json"
                
            filename = f"{scan_id}_{label}_{timestamp}{ext}"
            filepath = self.storage_dir / scan_id / "console" / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Serialize console messages
            json_data = json.dumps(console_messages, indent=2)
            
            # Prepare data (compress if needed)
            if compress:
                data = gzip.compress(json_data.encode('utf-8'))
            else:
                data = json_data.encode('utf-8')
            
            # Encrypt if enabled
            encrypted_data = self._encrypt_data(data)
            
            # Save (async file write)
            await asyncio.to_thread(self._write_bytes, filepath, encrypted_data)
            
            # Store metadata
            self._add_evidence(scan_id, {
                "type": "console_logs",
                "label": label,
                "filepath": str(filepath),
                "timestamp": timestamp,
                "compressed": compress,
                "encrypted": self.encryption_enabled,
                "message_count": len(console_messages)
            })
            
            return str(filepath)
            
        except Exception as e:
            logger.error(f"[ForensicCollector] Console log capture failed: {e}")
            return None
    
    async def bundle_evidence(
        self,
        scan_id: str,
        vuln_id: Optional[str] = None,
        include_types: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Bundle all evidence for a scan into a single archive.
        
        Args:
            scan_id: Scan identifier
            vuln_id: Optional vulnerability identifier
            include_types: Optional list of evidence types to include
            
        Returns:
            Path to evidence bundle, or None if failed
        """
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            
            # Determine file extension
            ext = ".json.gz.enc" if self.encryption_enabled else ".json.gz"
            bundle_name = f"{scan_id}_evidence_{timestamp}{ext}"
            
            if vuln_id:
                bundle_name = f"{scan_id}_{vuln_id}_evidence_{timestamp}{ext}"
            
            bundle_path = self.storage_dir / scan_id / bundle_name
            bundle_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Collect evidence metadata
            evidence_list = self.evidence_cache.get(scan_id, [])
            
            if include_types:
                evidence_list = [e for e in evidence_list if e["type"] in include_types]
            
            bundle_data = {
                "scan_id": scan_id,
                "vuln_id": vuln_id,
                "timestamp": timestamp,
                "evidence_count": len(evidence_list),
                "encrypted": self.encryption_enabled,
                "evidence": evidence_list
            }
            
            # Serialize and compress
            json_data = json.dumps(bundle_data, indent=2)
            compressed_data = gzip.compress(json_data.encode('utf-8'))
            
            # Encrypt if enabled
            encrypted_data = self._encrypt_data(compressed_data)
            
            # Save bundle (async file write)
            await asyncio.to_thread(self._write_bytes, bundle_path, encrypted_data)
            
            return str(bundle_path)
            
        except Exception as e:
            logger.error(f"[ForensicCollector] Evidence bundling failed: {e}")
            return None    def _add_evidence(self, scan_id: str, evidence: Dict[str, Any]):
        """
        Add evidence metadata to cache.

        Args:
            scan_id: Scan identifier
            evidence: Evidence metadata
        """
        if scan_id not in self.evidence_cache:
            self.evidence_cache[scan_id] = []
        
        self.evidence_cache[scan_id].append(evidence)
        # HIGH-23: Bound evidence cache per scan to prevent unbounded growth
        if len(self.evidence_cache[scan_id]) > 1000:
            self.evidence_cache[scan_id] = self.evidence_cache[scan_id][-500:]
    
    def get_evidence_summary(self, scan_id: str) -> Dict[str, Any]:
        """
        Get summary of collected evidence for a scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Evidence summary
        """
        evidence_list = self.evidence_cache.get(scan_id, [])
        
        summary = {
            "scan_id": scan_id,
            "total_evidence": len(evidence_list),
            "by_type": {},
            "by_engine": {},
            "storage_path": str(self.storage_dir / scan_id)
        }
        
        for evidence in evidence_list:
            # Count by type
            ev_type = evidence["type"]
            summary["by_type"][ev_type] = summary["by_type"].get(ev_type, 0) + 1
            
            # Count by engine
            engine = evidence.get("engine", "unknown")
            summary["by_engine"][engine] = summary["by_engine"].get(engine, 0) + 1
        
        return summary
    
    async def cleanup_old_evidence(self, max_age_days: int = 7) -> int:
        """
        Remove old forensic evidence files.
        
        Args:
            max_age_days: Maximum age of evidence in days
            
        Returns:
            Number of files cleaned up
        """
        try:
            from datetime import timedelta
            
            cleaned = 0
            cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
            
            for scan_dir in self.storage_dir.iterdir():
                if not scan_dir.is_dir():
                    continue
                
                for evidence_file in scan_dir.rglob("*"):
                    if not evidence_file.is_file():
                        continue
                    
                    # Check file modification time
                    mtime = datetime.fromtimestamp(evidence_file.stat().st_mtime)
                    
                    if mtime < cutoff_time:
                        evidence_file.unlink()
                        cleaned += 1
            
            logger.info(f"[ForensicCollector] Cleaned up {cleaned} old evidence files")
            return cleaned
            
        except Exception as e:
            logger.error(f"[ForensicCollector] Cleanup failed: {e}")
            return 0
