from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from backend.agents.alpha_recon.models import stable_id
from backend.core.config import settings
from backend.core.database import db_manager


class ArtifactStore:
    def __init__(self, scan_id: str):
        safe_scan = re.sub(r"[^A-Za-z0-9_.-]+", "_", scan_id or "GLOBAL")
        root = Path(getattr(settings, "ALPHA_ARTIFACT_ROOT", "data/scans")) / safe_scan
        self.root = root
        self.raw_dir = root / "raw"
        self.normalized_dir = root / "normalized"
        self.screenshots_dir = root / "screenshots"
        self.browser_dir = root / "browser"
        self.exports_dir = root / "exports"
        for path in [self.raw_dir, self.normalized_dir, self.screenshots_dir, self.browser_dir, self.exports_dir]:
            path.mkdir(parents=True, exist_ok=True)
        self.manifest_path = root / "artifact_manifest.json"
        self._manifest: list[dict[str, Any]] = []

    def _safe_resolve(self, relative: str) -> Path:
        """Resolve a relative path safely, preventing path traversal (C-10).

        Raises ValueError if the resolved path escapes self.root.
        """
        resolved = (self.root / relative).resolve()
        if not str(resolved).startswith(str(self.root.resolve())):
            raise ValueError(f"Path traversal blocked: '{relative}' resolves outside artifact root")
        return resolved

    async def write_json(self, relative: str, payload: Any, *, tool_name: str, artifact_type: str, scan_id: str) -> str:
        path = self._safe_resolve(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(payload, indent=2, default=str)
        path.write_text(data, encoding="utf-8")
        return await self.register(path, tool_name=tool_name, artifact_type=artifact_type, scan_id=scan_id)

    async def write_text(self, relative: str, text: str, *, tool_name: str, artifact_type: str, scan_id: str) -> str:
        path = self._safe_resolve(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="replace")
        return await self.register(path, tool_name=tool_name, artifact_type=artifact_type, scan_id=scan_id)

    async def register(
        self, path: Path, *, tool_name: str, artifact_type: str, scan_id: str, metadata: dict[str, Any] | None = None
    ) -> str:
        content = path.read_bytes() if path.exists() else b""
        sha256 = hashlib.sha256(content).hexdigest()
        artifact_id = stable_id(scan_id, tool_name, artifact_type, str(path))
        # FIX (tool-status honesty): an empty or near-empty artifact must be
        # flagged as such instead of silently reading as a successful run.
        # Observed: gobuster.txt/naabu.txt/tlsx.jsonl at 0 bytes and five inql
        # stubs at 27 bytes all listed beside real results with no signal that
        # they produced nothing.
        if len(content) == 0:
            _status = "empty"
        elif len(content) <= 64 and "inql" in tool_name.lower():
            _status = "stub"
        else:
            _status = "ok"
        row = {
            "id": artifact_id,
            "scan_id": scan_id,
            "tool_name": tool_name,
            "artifact_type": artifact_type,
            "path": str(path),
            "sha256": sha256,
            "bytes": len(content),
            "metadata": {"status": _status, **(metadata or {})},
        }
        self._manifest.append(row)
        await db_manager.create_recon_artifact(**row)
        self.manifest_path.write_text(json.dumps(self._manifest, indent=2, default=str), encoding="utf-8")
        return artifact_id
