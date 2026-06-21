from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import uuid
import logging
from dataclasses import dataclass
from pathlib import Path
from tempfile import gettempdir

from backend.core.guard_layer import guard_layer
from backend.core.queue import command_lane
from backend.core.stdout_watchdog import watch_output

logger = logging.getLogger(__name__)

temp_workspace_root = Path(os.getenv("VIGILAGENT_WORKSPACE_ROOT", Path(gettempdir()) / "vigilagent-workspaces"))

class TempWorkspace:
    """
    RAII pattern for isolated temporary workspaces.
    Ensures safe file system I/O and clutter prevention by strictly enforcing
    cleanup of artifacts when the context manager exits, mirroring OpenClaw's
    private-temp-workspace.ts.
    """
    def __init__(self, prefix: str = "workspace"):
        self.workspace_id = f"{prefix}-{uuid.uuid4().hex[:12]}"
        self.path = temp_workspace_root / self.workspace_id

    async def __aenter__(self):
        # Create isolated directory with 0o700 permissions (only owner can read/write/execute)
        self.path.mkdir(parents=True, exist_ok=True)
        self.path.chmod(0o700)
        logger.debug(f"Created isolated TempWorkspace: {self.path}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.path.exists():
            try:
                shutil.rmtree(self.path)
                logger.debug(f"Cleaned up TempWorkspace: {self.path}")
            except Exception as e:
                logger.error(f"Failed to clean up TempWorkspace {self.path}: {e}")

    def write_file(self, name: str, content: str | bytes) -> Path:
        """Writes a file inside the isolated workspace."""
        file_path = self.path / name
        # Prevent path traversal outside workspace
        if not str(file_path.resolve()).startswith(str(self.path.resolve())):
            raise PermissionError(f"Path traversal attempt: {name}")
            
        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"
        with open(file_path, mode, encoding=encoding) as f:
            f.write(content)
        return file_path

    def read_file(self, name: str) -> str | bytes:
        """Reads a file from the isolated workspace."""
        file_path = self.path / name
        if not str(file_path.resolve()).startswith(str(self.path.resolve())):
            raise PermissionError(f"Path traversal attempt: {name}")
            
        if not file_path.exists():
            raise FileNotFoundError(f"File not found in workspace: {name}")
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            with open(file_path, "rb") as f:
                return f.read()


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    command: str
    container_id: str | None = None
    truncated: bool = False


class DockerSandbox:
    def __init__(
        self,
        image: str | None = None,
        workspace_root: str | os.PathLike[str] = "scan_states/sandboxes",
        memory: str = "512m",
        cpus: str = "1.0",
        network: str = "none",
    ):
        self.image = image or os.getenv("VIGILAGENT_SANDBOX_IMAGE", os.getenv("VULAGENT_SANDBOX_IMAGE", "python:3.12-slim"))
        self.workspace_root = Path(workspace_root)
        self.memory = memory
        self.cpus = cpus
        self.network = network

    def workspace_for(self, engagement_id: str) -> Path:
        root = (self.workspace_root / engagement_id).resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    async def run(self, command: str, *, engagement_id: str = "GLOBAL", timeout: int = 120) -> SandboxResult:
        # SANDBOX FIX: Sandbox runs legitimate pentest tool commands
        # (sqlmap, nmap, etc.) that naturally contain shell keywords like
        # 'execute', 'subprocess', 'shell'. The prompt-injection filter
        # should NOT block commands running inside the sandbox — the
        # sandbox itself IS the security boundary. Only check for control
        # tokens that could break out of the sandbox.
        from backend.core.content_boundary import content_boundary
        # FIX: Use the sanitized result instead of discarding it
        sanitized_command = content_boundary.sanitize_control_tokens(command)
        workspace = self.workspace_for(engagement_id)
        container_name = f"vulagent-{engagement_id.lower()}-{uuid.uuid4().hex[:8]}"
        docker_cmd = [
            "docker", "run", "--rm", "--name", container_name,
            "--network", self.network,
            "--memory", self.memory,
            "--cpus", self.cpus,
            "-v", f"{workspace}:/workspace",
            "-w", "/workspace",
            self.image,
            "sh", "-lc", sanitized_command,
        ]
        try:
            async with command_lane.slot():
                proc = await asyncio.create_subprocess_exec(
                    *docker_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")
            watched = await watch_output(stdout)
            return SandboxResult(proc.returncode or 0, watched.content, stderr, command, container_name, watched.truncated)
        except FileNotFoundError:
            return SandboxResult(127, "", "Docker executable not found; sandbox execution unavailable.", command)
        except asyncio.TimeoutError:
            return SandboxResult(124, "", f"Sandbox command timed out after {timeout}s.", command, container_name)


def quote_command(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)
