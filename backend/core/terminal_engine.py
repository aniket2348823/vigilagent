"""
Vigilagent Terminal Engine (Architecture §8, §29.13)
================================================================================
The governed bridge between agents and real CLI tools. It is the single audited
path for recon/tool execution.

Responsibilities (Architecture §8):
  - Execute local commands where safe.
  - Execute Docker-isolated commands by default for Linux-native toolchains.
  - Support timeouts and no-output watchdogs.
  - Stream stdout in real time to a callback/WebSocket sink (§8).
  - Manage background/long-running processes with clean interrupt/cancellation.
  - Capture stdout, stderr, exit code, duration, hash, truncation status.
  - Enforce command allowlists (argv-only, no shell strings).
  - Enforce scope extraction from command arguments.
  - Require approval for risky or state-changing actions.
  - Store command artifacts under scan-specific directories.

Execution pipeline (Architecture §8):
  request -> tool registry -> budget consume -> command guard -> scope policy
          -> approval gate -> terminal engine -> docker/local backend
          -> output watchdog -> parser -> evidence store -> graph -> events

This engine is RECON/TOOL execution only. It is NOT a generic exploitation
shell: only registered, allowlisted binaries run, and every argv passes the
guardrail validator that rejects shell metacharacters.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import logging
import os
import re
import shutil
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from backend.core.queue import LanePriority, ProcessRunner, command_lane
from backend.core.sandbox import DockerSandbox
from backend.core.scope import ScopePolicy, ScopeViolation, scope_guard
from backend.core.stdout_watchdog import watch_output
from backend.tools.recon.guardrails import validate_command

if TYPE_CHECKING:
    from backend.core.iteration_budget import IterationBudget

logger = logging.getLogger("vigilagent.terminal")

_DEFAULT_OUTPUT_CAP = 10 * 1024 * 1024  # 10 MB (config/tools.yaml output_cap_bytes)
_STDERR_TAIL = 16 * 1024

# Serialize concurrent ``docker cp`` of the SAME input file into the shared
# recon container. Parallel recon tools (feroxbuster/ffuf/gobuster) all
# reference the same host wordlist; without this, concurrent `docker cp` to
# one destination can race/corrupt the copy and make tools fail.
_CP_IN_LOCKS: dict[str, "asyncio.Lock"] = {}


def _cp_in_lock(key: str) -> "asyncio.Lock":
    # Bound the cache: per-scan container paths accumulate over a long-running
    # backend. Resetting at a generous cap keeps memory flat with no perf cost.
    if len(_CP_IN_LOCKS) > 512:
        _CP_IN_LOCKS.clear()
    lock = _CP_IN_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _CP_IN_LOCKS[key] = lock
    return lock

# Real-time output sink: invoked with each stdout chunk as it arrives so an
# orchestrator can relay it to the WebSocket event stream (Architecture §8
# "Stream output to WebSocket"). May be a plain or async callable.
StreamCallback = Callable[[str], Any]


class TerminalBackend(StrEnum):
    LOCAL = "local"
    DOCKER = "docker"


class CancellationToken:
    """Cooperative cancel handle for a governed execution.

    Mirrors the intent of Hermes ``tools/interrupt.py`` (per-session interrupt
    signalling) but scoped to a single Terminal Engine run instead of a thread.
    Setting the token causes the streaming executor's watchdog to terminate the
    process tree at the next tick.
    """

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()


@dataclass
class _ExecOutcome:
    """Internal result of a streaming subprocess run."""

    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    cancelled: bool = False


@dataclass
class BackgroundProcess:
    """A tracked long-running governed process (Hermes process_registry pattern).

    Background runs return a handle immediately; their output streams into
    ``output`` and the final :class:`TerminalResult` lands in ``result`` when
    the process exits, is cancelled, or trips the no-output watchdog.
    """

    process_id: str
    tool: str
    argv: list[str]
    scan_id: str
    agent: str
    token: CancellationToken
    backend: str = ""
    started_at: float = field(default_factory=time.time)
    output: list[str] = field(default_factory=list)
    status: str = "running"  # running -> finished|failed|timeout|cancelled
    result: TerminalResult | None = None
    task: asyncio.Task | None = field(default=None, repr=False)

    def snapshot(self) -> dict[str, Any]:
        return {
            "process_id": self.process_id,
            "tool": self.tool,
            "argv": self.argv,
            "backend": self.backend,
            "scan_id": self.scan_id,
            "agent": self.agent,
            "status": self.status,
            "uptime_seconds": int(time.time() - self.started_at),
            "output_preview": "".join(self.output)[-2000:],
            "exit_code": self.result.exit_code if self.result else None,
        }


@dataclass
class TerminalResult:
    """Structured result of a single governed command execution (§8)."""

    tool: str
    argv: list[str]
    backend: str
    exit_code: int | None
    output_path: str
    stdout: str = ""
    stderr_tail: str = ""
    timed_out: bool = False
    blocked: bool = False
    block_reason: str = ""
    duration_ms: int = 0
    sha256: str = ""
    output_bytes: int = 0
    scan_id: str = ""
    agent: str = ""
    parser_hint: str = "lines"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.blocked:
            return "blocked"
        if self.metadata.get("cancelled"):
            return "cancelled"
        if self.timed_out:
            return "timeout"
        if self.exit_code == 0:
            return "finished"
        return "failed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "argv": self.argv,
            "backend": self.backend,
            "exit_code": self.exit_code,
            "status": self.status,
            "output_path": self.output_path,
            "stderr_tail": self.stderr_tail,
            "timed_out": self.timed_out,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "duration_ms": self.duration_ms,
            "sha256": self.sha256,
            "output_bytes": self.output_bytes,
            "scan_id": self.scan_id,
            "agent": self.agent,
            "parser_hint": self.parser_hint,
            "metadata": self.metadata,
        }


def _docker_available() -> bool:
    return shutil.which("docker") is not None


class TerminalEngine:
    """Single governed execution path for recon/tool CLI commands."""

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        *,
        prefer_docker: bool = True,
        docker_image: str | None = None,
        output_cap_bytes: int = _DEFAULT_OUTPUT_CAP,
    ) -> None:
        self.scope = scope or scope_guard
        self.prefer_docker = prefer_docker
        self.output_cap_bytes = output_cap_bytes
        self._sandbox = DockerSandbox(image=docker_image) if docker_image else DockerSandbox()
        self._docker_ok = _docker_available()
        self.telemetry = {
            "runs": 0,
            "blocked": 0,
            "timeouts": 0,
            "failures": 0,
            "cancelled": 0,
            "docker_runs": 0,
            "local_runs": 0,
            "background_runs": 0,
        }
        # Registry of live long-running/background processes (Hermes pattern).
        self._processes: dict[str, BackgroundProcess] = {}

    # ── Backend selection (Architecture §7 rule 3) ───────────────────────────

    def choose_backend(self, prefer_docker: bool | None = None) -> TerminalBackend:
        want_docker = self.prefer_docker if prefer_docker is None else prefer_docker
        if want_docker and self._docker_ok:
            return TerminalBackend.DOCKER
        return TerminalBackend.LOCAL

    @staticmethod
    def _extract_target(argv: Sequence[str]) -> str | None:
        """Find a host/URL inside an argv array for scope validation."""
        for idx, arg in enumerate(argv):
            a = str(arg)
            if a.startswith(("http://", "https://")):
                return a
            # bare domain heuristic: contains a dot, no slash, no leading dash
            # Skip argv[0] (the binary name) — e.g. `testssl.sh` or `massdns`
            # look like bare domains but are tool names, not targets.
            if idx == 0:
                continue
            if "." in a and "/" not in a and not a.startswith("-") and " " not in a:
                # Skip obvious file paths / flags-with-values
                if a.lower().endswith((".txt", ".json", ".jsonl", ".xml", ".kite", ".py", ".csv")):
                    continue
                # Skip glob/regex/extension-filter values (e.g. feroxbuster
                # `--dont-scan *.css` or `\.css$`) — these are NOT targets and
                # must not trip the scope gate.
                if any(ch in a for ch in ("*", ",", "?", "[", "]", "\\", "$", "^", "|", "(", ")")):
                    continue
                parsed = urlparse(f"//{a}", scheme="")
                if parsed.hostname:
                    return a
        return None

    # ── Execution ─────────────────────────────────────────────────────────────

    async def run(
        self,
        argv: Sequence[str],
        *,
        scan_id: str = "GLOBAL",
        agent: str = "terminal",
        output_path: str | Path | None = None,
        timeout_seconds: int = 3600,
        budget: IterationBudget | None = None,
        parser_hint: str = "lines",
        priority: LanePriority = LanePriority.NORMAL,
        stdin: str | None = None,
        cwd: str | Path | None = None,
        prefer_docker: bool | None = None,
        metadata: dict[str, Any] | None = None,
        on_output: StreamCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> TerminalResult:
        argv = [str(part) for part in argv]
        tool = os.path.basename(argv[0]) if argv else "unknown"
        out_path = str(output_path) if output_path else ""
        meta = metadata or {}

        def _blocked(reason: str) -> TerminalResult:
            self.telemetry["blocked"] += 1
            logger.warning("[TERMINAL] BLOCKED %s: %s", tool, reason)
            return TerminalResult(
                tool=tool,
                argv=argv,
                backend="none",
                exit_code=-1,
                output_path=out_path,
                blocked=True,
                block_reason=reason,
                scan_id=scan_id,
                agent=agent,
                parser_hint=parser_hint,
                metadata=meta,
            )

        # 1. Budget (Architecture §8 pipeline step 1)
        if budget is not None and not budget.consume(1):
            return _blocked("budget_exhausted")

        # 2. Command guardrail — argv-only, no shell strings (Property §29.14.6)
        guard = validate_command(argv)
        if not guard.allowed:
            if budget is not None:
                budget.refund(1)
            return _blocked(f"guardrail:{guard.reason}")

        # 3. Scope extraction from arguments (Architecture §8)
        target = self._extract_target(argv)
        if target:
            try:
                self.scope.assert_allowed(target, action="recon")
            except ScopeViolation as exc:
                if budget is not None:
                    budget.refund(1)
                return _blocked(f"scope:{exc}")

        # 4. Backend selection
        backend = self.choose_backend(prefer_docker)

        # 5. Prepare artifact directory
        if out_path:
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)

        self.telemetry["runs"] += 1
        started = time.time()

        try:
            if backend is TerminalBackend.DOCKER:
                result = await self._run_docker(
                    argv,
                    scan_id,
                    timeout_seconds,
                    output_path=out_path or None,
                    stdin=stdin,
                    on_output=on_output,
                    cancel_token=cancel_token,
                )
            else:
                result = await self._run_local(
                    argv,
                    stdin=stdin,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                    priority=priority,
                    on_output=on_output,
                    cancel_token=cancel_token,
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.telemetry["failures"] += 1
            logger.error("[TERMINAL] %s execution error: %s", tool, exc)
            return TerminalResult(
                tool=tool,
                argv=argv,
                backend=backend.value,
                exit_code=1,
                output_path=out_path,
                stderr_tail=str(exc)[-_STDERR_TAIL:],
                duration_ms=int((time.time() - started) * 1000),
                scan_id=scan_id,
                agent=agent,
                parser_hint=parser_hint,
                metadata=meta,
            )

        stdout, stderr, exit_code, timed_out, cancelled = result
        duration_ms = int((time.time() - started) * 1000)

        # 6. Output watchdog / cap + persist artifact
        watched = await watch_output(stdout, max_bytes=self.output_cap_bytes)
        sha256 = hashlib.sha256(watched.content.encode("utf-8", errors="replace")).hexdigest()
        out_bytes = len(watched.content.encode("utf-8", errors="replace"))
        if out_path:
            # In the Docker backend a tool may write its artifact DIRECTLY to the
            # mounted /scan path (e.g. `-o file.json`) and emit nothing to
            # stdout. Don't clobber a real on-disk artifact with empty stdout.
            artifact_written = (
                backend is TerminalBackend.DOCKER
                and not watched.content.strip()
                and Path(out_path).exists()
                and Path(out_path).stat().st_size > 0
            )
            if not artifact_written:
                try:
                    Path(out_path).write_text(watched.content, encoding="utf-8", errors="replace")
                except Exception as exc:
                    logger.warning("[TERMINAL] could not write artifact %s: %s", out_path, exc)

        if timed_out:
            self.telemetry["timeouts"] += 1
        elif cancelled:
            self.telemetry["cancelled"] += 1
        elif exit_code not in (0, None):
            self.telemetry["failures"] += 1

        if backend is TerminalBackend.DOCKER:
            self.telemetry["docker_runs"] += 1
        else:
            self.telemetry["local_runs"] += 1

        return TerminalResult(
            tool=tool,
            argv=argv,
            backend=backend.value,
            exit_code=exit_code,
            output_path=out_path,
            stdout=watched.content,
            stderr_tail=stderr[-_STDERR_TAIL:],
            timed_out=timed_out,
            duration_ms=duration_ms,
            sha256=sha256,
            output_bytes=out_bytes,
            scan_id=scan_id,
            agent=agent,
            parser_hint=parser_hint,
            metadata={**meta, "truncated": watched.truncated, "cancelled": cancelled},
        )

    async def _run_local(
        self,
        argv: list[str],
        *,
        stdin: str | None,
        cwd: str | Path | None,
        timeout_seconds: int,
        priority: LanePriority,
        on_output: StreamCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> tuple[str, str, int | None, bool, bool]:
        # Resolve binary from PATH first, then tool root (Architecture §7 rule 2).
        no_output_ms = min(timeout_seconds * 1000, 30_000)
        max_ms = timeout_seconds * 1000
        async with command_lane.slot(priority):
            # When real-time streaming or cancellation is requested, use the
            # streaming executor (Architecture §8 "Stream output to WebSocket").
            # Otherwise preserve the exact ProcessRunner path used by existing
            # recon callers.
            if on_output is not None or cancel_token is not None:
                outcome = await self._run_streamed_exec(
                    argv,
                    stdin=stdin,
                    cwd=cwd,
                    no_output_timeout_ms=no_output_ms,
                    max_runtime_ms=max_ms,
                    on_output=on_output,
                    cancel_token=cancel_token,
                )
                return (outcome.stdout, outcome.stderr, outcome.exit_code, outcome.timed_out, outcome.cancelled)
            proc = await ProcessRunner.run_exec(
                argv,
                stdin=stdin,
                cwd=cwd,
                no_output_timeout_ms=no_output_ms,
                max_runtime_ms=max_ms,
            )
        return proc.stdout, proc.stderr, proc.exit_code, proc.timed_out, False

    async def _run_docker(
        self,
        argv: list[str],
        scan_id: str,
        timeout_seconds: int,
        *,
        output_path: str | Path | None = None,
        stdin: str | None = None,
        on_output: StreamCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> tuple[str, str, int | None, bool, bool]:
        """Run a recon tool inside the bundled recon image (Architecture §7 r3).

        When the tool is part of the recon arsenal and the recon image is ready,
        we run it in that image with the scan dir mounted read-write and the
        tool root mounted read-only, with host paths rewritten to container
        paths. Otherwise we fall back to the generic isolated DockerSandbox
        (network=none) used for non-recon commands.
        """
        from backend.tools.recon.docker_runtime import (
            DOCKER_ALL_TOOLS,
            build_docker_argv,
            docker_recon_ready,
            running_recon_container,
        )

        tool = os.path.basename(argv[0]) if argv else ""
        tool_key = self._recon_tool_key(tool)
        # Python-launched vendored scripts (spiderfoot, linkfinder, dirsearch,
        # inql, paramspider, secretfinder) dispatch as `python <script>.py ...`.
        # Resolve the script back to its registry key so it runs in the recon
        # image (which bundles the scripts + their Python deps) instead of the
        # bare generic sandbox where the interpreter (and deps) don't exist.
        if tool_key == "python":
            for arg in argv[1:]:
                base = os.path.basename(str(arg)).lower()
                mapped = {
                    "sf.py": "spiderfoot",
                    "linkfinder.py": "linkfinder",
                    "secretfinder.py": "secretfinder",
                    "dirsearch.py": "dirsearch",
                    "inql.py": "inql",
                    "paramspider.py": "paramspider",
                }.get(base)
                if mapped:
                    tool_key = mapped
                    break

        # Run ANY registry tool (all 39 live in the recon image) through the
        # recon image. The Alpha/Sigma ownership split is about which AGENT
        # dispatches a tool — not which image can execute it. Restricting to
        # DOCKER_RECON_TOOLS silently broke httpx + nuclei (Sigma-owned), which
        # Alpha's planner legitimately dispatches: they fell back to the generic
        # sandbox (no recon tools) and died with "sh: 1: <tool>: not found".
        if tool_key in DOCKER_ALL_TOOLS and docker_recon_ready() and output_path:
            raw_dir = Path(output_path).resolve().parent
            tool_root = Path(
                getattr(
                    __import__("backend.core.config", fromlist=["settings"]).settings, "ALPHA_TOOL_ROOT", r"D:\projects"
                )
            )

            # Prefer exec-into-a-running-container when one exists. Works around
            # the Docker Desktop overlay bug where fresh `docker run` of the image
            # fails with "cannot execute binary file" while a long-lived container
            # from the same image runs fine (also faster: no per-tool spin-up).
            container = running_recon_container()
            if container:
                proc = await self._run_docker_in_container(
                    argv,
                    container=container,
                    raw_dir=raw_dir,
                    tool_root=tool_root,
                    output_path=Path(output_path),
                    stdin=stdin,
                    timeout_seconds=timeout_seconds,
                    on_output=on_output,
                    cancel_token=cancel_token,
                )
                return proc

            docker_argv = build_docker_argv(
                argv,
                raw_dir=raw_dir,
                tool_root=tool_root,
                scan_id=scan_id,
            )
            proc = await self._run_docker_exec(
                docker_argv,
                stdin=stdin,
                timeout_seconds=timeout_seconds,
                on_output=on_output,
                cancel_token=cancel_token,
            )
            return proc

        # Fallback: generic isolated sandbox for non-recon commands.
        # The DockerSandbox path has no live-stream hook; surface any buffered
        # output through the callback once after completion so the WebSocket
        # relay still observes it.
        from backend.core.sandbox import quote_command

        command = quote_command(argv)
        sandbox_res = await self._sandbox.run(command, engagement_id=scan_id, timeout=timeout_seconds)
        timed_out = sandbox_res.exit_code == 124
        if on_output and sandbox_res.stdout:
            await self._emit(on_output, sandbox_res.stdout)
        return sandbox_res.stdout, sandbox_res.stderr, sandbox_res.exit_code, timed_out, False

    @staticmethod
    def _recon_tool_key(binary: str) -> str:
        """Map a binary basename back to its recon registry key for image lookup."""
        b = binary.lower()
        if b.endswith(".exe"):
            b = b[:-4]
        alias = {
            "kr": "kiterunner",
            "testssl.sh": "testssl",
            "interactsh-client": "interactsh",
        }
        return alias.get(b, b)

    async def _run_docker_exec(
        self,
        docker_argv: list[str],
        *,
        stdin: str | None,
        timeout_seconds: int,
        on_output: StreamCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> tuple[str, str, int | None, bool, bool]:
        """Execute a prepared `docker run ...` argv with watchdog + timeout."""
        no_output_ms = min(timeout_seconds * 1000, 60_000)
        max_ms = timeout_seconds * 1000
        async with command_lane.slot():
            if on_output is not None or cancel_token is not None:
                outcome = await self._run_streamed_exec(
                    docker_argv,
                    stdin=stdin,
                    cwd=None,
                    no_output_timeout_ms=no_output_ms,
                    max_runtime_ms=max_ms,
                    on_output=on_output,
                    cancel_token=cancel_token,
                )
                return (outcome.stdout, outcome.stderr, outcome.exit_code, outcome.timed_out, outcome.cancelled)
            proc = await ProcessRunner.run_exec(
                docker_argv,
                stdin=stdin,
                no_output_timeout_ms=no_output_ms,
                max_runtime_ms=max_ms,
            )
        return proc.stdout, proc.stderr, proc.exit_code, proc.timed_out, False

    async def _run_docker_in_container(
        self,
        argv: list[str],
        *,
        container: str,
        raw_dir: Path,
        tool_root: Path,
        output_path: Path,
        stdin: str | None,
        timeout_seconds: int,
        on_output: StreamCallback | None = None,
        cancel_token: CancellationToken | None = None,
    ) -> tuple[str, str, int | None, bool, bool]:
        """Run a recon tool by ``docker exec`` into a RUNNING recon container.

        Output files the tool writes under the container scan dir are copied back
        to the host artifact path via ``docker cp`` so the parser registry sees
        them exactly as with the bind-mounted run path.
        """
        import asyncio as _asyncio

        from backend.tools.recon.docker_runtime import EXEC_WORKDIR, TOOLS_MNT, build_exec_argv

        # Rewrite loopback references in the stdin payload for in-container
        # execution. Tools that read targets from stdin (httprobe, hakrawler,
        # gospider's `-S -`, feroxbuster `--stdin`) would otherwise probe the
        # container itself when the payload says ``localhost``. Files copied in
        # via ``_cp_in`` already get the same rewrite; this closes the loop for
        # piped-stdin payloads.
        if stdin:
            low_s = stdin.lower()
            if any(h in low_s for h in ("localhost", "127.0.0.1", "[::1]")):
                stdin = re.sub(
                    r"(?<![\w.-])(?:127\.0\.0\.1|localhost|\[::1\])(?![\w.-])",
                    "host.docker.internal",
                    stdin,
                    flags=re.IGNORECASE,
                )

        out_name = output_path.name
        container_out = f"{EXEC_WORKDIR}/{out_name}"
        # Include the original (potentially relative) parent of output_path so
        # both absolute and relative argv path forms get rewritten to /scan.
        try:
            op_parent_str = str(Path(output_path).parent)
            extra_prefixes = [op_parent_str] if op_parent_str else []
        except Exception as exc:
            logger.debug("[TERMINAL] op_parent_str extraction failed: %s", exc)
            extra_prefixes = []
        exec_argv = build_exec_argv(
            argv,
            container=container,
            raw_dir=raw_dir,
            tool_root=tool_root,
            container_out=container_out,
            has_stdin=stdin is not None,
            extra_raw_prefixes=extra_prefixes,
        )

        # Copy INPUT files into the container before exec. The running recon
        # container does not bind-mount the host, so any host file referenced in
        # argv (wordlists under tool_root -> /tools, hosts/target files under
        # raw_dir -> /scan) must be pushed in or the tool fails (ffuf/gobuster
        # "-w wordlist" => no such file). The OUTPUT file is excluded; it is
        # produced in-container and copied back afterwards.
        #
        # The planner emits raw_dir paths in either ABSOLUTE or RELATIVE form
        # (ArtifactStore root defaults to a relative ``data/scans``). We match
        # argv tokens against both forms so the cp + path rewrite stay
        # consistent. Without this, secondary outputs are created with the
        # literal Windows path embedded as the filename and never round-trip
        # back to disk for the parser.
        abs_raw = raw_dir.resolve()
        raw_prefixes = {str(abs_raw)}
        try:
            if not raw_dir.is_absolute():
                raw_prefixes.add(str(raw_dir))
        except Exception as exc:
            logger.debug("[TERMINAL] raw_prefixes relative form failed: %s", exc)
        # output_path may itself carry the relative form the planner used. Its
        # parent is the canonical relative raw_dir for any sibling tokens (e.g.
        # ffuf's `-o <raw_dir>/ffuf_results.json`). Including it here is what
        # makes the secondary-file cp-back work for relative-style argv.
        try:
            op_parent = Path(output_path).parent
            if not op_parent.is_absolute():
                raw_prefixes.add(str(op_parent))
        except Exception as exc:
            logger.debug("[TERMINAL] op_parent raw_prefixes failed: %s", exc)
        tool_s = str(tool_root)
        out_host = str(output_path)
        out_host_abs = str(Path(output_path).resolve())

        async def _cp_in(host_path: str, container_path: str) -> None:
            try:
                # Ensure parent dir exists in the container, then copy the file.
                parent = container_path.rsplit("/", 1)[0] or "/"
                mk = await _asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    container,
                    "mkdir",
                    "-p",
                    parent,
                    stdout=_asyncio.subprocess.PIPE,
                    stderr=_asyncio.subprocess.PIPE,
                )
                await _asyncio.wait_for(mk.communicate(), timeout=15)
                # If the input is a small text file that references loopback
                # hosts (e.g. a `-iL hosts.txt` target list with localhost:8080),
                # rewrite those to host.docker.internal in a temp copy so the
                # tool — running INSIDE the container — reaches the host service
                # instead of the container itself. Wordlists and binaries are
                # left untouched (no loopback tokens, or too large).
                src = host_path
                tmp = None
                try:
                    if os.path.getsize(host_path) <= 1_000_000:
                        with open(host_path, encoding="utf-8", errors="strict") as fh:
                            content = fh.read()
                        low_c = content.lower()
                        if any(h in low_c for h in ("localhost", "127.0.0.1", "[::1]")):
                            rewritten = re.sub(
                                r"(?<![\w.-])(?:127\.0\.0\.1|localhost|\[::1\])(?![\w.-])",
                                "host.docker.internal",
                                content,
                                flags=re.IGNORECASE,
                            )
                            import tempfile as _tf

                            fd, tmp = _tf.mkstemp(suffix=".loopfix")
                            with os.fdopen(fd, "w", encoding="utf-8") as wf:
                                wf.write(rewritten)
                            src = tmp
                except (UnicodeDecodeError, OSError):
                    src = host_path  # binary or unreadable — copy as-is
                async with _cp_in_lock(container_path):
                    cp = await _asyncio.create_subprocess_exec(
                        "docker",
                        "cp",
                        src,
                        f"{container}:{container_path}",
                        stdout=_asyncio.subprocess.PIPE,
                        stderr=_asyncio.subprocess.PIPE,
                    )
                    await _asyncio.wait_for(cp.communicate(), timeout=60)
                if tmp:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp)
            except Exception as exc:
                logger.debug("[TERMINAL] docker cp in failed for %s: %s", host_path, exc)

        for tok in argv:
            s = str(tok)
            norm = s.replace("\\", "/")
            low = norm.lower()
            try:
                is_file = os.path.isfile(s)
            except Exception as exc:
                logger.debug("[TERMINAL] isfile check failed for %s: %s", s, exc)
                is_file = False
            if s in (out_host, out_host_abs) or not is_file:
                continue
            # Match against ALL candidate raw_dir prefixes (absolute + relative
            # forms) so files referenced via either path style are pushed in.
            best: tuple[int, str] | None = None
            for pref in raw_prefixes:
                pref_norm = pref.replace("\\", "/")
                if low.startswith(pref_norm.lower()) and (best is None or len(pref_norm) > best[0]):
                    best = (len(pref_norm), pref_norm)
            if best is not None:
                rel = norm[best[0] :].lstrip("/")
                await _cp_in(s, f"{EXEC_WORKDIR}/{rel}")
            elif low.startswith(tool_s.replace("\\", "/").lower()):
                rel = norm[len(tool_s) :].lstrip("\\/").replace("\\", "/")
                await _cp_in(s, f"{TOOLS_MNT}/{rel}")

        result = await self._run_docker_exec(
            exec_argv,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            on_output=on_output,
            cancel_token=cancel_token,
        )
        # Copy OUTPUT files back to the host. Many recon tools write their real
        # results to a SECONDARY file (ffuf `-o results.json`, nmap `-oX a.xml`,
        # whatweb `--log-json`) rather than stdout. Those files are created under
        # the container scan dir (/scan) and must be copied back or the parser
        # registry (which reads metadata.json_file/xml_file from the host
        # raw_dir) sees nothing. We copy back every argv token that maps to a
        # host raw_dir path, plus the conventional container_out, best effort.
        copied_back: set[str] = set()

        async def _cp_out(container_path: str, host_path: str) -> None:
            if host_path in copied_back:
                return
            copied_back.add(host_path)
            try:
                Path(host_path).parent.mkdir(parents=True, exist_ok=True)
                cp = await _asyncio.create_subprocess_exec(
                    "docker",
                    "cp",
                    f"{container}:{container_path}",
                    host_path,
                    stdout=_asyncio.subprocess.PIPE,
                    stderr=_asyncio.subprocess.PIPE,
                )
                await _asyncio.wait_for(cp.communicate(), timeout=60)
            except Exception as exc:
                logger.debug("[TERMINAL] docker cp back failed for %s: %s", container_path, exc)

        # Secondary output files referenced in argv (under raw_dir -> /scan).
        for tok in argv:
            s = str(tok)
            if s in (out_host, out_host_abs):
                continue
            norm = s.replace("\\", "/")
            low = norm.lower()
            best: tuple[int, str] | None = None
            for pref in raw_prefixes:
                pref_norm = pref.replace("\\", "/")
                if low.startswith(pref_norm.lower()) and (best is None or len(pref_norm) > best[0]):
                    best = (len(pref_norm), pref_norm)
            if best is not None:
                rel = norm[best[0] :].lstrip("/")
                await _cp_out(f"{EXEC_WORKDIR}/{rel}", s)
        # Conventional stdout artifact path.
        await _cp_out(container_out, out_host)
        return result

    # ── Streaming executor + cancellation (Hermes lifecycle) ────────────────

    @staticmethod
    async def _emit(on_output: StreamCallback | None, chunk: str) -> None:
        """Deliver an output chunk to the stream sink (sync or async)."""
        if not on_output or not chunk:
            return
        try:
            res = on_output(chunk)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:  # never let a sink error kill the run
            logger.debug("[TERMINAL] stream callback error: %s", exc)

    async def _run_streamed_exec(
        self,
        argv: Sequence[str],
        *,
        stdin: str | None,
        cwd: str | Path | None,
        no_output_timeout_ms: int,
        max_runtime_ms: int,
        on_output: StreamCallback | None,
        cancel_token: CancellationToken | None,
    ) -> _ExecOutcome:
        """Run a subprocess, streaming stdout chunks live to ``on_output``.

        Adopts the Hermes execution lifecycle: a no-output watchdog kills stalled
        processes, a max-runtime ceiling bounds total duration, and a cooperative
        cancellation token allows clean interrupt. The process tree is always
        reaped so no zombies leak (cf. Hermes reader-loop ``finally``).
        """
        argv = [str(part) for part in argv]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(cwd) if cwd else None,
                stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:
            logger.error("[TERMINAL] failed to spawn %s: %s", argv[:1], exc)
            return _ExecOutcome("", str(exc), -1, False, False)

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        timed_out = False
        cancelled = False
        killed = False
        last_output_at = time.monotonic()

        async def _read_stdout() -> None:
            nonlocal last_output_at
            if proc.stdout is None:
                return
            # Chunked read (not readline) so very long single-line tool output
            # (ffuf -json, httpx) doesn't trip asyncio's 64KB line limit.
            while True:
                try:
                    chunk = await proc.stdout.read(65536)
                except (asyncio.LimitOverrunError, ValueError):
                    try:
                        chunk = await proc.stdout.read(65536)
                    except Exception as read_exc:
                        logger.debug("[TERMINAL] stdout read error: %s", read_exc)
                        break
                except Exception as read_exc:
                    logger.debug("[TERMINAL] stdout read error: %s", read_exc)
                    break
                if not chunk:
                    break
                last_output_at = time.monotonic()
                text = chunk.decode("utf-8", errors="replace")
                stdout_chunks.append(text)
                await self._emit(on_output, text)

        async def _read_stderr() -> None:
            nonlocal last_output_at
            if proc.stderr is None:
                return
            while True:
                try:
                    chunk = await proc.stderr.read(65536)
                except (asyncio.LimitOverrunError, ValueError):
                    try:
                        chunk = await proc.stderr.read(65536)
                    except Exception as read_exc:
                        logger.debug("[TERMINAL] stderr read error: %s", read_exc)
                        break
                except Exception as read_exc:
                    logger.debug("[TERMINAL] stderr read error: %s", read_exc)
                    break
                if not chunk:
                    break
                last_output_at = time.monotonic()
                stderr_chunks.append(chunk.decode("utf-8", errors="replace"))

        async def _write_stdin() -> None:
            if stdin is None or proc.stdin is None:
                return
            try:
                proc.stdin.write(stdin.encode("utf-8") if isinstance(stdin, str) else stdin)
                await proc.stdin.drain()
                proc.stdin.close()
            except Exception as stdin_exc:
                logger.debug("[TERMINAL] stdin write error: %s", stdin_exc)

        def _terminate() -> None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()

        async def _supervisor() -> None:
            """No-output watchdog + max-runtime ceiling + cancellation."""
            nonlocal timed_out, cancelled, killed
            deadline = time.monotonic() + max_runtime_ms / 1000.0
            while proc.returncode is None:
                await asyncio.sleep(0.25)
                now = time.monotonic()
                if cancel_token is not None and cancel_token.cancelled:
                    cancelled = True
                    killed = True
                    logger.info("[TERMINAL] cancellation requested; killing process.")
                    _terminate()
                    return
                if (now - last_output_at) * 1000 > no_output_timeout_ms:
                    timed_out = True
                    killed = True
                    logger.warning("[TERMINAL] no-output watchdog tripped (%sms).", no_output_timeout_ms)
                    _terminate()
                    return
                if now >= deadline:
                    timed_out = True
                    killed = True
                    logger.warning("[TERMINAL] max runtime exceeded (%sms).", max_runtime_ms)
                    _terminate()
                    return

        readers = asyncio.gather(_read_stdout(), _read_stderr(), _write_stdin())
        supervisor = asyncio.ensure_future(_supervisor())
        try:
            await proc.wait()
        finally:
            supervisor.cancel()
            try:
                await readers
            except Exception as reader_exc:
                logger.debug("[TERMINAL] reader cleanup error: %s", reader_exc)
            # Always reap to avoid zombies (Hermes reader-loop finally).
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception as reap_exc:
                logger.debug("[TERMINAL] process reap error: %s", reap_exc)

        return _ExecOutcome(
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
            exit_code=proc.returncode if not killed else None,
            timed_out=timed_out,
            cancelled=cancelled,
        )

    # ── Background / long-running process control (Hermes registry) ─────────

    def run_background(
        self,
        argv: Sequence[str],
        *,
        scan_id: str = "GLOBAL",
        agent: str = "terminal",
        output_path: str | Path | None = None,
        timeout_seconds: int = 3600,
        budget: IterationBudget | None = None,
        parser_hint: str = "lines",
        priority: LanePriority = LanePriority.NORMAL,
        stdin: str | None = None,
        cwd: str | Path | None = None,
        prefer_docker: bool | None = None,
        metadata: dict[str, Any] | None = None,
        on_output: StreamCallback | None = None,
    ) -> BackgroundProcess:
        """Launch a governed command as a tracked background process.

        Returns a :class:`BackgroundProcess` handle immediately while the run
        proceeds on the event loop. Output streams into the handle (and the
        optional ``on_output`` sink); the final :class:`TerminalResult` is stored
        on ``handle.result`` when the process exits, is cancelled, or trips the
        watchdog. Mirrors Hermes ``terminal(background=true)`` + process_registry.
        """
        argv = [str(part) for part in argv]
        tool = os.path.basename(argv[0]) if argv else "unknown"
        token = CancellationToken()
        handle = BackgroundProcess(
            process_id=f"proc_{uuid.uuid4().hex[:12]}",
            tool=tool,
            argv=argv,
            scan_id=scan_id,
            agent=agent,
            token=token,
            backend=self.choose_backend(prefer_docker).value,
        )

        def _sink(chunk: str) -> Any:
            handle.output.append(chunk)
            return self._emit(on_output, chunk)

        async def _drive() -> None:
            try:
                result = await self.run(
                    argv,
                    scan_id=scan_id,
                    agent=agent,
                    output_path=output_path,
                    timeout_seconds=timeout_seconds,
                    budget=budget,
                    parser_hint=parser_hint,
                    priority=priority,
                    stdin=stdin,
                    cwd=cwd,
                    prefer_docker=prefer_docker,
                    metadata=metadata,
                    on_output=_sink,
                    cancel_token=token,
                )
                handle.result = result
                handle.status = result.status
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("[TERMINAL] background %s failed: %s", tool, exc)
                handle.status = "failed"

        self.telemetry["background_runs"] += 1
        self._processes[handle.process_id] = handle
        handle.task = asyncio.ensure_future(_drive())
        return handle

    def get_process(self, process_id: str) -> BackgroundProcess | None:
        return self._processes.get(process_id)

    def list_processes(self) -> list[dict[str, Any]]:
        return [p.snapshot() for p in self._processes.values()]

    async def cancel_process(self, process_id: str, *, wait: bool = True) -> dict[str, Any]:
        """Request clean cancellation of a tracked background process."""
        handle = self._processes.get(process_id)
        if handle is None:
            return {"status": "not_found", "process_id": process_id}
        if handle.result is not None or handle.status != "running":
            return {"status": "already_finished", "process_id": process_id, "final_status": handle.status}
        handle.token.cancel()
        if wait and handle.task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(handle.task), timeout=10)
            except Exception as cancel_exc:
                logger.debug("[TERMINAL] cancel wait error: %s", cancel_exc)
        return {"status": "cancelled", "process_id": process_id, "final_status": handle.status}

    def get_telemetry(self) -> dict[str, Any]:
        return {
            **self.telemetry,
            "docker_available": self._docker_ok,
            "prefer_docker": self.prefer_docker,
            "live_processes": sum(1 for p in self._processes.values() if p.status == "running"),
        }


# Global governed terminal engine, bound to the active scope guard.
def _build_default_engine() -> TerminalEngine:
    try:
        from backend.core.config import settings

        prefer_docker = bool(getattr(settings, "TERMINAL_PREFER_DOCKER", True))
        image = getattr(settings, "SANDBOX_IMAGE", None)
    except Exception as exc:
        logger.debug("[TERMINAL] config fallback: %s", exc)
        prefer_docker, image = True, None
    return TerminalEngine(scope=scope_guard, prefer_docker=prefer_docker, docker_image=image)


terminal_engine = _build_default_engine()


def register_terminal_tool() -> None:
    """Register terminal execution as a governed tool (Architecture §8, §24).

    The handler runs only allowlisted recon binaries (argv arrays) through the
    governed pipeline: guardrails -> scope -> backend -> watchdog. It is NOT a
    generic exploitation shell.
    """
    try:
        from backend.core.tool_registry import ToolDefinition, tool_registry
        from backend.core.tool_types import ToolType
    except Exception:  # pragma: no cover - registry optional at import time
        return

    if tool_registry.exists("terminal"):
        return

    async def _handler(argv, scan_id: str = "GLOBAL", agent: str = "terminal", timeout_seconds: int = 3600, **kwargs):
        result = await terminal_engine.run(
            argv, scan_id=scan_id, agent=agent, timeout_seconds=timeout_seconds, **kwargs
        )
        return result.to_dict()

    tool_registry.register(
        ToolDefinition(
            name="terminal",
            description=(
                "Execute an allowlisted recon CLI tool as an argv array through the "
                "governed Terminal Engine (scope-checked, sandboxed, audited). "
                "Recon only — not an exploitation shell."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command as an argv array (no shell strings).",
                    },
                    "scan_id": {"type": "string"},
                    "agent": {"type": "string"},
                    "timeout_seconds": {"type": "integer"},
                },
                "required": ["argv"],
            },
            handler=_handler,
            tool_type=ToolType.ENVIRONMENT,
            requires_approval=False,
            mutates_state=False,
            store_result=True,
        )
    )


# Register on import so the tool is discoverable by agents.
register_terminal_tool()
