from __future__ import annotations

import asyncio
import inspect
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Sequence

from backend.core.approval import approval_store
from backend.core.database import db_manager
from backend.core.guard_layer import PromptInjectionBlocked, guard_layer
from backend.core.memory import memory_store
from backend.core.stdout_watchdog import watch_output
from backend.core.telemetry import telemetry
from backend.core.tool_registry import ToolDefinition, tool_registry
from backend.core.tool_types import BarrierException, ToolType, is_barrier_tool
from backend.core.queue import command_lane
from backend.core.content_boundary import content_boundary
import logging

logger = logging.getLogger(__name__)

# Per-tool availability probes (definition.check_fn / .is_available) hit
# external state — a binary on PATH, a Docker daemon, a network credential.
# Cache the boolean for a short TTL so repeat dispatches inside one turn don't
# re-probe, while config/credential changes still propagate within seconds.
# Mirrors hermes-agent tools/registry._check_fn_cached.
_AVAILABILITY_TTL_SECONDS = 30.0

# Tool types whose execution mutates local/remote state and is worth a
# pre-execution checkpoint so a crash mid-run resumes from a safe boundary
# (Architecture §20 / §29.3 "checkpoint before risky mutation").
_RISKY_TOOL_TYPES = {ToolType.SCAN, ToolType.ENVIRONMENT}

# Callback invoked on tool lifecycle transitions. Signature:
#   callback(event: str, tool_name: str, payload: dict) -> None | Awaitable
# ``event`` is one of "tool.started" / "tool.completed". Sync or async.
ProgressCallback = Callable[[str, str, dict[str, Any]], Optional[Awaitable[None]]]


@dataclass
class ToolExecutionResult:
    call_id: str
    tool_name: str
    status: str
    result: Any = None
    error: str = ""
    duration_ms: int = 0
    truncated: bool = False
    approval_id: str = ""

    @property
    def ok(self) -> bool:
        """True when the tool ran and finished successfully."""
        return self.status == "finished"

    def to_message(self) -> dict[str, Any]:
        """Structured, serialization-friendly view of the result.

        Complements the raw dataclass with an explicit ``ok`` flag so callers
        (LLM tool-result framing, batch consumers) get a stable envelope
        without inspecting status strings.
        """
        return {
            "call_id": self.call_id,
            "tool_name": self.tool_name,
            "status": self.status,
            "ok": self.ok,
            "result": self.result,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
            "approval_id": self.approval_id,
        }


class ToolExecutor:
    def __init__(self, registry=tool_registry, *, progress_callback: ProgressCallback | None = None) -> None:
        self.registry = registry
        self.progress_callback = progress_callback
        # name -> (monotonic_ts, available_bool)
        self._availability_cache: dict[str, tuple[float, bool]] = {}

    def set_progress_callback(self, callback: ProgressCallback | None) -> None:
        """Register (or clear) the tool lifecycle progress callback."""
        self.progress_callback = callback

    def invalidate_availability_cache(self) -> None:
        """Drop cached availability probes (e.g. after a config/credential change)."""
        self._availability_cache.clear()

    async def execute(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        scan_id: str = "GLOBAL",
        agent: str = "system",
        approval_id: str | None = None,
        call_id: str | None = None,
    ) -> ToolExecutionResult:
        args = args or {}
        call_id = call_id or f"call_{uuid.uuid4().hex[:16]}"
        started = time.time()
        definition = self.registry.get(tool_name)

        with telemetry.span("tool.execute", kind="tool", scan_id=scan_id, tool_name=tool_name, agent=agent, call_id=call_id):
            try:
                guard_layer.assert_safe_text(json.dumps(args, default=str))
            except PromptInjectionBlocked as exc:
                await db_manager.create_toolcall(
                    call_id=call_id, scan_id=scan_id, tool_name=tool_name,
                    agent=agent, args=args, status="blocked", error=str(exc),
                )
                return ToolExecutionResult(call_id, tool_name, "blocked", error=str(exc))

            await db_manager.create_toolcall(
                call_id=call_id, scan_id=scan_id, tool_name=tool_name,
                agent=agent, args=args, status="running",
            )

            # Per-tool availability check (TTL-cached). No-op for tools that
            # declare no probe, so existing behaviour is preserved.
            if not self._is_available(definition):
                reason = f"Tool '{tool_name}' is unavailable in the current environment."
                await db_manager.finish_toolcall(call_id=call_id, status="unavailable", error=reason)
                return ToolExecutionResult(call_id, tool_name, "unavailable", error=reason)

            if (definition.requires_approval or definition.mutates_state) and not approval_store.is_approved(approval_id):
                reason = f"Tool '{tool_name}' requires approval before execution."
                ticket = approval_store.request(scan_id=scan_id, tool_name=tool_name, reason=reason, payload=args)
                await db_manager.create_approval(
                    approval_id=ticket.id, scan_id=scan_id, tool_name=tool_name,
                    reason=reason, payload=args, status="pending",
                )
                await db_manager.finish_toolcall(call_id=call_id, status="approval_required", result={"approval_id": ticket.id})
                return ToolExecutionResult(call_id, tool_name, "approval_required", approval_id=ticket.id)

            # Approval/scope gates have passed and the tool is about to run:
            # checkpoint before risky/mutating tools so a crash resumes from a
            # safe boundary (§29.3). Never blocks execution on failure.
            self._maybe_checkpoint(definition, scan_id)
            await self._emit_progress("tool.started", tool_name, args=args, scan_id=scan_id, agent=agent, call_id=call_id)

            try:
                async with command_lane.slot():
                    raw_result = await self._call(definition, args, scan_id=scan_id, agent=agent)
                    
                watched = await watch_output(raw_result) if definition.summarize_result else await watch_output(raw_result, max_bytes=10**9)
                guard_layer.assert_safe_text(watched.content, output=True)
                
                result: Any = watched.content
                if definition.store_result:
                    result = content_boundary.wrap_scan_output(tool_name, str(result))
                    
                duration_ms = int((time.time() - started) * 1000)
                logger.info(f"CommandLane telemetry: {command_lane.telemetry}")
                await db_manager.finish_toolcall(
                    call_id=call_id, status="finished", result=result, duration_ms=duration_ms,
                    result_bytes=watched.original_bytes, result_sha256=watched.sha256,
                )
                if definition.store_result:
                    await memory_store.remember_semantic({
                        "memory_type": "tool_result",
                        "tool_name": tool_name,
                        "scan_id": scan_id,
                        "content": str(result)[:8000],
                        "vector": [],
                    })
                await self._emit_progress("tool.completed", tool_name, status="finished", duration_ms=duration_ms, is_error=False, truncated=watched.truncated, call_id=call_id)
                return ToolExecutionResult(call_id, tool_name, "finished", result=result, duration_ms=duration_ms, truncated=watched.truncated)
            except BarrierException as exc:
                duration_ms = int((time.time() - started) * 1000)
                await db_manager.finish_toolcall(call_id=call_id, status="approval_required", result=exc.payload, duration_ms=duration_ms)
                await self._emit_progress("tool.completed", tool_name, status="approval_required", duration_ms=duration_ms, is_error=False, call_id=call_id)
                return ToolExecutionResult(call_id, tool_name, "approval_required", error=exc.reason, duration_ms=duration_ms, approval_id=exc.payload.get("approval_id", ""))
            except Exception as exc:
                duration_ms = int((time.time() - started) * 1000)
                await db_manager.finish_toolcall(call_id=call_id, status="failed", error=str(exc), duration_ms=duration_ms)
                await self._emit_progress("tool.completed", tool_name, status="failed", duration_ms=duration_ms, is_error=True, error=str(exc), call_id=call_id)
                return ToolExecutionResult(call_id, tool_name, "failed", error=str(exc), duration_ms=duration_ms)

    async def execute_batch(
        self,
        calls: Sequence[dict[str, Any] | tuple[str, dict[str, Any]] | tuple[str]],
        *,
        scan_id: str = "GLOBAL",
        agent: str = "system",
        approval_id: str | None = None,
        max_concurrent: int | None = None,
    ) -> list[ToolExecutionResult]:
        """Dispatch several tool calls and collect results in submission order.

        Adopts the hermes-agent concurrent-dispatch pattern, idiomatically for
        Vigilagent's async stack: results map back to the original call order
        regardless of completion order. Interactive/barrier tools (``done``,
        ``ask``, ``ask_user``) force the whole batch to run sequentially so a
        user-facing prompt is never raced. All per-call approval, budget, scope
        and guard gates run unchanged inside :meth:`execute`.

        Each entry is either a dict ``{"tool_name", "args", "approval_id"?,
        "call_id"?}`` or a ``(tool_name, args)`` tuple.
        """
        specs = [self._normalize_call(call) for call in calls]
        if not specs:
            return []

        async def _run(spec: dict[str, Any]) -> ToolExecutionResult:
            return await self.execute(
                spec["tool_name"],
                spec["args"],
                scan_id=scan_id,
                agent=agent,
                approval_id=spec.get("approval_id") or approval_id,
                call_id=spec.get("call_id"),
            )

        if not self._should_parallelize(specs):
            return [await _run(spec) for spec in specs]

        limit = max_concurrent or command_lane.max_concurrent
        semaphore = asyncio.Semaphore(max(1, limit))

        async def _guarded(spec: dict[str, Any]) -> ToolExecutionResult:
            async with semaphore:
                return await _run(spec)

        # gather preserves the order of the awaitables, giving ordered results.
        return list(await asyncio.gather(*(_guarded(spec) for spec in specs)))

    @staticmethod
    def _normalize_call(call: Any) -> dict[str, Any]:
        if isinstance(call, dict):
            return {
                "tool_name": call["tool_name"],
                "args": call.get("args") or {},
                "approval_id": call.get("approval_id"),
                "call_id": call.get("call_id"),
            }
        # (tool_name, args?) tuple/list form.
        tool_name = call[0]
        args = call[1] if len(call) > 1 else {}
        return {"tool_name": tool_name, "args": args or {}, "approval_id": None, "call_id": None}

    @staticmethod
    def _should_parallelize(specs: Sequence[dict[str, Any]]) -> bool:
        """True when a batch is safe to run concurrently.

        Falls back to sequential for single calls and for any batch containing
        a barrier/user-facing tool (mirrors hermes ``_NEVER_PARALLEL_TOOLS``).
        """
        if len(specs) <= 1:
            return False
        return not any(is_barrier_tool(spec["tool_name"]) for spec in specs)

    def _is_available(self, definition: ToolDefinition) -> bool:
        """Return whether a tool's optional availability probe passes (TTL-cached).

        Looks for a ``check_fn``/``is_available`` callable on the definition.
        Tools that declare neither are always available, so this is a no-op for
        the current registry and only activates once probes are added.
        """
        check_fn = getattr(definition, "check_fn", None) or getattr(definition, "is_available", None)
        if check_fn is None:
            return True
        now = time.monotonic()
        cached = self._availability_cache.get(definition.name)
        if cached is not None and now - cached[0] < _AVAILABILITY_TTL_SECONDS:
            return cached[1]
        try:
            value = bool(check_fn())
        except Exception as exc:
            logger.debug(f"Availability probe for {definition.name} raised; marking unavailable: {exc}")
            value = False
        self._availability_cache[definition.name] = (now, value)
        return value

    def _maybe_checkpoint(self, definition: ToolDefinition, scan_id: str) -> None:
        """Checkpoint before a risky/mutating tool runs. Never blocks execution."""
        if not scan_id or scan_id == "GLOBAL":
            return
        risky = (
            definition.mutates_state
            or definition.requires_approval
            or definition.tool_type in _RISKY_TOOL_TYPES
        )
        if not risky:
            return
        try:
            from backend.core.scan_state_db import scan_state_db
            scan_state_db.checkpoint_before_validation(scan_id, phase=f"pre_tool:{definition.name}")
        except Exception as exc:
            logger.debug(f"Pre-tool checkpoint skipped for {definition.name}: {exc}")

    async def _emit_progress(self, event: str, tool_name: str, **payload: Any) -> None:
        """Fire the progress callback if registered. Swallows callback errors."""
        callback = self.progress_callback
        if callback is None:
            return
        try:
            outcome = callback(event, tool_name, payload)
            if inspect.isawaitable(outcome):
                await outcome
        except Exception as exc:
            logger.debug(f"Tool progress callback error: {exc}")

    async def _call(self, definition: ToolDefinition, args: dict[str, Any], *, scan_id: str, agent: str) -> Any:
        if definition.handler is None:
            raise RuntimeError(f"Tool '{definition.name}' has no handler")
        kwargs = dict(args)
        sig = inspect.signature(definition.handler)
        if "scan_id" in sig.parameters and "scan_id" not in kwargs:
            kwargs["scan_id"] = scan_id
        if "agent" in sig.parameters and "agent" not in kwargs:
            kwargs["agent"] = agent
        result = definition.handler(**kwargs)
        if inspect.isawaitable(result):
            return await result
        return result


tool_executor = ToolExecutor()
