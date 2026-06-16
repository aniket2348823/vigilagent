"""Sub-agent 3 verification harness: end-to-end recon spine + tools.

Runs each tool in the http+discovery phases via the real engine, parses output,
counts entities, and asserts AlphaOrchestrator.run() emits RECON_COMPLETE.
Self-deletes on success.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Force settings used by recon path.
os.environ.setdefault("ALPHA_ENABLE_EXTERNAL_TOOLS", "true")
os.environ.setdefault("VIGILAGENT_RECON_CONTAINER", "reverent_banach")
os.environ.setdefault("ALPHA_TOOL_TIMEOUT_SECONDS", "60")


async def harness() -> int:
    from backend.agents.alpha_recon.models import ReconScope, ScanMode
    from backend.agents.alpha_recon.artifacts import ArtifactStore
    from backend.tools.recon.commands import ReconCommandPlanner
    from backend.tools.recon.runner import ReconCommandRunner
    from backend.parsers.recon import PARSER_REGISTRY

    scan_id = f"DEBUG-RECON-FULL-{int(time.time())}"
    target = "http://localhost:8080/index.php"
    parsed = urlparse(target)
    scope = ReconScope(
        base_domain=parsed.hostname or "localhost",
        target_url=target,
        scan_mode=ScanMode.STANDARD,
        base_url=f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 8080}",
        max_depth=2,
        max_rps=50,
        explicit_authorization=True,
    )
    artifacts = ArtifactStore(scan_id)
    planner = ReconCommandPlanner()
    runner = ReconCommandRunner()

    raw_dir = artifacts.raw_dir
    # Simulate hosts file the orchestrator would build for HTTP/discovery.
    hosts_file = raw_dir / "all_hosts.txt"
    hosts_file.write_text("localhost:8080\n", encoding="utf-8")

    live_hosts = [target.rstrip("/")]
    print(f"[harness] scan_id={scan_id} target={target}")
    print(f"[harness] raw_dir={raw_dir}")

    # Build commands for HTTP + discovery phases (the meaty ones for DVWA).
    cmds = []
    cmds.extend(planner.http_commands(scope, raw_dir, hosts_file))
    cmds.extend(planner.discovery_commands(scope, raw_dir, live_hosts))
    cmds.extend(planner.visual_commands(scope, raw_dir, live_hosts))

    rows: list[tuple[str, str, int, int, str]] = []
    for cmd in cmds:
        bytes_out = 0
        ents = 0
        note = ""
        try:
            res = await runner.execute(cmd, scan_id=scan_id)
            status = res.status
            # Find the file the parser should read (mirror alpha_orchestrator).
            parse_path = cmd.output_path
            if cmd.metadata.get("json_file"):
                alt = Path(cmd.metadata["json_file"])
                if alt.exists():
                    parse_path = alt
            if cmd.metadata.get("xml_file"):
                alt = Path(cmd.metadata["xml_file"])
                if alt.exists():
                    parse_path = alt
            try:
                bytes_out = parse_path.stat().st_size if parse_path.exists() else 0
            except OSError:
                bytes_out = 0
            parser = PARSER_REGISTRY.get(cmd.tool_name)
            if parser and parse_path.exists():
                try:
                    ents = len(parser(parse_path))
                except Exception as pe:
                    note = f"parser_err:{pe}"
            elif not parser:
                note = "no_parser"
            elif not parse_path.exists():
                note = f"no_file:{parse_path.name}"
        except Exception as exc:
            status = f"exec_err:{exc.__class__.__name__}"
            note = str(exc)[:80]
        rows.append((cmd.tool_name, status, bytes_out, ents, note))
        print(f"  {cmd.tool_name:18s} status={status:10s} bytes={bytes_out:7d} entities={ents:4d} {note}")

    print("\n[harness] PER-TOOL TABLE:")
    print(f"{'tool':18s} {'status':12s} {'bytes':>8s} {'entities':>9s}  note")
    for tool, status, b, e, note in rows:
        print(f"  {tool:18s} {status:12s} {b:8d} {e:9d}  {note}")

    # Now do a tiny AlphaOrchestrator.run() smoke — must publish RECON_COMPLETE.
    print("\n[harness] Running AlphaOrchestrator end-to-end smoke test...")
    from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator
    from backend.core.hive import EventType

    class _CapturingBus:
        def __init__(self) -> None:
            self.events: list = []
        async def publish(self, event) -> None:
            self.events.append(event)

    bus = _CapturingBus()
    orch = AlphaOrchestrator(bus)
    smoke_id = f"DEBUG-RECON-SMOKE-{int(time.time())}"
    try:
        await asyncio.wait_for(
            orch.run(target, scan_id=smoke_id, mode="STANDARD"),
            timeout=240,
        )
    except asyncio.TimeoutError:
        print("[harness] orchestrator timed out at 240s")
    except Exception as exc:
        print(f"[harness] orchestrator raised: {exc.__class__.__name__}: {exc}")

    complete_events = [e for e in bus.events if getattr(e, "type", None) == EventType.RECON_COMPLETE]
    print(f"[harness] events_published={len(bus.events)} recon_complete={len(complete_events)}")
    if complete_events:
        ce = complete_events[0]
        payload = ce.payload or {}
        summary = payload.get("summary", {})
        print(f"  summary: total_endpoints={summary.get('total_endpoints', 0)}, "
              f"total_subdomains={summary.get('total_subdomains', 0)}, "
              f"tools_run={len(payload.get('tools_run', []))}")
    else:
        print("  [FAIL] RECON_COMPLETE was NOT published")
    return 0 if complete_events else 1


if __name__ == "__main__":
    exit_code = asyncio.run(harness())
    sys.exit(exit_code)
