"""
Network Service Commander (Architecture §5, §16.1 Phase 2, §29.7)
================================================================================
Performs LAN-aware / service-layer discovery WHEN the authorized scope includes
it. Covers OSI layers beyond HTTP (Architecture §29.7):

  - Layer 7: HTTP/HTTPS, DNS, SMTP, FTP, SSH (banner/service detection)
  - Layer 6: TLS / certificate / cipher analysis (tlsx)
  - Layer 4: TCP/UDP scanning, banner grabbing, service detection (naabu, nmap)
  - Layer 3: ICMP/traceroute hints (via nmap host discovery)

Default posture (Architecture §9, §29.7):
  - Recon/validation allowed only inside scope.
  - Private-network scanning DISABLED unless scope.allow_private_networks.
  - Intrusive techniques require explicit approval.
  - ARP spoofing / MITM / credential theft / persistence are NOT implemented.

All execution goes through the governed TerminalEngine (argv-only, scope-checked,
budgeted, sandboxed, audited). Output is parsed into typed graph entities.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from backend.core.hive import BaseAgent, EventType, HiveEvent
from backend.core.iteration_budget import IterationBudget, budget_config
from backend.core.scope import ScopePolicy, ScopeViolation, scope_guard
from backend.core.terminal_engine import terminal_engine
from backend.core.unified_knowledge_graph import (
    EdgeKind,
    NodeKind,
    unified_knowledge_graph,
)

logger = logging.getLogger("agent.network_commander")


class NetworkServiceCommander(BaseAgent):
    """Commander for port/service/TLS assessment (Architecture §5, §29.7)."""

    def __init__(self, bus, scope: ScopePolicy | None = None):
        super().__init__("agent_network_commander", bus)
        self.scope = scope or scope_guard
        self.terminal = terminal_engine
        self.graph = unified_knowledge_graph

    async def setup(self):
        self.bus.subscribe(EventType.TARGET_ACQUIRED, self.handle_target)

    async def handle_target(self, event: HiveEvent):
        target_url = event.payload.get("url")
        scan_id = event.scan_id
        if not target_url:
            return
        host = urlparse(target_url if "://" in target_url else f"//{target_url}", scheme="").hostname
        if not host:
            return
        # Only proceed if the host is in scope (Architecture §9).
        try:
            self.scope.assert_allowed(target_url, action="recon")
        except ScopeViolation as exc:
            logger.info("[NetworkCommander] host out of scope, skipping: %s", exc)
            return
        await self.assess_host(host, scan_id)

    async def assess_host(
        self, host: str, scan_id: str = "GLOBAL", budget: IterationBudget | None = None
    ) -> dict[str, Any]:
        """Run port -> service -> TLS assessment for a host (Architecture §16.1)."""
        budget = budget or budget_config.make("commander", label="network_commander")
        artifacts_root = Path("data") / "scans" / scan_id / "network"
        results: dict[str, Any] = {"host": host, "ports": [], "services": [], "tls": {}, "tool_runs": []}

        await self._emit_log(scan_id, f"Network assessment starting for {host}")

        # 1. Port scan (L4) — prefer naabu, fall back to nmap.
        ports = await self._port_scan(host, scan_id, artifacts_root, budget, results)

        # 2. Service fingerprint (L4/L7) via nmap -sV on discovered ports.
        if ports:
            await self._service_fingerprint(host, ports, scan_id, artifacts_root, budget, results)

        # 3. TLS analysis (L6) via tlsx.
        await self._tls_analysis(host, scan_id, artifacts_root, budget, results)

        # 4. Ingest into the knowledge graph.
        self._ingest_graph(host, results, scan_id)

        await self._emit_log(
            scan_id,
            f"Network assessment complete for {host}: "
            f"{len(results['ports'])} ports, {len(results['services'])} services",
        )
        return results

    # ── Tool runs (governed via Terminal Engine) ─────────────────────────────

    async def _port_scan(self, host, scan_id, root, budget, results) -> list[int]:
        out = root / "naabu.txt"
        res = await self.terminal.run(
            ["naabu", "-host", host, "-top-ports", "1000", "-silent"],
            scan_id=scan_id,
            agent=self.name,
            output_path=out,
            timeout_seconds=180,
            budget=budget,
            parser_hint="lines",
        )
        results["tool_runs"].append(res.to_dict())
        ports: list[int] = []
        if res.status == "finished" and res.stdout:
            for line in res.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    try:
                        ports.append(int(line.rsplit(":", 1)[1]))
                    except ValueError:
                        continue
        # Fallback to nmap if naabu unavailable/empty.
        if not ports:
            nmap_out = root / "nmap_ports.txt"
            res2 = await self.terminal.run(
                ["nmap", "-Pn", "--top-ports", "1000", "-oG", "-", host],
                scan_id=scan_id,
                agent=self.name,
                output_path=nmap_out,
                timeout_seconds=240,
                budget=budget,
                parser_hint="lines",
            )
            results["tool_runs"].append(res2.to_dict())
            if res2.stdout:
                for tok in res2.stdout.split():
                    if "/open/" in tok:
                        try:
                            ports.append(int(tok.split("/")[0]))
                        except ValueError:
                            continue
        ports = sorted(set(ports))
        results["ports"] = ports
        return ports

    async def _service_fingerprint(self, host, ports, scan_id, root, budget, results) -> None:
        port_list = ",".join(str(p) for p in ports[:50])
        out = root / "nmap_sv.xml"
        res = await self.terminal.run(
            ["nmap", "-Pn", "-sV", "-p", port_list, "-oX", str(out), host],
            scan_id=scan_id,
            agent=self.name,
            output_path=root / "nmap_sv.stdout.txt",
            timeout_seconds=300,
            budget=budget,
            parser_hint="xml",
        )
        results["tool_runs"].append(res.to_dict())
        # Lightweight service extraction from stdout lines like "443/tcp open https".
        for line in (res.stdout or "").splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        port = int(parts[0].split("/")[0])
                    except ValueError:
                        continue
                    service = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    results["services"].append({"port": port, "service": service, "version": version})

    async def _tls_analysis(self, host, scan_id, root, budget, results) -> None:
        out = root / "tlsx.jsonl"
        res = await self.terminal.run(
            ["tlsx", "-u", host, "-san", "-cn", "-so", "-ss", "-mm", "-json", "-silent"],
            scan_id=scan_id,
            agent=self.name,
            output_path=out,
            timeout_seconds=120,
            budget=budget,
            parser_hint="jsonl",
        )
        results["tool_runs"].append(res.to_dict())
        if res.status == "finished" and res.stdout:
            import json as _json

            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _json.loads(line)
                    results["tls"] = {
                        "tls_version": rec.get("tls_version"),
                        "cipher": rec.get("cipher"),
                        "subject_cn": rec.get("subject_cn"),
                        "self_signed": rec.get("self_signed"),
                        "mismatched": rec.get("mismatched"),
                    }
                    break
                except Exception as e:
                    logger.debug("[NetworkCommander] tlsx JSON parse failed for %s: %s", line[:50], e)
                    continue

    # ── Graph ingestion ───────────────────────────────────────────────────────

    def _ingest_graph(self, host: str, results: dict, scan_id: str) -> None:
        try:
            host_id = self.graph.upsert_node(NodeKind.HOST, host, scan_id=scan_id)
            for svc in results["services"]:
                label = f"{host}:{svc['port']}/{svc['service']}"
                svc_id = self.graph.upsert_node(
                    NodeKind.SERVICE,
                    label,
                    scan_id=scan_id,
                    port=svc["port"],
                    service=svc["service"],
                    version=svc.get("version", ""),
                )
                self.graph.link(host_id, svc_id, EdgeKind.EXPOSES)
            for port in results["ports"]:
                port_id = self.graph.upsert_node(NodeKind.PORT, f"{host}:{port}", scan_id=scan_id, port=port)
                self.graph.link(host_id, port_id, EdgeKind.EXPOSES)
        except Exception as exc:
            logger.debug("[NetworkCommander] graph ingest skipped: %s", exc)

    async def _emit_log(self, scan_id: str, message: str) -> None:
        if self.bus is None:
            return
        try:
            await self.bus.publish(
                HiveEvent(type=EventType.LOG, source=self.name, scan_id=scan_id, payload={"message": message})
            )
        except Exception as exc:
            logger.debug("[NetworkCommander] emit_log failed: %s", exc)
