"""Benchmark the full recon pipeline (all applicable tools) against DVWA.

Replicates the Alpha orchestrator's phase flow for a localhost:8888 AGGRESSIVE
target using the REAL ReconCommandPlanner + ReconCommandRunner, so every tool
runs through the governed docker-exec backend exactly as in production.

Usage:
    python scripts/_benchmark_recon.py [--concurrency N] [--report-only]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.getcwd())

# Load the canonical .env WITH override (the config fix) so stale ambient env
# cannot shadow the correct values; then force the benchmark's own knobs.
from dotenv import load_dotenv

load_dotenv(override=True)
os.environ["ALPHA_ENABLE_EXTERNAL_TOOLS"] = "true"
os.environ["VIGILAGENT_RECON_IMAGE"] = "reveant_branch:latest"
os.environ["VIGILAGENT_RECON_CONTAINER"] = "quirky_chatterjee"
os.environ["ALPHA_TOOL_TIMEOUT_SECONDS"] = "150"

from backend.agents.alpha_recon.models import ReconScope, ScanMode  # noqa: E402
from backend.tools.recon.commands import ReconCommandPlanner, TOOL_DEPENDENCY_GRAPH  # noqa: E402
from backend.tools.recon.registry import ALL_TOOLS, check_tool_availability  # noqa: E402
from backend.tools.recon.runner import ReconCommandRunner  # noqa: E402
from backend.agents.alpha_recon.artifacts import ArtifactStore  # noqa: E402
from backend.tools.recon.docker_runtime import reset_container_cache  # noqa: E402

TARGET = "http://localhost:8888/login.php"


class _RagStub:
    async def ingest_tool_summary(self, *a, **k):
        pass


# Duplicate classification: group -> priority-ordered tool names. Tools in the
# same group do overlapping work; lower priority = redundant when a higher one
# is present. Groups the runtime DAG deduplicates against.
DEDUPE_CLASSIFICATION = {
    "crawler": ["katana", "gospider"],
    "param_miner": ["arjun", "paramspider"],  # both discover params
    "dir_fuzz": ["feroxbuster", "ffuf", "gobuster"],
    "port_scan": ["nmap", "naabu", "masscan"],  # nmap deep; naabu/masscan fast pre
    "tls_audit": ["tlsx", "testssl"],  # tlsx quick, testssl deep
    "passive_subs": ["subfinder", "amass", "assetfinder", "github-subdomains"],  # same job
    "passive_urls": ["gau", "waybackurls"],  # both archive URL mining
    "dns_resolve": ["dnsx", "puredns"],  # resolution/bruteforce
}


def classify_tool(name: str) -> str:
    for group, members in DEDUPE_CLASSIFICATION.items():
        if name in members:
            return group
    return "unique"


def report_tool_map() -> list[dict]:
    """Classify all 39 registry tools: phase, mode, duplicate group, applies-to-localhost."""
    rows = []
    for name, spec in sorted(ALL_TOOLS.items()):
        phase = spec.get("phase", "")
        group = classify_tool(name)
        localhost_applicable = not (
            group == "passive_subs"
            or group == "passive_urls"
            or name in ("github-subdomains", "cloudlist", "spiderfoot", "assetfinder", "amass", "puredns", "massdns")
        )
        rows.append(
            {
                "tool": name,
                "phase": phase,
                "owner": spec.get("owner", "alpha"),
                "duplicate_group": group,
                "localhost_applicable": localhost_applicable,
            }
        )
    return rows


def build_scope() -> ReconScope:
    return ReconScope(
        base_domain="localhost",
        target_url=TARGET,
        base_url="http://localhost",
        scan_mode=ScanMode.AGGRESSIVE,
        max_depth=3,
        max_rps=200,
        explicit_authorization=True,
    )


async def run_tools(cmds, runner, scan_id, raw_dir, concurrency, tools_log):
    """Bounded-parallel DAG execution mirroring _run_and_parse (governed runner)."""
    import asyncio as _aio

    from backend.tools.recon.registry import check_tool_availability as _avail

    ext = os.getenv("ALPHA_ENABLE_EXTERNAL_TOOLS", "false").lower() == "true"
    available = []
    for cmd in cmds:
        a = _avail(cmd.tool_name)
        if not a.get("installed") or not ext:
            tools_log.append(
                {
                    "tool": cmd.tool_name,
                    "phase": cmd.phase,
                    "status": "skipped",
                    "reason": "not_installed" if not a.get("installed") else "external_tools_disabled",
                    "seconds": 0.0,
                    "entities": 0,
                }
            )
            continue
        available.append(cmd)
    if not available:
        return 0

    names = {c.tool_name for c in available}
    deps = {c.tool_name: [d for d in TOOL_DEPENDENCY_GRAPH.get(c.tool_name, []) if d in names] for c in available}
    sem = _aio.Semaphore(max(1, concurrency))
    pending: dict = {}
    completed: set = set()
    total_entities = 0

    async def _run_one(cmd):
        nonlocal total_entities
        async with sem:
            t0 = time.time()
            status, reason, entities = "ok", "", 0
            try:
                await runner.execute(cmd, scan_id=scan_id, agent="bench_alpha")
                entities = _count_entities(cmd)
            except Exception as exc:
                status, reason = "error", str(exc)[:160]
            dt = time.time() - t0
            total_entities += entities
            tools_log.append(
                {
                    "tool": cmd.tool_name,
                    "phase": cmd.phase,
                    "status": status,
                    "reason": reason,
                    "seconds": round(dt, 2),
                    "entities": entities,
                }
            )

    while len(completed) < len(available):
        ready = [
            c
            for c in available
            if c.tool_name not in completed and c.tool_name not in pending and all(d in completed for d in deps[c.tool_name])
        ]
        for c in ready:
            pending[c.tool_name] = _aio.create_task(_run_one(c))
        if not pending:
            for c in available:
                if c.tool_name not in completed and c.tool_name not in pending:
                    pending[c.tool_name] = _aio.create_task(_run_one(c))
            if not pending:
                break
        done, _ = await _aio.wait(list(pending.values()), return_when=_aio.FIRST_COMPLETED)
        for task in done:
            name = next((n for n, t in pending.items() if t is task), None)
            if name is None:
                continue
            completed.add(name)
            del pending[name]
    return total_entities


def _count_entities(cmd) -> int:
    """Count non-empty lines / json records in the tool output (best-effort)."""
    import json as _json
    from pathlib import Path

    path = None
    jf = cmd.metadata.get("json_file") or cmd.metadata.get("xml_file")
    if jf and Path(jf).exists() and Path(jf).stat().st_size > 0:
        path = Path(jf)
    elif cmd.output_path.exists() and cmd.output_path.stat().st_size > 0:
        path = cmd.output_path
    else:
        for ext in (".json", ".jsonl", ".xml"):
            sib = Path(str(cmd.output_path) + ext)
            if sib.exists() and sib.stat().st_size > 0:
                path = sib
                break
    if not path:
        return 0
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".jsonl":
            return len([l for l in txt.splitlines() if l.strip()])
        if path.suffix == ".json":
            try:
                data = _json.loads(txt)
                return len(data) if isinstance(data, list) else 1
            except Exception:
                return 0
        if path.suffix == ".xml":
            return txt.count("<port") + txt.count("<host") // 2
        return len([l for l in txt.splitlines() if l.strip()])
    except Exception:
        return 0


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# Pass aliases share a parent binary (nuclei/ffuf) — probe the parent.
_PARENT_BINARY = {
    "nuclei_default_login": "nuclei",
    "nuclei_cve": "nuclei",
    "nuclei_takeover": "nuclei",
    "ffuf_vhost": "ffuf",
}


def probe_container_binaries() -> dict[str, dict]:
    """Verify every registry tool's binary actually EXISTS in the recon container.

    ``check_tool_availability`` only checks the tool name against the registry's
    DOCKER_ALL_TOOLS set — it NEVER verifies the binary is installed inside the
    image. A tool that was registered but never installed (or later removed from
    the Dockerfile) therefore still reports "installed". This probe execs into
    the running container and runs ``command -v`` per tool so dead tools are
    caught before they silently fail during a real engagement.

    Returns {tool_name: {"present": bool, "binary": str}}.
    """
    from backend.tools.recon.docker_runtime import running_recon_container

    c = running_recon_container()
    if not c:
        return {}
    result: dict[str, dict] = {}
    for name, spec in ALL_TOOLS.items():
        binary = _PARENT_BINARY.get(name, spec["binary"])
        # python-binary tools ship as console-script wrappers named after the
        # TOOL (linkfinder, secretfinder, paramspider, spiderfoot, inql).
        probe_name = name if spec["binary"] == "python" else binary
        try:
            p = subprocess.run(
                ["docker", "exec", c, "sh", "-lc", f"command -v {probe_name} >/dev/null 2>&1 && echo yes"],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            result[name] = {"present": p.returncode == 0 and "yes" in (p.stdout or ""), "binary": probe_name}
        except Exception as exc:
            result[name] = {"present": False, "binary": probe_name, "reason": str(exc)[:80]}
    return result


def tool_was_exercised(tool_name: str, tools_log: list[dict]) -> str:
    """Coverage status of a registry tool in the benchmark run.

    Returns one of: "ok", "error", "skipped", "not_dispatched".
    """
    rows = [r for r in tools_log if r["tool"] == tool_name or r["tool"] == f"sigma:{tool_name}"]
    if not rows:
        return "not_dispatched"
    if any(r["status"] == "error" for r in rows):
        return "error"
    if any(r["status"] in ("ok", "warn") for r in rows):
        return "ok"
    return "skipped"


async def build_phase_commands(planner, scope, raw_dir, scan_id="BENCH"):
    """Replicate the orchestrator's per-phase command building for localhost:8888."""
    hosts = raw_dir / "hosts.txt"
    _write(hosts, "localhost:8888\nlocalhost\n")
    live = ["http://localhost:8888"]

    phases = {
        "INFRA": planner.port_commands(scope, raw_dir, hosts, explicit_port=8888)
        + planner.tls_commands(scope, raw_dir, hosts),
        "HTTP": planner.http_commands(scope, raw_dir, hosts, explicit_port=8888),
    }
    # Discovery: custom wordlist (real pipeline builds from crawled entities).
    wl = raw_dir / "custom_wordlist.txt"
    dvwa_paths = [
        "login.php", "index.php", "setup.php", "security.php", "logout.php", "instructions.php",
        "about.php", "vulnerabilities/", "vulnerabilities/sqli/", "vulnerabilities/sqli_blind/",
        "vulnerabilities/xss_r/", "vulnerabilities/xss_d/", "vulnerabilities/csrf/",
        "vulnerabilities/exec/", "vulnerabilities/fi/", "vulnerabilities/brute/",
        "vulnerabilities/upload/", "vulnerabilities/captcha/", "vulnerabilities/sqli/",
        "vulnerabilities/sqli_blind/", "vulnerabilities/xss_r/", "vulnerabilities/xss_d/",
        "vulnerabilities/command_line/", "vulnerabilities/open_redirect/",
        "config/", "config/config.inc.php", "phpinfo.php", "README.md", "CHANGELOG.md",
        "external/", "docs/", "hackable/", "hackable/uploads/", "images/", "css/", "js/",
        "admin/", "admin/index.php", "robots.txt", "sitemap.xml", ".htaccess", "favicon.ico",
        "server-status", "server-info", "phpmyadmin/", "includes/", "source/",
        "vulnerabilities/view_source.php", "vulnerabilities/view_help.php",
    ]
    generic = ["admin", "api", "backup", "config", "data", "db", "dev", "login", "test",
               "upload", "user", "www", "assets", "static", "public", "private", "tmp", "logs"]
    wl_content = "\n".join(dict.fromkeys([*dvwa_paths, *generic])) + "\n"
    _write(wl, wl_content)
    # Auth-first: authenticate the target BEFORE discovery/validation so the
    # content fuzzers + nuclei see the authenticated app (matches orchestrator).
    auth_cookie = ""
    try:
        from backend.core.attack_surface_seeder import authenticate_attack_session

        auth_cookie = await asyncio.wait_for(authenticate_attack_session(TARGET, scan_id), timeout=30) or ""
    except Exception as exc:
        print(f"[bench] auth-first failed: {exc}")
    phases["DISCOVERY"] = planner.discovery_commands(scope, raw_dir, live, wl, cookie=auth_cookie)
    phases["API"] = planner.api_commands(scope, raw_dir, live)
    phases["VISUAL"] = planner.visual_commands(scope, raw_dir, live)
    phases["VALIDATION"] = planner.validation_commands(scope, raw_dir, live, interactsh_url="", cookie=auth_cookie)
    return phases


async def run_sigma_validation(scan_id: str, tools_log: list[dict], raw_dir) -> dict:
    """Replicate the orchestrator's recon→Sigma findings feed: authenticate to
    DVWA via the seeder, then run Sigma's exclusive CLI validators (nuclei,
    whatweb, wafw00f) against the authenticated seeded targets with the Cookie
    forwarded — exactly as backend/core/orchestrator.py now dispatches
    recon_nuclei/tech_fingerprint/tech_xss."""
    from backend.core.attack_surface_seeder import seed_attack_surface
    from backend.core.terminal_engine import terminal_engine

    result = {"authenticated": False, "targets": 0, "findings": 0, "tools": {}}
    try:
        surface = await seed_attack_surface(TARGET, scan_id)
        result["authenticated"] = surface.authenticated
        result["targets"] = len(surface.targets)
        tools_log.append(
            {
                "tool": "seeder",
                "phase": "recon_to_sigma",
                "status": "ok" if surface.authenticated else "warn",
                "reason": f"app={surface.app} authed={surface.authenticated} targets={len(surface.targets)}",
                "seconds": 0.0,
                "entities": len(surface.targets),
            }
        )
        if not surface.authenticated:
            return result
        # Run the Sigma CLI validators on the first authenticated seeded target.
        target = surface.targets[0]
        cookie = (target.headers or {}).get("Cookie") or ""
        # Nuclei runs against the ORIGIN (templates carry their own relative
        # paths like /login.php), not the seeded deep URL, so default-login and
        # exposed-panel templates can actually reach their targets.
        from urllib.parse import urlsplit

        _pu = urlsplit(target.url)
        origin = f"{_pu.scheme}://{_pu.netloc}/" if _pu.scheme else target.url
        # wafw00f -H takes a headers FILE path, not an inline header; write the
        # auth Cookie to a file and pass that path.
        wafw00f_h = []
        if cookie:
            hf = raw_dir / "wafw00f_headers.txt"
            hf.write_text(f"Cookie: {cookie}\n", encoding="utf-8")
            wafw00f_h = ["-H", str(hf)]
        # Default-login pass runs WITHOUT the forwarded cookie: those templates
        # do their own session handshake and a duplicate Cookie header breaks it
        # (verified: same flags match without cookie, 0 with). CVE sweep keeps it.
        argv_map = {
            "nuclei": [
                [
                    "nuclei", "-u", origin, "-tags", "default-login",
                    "-severity", "critical,high,medium",
                    "-timeout", "5", "-retries", "0", "-c", "1",
                    "-stats", "-stats-interval", "15",
                    "-exclude-tags", "fuzz,dos", "-jsonl", "-silent",
                ],
                [
                    "nuclei", "-u", origin, "-severity", "critical,high",
                    "-timeout", "5", "-retries", "0", "-rl", "150", "-c", "15",
                    "-stats", "-stats-interval", "20",
                    "-exclude-tags", "fuzz,dos", "-jsonl", "-silent", "-H", f"Cookie: {cookie}",
                ],
            ],
            "whatweb": [["whatweb", "--log-json=-", target.url, "-H", f"Cookie: {cookie}"]],
            "wafw00f": [["wafw00f", target.url, *wafw00f_h]],
            "httpx": [["httpx", "-u", target.url, "-tech-detect", "-status-code", "-json", "-silent", "-H", f"Cookie: {cookie}"]],
            "sqlmap": [
                [
                    "sqlmap", "-u", target.url, "--batch", "--level", "1", "--risk", "1",
                    "--timeout", "8", "--retries", "0", "--threads", "2",
                    "--output-dir", str(raw_dir / "sigma_sqlmap"),
                    *( [] if not cookie else ["--cookie", cookie] ),
                ]
            ],
            "nikto": [
                ["nikto", "-h", target.url, "-nointeractive", "-Format", "json",
                 "-o", str(raw_dir / "sigma_nikto.json")]
            ],
            "wpscan": [
                ["wpscan", "--url", target.url, "--no-banner", "--random-user-agent",
                 "--disable-tls-checks", "--format", "json"]
            ],
        }
        for tool, passes in argv_map.items():
            t0 = time.time()
            status, findings = "ok", 0
            for idx, argv in enumerate(passes):
                out = raw_dir / f"sigma_{tool}.out" if len(passes) == 1 else raw_dir / f"sigma_{tool}_p{idx + 1}.out"
                try:
                    res = await terminal_engine.run(
                        argv, scan_id=scan_id, agent="bench_sigma", output_path=out,
                        timeout_seconds=180, parser_hint="jsonl",
                    )
                    if res.output_path and os.path.exists(res.output_path):
                        txt = open(res.output_path, encoding="utf-8", errors="replace").read()
                        for ln in txt.splitlines():
                            try:
                                j = json.loads(ln)
                                if isinstance(j, dict) and j.get("info"):
                                    findings += 1
                            except Exception:
                                pass
                    # wpscan exits 4 on non-WordPress targets = correct verdict.
                    if res.status not in ("finished",) and not (
                        tool == "wpscan" and res.exit_code == 4
                    ):
                        status = res.status
                except Exception as exc:
                    status = "error"
            result["tools"][tool] = findings
            result["findings"] += findings
            tools_log.append(
                {
                    "tool": f"sigma:{tool}",
                    "phase": "recon_to_sigma",
                    "status": status,
                    "reason": f"authed={bool(cookie)}",
                    "seconds": round(time.time() - t0, 2),
                    "entities": findings,
                }
            )
    except Exception as exc:
        tools_log.append(
            {
                "tool": "seeder", "phase": "recon_to_sigma", "status": "error",
                "reason": str(exc)[:120], "seconds": 0.0, "entities": 0,
            }
        )
    return result


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()

    if args.report_only:
        print(json.dumps(report_tool_map(), indent=2))
        return 0

    scan_id = f"BENCH-{uuid.uuid4().hex[:8]}"
    artifacts = ArtifactStore(scan_id)
    raw_dir = artifacts.raw_dir
    planner = ReconCommandPlanner()
    runner = ReconCommandRunner()
    scope = build_scope()
    reset_container_cache()

    phases = await build_phase_commands(planner, scope, raw_dir, scan_id)
    tools_log: list[dict] = []
    grand_start = time.time()
    for phase_name in ("INFRA", "HTTP", "DISCOVERY", "API", "VISUAL", "VALIDATION"):
        cmds = phases[phase_name]
        if not cmds:
            continue
        t0 = time.time()
        n = await run_tools(cmds, runner, scan_id, raw_dir, args.concurrency, tools_log)
        dt = time.time() - t0
        print(f"[PHASE] {phase_name}: {len(cmds)} cmd(s) in {dt:.1f}s, {n} entities")

    # Stage 2: recon → Sigma findings feed (seeder auth + Sigma CLI validators).
    print("\n[PHASE] recon_to_sigma: seeder auth + Sigma CLI validation...")
    sigma_result = await run_sigma_validation(scan_id, tools_log, raw_dir)
    total = time.time() - grand_start

    print(f"\n=== BENCHMARK scan={scan_id} concurrency={args.concurrency} TOTAL={total:.1f}s ===")
    print(f"{'TOOL':<18}{'PHASE':<16}{'STATUS':<9}{'SECS':>8}{'ENT':>5}")
    for row in sorted(tools_log, key=lambda r: (r["phase"], r["tool"])):
        extra = f" ({row['reason'][:60]})" if row.get("reason") else ""
        print(f"{row['tool']:<18}{row['phase']:<16}{row['status']:<9}{row['seconds']:>8.1f}{row['entities']:>5}{extra}")
    ok = [r for r in tools_log if r["status"] == "ok"]
    skipped = [r for r in tools_log if r["status"] == "skipped"]
    err = [r for r in tools_log if r["status"] == "error"]
    warn = [r for r in tools_log if r["status"] == "warn"]
    print(f"\nSUMMARY: ran={len(ok)} skipped={len(skipped)} errors={len(err)} warnings={len(warn)} total_time={total:.1f}s")
    print(
        f"SIGMA-FEED: authenticated={sigma_result.get('authenticated')} "
        f"seeded_targets={sigma_result.get('targets')} cli_findings={sigma_result.get('findings')}"
    )
    # ── COVERAGE: every registry tool must be exercised or present ──────────
    # This is the dead-tool detector: check_tool_availability only matches the
    # tool NAME against the registry — a tool registered but never installed in
    # the image still reports "installed". Probing the container binaries + the
    # exercised log closes that gap: every ALL_TOOLS entry must be either
    # exercised by this benchmark (ok/warn) or present in the container.
    probe = probe_container_binaries()
    coverage = []
    for name in sorted(ALL_TOOLS):
        status = tool_was_exercised(name, tools_log)
        present = probe.get(name, {}).get("present", False)
        if status == "error":
            coverage.append((name, "FAIL", "ran but errored"))
        elif status in ("ok", "warn"):
            coverage.append((name, "PASS", f"exercised ({status})"))
        elif status == "skipped":
            reason = next((r.get("reason", "") for r in tools_log if r["tool"] == name or r["tool"] == f"sigma:{name}"), "")
            if not present and "not_installed" in reason:
                coverage.append((name, "FAIL", f"skipped not_installed but binary missing in container"))
            else:
                coverage.append((name, "PASS", f"skipped: {reason[:60] or 'legit'} (binary present={present})"))
        else:  # not_dispatched
            if present:
                coverage.append((name, "PASS", "not applicable to localhost target (binary present)"))
            else:
                coverage.append((name, "FAIL", "never dispatched AND binary missing from container (DEAD TOOL)"))
    print("\n=== COVERAGE: registry tool vs exercised/present ===")
    for name, verdict, note in coverage:
        print(f"  {verdict:<4} {name:<24} {note}")
    coverage_fails = [c for c in coverage if c[1] == "FAIL"]

    # Verdicts — the benchmark must demonstrate the core recon promises:
    verdicts = []
    if sigma_result.get("authenticated"):
        verdicts.append("PASS seeder authenticates DVWA")
    else:
        verdicts.append("FAIL seeder did not authenticate DVWA")
    if sigma_result.get("findings", 0) > 0:
        verdicts.append(f"PASS Sigma CLI validators produced {sigma_result['findings']} finding(s)")
    else:
        verdicts.append("FAIL Sigma CLI validators produced 0 findings")
    for tool in ("nmap", "httpx", "gobuster", "feroxbuster"):
        ent = next((r["entities"] for r in tools_log if r["tool"] == tool), 0)
        verdicts.append(f"{'PASS' if ent > 0 else 'FAIL'} {tool} produced {ent} entitie(s)")
    verdicts.append(
        f"PASS all {len(ALL_TOOLS)} registry tools exercised or present" if not coverage_fails
        else f"FAIL {len(coverage_fails)} dead/broken registry tool(s): {', '.join(c[0] for c in coverage_fails)}"
    )
    print("\n".join(f"  {v}" for v in verdicts))
    return 0 if all(not v.startswith("FAIL") for v in verdicts) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
