"""Apply recon improvement patches (idempotent, asserts every edit)."""

import io
import re
import sys

CHANGES = []


def _read(path):
    """Read with universal newlines; return (text, dominant_newline)."""
    raw = io.open(path, "rb").read()
    nl = "\r\n" if raw.count(b"\r\n") > raw.count(b"\n") - raw.count(b"\r\n") else "\n"
    return raw.decode("utf-8").replace("\r\n", "\n"), nl


def _write(path, text, nl):
    io.open(path, "wb").write(text.replace("\n", nl).encode("utf-8"))


def patch(path, replacements):
    src, nl = _read(path)
    applied = 0
    for old, new in replacements:
        if new in src:
            continue  # already applied (idempotent)
        if src.count(old) != 1:
            print(f"!! MISS/AMBIGUOUS in {path}: {old[:70]!r} (count={src.count(old)})")
            sys.exit(1)
        src = src.replace(old, new)
        applied += 1
    if applied:
        _write(path, src, nl)
        CHANGES.append(path)
    print(f"OK {path} ({applied} new edits)")


# ── 1. .env must beat stale ambient env (same convention AI providers use) ──
patch(
    "backend/core/config.py",
    [("load_dotenv()\n", "load_dotenv(override=True)\n")],
)
patch(
    "backend/main.py",
    [("load_dotenv()\n", "load_dotenv(override=True)\n")],
)

# ── 2. commands.py: native binaries + context-aware dedup ──
patch(
    "backend/tools/recon/commands.py",
    [
        # 2a. paramspider: native binary + skip non-registrable (localhost/IP)
        (
            '            ps_script = self.tool_root / "ParamSpider" / "paramspider.py"\n'
            '            if ps_script.exists() and scope.base_domain:\n'
            "                cmds.append(\n"
            '                    ReconCommand(\n'
            '                        "paramspider",\n'
            '                        "http_browser_intelligence",\n'
            '                        ("python", str(ps_script), "-d", scope.base_domain, "-o", str(raw_dir / "paramspider.txt")),\n'
            '                        raw_dir / "paramspider.txt",\n'
            "                        timeout_seconds=self.timeout,\n"
            '                        parser_hint="urls",\n'
            "                    )\n"
            "                )\n",
            "            if scope.base_domain and self._is_registrable_domain(scope.base_domain):\n"
            "                cmds.append(\n"
            '                    ReconCommand(\n'
            '                        "paramspider",\n'
            '                        "http_browser_intelligence",\n'
            '                        ("paramspider", "-d", scope.base_domain, "-o", str(raw_dir / "paramspider.txt")),\n'
            '                        raw_dir / "paramspider.txt",\n'
            "                        timeout_seconds=self.timeout,\n"
            '                        parser_hint="urls",\n'
            "                    )\n"
            "                )\n",
        ),
        # 2b. linkfinder/secretfinder: native binaries (they ARE in the image)
        (
            '        cmds: list[ReconCommand] = []\n'
            '        lf_script = self.tool_root / "LinkFinder" / "linkfinder.py"\n'
            '        sf_script = self.tool_root / "SecretFinder" / "SecretFinder.py"\n'
            "\n"
            "        # Batch JS files into a single input file\n",
            '        cmds: list[ReconCommand] = []\n'
            "\n"
            "        # Batch JS files into a single input file\n",
        ),
        ("        if lf_script.exists():\n", "        if js_files:\n"),
        (
            '                        ("python", str(lf_script), "-i", js_url, "-o", "cli"),\n',
            '                        ("linkfinder", "-i", js_url, "-o", "cli"),\n',
        ),
        (
            "        if sf_script.exists():\n            for js_url in js_files[:50]:\n",
            "        if js_files:\n            for js_url in js_files[:50]:\n",
        ),
        (
            '                        ("python", str(sf_script), "-i", js_url, "-o", "cli"),\n',
            '                        ("secretfinder", "-i", js_url, "-o", "cli"),\n',
        ),
        # 2c. inql: native binary
        (
            '        # InQL for GraphQL\n'
            '        inql_script = self.tool_root / "inql" / "inql.py"\n'
            "        if inql_script.exists():\n"
            "            for host in live_hosts[:5]:\n"
            '                safe = host.replace("/", "_").replace(":", "_")[:60]\n'
            "                cmds.append(\n"
            '                    ReconCommand(\n'
            '                        "inql",\n'
            '                        "api_reconnaissance",\n'
            '                        ("python", str(inql_script), "-t", f"{host}/graphql", "-o", str(raw_dir / f"inql_{safe}")),\n',
            "        # InQL for GraphQL\n"
            "        if live_hosts:\n"
            "            for host in live_hosts[:5]:\n"
            '                safe = host.replace("/", "_").replace(":", "_")[:60]\n'
            "                cmds.append(\n"
            '                    ReconCommand(\n'
            '                        "inql",\n'
            '                        "api_reconnaissance",\n'
            '                        ("inql", "-t", f"{host}/graphql", "-o", str(raw_dir / f"inql_{safe}")),\n',
        ),
        # 2d. tls_commands signature + skip testssl on HTTP-only lab ports
        (
            "    def tls_commands(self, scope: ReconScope, raw_dir: Path, hosts_file: Path) -> list[ReconCommand]:\n",
            "    def tls_commands(\n        self, scope: ReconScope, raw_dir: Path, hosts_file: Path, explicit_port: int | None = None\n    ) -> list[ReconCommand]:\n",
        ),
        (
            "        if scope.scan_mode == ScanMode.AGGRESSIVE and scope.base_domain:\n",
            "        if (\n            scope.scan_mode == ScanMode.AGGRESSIVE\n            and scope.base_domain\n            and (explicit_port is None or explicit_port == 443)\n        ):\n",
        ),
        # 2e. visual tools: mark requires_chrome so the DAG can skip fast
        (
            '                metadata={\n'
            '                    "note": "Requires Chrome in the recon image; expected-skip otherwise.",\n'
            '                    "json_file": str(raw_dir / "gowitness.jsonl"),\n'
            "                },\n",
            '                metadata={\n'
            '                    "note": "Requires Chrome in the recon image; expected-skip otherwise.",\n'
            '                    "json_file": str(raw_dir / "gowitness.jsonl"),\n'
            '                    "requires_chrome": "1",\n'
            "                },\n",
        ),
        (
            '                metadata={\n'
            '                    "json_file": str(raw_dir / "aquatone" / "aquatone_session.json"),\n'
            '                    "note": "Requires aquatone binary + Chrome; expected-skip otherwise.",\n'
            "                },\n",
            '                metadata={\n'
            '                    "json_file": str(raw_dir / "aquatone" / "aquatone_session.json"),\n'
            '                    "note": "Requires aquatone binary + Chrome; expected-skip otherwise.",\n'
            '                    "requires_chrome": "1",\n'
            "                },\n",
        ),
    ],
)

# ── 3. port_commands: whole-method rewrite (nmap-only for explicit-port labs) ──
# 3a. Repair the def line the first regex run consumed.
cmds_src, cmds_nl = _read("backend/tools/recon/commands.py")
if "    def tls_commands(" not in cmds_src:
    cmds_src = cmds_src.replace(
        "        return cmds\n\n\n        self, scope: ReconScope, raw_dir: Path, hosts_file: Path,",
        "        return cmds\n\n    def tls_commands(\n        self, scope: ReconScope, raw_dir: Path, hosts_file: Path,",
    )
    _write("backend/tools/recon/commands.py", cmds_src, cmds_nl)
    print("OK repaired tls_commands def line")
m = re.search(
    r"    def port_commands\(\n(?:.*?\n)*?        return cmds\n\n(?=    def tls_commands\()",
    cmds_src,
)
if not m:
    print("!! port_commands method bounds not found")
    sys.exit(1)
new_port_method = '''    def port_commands(
        self, scope: ReconScope, raw_dir: Path, hosts_file: Path, explicit_port: int | None = None
    ) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        rps = str(min(scope.max_rps, 1000))
        cmds: list[ReconCommand] = []
        # A single-target lab (e.g. localhost:8888) carries an explicit port:
        # nmap's deep -sV/-sC on that one port is the whole job. naabu's
        # resolver chokes on Docker's host.docker.internal alias and masscan's
        # full-range sweep would burn the entire tool budget for zero extra
        # signal on a one-port lab. Domain targets keep the fast pre-scan ->
        # deep-scan chain (naabu -> masscan -> nmap).
        if explicit_port:
            cmds.append(
                ReconCommand(
                    "nmap",
                    "dns_infrastructure",
                    (
                        "nmap",
                        "-sV",
                        "-sC",
                        "-p",
                        str(explicit_port),
                        "-oX",
                        str(raw_dir / "nmap_scan.xml"),
                        "-iL",
                        str(hosts_file),
                        "--min-rate",
                        rps,
                    ),
                    raw_dir / "nmap.stdout.txt",
                    timeout_seconds=self.timeout * 2,
                    parser_hint="xml",
                    metadata={"xml_file": str(raw_dir / "nmap_scan.xml")},
                )
            )
        else:
            cmds.append(
                ReconCommand(
                    "naabu",
                    "dns_infrastructure",
                    ("naabu", "-l", str(hosts_file), "-top-ports", "1000", "-rate", rps, "-json", "-silent"),
                    raw_dir / "naabu.jsonl",
                    timeout_seconds=self.timeout,
                    parser_hint="jsonl",
                )
            )
            if scope.scan_mode == ScanMode.AGGRESSIVE:
                cmds.append(
                    ReconCommand(
                        "masscan",
                        "dns_infrastructure",
                        (
                            "masscan",
                            "-iL",
                            str(hosts_file),
                            "-p",
                            "1-65535",
                            "--rate",
                            rps,
                            "-oJ",
                            str(raw_dir / "masscan.json"),
                        ),
                        raw_dir / "masscan.stdout.txt",
                        timeout_seconds=self.timeout * 2,
                        parser_hint="json",
                        metadata={
                            "json_file": str(raw_dir / "masscan.json"),
                            "note": "Requires raw-socket privileges; safe to skip without them.",
                        },
                    )
                )
                cmds.append(
                    ReconCommand(
                        "nmap",
                        "dns_infrastructure",
                        (
                            "nmap",
                            "-sV",
                            "-sC",
                            "--top-ports",
                            "1000",
                            "-oX",
                            str(raw_dir / "nmap_scan.xml"),
                            "-iL",
                            str(hosts_file),
                            "--min-rate",
                            rps,
                        ),
                        raw_dir / "nmap.stdout.txt",
                        timeout_seconds=self.timeout * 2,
                        parser_hint="xml",
                        metadata={"xml_file": str(raw_dir / "nmap_scan.xml")},
                    )
                )
        return cmds

'''
cmds_src = cmds_src[: m.start()] + new_port_method + cmds_src[m.end() :]
_write("backend/tools/recon/commands.py", cmds_src, cmds_nl)
print("OK backend/tools/recon/commands.py (port_commands rewrite)")
CHANGES.append("backend/tools/recon/commands.py")

# ── 4. alpha_orchestrator.py: chrome helper + dedup + js wiring ──
orch_src, orch_nl = _read("backend/agents/alpha_recon/alpha_orchestrator.py")

# 4a. module-level chrome probe helper (before the first class def)
m = re.search(r"\nclass \w+", orch_src)
if not m:
    print("!! orchestrator class not found")
    sys.exit(1)
helper = '''

@functools.lru_cache(maxsize=1)
def _container_has_chrome() -> bool | None:
    """True when the recon container ships a chrome-family browser (cached).

    None = unknown (no container or probe failed) — callers then let the tool
    try rather than pre-emptively skipping it.
    """
    try:
        import subprocess as _sp

        from backend.tools.recon.docker_runtime import running_recon_container

        c = running_recon_container()
        if not c:
            return None
        p = _sp.run(
            [
                "docker", "exec", c, "sh", "-lc",
                "command -v google-chrome chromium chromium-browser >/dev/null 2>&1 && echo yes",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return p.returncode == 0 and "yes" in (p.stdout or "")
    except Exception:
        return None


'''
if "_container_has_chrome" not in orch_src:
    orch_src = orch_src[: m.start()] + "\nimport functools\n" + helper + orch_src[m.start() :]

# 4b. dedup + chrome gate inside _run_and_parse
anchor_old = """        if not available:
            return all_parsed

        # 2. Phase-local dependency edges: a dependency on a tool NOT in this
"""
anchor_new = """        if not available:
            return all_parsed

        # 2a. De-duplicate redundant tools (availability-aware keep-first-N).
        #     Same-group tools issue the SAME kind of requests; running all of
        #     them floods the target and burns budget for near-zero extra
        #     signal. Keep order is data-driven from the DVWA benchmark
        #     (e.g. gobuster out-produces ffuf on 302-redirecting apps).
        _dedupe_specs = (
            ("http_probe", ("httpx", "httprobe"), 1),  # httpx is a superset of httprobe
            ("crawler", ("katana", "gospider", "hakrawler"), 2),  # hakrawler is the weakest
            ("dir_fuzz", ("feroxbuster", "gobuster", "ffuf", "dirsearch"), 2),
        )
        _present = {c.tool_name for c in available}
        _keep: set[str] = set()
        for _group, _members, _n in _dedupe_specs:
            _keep.update([mm for mm in _members if mm in _present][:_n])
        _by_group = {mm: g for g, mms, _nn in _dedupe_specs for mm in mms}
        for _c in available[:]:
            if _c.tool_name in _keep or _c.tool_name not in _by_group:
                continue
            _grp = _by_group[_c.tool_name]
            tools_skipped.append(ToolSkip(name=_c.tool_name, phase=_c.phase, reason=f"dedupe:{_grp}"))
            phase_result.tools_skipped.append(ToolSkip(name=_c.tool_name, phase=_c.phase, reason=f"dedupe:{_grp}"))
            available.remove(_c)
        if not available:
            return all_parsed

        # 2b. Chrome-gated tools (gowitness/aquatone). Skip them fast when the
        #     recon container has no chrome-family browser instead of letting
        #     each tool burn its timeout on a missing executable.
        _has_chrome = _container_has_chrome()
        if _has_chrome is False:
            for _c in available[:]:
                if _c.metadata.get("requires_chrome"):
                    tools_skipped.append(ToolSkip(name=_c.tool_name, phase=_c.phase, reason="chrome_missing"))
                    phase_result.tools_skipped.append(
                        ToolSkip(name=_c.tool_name, phase=_c.phase, reason="chrome_missing")
                    )
                    available.remove(_c)
            if not available:
                return all_parsed

        # 2. Phase-local dependency edges: a dependency on a tool NOT in this
"""
assert orch_src.count(anchor_old) == 1, "dedup anchor missing"
orch_src = orch_src.replace(anchor_old, anchor_new)

# 4c. wire js_analysis (linkfinder/secretfinder) into the HTTP phase
js_old = """        cmds = planner.http_commands(scope, artifacts.raw_dir, hosts_file, explicit_port=explicit_port)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        # Internal HTTP probe
"""
js_new = """        cmds = planner.http_commands(scope, artifacts.raw_dir, hosts_file, explicit_port=explicit_port)
        parsed = await self._run_and_parse(
            cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
        )
        # JS endpoint analysis (linkfinder/secretfinder): feed the crawlers'
        # discovered .js URLs so the JS tools actually get dispatched (they
        # were previously wired but never called from any phase).
        js_urls: list[str] = []
        for _e in parsed:
            _lab = str(getattr(_e, "label", "") or "")
            if ".js" in _lab.lower() and _lab.startswith("http"):
                js_urls.append(_lab)
            for _k in ("full_url", "url", "src", "label"):
                _v = (getattr(_e, "properties", None) or {}).get(_k, "")
                if isinstance(_v, str) and ".js" in _v.lower() and _v.startswith("http"):
                    js_urls.append(_v)
        js_cmds = planner.js_analysis_commands(scope, artifacts.raw_dir, list(dict.fromkeys(js_urls)))
        if js_cmds:
            parsed += await self._run_and_parse(
                js_cmds, runner, artifacts, rag, scan_id, tools_run, tools_skipped, pr, entities=entities
            )
        # Internal HTTP probe
"""
assert orch_src.count(js_old) == 1, "js wiring anchor missing"
orch_src = orch_src.replace(js_old, js_new)

# 4d. pass explicit_port into tls_commands
tls_call_old = "        cmds += planner.tls_commands(scope, artifacts.raw_dir, hosts_file)\n"
tls_call_new = "        cmds += planner.tls_commands(scope, artifacts.raw_dir, hosts_file, explicit_port=explicit_port)\n"
assert orch_src.count(tls_call_old) == 1, "tls call anchor missing"
orch_src = orch_src.replace(tls_call_old, tls_call_new)

_write("backend/agents/alpha_recon/alpha_orchestrator.py", orch_src, orch_nl)
print("OK backend/agents/alpha_recon/alpha_orchestrator.py (chrome helper, dedup, js wiring, tls port)")
CHANGES.append("backend/agents/alpha_recon/alpha_orchestrator.py")

print("\nALL PATCHES APPLIED:", CHANGES)
