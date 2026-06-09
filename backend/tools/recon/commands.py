"""
Alpha V6 Recon Command Planner — Full Phase Coverage.

Builds phase-gated, scope-aware command plans for ALL recon tools.
Emits argv arrays only — no shell strings reach the runtime.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, List
from pathlib import Path

from backend.agents.alpha_recon.models import ReconScope, ScanMode
from backend.core.config import settings

logger = logging.getLogger("alpha.commands")


@dataclass(frozen=True)
class ReconCommand:
    tool_name: str
    phase: str
    argv: tuple[str, ...]
    output_path: Path
    cwd: Path | None = None
    stdin: str = ""
    timeout_seconds: int = 180
    parser_hint: str = "lines"
    metadata: dict[str, str] = field(default_factory=dict)


    """DAG dependency support for parallel tool execution."""
    depends_on: Optional[List[str]] = None  # DAG dependencies - tool names that must complete first
class ReconCommandPlanner:
    """Builds phase-gated, scope-aware command plans for Alpha recon tools."""

    def __init__(self, tool_root: str | Path | None = None) -> None:
        self.tool_root = Path(tool_root or getattr(settings, "ALPHA_TOOL_ROOT", r"D:\projects"))
        self.timeout = int(getattr(settings, "ALPHA_TOOL_TIMEOUT_SECONDS", 180))

    # ── Phase 1: Passive Intelligence ──────────────────────────────


    def get_dependency_graph(self):
        """Return the tool dependency graph for DAG execution."""
        return TOOL_DEPENDENCY_GRAPH

    @staticmethod
    def _is_registrable_domain(host: str) -> bool:
        """True only for real registrable domains. Subdomain/OSINT passive tools
        (subfinder, amass, gau, waybackurls, github-subdomains) are meaningless
        against localhost, bare IPs, or single-label hosts — they just burn the
        full per-tool timeout. Skipping them on such targets gets the pipeline to
        the live HTTP + attack phases in seconds instead of minutes."""
        import ipaddress
        h = (host or "").strip().lower()
        if not h or h in ("localhost",):
            return False
        try:
            ipaddress.ip_address(h)
            return False  # bare IP — no subdomains to enumerate
        except ValueError:
            pass
        # Needs at least one dot and a non-numeric TLD (e.g. example.com).
        if "." not in h:
            return False
        if h.endswith(".local") or h.endswith(".internal") or h == "host.docker.internal":
            return False
        return True

    def passive_commands(self, scope: ReconScope, raw_dir: Path) -> list[ReconCommand]:
        d = scope.base_domain
        if not d:
            return []
        # Skip subdomain/OSINT enumeration for non-registrable targets (localhost,
        # IPs, *.local) — there are no subdomains to find and each tool would
        # otherwise stall for the full timeout. HTTP/discovery phases still run.
        if not self._is_registrable_domain(d):
            logger.info("[planner] passive subdomain enumeration skipped for "
                        "non-registrable target '%s' (localhost/IP/internal).", d)
            return []
        cmds = [
            ReconCommand("subfinder", "passive_intelligence",
                ("subfinder", "-d", d, "-all", "-recursive", "-silent", "-json"),
                raw_dir / "subfinder.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
            ReconCommand("amass", "passive_intelligence",
                ("amass", "enum", "-passive", "-d", d, "-src", "-ip", "-json",
                 str(raw_dir / "amass.passive.json")),
                raw_dir / "amass.passive.stdout.txt", timeout_seconds=self.timeout,
                parser_hint="json-file", metadata={"json_file": str(raw_dir / "amass.passive.json")}),
            ReconCommand("assetfinder", "passive_intelligence",
                ("assetfinder", "--subs-only", d),
                raw_dir / "assetfinder.txt", timeout_seconds=self.timeout, parser_hint="lines"),
            ReconCommand("github-subdomains", "passive_intelligence",
                ("github-subdomains", "-d", d, "-raw"),
                raw_dir / "github-subdomains.txt", timeout_seconds=self.timeout, parser_hint="lines",
                metadata={"note": "Requires GITHUB_TOKEN env; safe to skip when unset."}),
            ReconCommand("gau", "passive_intelligence",
                ("gau", "--threads", "5", "--subs", d),
                raw_dir / "gau.urls.txt", timeout_seconds=self.timeout, parser_hint="urls"),
            ReconCommand("waybackurls", "passive_intelligence",
                ("waybackurls",), stdin=f"{d}\n",
                output_path=raw_dir / "wayback.urls.txt",
                timeout_seconds=self.timeout, parser_hint="urls"),
        ]
        if scope.scan_mode in {ScanMode.STANDARD, ScanMode.AGGRESSIVE}:
            cmds.append(ReconCommand("cloudlist", "passive_intelligence",
                ("cloudlist", "-silent"), raw_dir / "cloudlist.txt",
                timeout_seconds=self.timeout, parser_hint="lines",
                metadata={"note": "Requires provider credentials; safe to skip."}))
        if scope.scan_mode == ScanMode.AGGRESSIVE:
            sf_script = self.tool_root / "spiderfoot" / "sf.py"
            if sf_script.exists():
                cmds.append(ReconCommand("spiderfoot", "passive_intelligence",
                    ("python", str(sf_script), "-s", d, "-q", "-o", "json",
                     "-F", "DOMAIN_NAME,EMAILADDR,IP_ADDRESS,INTERNET_NAME"),
                    raw_dir / "spiderfoot.json", timeout_seconds=self.timeout * 2,
                    parser_hint="json",
                    metadata={"note": "OSINT aggregation; passive only."}))
        return cmds

    # ── Phase 2: DNS & Infrastructure ──────────────────────────────

    def dns_commands(self, scope: ReconScope, raw_dir: Path, subdomain_file: Path) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        cmds = [
            ReconCommand("dnsx", "dns_infrastructure",
                ("dnsx", "-l", str(subdomain_file), "-a", "-aaaa", "-cname", "-mx",
                 "-txt", "-ptr", "-ns", "-soa", "-json", "-silent"),
                raw_dir / "dnsx.resolved.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
        ]
        if scope.scan_mode == ScanMode.AGGRESSIVE:
            wl = self.tool_root / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"
            resolvers = self.tool_root / "resolvers.txt"
            if wl.exists():
                cmds.append(ReconCommand("shuffledns", "dns_infrastructure",
                    ("shuffledns", "-d", scope.base_domain, "-w", str(wl),
                     "-r", str(resolvers) if resolvers.exists() else "8.8.8.8,1.1.1.1"),
                    raw_dir / "shuffledns.txt", timeout_seconds=self.timeout, parser_hint="lines"))
                cmds.append(ReconCommand("puredns", "dns_infrastructure",
                    ("puredns", "bruteforce", str(wl), scope.base_domain,
                     "-r", str(resolvers) if resolvers.exists() else "8.8.8.8",
                     "-q", "--write", str(raw_dir / "puredns.txt")),
                    raw_dir / "puredns.txt", timeout_seconds=self.timeout, parser_hint="lines"))
        # cdncheck classifies which resolved hosts sit behind a CDN/WAF so the
        # runtime governor (Zeta) and Beta can avoid wasting budget on edge IPs.
        cmds.append(ReconCommand("cdncheck", "dns_infrastructure",
            ("cdncheck", "-l", str(subdomain_file), "-resp", "-json", "-silent"),
            raw_dir / "cdncheck.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"))
        return cmds

    def port_commands(self, scope: ReconScope, raw_dir: Path, hosts_file: Path) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        rps = str(min(scope.max_rps, 1000))
        cmds = [
            ReconCommand("naabu", "dns_infrastructure",
                ("naabu", "-l", str(hosts_file), "-top-ports", "1000", "-rate", rps,
                 "-json", "-silent"),
                raw_dir / "naabu.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
        ]
        if scope.scan_mode == ScanMode.AGGRESSIVE:
            cmds.append(ReconCommand("masscan", "dns_infrastructure",
                ("masscan", "-iL", str(hosts_file), "-p", "1-65535", "--rate", rps,
                 "-oJ", str(raw_dir / "masscan.json")),
                raw_dir / "masscan.stdout.txt", timeout_seconds=self.timeout * 2,
                parser_hint="json", metadata={"json_file": str(raw_dir / "masscan.json"),
                    "note": "Requires raw-socket privileges; safe to skip without them."}))
            cmds.append(ReconCommand("nmap", "dns_infrastructure",
                ("nmap", "-sV", "-sC", "--top-ports", "1000", "-oX",
                 str(raw_dir / "nmap_scan.xml"), "-iL", str(hosts_file), "--min-rate", rps),
                raw_dir / "nmap.stdout.txt", timeout_seconds=self.timeout * 2, parser_hint="xml",
                metadata={"xml_file": str(raw_dir / "nmap_scan.xml")}))
        return cmds

    def tls_commands(self, scope: ReconScope, raw_dir: Path, hosts_file: Path) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        cmds = [
            ReconCommand("tlsx", "dns_infrastructure",
                ("tlsx", "-l", str(hosts_file), "-san", "-cn", "-so", "-wc",
                 "-ss", "-mm", "-re", "-un", "-json", "-silent"),
                raw_dir / "tlsx.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
        ]
        # testssl.sh does a deep TLS/cipher/vuln audit — aggressive only, one
        # host at a time to stay within budget.
        if scope.scan_mode == ScanMode.AGGRESSIVE and scope.base_domain:
            cmds.append(ReconCommand("testssl", "dns_infrastructure",
                ("testssl.sh", "--jsonfile", str(raw_dir / "testssl.json"),
                 "--quiet", "--color", "0", scope.base_domain),
                raw_dir / "testssl.stdout.txt", timeout_seconds=self.timeout * 2,
                parser_hint="json", metadata={"json_file": str(raw_dir / "testssl.json")}))
        return cmds

    # ── Phase 3: HTTP & Browser Intelligence ──────────────────────

    def http_commands(self, scope: ReconScope, raw_dir: Path, hosts_file: Path) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        cmds = [
            ReconCommand("httprobe", "http_browser_intelligence",
                ("httprobe", "-c", "50", "-p", "https:443", "-p", "http:80"),
                raw_dir / "httprobe.txt", timeout_seconds=self.timeout, parser_hint="lines",
                stdin=self._read_hosts_stdin(hosts_file)),
            ReconCommand("httpx", "http_browser_intelligence",
                ("httpx", "-l", str(hosts_file), "-tech-detect", "-status-code",
                 "-title", "-content-length", "-response-time", "-server",
                 "-content-type", "-location", "-favicon", "-jarm",
                 "-cdn", "-tls-grab", "-json", "-silent",
                 "-rate-limit", str(scope.max_rps)),
                raw_dir / "httpx.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
            ReconCommand("katana", "http_browser_intelligence",
                ("katana", "-list", str(hosts_file), "-js-crawl", "-known-files", "all",
                 "-depth", str(scope.max_depth), "-jsonl", "-silent",
                 "-rate-limit", str(scope.max_rps)),
                raw_dir / "katana.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
            ReconCommand("gospider", "http_browser_intelligence",
                ("gospider", "-S", str(self._build_url_sites_file(hosts_file, raw_dir)),
                 "-d", str(scope.max_depth),
                 "-c", "10", "-t", "5", "--json", "--subs",
                 "--delay", "0", "-q"),
                raw_dir / "gospider.jsonl", timeout_seconds=self.timeout, parser_hint="jsonl"),
            ReconCommand("hakrawler", "http_browser_intelligence",
                ("hakrawler", "-d", str(scope.max_depth), "-subs", "-insecure"),
                raw_dir / "hakrawler.txt", timeout_seconds=self.timeout, parser_hint="lines",
                stdin=f"http://{scope.base_domain}\nhttps://{scope.base_domain}\n"),
        ]
        if scope.scan_mode in {ScanMode.STANDARD, ScanMode.AGGRESSIVE}:
            # wafw00f removed: belongs to Sigma exploitation agent
            # whatweb removed: belongs to Sigma exploitation agent
            cmds.append(ReconCommand("arjun", "http_browser_intelligence",
                ("arjun", "-i", str(hosts_file), "-oJ", str(raw_dir / "arjun.json"),
                 "-t", "10", "--rate-limit", str(scope.max_rps)),
                raw_dir / "arjun.stdout.txt", timeout_seconds=self.timeout,
                parser_hint="json", metadata={"json_file": str(raw_dir / "arjun.json")}))
            ps_script = self.tool_root / "ParamSpider" / "paramspider.py"
            if ps_script.exists() and scope.base_domain:
                cmds.append(ReconCommand("paramspider", "http_browser_intelligence",
                    ("python", str(ps_script), "-d", scope.base_domain,
                     "-o", str(raw_dir / "paramspider.txt")),
                    raw_dir / "paramspider.txt", timeout_seconds=self.timeout, parser_hint="urls"))
        return cmds

    @staticmethod
    def _read_hosts_stdin(hosts_file: Path) -> str:
        """Return the host list as a newline-joined stdin payload (empty if missing)."""
        try:
            if hosts_file.exists():
                return hosts_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.debug("Failed to read hosts file for stdin: %s", e)
        return ""

    @staticmethod
    def _build_url_sites_file(hosts_file: Path, raw_dir: Path) -> Path:
        """Write a sites file of ABSOLUTE URLs for tools that require a scheme.

        gospider's ``-S`` sites file (and similar crawlers) reject bare
        ``host``/``host:port`` entries with "Input must be a valid absolute URL".
        The shared hosts file contains bare hosts, so we derive a sibling file
        where every entry is normalized to ``http(s)://host[:port]``. Lines that
        already carry a scheme are preserved as-is.
        """
        sites = raw_dir / "gospider_sites.txt"
        urls: list[str] = []
        try:
            raw = hosts_file.read_text(encoding="utf-8", errors="replace") if hosts_file.exists() else ""
        except Exception as e:
            logger.debug("Failed to read hosts file: %s", e)
            raw = ""
        for line in raw.splitlines():
            h = line.strip()
            if not h:
                continue
            if h.startswith(("http://", "https://")):
                urls.append(h)
            else:
                urls.append(f"http://{h}")
        sites.parent.mkdir(parents=True, exist_ok=True)
        sites.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
        return sites

    def js_analysis_commands(self, scope: ReconScope, raw_dir: Path, js_files: list[str]) -> list[ReconCommand]:
        """Generate LinkFinder/SecretFinder commands for discovered JS files."""
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not js_files:
            return []
        cmds: list[ReconCommand] = []
        lf_script = self.tool_root / "LinkFinder" / "linkfinder.py"
        sf_script = self.tool_root / "SecretFinder" / "SecretFinder.py"

        # Batch JS files into a single input file
        js_input = raw_dir / "js_urls_for_analysis.txt"
        js_input.parent.mkdir(parents=True, exist_ok=True)
        js_input.write_text("\n".join(js_files[:200]) + "\n", encoding="utf-8")

        if lf_script.exists():
            for js_url in js_files[:50]:  # limit per-file analysis
                safe = js_url.replace("/", "_").replace(":", "_")[:80]
                cmds.append(ReconCommand("linkfinder", "http_browser_intelligence",
                    ("python", str(lf_script), "-i", js_url, "-o", "cli"),
                    raw_dir / f"linkfinder_{safe}.txt", timeout_seconds=60, parser_hint="lines"))
        if sf_script.exists():
            for js_url in js_files[:50]:
                safe = js_url.replace("/", "_").replace(":", "_")[:80]
                cmds.append(ReconCommand("secretfinder", "http_browser_intelligence",
                    ("python", str(sf_script), "-i", js_url, "-o", "cli"),
                    raw_dir / f"secretfinder_{safe}.txt", timeout_seconds=60, parser_hint="lines"))
        return cmds

    # ── Phase 4: Directory & Route Discovery ──────────────────────

    def discovery_commands(self, scope: ReconScope, raw_dir: Path,
                           live_hosts: list[str], wordlist_path: Path | None = None) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not live_hosts:
            return []

        # Default wordlist. Prefer the compact common.txt (~4.7k entries) so a
        # directory sweep finishes within the tool timeout; raft-medium (~30k)
        # blows past the watchdog at the throttled recon rate. AGGRESSIVE mode
        # opts into the larger list.
        if wordlist_path:
            wl = wordlist_path
        else:
            common = self.tool_root / "SecLists" / "Discovery" / "Web-Content" / "common.txt"
            raft = self.tool_root / "SecLists" / "Discovery" / "Web-Content" / "raft-medium-directories.txt"
            if scope.scan_mode == ScanMode.AGGRESSIVE and raft.exists():
                wl = raft
            else:
                wl = common if common.exists() else raft

        # Write live hosts to file
        hosts_file = raw_dir / "live_hosts_for_discovery.txt"
        hosts_file.write_text("\n".join(live_hosts[:100]) + "\n", encoding="utf-8")

        cmds: list[ReconCommand] = []
        rps = str(min(scope.max_rps, 200))
        # Normalize live_hosts to absolute URLs (feroxbuster --stdin requires a
        # scheme; ffuf's -u takes a single URL; gobuster + dirsearch likewise).
        # When the orchestrator already seeded URLs (http://host:port/...) we
        # use them as-is; otherwise prepend http:// to bare host[:port] entries.
        def _to_url(h: str) -> str:
            h = h.strip()
            if not h:
                return ""
            return h if h.startswith(("http://", "https://")) else f"http://{h}"
        url_hosts = [u for u in (_to_url(h) for h in live_hosts) if u]
        if not url_hosts:
            return []

        cmds.append(ReconCommand("feroxbuster", "directory_route_discovery",
            ("feroxbuster", "--stdin", "-w", str(wl), "--json", "--silent",
             "--rate-limit", rps, "--depth", str(min(scope.max_depth, 2)),
             "--auto-tune", "--dont-scan",
             r"\.css$", r"\.js$", r"\.png$", r"\.jpg$", r"\.gif$", r"\.ico$"),
            raw_dir / "feroxbuster.jsonl", timeout_seconds=self.timeout * 2,
            parser_hint="jsonl", stdin="\n".join(url_hosts[:20]) + "\n"))

        cmds.append(ReconCommand("ffuf", "directory_route_discovery",
            ("ffuf", "-w", str(wl), "-u", f"{url_hosts[0]}/FUZZ",
             "-mc", "200,201,204,301,302,307,401,403,405",
             "-rate", rps, "-json", "-o", str(raw_dir / "ffuf_results.json"),
             # Bound the run so ffuf doesn't burn the whole watchdog budget on
             # apps (DVWA) that 302-redirect every path to login.
             "-maxtime", str(min(self.timeout - 10, 90))),
            raw_dir / "ffuf.stdout.txt", timeout_seconds=self.timeout,
            parser_hint="json", metadata={"json_file": str(raw_dir / "ffuf_results.json")}))

        # dirsearch: prefer the installed `dirsearch` binary (present in the
        # recon container as a pipx entry point, and on PATH for local installs).
        # The legacy `python <tool_root>/dirsearch/dirsearch.py` form broke in
        # the container (host script path does not exist there). Run the binary
        # directly so it works identically in Docker and locally. Output uses the
        # modern `-o PATH --format=json` flags (this dirsearch dropped the old
        # `--json-report` option).
        cmds.append(ReconCommand("dirsearch", "directory_route_discovery",
            ("dirsearch", "-u", url_hosts[0], "-e", "php,asp,aspx,jsp,html,js,json",
             "-o", str(raw_dir / "dirsearch.json"), "--format=json", "-q",
             "--max-time", str(min(self.timeout - 10, 60))),
            raw_dir / "dirsearch.stdout.txt", timeout_seconds=self.timeout,
            parser_hint="json", metadata={"json_file": str(raw_dir / "dirsearch.json")}))

        cmds.append(ReconCommand("gobuster", "directory_route_discovery",
            ("gobuster", "dir", "-u", url_hosts[0], "-w", str(wl),
             "-t", "50", "-q", "--no-error",
             # DVWA-style apps redirect every URL to login.php (302 wildcard);
             # without this gobuster aborts immediately. Excluding 302 lets it
             # find pages that genuinely exist (200/403/401).
             "-b", "302,404",
             "--wildcard"),
            raw_dir / "gobuster.txt", timeout_seconds=self.timeout, parser_hint="lines"))

        return cmds

    # ── Phase 5: API & GraphQL Reconnaissance ─────────────────────

    def api_commands(self, scope: ReconScope, raw_dir: Path, live_hosts: list[str]) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not live_hosts:
            return []
        cmds: list[ReconCommand] = []

        # Kiterunner
        kr_routes = self.tool_root / "kiterunner" / "routes-large.kite"
        if not kr_routes.exists():
            kr_routes = self.tool_root / "kiterunner" / "routes-small.kite"
        if kr_routes.exists():
            cmds.append(ReconCommand("kiterunner", "api_reconnaissance",
                ("kr", "brute", live_hosts[0], "-w", str(kr_routes), "--fail-status-codes", "404,400"),
                raw_dir / "kiterunner.txt", timeout_seconds=self.timeout, parser_hint="lines"))

        # InQL for GraphQL
        inql_script = self.tool_root / "inql" / "inql.py"
        if inql_script.exists():
            for host in live_hosts[:5]:
                safe = host.replace("/", "_").replace(":", "_")[:60]
                cmds.append(ReconCommand("inql", "api_reconnaissance",
                    ("python", str(inql_script), "-t", f"{host}/graphql", "-o", str(raw_dir / f"inql_{safe}")),
                    raw_dir / f"inql_{safe}.stdout.txt", timeout_seconds=60, parser_hint="json"))
        return cmds

    # ── Phase 6: Visual Documentation ─────────────────────────────

    def visual_commands(self, scope: ReconScope, raw_dir: Path, live_hosts: list[str]) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not live_hosts:
            return []
        hosts_file = raw_dir / "live_hosts_for_screenshots.txt"
        hosts_file.write_text("\n".join(live_hosts[:100]) + "\n", encoding="utf-8")
        cmds: list[ReconCommand] = []
        # gowitness v3 uses `scan file --write-jsonl --write-jsonl-file`. The
        # bundled recon image does not ship Chrome, so this command will fail
        # with "google-chrome: executable file not found in $PATH" — the runner
        # logs it and the parser correctly returns 0 entities. Keeping the
        # command in the plan documents the intent; install Chrome in the image
        # to enable real screenshots.
        cmds.append(ReconCommand("gowitness", "visual_documentation",
            ("gowitness", "scan", "file", "-f", str(hosts_file),
             "--write-jsonl", "--write-jsonl-file", str(raw_dir / "gowitness.jsonl"),
             "-s", str(raw_dir / "screenshots"), "--quiet", "-t", "2", "-T", "10"),
            raw_dir / "gowitness.jsonl", timeout_seconds=self.timeout,
            parser_hint="jsonl",
            metadata={"note": "Requires Chrome in the recon image; expected-skip otherwise.",
                      "json_file": str(raw_dir / "gowitness.jsonl")}))
        # aquatone consumes the same host list over stdin and produces a visual
        # cluster report + screenshots (complementary to gowitness). The recon
        # image does not currently package aquatone — the runner logs the skip.
        cmds.append(ReconCommand("aquatone", "visual_documentation",
            ("aquatone", "-out", str(raw_dir / "aquatone"), "-silent"),
            raw_dir / "aquatone" / "aquatone_session.json", timeout_seconds=self.timeout,
            parser_hint="json", stdin=self._read_hosts_stdin(hosts_file),
            metadata={"json_file": str(raw_dir / "aquatone" / "aquatone_session.json"),
                      "note": "Requires aquatone binary + Chrome; expected-skip otherwise."}))
        return cmds

    # ── Phase 7: Template Validation ──────────────────────────────

    def validation_commands(self, scope: ReconScope, raw_dir: Path,
                             live_hosts: list[str], interactsh_url: str = "") -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not live_hosts:
            return []
        hosts_file = raw_dir / "live_hosts_for_nuclei.txt"
        hosts_file.write_text("\n".join(live_hosts[:200]) + "\n", encoding="utf-8")

        cmds: list[ReconCommand] = []
        nuclei_args = [
            "nuclei", "-l", str(hosts_file), "-severity", "critical,high,medium",
            "-rate-limit", str(min(scope.max_rps, 100)), "-jsonl", "-silent",
            "-bulk-size", "25", "-concurrency", "10",
        ]
        if interactsh_url:
            nuclei_args.extend(["-iserver", interactsh_url])

        cmds.append(ReconCommand("nuclei", "template_validation",
            tuple(nuclei_args), raw_dir / "nuclei.jsonl",
            timeout_seconds=self.timeout * 3, parser_hint="jsonl"))

        # dalfox does focused, scope-bound XSS validation on URLs that carry
        # parameters (aggressive only — it actively probes reflected/DOM XSS).
# dalfox removed: belongs to Sigma exploitation agent
        return cmds

    def interactsh_commands(self, raw_dir: Path) -> list[ReconCommand]:
        """Start interactsh-client for OOB detection."""
        return [
            ReconCommand("interactsh", "template_validation",
                ("interactsh-client", "-json", "-o", str(raw_dir / "interactsh.jsonl"),
                 "-poll-interval", "5", "-n", "1"),
                raw_dir / "interactsh.jsonl", timeout_seconds=self.timeout * 3,
                parser_hint="jsonl"),
        ]


# =============================================
# TOOL DEPENDENCY GRAPH for DAG execution
# =============================================
# Maps tool name -> list of tool names that must complete first.
# Used by TaskGraph.execute_dag() for parallel execution.
#
# KEY INSIGHT: Tools start as soon as their dependencies finish,
# not when the entire phase finishes. This saves 15-30s per scan.
#
# EXAMPLE TIMELINE:
# Current: subfinder(5s) -> wait -> amass(60s) -> ALL DONE -> dnsx(10s)
# DAG:     subfinder(5s) -> dnsx(10s)
#          amass(60s) ----------------------------------------> (parallel)

TOOL_DEPENDENCY_GRAPH = {
    # STAGE 1: Passive Intelligence (no dependencies - fire immediately)
    "subfinder": [],
    "amass": [],
    "assetfinder": [],
    "github-subdomains": [],
    "gau": [],
    "waybackurls": [],
    "cloudlist": [],
    "spiderfoot": [],

    # STAGE 2: DNS & Infrastructure (depends on passive subdomain tools)
    "dnsx": ["subfinder", "amass"],  # Needs subdomains to resolve
    "shuffledns": ["subfinder", "amass"],  # Needs subdomains for DNS mass resolution
    "puredns": ["subfinder", "amass"],  # Alternative to shuffledns
    "cdncheck": ["dnsx"],  # Needs resolved IPs to check CDN

    # STAGE 2b: Port Scanning (depends on DNS resolution)
    "naabu": ["dnsx"],  # Needs resolved hosts
    "masscan": ["dnsx"],  # Fast port scan on resolved hosts
    "nmap": ["masscan"],  # Deep scan on masscan-discovered ports

    # STAGE 2c: TLS Analysis (depends on DNS resolution)
    "tlsx": ["dnsx"],  # TLS cert info on resolved hosts
    "testssl": ["nmap"],  # Deep TLS test on nmap-discovered ports

    # STAGE 3: HTTP & Browser Intelligence (depends on DNS + ports)
    "httprobe": ["dnsx"],  # Check which DNS results are web servers
    "httpx": ["dnsx"],  # Tech detection, status codes on live hosts
    "katana": ["httpx"],  # Crawl live HTTP endpoints
    "gospider": ["httpx"],  # Spider live HTTP endpoints
    "hakrawler": ["httpx"],  # Crawl for hidden endpoints
    "arjun": ["httpx"],  # Find hidden parameters on endpoints
    "paramspider": ["httpx"],  # Extract parameters from URLs

    # STAGE 3b: JavaScript Analysis (depends on HTTP crawl)
    "linkfinder": ["katana", "gospider"],  # Find JS links from crawled pages
    "secretfinder": ["linkfinder"],  # Find secrets in JS files

    # STAGE 4: Directory & Route Discovery (depends on HTTP)
    "feroxbuster": ["httpx"],  # Directory brute-force on live hosts
    "ffuf": ["httpx"],  # Fast directory brute-force
    "dirsearch": ["httpx"],  # Directory discovery
    "gobuster": ["httpx"],  # Directory/file brute-force

    # STAGE 4b: API Reconnaissance (depends on HTTP)
    "kiterunner": ["httpx"],  # API route discovery
    "inql": ["httpx"],  # GraphQL introspection

    # STAGE 4c: Visual Documentation (depends on HTTP)
    "gowitness": ["httpx"],  # Screenshot live hosts
    "aquatone": ["httpx"],  # Visual inspection of web targets

    # STAGE 5: Validation (depends on all prior stages)
    "nuclei": ["httpx"],  # Scans URLs from httpx, not ffuf dirs  # Template-based vuln scanning on endpoints
    "interactsh": ["httpx"],  # OOB server runs alongside nuclei  # OOB vulnerability detection
}
