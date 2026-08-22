"""
Alpha V6 Recon Command Planner — Full Phase Coverage.

Builds phase-gated, scope-aware command plans for ALL recon tools.
Emits argv arrays only — no shell strings reach the runtime.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
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
    timeout_seconds: int = 3600
    parser_hint: str = "lines"
    metadata: dict[str, str] = field(default_factory=dict)

    """DAG dependency support for parallel tool execution."""
    depends_on: list[str] | None = None  # DAG dependencies - tool names that must complete first


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
        return not (h.endswith(".local") or h.endswith(".internal") or h == "host.docker.internal")

    def passive_commands(self, scope: ReconScope, raw_dir: Path) -> list[ReconCommand]:
        d = scope.base_domain
        if not d:
            return []
        # Skip subdomain/OSINT enumeration for non-registrable targets (localhost,
        # IPs, *.local) — there are no subdomains to find and each tool would
        # otherwise stall for the full timeout. HTTP/discovery phases still run.
        if not self._is_registrable_domain(d):
            logger.info(
                "[planner] passive subdomain enumeration skipped for "
                "non-registrable target '%s' (localhost/IP/internal).",
                d,
            )
            return []
        cmds = [
            ReconCommand(
                "subfinder",
                "passive_intelligence",
                ("subfinder", "-d", d, "-all", "-recursive", "-silent", "-json"),
                raw_dir / "subfinder.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            ),
            ReconCommand(
                "amass",
                "passive_intelligence",
                ("amass", "enum", "-passive", "-d", d, "-src", "-ip", "-json", str(raw_dir / "amass.passive.json")),
                raw_dir / "amass.passive.stdout.txt",
                timeout_seconds=self.timeout,
                parser_hint="json-file",
                metadata={"json_file": str(raw_dir / "amass.passive.json")},
            ),
            ReconCommand(
                "assetfinder",
                "passive_intelligence",
                ("assetfinder", "--subs-only", d),
                raw_dir / "assetfinder.txt",
                timeout_seconds=self.timeout,
                parser_hint="lines",
            ),
            ReconCommand(
                "github-subdomains",
                "passive_intelligence",
                ("github-subdomains", "-d", d, "-raw"),
                raw_dir / "github-subdomains.txt",
                timeout_seconds=self.timeout,
                parser_hint="lines",
                metadata={"note": "Requires GITHUB_TOKEN env; safe to skip when unset."},
            ),
            ReconCommand(
                "gau",
                "passive_intelligence",
                ("gau", "--threads", "5", "--subs", d),
                raw_dir / "gau.urls.txt",
                timeout_seconds=self.timeout,
                parser_hint="urls",
            ),
            ReconCommand(
                "waybackurls",
                "passive_intelligence",
                ("waybackurls",),
                stdin=f"{d}\n",
                output_path=raw_dir / "wayback.urls.txt",
                timeout_seconds=self.timeout,
                parser_hint="urls",
            ),
        ]
        if scope.scan_mode in {ScanMode.STANDARD, ScanMode.AGGRESSIVE}:
            cmds.append(
                ReconCommand(
                    "cloudlist",
                    "passive_intelligence",
                    ("cloudlist", "-silent"),
                    raw_dir / "cloudlist.txt",
                    timeout_seconds=self.timeout,
                    parser_hint="lines",
                    metadata={"note": "Requires provider credentials; safe to skip."},
                )
            )
        if scope.scan_mode == ScanMode.AGGRESSIVE:
            # SpiderFoot ships as a `spiderfoot` console-script in the recon
            # image (the `python <tool_root>/spiderfoot/sf.py` form used a HOST
            # path that does not exist inside the container). Use the binary
            # directly so it runs identically in Docker and locally. The scan is
            # bounded to a small passive module set + strict type filter so the
            # OSINT aggregation finishes inside the watchdog instead of stalling
            # the whole phase on internet lookups.
            cmds.append(
                ReconCommand(
                    "spiderfoot",
                    "passive_intelligence",
                    (
                        "spiderfoot",
                        "-s",
                        d,
                        "-q",
                        "-m",
                        "sfp_dnsresolve,sfp_whois,sfp_dnsbrute,sfp_crt,sfp_robots,sfp_ahrefs",
                        "-o",
                        "json",
                        "-F",
                        "DOMAIN_NAME,EMAILADDR,IP_ADDRESS,INTERNET_NAME",
                    ),
                    raw_dir / "spiderfoot.json",
                    timeout_seconds=min(self.timeout * 2, 240),
                    parser_hint="json",
                    metadata={"note": "Bounded passive OSINT aggregation."},
                )
            )
        return cmds

    # ── Phase 2: DNS & Infrastructure ──────────────────────────────

    def dns_commands(self, scope: ReconScope, raw_dir: Path, subdomain_file: Path) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        cmds = [
            ReconCommand(
                "dnsx",
                "dns_infrastructure",
                (
                    "dnsx",
                    "-l",
                    str(subdomain_file),
                    "-a",
                    "-aaaa",
                    "-cname",
                    "-mx",
                    "-txt",
                    "-ptr",
                    "-ns",
                    "-soa",
                    "-json",
                    "-silent",
                    # Explicit local resolver: the recon container firewalls
                    # UDP egress, so dnsx's built-in UDP resolvers time out.
                    # 127.0.0.1 is the container-local unbound TCP forwarder.
                    "-r",
                    "127.0.0.1",
                ),
                raw_dir / "dnsx.resolved.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            ),
        ]
        # AGGRESSIVE: active DNS bruteforce. puredns is the single canonical
        # massdns wrapper (shuffledns was removed — same job, dead without
        # massdns). Requires the massdns binary in the recon image.
        if scope.scan_mode == ScanMode.AGGRESSIVE:
            wl = self.tool_root / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"
            resolvers = self.tool_root / "resolvers.txt"
            if not resolvers.exists():
                # Container-local unbound TCP forwarder (UDP egress firewalled).
                # puredns -r expects a FILE, not a bare IP — write one.
                resolvers = raw_dir / "puredns.resolvers.txt"
                resolvers.write_text("127.0.0.1\n", encoding="utf-8")
            if wl.exists():
                cmds.append(
                    ReconCommand(
                        "puredns",
                        "dns_infrastructure",
                        (
                            "puredns",
                            "bruteforce",
                            str(wl),
                            scope.base_domain,
                            "-r",
                            str(resolvers),
                            # Validation pass needs the same reachable resolver:
                            # puredns's built-in trusted list hits UDP-blocked
                            # public DNS and fails validation in the container.
                            "--resolvers-trusted",
                            str(resolvers),
                            "-q",
                            "--write",
                            str(raw_dir / "puredns.txt"),
                        ),
                        raw_dir / "puredns.txt",
                        timeout_seconds=self.timeout,
                        parser_hint="lines",
                    )
                )
        # cdncheck classifies which resolved hosts sit behind a CDN/WAF so the
        # runtime governor (Zeta) and Beta can avoid wasting budget on edge IPs.
        cmds.append(
            ReconCommand(
                "cdncheck",
                "dns_infrastructure",
                # NOTE: `-json` was removed from this cdncheck build — the JSONL
                # flag is `-j`. The parser (parse_cdncheck_jsonl) reads JSONL.
                ("cdncheck", "-l", str(subdomain_file), "-resp", "-j", "-silent"),
                raw_dir / "cdncheck.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            )
        )
        return cmds

    def port_commands(
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

    def tls_commands(
        self, scope: ReconScope, raw_dir: Path, hosts_file: Path, explicit_port: int | None = None
    ) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        cmds = [
            ReconCommand(
                "tlsx",
                "dns_infrastructure",
                (
                    "tlsx",
                    "-l",
                    str(hosts_file),
                    "-san",
                    "-cn",
                    "-so",
                    "-wc",
                    "-ss",
                    "-mm",
                    "-re",
                    "-un",
                    "-json",
                    "-silent",
                ),
                raw_dir / "tlsx.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            ),
        ]
        # testssl.sh does a deep TLS/cipher/vuln audit — aggressive only, one
        # host at a time to stay within budget.
        if (
            scope.scan_mode == ScanMode.AGGRESSIVE
            and scope.base_domain
            and (explicit_port is None or explicit_port == 443)
        ):
            cmds.append(
                ReconCommand(
                    "testssl",
                    "dns_infrastructure",
                    (
                        "testssl.sh",
                        "--jsonfile",
                        str(raw_dir / "testssl.json"),
                        "--quiet",
                        "--color",
                        "0",
                        scope.base_domain,
                    ),
                    raw_dir / "testssl.stdout.txt",
                    timeout_seconds=self.timeout * 2,
                    parser_hint="json",
                    metadata={"json_file": str(raw_dir / "testssl.json")},
                )
            )
        return cmds

    # ── Phase 3: HTTP & Browser Intelligence ──────────────────────

    def http_commands(
        self, scope: ReconScope, raw_dir: Path, hosts_file: Path, explicit_port: int | None = None, cookie: str = ""
    ) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return []
        # Auth-aware crawl: when the seeder already authenticated (auth-first
        # ordering), forward the Cookie so katana/gospider see the real app
        # instead of the 302-to-login wall.
        _h = ("-H", f"Cookie: {cookie}") if cookie else ()
        cmds = [
            ReconCommand(
                "httpx",
                "http_browser_intelligence",
                (
                    "httpx",
                    "-l",
                    str(hosts_file),
                    "-tech-detect",
                    "-status-code",
                    "-title",
                    "-content-length",
                    "-response-time",
                    "-server",
                    "-content-type",
                    "-location",
                    "-favicon",
                    "-jarm",
                    "-cdn",
                    "-tls-grab",
                    "-json",
                    "-silent",
                    "-rate-limit",
                    str(scope.max_rps),
                    *_h,
                ),
                raw_dir / "httpx.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            ),
            ReconCommand(
                "katana",
                "http_browser_intelligence",
                (
                    "katana",
                    "-list",
                    str(hosts_file),
                    "-js-crawl",
                    "-known-files",
                    "all",
                    "-depth",
                    str(scope.max_depth),
                    "-jsonl",
                    "-silent",
                    "-rate-limit",
                    str(scope.max_rps),
                    *_h,
                ),
                raw_dir / "katana.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            ),
            ReconCommand(
                "gospider",
                "http_browser_intelligence",
                (
                    "gospider",
                    "-S",
                    str(self._build_url_sites_file(hosts_file, raw_dir)),
                    "-d",
                    str(scope.max_depth),
                    "-c",
                    "10",
                    "-t",
                    "5",
                    "--json",
                    "--subs",
                    "--delay",
                    "0",
                    "-q",
                    *_h,
                ),
                raw_dir / "gospider.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
            ),
        ]
        if scope.scan_mode in {ScanMode.STANDARD, ScanMode.AGGRESSIVE}:
            # wafw00f removed: belongs to Sigma exploitation agent
            # whatweb removed: belongs to Sigma exploitation agent
            # arjun's `-i` reads a list of TARGET URLs — bare `host`/`host:port`
            # lines make it crash (`TypeError: 'NoneType' object is not
            # iterable`). Feed the derived ABSOLUTE-URL sites file instead.
            arjun_targets = self._build_url_sites_file(hosts_file, raw_dir)
            cmds.append(
                ReconCommand(
                    "arjun",
                    "http_browser_intelligence",
                    (
                        "arjun",
                        "-i",
                        str(arjun_targets),
                        "-oJ",
                        str(raw_dir / "arjun.json"),
                        "-t",
                        "10",
                        "--rate-limit",
                        str(scope.max_rps),
                    ),
                    raw_dir / "arjun.stdout.txt",
                    timeout_seconds=self.timeout,
                    parser_hint="json",
                    metadata={"json_file": str(raw_dir / "arjun.json")},
                )
            )
            if scope.base_domain and self._is_registrable_domain(scope.base_domain):
                cmds.append(
                    ReconCommand(
                        "paramspider",
                        "http_browser_intelligence",
                        # ParamSpider's current CLI dropped `-o`; `-s` streams
                        # URLs to stdout, which the governed runner captures
                        # into output_path (parser_hint="urls" reads it).
                        ("paramspider", "-d", scope.base_domain, "-s"),
                        raw_dir / "paramspider.txt",
                        timeout_seconds=self.timeout,
                        parser_hint="urls",
                    )
                )
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

        # Batch JS files into a single input file
        js_input = raw_dir / "js_urls_for_analysis.txt"
        js_input.parent.mkdir(parents=True, exist_ok=True)
        js_input.write_text("\n".join(js_files[:200]) + "\n", encoding="utf-8")

        if js_files:
            for js_url in js_files[:50]:  # limit per-file analysis
                safe = js_url.replace("/", "_").replace(":", "_")[:80]
                cmds.append(
                    ReconCommand(
                        "linkfinder",
                        "http_browser_intelligence",
                        ("linkfinder", "-i", js_url, "-o", "cli"),
                        raw_dir / f"linkfinder_{safe}.txt",
                        timeout_seconds=60,
                        parser_hint="lines",
                    )
                )
        if js_files:
            for js_url in js_files[:50]:
                safe = js_url.replace("/", "_").replace(":", "_")[:80]
                cmds.append(
                    ReconCommand(
                        "secretfinder",
                        "http_browser_intelligence",
                        ("secretfinder", "-i", js_url, "-o", "cli"),
                        raw_dir / f"secretfinder_{safe}.txt",
                        timeout_seconds=60,
                        parser_hint="lines",
                    )
                )
        return cmds

    # ── Phase 4: Directory & Route Discovery ──────────────────────

    def discovery_commands(
        self,
        scope: ReconScope,
        raw_dir: Path,
        live_hosts: list[str],
        wordlist_path: Path | None = None,
        cookie: str = "",
    ) -> list[ReconCommand]:
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
        # scheme; ffuf's -u takes a single URL; gobuster likewise).
        def _to_url(h: str) -> str:
            h = h.strip()
            if not h:
                return ""
            return h if h.startswith(("http://", "https://")) else f"http://{h}"

        url_hosts = [u for u in (_to_url(h) for h in live_hosts) if u]
        if not url_hosts:
            return []

        # Auth-forwarding header for the content fuzzers (auth-first ordering):
        # the seeder's Cookie lets them see the real app instead of the
        # 302-to-login wall on login-gated targets.
        _h = ("-H", f"Cookie: {cookie}") if cookie else ()

        cmds.append(
            ReconCommand(
                "feroxbuster",
                "directory_route_discovery",
                (
                    "feroxbuster",
                    "--stdin",
                    "-w",
                    str(wl),
                    "--json",
                    "--silent",
                    "--rate-limit",
                    rps,
                    "--depth",
                    str(min(scope.max_depth, 2)),
                    # NOTE: --auto-tune deliberately omitted. On redirect-heavy
                    # apps (DVWA-style: every unauthenticated path 302s to
                    # login) feroxbuster's wildcard-detection heuristic can
                    # decide the whole site is a wildcard and filter EVERY
                    # result, producing a 0-entity run on an otherwise healthy
                    # target. Plain scan + explicit status filtering is
                    # deterministic (probe-verified 37/37/37 on DVWA).
                    "--dont-scan",
                    r"\.css$",
                    r"\.js$",
                    r"\.png$",
                    r"\.jpg$",
                    r"\.gif$",
                    r"\.ico$",
                    *_h,
                ),
                raw_dir / "feroxbuster.jsonl",
                timeout_seconds=self.timeout * 2,
                parser_hint="jsonl",
                stdin="\n".join(url_hosts[:20]) + "\n",
            )
        )

        cmds.append(
            ReconCommand(
                "ffuf",
                "directory_route_discovery",
                (
                    "ffuf",
                    "-w",
                    str(wl),
                    "-u",
                    f"{url_hosts[0]}/FUZZ",
                    "-mc",
                    "200,201,204,301,302,307,401,403,405",
                    "-rate",
                    rps,
                    "-json",
                    "-o",
                    str(raw_dir / "ffuf_results.json"),
                    # Bound the run so ffuf doesn't burn the whole watchdog budget on
                    # apps (DVWA) that 302-redirect every path to login.
                    "-maxtime",
                    str(min(self.timeout - 10, 90)),
                    *_h,
                ),
                raw_dir / "ffuf.stdout.txt",
                timeout_seconds=self.timeout,
                parser_hint="json",
                metadata={"json_file": str(raw_dir / "ffuf_results.json")},
            )
        )

        cmds.append(
            ReconCommand(
                "gobuster",
                "directory_route_discovery",
                (
                    "gobuster",
                    "dir",
                    "-u",
                    url_hosts[0],
                    "-w",
                    str(wl),
                    "-t",
                    "50",
                    "-q",
                    "--no-error",
                    # DVWA-style apps redirect every URL to login.php (302 wildcard);
                    # excluding 302 lets gobuster find pages that genuinely exist
                    # (200/403/401). NOTE: `--wildcard` was dropped — the bundled
                    # gobuster rejects it ("flag provided but not defined"), which
                    # made the tool print usage help as "results".
                    "-b",
                    "302,404",
                    *_h,
                ),
                raw_dir / "gobuster.txt",
                timeout_seconds=self.timeout,
                parser_hint="lines",
            )
        )

        # Virtual-host fuzzing (AGGRESSIVE only, registrable domain targets).
        # The scoped domain's subdomains live on shared infrastructure; vhost
        # discovery finds internal/staging apps that never got a DNS record.
        # ffuf brute-forces the Host header against a small vhost wordlist.
        if (
            scope.scan_mode == ScanMode.AGGRESSIVE
            and scope.base_domain
            and self._is_registrable_domain(scope.base_domain)
        ):
            vhost_wl = self.tool_root / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"
            if vhost_wl.exists():
                cmds.append(
                    ReconCommand(
                        "ffuf_vhost",
                        "directory_route_discovery",
                        (
                            "ffuf",
                            "-w",
                            str(vhost_wl),
                            "-u",
                            url_hosts[0],
                            "-H",
                            f"Host: FUZZ.{scope.base_domain}",
                            "-mc",
                            "200,301,302,401,403",
                            "-fs",
                            "0",
                            "-rate",
                            rps,
                            "-t",
                            "20",
                            "-json",
                            "-o",
                            str(raw_dir / "ffuf_vhost_results.json"),
                            "-maxtime",
                            "45",
                        ),
                        raw_dir / "ffuf_vhost.stdout.txt",
                        timeout_seconds=self.timeout,
                        parser_hint="json",
                        metadata={"json_file": str(raw_dir / "ffuf_vhost_results.json")},
                    )
                )

        return cmds

    # ── Phase 5: API & GraphQL Reconnaissance ─────────────────────

    def api_commands(self, scope: ReconScope, raw_dir: Path, live_hosts: list[str]) -> list[ReconCommand]:
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not live_hosts:
            return []
        cmds: list[ReconCommand] = []

        # Kiterunner — API/content route discovery. The packaged
        # routes-*.kite files are NOT present in the recon image or the host
        # tool root, so the planner synthesizes a compact plain-text route
        # wordlist (kr `brute` accepts plain wordlists) covering common API and
        # admin paths. This keeps the tool genuinely usable instead of silently
        # skipped forever.
        kr_routes = self.tool_root / "kiterunner" / "routes-large.kite"
        if not kr_routes.exists():
            kr_routes = self.tool_root / "kiterunner" / "routes-small.kite"
        if kr_routes.exists():
            cmds.append(
                ReconCommand(
                    "kiterunner",
                    "api_reconnaissance",
                    ("kr", "brute", live_hosts[0], "-w", str(kr_routes), "--fail-status-codes", "404,400"),
                    raw_dir / "kiterunner.txt",
                    timeout_seconds=self.timeout,
                    parser_hint="lines",
                )
            )
        else:
            kr_wl = raw_dir / "kiterunner_routes.txt"
            kr_wl.parent.mkdir(parents=True, exist_ok=True)
            _api_routes = (
                "/api", "/api/v1", "/api/v2", "/api/health", "/api/status", "/api/users", "/api/auth",
                "/api/login", "/api/token", "/api/config", "/graphql", "/rest", "/rest/v1", "/v1", "/v2",
                "/admin", "/admin/login", "/admin/api", "/dashboard", "/swagger", "/swagger.json",
                "/openapi.json", "/api-docs", "/docs", "/redoc", "/graphiql", "/user", "/users", "/account",
                "/login", "/logout", "/register", "/oauth", "/callback", "/webhooks", "/health", "/status",
                "/metrics", "/debug", "/actuator", "/actuator/health", "/config.json", "/.env", "/robots.txt",
            )
            kr_wl.write_text("\n".join(_api_routes) + "\n", encoding="utf-8")
            cmds.append(
                ReconCommand(
                    "kiterunner",
                    "api_reconnaissance",
                    ("kr", "brute", live_hosts[0], "-w", str(kr_wl), "-q"),
                    raw_dir / "kiterunner.txt",
                    timeout_seconds=min(self.timeout, 120),
                    parser_hint="lines",
                )
            )

        # InQL for GraphQL
        if live_hosts:
            for host in live_hosts[:5]:
                safe = host.replace("/", "_").replace(":", "_")[:60]
                cmds.append(
                    ReconCommand(
                        "inql",
                        "api_reconnaissance",
                        ("inql", "-t", f"{host}/graphql", "-o", str(raw_dir / f"inql_{safe}")),
                        raw_dir / f"inql_{safe}.stdout.txt",
                        timeout_seconds=60,
                        parser_hint="json",
                    )
                )
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
        cmds.append(
            ReconCommand(
                "gowitness",
                "visual_documentation",
                (
                    "gowitness",
                    "scan",
                    "file",
                    "-f",
                    str(hosts_file),
                    "--write-jsonl",
                    "--write-jsonl-file",
                    str(raw_dir / "gowitness.jsonl"),
                    "-s",
                    str(raw_dir / "screenshots"),
                    "--quiet",
                    "-t",
                    "2",
                    "-T",
                    "10",
                ),
                raw_dir / "gowitness.jsonl",
                timeout_seconds=self.timeout,
                parser_hint="jsonl",
                metadata={
                    "note": "The recon image ships chromium, so real screenshots work.",
                    "json_file": str(raw_dir / "gowitness.jsonl"),
                    "requires_chrome": "1",
                },
            )
        )
        return cmds

    # ── Phase 7: Template Validation ──────────────────────────────

    def validation_commands(
        self, scope: ReconScope, raw_dir: Path, live_hosts: list[str], interactsh_url: str = "", cookie: str = ""
    ) -> list[ReconCommand]:
        """Template validation for the discovered live surface.

        Two-pass nuclei design (probe-verified on DVWA):
          1. Fast `-tags default-login` pass — deterministic (~20s) and catches
             default-credential logins (the classic critical finding). Runs
             WITHOUT the forwarded cookie: those templates do their own session
             handshake and a duplicate Cookie header breaks it.
          2. Bounded CVE sweep — critical/high with a tight per-request timeout,
             no retries, fuzz/dos excluded, `-stats` so the no-output watchdog
             doesn't kill the silent sweep. Forwards the auth Cookie when the
             seeder authenticated (auth-first ordering) so authenticated paths
             are tested.
          3. Subdomain-takeover pass (AGGRESSIVE) — `-tags takeover` templates.

        `-as` (auto-scan) is deliberately NOT used: probe-verified it MISSES
        `dvwa-default-login` because tech-detection only maps ~500 templates and
        the default-login family falls outside them.
        """
        if scope.scan_mode == ScanMode.PASSIVE_ONLY or not live_hosts:
            return []
        # Nuclei templates define their OWN relative paths (/login.php, /setup.php),
        # so they must be pointed at the target ORIGIN — a deep URL like
        # http://host:8888/vulnerabilities/sqli/ would make every template probe
        # /vulnerabilities/sqli/login.php (404). Derive origin URLs from whatever
        # the live surface contains (probe-verified: origin-based runs catch
        # dvwa-default-login; deep-URL runs catch nothing).
        origins: list[str] = []
        seen_origins: set[str] = set()
        for h in live_hosts[:200]:
            hs = h.strip()
            if not hs:
                continue
            if hs.startswith(("http://", "https://")):
                try:
                    from urllib.parse import urlsplit

                    pu = urlsplit(hs)
                    origin = f"{pu.scheme}://{pu.netloc}/"
                except Exception:
                    origin = hs
            else:
                origin = f"http://{hs}/"
            if origin not in seen_origins:
                seen_origins.add(origin)
                origins.append(origin)
        if not origins:
            return []
        hosts_file = raw_dir / "live_hosts_for_nuclei.txt"
        hosts_file.write_text("\n".join(origins) + "\n", encoding="utf-8")

        cmds: list[ReconCommand] = []
        _h = ("-H", f"Cookie: {cookie}") if cookie else ()

        # Pass 1: default-login tags — fast, reliable, no cookie.
        cmds.append(
            ReconCommand(
                "nuclei_default_login",
                "template_validation",
                (
                    "nuclei",
                    "-l",
                    str(hosts_file),
                    "-tags",
                    "default-login",
                    "-severity",
                    "critical,high,medium",
                    "-timeout",
                    "5",
                    "-retries",
                    "0",
                    # Serial execution: default-login templates do a 2-request
                    # handshake (GET login -> extract single-use CSRF token ->
                    # POST). Parallel templates race on that token and DVWA's
                    # login breaks (0 findings at -c 5+, deterministic 3/3 at
                    # -c 1). -stats keeps stderr alive so the no-output watchdog
                    # never kills the (necessarily slow) serial pass.
                    "-c",
                    "1",
                    "-stats",
                    "-stats-interval",
                    "15",
                    "-exclude-tags",
                    "fuzz,dos",
                    "-jsonl",
                    "-silent",
                ),
                raw_dir / "nuclei_default_login.jsonl",
                timeout_seconds=min(self.timeout, 120),
                parser_hint="jsonl",
            )
        )

        # Pass 2: bounded CVE sweep (auth-forwarding when seeded).
        cve_args = [
            "nuclei",
            "-l",
            str(hosts_file),
            "-severity",
            "critical,high",
            "-timeout",
            "5",
            "-retries",
            "0",
            "-exclude-tags",
            "fuzz,dos",
            "-rate-limit",
            str(min(scope.max_rps, 200)),
            "-jsonl",
            "-silent",
            "-bulk-size",
            "25",
            "-concurrency",
            "15",
            # -stats keeps stderr alive so the no-output watchdog never kills
            # the silent sweep while templates still load/run.
            "-stats",
            "-stats-interval",
            "20",
            *_h,
        ]
        if interactsh_url:
            cve_args.extend(["-iserver", interactsh_url])
        cmds.append(
            ReconCommand(
                "nuclei_cve",
                "template_validation",
                tuple(cve_args),
                raw_dir / "nuclei_cve.jsonl",
                timeout_seconds=min(self.timeout, 240),
                parser_hint="jsonl",
            )
        )

        # Pass 3: subdomain takeover (AGGRESSIVE only).
        if scope.scan_mode == ScanMode.AGGRESSIVE and scope.base_domain:
            cmds.append(
                ReconCommand(
                    "nuclei_takeover",
                    "template_validation",
                    (
                    "nuclei",
                    "-l",
                    str(hosts_file),
                    "-tags",
                    "takeover",
                    "-c",
                    "5",
                        "-severity",
                        "medium,high,critical",
                        "-timeout",
                        "5",
                        "-retries",
                        "0",
                        "-jsonl",
                        "-silent",
                    ),
                    raw_dir / "nuclei_takeover.jsonl",
                    timeout_seconds=min(self.timeout, 120),
                    parser_hint="jsonl",
                )
            )
        return cmds

    def interactsh_commands(self, raw_dir: Path) -> list[ReconCommand]:
        """Start interactsh-client for OOB detection."""
        return [
            ReconCommand(
                "interactsh",
                "template_validation",
                (
                    "interactsh-client",
                    "-json",
                    "-o",
                    str(raw_dir / "interactsh.jsonl"),
                    "-poll-interval",
                    "5",
                    "-n",
                    "1",
                ),
                raw_dir / "interactsh.jsonl",
                timeout_seconds=self.timeout * 3,
                parser_hint="jsonl",
            ),
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
    "puredns": ["subfinder", "amass"],  # Massdns-based bruteforce on base domain
    "cdncheck": ["dnsx"],  # Needs resolved IPs to check CDN
    # STAGE 2b: Port Scanning (depends on DNS resolution)
    "naabu": ["dnsx"],  # Needs resolved hosts
    "masscan": ["dnsx"],  # Fast port scan on resolved hosts
    "nmap": ["masscan"],  # Deep scan on masscan-discovered ports
    # STAGE 2c: TLS Analysis (depends on DNS resolution)
    "tlsx": ["dnsx"],  # TLS cert info on resolved hosts
    "testssl": ["nmap"],  # Deep TLS test on nmap-discovered ports
    # STAGE 3: HTTP & Browser Intelligence (depends on DNS + ports)
    "httpx": ["dnsx"],  # Tech detection, status codes on live hosts
    "katana": ["httpx"],  # Crawl live HTTP endpoints
    "gospider": ["httpx"],  # Spider live HTTP endpoints
    "arjun": ["httpx"],  # Find hidden parameters on endpoints
    "paramspider": ["httpx"],  # Extract parameters from URLs
    # STAGE 3b: JavaScript Analysis (depends on HTTP crawl)
    "linkfinder": ["katana", "gospider"],  # Find JS links from crawled pages
    "secretfinder": ["linkfinder"],  # Find secrets in JS files
    # STAGE 4: Directory & Route Discovery (depends on HTTP)
    "feroxbuster": ["httpx"],  # Directory brute-force on live hosts
    "ffuf": ["httpx"],  # Fast directory brute-force
    "ffuf_vhost": ["httpx"],  # Virtual-host brute-force (Host header)
    "gobuster": ["httpx"],  # Directory/file brute-force
    # STAGE 4b: API Reconnaissance (depends on HTTP)
    "kiterunner": ["httpx"],  # API route discovery
    "inql": ["httpx"],  # GraphQL introspection
    # STAGE 4c: Visual Documentation (depends on HTTP)
    "gowitness": ["httpx"],  # Screenshot live hosts (chromium in image)
    # STAGE 5: Validation (depends on all prior stages)
    "nuclei_default_login": ["httpx"],  # Fast default-login detection pass
    "nuclei_cve": ["httpx"],  # Bounded critical/high CVE sweep
    "nuclei_takeover": ["httpx"],  # Subdomain takeover check (AGGRESSIVE)
    "interactsh": ["httpx"],  # OOB server runs alongside nuclei  # OOB vulnerability detection
}
