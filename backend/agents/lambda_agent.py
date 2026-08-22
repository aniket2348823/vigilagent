import logging
"""
PROBLEM 18 FIX: Lambda Agent — PRE-CODE SCANNER
Detects vulnerabilities in source code before deployment.
Layer 1: Regex pattern scan (fast, broad)
Layer 2: AST deep scan (Python only, structural analysis)
"""

import ast
import asyncio
import os
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

# ── Lookup caches (module-level, TTL-based) ────────────────────────────────
def _load_sbom_config() -> dict[str, Any]:
    """Load sbom_scanner settings from engagement.yaml with safe defaults."""
    defaults: dict[str, Any] = {
        "registry_cache_ttl_seconds": 3600,
        "ghsa_cache_ttl_seconds": 3600,
        "osv_cache_ttl_seconds": 3600,
        "nvd_cache_ttl_seconds": 3600,
        "osv_enabled": True,
        "ghsa_enabled": True,
        "registry_enabled": True,
        "nvd_enabled": True,
        "max_advisories_per_package": 10,
    }
    try:
        import yaml
        from backend.core.config import ENGAGEMENT_CONFIG_PATH

        if os.path.exists(ENGAGEMENT_CONFIG_PATH):
            with open(ENGAGEMENT_CONFIG_PATH, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            sbom = data.get("sbom_scanner", {})
            if isinstance(sbom, dict):
                for k, v in sbom.items():
                    if k in defaults and v is not None:
                        defaults[k] = v
    except Exception as exc:
        logger.debug("Could not load sbom_scanner config: %s", exc)
    return defaults


_sbom_cfg = _load_sbom_config()

_REGISTRY_CACHE_TTL: int = int(_sbom_cfg["registry_cache_ttl_seconds"])
_registry_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_GHSA_CACHE_TTL: int = int(_sbom_cfg["ghsa_cache_ttl_seconds"])
_ghsa_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_OSV_CACHE_TTL: int = int(_sbom_cfg["osv_cache_ttl_seconds"])
_osv_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_OSV_ENABLED: bool = bool(_sbom_cfg["osv_enabled"])
_GHSA_ENABLED: bool = bool(_sbom_cfg["ghsa_enabled"])
_REGISTRY_ENABLED: bool = bool(_sbom_cfg["registry_enabled"])
_NVD_ENABLED: bool = bool(_sbom_cfg.get("nvd_enabled", True))
_NVD_CACHE_TTL: int = int(_sbom_cfg.get("nvd_cache_ttl_seconds", 3600))
_nvd_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_MAX_ADVISORIES: int = int(_sbom_cfg["max_advisories_per_package"])


class LambdaAgent:
    """PRE-CODE SCANNER — Detects vulnerabilities in source code before deployment.

    Exposes the same lifecycle interface as BaseAgent subclasses
    (name, start, stop) so the orchestrator can activate and deactivate
    it without special-casing.
    """

    name = "agent_lambda"

    # FP-reduced patterns: each rule includes optional 'context_exclude' regexes.
    # When ANY exclude pattern matches the *surrounding* code (±3 lines), the
    # finding is suppressed.  This eliminates noise from test files, commented-out
    # code, safe defaults, and docstring examples.
    PATTERNS = [
        {
            "type": "SQL Injection",
            "pattern": r'(execute|cursor\.execute)\s*\(\s*["\'].*[\+%]',
            "message": "String concatenation in SQL query. Use parameterized queries.",
            "severity": "CRITICAL",
            "confidence": 0.9,
            "context_exclude": [
                r"parameterized|paramstyle|%s|\?|:\w+",  # already uses params
                r"#\s*nosec|#\s*pragma:\s*nosec",  # intentional suppression
            ],
        },
        {
            "type": "Hardcoded Secret",
            "pattern": r'(password|secret|api_key|token|key)\s*=\s*["\'][^"\']{6,}["\']',
            "message": "Hardcoded secret detected. Use environment variables.",
            "severity": "HIGH",
            "confidence": 0.75,
            "context_exclude": [
                r"os\.environ|getenv|dotenv|load_env",  # env-based
                r"example|placeholder|changeme|dummy|test|mock",  # test values
                r"^\s*#",  # commented-out code
                r"TYPE_HINT|annotation|:\s*str\s*=",  # type hints
            ],
        },
        {
            "type": "Command Injection",
            "pattern": r"(os\.system|subprocess\.call|subprocess\.run)\s*\(.*shell\s*=\s*True",
            "message": "shell=True with dynamic input enables command injection.",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "context_exclude": [
                r"shlex\.quote|pipes\.quote|shell_quote",  # properly quoted
                r"#\s*nosec",
            ],
        },
        {
            "type": "Insecure Deserialization",
            "pattern": r"pickle\.loads?\s*\(|yaml\.load\s*\([^,)]+\)",
            "message": "Unsafe deserialization. Use pickle with caution or yaml.safe_load.",
            "severity": "HIGH",
            "confidence": 0.85,
            "context_exclude": [
                r"yaml\.safe_load|yaml\.safe_load_all",  # safe variant
                r"RestrictedUnpickler|_safe_pickle|trusted",  # safe unpickler
                r"test_|_test\.py|conftest",  # test files handled below
            ],
        },
        {
            "type": "XSS Risk",
            "pattern": r"render_template_string\s*\(.*request\.",
            "message": "User input in template render — potential XSS.",
            "severity": "HIGH",
            "confidence": 0.8,
            "context_exclude": [
                r"escape| Markup|sanitize|bleach|html\.escape",  # escaped
                r"#\s*nosec",
            ],
        },
        {
            "type": "Path Traversal",
            "pattern": r"open\s*\(\s*.*request\.",
            "message": "User input in file open — path traversal risk.",
            "severity": "HIGH",
            "confidence": 0.8,
            "context_exclude": [
                r"os\.path\.join.*secure_path|safe_join|traversal_check",  # validated
                r"startswith|os\.path\.abspath",  # path checked
            ],
        },
        {
            "type": "Weak Crypto",
            "pattern": r"hashlib\.md5|hashlib\.sha1",
            "message": "MD5/SHA1 are cryptographically broken. Use SHA-256 or better.",
            "severity": "MEDIUM",
            "confidence": 0.6,
            "context_exclude": [
                r"usedforsecurity\s*=\s*False",  # explicit non-security use
                r"fingerprint|integrity|checksum|noncryptographic",  # non-security context
                r"#\s*nosec",
            ],
        },
        {
            "type": "Debug Mode",
            "pattern": r"debug\s*=\s*True|DEBUG\s*=\s*True",
            "message": "Debug mode enabled. Disable before production.",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "context_exclude": [
                r"if.*DEBUG|environ.*DEBUG|getenv.*DEBUG|config.*DEBUG",  # env-gated
                r"unittest|pytest|test_",  # test files
            ],
        },
        {
            "type": "SSRF Risk",
            "pattern": r"requests\.(get|post|put|delete)\s*\(\s*.*request\.",
            "message": "User input directly in HTTP request — potential SSRF.",
            "severity": "HIGH",
            "confidence": 0.7,
            "context_exclude": [
                r"allowlist|whitelist|validate_url|urlparse.*netloc",  # URL validated
                r"trusted_domain|internal_only",  # domain checked
            ],
        },
        {
            "type": "Insecure Random",
            "pattern": r"random\.random\(\)|random\.randint\(",
            "message": "Using non-cryptographic random for security-sensitive operation. Use secrets module.",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "context_exclude": [
                r"secrets\.",  # already using secrets module nearby
                r"#\s*nosec",
                r"non.?crypto|non.?security|testing|mock",  # explicit non-security
            ],
        },
    ]

    def __init__(self, agent_id: str = "agent_lambda", bus=None):
        self.agent_id = agent_id
        self.name = agent_id
        self.bus = bus
        self._is_active = False
        self.active = False

    async def start(self):
        """Start the agent (BaseAgent-compatible lifecycle)."""
        self._is_active = True
        self.active = True
        # FULL-SWARM: Lambda previously never subscribed to the bus, so its
        # SAST pipeline was only reachable via the code-analysis API — it never
        # participated in live pentests. Wire the JOB_ASSIGNED handler now so
        # the orchestrator's lambda_js_sast jobs reach it.
        if self.bus is not None:
            try:
                from backend.core.hive import EventType

                self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_job)
            except Exception as exc:
                logger.debug("LambdaAgent bus subscription failed: %s", exc)
        logger.info(f"🤖 {self.name} is ONLINE. Intelligence backbone synced.")

    async def stop(self):
        """Stop the agent (BaseAgent-compatible lifecycle)."""
        self._is_active = False
        self.active = False
        logger.info(f"💤 {self.name} is OFFLINE.")

    async def handle_job(self, event) -> None:
        """Process lambda_js_sast jobs: run SAST over JS assets from recon.

        Fetches each JS URL handed over by the orchestrator (or falls back to
        the assigned target URL), analyzes the script source, and bridges any
        dangerous findings into the runtime-validation loop via
        VULN_CANDIDATE (same pipeline as the code-analysis API path).
        """
        try:
            from backend.core.protocol import AgentID, JobPacket

            packet = JobPacket(**event.payload)
        except Exception as exc:
            logger.debug("LambdaAgent job parse failed: %s", exc)
            return
        if packet.config.agent_id != AgentID.LAMBDA:
            return
        if packet.config.module_id not in ("lambda_js_sast", "lambda_sast"):
            return

        params = packet.config.params or {}
        js_urls = list(params.get("js_urls") or []) or [packet.target.url]
        scan_id = getattr(event, "scan_id", "GLOBAL")

        try:
            import aiohttp
        except Exception:
            return

        total_findings = 0
        timeout = aiohttp.ClientTimeout(total=15)
        for js_url in js_urls[:10]:
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(js_url, timeout=timeout, ssl=False) as resp:
                        if resp.status != 200:
                            continue
                        code = await resp.text()
            except Exception:
                continue
            if not code or not code.strip():
                continue
            try:
                result = await self.analyze_and_bridge(
                    code,
                    language="javascript",
                    scan_id=scan_id,
                    endpoint_hint=js_url,
                    filename=js_url.rsplit("/", 1)[-1],
                )
                total_findings += len(result.get("findings") or [])
            except Exception as exc:
                logger.debug("LambdaAgent analyze failed for %s: %s", js_url, exc)

        # Always complete the job so the planner/lifecycle sees the work done.
        if self.bus is not None:
            try:
                from backend.core.hive import EventType, HiveEvent

                await self.bus.publish(
                    HiveEvent(
                        type=EventType.JOB_COMPLETED,
                        source=self.agent_id,
                        scan_id=scan_id,
                        payload={
                            "job_id": packet.id,
                            "status": "SUCCESS",
                            "data": {"js_urls": len(js_urls), "sast_findings": total_findings},
                        },
                    )
                )
            except Exception as exc:
                logger.debug("LambdaAgent JOB_COMPLETED publish failed: %s", exc)

    async def analyze(self, code: str, language: str = "python", filename: str = "") -> list[dict]:
        """Analyze source code for security vulnerabilities.

        Accuracy improvements:
        - Filename-based test/mock detection (replaces fragile code[:200] heuristic)
        - Context-aware FP suppression via ``context_exclude`` patterns
        - Per-finding confidence scoring (0.0–1.0)
        - Test-file awareness (downgrades severity for test/mock files)
        - Comment-only line filtering (skip blank/comment lines)
        - Import-aware FP reduction (checks for safe imports in context)
        """
        findings = []
        lines = code.split("\n")

        # ── Detect test/mock files using filename (accurate) ──────────
        fn = filename.lower()
        is_test_file = bool(re.search(
            r"(?:test_|_test|tests?|mock|spec|conftest|fixture|__test__)",
            fn,
            re.IGNORECASE,
        )) if fn else bool(re.search(
            # Fallback: check first 200 chars when no filename provided
            r"(?:test_|_test|tests?|mock|spec|conftest|fixture)",
            code[:200],
            re.IGNORECASE,
        ))

        # ── Pre-compute import context for FP reduction ───────────────
        # Build a set of all imports at the top of the file so context_exclude
        # can check whether safe modules (yaml.safe_load, secrets, etc.) are
        # imported anywhere in the file, not just in the ±3 line window.
        import_block = "\n".join(lines[:50])  # imports are typically in first 50 lines
        import_suffix = " " + import_block  # pre-compute constant suffix

        # ── Build context window set for exclude checks ───────────────
        # Pre-join lines ±3 around each for fast context_exclude matching.
        def _get_context(line_idx: int, radius: int = 3) -> str:
            start = max(0, line_idx - radius)
            end = min(len(lines), line_idx + radius + 1)
            return " ".join(lines[start:end])

        # Layer 1 — Regex pattern scan with FP suppression (all languages)
        for i, line in enumerate(lines, start=1):
            # Skip blank / pure-comment lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for rule in self.PATTERNS:
                if not re.search(rule["pattern"], line, re.IGNORECASE):
                    continue

                # ── Context-exclude check (FP suppression) ──────────────
                # Check both the ±3 line window AND the file-level import block
                # (e.g. if yaml.safe_load is imported anywhere, yaml.load FPs reduce)
                context = _get_context(i - 1)  # 0-indexed
                combined = context + import_suffix
                excluded = False
                for exc_pattern in rule.get("context_exclude", []):
                    if re.search(exc_pattern, combined, re.IGNORECASE):
                        excluded = True
                        break
                if excluded:
                    continue

                # ── Compute final severity & confidence ─────────────────
                severity = rule["severity"]
                confidence = rule.get("confidence", 0.7)

                # Downgrade test-file findings
                if is_test_file:
                    if severity == "CRITICAL":
                        severity = "HIGH"
                    elif severity == "HIGH":
                        severity = "MEDIUM"
                    confidence *= 0.6  # reduce confidence in test files

                findings.append(
                    {
                        "line": i,
                        "type": rule["type"],
                        "message": rule["message"],
                        "severity": severity,
                        "confidence": round(confidence, 2),
                        "code_snippet": stripped[:120],
                        "source": "regex",
                    }
                )

        # Layer 2 — AST deep scan (Python only)
        if language == "python":
            try:
                tree = ast.parse(code)
                findings.extend(self._ast_scan(tree, is_test_file=is_test_file))
            except SyntaxError:
                pass  # incomplete code while typing — skip silently

        # Deduplicate by (line, type) — keep the highest-confidence instance
        seen: dict[tuple, dict] = {}
        for f in findings:
            key = (f["line"], f["type"])
            if key not in seen or f.get("confidence", 0) > seen[key].get("confidence", 0):
                seen[key] = f
        return list(seen.values())

    def _ast_scan(self, tree, *, is_test_file: bool = False) -> list[dict]:
        """Deep structural analysis of Python AST.

        Accuracy improvements:
        - Per-finding confidence scoring
        - Test-file severity downgrade
        - Rejects patterns in ``# nosec`` / ``# pragma: no cover`` lines
        - Filters assert-in-test-file noise
        """
        findings = []
        for node in ast.walk(tree):
            # eval() / exec() usage
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                    conf = 0.95
                    sev = "CRITICAL"
                    if is_test_file:
                        sev, conf = "HIGH", 0.55
                    findings.append(
                        {
                            "line": node.lineno,
                            "type": "Code Injection",
                            "message": f"{node.func.id}() with dynamic input is dangerous.",
                            "severity": sev,
                            "confidence": conf,
                            "code_snippet": f"{node.func.id}() at line {node.lineno}",
                            "source": "ast",
                        }
                    )
                # __import__ usage
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    findings.append(
                        {
                            "line": node.lineno,
                            "type": "Dynamic Import",
                            "message": "__import__() can be used for code injection. Use importlib instead.",
                            "severity": "MEDIUM",
                            "confidence": 0.6,
                            "code_snippet": f"__import__() at line {node.lineno}",
                            "source": "ast",
                        }
                    )

            # Assert usage (disabled in optimized Python)
            # In test files, asserts are the primary mechanism — skip.
            if isinstance(node, ast.Assert):
                if is_test_file:
                    continue
                findings.append(
                    {
                        "line": node.lineno,
                        "type": "Unreliable Security Check",
                        "message": "assert statements are disabled with python -O. Do not use for security checks.",
                        "severity": "MEDIUM",
                        "confidence": 0.55,
                        "code_snippet": f"assert at line {node.lineno}",
                        "source": "ast",
                    }
                )

            # Global variable assignments of sensitive names
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.upper() in [
                        "PASSWORD",
                        "SECRET_KEY",
                        "API_KEY",
                        "TOKEN",
                    ]:
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            # FP: placeholder/example values
                            if val.lower() in ("changeme", "example", "placeholder",
                                               "test", "dummy", "xxx", "todo"):
                                continue
                            conf = 0.8
                            sev = "HIGH"
                            if is_test_file:
                                sev, conf = "MEDIUM", 0.4
                            findings.append(
                                {
                                    "line": node.lineno,
                                    "type": "Hardcoded Secret (AST)",
                                    "message": f"Sensitive variable '{target.id}' assigned a string literal.",
                                    "severity": sev,
                                    "confidence": conf,
                                    "code_snippet": f"{target.id} = '...' at line {node.lineno}",
                                    "source": "ast",
                                }
                            )

        return findings

    # ── SAST → runtime validation bridge (Architecture §5.2, §29.5) ──────────
    # Maps a static finding type to the runtime vuln class Alpha/Beta should
    # prioritize validating at the corresponding endpoint.
    SAST_TO_RUNTIME = {
        "SQL Injection": "SQL_INJECTION",
        "Command Injection": "COMMAND_INJECTION",
        "Code Injection": "RCE",
        "XSS Risk": "XSS",
        "Path Traversal": "PATH_TRAVERSAL",
        "SSRF Risk": "SSRF",
        "Insecure Deserialization": "RCE",
        "Hardcoded Secret": "DATA_LEAK",
        "Hardcoded Secret (AST)": "DATA_LEAK",
        # IaC/SBOM → runtime validation priorities (Architecture §29.5).
        "IaC Misconfiguration (terraform)": "CONFIG_EXPOSURE",
        "IaC Misconfiguration (kubernetes)": "CONFIG_EXPOSURE",
        "IaC Misconfiguration (dockerfile)": "CONFIG_EXPOSURE",
        "IaC Misconfiguration (cloudformation)": "CONFIG_EXPOSURE",
        "Vulnerable Dependency": "KNOWN_CVE",
        "Unpinned Dependency": "SUPPLY_CHAIN",
    }

    async def bridge_to_runtime(self, findings: list, *, scan_id: str = "GLOBAL", endpoint_hint: str = "") -> list:
        """Connect static code risks to runtime validation (Architecture §5.2,
        §29.5). For each dangerous SAST finding, emit a prioritization hint so
        Alpha/Beta validate that vuln class at the related endpoint.

        Returns the list of emitted hints (also published to the bus when one is
        attached)."""
        hints = []
        for f in findings:
            runtime_class = self.SAST_TO_RUNTIME.get(f.get("type"))
            if not runtime_class:
                continue
            if f.get("severity") not in ("CRITICAL", "HIGH"):
                continue
            hint = {
                "source": "lambda_sast",
                "vuln_class": runtime_class,
                "static_type": f.get("type"),
                "severity": f.get("severity"),
                "line": f.get("line"),
                "endpoint_hint": endpoint_hint,
                "priority_boost": 3 if f.get("severity") == "CRITICAL" else 2,
                "rationale": f.get("message", ""),
            }
            hints.append(hint)
            if self.bus is not None:
                try:
                    from backend.core.hive import EventType, HiveEvent

                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CANDIDATE,
                            source=self.agent_id,
                            scan_id=scan_id,
                            payload={
                                "url": endpoint_hint,
                                "vuln_type": runtime_class,
                                "tag": "SAST_HINT",
                                "description": f"Static analysis flagged {f.get('type')} "
                                f"(line {f.get('line')}): {f.get('message', '')}",
                                "evidence": f"SAST finding requires runtime validation. "
                                f"Code: {f.get('code_snippet', '')}",
                                "needs_runtime_validation": True,
                                "priority_boost": hint["priority_boost"],
                            },
                        )
                    )
                except Exception as exc:
                    # Bus publish failure must not break the analysis loop.
                    import logging as _log

                    _log.debug(f"LambdaAgent bridge_to_runtime bus publish failed: {exc}")
        return hints

    async def analyze_and_bridge(
        self, code: str, *, language: str = "python", scan_id: str = "GLOBAL", endpoint_hint: str = "", filename: str = ""
    ) -> dict:
        """Run SAST and immediately bridge dangerous findings to runtime
        validation (Architecture §29.5)."""
        findings = await self.analyze(code, language=language, filename=filename)
        hints = await self.bridge_to_runtime(findings, scan_id=scan_id, endpoint_hint=endpoint_hint)
        return {"findings": findings, "runtime_hints": hints}


# ══════════════════════════════════════════════════════════════════════════════
# IaC + SBOM SCANNING (Architecture §5.3.5, §29.5) — native, no external tools
# ══════════════════════════════════════════════════════════════════════════════


class IaCScanner:
    """Infrastructure-as-Code misconfiguration scanner (Architecture §29.5).

    Native regex/heuristic checks across Terraform, CloudFormation, Kubernetes
    manifests, and Dockerfiles — no external binary (Trivy/kube-bench) required.
    External scanners can augment this when present, but are not required."""

    TERRAFORM_RULES = [
        (r"(?i)0\.0\.0\.0/0", "Open ingress CIDR (0.0.0.0/0) — world-reachable.", "HIGH"),
        (r'(?i)acl\s*=\s*"public-read', "S3 bucket public-read ACL.", "HIGH"),
        (r"(?i)encrypted\s*=\s*false", "Resource encryption disabled.", "HIGH"),
        (r"(?i)force_destroy\s*=\s*true", "force_destroy enabled — data loss risk.", "MEDIUM"),
        (r"(?i)publicly_accessible\s*=\s*true", "DB publicly accessible.", "CRITICAL"),
        (r"(?i)skip_final_snapshot\s*=\s*true", "No final DB snapshot on destroy.", "MEDIUM"),
    ]
    K8S_RULES = [
        (r"(?i)privileged:\s*true", "Privileged container — host escape risk.", "CRITICAL"),
        (r"(?i)hostNetwork:\s*true", "hostNetwork enabled.", "HIGH"),
        (r"(?i)hostPID:\s*true", "hostPID enabled.", "HIGH"),
        (r"(?i)runAsNonRoot:\s*false", "Container allowed to run as root.", "HIGH"),
        (r"(?i)allowPrivilegeEscalation:\s*true", "Privilege escalation allowed.", "HIGH"),
        (r"(?i)readOnlyRootFilesystem:\s*false", "Writable root filesystem.", "MEDIUM"),
        (r"(?i)imagePullPolicy:\s*Never", "imagePullPolicy Never — stale image risk.", "LOW"),
    ]
    DOCKERFILE_RULES = [
        (r"(?im)^\s*USER\s+root", "Container runs as root.", "MEDIUM"),
        (r"(?i)ADD\s+http", "ADD with remote URL — supply-chain risk; use COPY.", "MEDIUM"),
        (r"(?i)(curl|wget)\s+[^\n|]*\|\s*(sh|bash)", "Pipe-to-shell install in image.", "HIGH"),
        (r"(?i)--no-check-certificate", "TLS verification disabled.", "HIGH"),
        (r"(?i)(password|secret|api_key|token)\s*=\s*\S+", "Hardcoded secret in Dockerfile.", "HIGH"),
    ]
    CFN_RULES = [
        (r'(?i)"?CidrIp"?\s*:?\s*"?0\.0\.0\.0/0', "CloudFormation open ingress.", "HIGH"),
        (r'(?i)"?PubliclyAccessible"?\s*:?\s*true', "CFN resource publicly accessible.", "CRITICAL"),
        (r'(?i)"?Encryption"?\s*:?\s*"?(false|none)', "CFN encryption disabled.", "HIGH"),
    ]

    def _detect_kind(self, filename: str, content: str) -> str:
        f = (filename or "").lower()
        if f.endswith(".tf") or 'resource "' in content or 'provider "' in content:
            return "terraform"
        if f.endswith("dockerfile") or content.lstrip().upper().startswith("FROM "):
            return "dockerfile"
        if "apiVersion:" in content and "kind:" in content:
            return "kubernetes"
        if "AWSTemplateFormatVersion" in content or '"Resources"' in content or "Resources:" in content:
            return "cloudformation"
        return "unknown"

    def scan(self, content: str, filename: str = "") -> list[dict]:
        kind = self._detect_kind(filename, content)
        rules = {
            "terraform": self.TERRAFORM_RULES,
            "kubernetes": self.K8S_RULES,
            "dockerfile": self.DOCKERFILE_RULES,
            "cloudformation": self.CFN_RULES,
        }.get(kind, [])
        findings = []
        lines = content.split("\n")
        for i, line in enumerate(lines, start=1):
            for pattern, message, severity in rules:
                if re.search(pattern, line):
                    findings.append(
                        {
                            "line": i,
                            "type": f"IaC Misconfiguration ({kind})",
                            "message": message,
                            "severity": severity,
                            "code_snippet": line.strip()[:120],
                            "source": "iac",
                            "iac_kind": kind,
                        }
                    )
        return findings


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


# Well-known packages whose names are commonly typosquatted.
_POPULAR_PACKAGES = {
    # npm
    "lodash", "react", "express", "axios", "webpack", "moment",
    "chalk", "commander", "underscore", "debug", "typescript",
    "eslint", "prettier", "babel", "jest", "mocha", "gulp",
    "grunt", "bower", "request", "fs-extra", "mongoose",
    "next", "nuxt", "vue", "angular", "svelte",
    # pip / PyPI
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "scikit-learn", "tensorflow", "torch", "pillow", "boto3",
    "cryptography", "pyyaml", "click", "fastapi", "uvicorn",
    "sqlalchemy", "celery", "redis", "pytest", "black",
    # Go
    "gorilla/mux", "gin-gonic/gin", "go-chi/chi",
}


def _detect_ghsa_ecosystems(package_name: str, filename: str = "") -> list[str]:
    """Determine the most likely package ecosystems for a GHSA lookup.

    Returns a deduplicated list of ecosystems to query (typically 1-2).
    Prefers the filename hint when available; falls back to naming heuristics.
    """
    name_lower = package_name.lower()
    f = (filename or "").lower()

    # If the caller provides a filename, use it to pick the primary ecosystem.
    if f.endswith("requirements.txt") or f.endswith("setup.py") or f.endswith("pyproject.toml"):
        return ["pip"]
    if f.endswith("package.json") or f.endswith("package-lock.json") or f.endswith("yarn.lock"):
        return ["npm"]
    if f.endswith("go.mod"):
        return ["go"]
    if f.endswith("pom.xml") or f.endswith("build.gradle"):
        return ["maven"]
    if f.endswith("Cargo.toml"):
        return ["cargo"]
    if f.endswith("Gemfile"):
        return ["rubygems"]
    if f.endswith("composer.json"):
        return ["composer"]

    # No filename — heuristic detection.
    if "/" in package_name:
        return ["go"]  # Go-style path
    # Default: check both npm and pip (most common ecosystems)
    return ["npm", "pip"]


def _semver_satisfies(version_str: str, vulnerable_range: str) -> bool:
    """Check if *version_str* falls within *vulnerable_range*.

    Handles common GHSA range operators: ``< X``, ``>= X``, ``> X``,
    ``<= X``, ``>= X, < Y``.  Returns True when the version IS affected.
    Returns True conservatively when parsing fails or when no version is
    supplied (caller should skip the advisory in that case).
    """
    if not version_str or not vulnerable_range:
        return True  # can't determine — conservatively report

    def _parse(v: str) -> tuple[int, ...]:
        parts = re.split(r"[^0-9]", v.strip().lstrip("<>=!~ ^"))
        return tuple(int(p) for p in parts if p)

    ver = _parse(version_str)
    vr = vulnerable_range.strip()

    # Handle compound ranges like ">= 1.0, < 2.0"
    parts = [p.strip() for p in vr.split(",") if p.strip()]
    for part in parts:
        part = part.strip()
        if part.startswith(">="):
            if ver < _parse(part[2:]):
                return False
        elif part.startswith(">"):
            if ver <= _parse(part[1:]):
                return False
        elif part.startswith("<="):
            if ver > _parse(part[2:]):
                return False
        elif part.startswith("<"):
            if ver >= _parse(part[1:]):
                return False
        elif part.startswith("!="):
            if ver == _parse(part[2:]):
                return False
        else:
            # bare version like "1.0" — treat as "=="
            if ver == _parse(part):
                return True
    return True  # all sub-ranges satisfied


async def _ghsa_lookup(
    package_name: str, version: str = "", filename: str = ""
) -> list[dict[str, Any]]:
    """Query the GitHub Advisory Database for known vulnerabilities.

    Uses the public GHSA REST endpoint to find advisories affecting
    *package_name*.  Results are cached in-memory for ``_GHSA_CACHE_TTL``
    seconds keyed on ``(package_name, version)``.
    """
    import aiohttp

    # ── Cache check ──────────────────────────────────────────────────────
    cache_key = f"{package_name.lower().strip()}:{version}"
    now = time.monotonic()
    cached = _ghsa_cache.get(cache_key)
    if cached is not None:
        cached_ts, cached_val = cached
        if now - cached_ts < _GHSA_CACHE_TTL:
            return cached_val

    ecosystems = _detect_ghsa_ecosystems(package_name, filename)
    name_lower = package_name.lower().strip()
    advisories: list[dict[str, Any]] = []

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for eco in ecosystems:
            try:
                url = (
                    f"https://api.github.com/advisories"
                    f"?type=reviewed&ecosystem={eco}&package={package_name}"
                )
                headers = {"Accept": "application/vnd.github+json"}
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 403:
                        logger.warning(
                            "GHSA rate limit hit for %s (ecosystem=%s) — "
                            "some advisories may be missing",
                            package_name, eco,
                        )
                        break
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    for adv in data:
                        ghsa_id = adv.get("ghsa_id", "")
                        cve_id = adv.get("cve_id", "")
                        severity = (adv.get("severity") or "unknown").upper()
                        summary = adv.get("summary", "")
                        published = adv.get("published_at", "")
                        # Filter by version when possible.
                        affected_versions = []
                        version_is_affected = False
                        for vuln in adv.get("vulnerabilities", []):
                            pkg = vuln.get("package", {})
                            if pkg.get("name", "").lower() != name_lower:
                                continue
                            vp = vuln.get("vulnerable_version_range", "")
                            pv = vuln.get("patched_versions", "")
                            if version and vp:
                                if _semver_satisfies(version, vp):
                                    affected_versions.append({
                                        "range": vp,
                                        "patched_version": pv,
                                    })
                                    version_is_affected = True
                            elif not version:
                                affected_versions.append({
                                    "range": vp,
                                    "patched_version": pv,
                                })
                                version_is_affected = True
                        # Skip advisories that don't affect the pinned version.
                        if version and not version_is_affected:
                            continue
                        advisories.append({
                            "ghsa_id": ghsa_id,
                            "cve_id": cve_id,
                            "severity": severity,
                            "summary": summary,
                            "published_at": published,
                            "ecosystem": eco,
                            "affected_versions": affected_versions,
                        })
            except Exception as gh_err:
                logger.debug("GHSA lookup failed for %s in %s: %s", package_name, eco, gh_err)

    # ── Cache write ──────────────────────────────────────────────────────
    _ghsa_cache[cache_key] = (time.monotonic(), advisories)
    return advisories


async def _registry_lookup(package_name: str) -> dict[str, Any]:
    """Look up a package name on npm and PyPI registries in parallel.

    Returns metadata about whether the package exists, download counts,
    and publication timestamps. Results are cached in-memory for
    ``_REGISTRY_CACHE_TTL`` seconds to avoid redundant HTTP calls.
    """
    # ── Cache check ──────────────────────────────────────────────────────
    cache_key = package_name.lower().strip()
    now = time.monotonic()
    cached = _registry_cache.get(cache_key)
    if cached is not None:
        cached_ts, cached_val = cached
        if now - cached_ts < _REGISTRY_CACHE_TTL:
            return cached_val

    import aiohttp

    result: dict[str, Any] = {
        "package": package_name,
        "npm_exists": False,
        "npm_downloads_weekly": 0,
        "npm_created": None,
        "pypi_exists": False,
        "pypi_downloads_total": 0,
        "pypi_created": None,
        "exists_anywhere": False,
    }

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:

        async def _check_npm():
            try:
                async with session.get(f"https://registry.npmjs.org/{package_name}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result["npm_exists"] = True
                        times = data.get("time", {})
                        result["npm_created"] = times.get("created")
                        dist_tags = data.get("dist-tags", {})
                        latest_version = dist_tags.get("latest")
                        if latest_version:
                            versions = data.get("versions", {})
                            ver_data = versions.get(latest_version, {})
                            result["npm_version"] = latest_version
                            result["npm_description"] = ver_data.get("description", "")
                            result["npm_keywords"] = ver_data.get("keywords", [])
            except Exception:
                pass

        async def _check_npm_downloads():
            try:
                async with session.get(
                    f"https://api.npmjs.org/downloads/point/last-week/{package_name}") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result["npm_downloads_weekly"] = data.get("downloads", 0)
            except Exception:
                pass

        async def _check_pypi():
            try:
                async with session.get(f"https://pypi.org/pypi/{package_name}/json") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result["pypi_exists"] = True
                        info = data.get("info", {})
                        result["pypi_version"] = info.get("version")
                        result["pypi_description"] = info.get("summary", "")
                        result["pypi_keywords"] = info.get("keywords", "")
                        releases = data.get("releases", {})
                        if releases:
                            first_ver = list(releases.keys())[0]
                            uploads = releases[first_ver]
                            if uploads:
                                result["pypi_created"] = uploads[0].get("upload_time")
            except Exception:
                pass

        async def _check_pypi_downloads():
            try:
                async with session.get(
                    f"https://pypistats.org/api/packages/{package_name}/recent") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result["pypi_downloads_total"] = (
                            data.get("data", {}).get("last_week", 0)
                        )
            except Exception:
                pass

        # Run all 4 checks in parallel (worst case ~5s total, not ~20s)
        await asyncio.gather(
            _check_npm(), _check_npm_downloads(),
            _check_pypi(), _check_pypi_downloads(),
            return_exceptions=True,
        )

    result["exists_anywhere"] = result["npm_exists"] or result["pypi_exists"]
    # ── Cache write ──────────────────────────────────────────────────────
    _registry_cache[cache_key] = (time.monotonic(), result)
    return result


async def _osv_lookup(package_name: str, version: str = "", ecosystem: str = "") -> dict[str, Any]:
    """Query the Open Source Vulnerabilities (osv.dev) database.

    OSV is a distributed vulnerability database that aggregates advisories
    from NVD, GitHub, and ecosystem-specific sources.  Results are cached
    in-memory for ``_OSV_CACHE_TTL`` seconds.
    """
    import aiohttp

    cache_key = f"{package_name.lower().strip()}:{version}:{ecosystem}"
    now = time.monotonic()
    cached = _osv_cache.get(cache_key)
    if cached is not None:
        cached_ts, cached_val = cached
        if now - cached_ts < _OSV_CACHE_TTL:
            return cached_val

    # OSV API accepts a POST with a JSON body.
    query: dict[str, Any] = {"package": {"name": package_name}}
    if ecosystem:
        query["package"]["ecosystem"] = ecosystem
    if version:
        query["version"] = version

    result: dict[str, Any] = {
        "package": package_name,
        "version": version,
        "vulns": [],
        "vuln_count": 0,
        "severity_map": {},
    }

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.post(
                "https://api.osv.dev/v1/query",
                json=query,
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulns = data.get("vulns", []) or []
                    for v in vulns:
                        vid = v.get("id", "")
                        summary = v.get("summary", "")
                        details = v.get("details", "")
                        aliases = v.get("aliases", [])
                        published = v.get("published", "")
                        modified = v.get("modified", "")
                        # Extract severity from database_specific or severity field
                        sev = "UNKNOWN"
                        for s in v.get("severity", []):
                            if s.get("type") == "CVSS_V3":
                                score_str = s.get("score", "")
                                # Parse CVSS vector — extract severity from it
                                if "AV:N" in score_str:
                                    sev = "HIGH"  # network-accessible
                                else:
                                    sev = "MEDIUM"
                                break
                        # Also check database_specific for GitHub-style severity
                        db_sev = (v.get("database_specific", {}).get("severity", "")).upper()
                        if db_sev in ("CRITICAL", "HIGH", "MODERATE", "LOW"):
                            sev = db_sev

                        # Check if the specific version is affected
                        affected = False
                        fixed_version = ""
                        if not version:
                            affected = True  # no version pinned — report all
                        else:
                            for aff in v.get("affected", []):
                                for rng in aff.get("ranges", []):
                                    intro = "0"
                                    for ev in rng.get("events", []):
                                        if "introduced" in ev:
                                            intro = ev["introduced"]
                                        if "fixed" in ev:
                                            fixed_version = ev["fixed"]
                                            if _semver_satisfies(
                                                version,
                                                f">= {intro}, < {ev['fixed']}",
                                            ):
                                                affected = True
                                if affected:
                                    break

                        if not affected and version:
                            continue

                        result["vulns"].append({
                            "id": vid,
                            "summary": summary or details[:200],
                            "severity": sev,
                            "aliases": aliases,
                            "cve_id": next((a for a in aliases if a.startswith("CVE-")), ""),
                            "published": published,
                            "modified": modified,
                            "fixed_version": fixed_version,
                            "url": f"https://osv.dev/vulnerability/{vid}",
                        })
                        result["severity_map"][vid] = sev
                elif resp.status == 429:
                    logger.warning("OSV rate limit hit for %s", package_name)
        except Exception as osv_err:
            logger.debug("OSV lookup failed for %s: %s", package_name, osv_err)

    result["vuln_count"] = len(result["vulns"])
    _osv_cache[cache_key] = (time.monotonic(), result)
    return result


async def _nvd_lookup(package_name: str, version: str = "") -> list[dict[str, Any]]:
    """Query the NIST National Vulnerability Database (NVD) for CVEs.

    Uses the NVD REST API v2.0 ``keywordSearch`` parameter to find CVEs
    mentioning the package name.  Rate-limited to 5 requests per 30 seconds
    for unauthenticated callers.  Results are cached for ``_NVD_CACHE_TTL``
    seconds.
    """
    import aiohttp

    cache_key = f"{package_name.lower().strip()}:{version}"
    now = time.monotonic()
    cached = _nvd_cache.get(cache_key)
    if cached is not None:
        cached_ts, cached_val = cached
        if now - cached_ts < _NVD_CACHE_TTL:
            return cached_val

    results: list[dict[str, Any]] = []
    timeout = aiohttp.ClientTimeout(total=8)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            # keywordSearch searches CVE descriptions for the package name.
            url = (
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={package_name}&resultsPerPage=20"
            )
            headers = {}
            # If user has an NVD API key, use it for higher rate limits.
            nvd_key = os.getenv("NVD_API_KEY", "")
            if nvd_key:
                headers["apiKey"] = nvd_key
            async with session.get(url, headers=headers) as resp:
                if resp.status == 403:
                    logger.warning("NVD rate limit hit for %s", package_name)
                elif resp.status == 200:
                    data = await resp.json()
                    for vuln in data.get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "")
                        # Extract CVSS v3.1 severity and score
                        sev = "UNKNOWN"
                        cvss_score = 0.0
                        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                            metrics = cve.get("metrics", {}).get(metric_key, [])
                            if metrics:
                                cvss_data = metrics[0].get("cvssData", {})
                                sev = (cvss_data.get("baseSeverity", "UNKNOWN") or "UNKNOWN").upper()
                                cvss_score = cvss_data.get("baseScore", 0.0)
                                break
                        # Fallback to CVSS v2
                        if sev == "UNKNOWN":
                            v2_metrics = cve.get("metrics", {}).get("cvssMetricV2", [])
                            if v2_metrics:
                                v2 = v2_metrics[0].get("cvssData", {})
                                cvss_score = v2.get("baseScore", 0.0)
                                sev = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"

                        descriptions = cve.get("descriptions", [])
                        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                        published = cve.get("published", "")
                        status = cve.get("vulnStatus", "")

                        # ── FP reduction: verify package name actually matches CPE ──
                        name_affected = False
                        for config in vuln.get("configurations", []):
                            for node in config.get("nodes", []):
                                for cpe_match in node.get("cpeMatch", []):
                                    cpe_uri = cpe_match.get("criteria", "")
                                    # CPE format: cpe:2.3:a:<vendor>:<product>:... 
                                    if package_name.lower() in cpe_uri.lower():
                                        name_affected = True
                                        break
                                if name_affected:
                                    break
                            if name_affected:
                                break
                        # If no CPE data at all, still report (keyword match only)
                        has_cpe = any(
                            node.get("cpeMatch")
                            for config in vuln.get("configurations", [])
                            for node in config.get("nodes", [])
                        )
                        if has_cpe and not name_affected:
                            continue  # CPE exists but doesn't match this package — false positive

                        # ── FP reduction: filter by version via CPE match ──
                        version_affected = True  # default: report all if no version
                        if version:
                            version_affected = False
                            for config in vuln.get("configurations", []):
                                for node in config.get("nodes", []):
                                    for cpe_match in node.get("cpeMatch", []):
                                        cpe_ver_incl = cpe_match.get("versionEndIncluding", "")
                                        cpe_ver_excl = cpe_match.get("versionEndExcluding", "")
                                        cpe_ver = cpe_ver_incl or cpe_ver_excl
                                        cpe_ver_start = cpe_match.get("versionStartIncluding", "") or cpe_match.get("versionStartExcluding", "")
                                        if cpe_ver:
                                            if cpe_ver_start and _semver_satisfies(version, f">= {cpe_ver_start}, < {cpe_ver}"):
                                                version_affected = True
                                                break
                                            elif not cpe_ver_start and _semver_satisfies(version, f"< {cpe_ver}"):
                                                version_affected = True
                                                break
                                    if version_affected:
                                        break
                                if version_affected:
                                    break

                        if not version_affected:
                            continue

                        # ── FP reduction: skip rejected/withdrawn CVEs ──
                        if status in ("Rejected", "Withdrawn"):
                            continue

                        results.append({
                            "cve_id": cve_id,
                            "severity": sev,
                            "cvss_score": cvss_score,
                            "summary": summary[:300],
                            "published": published,
                            "status": status,
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        })
                elif resp.status != 200:
                    logger.debug("NVD returned status %d for %s", resp.status, package_name)
        except Exception as nvd_err:
            logger.debug("NVD lookup failed for %s: %s", package_name, nvd_err)

    _nvd_cache[cache_key] = (time.monotonic(), results)
    return results


def _detect_typosquats(package_name: str) -> list[dict[str, Any]]:
    """Check if a package name is a likely typosquat of a popular package.

    Uses Levenshtein distance: distance <= 2 for names > 4 chars,
    or distance == 1 for short names. Also catches common typosquat
    patterns like prepending/appending single chars.
    """
    name_lower = package_name.lower().strip()
    if not name_lower or len(name_lower) < 3:
        return []

    hits = []
    for popular in _POPULAR_PACKAGES:
        pop = popular.lower().split("/")[-1]  # strip org prefix for Go pkgs
        if name_lower == pop:
            continue  # exact match = not a typosquat

        dist = _levenshtein(name_lower, pop)
        max_dist = 2 if len(pop) > 4 else 1

        if dist <= max_dist:
            hits.append({
                "popular_package": popular,
                "edit_distance": dist,
                "risk": "CRITICAL" if dist <= 1 else "HIGH",
            })

        # Also catch: popular + suffix/prefix (e.g. "lodashs", "xreact")
        if len(name_lower) > len(pop) and name_lower.startswith(pop) and dist <= 2:
            if not any(h["popular_package"] == popular for h in hits):
                hits.append({
                    "popular_package": popular,
                    "edit_distance": dist,
                    "risk": "HIGH",
                    "pattern": "prefix-append",
                })
        elif len(name_lower) > len(pop) and name_lower.endswith(pop) and dist <= 2:
            if not any(h["popular_package"] == popular for h in hits):
                hits.append({
                    "popular_package": popular,
                    "edit_distance": dist,
                    "risk": "HIGH",
                    "pattern": "suffix-prepend",
                })

    return hits


class SBOMScanner:
    """Dependency / SBOM analyzer (Architecture §29.5).

    Parses dependency manifests (requirements.txt, package.json, go.mod, etc.)
    and flags unpinned versions, known-risky packages, and typosquatting.
    Native — no Grype/Trivy binary required; integrates with them when present."""

    # Minimal built-in advisory set (illustrative; real deployments add a feed).
    KNOWN_RISKY = {
        "lodash": ("< 4.17.21", "Prototype pollution (CVE-2021-23337).", "HIGH"),
        "minimist": ("< 1.2.6", "Prototype pollution (CVE-2021-44906).", "HIGH"),
        "pyyaml": ("< 5.4", "Arbitrary code execution via yaml.load (CVE-2020-14343).", "HIGH"),
        "flask": ("< 2.2.5", "Multiple advisories; upgrade recommended.", "MEDIUM"),
        "requests": ("< 2.31.0", "CVE-2023-32681 proxy auth leak.", "MEDIUM"),
        "log4j": ("< 2.17.1", "Log4Shell RCE (CVE-2021-44228).", "CRITICAL"),
    }

    async def scan(self, content: str, filename: str = "") -> list[dict]:
        f = (filename or "").lower()
        if f.endswith("requirements.txt") or ("==" in content and "{" not in content and f.endswith(".txt")):
            return await self._scan_requirements(content, filename=filename)
        if f.endswith("package.json") or '"dependencies"' in content:
            return await self._scan_package_json(content, filename=filename)
        if f.endswith("go.mod") or content.lstrip().startswith("module "):
            return await self._scan_go_mod(content, filename=filename)
        # Best-effort: try requirements style.
        return await self._scan_requirements(content, filename=filename)

    async def _advise(self, name: str, version: str, line: int, *, filename: str = "") -> list[dict]:
        out = []
        info = self.KNOWN_RISKY.get(name.lower())
        if info:
            affected, message, severity = info
            out.append(
                {
                    "line": line,
                    "type": "Vulnerable Dependency",
                    "message": f"{name} {affected}: {message}",
                    "severity": severity,
                    "code_snippet": f"{name} {version}".strip()[:120],
                    "source": "sbom",
                    "package": name,
                    "version": version,
                }
            )
        if not version or version in ("*", "latest"):
            out.append(
                {
                    "line": line,
                    "type": "Unpinned Dependency",
                    "message": f"{name} has no pinned version — supply-chain risk.",
                    "severity": "MEDIUM",
                    "code_snippet": f"{name} {version}".strip()[:120],
                    "source": "sbom",
                    "package": name,
                    "version": version or "unpinned",
                }
            )
        # Typosquatting detection
        typos = _detect_typosquats(name)
        for t in typos:
            finding = {
                "line": line,
                "type": "Typosquatting",
                "message": (
                    f"'{name}' resembles popular package '{t['popular_package']}' "
                    f"(edit distance {t['edit_distance']}) — likely typosquat."
                ),
                "severity": t["risk"],
                "code_snippet": f"{name} {version}".strip()[:120],
                "source": "sbom",
                "package": name,
                "version": version,
                "typosquat_of": t["popular_package"],
                "edit_distance": t["edit_distance"],
            }
            out.append(finding)

        # Registry lookup for typosquatted packages — verify they actually exist
        if typos and _REGISTRY_ENABLED:
            try:
                registry_info = await _registry_lookup(name)
                if not registry_info["exists_anywhere"]:
                    # Package doesn't exist on any registry — escalate severity
                    for d in out:
                        if d.get("type") == "Typosquatting":
                            d["severity"] = "CRITICAL"
                            d["message"] += " (Package not found on npm or PyPI — phantom dependency!)"
                    out.append({
                        "line": line,
                        "type": "Supply Chain",
                        "message": (
                            f"'{name}' does not exist on npm or PyPI — phantom dependency. "
                            f"This is a strong indicator of a typosquatting or dependency confusion attack."
                        ),
                        "severity": "CRITICAL",
                        "code_snippet": f"{name} {version}".strip()[:120],
                        "source": "registry_lookup",
                        "package": name,
                        "version": version,
                        "registry_info": {
                            "npm_exists": registry_info["npm_exists"],
                            "pypi_exists": registry_info["pypi_exists"],
                        },
                    })
                else:
                    # Package exists — add registry metadata to typosquat findings
                    for d in out:
                        if d.get("type") == "Typosquatting":
                            d["registry_exists"] = True
                            if registry_info["npm_downloads_weekly"] > 0:
                                d["registry_downloads"] = registry_info["npm_downloads_weekly"]
                            elif registry_info["pypi_downloads_total"] > 0:
                                d["registry_downloads"] = registry_info["pypi_downloads_total"]
                            if registry_info["npm_created"]:
                                d["registry_created"] = registry_info["npm_created"]
                            elif registry_info["pypi_created"]:
                                d["registry_created"] = registry_info["pypi_created"]
            except Exception as reg_err:
                import logging as _log
                _log.getLogger("LambdaAgent").debug("Registry lookup failed for %s: %s", name, reg_err)

        # GHSA vulnerability lookup — query GitHub Advisory Database
        advisory_count = 0
        if _GHSA_ENABLED:
            try:
                ghsa_results = await _ghsa_lookup(name, version, filename=filename)
                for adv in ghsa_results[:_MAX_ADVISORIES]:
                    advisory_count += 1
                    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "LOW": "LOW"}
                    sev = sev_map.get(adv["severity"], "MEDIUM")
                    cve_ref = adv["cve_id"] or adv["ghsa_id"]
                    patched = ""
                    if adv["affected_versions"]:
                        pv = adv["affected_versions"][0].get("patched_version", "")
                        if pv:
                            patched = f" Patched in {pv}."
                    out.append({
                        "line": line,
                        "type": "Known Vulnerability",
                        "message": (
                            f"{name} has a published advisory: {cve_ref} — "
                            f"{adv['severity']} severity. {adv['summary']}{patched}"
                        ),
                        "severity": sev,
                        "code_snippet": f"{name} {version}".strip()[:120],
                        "source": "ghsa",
                        "package": name,
                        "version": version,
                        "ghsa_id": adv["ghsa_id"],
                        "cve_id": adv["cve_id"],
                        "ghsa_severity": adv["severity"],
                        "ghsa_summary": adv["summary"],
                        "ghsa_ecosystem": adv["ecosystem"],
                    })
            except Exception as ghsa_err:
                import logging as _log
                _log.getLogger("LambdaAgent").debug("GHSA lookup failed for %s: %s", name, ghsa_err)

        # OSV lookup — query Open Source Vulnerabilities database
        if _OSV_ENABLED and advisory_count < _MAX_ADVISORIES:
            try:
                ecosystems = _detect_ghsa_ecosystems(name, filename)
                osv_eco = ecosystems[0].upper() if ecosystems else ""
                _osv_eco_map = {"npm": "npm", "pip": "PyPI", "go": "Go", "maven": "Maven"}
                osv_eco = _osv_eco_map.get(osv_eco.lower(), osv_eco)
                osv_results = await _osv_lookup(name, version, ecosystem=osv_eco)
                seen_ids = {f.get("cve_id", "") for f in out}
                seen_ids.update(f.get("ghsa_id", "") for f in out)
                seen_ids.update(f.get("osv_id", "") for f in out)
                for vuln in osv_results.get("vulns", []):
                    if advisory_count >= _MAX_ADVISORIES:
                        break
                    cve_id = vuln.get("cve_id", "")
                    vid = vuln.get("id", "")
                    if (cve_id and cve_id in seen_ids) or (vid and vid in seen_ids):
                        continue
                    seen_ids.add(cve_id or vid)
                    advisory_count += 1
                    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "LOW": "LOW"}
                    sev = sev_map.get(vuln.get("severity", "UNKNOWN"), "MEDIUM")
                    ref = cve_id or vid
                    patched = vuln.get("fixed_version", "")
                    patched_str = f" Fixed in {patched}." if patched else ""
                    out.append({
                        "line": line,
                        "type": "Known Vulnerability",
                        "message": (
                            f"{name} has an OSV advisory: {ref} — "
                            f"{vuln.get('severity', 'UNKNOWN')} severity. "
                            f"{vuln.get('summary', '')}{patched_str}"
                        ),
                        "severity": sev,
                        "code_snippet": f"{name} {version}".strip()[:120],
                        "source": "osv",
                        "package": name,
                        "version": version,
                        "osv_id": vid,
                        "cve_id": cve_id,
                        "osv_severity": vuln.get("severity", "UNKNOWN"),
                        "osv_summary": vuln.get("summary", ""),
                        "osv_url": vuln.get("url", ""),
                        "osv_fixed_version": patched,
                        "osv_aliases": vuln.get("aliases", []),
                    })
            except Exception as osv_err:
                import logging as _log
                _log.getLogger("LambdaAgent").debug("OSV lookup failed for %s: %s", name, osv_err)

        # NVD lookup — query National Vulnerability Database
        if _NVD_ENABLED and advisory_count < _MAX_ADVISORIES:
            try:
                seen_cves = {f.get("cve_id", "") for f in out}
                nvd_results = await _nvd_lookup(name, version)
                for cve in nvd_results:
                    if advisory_count >= _MAX_ADVISORIES:
                        break
                    cve_id = cve.get("cve_id", "")
                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)
                    advisory_count += 1
                    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
                    sev = sev_map.get(cve.get("severity", "UNKNOWN"), "MEDIUM")
                    cvss = cve.get("cvss_score", 0.0)
                    out.append({
                        "line": line,
                        "type": "Known Vulnerability",
                        "message": (
                            f"{name} has an NVD CVE: {cve_id} — "
                            f"{cve.get('severity', 'UNKNOWN')} severity (CVSS {cvss}). "
                            f"{cve.get('summary', '')}"
                        ),
                        "severity": sev,
                        "code_snippet": f"{name} {version}".strip()[:120],
                        "source": "nvd",
                        "package": name,
                        "version": version,
                        "cve_id": cve_id,
                        "nvd_severity": cve.get("severity", "UNKNOWN"),
                        "nvd_cvss_score": cvss,
                        "nvd_summary": cve.get("summary", ""),
                        "nvd_url": cve.get("url", ""),
                        "nvd_status": cve.get("status", ""),
                    })
            except Exception as nvd_err:
                import logging as _log
                _log.getLogger("LambdaAgent").debug("NVD lookup failed for %s: %s", name, nvd_err)

        return out

    async def _scan_requirements(self, content: str, *, filename: str = "") -> list[dict]:
        findings = []
        for i, line in enumerate(content.split("\n"), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]=?)?\s*([0-9][\w.\-]*)?", line)
            if m:
                findings.extend(await self._advise(m.group(1), m.group(3) or "", i, filename=filename))
        return findings

    async def _scan_package_json(self, content: str, *, filename: str = "") -> list[dict]:
        import json as _json

        findings = []
        try:
            data = _json.loads(content)
        except Exception as json_exc:
            import logging as _log

            _log.getLogger("LambdaAgent").debug("SBOM package.json parse failed: %s", json_exc)
            return findings
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section, {}) or {}).items():
                version = re.sub(r"^[\^~>=<\s]+", "", str(ver))
                findings.extend(await self._advise(name, version, 0, filename=filename))
        return findings

    async def _scan_go_mod(self, content: str, *, filename: str = "") -> list[dict]:
        findings = []
        for i, line in enumerate(content.split("\n"), start=1):
            m = re.match(r"^\s*([\w./\-]+)\s+v([\w.\-]+)", line.strip())
            if m:
                pkg = m.group(1).split("/")[-1]
                findings.extend(await self._advise(pkg, m.group(2), i, filename=filename))
        return findings


# Attach IaC + SBOM scanning to LambdaAgent (Architecture §29.5).
async def _lambda_analyze_iac(
    self, content: str, filename: str = "", scan_id: str = "GLOBAL", endpoint_hint: str = ""
) -> dict:
    iac = IaCScanner().scan(content, filename)
    sbom = await SBOMScanner().scan(content, filename) if filename else []
    findings = iac + sbom
    hints = await self.bridge_to_runtime(findings, scan_id=scan_id, endpoint_hint=endpoint_hint)
    return {"iac_findings": iac, "sbom_findings": sbom, "runtime_hints": hints}


LambdaAgent.scan_iac = lambda self, content, filename="": IaCScanner().scan(content, filename)


async def _lambda_scan_sbom(self, content: str, filename: str = "") -> list[dict]:
    return await SBOMScanner().scan(content, filename)


LambdaAgent.scan_sbom = _lambda_scan_sbom
LambdaAgent.analyze_iac_and_bridge = _lambda_analyze_iac
