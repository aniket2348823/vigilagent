import logging

"""
PROBLEM 18 FIX: Lambda Agent — PRE-CODE SCANNER
Detects vulnerabilities in source code before deployment.
Layer 1: Regex pattern scan (fast, broad)
Layer 2: AST deep scan (Python only, structural analysis)
"""

import ast
import re

logger = logging.getLogger(__name__)


class LambdaAgent:
    """PRE-CODE SCANNER — Detects vulnerabilities in source code before deployment.

    Exposes the same lifecycle interface as BaseAgent subclasses
    (name, start, stop) so the orchestrator can activate and deactivate
    it without special-casing.
    """

    name = "agent_lambda"

    PATTERNS = [
        {
            "type": "SQL Injection",
            "pattern": r'(execute|cursor\.execute)\s*\(\s*["\'].*[\+%]',
            "message": "String concatenation in SQL query. Use parameterized queries.",
            "severity": "CRITICAL",
        },
        {
            "type": "Hardcoded Secret",
            "pattern": r'(password|secret|api_key|token|key)\s*=\s*["\'][^"\']{6,}["\']',
            "message": "Hardcoded secret detected. Use environment variables.",
            "severity": "HIGH",
        },
        {
            "type": "Command Injection",
            "pattern": r"(os\.system|subprocess\.call|subprocess\.run)\s*\(.*shell\s*=\s*True",
            "message": "shell=True with dynamic input enables command injection.",
            "severity": "CRITICAL",
        },
        {
            "type": "Insecure Deserialization",
            "pattern": r"pickle\.loads\s*\(|yaml\.load\s*\([^,)]+\)",
            "message": "Unsafe deserialization. Use pickle with caution or yaml.safe_load.",
            "severity": "HIGH",
        },
        {
            "type": "XSS Risk",
            "pattern": r"render_template_string\s*\(.*request\.",
            "message": "User input in template render — potential XSS.",
            "severity": "HIGH",
        },
        {
            "type": "Path Traversal",
            "pattern": r"open\s*\(\s*.*request\.",
            "message": "User input in file open — path traversal risk.",
            "severity": "HIGH",
        },
        {
            "type": "Weak Crypto",
            "pattern": r"hashlib\.md5|hashlib\.sha1",
            "message": "MD5/SHA1 are cryptographically broken. Use SHA-256 or better.",
            "severity": "MEDIUM",
        },
        {
            "type": "Debug Mode",
            "pattern": r"debug\s*=\s*True|DEBUG\s*=\s*True",
            "message": "Debug mode enabled. Disable before production.",
            "severity": "MEDIUM",
        },
        {
            "type": "SSRF Risk",
            "pattern": r"requests\.(get|post|put|delete)\s*\(\s*.*request\.",
            "message": "User input directly in HTTP request — potential SSRF.",
            "severity": "HIGH",
        },
        {
            "type": "Insecure Random",
            "pattern": r"random\.random\(\)|random\.randint\(",
            "message": "Using non-cryptographic random for security-sensitive operation. Use secrets module.",
            "severity": "MEDIUM",
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
        logger.info(f"🤖 {self.name} is ONLINE. Intelligence backbone synced.")

    async def stop(self):
        """Stop the agent (BaseAgent-compatible lifecycle)."""
        self._is_active = False
        self.active = False
        logger.info(f"💤 {self.name} is OFFLINE.")

    async def analyze(self, code: str, language: str = "python") -> list[dict]:
        """Analyze source code for security vulnerabilities."""
        findings = []
        lines = code.split("\n")

        # Layer 1 — Regex pattern scan (all languages)
        for i, line in enumerate(lines, start=1):
            for rule in self.PATTERNS:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    findings.append(
                        {
                            "line": i,
                            "type": rule["type"],
                            "message": rule["message"],
                            "severity": rule["severity"],
                            "code_snippet": line.strip()[:120],
                            "source": "regex",
                        }
                    )

        # Layer 2 — AST deep scan (Python only)
        if language == "python":
            try:
                tree = ast.parse(code)
                findings.extend(self._ast_scan(tree))
            except SyntaxError:
                pass  # incomplete code while typing — skip silently

        # Deduplicate by (line, type)
        seen = set()
        unique = []
        for f in findings:
            key = (f["line"], f["type"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _ast_scan(self, tree) -> list[dict]:
        """Deep structural analysis of Python AST."""
        findings = []
        for node in ast.walk(tree):
            # eval() / exec() usage
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                    findings.append(
                        {
                            "line": node.lineno,
                            "type": "Code Injection",
                            "message": f"{node.func.id}() with dynamic input is dangerous.",
                            "severity": "CRITICAL",
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
                            "code_snippet": f"__import__() at line {node.lineno}",
                            "source": "ast",
                        }
                    )

            # Assert usage (disabled in optimized Python)
            if isinstance(node, ast.Assert):
                findings.append(
                    {
                        "line": node.lineno,
                        "type": "Unreliable Security Check",
                        "message": "assert statements are disabled with python -O. Do not use for security checks.",
                        "severity": "MEDIUM",
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
                            findings.append(
                                {
                                    "line": node.lineno,
                                    "type": "Hardcoded Secret (AST)",
                                    "message": f"Sensitive variable '{target.id}' assigned a string literal.",
                                    "severity": "HIGH",
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
        self, code: str, *, language: str = "python", scan_id: str = "GLOBAL", endpoint_hint: str = ""
    ) -> dict:
        """Run SAST and immediately bridge dangerous findings to runtime
        validation (Architecture §29.5)."""
        findings = await self.analyze(code, language=language)
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


class SBOMScanner:
    """Dependency / SBOM analyzer (Architecture §29.5).

    Parses dependency manifests (requirements.txt, package.json, go.mod, etc.)
    and flags unpinned versions and a small built-in set of known-risky packages.
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

    def scan(self, content: str, filename: str = "") -> list[dict]:
        f = (filename or "").lower()
        if f.endswith("requirements.txt") or ("==" in content and "{" not in content and f.endswith(".txt")):
            return self._scan_requirements(content)
        if f.endswith("package.json") or '"dependencies"' in content:
            return self._scan_package_json(content)
        if f.endswith("go.mod") or content.lstrip().startswith("module "):
            return self._scan_go_mod(content)
        # Best-effort: try requirements style.
        return self._scan_requirements(content)

    def _advise(self, name: str, version: str, line: int) -> list[dict]:
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
        return out

    def _scan_requirements(self, content: str) -> list[dict]:
        findings = []
        for i, line in enumerate(content.split("\n"), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]=?)?\s*([0-9][\w.\-]*)?", line)
            if m:
                findings.extend(self._advise(m.group(1), m.group(3) or "", i))
        return findings

    def _scan_package_json(self, content: str) -> list[dict]:
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
                findings.extend(self._advise(name, version, 0))
        return findings

    def _scan_go_mod(self, content: str) -> list[dict]:
        findings = []
        for i, line in enumerate(content.split("\n"), start=1):
            m = re.match(r"^\s*([\w./\-]+)\s+v([\w.\-]+)", line.strip())
            if m:
                pkg = m.group(1).split("/")[-1]
                findings.extend(self._advise(pkg, m.group(2), i))
        return findings


# Attach IaC + SBOM scanning to LambdaAgent (Architecture §29.5).
async def _lambda_analyze_iac(
    self, content: str, filename: str = "", scan_id: str = "GLOBAL", endpoint_hint: str = ""
) -> dict:
    iac = IaCScanner().scan(content, filename)
    sbom = SBOMScanner().scan(content, filename) if filename else []
    findings = iac + sbom
    hints = await self.bridge_to_runtime(findings, scan_id=scan_id, endpoint_hint=endpoint_hint)
    return {"iac_findings": iac, "sbom_findings": sbom, "runtime_hints": hints}


LambdaAgent.scan_iac = lambda self, content, filename="": IaCScanner().scan(content, filename)
LambdaAgent.scan_sbom = lambda self, content, filename="": SBOMScanner().scan(content, filename)
LambdaAgent.analyze_iac_and_bridge = _lambda_analyze_iac
