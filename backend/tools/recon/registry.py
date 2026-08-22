"""Unified Tool Registry — 34 Recon (Alpha) + 5 Validation (Sigma) = 39 Tools.

Architecture §7, §5.1.1, §5.2:

  RECON_TOOLS (34) — owned exclusively by Alpha, the recon commander.
  SIGMA_TOOLS (5)  — owned exclusively by Sigma, the validation/exploitation
                     commander (nuclei, httpx, dalfox, whatweb, wafw00f).

All 39 tools live in the same Docker recon image but are dispatched by different
agents. Alpha never calls Sigma tools; Sigma never calls recon tools. The
check_tool_availability() function resolves from BOTH dicts so any caller can
verify install state regardless of ownership.

Binaries resolve from PATH first, then the project-local recon bin
(tools/recon_bin), then ALPHA_TOOL_ROOT (D:\\projects), Go bin, and pip Scripts.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from backend.core.config import settings

logger = logging.getLogger(__name__)


RECON_TOOLS = {
    # ── Phase 1: Passive Intelligence ──────────────────────────────────────
    "subfinder": {
        "phase": "passive_intelligence",
        "binary": "subfinder",
        "modes": ["PASSIVE_ONLY", "STANDARD", "AGGRESSIVE"],
    },
    "amass": {"phase": "passive_intelligence", "binary": "amass", "modes": ["PASSIVE_ONLY", "STANDARD", "AGGRESSIVE"]},
    "assetfinder": {
        "phase": "passive_intelligence",
        "binary": "assetfinder",
        "modes": ["PASSIVE_ONLY", "STANDARD", "AGGRESSIVE"],
    },
    "github-subdomains": {
        "phase": "passive_intelligence",
        "binary": "github-subdomains",
        "modes": ["PASSIVE_ONLY", "STANDARD", "AGGRESSIVE"],
    },
    "gau": {"phase": "passive_intelligence", "binary": "gau", "modes": ["PASSIVE_ONLY", "STANDARD", "AGGRESSIVE"]},
    "waybackurls": {
        "phase": "passive_intelligence",
        "binary": "waybackurls",
        "modes": ["PASSIVE_ONLY", "STANDARD", "AGGRESSIVE"],
    },
    "cloudlist": {"phase": "passive_intelligence", "binary": "cloudlist", "modes": ["STANDARD", "AGGRESSIVE"]},
    "spiderfoot": {"phase": "passive_intelligence", "binary": "python", "modes": ["AGGRESSIVE"]},
    # ── Phase 2: DNS & Infrastructure ──────────────────────────────────────
    "dnsx": {"phase": "dns_infrastructure", "binary": "dnsx", "modes": ["STANDARD", "AGGRESSIVE"]},
    "puredns": {"phase": "dns_infrastructure", "binary": "puredns", "modes": ["AGGRESSIVE"]},
    "massdns": {"phase": "dns_infrastructure", "binary": "massdns", "modes": ["AGGRESSIVE"]},
    "dnsgen": {"phase": "dns_infrastructure", "binary": "dnsgen", "modes": ["AGGRESSIVE"]},
    "cdncheck": {"phase": "dns_infrastructure", "binary": "cdncheck", "modes": ["STANDARD", "AGGRESSIVE"]},
    "naabu": {"phase": "dns_infrastructure", "binary": "naabu", "modes": ["STANDARD", "AGGRESSIVE"]},
    "masscan": {"phase": "dns_infrastructure", "binary": "masscan", "modes": ["AGGRESSIVE"]},
    "nmap": {"phase": "dns_infrastructure", "binary": "nmap", "modes": ["AGGRESSIVE"]},
    "tlsx": {"phase": "dns_infrastructure", "binary": "tlsx", "modes": ["STANDARD", "AGGRESSIVE"]},
    "testssl": {"phase": "dns_infrastructure", "binary": "testssl.sh", "modes": ["AGGRESSIVE"]},
    # ── Phase 3: HTTP & Browser Intelligence ───────────────────────────────
    # NOTE: httpx, whatweb, wafw00f moved to SIGMA_TOOLS (Sigma-exclusive).
    "katana": {"phase": "http_browser_intelligence", "binary": "katana", "modes": ["STANDARD", "AGGRESSIVE"]},
    "gospider": {"phase": "http_browser_intelligence", "binary": "gospider", "modes": ["STANDARD", "AGGRESSIVE"]},
    "linkfinder": {"phase": "http_browser_intelligence", "binary": "python", "modes": ["STANDARD", "AGGRESSIVE"]},
    "secretfinder": {"phase": "http_browser_intelligence", "binary": "python", "modes": ["STANDARD", "AGGRESSIVE"]},
    "arjun": {"phase": "http_browser_intelligence", "binary": "arjun", "modes": ["STANDARD", "AGGRESSIVE"]},
    "paramspider": {"phase": "http_browser_intelligence", "binary": "python", "modes": ["STANDARD", "AGGRESSIVE"]},
    # ── Phase 4: Directory & Route Discovery ───────────────────────────────
    "feroxbuster": {"phase": "directory_route_discovery", "binary": "feroxbuster", "modes": ["STANDARD", "AGGRESSIVE"]},
    "ffuf": {"phase": "directory_route_discovery", "binary": "ffuf", "modes": ["STANDARD", "AGGRESSIVE"]},
    "gobuster": {"phase": "directory_route_discovery", "binary": "gobuster", "modes": ["STANDARD", "AGGRESSIVE"]},
    # ── Phase 5: API Reconnaissance ────────────────────────────────────────
    "kiterunner": {"phase": "api_reconnaissance", "binary": "kr", "modes": ["STANDARD", "AGGRESSIVE"]},
    "inql": {"phase": "api_reconnaissance", "binary": "python", "modes": ["AGGRESSIVE"]},
    # ── Phase 6: Visual Documentation ──────────────────────────────────────
    # NOTE: gowitness v3 ships in the recon image with chromium available, so
    # real screenshots work. aquatone was removed (screenshots broken + gowitness
    # superset).
    "gowitness": {"phase": "visual_documentation", "binary": "gowitness", "modes": ["STANDARD", "AGGRESSIVE"]},
    # ── Phase 7: Template Validation ───────────────────────────────────────
    # NOTE: nuclei, dalfox moved to SIGMA_TOOLS (Sigma-exclusive).
    "interactsh": {"phase": "template_validation", "binary": "interactsh-client", "modes": ["AGGRESSIVE"]},
}


# ═══════════════════════════════════════════════════════════════════════════════
# SIGMA_TOOLS — 5 validation/exploitation tools, owned EXCLUSIVELY by Sigma.
# These live in the same Docker image but are NEVER dispatched by Alpha.
# Sigma uses them for vulnerability validation, fingerprinting, and WAF detection.
# ═══════════════════════════════════════════════════════════════════════════════
SIGMA_TOOLS = {
    # ── Vulnerability Validation (Sigma §5.2, §29.4) ──────────────────────
    "nuclei": {"phase": "sigma_validation", "binary": "nuclei", "modes": ["STANDARD", "AGGRESSIVE"], "owner": "sigma"},
    "dalfox": {"phase": "sigma_validation", "binary": "dalfox", "modes": ["AGGRESSIVE"], "owner": "sigma"},
    "sqlmap": {"phase": "sigma_validation", "binary": "sqlmap", "modes": ["AGGRESSIVE"], "owner": "sigma"},
    "nikto": {"phase": "sigma_validation", "binary": "nikto", "modes": ["STANDARD", "AGGRESSIVE"], "owner": "sigma"},
    "wpscan": {"phase": "sigma_validation", "binary": "wpscan", "modes": ["AGGRESSIVE"], "owner": "sigma"},
    # ── Fingerprinting & WAF Detection (Sigma §5.2) ───────────────────────
    "httpx": {"phase": "sigma_fingerprint", "binary": "httpx", "modes": ["STANDARD", "AGGRESSIVE"], "owner": "sigma"},
    "whatweb": {
        "phase": "sigma_fingerprint",
        "binary": "whatweb",
        "modes": ["STANDARD", "AGGRESSIVE"],
        "owner": "sigma",
    },
    "wafw00f": {
        "phase": "sigma_fingerprint",
        "binary": "wafw00f",
        "modes": ["STANDARD", "AGGRESSIVE"],
        "owner": "sigma",
    },
}

# Pass-alias entries: specialized nuclei/ffuf passes share the parent binary
# but carry distinct tool names so the planner can emit multiple passes of the
# same binary with separate outputs. check_tool_availability() resolves these
# to the parent binary for install-state checks.
_PASS_ALIASES = {
    "nuclei_default_login": {"phase": "template_validation", "binary": "nuclei", "modes": ["STANDARD", "AGGRESSIVE"]},
    "nuclei_cve": {"phase": "template_validation", "binary": "nuclei", "modes": ["STANDARD", "AGGRESSIVE"]},
    "nuclei_takeover": {"phase": "template_validation", "binary": "nuclei", "modes": ["AGGRESSIVE"]},
    "ffuf_vhost": {"phase": "directory_route_discovery", "binary": "ffuf", "modes": ["AGGRESSIVE"]},
}

# Combined registry for availability lookups (35 tools + 4 pass aliases).
ALL_TOOLS = {**RECON_TOOLS, **SIGMA_TOOLS, **_PASS_ALIASES}


def check_tool_availability(name: str) -> dict:
    """Check if a tool is installed and accessible.

    Resolves from ALL_TOOLS (34 recon + 5 Sigma = 39 total) so any caller
    can verify install state regardless of tool ownership.

    Resolution order (Architecture §7 rule 2 + project-local integration):
      1. System PATH.
      2. Project-local recon bin: tools/recon_bin/.
      3. ALPHA_TOOL_ROOT (D:\\projects) — binary, binary.exe, binary/binary.
      4. Go bin (~/go/bin) and Python Scripts dir (pip console scripts).
      5. Vendored Python scripts under the tool root for git-only tools.
    """
    spec = ALL_TOOLS.get(name)
    if not spec:
        return {"installed": False, "reason": f"unknown_tool:{name}"}
    binary = spec["binary"]
    tool_root = Path(getattr(settings, "ALPHA_TOOL_ROOT", r"D:\projects"))
    project_bin = Path(getattr(settings, "PROJECT_ROOT", ".")) / "tools" / "recon_bin"

    # 0. Docker recon image (Architecture §7 rule 3): when Docker + the bundled
    # recon image are ready, every arsenal tool is available with no host
    # install. This is the preferred backend for Linux-native tools on Windows.
    # Pass aliases (nuclei_default_login, ffuf_vhost, ...) resolve via their
    # parent binary (nuclei/ffuf), which IS in the image.
    try:
        from backend.tools.recon.docker_runtime import DOCKER_ALL_TOOLS, docker_recon_ready

        if (name in DOCKER_ALL_TOOLS or binary in DOCKER_ALL_TOOLS) and docker_recon_ready():
            return {"installed": True, "path": "docker://vigilagent-recon", "source": "docker"}
    except Exception as e:
        logger.debug("Docker recon check skipped: %s", e)

    # 1. System PATH
    path = shutil.which(binary)
    if path:
        return {"installed": True, "path": path, "source": "PATH"}

    # 2. Project-local recon bin (in-repo integration)
    for cand in (project_bin / binary, project_bin / f"{binary}.exe"):
        if cand.exists():
            return {"installed": True, "path": str(cand), "source": "project_bin"}

    # 3. Tool root (D:\projects): binary, binary.exe, binary/binary[.exe]
    for cand in (
        tool_root / binary,
        tool_root / f"{binary}.exe",
        tool_root / binary / binary,
        tool_root / binary / f"{binary}.exe",
    ):
        if cand.exists():
            return {"installed": True, "path": str(cand), "source": "tool_root"}

    # 4. Go bin, Python Scripts dir, user-local bins
    import os

    _home = Path(os.path.expanduser("~"))
    go_bin = _home / "go" / "bin"
    local_bin = _home / ".local" / "bin"
    user_tools = _home / "tools"
    for cand in (go_bin / binary, go_bin / f"{binary}.exe", local_bin / binary, local_bin / f"{binary}.exe"):
        if cand.exists():
            return {"installed": True, "path": str(cand), "source": "user_bin"}
    # Also check ~/tools/<ToolName>/<binary> for git-cloned tools
    for subdir in user_tools.iterdir() if user_tools.is_dir() else []:
        for cand in (subdir / binary, subdir / f"{binary}.exe"):
            if cand.exists():
                return {"installed": True, "path": str(cand), "source": "user_tools"}
    try:
        import sysconfig

        scripts_dir = Path(sysconfig.get_path("scripts"))
        for cand in (scripts_dir / binary, scripts_dir / f"{binary}.exe"):
            if cand.exists():
                return {"installed": True, "path": str(cand), "source": "pip_scripts"}
    except Exception as e:
        logger.debug("sysconfig scripts dir check skipped: %s", e)

    # 5. Vendored / git-only Python scripts
    if binary == "python":
        # Check both tool_root (D:\projects), project_bin, and user ~/tools/
        _user_tools = Path(os.path.expanduser("~")) / "tools"
        script_map = {
            "linkfinder": [
                tool_root / "LinkFinder" / "linkfinder.py",
                project_bin / "LinkFinder" / "linkfinder.py",
                _user_tools / "LinkFinder" / "linkfinder.py",
            ],
            "secretfinder": [
                tool_root / "SecretFinder" / "SecretFinder.py",
                project_bin / "SecretFinder" / "SecretFinder.py",
                _user_tools / "SecretFinder" / "SecretFinder.py",
            ],
            "inql": [
                tool_root / "inql" / "inql.py",
                project_bin / "inql" / "inql.py",
                _user_tools / "inql" / "inql.py",
            ],
            "spiderfoot": [
                tool_root / "spiderfoot" / "sf.py",
                project_bin / "spiderfoot" / "sf.py",
                _user_tools / "spiderfoot" / "sf.py",
                _user_tools / "spiderfoot" / "spiderfoot",
            ],
            "paramspider": [
                tool_root / "ParamSpider" / "paramspider.py",
                project_bin / "ParamSpider" / "paramspider.py",
                _user_tools / "ParamSpider" / "paramspider.py",
            ],
            # NOTE: testssl has binary="testssl.sh" (not python), so it's
            # resolved by the user_tools.iterdir() loop in step 4 above.
        }
        for script in script_map.get(name, []):
            if script.exists():
                return {"installed": True, "path": str(script), "source": "python_script"}
        return {"installed": False, "reason": f"script_not_found:{name}"}

    return {"installed": False, "reason": f"binary_not_in_path:{binary}"}
