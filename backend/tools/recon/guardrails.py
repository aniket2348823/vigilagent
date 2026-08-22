"""
Alpha V6 Command Guardrails — Adapted from CAI guardrails patterns.

Validates commands before execution to prevent dangerous operations.
All commands go through this validation layer before reaching subprocess.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import unicodedata
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class GuardrailResult:
    allowed: bool
    reason: str = ""
    sanitized_command: str = ""


# Dangerous command patterns (adapted from CAI generic_linux_command.py)
_DANGEROUS_PATTERNS = [
    (r"(?i)rm\s+-rf\s+/", "recursive_root_deletion"),
    (r"(?i):()\{\s*:\|\:&\s*\};:", "fork_bomb"),
    (r"(?i)curl.*\|.*sh", "curl_pipe_shell"),
    (r"(?i)wget.*\|.*bash", "wget_pipe_bash"),
    (r"(?i)nc\s+[\d\.]+\s+\d+.*(-e|/bin/sh|/bin/bash)", "netcat_reverse_shell"),
    (r"(?i)bash.*-i.*>&.*tcp/", "bash_reverse_shell"),
    (r"(?i)/dev/tcp/[\d\.]+/\d+", "bash_network_redirect"),
    (r"(?i)echo.*\|.*bash", "echo_pipe_bash"),
    (r"(?i)socat\s+TCP:[\d\.]+:\d+.*EXEC", "socat_reverse_shell"),
    (r"(?i)mkfifo.*nc\s+", "fifo_reverse_shell"),
    (r"(?i)python.*-c.*import\s+socket", "python_reverse_shell"),
    (r"(?i)perl.*-e.*socket", "perl_reverse_shell"),
    (r"(?i)php.*-r.*fsockopen", "php_reverse_shell"),
]

# Unicode homograph map (adapted from CAI)
_HOMOGRAPH_MAP = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0425": "X",
    "\u03b1": "a",
    "\u03bf": "o",
    "\u03c1": "p",
}

# Commands that should NEVER be in an argv array (shell-only constructs)
_SHELL_CONSTRUCTS = ["|", "&&", "||", ";", "$(", "`", ">", "<", ">>", "<<"]


def validate_command(argv: tuple[str, ...] | list[str], *, allow_shell: bool = False) -> GuardrailResult:
    """Validate a command argv array before execution."""
    if not argv:
        return GuardrailResult(allowed=False, reason="empty_command")

    binary = argv[0] if argv else ""
    full_cmd = " ".join(str(a) for a in argv)

    # 1. Check for Unicode homograph attacks
    has_homographs = any(c in full_cmd for c in _HOMOGRAPH_MAP)
    if has_homographs:
        normalized = full_cmd
        for hg, repl in _HOMOGRAPH_MAP.items():
            normalized = normalized.replace(hg, repl)
        normalized = unicodedata.normalize("NFKD", normalized)
        return GuardrailResult(allowed=False, reason=f"unicode_homograph_detected:{binary}")

    # 2. Check for shell constructs in argv (should never be there)
    if not allow_shell:
        for arg in argv:
            for construct in _SHELL_CONSTRUCTS:
                if construct in str(arg) and str(arg) != construct:
                    # Allow pipes/redirects as standalone args only in special cases
                    pass
            # Full shell string detection. NOTE: `;` inside a single argv token
            # is NOT a shell construct when the token is passed as a literal
            # argument to exec (never interpolated). HTTP header values such as
            # `Cookie: PHPSESSID=x; security=low` legitimately contain `;` — the
            # seeder's authenticated session MUST be forwardable to nuclei/
            # whatweb/wafw00f. Only the pipe/command-substitution constructs are
            # shell-significant in an argv array.
            if any(c in str(arg) for c in ["|", "$(", "`"]):
                return GuardrailResult(allowed=False, reason=f"shell_construct_in_argv:{arg[:50]}")

    # 3. Check dangerous patterns
    for pattern, name in _DANGEROUS_PATTERNS:
        if re.search(pattern, full_cmd):
            return GuardrailResult(allowed=False, reason=f"dangerous_pattern:{name}")

    # 4. Check for base64 encoded payloads
    if "base64" in full_cmd.lower() and ("-d" in full_cmd or "--decode" in full_cmd):
        b64_match = re.search(r"([A-Za-z0-9+/=]{20,})", full_cmd)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", "ignore")
                for pattern, name in _DANGEROUS_PATTERNS:
                    if re.search(pattern, decoded):
                        return GuardrailResult(allowed=False, reason=f"encoded_dangerous_pattern:{name}")
            except Exception as e:
                import logging as _log

                _log.debug("Base64 decode check failed: %s", e)

    # 5. Validate binary is a known recon tool (Architecture §7, 39-tool matrix)
    known_binaries = {
        "subfinder",
        "amass",
        "assetfinder",
        "gau",
        "waybackurls",
        "cloudlist",
        "spiderfoot",
        "github-subdomains",
        "dnsx",
        "puredns",
        "cdncheck",
        "naabu",
        "masscan",
        "nmap",
        "tlsx",
        "testssl.sh",
        "httpx",
        "whatweb",
        "wafw00f",
        "katana",
        "gospider",
        "arjun",
        "paramspider",
        "linkfinder",
        "secretfinder",
        "feroxbuster",
        "ffuf",
        "gobuster",
        "kr",
        "kiterunner",
        "gowitness",
        "nuclei",
        "dalfox",
        "sqlmap",
        "nikto",
        "wpscan",
        "dnsgen",
        "interactsh-client",
        "inql",
        "python",
        "python3",
        "massdns",
    }
    base_binary = os.path.basename(binary).lower()
    if base_binary not in known_binaries:
        return GuardrailResult(allowed=False, reason=f"unknown_binary:{base_binary}")

    return GuardrailResult(allowed=True, sanitized_command=full_cmd)


def validate_output_path(path: str) -> bool:
    """Ensure output paths stay within the scan data directory."""
    normalized = os.path.normpath(path)
    # Block path traversal
    if ".." in normalized:
        return False
    # Must be under data/scans or a temp dir
    # FIX-019: Restrict to project-specific scan directories only
    # Check if path contains allowed directories as components (handles Windows paths)
    path_parts = normalized.split(os.sep)
    allowed_dirs = {"data", "scan_states"}
    if any(part in allowed_dirs for part in path_parts):
        return True
    return "scans" in normalized
