"""
Skill -> agent + tool mapper (Architecture §5.3.5)
================================================================================
Maps a skill (by domain) to the agents that should receive it, following the
agent skill routing rules in Architecture §5.3.5.
"""

from __future__ import annotations

# Domain -> agents (Architecture §5.3.5 routing rules).
_DOMAIN_AGENTS: dict[str, list[str]] = {
    "web_api_testing": ["Sigma", "Beta", "Gamma", "Prism"],
    "recon_network": ["Alpha", "NetworkCommander"],
    "active_directory": ["NetworkCommander", "Sigma", "Gamma"],
    "cloud": ["Lambda", "Gamma"],
    "container_kubernetes": ["Lambda", "Gamma"],
    "mobile": ["Delta", "Prism", "Sigma"],
    "malware_re": ["Lambda", "Gamma"],
    "forensics_ir": ["Gamma"],
    "detection_engineering": ["Lambda", "ReportingCommander"],
    "threat_intelligence": ["Kappa", "ReportingCommander"],
    "hardening_remediation": ["Lambda"],
    "reporting_governance": ["ReportingCommander"],
    "uncategorized": ["Omega"],
}

# Coarse routing rules from §5.3.5 (agent -> domains they own), used to validate.
AGENT_DOMAINS = {
    "Alpha": ["recon_network"],
    "Beta": ["web_api_testing"],
    "Gamma": ["forensics_ir", "web_api_testing"],
    "Omega": ["uncategorized"],
    "Sigma": ["web_api_testing", "active_directory", "cloud"],
    "Kappa": ["threat_intelligence"],
    "Zeta": [],
    "Delta": ["mobile"],
    "Chi": [],
    "Prism": ["web_api_testing", "mobile"],
    "Lambda": ["cloud", "container_kubernetes", "malware_re", "detection_engineering", "hardening_remediation"],
}


def agents_for_domain(domain: str) -> list[str]:
    return list(_DOMAIN_AGENTS.get(domain, _DOMAIN_AGENTS["uncategorized"]))


def map_required_tools(meta_text: str) -> list[str]:
    """Best-effort extraction of required tools mentioned in skill text."""
    text = meta_text.lower()
    known = [
        "nmap",
        "naabu",
        "httpx",
        "katana",
        "ffuf",
        "feroxbuster",
        "dirsearch",
        "gobuster",
        "nuclei",
        "tlsx",
        "subfinder",
        "amass",
        "gau",
        "waybackurls",
        "gowitness",
        "sqlmap",
        "nikto",
        "masscan",
        "testssl",
        "sslyze",
        "enum4linux",
        "smbclient",
        "ldapsearch",
        "impacket",
        "bloodhound",
        "trivy",
        "grype",
        "kube-bench",
        "kubesec",
        "volatility",
        "wireshark",
        "tshark",
        "zeek",
        "yara",
        "frida",
        "objection",
        "jadx",
        "mobsf",
        "ghidra",
    ]
    return [t for t in known if t in text]
