"""
Skill domain + risk classifier (Architecture §5.3.2, §5.3.3)
================================================================================
Classifies a skill into a Vigilagent domain (§5.3.2) and assigns a risk class
(§5.3.3) from its name/description/metadata. Deterministic keyword heuristics;
no LLM required (keeps ingestion offline-safe).
"""

from __future__ import annotations

from backend.skills.policy import RiskClass

# Domain -> keyword signals (Architecture §5.3.2 skill categories).
_DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "web_api_testing": [
        "api",
        "bola",
        "mass assignment",
        "xss",
        "xxe",
        "cors",
        "host header",
        "websocket",
        "graphql",
        "auth",
        "idor",
        "ssrf",
    ],
    "recon_network": [
        "osint",
        "subfinder",
        "nmap",
        "dns enumeration",
        "tls",
        "wireless",
        "recon",
        "port scan",
        "amass",
        "naabu",
    ],
    "active_directory": [
        "bloodhound",
        "kerberoast",
        "adcs",
        "esc1",
        "acl abuse",
        "dcsync",
        "active directory",
        "ldap",
        "kerberos",
    ],
    "cloud": ["aws", "azure", "gcp", "iam", "s3", "guardduty", "cloudtrail", "cloud"],
    "container_kubernetes": [
        "trivy",
        "grype",
        "kube-bench",
        "kubesec",
        "rbac",
        "kubernetes",
        "falco",
        "container",
        "docker",
    ],
    "mobile": ["android", "ios", "frida", "objection", "jadx", "mobsf", "mobile"],
    "malware_re": [
        "ghidra",
        "dnspy",
        "volatility",
        "cuckoo",
        "yara",
        "macro",
        "reverse engineering",
        "malware",
        "disassembl",
    ],
    "forensics_ir": [
        "disk",
        "memory",
        "mft",
        "registry",
        "prefetch",
        "zeek",
        "splunk",
        "timesketch",
        "forensic",
        "incident",
    ],
    "detection_engineering": ["sigma rule", "splunk spl", "suricata", "snort", "siem", "detection", "mitre mapping"],
    "threat_intelligence": ["misp", "opencti", "stix", "taxii", "ioc", "actor profil"],
    "hardening_remediation": ["zero trust", "hardening", "waf", "remediation", "harden", "mitigation"],
    "reporting_governance": ["cvss", "ssvc", "sla", "compliance", "exception", "dashboard", "report"],
}

# Risk signals (Architecture §5.3.3). Order matters: most dangerous first.
_DISABLED_SIGNALS = [
    "persistence",
    "stealth",
    "destructive",
    "credential theft",
    "malware deployment",
    "lateral movement",
    "ransomware",
    "log wiping",
    "c2",
    "reverse shell",
    "rootkit",
]
_INTRUSIVE_SIGNALS = [
    "exploit",
    "rce",
    "privilege escalation",
    "buffer overflow",
    "deserialization",
    "command injection",
    "sqli dump",
]
_CONTROLLED_SIGNALS = [
    "xss",
    "idor",
    "bola",
    "validate",
    "proof of concept",
    "injection test",
    "auth bypass test",
    "cors test",
]
_ACTIVE_RECON_SIGNALS = ["scan", "nmap", "naabu", "fuzz", "enumerate", "probe", "directory brute", "subdomain"]
_PASSIVE_SIGNALS = ["osint", "passive", "public data", "whois", "certificate transparency"]


def classify_domain(meta_text: str) -> str:
    text = meta_text.lower()
    best_domain = "uncategorized"
    best_hits = 0
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text)
        if hits > best_hits:
            best_hits, best_domain = hits, domain
    return best_domain


def classify_risk(meta_text: str, *, offensive_hint: bool = False) -> RiskClass:
    text = meta_text.lower()
    if any(sig in text for sig in _DISABLED_SIGNALS):
        return RiskClass.DISABLED_BY_DEFAULT
    if any(sig in text for sig in _INTRUSIVE_SIGNALS):
        return RiskClass.INTRUSIVE_VALIDATION
    if any(sig in text for sig in _CONTROLLED_SIGNALS):
        return RiskClass.CONTROLLED_VALIDATION
    if any(sig in text for sig in _ACTIVE_RECON_SIGNALS):
        return RiskClass.ACTIVE_RECON
    if any(sig in text for sig in _PASSIVE_SIGNALS):
        return RiskClass.PASSIVE_RECON
    # Default: analysis-only is the safest assumption.
    return RiskClass.ANALYSIS_ONLY


def is_offensive(meta_text: str) -> bool:
    text = meta_text.lower()
    return any(sig in text for sig in (_INTRUSIVE_SIGNALS + _CONTROLLED_SIGNALS + _DISABLED_SIGNALS))


def needs_network(meta_text: str) -> bool:
    text = meta_text.lower()
    return any(kw in text for kw in ["http", "scan", "request", "api", "dns", "network", "remote", "url", "target"])
