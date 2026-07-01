"""
MITRE ATT&CK Technique Tagger for Vigilagent
=============================================
Maps vulnerability types discovered during scanning to their corresponding
MITRE ATT&CK Enterprise techniques and tactics. Each finding is enriched with:
  - technique_id: e.g. "T1190"
  - technique_name: e.g. "Exploit Public-Facing Application"
  - tactic: e.g. "initial-access"
  - tactic_id: e.g. "TA0001"
  - kill_chain_phase: e.g. "exploitation"
  - sub_techniques: list of related sub-techniques when applicable
  - reference_url: link to ATT&CK page

Based on MITRE ATT&CK v15 (2024).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("MitreTagger")


@dataclass
class MitreTag:
    """A single MITRE ATT&CK tag applied to a vulnerability finding."""

    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    kill_chain_phase: str
    sub_techniques: list[str] = field(default_factory=list)
    reference_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "kill_chain_phase": self.kill_chain_phase,
            "sub_techniques": self.sub_techniques,
            "reference_url": self.reference_url,
        }


# ══════════════════════════════════════════════════════════════════════════════
# VULN TYPE → MITRE ATT&CK MAPPING
# ══════════════════════════════════════════════════════════════════════════════
# Keys are lowercase vuln type strings (as produced by evidence.py, sigma, beta, etc.)
# Values are lists of MitreTag (a vuln may map to multiple techniques).

_VULN_TO_MITRE: dict[str, list[MitreTag]] = {
    # ── SQL Injection ──
    "sqli": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
        MitreTag(
            technique_id="T1059.008",
            technique_name="Command and Scripting Interpreter: SQL",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            sub_techniques=["T1059.008"],
            reference_url="https://attack.mitre.org/techniques/T1059/008/",
        ),
    ],
    "sql injection": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── XSS ──
    "xss": [
        MitreTag(
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1189/",
        ),
        MitreTag(
            technique_id="T1059.007",
            technique_name="Command and Scripting Interpreter: JavaScript",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            sub_techniques=["T1059.007"],
            reference_url="https://attack.mitre.org/techniques/T1059/007/",
        ),
    ],
    "cross-site scripting": [
        MitreTag(
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1189/",
        ),
    ],
    "dom xss": [
        MitreTag(
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1189/",
        ),
    ],
    "reflected xss": [
        MitreTag(
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1189/",
        ),
    ],
    "stored xss": [
        MitreTag(
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1189/",
        ),
        MitreTag(
            technique_id="T1565.001",
            technique_name="Data Manipulation: Stored Data Manipulation",
            tactic="impact",
            tactic_id="TA0040",
            kill_chain_phase="actions-on-objectives",
            reference_url="https://attack.mitre.org/techniques/T1565/001/",
        ),
    ],
    # ── Command Injection ──
    "cmdi": [
        MitreTag(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1059/",
        ),
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    "command injection": [
        MitreTag(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1059/",
        ),
    ],
    # ── Path Traversal / LFI ──
    "path traversal": [
        MitreTag(
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            tactic="discovery",
            tactic_id="TA0007",
            kill_chain_phase="discovery",
            reference_url="https://attack.mitre.org/techniques/T1083/",
        ),
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    "lfi": [
        MitreTag(
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            tactic="discovery",
            tactic_id="TA0007",
            kill_chain_phase="discovery",
            reference_url="https://attack.mitre.org/techniques/T1083/",
        ),
    ],
    # ── IDOR ──
    "idor": [
        MitreTag(
            technique_id="T1213",
            technique_name="Data from Information Repositories",
            tactic="collection",
            tactic_id="TA0009",
            kill_chain_phase="actions-on-objectives",
            reference_url="https://attack.mitre.org/techniques/T1213/",
        ),
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── SSRF ──
    "ssrf": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
        MitreTag(
            technique_id="T1552.005",
            technique_name="Unsecured Credentials: Cloud Instance Metadata API",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1552/005/",
        ),
    ],
    # ── SSTI ──
    "ssti": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── Auth Bypass ──
    "auth bypass": [
        MitreTag(
            technique_id="T1557",
            technique_name="Adversary-in-the-Middle",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1557/",
        ),
        MitreTag(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="persistence",
            tactic_id="TA0003",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1078/",
        ),
    ],
    # ── JWT ──
    "jwt": [
        MitreTag(
            technique_id="T1557",
            technique_name="Adversary-in-the-Middle",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1557/",
        ),
    ],
    # ── Brute Force ──
    "brute force": [
        MitreTag(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="exploitation",
            sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
            reference_url="https://attack.mitre.org/techniques/T1110/",
        ),
    ],
    # ── Hardcoded Secret / Data Leak ──
    "hardcoded secret": [
        MitreTag(
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials In Files",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="discovery",
            reference_url="https://attack.mitre.org/techniques/T1552/001/",
        ),
    ],
    "data leak": [
        MitreTag(
            technique_id="T1005",
            technique_name="Data from Local System",
            tactic="collection",
            tactic_id="TA0009",
            kill_chain_phase="actions-on-objectives",
            reference_url="https://attack.mitre.org/techniques/T1005/",
        ),
    ],
    # ── Open Redirect ──
    "open redirect": [
        MitreTag(
            technique_id="T1566",
            technique_name="Phishing",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1566/",
        ),
    ],
    # ── Supply Chain ──
    "supply chain": [
        MitreTag(
            technique_id="T1195",
            technique_name="Supply Chain Compromise",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            sub_techniques=["T1195.001", "T1195.002"],
            reference_url="https://attack.mitre.org/techniques/T1195/",
        ),
    ],
    "vulnerable dependency": [
        MitreTag(
            technique_id="T1195.002",
            technique_name="Supply Chain Compromise: Compromise Software Dependencies",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1195/002/",
        ),
    ],
    "unpinned dependency": [
        MitreTag(
            technique_id="T1195.002",
            technique_name="Supply Chain Compromise: Compromise Software Dependencies",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1195/002/",
        ),
    ],
    # ── Insecure Deserialization ──
    "insecure deserialization": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── Code Injection / RCE ──
    "code injection": [
        MitreTag(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1059/",
        ),
    ],
    "rce": [
        MitreTag(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1059/",
        ),
    ],
    # ── Mass Assignment ──
    "mass assignment": [
        MitreTag(
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic="persistence",
            tactic_id="TA0003",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1098/",
        ),
    ],
    # ── Race Condition ──
    "race condition": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── Workflow Bypass ──
    "workflow bypass": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── Financial Logic ──
    "financial": [
        MitreTag(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1190/",
        ),
    ],
    # ── Weak Crypto ──
    "weak crypto": [
        MitreTag(
            technique_id="T1557",
            technique_name="Adversary-in-the-Middle",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1557/",
        ),
    ],
    # ── Debug Mode ──
    "debug mode": [
        MitreTag(
            technique_id="T1592",
            technique_name="Gather Victim Host Information",
            tactic="reconnaissance",
            tactic_id="TA0043",
            kill_chain_phase="reconnaissance",
            reference_url="https://attack.mitre.org/techniques/T1592/",
        ),
    ],
    # ── Insecure Random ──
    "insecure random": [
        MitreTag(
            technique_id="T1552.006",
            technique_name="Unsecured Credentials: Group Policy Preferences",
            tactic="credential-access",
            tactic_id="TA0006",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1552/006/",
        ),
    ],
    # ── Prompt Injection (AI-specific) ──
    "prompt injection": [
        MitreTag(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            tactic_id="TA0002",
            kill_chain_phase="exploitation",
            reference_url="https://attack.mitre.org/techniques/T1059/",
        ),
    ],
    # ── Dark Pattern ──
    "dark pattern": [
        MitreTag(
            technique_id="T1566",
            technique_name="Phishing",
            tactic="initial-access",
            tactic_id="TA0001",
            kill_chain_phase="delivery",
            reference_url="https://attack.mitre.org/techniques/T1566/",
        ),
    ],
}


def _normalize_vuln_type(vuln_type: str) -> str:
    """Normalize a vuln type string for lookup (lowercase, strip whitespace)."""
    return vuln_type.strip().lower().replace("_", " ")


def tag_finding(vuln_type: str) -> list[MitreTag]:
    """Look up MITRE ATT&CK tags for a given vulnerability type.

    Returns a list of MitreTag objects. Falls back to a generic
    'Exploit Public-Facing Application' tag if no specific mapping exists.
    """
    key = _normalize_vuln_type(vuln_type)
    tags = _VULN_TO_MITRE.get(key)

    if not tags:
        # Fallback: generic initial-access exploitation
        tags = [
            MitreTag(
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="initial-access",
                tactic_id="TA0001",
                kill_chain_phase="exploitation",
                reference_url="https://attack.mitre.org/techniques/T1190/",
            )
        ]

    return tags


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Enrich a vulnerability finding dict with MITRE ATT&CK tags.

    Modifies the finding in-place and returns it. Adds a ``mitre`` key
    containing a list of technique dicts.
    """
    vuln_type = finding.get("type", "") or finding.get("vuln_type", "")
    if not vuln_type:
        return finding

    tags = tag_finding(vuln_type)
    finding["mitre"] = [t.to_dict() for t in tags]

    # Convenience fields for quick access
    if tags:
        finding["mitre_technique"] = tags[0].technique_id
        finding["mitre_tactic"] = tags[0].tactic_id
        finding["kill_chain_phase"] = tags[0].kill_chain_phase

    return finding


def get_all_techniques() -> dict[str, list[str]]:
    """Return a summary of all mapped techniques grouped by tactic.

    Useful for ATT&CK coverage analysis.
    """
    by_tactic: dict[str, list[str]] = {}
    for tags in _VULN_TO_MITRE.values():
        for tag in tags:
            if tag.tactic_id not in by_tactic:
                by_tactic[tag.tactic_id] = []
            label = f"{tag.technique_id} ({tag.technique_name})"
            if label not in by_tactic[tag.tactic_id]:
                by_tactic[tag.tactic_id].append(label)
    return by_tactic
