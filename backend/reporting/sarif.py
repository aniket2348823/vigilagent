from typing import Any


def findings_to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules = {}
    results = []
    for finding in findings:
        raw_cwe = finding.get("cwe", ["VULAGENT"])
        rule_id = raw_cwe[0] if isinstance(raw_cwe, list) and raw_cwe else str(raw_cwe) if raw_cwe else finding.get("vuln_type", "VULAGENT")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.get("title") or finding.get("name") or rule_id,
            "shortDescription": {"text": finding.get("description", "")[:200]},
            "properties": {"severity": finding.get("severity", "warning")},
        })
        uri = finding.get("affected_component") or finding.get("url") or finding.get("endpoint") or "target"
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding.get("severity", "")),
            "message": {"text": finding.get("description") or finding.get("title") or "Security finding"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vigilagent",
                    "informationUri": "https://owasp.org/API-Security/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def _sarif_level(severity: str) -> str:
    sev = str(severity).lower()
    if sev in {"critical", "high"}:
        return "error"
    if sev == "medium":
        return "warning"
    return "note"
