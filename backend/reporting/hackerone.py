from typing import Any


def render_hackerone_report(finding: dict[str, Any]) -> str:
    # Real findings carry the vuln class in ``type``/``vuln_type`` (not
    # ``title``/``name``) — fall back through all of them so the report title
    # names the actual vulnerability instead of the generic placeholder.
    title = (
        finding.get("title")
        or finding.get("name")
        or finding.get("type")
        or finding.get("vuln_type")
        or "Security Finding"
    )
    severity = finding.get("severity", "medium")
    target = finding.get("affected_target") or finding.get("url") or finding.get("endpoint") or "N/A"
    steps = finding.get("steps_to_reproduce") or []
    if not steps and finding.get("evidence"):
        steps = ["Review the attached evidence.", "Replay the captured request.", "Observe the vulnerable behavior."]
    steps_md = "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(steps))
    return f"""# {title}

## Summary
{finding.get("description", "A verified vulnerability was identified.")}

## Affected Asset
{target}

## Severity
{severity}

## Steps To Reproduce
{steps_md or "1. Reproduce with the captured request and payload."}

## Impact
{finding.get("impact", "An attacker may be able to abuse this weakness depending on exposed privileges and data.")}

## Evidence
{finding.get("evidence", "See scanner evidence bundle.")}

## Remediation
{finding.get("remediation", "Apply input validation, authorization checks, and regression tests for this class of issue.")}
"""
