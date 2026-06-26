from typing import Any


def render_hackerone_report(finding: dict[str, Any]) -> str:
    title = finding.get("title") or finding.get("name") or "Security Finding"
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
