"""
Alpha V6 SARIF & Report Exporter.

Exports recon findings to industry-standard formats:
- SARIF v2.1.0 (Static Analysis Results Interchange Format)
- HackerOne-compatible JSON
- Markdown executive summary
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from backend.agents.alpha_recon.models import ReconRunResult
    from backend.parsers.recon.base import ParsedEntity


class SARIFExporter:
    """Export vulnerability candidates to SARIF v2.1.0 format."""

    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    def export(self, result: ReconRunResult, entities: list[ParsedEntity], output_path: Path) -> Path:
        vulns = [e for e in entities if e.kind == "vulnerability_candidate"]
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AlphaV6-Recon",
                            "version": "6.0.0",
                            "informationUri": "https://github.com/vigilagent/Vigilagent",
                            "rules": self._build_rules(vulns),
                        }
                    },
                    "results": self._build_results(vulns),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": f"alpha --target {result.target} --mode {result.mode.value}",
                            "startTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        }
                    ],
                }
            ],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return output_path

    def _build_rules(self, vulns: list[ParsedEntity]) -> list[dict]:
        seen: set[str] = set()
        rules = []
        for v in vulns:
            rule_id = v.properties.get("template_id", v.properties.get("vuln_type", v.label))
            if rule_id in seen:
                continue
            seen.add(rule_id)
            severity = v.properties.get("severity", "medium")
            rules.append(
                {
                    "id": rule_id,
                    "name": v.properties.get("name", rule_id),
                    "shortDescription": {"text": v.properties.get("description", v.label)[:200]},
                    "defaultConfiguration": {
                        "level": self._severity_to_level(severity),
                    },
                    "properties": {"tags": v.properties.get("tags", [])},
                }
            )
        return rules

    def _build_results(self, vulns: list[ParsedEntity]) -> list[dict]:
        results = []
        for v in vulns:
            rule_id = v.properties.get("template_id", v.properties.get("vuln_type", v.label))
            severity = v.properties.get("severity", "medium")
            matched = v.properties.get("matched_at", v.properties.get("host", v.label))
            results.append(
                {
                    "ruleId": rule_id,
                    "level": self._severity_to_level(severity),
                    "message": {
                        "text": v.properties.get(
                            "description", f"{v.properties.get('name', rule_id)} found at {matched}"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": matched},
                            }
                        }
                    ],
                    "properties": {
                        "confidence": v.confidence,
                        "source_tool": v.source_tool,
                        "phase": v.phase,
                    },
                }
            )
        return results

    @staticmethod
    def _severity_to_level(severity: str) -> str:
        return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
            severity.lower(), "note"
        )


class HackerOneExporter:
    """Export findings in HackerOne-compatible format."""

    def export(self, result: ReconRunResult, entities: list[ParsedEntity], output_path: Path) -> Path:
        vulns = [e for e in entities if e.kind == "vulnerability_candidate"]
        reports = []
        for v in vulns:
            severity = v.properties.get("severity", "medium")
            reports.append(
                {
                    "title": v.properties.get("name", v.label),
                    "severity_rating": severity,
                    "vulnerability_information": v.properties.get("description", ""),
                    "impact": f"Confidence: {v.confidence:.0%}",
                    "weakness_id": v.properties.get("template_id", ""),
                    "structured_scope": v.properties.get("matched_at", v.properties.get("host", "")),
                    "source_tool": v.source_tool,
                    "evidence": {
                        "curl_command": v.properties.get("curl_command", ""),
                        "extracted_results": v.properties.get("extracted_results", []),
                    },
                }
            )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps({"reports": reports}, indent=2), encoding="utf-8")
        return output_path


class MarkdownReportExporter:
    """Generate an executive summary in Markdown."""

    def export(self, result: ReconRunResult, entities: list[ParsedEntity], output_path: Path) -> Path:
        vulns = [e for e in entities if e.kind == "vulnerability_candidate"]
        secrets = [e for e in entities if e.kind == "secret"]
        subs = [e for e in entities if e.kind == "subdomain"]
        services = [e for e in entities if e.kind in ("http_service", "service")]

        lines = [
            f"# Alpha V6 Recon Report — {result.target}",
            f"**Mode:** {result.mode.value} | **Duration:** {result.duration_seconds}s | **Scan ID:** {result.scan_id}",
            "",
            "## Attack Surface Summary",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Subdomains | {len(subs)} |",
            f"| IPs | {result.summary.total_ips} |",
            f"| Live HTTP Services | {len(services)} |",
            f"| Open Ports | {result.summary.total_open_ports} |",
            f"| Endpoints | {result.summary.total_endpoints} |",
            f"| JS Files | {result.summary.total_js_files} |",
            f"| Parameters | {result.summary.total_parameters} |",
            f"| Secrets | {len(secrets)} |",
            f"| Vulnerability Candidates | {len(vulns)} |",
            "",
            "## Tools Executed",
            ", ".join(f"`{t}`" for t in result.tools_run) if result.tools_run else "_None_",
            "",
        ]

        if vulns:
            lines.append("## Vulnerability Candidates")
            lines.append("| Severity | Name | Target | Confidence |")
            lines.append("|----------|------|--------|------------|")
            for v in sorted(vulns, key=lambda x: x.confidence, reverse=True)[:50]:
                sev = v.properties.get("severity", "?")
                name = v.properties.get("name", v.label)[:60]
                target = v.properties.get("matched_at", v.properties.get("host", ""))[:60]
                lines.append(f"| {sev.upper()} | {name} | {target} | {v.confidence:.0%} |")
            lines.append("")

        if secrets:
            lines.append("## Exposed Secrets")
            for s in secrets[:20]:
                lines.append(
                    f"- **{s.properties.get('secret_type', '?')}**: "
                    f"`{s.properties.get('redacted_value', '****')}` "
                    f"(source: {s.source_tool})"
                )
            lines.append("")

        lines.extend(
            [
                "## Data Artifacts",
                f"- Raw data: `{result.raw_data_path}`",
                f"- Screenshots: `{result.screenshots_path}`",
                f"- Manifest: `{result.artifact_manifest_path}`",
                "",
                "---\n*Generated by Alpha V6 Deep Recon Engine*",
            ]
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path
