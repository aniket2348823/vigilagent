"""
Unified Finding Report Engine (Architecture §18)
================================================================================
Produces evidence-first reports from CONFIRMED `Finding` objects (not just recon
entities). Every output format is driven from the same `Finding` model so each
finding carries the §18 required fields: title, severity, affected asset, scope
status, evidence IDs, reproduction summary, business + technical impact,
confidence, false-positive controls used, remediation, references.

Formats (Architecture §18):
  - JSON            (findings + metadata)
  - SARIF v2.1.0
  - HackerOne markdown
  - Executive PDF   (summary, business-impact focused)
  - Technical PDF   (full reproduction + evidence)   [separate from executive]
  - STIX 2.1 bundle

Graph exports (Neo4j/Maltego) remain entity-based in alpha_recon.graph_exporters.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any

from backend.schemas.findings import Finding, FindingState

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger("FindingReport")

_SEV_TO_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _active(findings: Iterable[Finding]) -> list[Finding]:
    """Only report findings that are not FP/duplicate/out-of-scope (§17, §18)."""
    excluded = {FindingState.FALSE_POSITIVE, FindingState.DUPLICATE, FindingState.OUT_OF_SCOPE}
    return [f for f in findings if f.state not in excluded]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity.value, 9))


class FindingReportEngine:
    """Multi-format report engine over confirmed Finding objects (§18)."""

    def __init__(self, scan_id: str, target: str = ""):
        self.scan_id = scan_id
        self.target = target

    # ── JSON ─────────────────────────────────────────────────────────────────

    def to_json(self, findings: list[Finding], out: Path) -> Path:
        active = _sorted(_active(findings))
        doc = {
            "scan_id": self.scan_id,
            "target": self.target,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "finding_count": len(active),
            "severity_counts": self._severity_counts(active),
            "findings": [self._finding_dict(f) for f in active],
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        return out

    @staticmethod
    def _finding_dict(f: Finding) -> dict[str, Any]:
        return {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "state": f.state.value,
            "scope_status": f.scope_status,
            "affected_asset": f.affected_target,
            "affected_component": f.affected_component,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "cwe": f.cwe,
            "mitre": f.mitre,
            "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
            "evidence_ids": f.evidence_ids or [e.sha256 or e.path for e in f.evidence],
            "reproduction_summary": f.steps_to_reproduce,
            "business_impact": f.business_impact or f.impact,
            "technical_impact": f.technical_impact or f.impact,
            "false_positive_controls": f.false_positive_controls,
            "verification_signals": [s.value if hasattr(s, "value") else str(s) for s in f.verification_signals],
            "remediation": f.remediation,
            "references": f.references,
        }

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    # ── SARIF ────────────────────────────────────────────────────────────────

    def to_sarif(self, findings: list[Finding], out: Path) -> Path:
        active = _active(findings)
        rules, results, seen = [], [], set()
        for f in active:
            rule_id = f.cwe[0] if f.cwe else f.title
            if rule_id not in seen:
                seen.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": f.title,
                        "shortDescription": {"text": f"{f.title} at {f.affected_target}".strip()},
                        "defaultConfiguration": {"level": _SEV_TO_SARIF.get(f.severity.value, "note")},
                    }
                )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _SEV_TO_SARIF.get(f.severity.value, "note"),
                    "message": {"text": f.description},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.affected_target}}}],
                    "properties": {
                        "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                        "cvss": f.cvss_score,
                        "state": f.state.value,
                        "false_positive_controls": f.false_positive_controls,
                    },
                }
            )
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Vigilagent", "version": "1.0.0", "rules": rules}},
                    "results": results,
                }
            ],
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return out

    # ── HackerOne markdown ───────────────────────────────────────────────────

    def to_hackerone_markdown(self, findings: list[Finding], out: Path) -> Path:
        lines = [f"# Security Assessment — {self.target or self.scan_id}", ""]
        for f in _sorted(_active(findings)):
            repro = [f"{i + 1}. {s}" for i, s in enumerate(f.steps_to_reproduce)] or ["(see evidence)"]
            refs = [f"- {r}" for r in f.references] or ["n/a"]
            conf = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            lines += [
                f"## {f.title} ({f.severity.value.upper()})",
                f"**Asset:** {f.affected_target}  |  **Scope:** {f.scope_status}  "
                f"|  **CVSS:** {f.cvss_score or 'n/a'} ({f.cvss_vector or 'n/a'})  "
                f"|  **State:** {f.state.value}  |  **Confidence:** {conf}",
                "",
                "### Description",
                f.description,
                "",
                "### Steps to Reproduce",
                *repro,
                "",
                "### Business Impact",
                f.business_impact or f.impact or "n/a",
                "",
                "### Technical Impact",
                f.technical_impact or f.impact or "n/a",
                "",
                "### False-Positive Controls Applied",
                ", ".join(f.false_positive_controls) or "n/a",
                "",
                "### Remediation",
                f.remediation or "n/a",
                "",
                "### References",
                *refs,
                "",
                "---",
                "",
            ]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines), encoding="utf-8")
        return out

    # ── STIX 2.1 ──────────────────────────────────────────────────────────────

    def to_stix(self, findings: list[Finding], out: Path) -> Path:
        objects = []
        for f in _active(findings):
            objects.append(
                {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": f"vulnerability--{f.id}",
                    "created": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                    "name": f.title,
                    "description": f.description,
                    "external_references": (
                        [{"source_name": "cwe", "external_id": c} for c in f.cwe]
                        + [{"source_name": "ref", "url": r} for r in f.references]
                    ),
                }
            )
        bundle = {"type": "bundle", "id": f"bundle--{self.scan_id}", "objects": objects}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return out

    # ── PDFs (Executive vs Technical, Architecture §18) ──────────────────────

    def to_executive_pdf(self, findings: list[Finding], out: Path) -> Path:
        """Executive PDF: business-impact-focused summary."""
        return self._pdf(findings, out, technical=False)

    def to_technical_pdf(self, findings: list[Finding], out: Path) -> Path:
        """Technical PDF: full reproduction + evidence detail."""
        return self._pdf(findings, out, technical=True)

    def _pdf(self, findings: list[Finding], out: Path, *, technical: bool) -> Path:
        active = _sorted(_active(findings))
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            from fpdf import FPDF
        except Exception as exc:
            logger.debug("[FindingReport] fpdf unavailable, falling back to text: %s", exc)
            txt = out.with_suffix(".txt")
            txt.write_text(self._pdf_text(active, technical=technical), encoding="utf-8")
            return txt

        def _s(text: str) -> str:
            # fpdf core fonts are latin-1 only; strip unsupported chars.
            return str(text).encode("latin-1", "replace").decode("latin-1")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_margins(15, 15, 15)
        pdf.add_page()
        # Explicit usable width — some fpdf2 versions mishandle width=0 multi_cell.
        try:
            w = pdf.epw
        except Exception as exc:
            logger.debug("[FindingReport] fpdf epw unavailable: %s", exc)
            w = 180
        if not w or w <= 1:
            w = 180
        kind = "Technical" if technical else "Executive"
        pdf.set_font("Arial", "B", 16)
        pdf.multi_cell(w, 10, _s(f"Vigilagent {kind} Report"))
        pdf.set_font("Arial", "", 10)
        pdf.multi_cell(w, 6, _s(f"Target: {self.target or self.scan_id}"))
        counts = self._severity_counts(active)
        pdf.multi_cell(w, 6, _s("Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items())))
        pdf.ln(4)
        for f in active:
            pdf.set_font("Arial", "B", 12)
            pdf.multi_cell(w, 6, _s(f"[{f.severity.value.upper()}] {f.title}"))
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(w, 5, _s(f"Asset: {f.affected_target} | Scope: {f.scope_status} | State: {f.state.value}"))
            pdf.multi_cell(w, 5, _s(f"CVSS: {f.cvss_score or 'n/a'} | {f.cvss_vector or 'n/a'}"))
            if technical:
                pdf.multi_cell(w, 5, _s(f"Description: {f.description[:1500]}"))
                if f.steps_to_reproduce:
                    pdf.multi_cell(w, 5, _s("Reproduction: " + "; ".join(f.steps_to_reproduce)[:1500]))
                pdf.multi_cell(w, 5, _s(f"Technical impact: {(f.technical_impact or f.impact)[:800]}"))
                pdf.multi_cell(w, 5, _s("FP controls: " + (", ".join(f.false_positive_controls) or "n/a")))
                pdf.multi_cell(w, 5, _s(f"Evidence: {len(f.evidence)} item(s); ids={f.evidence_ids}"))
            else:
                pdf.multi_cell(w, 5, _s(f"Business impact: {(f.business_impact or f.impact)[:800]}"))
            pdf.multi_cell(w, 5, _s(f"Remediation: {f.remediation[:800] or 'n/a'}"))
            pdf.ln(3)
        pdf.output(str(out))
        return out

    def _pdf_text(self, findings: list[Finding], *, technical: bool) -> str:
        kind = "TECHNICAL" if technical else "EXECUTIVE"
        lines = [f"VIGILAGENT {kind} REPORT", f"Target: {self.target or self.scan_id}", ""]
        for f in findings:
            lines.append(f"[{f.severity.value.upper()}] {f.title} ({f.state.value})")
            lines.append(f"  Asset: {f.affected_target} | Scope: {f.scope_status} | CVSS: {f.cvss_score}")
            if technical:
                lines.append(f"  Repro: {'; '.join(f.steps_to_reproduce)}")
                lines.append(f"  Technical impact: {f.technical_impact or f.impact}")
                lines.append(f"  FP controls: {', '.join(f.false_positive_controls)}")
            else:
                lines.append(f"  Business impact: {f.business_impact or f.impact}")
            lines.append(f"  Remediation: {f.remediation}")
            lines.append("")
        return "\n".join(lines)

    # ── One-shot: emit every format ──────────────────────────────────────────

    def emit_all(self, findings: list[Finding], base_dir: Path) -> dict[str, str]:
        base_dir.mkdir(parents=True, exist_ok=True)
        return {
            "json": str(self.to_json(findings, base_dir / "findings.json")),
            "sarif": str(self.to_sarif(findings, base_dir / "findings.sarif")),
            "hackerone": str(self.to_hackerone_markdown(findings, base_dir / "hackerone.md")),
            "stix": str(self.to_stix(findings, base_dir / "stix_bundle.json")),
            "executive_pdf": str(self.to_executive_pdf(findings, base_dir / "executive_report.pdf")),
            "technical_pdf": str(self.to_technical_pdf(findings, base_dir / "technical_report.pdf")),
        }
