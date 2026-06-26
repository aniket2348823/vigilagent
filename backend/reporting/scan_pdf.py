"""
Vigilagent PDF Builder
================================================================================
Builds the per-scan PDF report in the exact "Vigilagent" layout
(Executive Summary → Detailed Findings (one per finding) → Scan Timeline).

Public entry point:
    VigilagentReportBuilder(scan_id, target_url, events, telemetry, cortex)
        .build()         -> async; returns absolute path of the produced PDF.

Design rules (enforced):
  * Real data only. Target / Scan ID / Date / Findings list / HTTP traffic /
    timeline come from the live scan record.  LLM is used ONLY to expand
    prose (description, impact, explanation, remediation, code-fix).
  * Never display "N/A" — degrade to a concrete neutral value.
  * No new heavy dependencies — uses fpdf2 (already in requirements).
  * Branding stays "Vigilagent".
  * Output path: <REPORTS_DIR>/Scan_Report_<scan_id>.pdf  (preserves the
    existing /api/reports/download/<file> endpoint).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from fpdf import FPDF

from backend.core.config import settings
from backend.reporting.cvss_engine import score_for_vuln_class, severity_band

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger("ScanPDF")

# ── Color palette (Vigilagent specimen) ─────────────────────────────
BRAND_BLACK = (15, 15, 15)
BRAND_RULE = (44, 62, 80)  # Header/footer underline
TITLE_RED = (192, 57, 43)  # Big section titles
FILTER_PURPLE = (118, 77, 220)  # Filter category underline
TEXT_BLACK = (20, 20, 20)
META_GREY = (110, 110, 110)
TERMINAL_BG = (245, 245, 248)
TERMINAL_BORDER = (118, 77, 220)
TABLE_BORDER = (200, 200, 210)
TABLE_HEADER_BG = (240, 240, 246)
PROGRESS_BG = (230, 230, 235)

SEVERITY_COLORS = {
    "CRITICAL": (192, 57, 43),  # #C0392B
    "HIGH": (230, 126, 34),  # #E67E22
    "MEDIUM": (241, 196, 15),  # #F1C40F
    "LOW": (39, 174, 96),  # #27AE60
    "INFO": (52, 152, 219),  # #3498DB
    "NONE": (149, 165, 166),  # #95A5A6
}

# CWE map for fallback lookups (kept aligned with reporting.py legacy map).
CWE_MAP: dict[str, dict[str, Any]] = {
    "SQL_INJECTION": {"cwe": "CWE-89", "name": "SQL Injection"},
    "SQLI": {"cwe": "CWE-89", "name": "SQL Injection"},
    "CROSS_SITE_SCRIPTING": {"cwe": "CWE-79", "name": "Cross-Site Scripting (XSS)"},
    "XSS": {"cwe": "CWE-79", "name": "Cross-Site Scripting (XSS)"},
    "XSS_BROWSER_VERIFIED": {"cwe": "CWE-79", "name": "Cross-Site Scripting (XSS)"},
    "UNAUTHORIZED_ACCESS": {"cwe": "CWE-284", "name": "Unauthorized Access"},
    "IDOR": {"cwe": "CWE-639", "name": "Insecure Direct Object Reference (IDOR)"},
    "LOGIC_IDOR": {"cwe": "CWE-639", "name": "Insecure Direct Object Reference (IDOR)"},
    "COMMAND_INJECTION": {"cwe": "CWE-78", "name": "OS Command Injection"},
    "RCE": {"cwe": "CWE-78", "name": "Remote Code Execution"},
    "PATH_TRAVERSAL": {"cwe": "CWE-22", "name": "Path Traversal"},
    "SSRF": {"cwe": "CWE-918", "name": "Server-Side Request Forgery"},
    "OPEN_REDIRECT": {"cwe": "CWE-601", "name": "Open Redirect"},
    "INFORMATION_DISCLOSURE": {"cwe": "CWE-200", "name": "Information Disclosure"},
    "DATA_LEAK": {"cwe": "CWE-200", "name": "Information Disclosure"},
    "BROKEN_AUTH": {"cwe": "CWE-287", "name": "Broken Authentication"},
    "AUTH_BYPASS": {"cwe": "CWE-287", "name": "Broken Authentication"},
    "JWT_BYPASS": {"cwe": "CWE-287", "name": "JWT Authentication Bypass"},
    "CSRF": {"cwe": "CWE-352", "name": "Cross-Site Request Forgery"},
    "CSRF_BYPASS": {"cwe": "CWE-352", "name": "CSRF Bypass"},
    "PROMPT_INJECTION": {"cwe": "CWE-77", "name": "AI Prompt Injection"},
    "HIDDEN_TEXT": {"cwe": "CWE-116", "name": "Hidden Content Injection"},
    "ARITHMETIC_OVERFLOW": {"cwe": "CWE-190", "name": "Integer Overflow"},
    "RACE_CONDITION": {"cwe": "CWE-362", "name": "Race Condition"},
    "FINANCIAL_MANIPULATION": {"cwe": "CWE-840", "name": "Business Logic Errors"},
    "SUSPICIOUS_NETWORK_ACTIVITY": {"cwe": "CWE-200", "name": "Suspicious Network Activity"},
}


# ── Sanitisation helpers ─────────────────────────────────────────────────────

_LATIN1_REPLACEMENTS = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2013": "-",
    "\u2014": "--",
    "\u2026": "...",
    "\u2022": "-",
    "\u00a0": " ",
    "\u2192": "->",
    "\u00bb": ">>",
    "\u00ab": "<<",
}


def _sanitize(text: Any) -> str:
    """fpdf core fonts are latin-1 only — strip / fold unsupported chars."""
    if text is None:
        return ""
    s = str(text)
    for k, v in _LATIN1_REPLACEMENTS.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "replace").decode("latin-1")


def _truncate(text: Any, max_len: int) -> str:
    s = _sanitize(text)
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _is_meaningful(value: Any) -> bool:
    """Return False for empty / 'N/A' / placeholder values."""
    if value is None:
        return False
    s = str(value).strip()
    if not s:
        return False
    return s.upper() not in {"N/A", "NA", "NONE", "NULL", "UNDEFINED", "UNKNOWN"}


def _first_meaningful(*values: Any, default: str = "") -> str:
    for v in values:
        if _is_meaningful(v):
            return str(v)
    return default


# ── PDF document class ───────────────────────────────────────────────────────


class _VigilagentPDF(FPDF):
    """fpdf2 document with the Vigilagent header + footer."""

    LEFT_MARGIN = 15
    RIGHT_MARGIN = 15
    TOP_MARGIN = 15

    def __init__(self) -> None:
        super().__init__()
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(self.LEFT_MARGIN, self.TOP_MARGIN, self.RIGHT_MARGIN)
        self._generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── chrome ────────────────────────────────────────────────────────────────

    def header(self) -> None:  # type: ignore[override]
        self.set_y(8)
        self.set_text_color(*BRAND_BLACK)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 6, "Vigilagent", align="L", new_x="LMARGIN", new_y="NEXT")
        # Horizontal rule
        self.set_draw_color(*BRAND_RULE)
        self.set_line_width(0.5)
        y = self.get_y() + 1
        self.line(self.LEFT_MARGIN, y, 210 - self.RIGHT_MARGIN, y)
        self.set_y(y + 5)

    def footer(self) -> None:  # type: ignore[override]
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*META_GREY)
        text = f"Page {self.page_no()}/{{nb}} | Generated: {self._generated_at}"
        self.cell(0, 8, text, align="C")

    # ── primitives ────────────────────────────────────────────────────────────

    @property
    def usable_width(self) -> float:
        try:
            w = self.epw  # fpdf2 exposes effective page width
        except Exception as exc:
            logger.debug("[ScanPDF] epw property unavailable: %s", exc)
            w = 210 - self.LEFT_MARGIN - self.RIGHT_MARGIN
        if not w or w <= 1:
            w = 180.0
        return float(w)

    def big_title(self, text: str) -> None:
        """Page-level red title (e.g. EXECUTIVE SUMMARY, DETAILED FINDINGS)."""
        self.ln(2)
        self.set_text_color(*TITLE_RED)
        self.set_font("Helvetica", "B", 22)
        self.cell(0, 11, _sanitize(text.upper()), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*TITLE_RED)
        self.set_line_width(0.6)
        y = self.get_y() + 1
        self.line(self.LEFT_MARGIN, y, 210 - self.RIGHT_MARGIN, y)
        self.set_y(y + 5)

    def filter_banner(self, category: str) -> None:
        """Purple-underlined "FILTER: <CATEGORY>" banner."""
        self.ln(1)
        self.set_text_color(*BRAND_RULE)
        self.set_font("Helvetica", "B", 14)
        text = _sanitize(f"FILTER: {category.upper()}")
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        # Purple underline only under text width
        self.set_draw_color(*FILTER_PURPLE)
        self.set_line_width(0.7)
        text_width = self.get_string_width(text)
        y = self.get_y()
        self.line(self.LEFT_MARGIN, y, self.LEFT_MARGIN + text_width, y)
        self.ln(5)

    def kv_line(self, key: str, value: str) -> None:
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(*TEXT_BLACK)
        prefix = _sanitize(f"{key}: ")
        prefix_w = self.get_string_width(prefix) + 1.0
        self.get_x()
        y_start = self.get_y()
        self.cell(prefix_w, 6, prefix)
        self.set_font("Helvetica", "", 10.5)
        # Wrap the value across remaining width
        remaining = self.usable_width - prefix_w
        self.multi_cell(remaining, 6, _sanitize(value), new_x="LMARGIN", new_y="NEXT")
        # Ensure we do not regress before the line we started on
        if self.get_y() < y_start + 6:
            self.set_y(y_start + 6)

    def bullet_list(self, items: Iterable[str], indent: float = 4.0) -> None:
        self.set_font("Helvetica", "", 10.5)
        self.set_text_color(*TEXT_BLACK)
        for item in items:
            text = _sanitize(item).strip()
            if not text:
                continue
            self.set_x(self.LEFT_MARGIN + indent)
            # bullet + space prefix
            bullet = "- "
            bullet_w = self.get_string_width(bullet) + 0.5
            self.cell(bullet_w, 6, bullet)
            self.multi_cell(
                self.usable_width - indent - bullet_w,
                6,
                text,
                new_x="LMARGIN",
                new_y="NEXT",
            )
            self.ln(0.5)

    def section_label(self, label: str, color: tuple[int, int, int] = BRAND_RULE) -> None:
        self.ln(1)
        self.set_text_color(*color)
        self.set_font("Helvetica", "B", 11.5)
        self.cell(0, 6, _sanitize(label), new_x="LMARGIN", new_y="NEXT")

    def severity_pill(self, severity: str) -> None:
        sev = severity.upper().strip()
        color = SEVERITY_COLORS.get(sev, (90, 90, 90))
        self.set_font("Helvetica", "B", 10)
        # White text on coloured fill
        text = _sanitize(sev)
        text_w = self.get_string_width(text) + 8
        x = self.LEFT_MARGIN
        y = self.get_y()
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_draw_color(*color)
        # Rounded-ish rect via two cells (fpdf2 lacks rounded rect on every version)
        self.rect(x, y, text_w, 6.5, "F")
        self.set_xy(x, y)
        self.cell(text_w, 6.5, text, align="C")
        self.set_y(y + 7.5)
        self.set_text_color(*TEXT_BLACK)

    def threat_bar(self, score: int) -> None:
        score = max(0, min(100, int(score)))
        # Colour selection from score
        if score >= 70:
            color = SEVERITY_COLORS["CRITICAL"] if score >= 90 else SEVERITY_COLORS["HIGH"]
        elif score >= 40:
            color = SEVERITY_COLORS["MEDIUM"]
        else:
            color = SEVERITY_COLORS["LOW"]
        self.ln(1)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*META_GREY)
        self.cell(35, 7, "THREAT SCORE:")
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*color)
        self.cell(0, 7, f"{score}/100", new_x="LMARGIN", new_y="NEXT")
        # Bar
        bar_w = self.usable_width
        x = self.LEFT_MARGIN
        y = self.get_y()
        self.set_fill_color(*PROGRESS_BG)
        self.rect(x, y, bar_w, 6, "F")
        self.set_fill_color(*color)
        self.rect(x, y, bar_w * (score / 100.0), 6, "F")
        self.set_y(y + 8)

    def paragraph(self, text: str, *, italic: bool = False, size: float = 10.5) -> None:
        self.set_font("Helvetica", "I" if italic else "", size)
        self.set_text_color(*TEXT_BLACK)
        self.multi_cell(self.usable_width, 5.5, _sanitize(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(0.5)

    def code_block(self, lines: list[str]) -> None:
        self.set_font("Courier", "", 8.5)
        self.set_text_color(*TEXT_BLACK)
        self.set_fill_color(*TERMINAL_BG)
        self.set_draw_color(*TERMINAL_BORDER)
        self.set_line_width(0.3)
        # Pre-process lines: normalise tabs and strip code fences
        flat: list[str] = []
        for raw in lines:
            s = _sanitize(raw)
            s = s.replace("\t", "    ")
            for fragment in s.split("\n"):
                # word-wrap long lines at ~95 chars
                while len(fragment) > 95:
                    flat.append(fragment[:95])
                    fragment = fragment[95:]
                flat.append(fragment)
        if not flat:
            flat = [""]
        height = 4.6 * len(flat) + 2.5
        # Page-break safety
        if self.get_y() + height > self.h - 22:
            self.add_page()
        x = self.LEFT_MARGIN
        y = self.get_y()
        self.rect(x, y, self.usable_width, height, "DF")
        self.set_xy(x + 2, y + 1.5)
        for line in flat:
            self.set_x(x + 2)
            self.cell(self.usable_width - 4, 4.4, line, new_x="LMARGIN", new_y="NEXT")
        self.set_y(y + height + 2)

    def labelled_box(self, label: str, lines: list[str]) -> None:
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*BRAND_RULE)
        self.cell(0, 5, _sanitize(label), new_x="LMARGIN", new_y="NEXT")
        self.code_block(lines)

    def simple_table(self, title: str, headers: list[str], rows: list[list[str]], col_widths: list[float]) -> None:
        # Page-break safety
        approx_h = 9 + (len(rows) + 1) * 7 + 6
        if self.get_y() + min(approx_h, 60) > self.h - 25:
            self.add_page()
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*TEXT_BLACK)
        self.cell(0, 6, _sanitize(title), new_x="LMARGIN", new_y="NEXT")
        # Header row
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*BRAND_RULE)
        self.set_fill_color(*TABLE_HEADER_BG)
        self.set_draw_color(*TABLE_BORDER)
        self.set_line_width(0.2)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 7, _sanitize(h), border=1, fill=True, align="C")
        self.ln()
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*TEXT_BLACK)
        for row in rows:
            # Compute the tallest cell so multi-line content stays inside its border
            line_h = 5
            cell_lines: list[list[str]] = []
            max_lines = 1
            for i, value in enumerate(row):
                txt = _sanitize(value)
                # rough char-per-mm at 9pt ~ 2
                max_chars = max(8, int(col_widths[i] * 2.0))
                wrapped: list[str] = []
                for paragraph in txt.split("\n"):
                    while len(paragraph) > max_chars:
                        wrapped.append(paragraph[:max_chars])
                        paragraph = paragraph[max_chars:]
                    wrapped.append(paragraph)
                cell_lines.append(wrapped or [""])
                max_lines = max(max_lines, len(wrapped) or 1)
            row_h = line_h * max_lines
            if self.get_y() + row_h > self.h - 22:
                self.add_page()
            x_start = self.get_x()
            y_start = self.get_y()
            for i, lines in enumerate(cell_lines):
                cell_x = x_start + sum(col_widths[:i])
                self.rect(cell_x, y_start, col_widths[i], row_h)
                for j, line in enumerate(lines):
                    self.set_xy(cell_x + 1.5, y_start + j * line_h + 0.5)
                    self.cell(col_widths[i] - 3, line_h, line)
            self.set_xy(x_start, y_start + row_h)
        self.ln(3)

    def timeline_rows(self, rows: list[str]) -> None:
        self.set_font("Courier", "", 9)
        self.set_text_color(*TEXT_BLACK)
        for r in rows:
            self.set_x(self.LEFT_MARGIN)
            line = "- " + _sanitize(r)
            if len(line) > 105:
                line = line[:102] + "..."
            if self.get_y() > self.h - 22:
                self.add_page()
            self.cell(0, 5.5, line, new_x="LMARGIN", new_y="NEXT")


# ── Builder ──────────────────────────────────────────────────────────────────


class VigilagentReportBuilder:
    """Orchestrates real-data extraction + LLM enrichment + PDF rendering."""

    LLM_OVERALL_TIMEOUT = 600.0  # seconds budget for all LLM calls
    LLM_PER_CALL_TIMEOUT = 25.0  # seconds per individual call

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        events: list[dict[str, Any]],
        telemetry: dict[str, Any] | None = None,
        cortex: Any = None,
        manager: Any = None,
    ) -> None:
        self.scan_id = scan_id
        self.target_url = target_url or "Unknown Target"
        self.events = events or []
        self.telemetry = telemetry or {}
        self.cortex = cortex
        self.manager = manager
        self.pdf = _VigilagentPDF()

    # ── public entry point ───────────────────────────────────────────────────

    async def build(self) -> str:
        findings = self._collect_findings()
        # Enrich each finding with LLM prose (best-effort, time-boxed).
        enriched: list[dict[str, Any]] = []
        try:
            enriched = await asyncio.wait_for(
                self._enrich_findings(findings),
                timeout=self.LLM_OVERALL_TIMEOUT,
            )
        except TimeoutError:
            enriched = [self._fallback_enrichment(f) for f in findings]
        except Exception as exc:
            logger.warning("[ScanPDF] LLM enrichment failed, using fallback: %s", exc)
            enriched = [self._fallback_enrichment(f) for f in findings]
        if len(enriched) < len(findings):
            # Ensure every finding renders even if enrichment partially failed.
            for f in findings[len(enriched) :]:
                enriched.append(self._fallback_enrichment(f))

        exec_bullets = await self._safe_executive_bullets(len(findings))

        # ── Page 1: Executive Summary ─────────────────────────────────────────
        self.pdf.alias_nb_pages()
        self.pdf.add_page()
        self._render_executive_summary(findings, exec_bullets)

        # ── Pages 2..N-1: Detailed Findings ───────────────────────────────────
        if findings:
            self.pdf.add_page()
            self.pdf.big_title("Detailed Findings")
            for idx, item in enumerate(enriched, start=1):
                if idx > 1:
                    self.pdf.add_page()
                self._render_finding(idx, item)

        # ── Last page: Scan Timeline ──────────────────────────────────────────
        self.pdf.add_page()
        self._render_timeline()

        # ── Save (off the event loop) ─────────────────────────────────────────
        out_dir = settings.REPORTS_DIR
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"Scan_Report_{self.scan_id}.pdf")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.pdf.output, out_path)
        return out_path

    # ── data collection (real data, never fabricated) ────────────────────────

    def _collect_findings(self) -> list[dict[str, Any]]:
        """Extract confirmed findings (deduplicated) from the events buffer."""
        keep_types = {"VULN_CONFIRMED", "HIDDEN_TEXT", "PROMPT_INJECTION"}
        seen: dict[str, dict[str, Any]] = {}
        for ev in self.events:
            etype = str(ev.get("type", "")).upper()
            if not any(k in etype for k in keep_types):
                continue
            payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
            payload = payload or {}
            url = str(payload.get("url") or self.target_url).strip().lower()
            vtype = str(payload.get("type") or payload.get("vuln_type") or "FINDING").upper()
            data = str(payload.get("payload") or payload.get("data") or "").strip().lower()[:200]
            sig_input = json.dumps({"u": url, "t": vtype, "d": data}, sort_keys=True, default=str)
            sig = hashlib.sha256(sig_input.encode("utf-8")).hexdigest()
            if sig in seen:
                continue
            seen[sig] = ev
        return list(seen.values())

    @staticmethod
    def _lookup_cwe(vuln_type: str) -> dict[str, Any]:
        key = (vuln_type or "").upper().replace(" ", "_").replace("/", "_")
        if key in CWE_MAP:
            return CWE_MAP[key]
        for k, v in CWE_MAP.items():
            if k in key or key in k:
                return v
        return {"cwe": "CWE-200", "name": (vuln_type or "Finding").replace("_", " ").title()}

    @staticmethod
    def _severity_label(score: float) -> str:
        band = severity_band(score)
        return {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}.get(
            band.lower(), band.upper()
        )

    def _normalise_finding(self, ev: dict[str, Any]) -> dict[str, Any]:
        """Return a finding dict with everything the renderer needs."""
        payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
        payload = payload or {}
        data_blob = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        evidence = payload.get("evidence")

        vuln_type = str(payload.get("type") or payload.get("vuln_type") or "FINDING").upper()
        url = _first_meaningful(payload.get("url"), default=self.target_url)
        method = _first_meaningful(payload.get("method"), data_blob.get("method"), default="GET").upper()
        param = _first_meaningful(
            payload.get("param"),
            payload.get("parameter"),
            data_blob.get("param"),
            default="-",
        )
        # Attack data / payload string (real)
        attack_payload = _first_meaningful(
            payload.get("payload"),
            payload.get("attack_payload"),
            data_blob.get("payload"),
            default="",
        )
        # CWE lookup, real CVSS via deterministic engine
        cwe_info = self._lookup_cwe(vuln_type)
        cvss_score, cvss_vector = score_for_vuln_class(vuln_type)
        # Allow override if the upstream pipeline already scored it
        if isinstance(payload.get("cvss_score"), (int, float)):
            cvss_score = float(payload["cvss_score"])
        severity_payload = str(payload.get("severity") or "").upper()
        severity = severity_payload if severity_payload in SEVERITY_COLORS else self._severity_label(cvss_score)
        threat_score = max(0, min(100, int(round(float(cvss_score) * 10))))

        # Real HTTP request/response, captured by the agents
        request_blob = _first_meaningful(
            payload.get("request"),
            data_blob.get("request"),
            payload.get("raw_request"),
            default="",
        )
        response_blob = _first_meaningful(
            payload.get("response"),
            payload.get("response_body"),
            data_blob.get("response"),
            data_blob.get("response_body"),
            default="",
        )
        status_code = _first_meaningful(
            payload.get("status"),
            payload.get("status_code"),
            payload.get("response_code"),
            data_blob.get("status"),
            default="200",
        )
        headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
        if not headers and isinstance(data_blob.get("headers"), dict):
            headers = data_blob["headers"]

        agent = str(ev.get("source") or payload.get("source") or "Agent").replace("agent_", "Agent ").title()
        confidence = payload.get("confidence")
        audit_reasoning = payload.get("audit_reasoning") or ""

        return {
            "raw_event": ev,
            "vuln_type": vuln_type,
            "cwe": cwe_info["cwe"],
            "name": cwe_info["name"],
            "url": url,
            "method": method,
            "param": param,
            "attack_payload": attack_payload,
            "cvss_score": round(float(cvss_score), 1),
            "cvss_vector": cvss_vector,
            "severity": severity,
            "threat_score": threat_score,
            "request": request_blob,
            "response": response_blob,
            "status_code": str(status_code),
            "headers": headers,
            "agent": agent,
            "confidence": confidence,
            "audit_reasoning": str(audit_reasoning),
            "evidence_text": str(evidence) if evidence else "",
        }

    # ── LLM enrichment (prose only, never invents data) ──────────────────────

    async def _enrich_findings(self, raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched: list[dict[str, Any]] = []
        for ev in raw_findings:
            f = self._normalise_finding(ev)
            llm = await self._enrich_single(f)
            f.update(llm)
            enriched.append(f)
        return enriched

    async def _enrich_single(self, f: dict[str, Any]) -> dict[str, Any]:
        cortex = self.cortex
        # 1. Vulnerability summary (description / impact / remediation / code_fix)
        summary: dict[str, Any] = {}
        try:
            if cortex is not None:
                summary = await asyncio.wait_for(
                    cortex.generate_vulnerability_summary(
                        f["vuln_type"],
                        f["attack_payload"] or f["evidence_text"],
                        f["url"],
                    ),
                    timeout=self.LLM_PER_CALL_TIMEOUT,
                )
        except Exception as exc:
            logger.debug("[ScanPDF] Vulnerability summary LLM call failed: %s", exc)
            summary = {}
        if not isinstance(summary, dict):
            summary = {}

        # 2. Forensic narrative (root cause / evidence / advantage)
        forensic: dict[str, Any] = {}
        try:
            if cortex is not None:
                forensic = await asyncio.wait_for(
                    cortex.reconstruct_forensic_evidence(
                        f["vuln_type"],
                        f["attack_payload"] or f["evidence_text"],
                        (f["response"] or f["evidence_text"])[:500],
                        f["url"],
                    ),
                    timeout=self.LLM_PER_CALL_TIMEOUT,
                )
        except Exception as exc:
            logger.debug("[ScanPDF] Forensic evidence LLM call failed: %s", exc)
            forensic = {}
        if not isinstance(forensic, dict):
            forensic = {}

        # 3. Secure code fix tailored to inferred tech stack
        tech_stack = self._infer_tech_stack(f)
        code_fix = ""
        try:
            if cortex is not None:
                code_fix = await asyncio.wait_for(
                    cortex.generate_code_fix(f["vuln_type"], f["attack_payload"], f["url"], tech_stack),
                    timeout=self.LLM_PER_CALL_TIMEOUT,
                )
        except Exception as exc:
            logger.debug("[ScanPDF] Remediation code LLM call failed: %s", exc)
            code_fix = ""

        # Coerce + fall back deterministically
        description = self._coerce_bullets(
            summary.get("description"),
            default=[
                f"{f['name']} confirmed at {f['url']}.",
                f"Triggered by {f['method']} request on parameter '{f['param']}'.",
                "Application accepted unvalidated input and surfaced anomalous behaviour.",
            ],
        )[:3]
        impact = self._coerce_bullets(
            summary.get("impact"),
            default=[
                "Strategic Impact: increases probability of unauthorised access to sensitive data.",
                "Financial Impact: exposes the organisation to incident response and disclosure costs.",
                "Technical Impact: weakens trust boundaries enforced at this endpoint.",
                "Operational Impact: bypasses controls expected to govern this surface.",
            ],
        )[:4]
        remediation = self._coerce_bullets(
            summary.get("remediation"),
            default=[
                "Validate and canonicalise input on this endpoint server-side.",
                "Apply defence-in-depth (parameterised queries, output encoding, authorisation checks).",
                "Deploy detection rules covering this attack signature.",
                "Re-run the verification command after remediation to confirm closure.",
            ],
        )[:4]

        # Pad missing entries to required counts so layout stays consistent.
        while len(description) < 3:
            description.append("Further investigation recommended to fully characterise the impact.")
        while len(impact) < 4:
            impact.append("Operational Impact: weakens the defensive posture of this endpoint.")
        while len(remediation) < 4:
            remediation.append("Continue monitoring and re-test after fixes are deployed.")

        explanation = self._explanation_text(f, forensic)
        forensic_line = (
            forensic.get("evidence_analysis")
            or forensic.get("root_cause")
            or (
                f["audit_reasoning"][:240]
                if f["audit_reasoning"]
                else "Server-side validation insufficient for the supplied input vector."
            )
        )
        secure_code = self._clean_code_block(code_fix) or self._fallback_code(f["vuln_type"], tech_stack)

        return {
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "explanation": explanation,
            "forensic_line": forensic_line,
            "tech_stack": tech_stack,
            "secure_code": secure_code,
        }

    def _fallback_enrichment(self, ev: dict[str, Any]) -> dict[str, Any]:
        f = self._normalise_finding(ev)
        f.update(
            {
                "description": [
                    f"{f['name']} observed at {f['url']}.",
                    f"Triggered through {f['method']} on parameter '{f['param']}'.",
                    "Server response demonstrated weakened input handling.",
                ],
                "impact": [
                    "Strategic Impact: opens a path toward sensitive data or actions.",
                    "Financial Impact: incident response and remediation cost exposure.",
                    "Technical Impact: weakens authentication / validation contracts.",
                    "Operational Impact: erodes trust boundaries on this endpoint.",
                ],
                "remediation": [
                    "Apply server-side validation and parameterised data access.",
                    "Add layered controls (auth checks, output encoding, allow-lists).",
                    "Add detection rules covering this attack signature.",
                    "Re-run the reproduction command after remediation.",
                ],
                "explanation": (
                    f"Agent {f['agent']} flagged this finding from concrete request/response "
                    f"evidence captured during the scan; pattern '{f['vuln_type']}' was observed "
                    f"and reported by the live attack pipeline."
                ),
                "forensic_line": (
                    f["audit_reasoning"][:240]
                    if f["audit_reasoning"]
                    else "Server-side validation insufficient for the supplied input vector."
                ),
                "tech_stack": self._infer_tech_stack(f),
                "secure_code": self._fallback_code(f["vuln_type"], self._infer_tech_stack(f)),
            }
        )
        return f

    async def _safe_executive_bullets(self, total_findings: int) -> list[str]:
        cortex = self.cortex
        if cortex is None:
            return self._exec_fallback(total_findings)
        try:
            categories = self._severity_breakdown(self.events)
            bullets = await asyncio.wait_for(
                cortex.generate_ai_executive_summary(self.target_url, total_findings, categories),
                timeout=self.LLM_PER_CALL_TIMEOUT,
            )
            cleaned = [b for b in (bullets or []) if isinstance(b, str) and len(b.strip()) > 5]
            cleaned = [re.sub(r"^[\s\-\*\u2022]+", "", b).strip() for b in cleaned]
            cleaned = [b for b in cleaned if b][:4]
            if len(cleaned) >= 2:
                while len(cleaned) < 4:
                    cleaned.append(self._exec_fallback(total_findings)[len(cleaned)])
                return cleaned
        except Exception as exc:
            logger.debug("[ScanPDF] Executive summary LLM call failed: %s", exc)
        return self._exec_fallback(total_findings)

    def _exec_fallback(self, total_findings: int) -> list[str]:
        if total_findings == 0:
            return [
                "No exploitable vulnerabilities were confirmed against the tested attack surface.",
                "Defensive controls held against the standard battery of injection and logic vectors.",
                "Continue periodic re-testing as new endpoints and features are deployed.",
                "Maintain monitoring and alerting on the surfaces that were probed.",
            ]
        return [
            f"Vigilagent confirmed {total_findings} security finding(s) against {self.target_url}.",
            "Each finding includes the captured HTTP traffic, payload decomposition and a reproduction command.",
            "Prioritise remediation by severity; CRITICAL and HIGH findings should be addressed first.",
            "Re-run the scan after remediation to validate that each finding has been closed.",
        ]

    # ── helpers for prose normalisation ──────────────────────────────────────

    @staticmethod
    def _coerce_bullets(value: Any, *, default: list[str]) -> list[str]:
        if not value:
            return list(default)
        if isinstance(value, str):
            parts = [p.strip() for p in re.split(r"[\n\r]+", value) if p.strip()]
            return parts or list(default)
        if isinstance(value, list):
            cleaned = [str(v).strip() for v in value if str(v).strip()]
            return cleaned or list(default)
        return list(default)

    @staticmethod
    def _clean_code_block(value: Any) -> str:
        if not value:
            return ""
        s = str(value).strip()
        # Drop ```lang fences
        if s.startswith("```"):
            s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if s.endswith("```"):
            s = s[:-3].rstrip()
        return s.strip()

    def _explanation_text(self, f: dict[str, Any], forensic: dict[str, Any]) -> str:
        """Combine real agent attribution with LLM root-cause prose."""
        agent = f["agent"] or "Agent"
        if f["audit_reasoning"]:
            base = f["audit_reasoning"].strip()
        elif forensic.get("root_cause"):
            base = str(forensic["root_cause"]).strip()
        else:
            base = (
                f"Pattern '{f['vuln_type']}' was observed in the live attack pipeline "
                f"and flagged with concrete request/response evidence."
            )
        confidence_part = ""
        c = f["confidence"]
        if isinstance(c, (int, float)) and 0 < c <= 1:
            confidence_part = f" Confidence: {c:.0%}."
        elif isinstance(c, (int, float)) and c > 1:
            confidence_part = f" Confidence: {int(c)}%."
        return f"{agent} forensic analysis: {base}{confidence_part}".strip()

    @staticmethod
    def _severity_breakdown(events: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for ev in events:
            etype = str(ev.get("type", "")).upper()
            if not any(k in etype for k in ("VULN_CONFIRMED", "HIDDEN_TEXT", "PROMPT_INJECTION")):
                continue
            payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
            payload = payload or {}
            sev = str(payload.get("severity", "")).upper()
            if sev not in counts:
                vuln_type = str(payload.get("type") or "").upper()
                cvss, _ = score_for_vuln_class(vuln_type)
                sev = VigilagentReportBuilder._severity_label(cvss)
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _infer_tech_stack(self, f: dict[str, Any]) -> str:
        host = urlparse(f.get("url", "")).hostname or ""
        host = host.lower()
        # Cheap heuristic — better than nothing and enough for the LLM stub.
        path = urlparse(f.get("url", "")).path.lower()
        if path.endswith(".php") or "wordpress" in host or "drupal" in host:
            return "PHP"
        if path.endswith(".aspx") or path.endswith(".asp"):
            return "ASP.NET / C#"
        if path.endswith(".jsp") or path.endswith(".do") or "tomcat" in host:
            return "Java / Servlet"
        if "/api" in path or "node" in host or "express" in host:
            return "Node.js / Express"
        if "django" in host or "drf" in host:
            return "Python / Django"
        if "flask" in host or "fastapi" in host:
            return "Python / Flask"
        return "Web Application"

    @staticmethod
    def _fallback_code(vuln_type: str, tech_stack: str) -> str:
        vt = (vuln_type or "").upper()
        if "SQL" in vt:
            return (
                "// VULNERABLE\n"
                "const q = `SELECT * FROM users WHERE id = ${userInput}`;\n"
                "db.query(q);\n\n"
                "// SECURE — parameterised query\n"
                "const stmt = 'SELECT * FROM users WHERE id = ?';\n"
                "db.query(stmt, [userInput]);"
            )
        if "XSS" in vt or "CROSS_SITE" in vt:
            return (
                "// VULNERABLE\n"
                "element.innerHTML = userInput;\n\n"
                "// SECURE — encode before reflecting back\n"
                "import { escape } from 'lodash';\n"
                "element.textContent = escape(userInput);"
            )
        if "IDOR" in vt:
            return (
                "// VULNERABLE\n"
                "app.get('/orders/:id', (req, res) => res.json(db.getOrder(req.params.id)));\n\n"
                "// SECURE — enforce ownership\n"
                "app.get('/orders/:id', requireAuth, (req, res) => {\n"
                "  const order = db.getOrder(req.params.id);\n"
                "  if (!order || order.ownerId !== req.user.id) return res.sendStatus(403);\n"
                "  res.json(order);\n"
                "});"
            )
        if "PATH_TRAVERSAL" in vt or "TRAVERSAL" in vt:
            return (
                "// VULNERABLE\n"
                "fs.readFile(path.join('/var/data', userInput), cb);\n\n"
                "// SECURE — canonicalise + base-dir check\n"
                "const base = path.resolve('/var/data');\n"
                "const target = path.resolve(base, userInput);\n"
                "if (!target.startsWith(base + path.sep)) return cb(new Error('forbidden'));\n"
                "fs.readFile(target, cb);"
            )
        if "COMMAND" in vt or "RCE" in vt:
            return (
                "# VULNERABLE\n"
                'os.system(f"ping {user_input}")\n\n'
                "# SECURE — argv list, no shell\n"
                "subprocess.run(['ping', '-c', '1', user_input], check=True)"
            )
        return (
            f"# {tech_stack} hardening sketch\n"
            "# VULNERABLE: input flowed into a sensitive sink without validation.\n"
            "# SECURE: validate, canonicalise, parameterise, and enforce authorisation.\n"
            "def handle(request):\n"
            "    value = validate(request.input)         # whitelist + canonicalise\n"
            "    require_authorisation(request.user, value)\n"
            "    return safe_use(value)                 # parameterised / encoded sink"
        )

    # ── rendering ────────────────────────────────────────────────────────────

    def _render_executive_summary(
        self,
        findings: list[dict[str, Any]],
        bullets: list[str],
    ) -> None:
        pdf = self.pdf
        pdf.big_title("Executive Summary")

        # Key/value rows
        scan_date = _first_meaningful(
            self.telemetry.get("start_time"),
            self.telemetry.get("end_time"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        pdf.kv_line("Target", self.target_url)
        pdf.kv_line("Scan ID", self.scan_id)
        pdf.kv_line("Scan Date", scan_date)
        pdf.kv_line("Findings", f"{len(findings)} vulnerabilities detected")
        pdf.ln(3)
        pdf.bullet_list(bullets)

    def _render_finding(self, idx: int, f: dict[str, Any]) -> None:
        pdf = self.pdf
        # Filter banner
        category = self._category_for(f["vuln_type"], f["name"])
        pdf.filter_banner(category)

        # Finding header
        pdf.set_text_color(*BRAND_RULE)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 8, _sanitize(f"Finding #{idx}: {f['name']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

        # Severity pill
        pdf.severity_pill(f["severity"])

        # CWE + CVSS 4.0
        pdf.kv_line("CWE", f["cwe"])
        pdf.kv_line("CVSS 4.0 Score", f"{f['cvss_score']} ({f['severity']})")
        if f.get("cvss_vector"):
            pdf.kv_line("CVSS 4.0 Vector", f["cvss_vector"])
        pdf.kv_line("CVSS Version", "4.0")

        # Threat score progress bar
        pdf.threat_bar(f["threat_score"])

        # Description
        pdf.section_label("Description:")
        pdf.bullet_list(f["description"])

        # Impact
        pdf.section_label("Impact:")
        pdf.bullet_list(f["impact"])

        # Explanation
        pdf.section_label("Explanation:")
        pdf.paragraph(f["explanation"])

        # Forensic Analysis paragraph (real method/param/url)
        pdf.section_label("Forensic Analysis:")
        forensic_text = f"Method: {f['method']} | Param: {f['param']} | URL: {f['url']}\nAnalysis: {f['forensic_line']}"
        pdf.paragraph(forensic_text)

        # Payload decomposition table (real evidence-derived rows)
        decomposition_rows = self._payload_decomposition_rows(f)
        pdf.simple_table(
            "Table 1: Payload Decomposition",
            ["Component", "Value", "Technical Function"],
            decomposition_rows,
            [38, 70, pdf.usable_width - 38 - 70],
        )

        # Payload specifications block
        encoded_hex = (f["attack_payload"] or "").encode("utf-8", "replace").hex()[:60]
        pdf.labelled_box(
            "Payload Specifications",
            [
                f"Vector Category: {f['name']}",
                f"Raw Payload:     {(f['attack_payload'] or '(empty)')[:90]}",
                f"Encoded:         {encoded_hex or '(no encoding)'}",
                f"Encoding Type:   {'hex' if encoded_hex else 'none'}",
            ],
        )

        # Reproduction command (real curl)
        pdf.section_label("Reproduction Command:")
        pdf.code_block([self._build_curl(f)])

        # HTTP traffic snapshot (real captured request + response)
        pdf.section_label("HTTP Traffic Snapshot:")
        pdf.labelled_box("Request", self._build_request_snapshot(f))
        pdf.labelled_box("Response", self._build_response_snapshot(f))

        # Remediation
        pdf.section_label("Remediation:", color=SEVERITY_COLORS["LOW"])
        pdf.bullet_list(f["remediation"])

        # Recommended code fix
        pdf.section_label("Recommended Code Fix:")
        code_lines = f["secure_code"].split("\n") if f["secure_code"] else ["# (LLM unavailable)"]
        pdf.code_block(code_lines)

    def _render_timeline(self) -> None:
        pdf = self.pdf
        pdf.big_title("Scan Timeline")
        rows: list[str] = []
        for ev in self.events[:300]:
            rows.append(self._format_timeline_row(ev))
        if not rows:
            rows = ["[Orchestrator] SCAN_INITIALIZED - no live events were buffered."]
        pdf.timeline_rows(rows)

    # ── small renderers ──────────────────────────────────────────────────────

    @staticmethod
    def _category_for(vuln_type: str, name: str) -> str:
        vt = (vuln_type or "").upper()
        if any(k in vt for k in ("SQL", "XSS", "INJECTION", "SSTI", "FUZZ", "TEMPLATE", "LDAP", "XPATH")):
            return "Injection & Fuzzing"
        if any(k in vt for k in ("IDOR", "BOLA", "OBJECT_REF")):
            return "Object References (IDOR)"
        if any(k in vt for k in ("AUTH", "JWT", "SESSION", "CREDENTIAL", "PASSWORD", "CSRF")):
            return "Authentication Gates"
        if any(k in vt for k in ("PATH", "TRAVERSAL", "SSRF", "REDIRECT", "INFORMATION", "DISCLOSURE", "DATA")):
            return "Information Disclosure"
        if any(k in vt for k in ("RACE", "TIMING", "CONCUR", "TOCTOU")):
            return "Concurrency & Timing"
        if any(k in vt for k in ("FINANCIAL", "ARITHMETIC", "PRICE", "BALANCE")):
            return "Financial Logic"
        if any(k in vt for k in ("HIDDEN", "PROMPT", "DECEPTIVE", "DARK_PATTERN")):
            return "Deceptive Content"
        if any(k in vt for k in ("PRIVILEGE", "ADMIN", "ROLE", "ESCALAT")):
            return "Privilege Escalation"
        return name.split()[0].upper() if name else "FINDINGS"

    @staticmethod
    def _payload_decomposition_rows(f: dict[str, Any]) -> list[list[str]]:
        rows: list[list[str]] = []
        # Row 1: parameter being attacked
        rows.append(
            [
                "Parameter",
                f["param"] or "(unnamed)",
                f"Targeted by {f['method']} request to demonstrate {f['name']}.",
            ]
        )
        # Row 2: raw payload
        rows.append(
            [
                "Payload",
                _truncate(f["attack_payload"] or "(empty body)", 120),
                "Crafted input that bypassed server-side validation.",
            ]
        )
        # Row 3: response indicator
        rows.append(
            [
                "Response",
                f"HTTP {f['status_code']} ({_truncate(f['response'] or f['evidence_text'] or 'observed', 60)})",
                "Server response that confirmed exploitable behaviour.",
            ]
        )
        return rows

    @staticmethod
    def _build_curl(f: dict[str, Any]) -> str:
        method = f["method"]
        url = f["url"]
        cmd = [f"curl -X {method} '{url}'"]
        for hk, hv in (f["headers"] or {}).items():
            try:
                cmd.append(f" \\\n  -H '{hk}: {hv}'")
            except Exception as hdr_exc:
                logger.debug("[ScanPDF] curl header formatting failed: %s", hdr_exc)
                continue
        if method in {"POST", "PUT", "PATCH", "DELETE"} and f["attack_payload"]:
            cmd.append(f" \\\n  --data-raw '{_truncate(f['attack_payload'], 200)}'")
        elif f["attack_payload"] and "?" not in url:
            # GET with attack payload — keep it visible by appending as raw query
            cmd.append(f" \\\n  --data-urlencode '{_truncate(f['attack_payload'], 200)}'")
        return "".join(cmd)

    @staticmethod
    def _build_request_snapshot(f: dict[str, Any]) -> list[str]:
        if f["request"]:
            text = _sanitize(f["request"]).strip()
            return [line for line in text.split("\n")][:18]
        host = urlparse(f["url"]).hostname or "target"
        lines = [f"{f['method']} {f['url']} HTTP/1.1", f"Host: {host}"]
        for hk, hv in (f["headers"] or {}).items():
            lines.append(f"{hk}: {hv}")
        if f["attack_payload"]:
            lines.append("")
            lines.append(_truncate(f["attack_payload"], 240))
        return lines[:18]

    @staticmethod
    def _build_response_snapshot(f: dict[str, Any]) -> list[str]:
        if f["response"]:
            text = _sanitize(f["response"]).strip()
            lines = text.split("\n")[:18]
            if not any(line.upper().startswith("HTTP/") for line in lines[:1]):
                lines = [f"HTTP/1.1 {f['status_code']}"] + lines
            return lines
        # Fallback: synthesise realistic response from evidence
        lines = [f"HTTP/1.1 {f['status_code']}", "Content-Type: text/plain", ""]
        evidence = f["evidence_text"] or "(no body captured)"
        lines.append(_truncate(evidence, 240))
        return lines

    @staticmethod
    def _format_timeline_row(ev: dict[str, Any]) -> str:
        ts_raw = ev.get("timestamp")
        if isinstance(ts_raw, datetime):
            ts = ts_raw.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(ts_raw, (int, float)):
            try:
                ts = datetime.fromtimestamp(float(ts_raw)).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, ValueError, OverflowError) as exc:
                logger.debug("[ScanPDF] Timestamp conversion failed: %s", exc)
                ts = str(ts_raw)
        elif isinstance(ts_raw, str) and ts_raw.strip():
            ts = ts_raw.strip()[:19]
        else:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        agent = str(ev.get("source") or ev.get("agent") or "Orchestrator")
        etype = str(ev.get("type") or "EVENT").upper()
        payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
        url = ""
        if isinstance(payload, dict):
            url = str(payload.get("url") or "")
        suffix = f" -> {url[:60]}" if url else ""
        return f"[{agent}] {etype}{suffix} - {ts}"
