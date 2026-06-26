"""
Vigilagent Report Generator (V8)
================================================================================
Per-scan PDF generator that mirrors the uploaded "Vigilagent" layout
exactly:

  * Page 1:  EXECUTIVE SUMMARY  (real Target / Scan ID / Date / Findings)
  * Pages 2..N-1: DETAILED FINDINGS — one section per real confirmed finding
  * Last page: SCAN TIMELINE — bullets from the live scan_events buffer.

All HTTP request/response bodies, payloads, parameters, methods, URLs, and
timeline rows come from the scan record. The Cortex LLM (Gemini / OpenRouter)
is used ONLY to expand prose (description / impact / explanation / remediation
/ secure code fix). When the LLM is offline we fall back to deterministic text.

Public API preserved:
    ReportGenerator().generate_report(scan_id, events, target_url, telemetry, manager)
        -> str | None    (absolute path to the produced PDF)

The output path stays at <REPORTS_DIR>/Scan_Report_<scan_id>.pdf so the
existing /api/reports/download/<file> endpoint keeps working.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.ai.cortex import get_cortex_engine
from backend.reporting.scan_pdf import VigilagentReportBuilder

logger = logging.getLogger("REPORTING")


class ReportGenerator:
    """Thin façade that delegates to the Vigilagent PDF builder.

    Kept as a class to preserve the public surface used by:
      - backend.core.orchestrator
      - backend.api.endpoints.reports
    """

    async def generate_report(
        self,
        scan_id: str,
        events: list[dict[str, Any]],
        target_url: str,
        telemetry: dict[str, Any] | None = None,
        manager: Any = None,
    ) -> str | None:
        try:
            cortex = get_cortex_engine()
        except Exception as exc:  # pragma: no cover - never fatal
            logger.warning("ReportGenerator: cortex unavailable (%s) - LLM disabled", exc)
            cortex = None

        builder = VigilagentReportBuilder(
            scan_id=scan_id,
            target_url=target_url,
            events=events or [],
            telemetry=telemetry or {},
            cortex=cortex,
            manager=manager,
        )
        try:
            out_path = await builder.build()
            logger.info("[REPORTER] Vigilagent report generated: %s", out_path)
            return out_path
        except Exception as exc:
            logger.exception("[REPORTER] Failed to generate Vigilagent report: %s", exc)
            return None
