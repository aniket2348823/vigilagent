"""
THE SKIPPER (Architecture §9.3 — workflow-bypass logic flaw).

Tightened so it only fires when there is actual evidence of a multi-step state
machine being bypassed. Previously, this module emitted CONFIRMED findings on
any endpoint whose response body happened to contain the word "success" or
"welcome" — DVWA's `/brute/` login form returns "Welcome to the password
protected area" on the failure page, which tripped the heuristic.

The hardened logic requires:
  1) the orchestrator/recon must have flagged this endpoint as part of a
     multi-step workflow (`packet.config.params['workflow_steps']` populated
     by Cortex), OR the URL must contain an obvious workflow-step keyword
     (checkout/payment/confirm/success/order/wizard/step), AND
  2) the response carries POST-WORKFLOW positive markers AND the baseline
     (a fetch without spoofed Referer) does NOT, AND
  3) we observe a meaningful structural divergence between the baseline and
     the bypass attempt (>=1 verifier signal).

Without all three, this module returns no findings.

Architecture §17/§25 reinforcement:
  * ``preconditions_met`` is the explicit gate. ``generate_payloads`` AND
    ``analyze_responses`` both bail when it fails — defending against the
    case where the orchestrator hands the module pre-built interactions.
  * If any captured response body clearly belongs to a DIFFERENT vuln class
    (SQL error, /etc/passwd, executable XSS reflection, CMDI output) the
    module suppresses any finding it produced. Skipper MUST NOT confirm a
    workflow bypass on /brute/, /sqli/, /fi/, /xss_r/, /exec/.
"""

from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

logger = logging.getLogger("TheSkipper")

_WORKFLOW_HINTS = (
    "checkout",
    "payment",
    "confirm",
    "success",
    "complete",
    "order",
    "review",
    "wizard",
    "step",
    "thank",
    "summary",
    "finalize",
)


def _looks_like_workflow(url: str, params: dict | None) -> bool:
    """The Skipper only runs when the orchestrator flags a workflow OR the URL
    is obviously a multi-step flow."""
    if params and params.get("workflow_steps"):
        return True
    low = (url or "").lower()
    return any(h in low for h in _WORKFLOW_HINTS)


def preconditions_met(packet: JobPacket) -> bool:
    """Public precondition gate. Returns False on single-step / non-workflow
    targets (login forms, single GETs, brute force pages, SQLi/XSS sinks) so
    Skipper does NOT confirm WORKFLOW_BYPASS on the wrong category."""
    target = getattr(packet, "target", None)
    url = getattr(target, "url", "") if target else ""
    params = getattr(getattr(packet, "config", None), "params", None) or {}
    return _looks_like_workflow(url, params)


class TheSkipper(BaseArsenalModule):
    """Workflow Bypass (State Machine Violation)."""

    def __init__(self):
        super().__init__()
        self.name = "The Skipper"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        target = packet.target
        if not preconditions_met(packet):
            # Not a workflow target — do nothing. Returning an empty list keeps
            # the analyzer honest (it will not invent signals).
            return []

        # Resolve the workflow chain via Cortex (best effort).
        success_url = target.url
        try:
            cortex_engine = getattr(self, "cortex", None)
            if cortex_engine is None:
                from backend.ai.cortex import get_cortex_engine

                cortex_engine = get_cortex_engine()
            workflow_steps = await cortex_engine.infer_workflow_chain(target.url)
            if workflow_steps:
                success_url = urljoin(target.url, workflow_steps[-1])
        except Exception as exc:
            logger.debug("[Skipper] Workflow chain inference failed: %s", exc)
            workflow_steps = []

        targets: list[TaskTarget] = []

        # Index 0: BASELINE — direct fetch of the final step with NO Referer
        #   and NO spoofed cookies. A real workflow rejects this.
        targets.append(
            TaskTarget(
                url=success_url,
                method="GET",
                headers={k: v for k, v in (target.headers or {}).items() if k.lower() not in ("referer",)},
                payload=target.payload,
            )
        )

        # Index 1: STEP-JUMPING with same headers (still no Referer).
        targets.append(
            TaskTarget(url=success_url, method="GET", headers=dict(target.headers or {}), payload=target.payload)
        )

        # Index 2: REFERER-SPOOFING — pretend we came from the previous step.
        spoofed = dict(target.headers or {})
        # Build a plausible "previous step" referer.
        parsed = urlparse(target.url)
        prev_step_path = "checkout" if parsed.path != "/checkout" else "cart"
        spoofed["Referer"] = f"{parsed.scheme}://{parsed.netloc}/{prev_step_path}"
        targets.append(TaskTarget(url=success_url, method="GET", headers=spoofed, payload=target.payload))
        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        from backend.modules.evidence import classify_response_evidence, differential, logic_confirm

        # PRECONDITION GATE re-enforced on the analyze side. If the worker
        # somehow handed us interactions for a non-workflow target, refuse to
        # produce findings (Architecture §17, §25).
        if not preconditions_met(packet):
            return []

        if len(interactions) < 2:
            return []
        baseline_target, baseline_text = interactions[0]
        baseline_text = baseline_text if isinstance(baseline_text, str) else ""

        # WRONG-CLASS SUPPRESSION: any captured body that clearly belongs to
        # a different vuln class (SQL error, /etc/passwd, XSS sentinel, CMDI
        # output) → drop. This endpoint is plainly NOT a workflow page.
        for _t, text in interactions:
            if isinstance(text, str):
                classes = classify_response_evidence(text)
                if classes - {"WORKFLOW_BYPASS"}:
                    return []

        # If the BASELINE itself shows post-workflow markers, the endpoint is
        # public and has no workflow to bypass — bail out, no finding.
        baseline_ev = logic_confirm(
            baseline_text,
            positive_markers=["order confirmed", "payment received", "purchase complete", "checkout success"],
        )
        if baseline_ev.verified:
            return []

        vulns: list[Vulnerability] = []
        for idx, (target, text) in enumerate(interactions[1:], start=1):
            if not isinstance(text, str) or not text:
                continue
            # Signal 1: post-workflow markers present here AND absent in baseline.
            ev = logic_confirm(
                text,
                positive_markers=[
                    "order confirmed",
                    "payment received",
                    "purchase complete",
                    "checkout success",
                    "thank you for your order",
                ],
            )
            if not ev.verified:
                continue
            # Signal 2: structural divergence vs baseline.
            diff = differential(baseline_text, text)
            if diff.signals < 1 and not diff.verified:
                continue

            if idx == 1:
                vulns.append(
                    Vulnerability(
                        name="Workflow Bypass (Direct Access)",
                        severity="HIGH",
                        description="Post-workflow page accessible by direct request without "
                        "completing the prior steps.",
                        evidence=f"URL: {target.url}. Skipper baseline rejected. {ev.summary}; {diff.summary}",
                        remediation="Enforce server-side state machine checks at every workflow step.",
                    )
                )
            elif idx == 2:
                vulns.append(
                    Vulnerability(
                        name="Workflow Bypass (Referer Spoofing)",
                        severity="CRITICAL",
                        description="Post-workflow page accessible by spoofing the Referer header.",
                        evidence=(
                            f"URL: {target.url}; Referer: {target.headers.get('Referer', '')}. "
                            f"{ev.summary}; {diff.summary}"
                        ),
                        remediation="Never trust Referer for authorization; use signed/anti-CSRF tokens.",
                    )
                )
        return vulns
