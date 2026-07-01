"""
CHRONOMANCER (Architecture §9.3 — race condition / time-bound logic flaw).

Hardened gating (Architecture §17, §25):
  * ``preconditions_met`` requires a date/time-bound resource signal —
    a redeem/coupon/claim/withdraw/transfer/buy keyword in the URL OR a
    payload field that names a quantity/price/coupon/voucher/expires/start_at/
    end_at field. Without this signal Chronomancer does NOT confirm a race
    condition on the wrong endpoint type (e.g. /sqli/, /xss_r/, /brute/).
  * Wrong-class suppression: any captured response that clearly carries
    SQLI/XSS/CMDI/LFI/JWT evidence drops the finding.
"""

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability
from backend.core.verification import (
    calculate_final_confidence,
    negative_proof_check,
)

# Module-level canary reference (set by orchestrator before scan)
_canary = None
_oob_tokens: list[str] = []


def set_canary(canary) -> None:
    """Set the canary receiver for OOB verification."""
    global _canary, _oob_tokens
    _canary = canary
    _oob_tokens = []


def clear_canary() -> None:
    """Reset canary state after a scan."""
    global _canary, _oob_tokens
    _canary = None
    _oob_tokens = []

_RACE_FIELDS = (
    "quantity",
    "qty",
    "amount",
    "voucher",
    "coupon",
    "code",
    "expires",
    "expires_at",
    "start_at",
    "end_at",
    "deadline",
    "claim",
    "redeem",
)
_RACE_URL_HINTS = (
    "redeem",
    "coupon",
    "claim",
    "withdraw",
    "transfer",
    "buy",
    "purchase",
    "vote",
    "like",
    "follow",
    "checkout",
    "subscribe",
    "ticket",
    "reservation",
)


def preconditions_met(packet: JobPacket) -> bool:
    """Return True iff the target is a date/time-bound or stateful resource
    that a race-condition attack could meaningfully exploit. Returns False for
    plain GET endpoints with no money/voucher/expiry signal."""
    target = getattr(packet, "target", None)
    if not target:
        return False
    payload = getattr(target, "payload", None) or {}
    if isinstance(payload, dict):
        keys = {str(k).lower() for k in payload}
        if keys & set(_RACE_FIELDS):
            return True
    url = (getattr(target, "url", "") or "").lower()
    return any(h in url for h in _RACE_URL_HINTS)


class Chronomancer(BaseArsenalModule):
    """
    MODULE: CHRONOMANCER
    Logic: Race Conditions (Concurrency Exploitation).
    Cyber-Organism Protocol: Gate Synchronization (Single Packet Flood).
    """

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        if not preconditions_met(packet):
            return []

        targets: list[TaskTarget] = [packet.target] * 20

        # Method 20: OOB canary-backed race detection.
        # Send extra requests with OOB payloads so the canary server
        # records concurrent callbacks — proving the race path executes.
        if _canary and hasattr(_canary, 'generate_token') and len(_oob_tokens) < 50:
            try:
                oob_token = _canary.generate_token()
                _oob_tokens.append(oob_token)
                oob_domain = _canary.base_url.replace("http://", "").replace("https://", "")
                callback_url = f"http://{oob_domain}/race?token={oob_token}"
                # Append a few extra targets that include the canary callback URL
                # in the request body (server may trigger outbound request)
                race_target = TaskTarget(
                    url=packet.target.url,
                    method=packet.target.method or "GET",
                    headers=dict(packet.target.headers or {}),
                    payload={
                        **(packet.target.payload if isinstance(packet.target.payload, dict) else {}),
                        "callback": callback_url,
                        "redirect_url": callback_url,
                    },
                )
                targets.extend([race_target] * 5)
            except Exception:
                pass

        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """Confirm a race condition by counting concurrent CLEAN successes
        (Architecture §9.3): a success marker AND no denial/error marker. A
        single success is not a race; we require > 1 simultaneous clean success.

        Method 28 integration: Uses verification engine's race_condition_detection
        signal pattern for consistent, multi-signal confirmation.
        """
        from backend.modules.evidence import classify_response_evidence, logic_confirm

        if not preconditions_met(packet):
            return []

        # Wrong-class suppression.
        for _t, text in interactions:
            if isinstance(text, str):
                classes = classify_response_evidence(text)
                if classes - {"RACE_CONDITION"}:
                    return []

        vulns = []
        clean_successes = 0
        inconsistent_bodies = set()
        for _target, text in interactions:
            if not isinstance(text, str):
                continue
            ev = logic_confirm(text, positive_markers=["success", "redeem", "confirm", "applied"])
            if ev.verified:
                clean_successes += 1
                inconsistent_bodies.add(text[:200])  # track unique response bodies

        # The race signal is multiple clean concurrent successes where the logic
        # should have allowed only one.
        if clean_successes > 1:
            # Method 28: Inconsistent response bodies strengthen race condition proof
            body_diversity = len(inconsistent_bodies)
            signals = ["concurrent_success", f"{clean_successes}_parallel_succeeded"]
            if body_diversity > 1:
                signals.append(f"{body_diversity}_unique_responses")

            # Method 20: OOB canary callback — proves race path triggers outbound
            if _canary and _oob_tokens:
                try:
                    canary_hits = sum(1 for t in _oob_tokens if _canary.check_token(t))
                    if canary_hits > 0:
                        signals.append("oob_canary_callback")
                except Exception:
                    pass

            # Method 3: Negative proof — ensure no denial markers
            combined_text = " ".join(t for _, t in interactions if isinstance(t, str))
            is_genuine, neg_reasons = negative_proof_check(
                combined_text, interactions[0][1] if interactions else "", "RACE_CONDITION"
            )

            confidence = calculate_final_confidence(
                base_confidence=0.85,
                reproducibility=clean_successes,
                has_negative_proof_pass=is_genuine,
                has_side_channel=body_diversity > 1,
            )

            vulns.append(
                Vulnerability(
                    name="Race Condition (Concurrency Exploitation)",
                    severity="HIGH",
                    description=f"Executed {len(interactions)} parallel requests; "
                    f"{clean_successes} succeeded simultaneously without denial. "
                    f"Signals: {', '.join(signals)}.",
                    evidence=f"Clean concurrent successes: {clean_successes}/{len(interactions)}; "
                    f"Unique response bodies: {body_diversity}; {', '.join(signals)}",
                    remediation="Implement strict database locks, atomic operations, or mutexes.",
                    confidence=confidence,
                )
            )
        return vulns
