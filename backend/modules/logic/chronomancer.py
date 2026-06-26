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
        # Cyber-Organism Protocol: 20 Parallel Connections (Single Packet Flood via gather)
        return [packet.target] * 20

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """Confirm a race condition by counting concurrent CLEAN successes
        (Architecture §9.3): a success marker AND no denial/error marker. A
        single success is not a race; we require > 1 simultaneous clean success."""
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
        for _target, text in interactions:
            if not isinstance(text, str):
                continue
            ev = logic_confirm(text, positive_markers=["success", "redeem", "confirm", "applied"])
            if ev.verified:
                clean_successes += 1

        # The race signal is multiple clean concurrent successes where the logic
        # should have allowed only one.
        if clean_successes > 1:
            vulns.append(
                Vulnerability(
                    name="Race Condition (Concurrency Exploitation)",
                    severity="HIGH",
                    description=f"Executed {len(interactions)} parallel requests; "
                    f"{clean_successes} succeeded simultaneously without denial.",
                    evidence=f"Clean concurrent successes: {clean_successes}/{len(interactions)}",
                    remediation="Implement strict database locks, atomic operations, or mutexes.",
                )
            )
        return vulns
