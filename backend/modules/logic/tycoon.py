"""
THE TYCOON (Architecture §9.3 — financial logic flaw).

Hardened gating (Architecture §17, §25):
  * ``preconditions_met`` requires a money/quantity/price field signal — either
    a dedicated price/quantity/amount/cost/total field in the request payload,
    OR a checkout/cart/payment/order/billing keyword in the URL. Without it
    Tycoon does NOT confirm a financial logic flaw on the wrong endpoint
    (e.g. /vulnerabilities/sqli/?id=1, /xss_r/?name=test, /brute/).
  * After analysis, any captured response body that clearly belongs to a
    different vuln class (SQL error, /etc/passwd, executable XSS reflection,
    CMDI output) suppresses Tycoon findings.
"""

import copy
import logging

from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

logger = logging.getLogger(__name__)

# Lazy-init: import at call time to avoid blocking app startup (HIGH-49)
_cortex = None


def _get_cortex():
    global _cortex
    if _cortex is None:
        from backend.ai.cortex import get_cortex_engine

        _cortex = get_cortex_engine()
    return _cortex


_FINANCIAL_FIELDS = (
    "price",
    "quantity",
    "qty",
    "amount",
    "cost",
    "total",
    "subtotal",
    "currency",
    "discount",
    "voucher",
    "coupon",
    "balance",
    "fee",
    "tax",
    "rate",
    "value",
)
_FINANCIAL_URL_HINTS = (
    "checkout",
    "cart",
    "payment",
    "pay",
    "order",
    "purchase",
    "buy",
    "billing",
    "invoice",
    "wallet",
    "transfer",
    "refund",
    "subscribe",
    "subscription",
    "plan",
    "pricing",
)


def preconditions_met(packet: JobPacket) -> bool:
    """Return True iff the target carries a financial signal — either a known
    money/quantity field in the request body, or a financial-shaped URL.
    Without one, Tycoon refuses to fabricate a 'financial logic flaw'."""
    target = getattr(packet, "target", None)
    if not target:
        return False
    payload = getattr(target, "payload", None) or {}
    if isinstance(payload, dict):
        keys = {str(k).lower() for k in payload}
        if keys & set(_FINANCIAL_FIELDS):
            return True
    url = (getattr(target, "url", "") or "").lower()
    return any(h in url for h in _FINANCIAL_URL_HINTS)


class TheTycoon(BaseArsenalModule):
    """
    MODULE: THE TYCOON
    Category: Logic Assassin (Financial)
    Advanced Capabilities:
    1. Negative Quantity Injection (Integer Overflow)
    2. Floating Point Rounding (0.1 + 0.2 != 0.3)
    3. Currency Arbitrage
    """

    def __init__(self):
        super().__init__()
        self.name = "The Tycoon"

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        # PRECONDITION GATE: refuse to generate payloads on non-financial targets.
        if not preconditions_met(packet):
            return []

        target = packet.target
        targets = []

        # HYBRID AI: Generate financial attack vectors
        ai_vectors = await _get_cortex().generate_financial_vectors(target.url, target.payload)

        # VECTOR 1: Standard + AI-generated financial attacks
        test_values = [(-1, "Negative Quantity"), (2147483648, "Integer Overflow")]
        for vec in ai_vectors:
            try:
                if isinstance(vec, dict) and isinstance(vec.get("value"), (int, float)) and "attack" in vec:
                    test_values.append((vec["value"], str(vec.get("attack", "AI_Generated"))[:100]))
            except Exception as vec_exc:
                import logging as _log

                _log.getLogger("Tycoon").debug("Malformed AI vector skipped: %s", vec_exc)
                continue  # HIGH-55: skip malformed AI vectors without crashing

        for qty, _attack_name in test_values:
            payload_qty = copy.deepcopy(target.payload) if target.payload else {}
            payload_qty["quantity"] = qty
            targets.append(TaskTarget(url=target.url, method="POST", headers=target.headers, payload=payload_qty))

        # VECTOR 2: FLOATING POINT ROUNDING
        payload_float = copy.deepcopy(target.payload) if target.payload else {}
        payload_float["price"] = 0.00001
        payload_float["amount"] = 1000
        targets.append(TaskTarget(url=target.url, method="POST", headers=target.headers, payload=payload_float))

        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """Confirm financial logic flaws with >= 2 independent signals (Architecture §9.3)."""
        from backend.modules.evidence import classify_response_evidence, logic_confirm

        # PRECONDITION GATE re-enforced on the analyze side.
        if not preconditions_met(packet):
            return []

        # WRONG-CLASS SUPPRESSION: drop everything if any response clearly
        # belongs to a different vuln class.
        for _t, text in interactions:
            if isinstance(text, str):
                classes = classify_response_evidence(text)
                if classes - {"FINANCIAL"}:
                    return []

        vulns = []
        for target, text in interactions:
            if not isinstance(text, str):
                continue
            ev = logic_confirm(text, positive_markers=["success", "order confirmed", "accepted", "paid"])
            if not ev.verified:
                continue
            if target.payload and "quantity" in target.payload:
                qty = target.payload.get("quantity")
                vulns.append(
                    Vulnerability(
                        name="Financial Logic Flaw (Qty)",
                        severity="CRITICAL",
                        description=f"Server accepted quantity {qty}, potentially refunding or overflowing.",
                        evidence=f"{target.payload}. {ev.summary}",
                        remediation="Perform strict validation on quantity and ensure it is > 0.",
                    )
                )
            elif target.payload and "price" in target.payload:
                vulns.append(
                    Vulnerability(
                        name="Precision Rounding Bypass",
                        severity="HIGH",
                        description="Server accepted sub-atomic currency values.",
                        evidence=f"{target.payload}. {ev.summary}",
                        remediation="Validate decimal precision matches currency constraints.",
                    )
                )
        return vulns
