import difflib
from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, Vulnerability, TaskTarget
from backend.core.credential_vault import credential_vault
from backend.modules.evidence import classify_response_evidence

# Lazy-init: import at call time to avoid blocking app startup (HIGH-49)
_cortex = None


def _get_cortex():
    global _cortex
    if _cortex is None:
        from backend.ai.cortex import get_cortex_engine
        _cortex = get_cortex_engine()
    return _cortex

class Doppelganger(BaseArsenalModule):
    """
    MODULE: DOPPELGANGER
    Logic: Insecure Direct Object Reference (IDOR).
    Cyber-Organism Protocol: Cosine Similarity Diffing.

    Uses a REAL alternate identity from the CredentialVault (Architecture §25),
    replacing the former hardcoded MOCK_USER_B_TOKEN.
    """
    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        target = packet.target
        user_a_token = target.headers.get("Authorization")
        if not user_a_token:
            return []

        # Obtain a real second identity (User B) from the credential vault.
        # The vault holds only authorized, in-scope test credentials.
        scan_id = getattr(packet, "scan_id", None) or getattr(getattr(packet, "config", None), "scan_id", "GLOBAL")
        alt = credential_vault.get_alternate_identity(target.url, exclude_principal=user_a_token)
        if not alt:
            # No second authorized identity available — cannot run an IDOR
            # differential safely. Skip rather than fabricate a mock token.
            return []
        _cred, user_b_secret = alt
        user_b_token = user_b_secret if user_b_secret.lower().startswith("bearer ") else f"Bearer {user_b_secret}"

        headers_b = target.headers.copy()
        headers_b["Authorization"] = user_b_token

        return [
            target,  # Baseline Target (User A)
            TaskTarget(url=target.url, method=target.method, headers=headers_b, payload=target.payload),  # Attack Target (User B)
        ]

    async def analyze_responses(self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket) -> list[Vulnerability]:
        if len(interactions) < 2: return []
        
        baseline_target, baseline_text = interactions[0]
        attack_target, attack_text = interactions[1]
        
        vulns = []
        if isinstance(attack_text, str) and isinstance(baseline_text, str):
            # WRONG-CLASS SUPPRESSION: drop if response clearly belongs to another class
            for _t, text in interactions:
                if isinstance(text, str):
                    classes = classify_response_evidence(text)
                    if classes - {"IDOR"}:
                        return []

            # HIGH-36: Truncate large responses before O(n²) comparison
            max_cmp = 50000
            b_text = baseline_text[:max_cmp] if len(baseline_text) > max_cmp else baseline_text
            a_text = attack_text[:max_cmp] if len(attack_text) > max_cmp else attack_text
            ratio = difflib.SequenceMatcher(None, b_text, a_text).ratio()
            # NC-7: Require multi-signal confirmation — high similarity alone is insufficient
            if ratio > 0.95:
                cortex = _get_cortex()
                idor_analysis = await cortex.classify_idor_response(attack_text, ratio)
                sensitivity = idor_analysis.get("sensitivity", "HIGH")
                data_types = idor_analysis.get("data_types", [])
                is_leak = idor_analysis.get("is_leak", False)
                # Require at least one signal: AI-confirmed leak or data types exposed
                if not is_leak and not data_types:
                    return []
                vulns.append(Vulnerability(
                    name="IDOR (Broken Access Control)",
                    severity="CRITICAL" if sensitivity in ["CRITICAL", "HIGH"] else "HIGH",
                    description=f"User B access confirmed. Similarity: {ratio*100:.2f}%. Sensitivity: {sensitivity}. Data: {data_types}",
                    evidence=f"Diff Ratio: {ratio}, AI Sensitivity: {sensitivity}",
                    remediation="Implement strict object-level authorization matching session ID to resource owner."
                ))
        return vulns
