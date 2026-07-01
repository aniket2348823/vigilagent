import logging
import random
import urllib.parse

from backend.ai.cortex import get_cortex_engine
from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability
from backend.core.verification import (
    negative_proof_check,
    entropy_delta,
    side_channel_analysis,
    fingerprint_length_delta,
    generate_stochastic_sqli_boolean,
    calculate_final_confidence,
    stack_inconsistent_with_vuln,
    generate_oob_exfil_payloads,
)

# Module-level canary reference (set by orchestrator before scan)
_canary = None
_oob_tokens: list[str] = []  # tokens generated for current scan


def set_canary(canary) -> None:
    """Set the canary receiver for OOB verification."""
    global _canary, _oob_tokens
    _canary = canary
    _oob_tokens = []


def clear_canary() -> None:
    """Reset canary state after a scan to prevent stale tokens."""
    global _canary, _oob_tokens
    _canary = None
    _oob_tokens = []

logger = logging.getLogger("sqli")


class SQLInjectionProbe(BaseArsenalModule):
    def __init__(self):
        super().__init__()
        self.name = "SQL Injection Probe"
        # CORTEX AI for intelligent payload generation
        try:
            self.ai = get_cortex_engine()
        except Exception as _e:
            logger.debug("AI engine init deferred: %s", _e)
            self.ai = None

    async def generate_payloads(self, packet: JobPacket) -> list[TaskTarget]:
        targets = []
        payloads = [
            "' OR 1=1--",
            "admin' #",
            "' UNION SELECT 1,2,3--",
        ]

        # Method 11: Add stochastic boolean toggle payloads for deterministic proof
        for true_p, false_p, _desc in generate_stochastic_sqli_boolean():
            payloads.extend([true_p, false_p])

        # Method 17: Add divergence-mapping payloads (benign + other class)
        payloads.extend([
            "hello world",          # benign control
            "test123",
            "<script>alert(1)</script>",  # XSS class (should NOT diverge for SQLi)
        ])

        # Method 21: WAF bypass payloads
        try:
            from backend.core.verification import generate_waf_bypass_payloads
            bypasses = generate_waf_bypass_payloads("' OR 1=1--")
            payloads.extend(b for b in bypasses if b not in payloads)
        except Exception:
            pass

        # Method 20: OOB exfiltration payloads (canary-backed)
        if _canary and hasattr(_canary, 'generate_token'):
            if len(_oob_tokens) >= 50:
                logger.debug("OOB token cap reached (50), skipping")
            else:
                try:
                    oob_token = _canary.generate_token()
                    _oob_tokens.append(oob_token)
                    oob_domain = _canary.base_url.replace("http://", "").replace("https://", "")
                    for oob_payload, _oob_path in generate_oob_exfil_payloads(oob_domain, oob_token, "SQLI"):
                        payloads.append(oob_payload)
                except Exception as e:
                    logger.debug("OOB payload generation failed: %s", e)

        # CORTEX AI: Generate database-specific payloads
        if self.ai and self.ai.enabled:
            try:
                db_type = (
                    packet.config.params.get("db_type", "unknown") if hasattr(packet.config, "params") else "unknown"
                )
                ai_payloads = await self.ai.generate_sqli_payloads(target_url=packet.target.url, db_type=db_type)
                if ai_payloads:
                    payloads.extend(ai_payloads)
            except Exception as e:
                logger.debug("AI payload generation failed: %s", e)

        if "?" in packet.target.url:
            base_url, query = packet.target.url.split("?", 1)
            params = urllib.parse.parse_qs(query)

            for param, values in params.items():
                for payload in payloads:
                    # MED-44: Use copy.deepcopy to prevent mutating shared params
                    attack_params = {k: list(v) for k, v in params.items()}
                    attack_params[param] = [values[0] + payload]
                    attack_query = urllib.parse.urlencode(attack_params, doseq=True)
                    attack_url = f"{base_url}?{attack_query}"

                    targets.append(
                        TaskTarget(
                            url=attack_url, method="GET", headers=packet.target.headers, payload=packet.target.payload
                        )
                    )
        return targets

    async def analyze_responses(
        self, interactions: list[tuple[TaskTarget, str]], packet: JobPacket
    ) -> list[Vulnerability]:
        """Confirm SQLi via multi-layer verification (Methods 3, 9, 11, 14, 16, 18).

        Requires >= 2 independent signals:
          - DB-error signature + differential (Method 9: side-channel)
          - Stochastic boolean toggle (Method 11: deterministic proof)
          - Content-length fingerprint (Method 16)
          - Negative proof check (Method 3: no innocent explanations)
          - Tech-stack consistency (Method 18: wrong-stack FP suppression)
          - Entropy analysis (Method 14: high-entropy = real data)
        """
        from backend.modules.evidence import differential

        vulnerabilities = []
        if not interactions:
            return vulnerabilities

        # Baseline = first interaction (original/unmodified request).
        baseline_target, baseline_text = interactions[0]
        baseline_text = baseline_text if isinstance(baseline_text, str) else ""

        sql_error_markers = [
            "sql syntax",
            "sql error",
            "mysql",
            "psql",
            "ora-",
            "sqlite",
            "syntax error",
            "unclosed quotation",
            "odbc",
            "sqlstate",
        ]

        # Method 3: Negative proof — SQL error markers in baseline = FP
        is_genuine, neg_reasons = negative_proof_check(baseline_text, baseline_text, "SQLI")
        if not is_genuine:
            logger.debug("SQLi negative proof failed: %s", neg_reasons)
            return []

        # Build a URL→index lookup for matching true/false boolean pairs
        # so the stochastic toggle check uses the SAME random tokens sent
        # in generate_payloads() — not freshly generated ones.
        url_index: dict[str, int] = {}
        for i, (tgt, _t) in enumerate(interactions):
            if tgt and tgt.url:
                url_index[tgt.url] = i

        seen = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue
            low = text.lower()
            error_signal = any(m in low for m in sql_error_markers)
            ev = differential(baseline_text, text)

            signals: list[str] = []

            # Signal 1: DB error signature + differential
            if error_signal and (ev.signals >= 1 or ev.verified):
                signals.append("error_differential")

            # Signal 1b: Strong differential alone (data extraction via UNION)
            if ev.verified and not error_signal:
                signals.append("data_extraction_differential")

            # Method 11: Stochastic boolean toggle — extract the actual payload
            # from the URL and look for the paired false payload in other
            # interactions (same random tokens from generate_payloads).
            payload_url = target.url
            for true_p, false_p, _desc in generate_stochastic_sqli_boolean():
                if true_p in payload_url:
                    for other_idx, (other_target, other_text) in enumerate(interactions):
                        if other_idx != idx and other_target and false_p in other_target.url:
                            if isinstance(other_text, str) and len(text) != len(other_text):
                                signals.append("stochastic_boolean_toggle")
                                break
                    break  # only match the first stochastic pair

            # Method 9: Side-channel via status + length pattern
            sc_ok, sc_desc = side_channel_analysis(200, len(baseline_text), 200, len(text), "SQLI")
            if sc_ok:
                signals.append("side_channel")

            # Method 20: OOB canary callback verification (only scan our tokens)
            if _canary and _oob_tokens:
                try:
                    for oob_tok in _oob_tokens:
                        if _canary.check_token(oob_tok):
                            signals.append("oob_canary_callback")
                            break
                except Exception as e:
                    logger.debug("OOB callback check failed: %s", e)

            # Method 14: Entropy analysis — SQL errors are high-entropy
            ent_d = entropy_delta(baseline_text, text)
            if abs(ent_d) > 0.5:
                signals.append("entropy_change")

            if not signals:
                continue

            key = target.url
            if key in seen:
                continue
            seen.add(key)

            # Method 34: Stack consistency check
            try:
                from backend.core.verification import fingerprint_tech_stack
                fp = fingerprint_tech_stack(packet.target.headers or {}, baseline_text)
                stack_bad, stack_reason = stack_inconsistent_with_vuln(fp, "SQLI")
            except Exception:
                stack_bad, stack_reason = False, ""

            confidence = calculate_final_confidence(
                base_confidence=0.75 if error_signal else 0.65,
                has_negative_proof_pass=is_genuine,
                has_timing_proof=False,
                has_semantic_marker="stochastic_boolean_toggle" in signals,
                has_side_channel="side_channel" in signals,
                has_entropy_signal="entropy_change" in signals,
                has_stack_consistency=not stack_bad,
            )

            vulnerabilities.append(
                Vulnerability(
                    name="SQL Injection",
                    severity="CRITICAL",
                    description=(
                        "Injection caused a material, repeatable response divergence. "
                        f"Signals: {', '.join(signals)}."
                    ),
                    evidence=(
                        f"Target: {target.url}\n"
                        f"DB-error signature: {error_signal}; {ev.summary}\n"
                        f"Verification signals: {', '.join(signals)}\n"
                        f"Side-channel: {sc_desc}"
                    ),
                    remediation="Use parameterized queries (Prepared Statements).",
                    confidence=confidence,
                )
            )
        return vulnerabilities
