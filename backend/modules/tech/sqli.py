import logging
import urllib.parse

from backend.ai.cortex import get_cortex_engine
from backend.core.base import BaseArsenalModule
from backend.core.protocol import JobPacket, TaskTarget, Vulnerability

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
        payloads = ["' OR 1=1--", "admin' #", "' UNION SELECT 1,2,3--"]

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
                import logging

                logging.getLogger("sqli").debug("AI payload generation failed: %s", e)  # Keep base payloads

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
        """Confirm SQLi via differential analysis, not a bare substring match.

        A DB-error signature alone is a weak signal; we require it to coincide
        with a material differential vs the baseline response (Architecture §9,
        §17 — >= 2 independent signals)."""
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
        ]
        seen = set()
        for idx, (target, text) in enumerate(interactions):
            if idx == 0 or not isinstance(text, str) or not text:
                continue
            low = text.lower()
            error_signal = any(m in low for m in sql_error_markers)
            ev = differential(baseline_text, text)
            # Require either (error signature + at least one diff signal) or a
            # strong differential (>=2 signals). Never confirm on substring alone.
            confirmed = (error_signal and ev.signals >= 1) or ev.verified
            if confirmed and target.url not in seen:
                seen.add(target.url)
                vulnerabilities.append(
                    Vulnerability(
                        name="SQL Injection",
                        severity="CRITICAL",
                        description="Injection caused a material, repeatable response divergence.",
                        evidence=(f"Target: {target.url}\nDB-error signature: {error_signal}; {ev.summary}"),
                        remediation="Use parameterized queries (Prepared Statements).",
                    )
                )
        return vulnerabilities
