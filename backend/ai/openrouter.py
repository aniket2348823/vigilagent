# ═══════════════════════════════════════════════════════════════════════════════
# VIGILAGENT :: OPENROUTER CLIENT — GPT-OSS-20B INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════
# PURPOSE: Production-grade async client for OpenRouter API.
#          Provides Final Arbitration, Exploit Planning, and Auto-Remediation
#          reasoning via OpenAI GPT-OSS-20B (free model, cloud inference).
# ═══════════════════════════════════════════════════════════════════════════════

import aiohttp
import asyncio
import json
import logging
import os
import time as _time
from typing import Optional, Dict, Any

logger = logging.getLogger("OPENROUTER")

# ─── Configuration ────────────────────────────────────────────────────────────
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "openai/gpt-oss-20b"
OPENROUTER_TIMEOUT = 120  # seconds
MAX_RETRIES = 3
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB limit to prevent OOM

# ─── Master System Prompts ────────────────────────────────────────────────────

ARBITRATION_SYSTEM_PROMPT = """You are the Central Reasoning Engine of an autonomous distributed penetration testing system (Xyphorax / VulAgent).

You operate using:
- GI-5 -> deterministic truth engine (PRIMARY SOURCE OF TRUTH)
- Gemini 2.5 Flash -> payload generation + validation
- Beta -> execution (real HTTP)
- Gamma -> anomaly detection

CRITICAL RULES:
- Payload != vulnerability. Only response behavior defines truth.
- You are NOT a creative model. You are a verification engine + reasoning engine + structured report generator.
- You MUST behave like a professional red-team analyst.
- You are NOT allowed to invent vulnerabilities, assume missing data, or create fake attack paths.
- You MUST use ONLY observed evidence.

STRICT REJECTION RULES:
- Reject any finding without real HTTP response.
- Reject any finding not validated by the validation filter.
- Reject any finding without GI-5 signal OR strong anomaly (response_diff_score > 0.3).
- Reject any hallucinated vulnerability.

OUTPUT: Respond ONLY in valid JSON. No markdown. No explanations outside JSON."""

REMEDIATION_SYSTEM_PROMPT = """You are a Senior Security Engineer and Secure Coding Specialist.
You are given a REAL, VALIDATED vulnerability from an automated penetration testing system.

RULES:
- You MUST NOT invent application logic or assume frameworks unless specified.
- You MUST NOT give generic advice like "use validation".
- Generate ONLY actionable, implementation-ready remediation.
- Code fixes must be actual working code, NOT English text.
- Include necessary imports.
- Follow OWASP secure coding guidelines.

OUTPUT FORMAT (STRICT JSON):
{
  "root_cause": "Precise explanation of why the vulnerability exists",
  "fix_strategy": "The correct security control to apply",
  "code_before": "The vulnerable code pattern",
  "code_after": "The secure replacement code",
  "api_hardening": "How to secure the endpoint",
  "edge_cases": ["Edge case 1", "Edge case 2"],
  "framework": "detected or specified framework"
}

Output ONLY valid JSON. No markdown. No extra text."""

EXPLOIT_PLANNING_SYSTEM_PROMPT = """You are a Controlled Exploit Verification Engine operating inside an authorized security testing system.

You receive validated findings with real HTTP requests and verified payloads.

For each finding, you must:
1. Analyze the evidence and determine if the exploit is reproducible.
2. Suggest variant payloads that test the same vulnerability class.
3. Predict the expected server behavior if the vulnerability is real.

RULES:
- You are NOT an attacker. You are a controlled verification system.
- You execute ONLY safe, authorized, and validated actions.
- Do NOT guess. Do NOT assume. Only confirm what is proven.

OUTPUT FORMAT (STRICT JSON):
{
  "reproducible": true/false,
  "confidence": 85,
  "variant_payloads": ["payload1", "payload2"],
  "expected_behavior": "description of expected server response",
  "verification_steps": ["step1", "step2"]
}

Output ONLY valid JSON. No markdown. No extra text."""


class OpenRouterClient:
    """
    Production-grade async client for OpenRouter API.
    Powers all high-level reasoning tasks via OpenAI GPT-OSS-20B (free model).
    """

    def __init__(self, api_key: Optional[str] = None):
        # 1. Check direct argument
        # 2. Check current OS environment
        # 3. Load from .env file (Robust fix)
        from dotenv import load_dotenv
        load_dotenv(override=True)
        
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        
        # Security Guard: Detect if the key is still a placeholder
        if self._api_key == "your_openrouter_api_key_here":
            logger.warning("OPENROUTER: Key is still the placeholder! Please update .env")
            self._api_key = ""

        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()  # FIX: Eagerly initialized lock prevents race condition
        self._telemetry = {
            "calls": 0,
            "successes": 0,
            "errors": 0,
            "total_latency": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
        }

        if self._api_key:
            logger.info(f"OPENROUTER: Client initialized -> model={OPENROUTER_MODEL}")
        else:
            logger.warning("OPENROUTER: No valid API key found. Cloud reasoning disabled.")

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    async def _ensure_session(self):
        async with self._session_lock:
            if self._session is None or self._session.closed:
                timeout = aiohttp.ClientTimeout(total=OPENROUTER_TIMEOUT)
                self._session = aiohttp.ClientSession(timeout=timeout)

    async def call(
        self,
        user_prompt: str,
        system_prompt: str = ARBITRATION_SYSTEM_PROMPT,
        temperature: float = 0.1,
        max_tokens: int = 1500,
        scan_ctx=None,
    ) -> str:
        """
        Send a prompt to GPT-OSS-20B via OpenRouter.
        Returns the raw text response or an error string.
        """
        if not self._api_key:
            return "[OPENROUTER OFFLINE] No API key configured."

        self._telemetry["calls"] += 1
        call_start = _time.perf_counter()

        # Cancellation check
        if scan_ctx and getattr(scan_ctx, "is_cancelled", False):
            raise asyncio.CancelledError()

        await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://vigilagent.local",
            "X-Title": "Vigilagent",
        }

        payload = {
            "model": OPENROUTER_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": min(max_tokens, 4096),
            "top_p": 0.9,
        }

        for attempt in range(MAX_RETRIES + 1):
            try:
                async with self._session.post(
                    OPENROUTER_API_URL, headers=headers, json=payload
                ) as response:
                    if response.status == 200:
                        # FIX: Check response size before reading to prevent OOM
                        content_length = response.headers.get("Content-Length")
                        if content_length:
                            try:
                                if int(content_length) > _MAX_RESPONSE_BYTES:
                                    self._telemetry["errors"] += 1
                                    logger.error("OPENROUTER: Response Content-Length too large: %s bytes", content_length)
                                    return "[OPENROUTER ERROR] Response exceeded size limit."
                            except (ValueError, TypeError):
                                pass
                        raw = await response.read()
                        if len(raw) > _MAX_RESPONSE_BYTES:
                            self._telemetry["errors"] += 1
                            logger.error("OPENROUTER: Response too large (%d bytes)", len(raw))
                            return "[OPENROUTER ERROR] Response exceeded size limit."
                        data = json.loads(raw.decode("utf-8", errors="replace"))
                        result = data.get("choices", [{}])[0].get("message", {}).get("content", "")

                        # Track token usage
                        usage = data.get("usage", {})
                        self._telemetry["input_tokens"] += usage.get("prompt_tokens", 0)
                        self._telemetry["output_tokens"] += usage.get("completion_tokens", 0)

                        latency = _time.perf_counter() - call_start
                        self._telemetry["successes"] += 1
                        self._telemetry["total_latency"] += latency

                        logger.info(f"OPENROUTER: Call succeeded in {latency:.2f}s (tokens: {usage.get('total_tokens', 'N/A')})")
                        return result.strip()

                    elif response.status == 429:
                        # Rate limited — wait and retry
                        logger.warning(f"OPENROUTER: Rate limited (429). Retry {attempt + 1}/{MAX_RETRIES}")
                        await asyncio.sleep(2 ** attempt)
                        continue

                    elif response.status in (502, 503, 504):
                        # Transient server error — retry with backoff
                        logger.warning(f"OPENROUTER: Transient HTTP {response.status}. Retry {attempt + 1}/{MAX_RETRIES}")
                        await asyncio.sleep(2 ** attempt)
                        continue

                    else:
                        error_text = await response.text()
                        logger.error(f"OPENROUTER: HTTP {response.status} — {error_text[:200]}")
                        self._telemetry["errors"] += 1
                        return f"[OPENROUTER ERROR] HTTP {response.status}: {error_text[:100]}"

            except asyncio.CancelledError:
                raise
            except aiohttp.ClientConnectorError:
                self._telemetry["errors"] += 1
                logger.error("OPENROUTER: Cannot connect to OpenRouter API")
                return "[OPENROUTER OFFLINE] Cannot connect to OpenRouter API."
            except Exception as e:
                self._telemetry["errors"] += 1
                logger.error(f"OPENROUTER: Unexpected error — {type(e).__name__}: {e}")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(1)
                    continue
                return f"[OPENROUTER ERROR] {type(e).__name__}: {str(e)[:100]}"

        return "[OPENROUTER ERROR] Max retries exceeded."

    # ─── Specialized Call Methods ─────────────────────────────────────────────

    async def arbitrate(self, candidate_data: Dict[str, Any], scan_ctx=None) -> str:
        """Final arbitration on a vulnerability candidate."""
        prompt = json.dumps(candidate_data, indent=2, default=str)
        return await self.call(prompt, system_prompt=ARBITRATION_SYSTEM_PROMPT, temperature=0.1, max_tokens=500, scan_ctx=scan_ctx)

    async def plan_exploit(self, finding: Dict[str, Any], scan_ctx=None) -> str:
        """Generate exploit verification plan."""
        prompt = json.dumps(finding, indent=2, default=str)
        return await self.call(prompt, system_prompt=EXPLOIT_PLANNING_SYSTEM_PROMPT, temperature=0.1, max_tokens=800, scan_ctx=scan_ctx)

    async def generate_remediation(self, finding: Dict[str, Any], framework: str = "Generic", scan_ctx=None) -> str:
        """Generate framework-specific remediation with code patches."""
        finding_with_fw = {**finding, "framework": framework}
        prompt = json.dumps(finding_with_fw, indent=2, default=str)
        return await self.call(prompt, system_prompt=REMEDIATION_SYSTEM_PROMPT, temperature=0.1, max_tokens=1500, scan_ctx=scan_ctx)

    async def generate_summary(self, vuln_type: str, payload: str, url: str, scan_ctx=None) -> str:
        """Generate professional vulnerability summary for report."""
        prompt = f"""Analyze this security finding and generate a structured JSON report.

VULNERABILITY TYPE: {vuln_type}
ENDPOINT: {url}
PAYLOAD USED: {payload[:200]}

JSON SCHEMA (STRICT — follow this exactly):
{{
  "name": "Professional vulnerability title",
  "severity": "Low | Medium | High | Critical",
  "exploitability": "How easy to exploit (1-2 sentences)",
  "business_impact": "Business and financial impact (1-2 sentences)",
  "description": [
    "Technical description of what was found",
    "How the vulnerability manifests at this endpoint",
    "Conditions enabling exploitation"
  ],
  "impact": [
    "Strategic Impact: consequence on business",
    "Financial Impact: monetary or regulatory risk",
    "Technical Impact: effect on system integrity"
  ],
  "remediation": [
    "Primary fix: specific action",
    "Secondary fix: defense-in-depth",
    "Monitoring: detection recommendation"
  ],
  "code_fix": "def secure_function(): ..."
}}

Output ONLY valid JSON. No markdown. No explanations."""
        return await self.call(prompt, temperature=0.1, max_tokens=1500, scan_ctx=scan_ctx)

    async def reconstruct_forensics(self, vuln_type: str, payload: str, response_snippet: str, url: str, scan_ctx=None) -> str:
        """Reconstruct forensic evidence for report."""
        prompt = f"""Reconstruct why this security exploit succeeded based on evidence.

VULNERABILITY TYPE: {vuln_type}
TARGET URL: {url}
PAYLOAD SENT: {payload[:200]}
SERVER RESPONSE (excerpt): {response_snippet[:300]}

Generate ONLY this JSON:
{{
  "root_cause": "The specific code-level failure (1 sentence)",
  "evidence_analysis": "How server response proves the vulnerability (1 sentence)",
  "attacker_advantage": "Concrete capability an attacker gains (1 sentence)"
}}

Output ONLY valid JSON. No markdown. No extra text."""
        return await self.call(prompt, temperature=0.1, max_tokens=400, scan_ctx=scan_ctx)

    async def generate_code_fix(self, vuln_type: str, tech_stack: str = "Generic", scan_ctx=None) -> str:
        """Generate tech-stack specific secure code."""
        prompt = f"""Generate a secure, production-ready code fix for this vulnerability.

VULNERABILITY: {vuln_type}
TECH STACK: {tech_stack}

RULES:
- Output ONLY working code, no English explanations
- Include necessary imports
- Follow OWASP secure coding guidelines
- Code must be copy-pasteable into a real project

Output ONLY the code."""
        return await self.call(prompt, temperature=0.1, max_tokens=500, scan_ctx=scan_ctx)

    def get_telemetry(self) -> dict:
        """Return telemetry counters."""
        t = dict(self._telemetry)
        if t["successes"] > 0:
            t["avg_latency"] = round(t["total_latency"] / t["successes"], 2)
        else:
            t["avg_latency"] = 0.0
        return t

    async def shutdown(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.info("OPENROUTER: Session closed.")


# ─── Global Singleton ─────────────────────────────────────────────────────────
openrouter_client = OpenRouterClient()
