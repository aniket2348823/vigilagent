# ═══════════════════════════════════════════════════════════════════════════════
# VIGILAGENT :: NVIDIA CLIENT — NVIDIA NIM / BUILD.NVIDIA.COM INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════
# PURPOSE: Production-grade async client for the NVIDIA API (build.nvidia.com /
#          NVIDIA NIM microservices). OpenAI-compatible chat-completions endpoint
#          hosting the full NVIDIA model catalog (Llama, DeepSeek, Qwen, Nemotron,
#          Mistral, Gemma, ...) — like OpenRouter, one key reaches many models.
#          DEFAULT MODEL: NVIDIA Nemotron 3 Nano 30B (nvidia/nemotron-3-nano-30b-a3b)
#          — benchmark-verified best under-50B tactical model for strict-JSON
#          payload/validation workloads (4/4 in live tests, 1–5s latency).
#          Controls reasoning via OpenAI-style `reasoning_effort`.
#          A SECOND client (nvidia_strategic_client) reads NVIDIA_API_KEY_2 /
#          NVIDIA_MODEL_2 and serves strategic work (planning, arbitration,
#          reporting) — default llama-3.3-nemotron-super-49b-v1.
#          Configured to act as the PRIMARY tactical LLM provider, with Gemini
#          as the sole fallback (OpenRouter retired from the runtime chain).
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
import json
import logging
import os
import random
import time as _time
from typing import Any

import aiohttp

# Shared system prompts + retry helper were previously imported from
# backend.ai.openrouter. OpenRouter is retired from the runtime chain
# (NVIDIA-only policy) — the definitions now live here so openrouter.py is
# never imported at runtime. The file remains on disk for reference.
def _parse_retry_after(headers) -> float | None:
    """Honour the server's Retry-After header (seconds only), capped."""
    raw = headers.get("Retry-After")
    if not raw:
        return None

# ─── Master System Prompts ────────────────────────────────────────────────────

ARBITRATION_SYSTEM_PROMPT = """You are the Central Reasoning Engine of an autonomous distributed penetration testing system (Vigilagent / Vigilagent).

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

logger = logging.getLogger("NVIDIA")

# ─── Configuration ────────────────────────────────────────────────────────────
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_TIMEOUT = 120  # seconds
MAX_RETRIES = 4
_BASE_BACKOFF = 1.0
_MAX_BACKOFF = 12.0
_MAX_COOLDOWN = 60.0
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB limit to prevent OOM


class NVIDIAClient:
    """
    Production-grade async client for the NVIDIA API (build.nvidia.com).

    OpenAI-compatible chat-completions endpoint hosting the full NVIDIA model
    catalog. Acts as the PRIMARY tactical LLM provider (replacing Gemini);
    Gemini remains as the sole fallback in the Cortex chain.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        api_key_env: str = "NVIDIA_API_KEY",
        model_env: str = "NVIDIA_MODEL",
    ):
        # 1. Check direct argument
        # 2. Check current OS environment
        # 3. Load from .env file (Robust fix)
        from dotenv import load_dotenv

        load_dotenv(override=True)

        self._api_key = api_key or os.environ.get(api_key_env, "")
        # Read lazily so .env (loaded by load_dotenv above) is honoured even
        # when the module was imported before the .env values were present.
        self._model = model or os.environ.get(
            model_env, "nvidia/nemotron-3-nano-30b-a3b"
        )
        # Thinking-token budget — Nemotron / DeepSeek-style models only.
        # (Muse Glimmer uses reasoning_effort, not these.) Set to 0 to disable.
        try:
            self._min_thinking = int(os.environ.get("NVIDIA_MIN_THINKING_TOKENS", "1024") or "0")
        except (TypeError, ValueError):
            self._min_thinking = 1024
        try:
            self._max_thinking = int(os.environ.get("NVIDIA_MAX_THINKING_TOKENS", "2048") or "0")
        except (TypeError, ValueError):
            self._max_thinking = 2048
        try:
            self._max_output = int(os.environ.get("NVIDIA_MAX_OUTPUT_TOKENS", "2048") or "2048")
        except (TypeError, ValueError):
            self._max_output = 2048
        # Muse Glimmer + Nemotron 3 family use OpenAI-style reasoning_effort
        # instead of thinking-token bounds (min/max_thinking_tokens 400 on
        # those models).
        _effort = os.environ.get("NVIDIA_REASONING_EFFORT", "medium").strip().lower()
        if _effort not in ("low", "medium", "high", "xhigh"):
            logger.warning("NVIDIA: Invalid NVIDIA_REASONING_EFFORT=%r — using 'medium'", _effort)
            _effort = "medium"
        self._reasoning_effort = _effort

        # Security Guard: Detect if the key is still a placeholder
        if self._api_key in ("your_nvidia_api_key_here", "nvapi-...", "nvapi-"):
            logger.warning("NVIDIA: Key is still the placeholder! Please update .env")
            self._api_key = ""

        self._session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()  # Eagerly initialized lock prevents race
        self._telemetry = {
            "calls": 0,
            "successes": 0,
            "errors": 0,
            "total_latency": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
        }

        if self._api_key:
            logger.info(f"NVIDIA: Client initialized -> model={self._model}")
        else:
            logger.warning("NVIDIA: No valid API key found. Cloud reasoning disabled.")

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    async def _ensure_session(self):
        async with self._session_lock:
            if self._session is None or self._session.closed:
                timeout = aiohttp.ClientTimeout(total=NVIDIA_TIMEOUT)
                self._session = aiohttp.ClientSession(timeout=timeout)

    async def call(
        self,
        user_prompt: str,
        system_prompt: str = ARBITRATION_SYSTEM_PROMPT,
        temperature: float = 0.1,
        max_tokens: int = 1500,
        scan_ctx=None,
        model: str | None = None,
        json_mode: bool = False,
    ) -> str:
        """
        Send a prompt to an NVIDIA-hosted model.
        Returns the raw text response or an error string.

        ``json_mode`` pins ``response_format`` to ``json_object`` (verified
        live on nemotron-3-nano-30b-a3b) so tactical calls that need
        structured output get valid JSON instead of prose that the Cortex
        JSON extractor then has to guess at.
        """
        if not self._api_key:
            return "[NVIDIA OFFLINE] No API key configured. Set NVIDIA_API_KEY."

        self._telemetry["calls"] += 1
        call_start = _time.perf_counter()

        # Cancellation check
        if scan_ctx and getattr(scan_ctx, "is_cancelled", False):
            raise asyncio.CancelledError()

        await self._ensure_session()

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model or self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": min(max_tokens, self._max_output),
            "top_p": 0.95,
            "frequency_penalty": 0,
            "presence_penalty": 0,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        # Reasoning-model tuning. Two styles exist in the NVIDIA catalog
        # (both verified live):
        #   - OpenAI-style `reasoning_effort` (low/medium/high/xhigh):
        #     Muse Glimmer + Nemotron 3 family. min/max_thinking_tokens are
        #     REJECTED with HTTP 400 on these.
        #   - Legacy `min/max_thinking_tokens` bounds: only the old
        #     nemotron-nano-9b/12b-v2 line.
        # Sent ONLY for reasoning models — keeps plain-model switches from 400s.
        _model_l = (model or self._model).lower()
        _effort_style = (
            ("glimmer" in _model_l)
            or ("muse" in _model_l)
            or ("nemotron-3" in _model_l)
        )
        _token_style = ("nemotron-nano-9b" in _model_l) or ("nemotron-nano-12b" in _model_l)
        if _effort_style:
            payload["reasoning_effort"] = self._reasoning_effort
        elif _token_style and (self._min_thinking > 0 or self._max_thinking > 0):
            if self._min_thinking > 0:
                payload["min_thinking_tokens"] = self._min_thinking
            if self._max_thinking > 0:
                payload["max_thinking_tokens"] = self._max_thinking

        for attempt in range(MAX_RETRIES + 1):
            try:
                async with self._session.post(NVIDIA_API_URL, headers=headers, json=payload) as response:
                    if response.status == 200:
                        # Check response size before reading to prevent OOM
                        content_length = response.headers.get("Content-Length")
                        if content_length:
                            try:
                                if int(content_length) > _MAX_RESPONSE_BYTES:
                                    self._telemetry["errors"] += 1
                                    logger.error(
                                        "NVIDIA: Response Content-Length too large: %s bytes", content_length
                                    )
                                    return "[NVIDIA ERROR] Response exceeded size limit."
                            except (ValueError, TypeError):
                                pass
                        raw = await response.read()
                        if len(raw) > _MAX_RESPONSE_BYTES:
                            self._telemetry["errors"] += 1
                            logger.error("NVIDIA: Response too large (%d bytes)", len(raw))
                            return "[NVIDIA ERROR] Response exceeded size limit."
                        data = json.loads(raw.decode("utf-8", errors="replace"))
                        # Reasoning models may return content in either `content`
                        # or `reasoning_content` — prefer content, fall back to
                        # reasoning so a reasoning-only response isn't lost.
                        try:
                            message = (data.get("choices") or [{}])[0].get("message") or {}
                            result = message.get("content") or ""
                            if not result.strip():
                                result = message.get("reasoning_content") or ""
                        except (AttributeError, IndexError, TypeError):
                            result = ""
                        if not result.strip():
                            self._telemetry["errors"] += 1
                            logger.warning("NVIDIA: Empty content in response (attempt %d/%d)", attempt + 1, MAX_RETRIES)
                            if attempt < MAX_RETRIES:
                                await asyncio.sleep(
                                    min(_BASE_BACKOFF * (2**attempt), _MAX_BACKOFF) + random.uniform(0, 0.5)
                                )
                                continue
                            return "[NVIDIA ERROR] Empty content in response."

                        # Track token usage
                        usage = data.get("usage", {})
                        self._telemetry["input_tokens"] += usage.get("prompt_tokens", 0)
                        self._telemetry["output_tokens"] += usage.get("completion_tokens", 0)

                        latency = _time.perf_counter() - call_start
                        self._telemetry["successes"] += 1
                        self._telemetry["total_latency"] += latency

                        logger.info(
                            f"NVIDIA: Call succeeded in {latency:.2f}s (tokens: {usage.get('total_tokens', 'N/A')})"
                        )
                        return result.strip()

                    elif response.status in _RETRYABLE_STATUSES:
                        # 429 (quota) + 5xx (overload) — retry with Retry-After
                        # / jittered exponential backoff.
                        retry_after = _parse_retry_after(response.headers)
                        delay = (
                            retry_after
                            if retry_after is not None
                            else min(_BASE_BACKOFF * (2**attempt), _MAX_BACKOFF) + random.uniform(0, 0.5)
                        )
                        logger.warning(
                            "NVIDIA: HTTP %s (retryable). Attempt %d/%d, retry in %.1fs",
                            response.status,
                            attempt + 1,
                            MAX_RETRIES,
                            delay,
                        )
                        await asyncio.sleep(delay)
                        continue

                    else:
                        error_text = await response.text()
                        logger.error(f"NVIDIA: HTTP {response.status} — {error_text[:200]}")
                        self._telemetry["errors"] += 1
                        return f"[NVIDIA ERROR] HTTP {response.status}: {error_text[:100]}"

            except asyncio.CancelledError:
                raise
            except aiohttp.ClientConnectorError:
                self._telemetry["errors"] += 1
                logger.error("NVIDIA: Cannot connect to NVIDIA API")
                return "[NVIDIA OFFLINE] Cannot connect to NVIDIA API."
            except Exception as e:
                self._telemetry["errors"] += 1
                logger.error(f"NVIDIA: Unexpected error — {type(e).__name__}: {e}")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(min(_BASE_BACKOFF * (2**attempt), _MAX_BACKOFF) + random.uniform(0, 0.5))
                    continue
                return f"[NVIDIA ERROR] {type(e).__name__}: {str(e)[:100]}"

        return "[NVIDIA ERROR] Max retries exceeded."

    # ─── Specialized Call Methods ─────────────────────────────────────────────

    async def generate_narrative(self, prompt: str, scan_ctx=None) -> str:
        """Generate narrative text for reports and summaries."""
        return await self.call(prompt, temperature=0.3, max_tokens=500, scan_ctx=scan_ctx)

    async def arbitrate(self, candidate_data: dict[str, Any], scan_ctx=None) -> str:
        """Final arbitration on a vulnerability candidate."""
        prompt = json.dumps(candidate_data, indent=2, default=str)
        return await self.call(
            prompt, system_prompt=ARBITRATION_SYSTEM_PROMPT, temperature=0.1, max_tokens=500, scan_ctx=scan_ctx
        )

    async def plan_exploit(self, finding: dict[str, Any], scan_ctx=None) -> str:
        """Generate exploit verification plan."""
        prompt = json.dumps(finding, indent=2, default=str)
        return await self.call(
            prompt, system_prompt=EXPLOIT_PLANNING_SYSTEM_PROMPT, temperature=0.1, max_tokens=800, scan_ctx=scan_ctx
        )

    async def generate_remediation(self, finding: dict[str, Any], framework: str = "Generic", scan_ctx=None) -> str:
        """Generate framework-specific remediation with code patches."""
        finding_with_fw = {**finding, "framework": framework}
        prompt = json.dumps(finding_with_fw, indent=2, default=str)
        return await self.call(
            prompt, system_prompt=REMEDIATION_SYSTEM_PROMPT, temperature=0.1, max_tokens=1500, scan_ctx=scan_ctx
        )

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

    async def reconstruct_forensics(
        self, vuln_type: str, payload: str, response_snippet: str, url: str, scan_ctx=None
    ) -> str:
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
            logger.info("NVIDIA: Session closed.")


# ─── Global Singleton ─────────────────────────────────────────────────────────
nvidia_client = NVIDIAClient()

# Second NVIDIA instance — STRATEGIC engine (key 2 / model 2). Reads
# NVIDIA_API_KEY_2 + NVIDIA_MODEL_2 so one account's tactical key and a
# separate strategic key can run concurrently. Defaults to the 49B strategic
# model (llama-3.3-nemotron-super-49b-v1) when NVIDIA_MODEL_2 is unset.
_nvidia_key_2 = os.environ.get("NVIDIA_API_KEY_2", "") or os.environ.get("NVIDIA_API_KEY", "")
nvidia_strategic_client = NVIDIAClient(
    api_key=_nvidia_key_2,
    model=os.environ.get("NVIDIA_MODEL_2", "nvidia/llama-3.3-nemotron-super-49b-v1"),
    api_key_env="NVIDIA_API_KEY_2",
    model_env="NVIDIA_MODEL_2",
)
