# ═══════════════════════════════════════════════════════════════════════════════
# VIGILAGENT :: GEMINI CLIENT — GEMINI 2.5 FLASH INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════
# PURPOSE: Production-grade async client for Google Gemini API.
#          Provides payload generation, validation, narrative synthesis,
#          and vector embeddings for Agent Kappa memory via Gemini 2.5 Flash
#          and text-embedding-004 (cloud inference).
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
import json
import logging
import os
import random
import time as _time
from typing import Any

import aiohttp

logger = logging.getLogger("GEMINI")

# ─── Configuration ────────────────────────────────────────────────────────────
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_EMBEDDING_MODEL = os.environ.get("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")
GEMINI_EMBEDDING_FALLBACK_MODELS = [
    model.strip()
    for model in os.environ.get("GEMINI_EMBEDDING_FALLBACK_MODELS", "text-embedding-004").split(",")
    if model.strip()
]
GEMINI_TIMEOUT = 120  # seconds
MAX_RETRIES = 4

# Rate-limit resilience: 429 (quota/RPM) and 5xx (overload/unavailable) are
# transient and MUST be retried with jittered exponential backoff instead of
# failing the call (a 503 while rate-limited is what froze earlier scans).
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_BASE_BACKOFF = 1.0        # seconds; doubles per attempt
_MAX_BACKOFF = 12.0        # per-attempt cap
_MAX_COOLDOWN = 60.0       # breaker cooldown after persistent rate limiting
_RATE_LIMIT_TRIP_AFTER = 2  # consecutive retryable responses before tripping
_MAX_CONCURRENT = 4        # cap concurrent in-flight Gemini calls
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB limit to prevent OOM


def _parse_retry_after(headers) -> float | None:
    """Honour the server's Retry-After header (seconds only), capped."""
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        value = float(raw)
        return min(max(value, 0.0), _MAX_COOLDOWN)
    except (TypeError, ValueError):
        return None  # HTTP-date format not supported; use exponential backoff


class GeminiClient:
    """
    Production-grade async client for Google Gemini API.
    Powers tactical payload generation, validation, narrative synthesis,
    and vector embeddings for Agent Kappa memory.
    """

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY", "")

        if self._api_key == "your_gemini_api_key_here":
            logger.warning("GEMINI: Key is still the placeholder! Please update .env")
            self._api_key = ""

        self._session: aiohttp.ClientSession | None = None
        self._session_lock = asyncio.Lock()  # FIX: Initialize lock eagerly to prevent race condition

        # Client-level circuit breaker: when a rate limit / 5xx storm is
        # detected we stop hammering the API for a cooldown window so the
        # caller (Cortex) can fall back to GI5-only mode instead of burning
        # retries against a dead key.
        self._consecutive_retryable = 0
        self._breaker_open_until = 0.0
        self._breaker_lock = asyncio.Lock()
        self._concurrency = asyncio.Semaphore(_MAX_CONCURRENT)

        self._telemetry = {
            "calls": 0,
            "successes": 0,
            "errors": 0,
            "total_latency": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "rate_limited": 0,
            "breaker_trips": 0,
        }

        if self._api_key:
            logger.info(f"GEMINI: Client initialized -> model={GEMINI_MODEL}")
        else:
            logger.warning("GEMINI: No valid API key found. Gemini inference disabled.")

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    async def _ensure_session(self):
        async with self._session_lock:
            try:
                is_closed = self._session.closed if self._session else True
            except Exception:
                is_closed = True
            if self._session is None or is_closed:
                timeout = aiohttp.ClientTimeout(total=GEMINI_TIMEOUT)
                self._session = aiohttp.ClientSession(timeout=timeout)

    async def call(
        self,
        prompt: str,
        *,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 1500,
        scan_ctx=None,
    ) -> str:
        """
        Send a prompt to Gemini 2.5 Flash via the Generative Language API.
        Returns the raw text response or an error string.
        """
        if not self._api_key:
            return "[GEMINI OFFLINE] No API key configured."

        self._telemetry["calls"] += 1
        call_start = _time.perf_counter()

        if scan_ctx and getattr(scan_ctx, "is_cancelled", False):
            raise asyncio.CancelledError()

        await self._ensure_session()

        url = f"{GEMINI_API_URL}/models/{GEMINI_MODEL}:generateContent"

        body: dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": min(max_tokens, 8192),
                "topP": 0.9,
            },
        }

        if system_prompt:
            body["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        request_headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self._api_key,
        }

        # Circuit breaker: if we recently tripped due to a rate-limit storm,
        # fail fast so the caller can fall back to GI5-only mode immediately.
        async with self._breaker_lock:
            breaker_open = _time.time() < self._breaker_open_until
        if breaker_open:
            self._telemetry["rate_limited"] += 1
            return "[GEMINI RATE_LIMITED] Circuit breaker open (rate-limit cooldown). Use fallback provider."

        async with self._concurrency:  # cap in-flight calls to protect quota
            for attempt in range(MAX_RETRIES + 1):
                try:
                    if scan_ctx and getattr(scan_ctx, "is_cancelled", False):
                        raise asyncio.CancelledError()

                    async with self._session.post(
                        url,
                        json=body,
                        headers=request_headers,
                    ) as response:
                        if response.status == 200:
                            # Check Content-Length before reading body to prevent OOM
                            content_length = response.headers.get("Content-Length")
                            if content_length:
                                try:
                                    if int(content_length) > _MAX_RESPONSE_BYTES:
                                        self._telemetry["errors"] += 1
                                        logger.error("GEMINI: Response Content-Length too large: %s bytes", content_length)
                                        return "[GEMINI ERROR] Response exceeded size limit."
                                except (ValueError, TypeError):
                                    pass  # Malformed header; fall through to body size check
                            raw = await response.read()
                            if len(raw) > _MAX_RESPONSE_BYTES:
                                self._telemetry["errors"] += 1
                                logger.error("GEMINI: Response too large (%d bytes)", len(raw))
                                return "[GEMINI ERROR] Response exceeded size limit."
                            data = json.loads(raw.decode("utf-8", errors="replace"))

                            candidates = data.get("candidates", [])
                            if not candidates:
                                self._telemetry["errors"] += 1
                                logger.error("GEMINI: Empty candidates in response")
                                return "[GEMINI ERROR] No candidates returned."

                            result = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")

                            usage = data.get("usageMetadata", {})
                            self._telemetry["input_tokens"] += usage.get("promptTokenCount", 0)
                            self._telemetry["output_tokens"] += usage.get("candidatesTokenCount", 0)

                            latency = _time.perf_counter() - call_start
                            self._telemetry["successes"] += 1
                            self._telemetry["total_latency"] += latency

                            # Healthy call — reset retryable-failure counter.
                            async with self._breaker_lock:
                                self._consecutive_retryable = 0

                            total_tokens = usage.get("totalTokenCount", "N/A")
                            logger.info(f"GEMINI: Call succeeded in {latency:.2f}s (tokens: {total_tokens})")
                            return result.strip()

                        elif response.status in _RETRYABLE_STATUSES:
                            # 429 (quota/RPM) + 5xx (overload/unavailable) are
                            # transient — retry with Retry-After / jittered
                            # exponential backoff instead of giving up.
                            self._telemetry["rate_limited"] += 1
                            retry_after = _parse_retry_after(response.headers)
                            delay = (
                                retry_after
                                if retry_after is not None
                                else min(_BASE_BACKOFF * (2**attempt), _MAX_BACKOFF) + random.uniform(0, 0.5)
                            )
                            async with self._breaker_lock:
                                self._consecutive_retryable += 1
                                consecutive = self._consecutive_retryable
                                if consecutive >= _RATE_LIMIT_TRIP_AFTER:
                                    self._breaker_open_until = _time.time() + _MAX_COOLDOWN
                                    self._consecutive_retryable = 0
                                    self._telemetry["breaker_trips"] += 1
                            if consecutive >= _RATE_LIMIT_TRIP_AFTER:
                                logger.warning(
                                    "GEMINI: Persistent rate limiting (HTTP %s) — tripping breaker for %ss",
                                    response.status,
                                    _MAX_COOLDOWN,
                                )
                                return (
                                    "[GEMINI RATE_LIMITED] Persistent quota/overload (HTTP "
                                    f"{response.status}). Use fallback provider."
                                )
                            logger.warning(
                                "GEMINI: HTTP %s (retryable). Attempt %d/%d, retry in %.1fs",
                                response.status,
                                attempt + 1,
                                MAX_RETRIES,
                                delay,
                            )
                            await asyncio.sleep(delay)
                            continue

                        else:
                            error_text = await response.text()
                            logger.error(f"GEMINI: HTTP {response.status} — {error_text[:200]}")
                            self._telemetry["errors"] += 1
                            return f"[GEMINI ERROR] HTTP {response.status}: {error_text[:100]}"

                except asyncio.CancelledError:
                    raise
                except aiohttp.ClientConnectorError:
                    self._telemetry["errors"] += 1
                    logger.error("GEMINI: Cannot connect to Gemini API")
                    return "[GEMINI OFFLINE] Cannot connect to Gemini API."
                except TimeoutError:
                    self._telemetry["errors"] += 1
                    logger.error(f"GEMINI: Request timed out after {GEMINI_TIMEOUT}s")
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(min(_BASE_BACKOFF * (2**attempt), _MAX_BACKOFF) + random.uniform(0, 0.5))
                        continue
                    return f"[GEMINI TIMEOUT] Request exceeded {GEMINI_TIMEOUT}s."
                except Exception as e:
                    self._telemetry["errors"] += 1
                    logger.error(f"GEMINI: Unexpected error — {type(e).__name__}: {e}")
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(min(_BASE_BACKOFF * (2**attempt), _MAX_BACKOFF) + random.uniform(0, 0.5))
                        continue
                    return f"[GEMINI ERROR] {type(e).__name__}: {str(e)[:100]}"

        return "[GEMINI ERROR] Max retries exceeded."

    # ─── Specialized Call Methods ─────────────────────────────────────────────

    async def generate_payloads(self, prompt: str, *, max_tokens: int = 1024, scan_ctx=None) -> str:
        """Generate attack payloads via Gemini 2.5 Flash."""
        return await self.call(prompt, temperature=0.2, max_tokens=max_tokens, scan_ctx=scan_ctx)

    async def validate_candidate(self, prompt: str, *, max_tokens: int = 4096, scan_ctx=None) -> str:
        """Validate a vulnerability candidate. Uses temperature=0.1 (not 0.0) so the
        self-consistency check in cortex.py actually tests for agreement rather than
        producing deterministic identical output."""
        return await self.call(prompt, temperature=0.1, max_tokens=max_tokens, scan_ctx=scan_ctx)

    async def generate_narrative(self, prompt: str, scan_ctx=None) -> str:
        """Generate narrative text for reports and summaries."""
        return await self.call(prompt, temperature=0.3, max_tokens=500, scan_ctx=scan_ctx)

    async def generate_embedding(self, text: str, scan_ctx=None) -> list[float]:
        """
        Generate a vector embedding via Gemini embeddings.
        Returns the embedding values or an empty list on failure.
        """
        if not self._api_key:
            return []

        if scan_ctx and getattr(scan_ctx, "is_cancelled", False):
            raise asyncio.CancelledError()

        # Respect the rate-limit breaker: embeddings are best-effort and must
        # never block a scan or hammer a rate-limited key.
        async with self._breaker_lock:
            breaker_open = _time.time() < self._breaker_open_until
        if breaker_open:
            return []

        await self._ensure_session()

        models = [GEMINI_EMBEDDING_MODEL, *GEMINI_EMBEDDING_FALLBACK_MODELS]
        seen_models = set()

        for model in models:
            if model in seen_models:
                continue
            seen_models.add(model)

            # FIX: Use header for API key instead of URL query parameter
            url = f"{GEMINI_API_URL}/models/{model}:embedContent"
            body = {
                "content": {"parts": [{"text": text[:8000]}]},
                "taskType": "RETRIEVAL_DOCUMENT",
                "outputDimensionality": 768,
            }

            try:
                async with self._session.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json", "x-goog-api-key": self._api_key},
                ) as response:
                    if response.status == 200:
                        raw = await response.read()
                        if len(raw) > _MAX_RESPONSE_BYTES:
                            logger.error("GEMINI: Embedding response too large (%d bytes)", len(raw))
                            return []
                        data = json.loads(raw.decode("utf-8", errors="replace"))
                        values = data.get("embedding", {}).get("values", [])
                        logger.info(f"GEMINI: Embedding generated by {model} (dim={len(values)})")
                        return values

                    error_text = await response.text()
                    if response.status == 404 and model != models[-1]:
                        logger.warning("GEMINI: Embedding model %s returned 404; trying fallback", model)
                        continue
                    logger.error(f"GEMINI: Embedding HTTP {response.status} - {error_text[:200]}")
                    return []

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"GEMINI: Embedding error with {model} - {type(e).__name__}: {e}")
                return []

        return []

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
            logger.info("GEMINI: Session closed.")


# ─── Global Singleton ─────────────────────────────────────────────────────────
gemini_client = GeminiClient()
