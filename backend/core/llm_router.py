import asyncio
import logging
import os
import random
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger("LLMRouter")


class ModelTier(StrEnum):
    HIGH = "high"
    MID = "mid"
    LOW = "low"


# ─── Agent-to-Tier Mapping ───────────────────────────────────────────────────
# HIGH = Strategic reasoning (NVIDIA Llama 3.3 Nemotron Super 49B — planning,
#        arbitration, reporting; Gemini fallback)
# MID  = Tactical execution (NVIDIA Nemotron 3 Nano 30B primary, Gemini fallback)
# LOW  = Fast/lightweight ops (NVIDIA Nemotron 3 Nano 30B primary, Gemini fallback)
AGENT_TIERS = {
    "orchestrator": ModelTier.HIGH,
    "alpha": ModelTier.LOW,
    "beta": ModelTier.MID,
    "gamma": ModelTier.MID,
    "sigma": ModelTier.MID,
    "omega": ModelTier.HIGH,
    "kappa": ModelTier.LOW,
    "zeta": ModelTier.MID,
    "reporter": ModelTier.HIGH,
    "recon": ModelTier.LOW,
    "exploit": ModelTier.HIGH,
    "analyst": ModelTier.HIGH,
}

# ─── Multi-LLM Tier Models ───────────────────────────────────────────────────
# Provider 1: NVIDIA STRATEGIC (Llama 3.3 Nemotron Super 49B via NVIDIA_API_KEY_2)
#             — deep reasoning, arbitration, reporting, forensics
# Provider 2: NVIDIA TACTICAL (Nemotron 3 Nano 30B) — PRIMARY fast execution,
#             payloads, validation pass 1
# Provider 3: Gemini API — fallback for both NVIDIA keys
# NOTE: OpenRouter retired from the runtime chain (NVIDIA-only policy).
TIER_MODELS = {
    ModelTier.HIGH: ["nvidia/llama-3.3-nemotron-super-49b-v1", "nvidia/nemotron-3-nano-30b-a3b", "gemini/gemini-2.5-flash"],
    ModelTier.MID: ["nvidia/nemotron-3-nano-30b-a3b", "gemini/gemini-2.5-flash"],
    ModelTier.LOW: ["nvidia/nemotron-3-nano-30b-a3b", "gemini/gemini-2.5-flash"],
}

AGENT_TEMPERATURES = {
    "orchestrator": 0.3,
    "alpha": 0.3,
    "beta": 0.2,
    "gamma": 0.2,
    "sigma": 0.2,
    "omega": 0.3,
    "kappa": 0.2,
    "zeta": 0.2,
    "reporter": 0.5,
}


@dataclass
class ModelAssignment:
    primary: str
    fallbacks: list[str] = field(default_factory=list)
    temperature: float = 0.3
    tier: ModelTier = ModelTier.MID


class LLMRouter:
    """Routes LLM requests to the appropriate model tier with retry/backoff.

    FIX: Added exponential backoff retry logic so transient provider errors
    (429, 500, timeouts) are retried across the fallback chain before giving
    up.  Previously a single failure in the primary model would immediately
    cascade with no retry, causing spurious LLM errors under load.
    """

    def __init__(self, profile: str | None = None):
        self.profile = (profile or os.getenv("VIGILAGENT_MODEL_PROFILE", "eco")).lower()
        # Per-model error counters for circuit-breaker awareness
        self._model_errors: dict[str, int] = {}
        self._model_successes: dict[str, int] = {}

    def tier_for(self, agent_name: str) -> ModelTier:
        if self.profile == "max":
            return ModelTier.HIGH
        if self.profile in {"test", "ci"}:
            return ModelTier.LOW
        key = agent_name.lower().replace("agent_", "")
        return AGENT_TIERS.get(key, ModelTier.MID)

    def resolve(self, agent_name: str) -> ModelAssignment:
        env_key = f"VIGILAGENT_{agent_name.upper().replace('AGENT_', '')}_MODEL"
        override = os.getenv(env_key) or os.getenv("VIGILAGENT_MODEL")
        tier = self.tier_for(agent_name)
        chain = [override] if override else list(TIER_MODELS[tier])
        return ModelAssignment(
            primary=chain[0],
            fallbacks=chain[1:],
            temperature=AGENT_TEMPERATURES.get(agent_name.lower().replace("agent_", ""), 0.3),
            tier=tier,
        )

    def get_temperature(self, agent_name: str, override: float | None = None) -> float:
        """Return the temperature for an agent, with optional runtime override.

        FIX: Previously temperature was hardcoded per agent name with no way
        to adjust at runtime. This method allows callers (e.g. CortexEngine)
        to override temperature based on current context.
        """
        if override is not None:
            return max(0.0, min(2.0, override))
        key = agent_name.lower().replace("agent_", "")
        return AGENT_TEMPERATURES.get(key, 0.3)

    def record_model_error(self, model: str) -> None:
        """Record a failure for the given model (used by backoff logic)."""
        self._model_errors[model] = self._model_errors.get(model, 0) + 1

    def record_model_success(self, model: str) -> None:
        """Record a success, resetting error counter for the model."""
        self._model_errors[model] = 0
        self._model_successes[model] = self._model_successes.get(model, 0) + 1

    async def retry_with_backoff(
        self,
        coro_factory,
        model_chain: list[str],
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
    ):
        """Execute an async coroutine with exponential backoff across a model chain.

        ``coro_factory`` is a callable that accepts a model name and returns
        an awaitable.  We try each model in ``model_chain`` up to
        ``max_retries`` times each, with exponential jittered backoff between
        attempts.

        Returns the first successful result, or raises the last exception
        after all retries are exhausted.
        """
        last_error = None
        for model in model_chain:
            for attempt in range(max_retries):
                try:
                    result = await coro_factory(model)
                    self.record_model_success(model)
                    return result
                except Exception as exc:
                    last_error = exc
                    self.record_model_error(model)
                    delay = min(base_delay * (2**attempt), max_delay)
                    # Add jitter to prevent thundering herd
                    delay *= 0.5 + random.random()
                    logger.warning(
                        "LLM call to %s failed (attempt %d/%d): %s — retrying in %.1fs",
                        model,
                        attempt + 1,
                        max_retries,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
        # All models and retries exhausted
        raise last_error


llm_router = LLMRouter()
