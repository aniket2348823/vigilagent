import asyncio
import logging
import random

import aiohttp

# Hybrid AI Engine
from backend.ai.cortex import get_cortex_engine

logger = logging.getLogger("Mimic")
cortex = get_cortex_engine()


class MimicSession:
    """
    NEUROMANCER PROTOCOL: MIMIC
    A wrapper around aiohttp that enforces Markov Chain behavior for WAF evasion.

    States:
    0: BURST (Rapid fire, low delay)
    1: PAUSE (Thinking time, high delay)
    """

    # Transition Matrix:
    # [From BURST -> BURST, From BURST -> PAUSE]
    # [From PAUSE -> BURST, From PAUSE -> PAUSE]
    TRANSITION_MATRIX = [
        [0.85, 0.15],  # If Bursting, 85% chance to keep bursting
        [0.90, 0.10],  # If Paused, 90% chance to start bursting again
    ]

    # Header Profiles (Coherent User-Agent + Sec-CH-UA)
    PROFILES = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
            "sec-ch-ua-platform": '"Windows"',
        },
        {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "sec-ch-ua": '"Safari";v="17", "Not:A-Brand";v="8"',  # Safari doesn't always send this, but good to have
            "sec-ch-ua-platform": '"macOS"',
        },
    ]

    def __init__(self, target_url: str = ""):
        self.state = 0  # Start in BURST
        self.current_profile = random.choice(self.PROFILES)
        self.request_count = 0
        self.rotate_threshold = random.randint(50, 200)  # Rotate headers every N requests

    def _next_state(self):
        """Calculates next state based on Transition Matrix."""
        probs = self.TRANSITION_MATRIX[self.state]
        # Weighted random choice
        r = random.random()
        if r < probs[0]:
            self.state = 0  # BURST
        else:
            self.state = 1  # PAUSE

    async def _compliance_sleep(self):
        """Sleeps based on current state."""
        self._next_state()

        if self.state == 0:  # BURST
            # Human burst speed: 100ms - 500ms
            delay = random.uniform(0.1, 0.5)
        else:  # PAUSE
            # Human thinking speed: 2s - 5s
            delay = random.uniform(2.0, 5.0)
            logger.info(f"Mimic: Pausing for {delay:.2f}s (Human behavior simulation)")

        await asyncio.sleep(delay)

    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        """
        Executes a request with Mimic logic.
        """
        # 1. Update Profile if threshold reached
        self.request_count += 1
        if self.request_count > self.rotate_threshold:
            self.current_profile = random.choice(self.PROFILES)
            self.request_count = 0
            self.rotate_threshold = random.randint(50, 200)
            logger.info("Mimic: Rotating Digital Fingerprint")

        # 2. Inject Headers
        headers = kwargs.get("headers", {})
        # Merge profile headers (don't overwrite if caller explicitly set them, maybe)
        # Ideally we overwrite to ensure safety
        for k, v in self.current_profile.items():
            if k not in headers:
                headers[k] = v
        kwargs["headers"] = headers

        # 3. Apply Markov Delay
        await self._compliance_sleep()

        # 4. Execute
        # Note: We create a fresh session for simplicity or pass one in.
        # For 'Mimic' to be truly effective, it should probably manage the session.
        # But 'aiohttp' recommends one session per app.
        # For this architecture, we will instantiate a session here to apply the specific profile logic,
        # OR the caller should pass the session.
        # Let's assume the caller uses this Wrapper to *get* a context manager.
        return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))

    # Helper context manager pattern for drop-in replacement
    # Usage: async with MimicSession().get(url) as resp:
    def get(self, url: str, **kwargs):
        return _MimicContext(self, "GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return _MimicContext(self, "POST", url, **kwargs)


class _MimicContext:
    def __init__(self, mimic_instance, method, url, **kwargs):
        self.mimic = mimic_instance
        self.method = method
        self.url = url
        self.kwargs = kwargs
        self.session = None
        self.response = None

    async def __aenter__(self):
        # Apply delay
        await self.mimic._compliance_sleep()

        # Inject headers
        headers = self.kwargs.get("headers", {}).copy()
        for k, v in self.mimic.current_profile.items():
            headers[k] = v
        self.kwargs["headers"] = headers

        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        self.response = await self.session.request(self.method, self.url, **self.kwargs)
        return self.response

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.response:
            self.response.release()
        if self.session:
            await self.session.close()
