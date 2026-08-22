"""Live test: Nemotron <50B candidates on NVIDIA API vs Muse Glimmer."""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.getcwd())

SYSTEM_JSON = (
    "You are a security analysis engine. Respond ONLY in valid JSON matching the "
    "exact schema given. No markdown fences. No explanations outside the JSON."
)
USER_JSON = (
    'Schema: {"name": "title", "severity": "Low|Medium|High|Critical", '
    '"impact": ["a"], "remediation": ["fix"], "code_fix": "def x(): ..."}\n'
    "Finding: SQL injection in /vulnerabilities/sqli/?id=1"
)

CANDIDATES = [
    "nvidia/nemotron-3-nano-30b-a3b",  # 30B, 3B active (fast)
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning",  # 30B reasoning, 3B active
    "meta/muse-glimmer-30b",  # baseline (current primary)
]


def parse_json(s):
    s2 = s.strip()
    lines = s2.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    s2 = "\n".join(lines).strip()
    try:
        return json.loads(s2)
    except Exception:
        return None


async def main():
    from backend.ai.nvidia import NVIDIAClient

    c = NVIDIAClient()
    if not c._api_key:
        print("NO NVIDIA KEY")
        return

    for mid in CANDIDATES:
        t0 = time.perf_counter()
        r = await c.call(
            USER_JSON,
            system_prompt=SYSTEM_JSON,
            temperature=0.0,
            max_tokens=300,
            model=mid,
        )
        dt = time.perf_counter() - t0
        obj = parse_json(r) if r else None
        ok = isinstance(obj, dict) and "name" in obj
        print(f"{mid}")
        print(f"   {dt:6.2f}s  json={'VALID' if ok else 'FAIL'}  raw={r[:90]!r}")

    await c.shutdown()


asyncio.run(main())
