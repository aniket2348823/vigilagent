import asyncio
import os
import redis.asyncio as aioredis
import json

REDIS_URL = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')

async def cancel_all():
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    scan_keys = await redis.keys("scan:*")
    for key in scan_keys:
        if not key.endswith(":events") and not key.endswith(":results"):
            data = await redis.hgetall(key)
            if data and data.get("status") not in ("Completed", "Failed", "Cancelled"):
                print(f"Cancelling {data.get('id')}")
                await redis.hset(key, "status", "Cancelled")
    await redis.aclose()

if __name__ == "__main__":
    asyncio.run(cancel_all())
