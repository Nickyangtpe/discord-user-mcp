"""Rate limit accounting.

Discord answers with ``X-RateLimit-*`` headers and, on 429, a ``retry_after``
value. We keep a route bucket map so a tool call waits instead of hammering
the API, and we honour both per-bucket and global limits.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Mapping

# Discord resets are unix timestamps. Anything further away than this is clock
# skew or a malformed header, and sleeping for it would hang the server.
_MAX_TRUSTED_DELAY = 900.0


@dataclass
class BucketState:
    remaining: int = 1
    reset_at: float = 0.0
    bucket: str | None = None
    scope: str | None = None
    limit: int | None = None


class RateLimiter:
    def __init__(
        self,
        *,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._sleep = sleep or asyncio.sleep
        self._clock = clock
        self._lock = asyncio.Lock()
        self._buckets: dict[str, BucketState] = {}
        self._hash_of_route: dict[str, str] = {}
        self._hash_blocked_until: dict[str, float] = {}
        self._global_until: float = 0.0

    async def acquire(self, route_key: str) -> None:
        """Wait until this route may be called again."""
        while True:
            async with self._lock:
                now = self._clock()
                delay = 0.0
                if self._global_until > now:
                    delay = self._global_until - now
                else:
                    state = self._buckets.get(route_key)
                    if state and state.remaining <= 0:
                        delay = max(delay, state.reset_at - now)
                    bucket_hash = self._hash_of_route.get(route_key)
                    if bucket_hash:
                        delay = max(delay, self._hash_blocked_until.get(bucket_hash, 0.0) - now)
            if delay <= 0:
                return
            # Sleeping in slices keeps us responsive to a bucket being reset
            # early and avoids absurd sleeps on skewed clocks.
            await self._sleep(min(max(delay, 0.0), 5.0) + 0.01)

    def observe(self, route_key: str, headers: Mapping[str, str]) -> None:
        """Record rate limit headers from a response."""
        now = self._clock()
        try:
            remaining = int(headers.get("x-ratelimit-remaining", ""))
        except (TypeError, ValueError):
            remaining = None
        try:
            reset_at = float(headers.get("x-ratelimit-reset", ""))
        except (TypeError, ValueError):
            reset_at = None
        try:
            limit = int(headers.get("x-ratelimit-limit", ""))
        except (TypeError, ValueError):
            limit = None
        bucket = headers.get("x-ratelimit-bucket")
        scope = headers.get("x-ratelimit-scope")

        if remaining is None and reset_at is None and not bucket:
            return
        if reset_at is not None and reset_at - now > _MAX_TRUSTED_DELAY:
            reset_at = None

        state = self._buckets.setdefault(route_key, BucketState())
        if remaining is not None:
            state.remaining = remaining
        if reset_at is not None:
            state.reset_at = reset_at
        if limit is not None:
            state.limit = limit
        if bucket:
            state.bucket = bucket
            self._hash_of_route[route_key] = bucket
        if scope:
            state.scope = scope

        if remaining is not None and remaining <= 0 and reset_at:
            if bucket:
                self._hash_blocked_until[bucket] = max(
                    self._hash_blocked_until.get(bucket, 0.0), reset_at
                )

    def block(self, route_key: str, seconds: float, *, bucket: str | None = None) -> None:
        deadline = self._clock() + max(0.0, seconds)
        state = self._buckets.setdefault(route_key, BucketState())
        state.remaining = 0
        state.reset_at = max(state.reset_at, deadline)
        if bucket:
            self._hash_blocked_until[bucket] = max(
                self._hash_blocked_until.get(bucket, 0.0), deadline
            )

    def block_global(self, seconds: float) -> None:
        self._global_until = max(self._global_until, self._clock() + max(0.0, seconds))

    def snapshot(self) -> list[dict[str, object]]:
        now = self._clock()
        rows = []
        for route, state in sorted(self._buckets.items()):
            rows.append(
                {
                    "route": route,
                    "remaining": state.remaining,
                    "reset_in": round(max(0.0, state.reset_at - now), 3),
                    "limit": state.limit,
                    "bucket": state.bucket,
                    "scope": state.scope,
                }
            )
        return rows

    @property
    def global_blocked_for(self) -> float:
        return round(max(0.0, self._global_until - self._clock()), 3)
