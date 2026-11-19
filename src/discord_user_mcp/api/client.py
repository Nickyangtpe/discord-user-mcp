"""HTTP client for the Discord user API.

Design rules baked in here:

* The ``Authorization`` header always carries the **raw user token**. Bot
  tokens (``Bot <token>``) are never used.
* 401 is never retried - the token is wrong and retrying only risks a lockout.
* 429 is retried after the server supplied ``retry_after`` and the bucket is
  recorded so later calls wait.
* Non-idempotent requests (POST/PATCH) are never retried on a *network* error,
  because the request may already have been applied. They are retried on 429,
  where Discord guarantees the request was not processed.
* Nothing logs the Authorization header.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
from typing import Any, Awaitable, Callable, Mapping, Sequence
from urllib.parse import quote

import httpx

from ..config import Settings
from .errors import NetworkError, from_http_response
from .ratelimit import RateLimiter

logger = logging.getLogger(__name__)

_SNOWFLAKE_SEGMENT = re.compile(r"^\d{5,20}$")
_RETRYABLE_STATUS = {500, 502, 503, 504}
_FILE_FIELD = re.compile(r"^files\[\d+\]$")


def normalize_path(path: str) -> str:
    """Collapse ids and encoded emoji so routes share one rate limit bucket."""
    segments = []
    for segment in path.split("/"):
        if _SNOWFLAKE_SEGMENT.match(segment):
            segments.append(":id")
        elif "%" in segment:
            segments.append(":encoded")
        else:
            segments.append(segment)
    normalized = "/".join(segments)
    return normalized if normalized.startswith("/") else f"/{normalized}"


def route_key(method: str, path: str) -> str:
    return f"{method.upper()} {normalize_path(path)}"


def _clean_params(params: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not params:
        return None
    cleaned = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            cleaned[key] = "true" if value else "false"
        else:
            cleaned[key] = value
    return cleaned or None


class DiscordClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self._sleep = sleep or asyncio.sleep
        self._clock = clock
        self.limiter = RateLimiter(sleep=self._sleep, clock=clock)
        self._token = settings.require_token()
        self._http = httpx.AsyncClient(
            base_url=settings.http.base_url.rstrip("/"),
            headers=self._default_headers(),
            timeout=httpx.Timeout(
                settings.http.timeout_seconds,
                connect=settings.http.connect_timeout_seconds,
            ),
            transport=transport,
            follow_redirects=False,
        )

    # -- public surface ----------------------------------------------------

    @property
    def base_url(self) -> str:
        return self.settings.http.base_url.rstrip("/")

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "DiscordClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        payload: Any = None,
        files: Sequence[tuple[str, tuple[str, bytes, str]]] | None = None,
        audit_reason: str | None = None,
        idempotent: bool | None = None,
        accept_status: Sequence[int] = (),
    ) -> Any:
        method = method.upper()
        key = route_key(method, path)
        headers: dict[str, str] = {}
        if audit_reason:
            headers["X-Audit-Log-Reason"] = quote(audit_reason[:512], safe="")
        if idempotent is None:
            idempotent = method in {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}

        query = _clean_params(params)
        attempts_429 = 0
        attempts_retry = 0
        started_at = self._clock()

        while True:
            await self.limiter.acquire(key)
            request_started = time.perf_counter()
            try:
                if files:
                    data = {"payload_json": json.dumps(payload or {}, ensure_ascii=False)}
                    response = await self._http.request(
                        method, path, params=query, data=data, files=list(files), headers=headers
                    )
                else:
                    response = await self._http.request(
                        method,
                        path,
                        params=query,
                        json=payload if payload is not None else None,
                        headers=headers,
                    )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if idempotent and attempts_retry < self.settings.http.max_retries:
                    delay = self._backoff(attempts_retry)
                    attempts_retry += 1
                    logger.warning(
                        "network error on %s %s (%s); retrying in %.1fs",
                        method,
                        normalize_path(path),
                        type(exc).__name__,
                        delay,
                    )
                    await self._sleep(delay)
                    continue
                hint = (
                    ""
                    if idempotent
                    else " The request may already have been applied by Discord; check the target before retrying."
                )
                raise NetworkError(
                    f"Network error talking to Discord ({type(exc).__name__}).{hint}"
                ) from exc
            elapsed_ms = (time.perf_counter() - request_started) * 1000
            self.limiter.observe(key, response.headers)
            logger.debug(
                "%s %s -> %s in %.0fms (%s)",
                method,
                normalize_path(path),
                response.status_code,
                elapsed_ms,
                response.headers.get("x-ratelimit-remaining", "?"),
            )

            if response.status_code == 429:
                retry_after = self._retry_after(response)
                bucket = response.headers.get("x-ratelimit-bucket")
                if (response.headers.get("x-ratelimit-global") or "").lower() == "true":
                    self.limiter.block_global(retry_after)
                else:
                    self.limiter.block(key, retry_after, bucket=bucket)
                if attempts_429 < self.settings.http.max_rate_limit_retries:
                    attempts_429 += 1
                    logger.warning(
                        "rate limited on %s %s; waiting %.2fs (%d/%d)",
                        method,
                        normalize_path(path),
                        retry_after,
                        attempts_429,
                        self.settings.http.max_rate_limit_retries,
                    )
                    await self._sleep(retry_after + 0.05)
                    continue
                raise from_http_response(
                    response.status_code,
                    self._safe_json(response),
                    response.headers,
                    method=method,
                    path=path,
                )

            if response.status_code in _RETRYABLE_STATUS and attempts_retry < self.settings.http.max_retries:
                delay = self._backoff(attempts_retry)
                attempts_retry += 1
                logger.warning(
                    "Discord %s on %s %s; retrying in %.1fs",
                    response.status_code,
                    method,
                    normalize_path(path),
                    delay,
                )
                await self._sleep(delay)
                continue

            if response.status_code in accept_status:
                return {"status_code": response.status_code, "body": self._safe_json(response)}

            if 200 <= response.status_code < 300:
                return self._parse_success(response)

            if response.status_code == 401:
                logger.error(
                    "Discord rejected the token (401) after %.2fs; not retrying",
                    self._clock() - started_at,
                )
            raise from_http_response(
                response.status_code,
                self._safe_json(response),
                response.headers,
                method=method,
                path=path,
            )

    # -- helpers -----------------------------------------------------------

    def _default_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": self._token,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            "X-Discord-Locale": "en-US",
        }
        if self.settings.http.api_version >= 9:
            headers["X-Discord-Timezone"] = "Etc/UTC"
        return headers

    def _backoff(self, attempt: int) -> float:
        base = min(8.0, 0.5 * (2**attempt))
        return base + random.uniform(0.0, 0.25)

    def _retry_after(self, response: httpx.Response) -> float:
        payload = self._safe_json(response)
        if isinstance(payload, Mapping):
            try:
                return max(0.0, float(payload.get("retry_after")))
            except (TypeError, ValueError):
                pass
        header = response.headers.get("retry-after")
        if header:
            try:
                return max(0.0, float(header))
            except ValueError:
                pass
        reset = response.headers.get("x-ratelimit-reset")
        if reset:
            try:
                return max(0.0, float(reset) - self._clock())
            except ValueError:
                pass
        return 1.0

    @staticmethod
    def _safe_json(response: httpx.Response) -> Any:
        if not response.content:
            return None
        content_type = (response.headers.get("content-type") or "").lower()
        if "json" in content_type:
            try:
                return response.json()
            except ValueError:
                return None
        text = response.text
        return text[:500] if text else None

    def _parse_success(self, response: httpx.Response) -> Any:
        if response.status_code == 204 or not response.content:
            return {}
        content_type = (response.headers.get("content-type") or "").lower()
        if "json" in content_type:
            try:
                return response.json()
            except ValueError:
                return {"raw": response.text[:2000]}
        return response.text

    def token_fingerprint(self) -> str:
        """A short, non-reversible fingerprint for diagnostics.

        Only a truncated SHA-256 is exposed; never the token or a prefix of it.
        """
        return f"sha256:{_sha256_short(self._token)}"


def _sha256_short(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
