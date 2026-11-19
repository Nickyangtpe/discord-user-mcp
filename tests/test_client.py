"""HTTP client behaviour: auth header, retries, rate limits."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from discord_user_mcp.api.client import DiscordClient, normalize_path, route_key
from discord_user_mcp.api.errors import (
    AuthenticationError,
    ForbiddenError,
    NetworkError,
    RateLimitedError,
)

from conftest import TEST_TOKEN, make_client, make_settings


def _settings(tmp_path: Path):
    return make_settings(tmp_path / "state")


async def test_authorization_header_is_the_raw_user_token(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "1" * 18})

    client = make_client(_settings(tmp_path), handler)
    try:
        await client.request("GET", "/users/@me")
    finally:
        await client.close()
    assert seen[0].headers["authorization"] == TEST_TOKEN
    assert not seen[0].headers["authorization"].startswith("Bot ")


async def test_401_is_never_retried(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"message": "401: Unauthorized", "code": 0})

    client = make_client(_settings(tmp_path), handler)
    try:
        with pytest.raises(AuthenticationError):
            await client.request("GET", "/users/@me")
    finally:
        await client.close()
    assert calls == 1


async def test_429_is_retried_and_honours_retry_after(tmp_path: Path) -> None:
    calls = 0
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                json={"message": "rate limited", "retry_after": 1.5, "global": False},
                headers={"retry-after": "1.5", "x-ratelimit-remaining": "0"},
            )
        return httpx.Response(200, json={"ok": True})

    settings = _settings(tmp_path)
    client = DiscordClient(
        settings, transport=httpx.MockTransport(handler), sleep=fake_sleep
    )
    try:
        result = await client.request("GET", "/users/@me")
    finally:
        await client.close()
    assert result == {"ok": True}
    assert calls == 2
    assert any(delay >= 1.5 for delay in sleeps)


async def test_429_exhausted_raises_rate_limited(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "nope", "retry_after": 0.01})

    settings = _settings(tmp_path)
    settings.http.max_rate_limit_retries = 1
    client = DiscordClient(settings, transport=httpx.MockTransport(handler), sleep=_noop)
    try:
        with pytest.raises(RateLimitedError):
            await client.request("GET", "/users/@me")
    finally:
        await client.close()


async def test_500_is_retried_then_succeeds(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(500, json={"message": "boom"})
        return httpx.Response(200, json={"ok": True})

    client = DiscordClient(
        _settings(tmp_path), transport=httpx.MockTransport(handler), sleep=_noop
    )
    try:
        assert await client.request("GET", "/channels/1/messages") == {"ok": True}
    finally:
        await client.close()
    assert calls == 3


async def test_post_network_error_is_not_retried(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("connection reset", request=request)

    client = DiscordClient(
        _settings(tmp_path), transport=httpx.MockTransport(handler), sleep=_noop
    )
    try:
        with pytest.raises(NetworkError) as info:
            await client.request("POST", "/channels/1/messages", payload={"content": "hi"})
    finally:
        await client.close()
    assert calls == 1
    assert "may already have been applied" in str(info.value)


async def test_get_network_error_is_retried(tmp_path: Path) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("connection reset", request=request)

    settings = _settings(tmp_path)
    settings.http.max_retries = 2
    client = DiscordClient(settings, transport=httpx.MockTransport(handler), sleep=_noop)
    try:
        with pytest.raises(NetworkError):
            await client.request("GET", "/users/@me")
    finally:
        await client.close()
    assert calls == settings.http.max_retries + 1


async def test_html_403_names_the_platform_check(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            text="<html>blocked</html>",
            headers={"content-type": "text/html"},
        )

    client = make_client(_settings(tmp_path), handler)
    try:
        with pytest.raises(ForbiddenError, match="bypass"):
            await client.request("GET", "/users/@me")
    finally:
        await client.close()


async def test_204_returns_empty_object(tmp_path: Path) -> None:
    client = make_client(_settings(tmp_path), lambda request: httpx.Response(204))
    try:
        assert await client.request("DELETE", "/channels/1/messages/2") == {}
    finally:
        await client.close()


async def test_rate_limit_headers_are_recorded(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={},
            headers={
                "x-ratelimit-remaining": "4",
                "x-ratelimit-reset": "9999999999",
                "x-ratelimit-limit": "5",
                "x-ratelimit-bucket": "abc",
            },
        )

    client = make_client(_settings(tmp_path), handler)
    try:
        await client.request("GET", "/channels/1/messages")
        rows = client.limiter.snapshot()
    finally:
        await client.close()
    assert rows and rows[0]["remaining"] == 4 and rows[0]["bucket"] == "abc"


def test_route_key_collapses_ids() -> None:
    assert normalize_path("/channels/123456789012345678/messages") == "/channels/:id/messages"
    assert route_key("get", "/users/123456789012345678") == "GET /users/:id"


async def _noop(_seconds: float) -> None:
    return None
