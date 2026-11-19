"""Shared fixtures.

Tests never touch a real Discord token or the network: the HTTP client is given
an ``httpx.MockTransport`` and the approval console binds to loopback only.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest
from pydantic import SecretStr

from discord_user_mcp.api.client import DiscordClient
from discord_user_mcp.config import Settings
from discord_user_mcp.runtime import AppContext, execute_approved, set_context
from discord_user_mcp.security.approval import ApprovalManager, ApprovalStore
from discord_user_mcp.security.audit import AuditLogger

TEST_TOKEN = "A" * 24 + "." + "B" * 6 + "." + "C" * 27


def make_settings(state_dir: Path, **overrides: Any) -> Settings:
    payload: dict[str, Any] = {
        "token": SecretStr(TEST_TOKEN),
        "token_source": "test",
        "state_dir": state_dir,
        "require_startup_auth_check": False,
        "log_level": "WARNING",
    }
    payload.update(overrides)
    settings = Settings(**payload)
    settings.ensure_dirs()
    return settings


def make_client(settings: Settings, handler: Callable[[httpx.Request], httpx.Response]) -> DiscordClient:
    return DiscordClient(settings, transport=httpx.MockTransport(handler), sleep=_no_sleep)


async def _no_sleep(_seconds: float) -> None:
    return None


def json_response(payload: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", **headers},
    )


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture
def settings(state_dir: Path) -> Settings:
    return make_settings(state_dir)


class Harness:
    """A fully wired app context for tool-level tests."""

    def __init__(self, settings: Settings, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.settings = settings
        self.requests: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return handler(request)

        self.client = make_client(settings, recording)
        self.audit = AuditLogger(settings.state_dir / "audit.jsonl")
        self.store = ApprovalStore(settings.state_dir / "approvals.sqlite3")
        self.executions: list[tuple[str, dict[str, Any]]] = []

        async def executor(tool: str, args: dict[str, Any]) -> Any:
            self.executions.append((tool, args))
            return {"executed": tool}

        self.approvals = ApprovalManager(
            settings, self.store, self.audit, executor=executor
        )
        self.context = AppContext(
            settings=settings,
            client=self.client,
            audit=self.audit,
            approvals=self.approvals,
            console=None,
        )
        self.approvals.bind_loop(asyncio.get_running_loop())
        set_context(self.context)

    async def close(self) -> None:
        await self.client.close()

    async def __aenter__(self) -> "Harness":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()


def default_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/users/@me"):
        return json_response({"id": "9" * 18, "username": "tester", "bot": False})
    return json_response({"ok": True, "path": request.url.path})


@pytest.fixture
async def harness(settings: Settings):
    wired = Harness(settings, default_handler)
    try:
        yield wired
    finally:
        await wired.close()
