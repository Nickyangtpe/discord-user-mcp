"""The local approval console: loopback only, token gated, cannot be driven by MCP."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from discord_user_mcp.security.approval import ApprovalManager, ApprovalStore, ToolRequest
from discord_user_mcp.security.audit import AuditLogger
from discord_user_mcp.security.console import ApprovalConsole
from discord_user_mcp.security.permissions import Risk

from conftest import make_settings


class Setup:
    def __init__(self, state_dir: Path) -> None:
        self.settings = make_settings(state_dir)
        self.audit = AuditLogger(state_dir / "audit.jsonl")
        self.store = ApprovalStore(state_dir / "approvals.sqlite3")

        async def executor(tool: str, args):  # pragma: no cover - not asserted here
            return {"executed": tool}

        self.manager = ApprovalManager(self.settings, self.store, self.audit, executor=executor)
        self.console = ApprovalConsole(self.settings, self.manager, token="test-token")
        self.manager.console = self.console


@pytest.fixture
async def console_setup(tmp_path: Path):
    setup = Setup(tmp_path / "state")
    setup.manager.bind_loop(__import__("asyncio").get_running_loop())
    try:
        yield setup
    finally:
        setup.console.stop()


async def test_console_rejects_missing_and_wrong_token(console_setup: Setup) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        assert (await http.get("/api/state")).status_code == 401
        assert (
            await http.get("/api/state", headers={"X-Approval-Token": "nope"})
        ).status_code == 401
        page = await http.get("/?t=nope")
        assert page.status_code == 401
        assert "<!doctype html" not in page.text.lower()


async def test_console_accepts_token_in_header_and_query(console_setup: Setup) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        state = await http.get("/api/state", headers={"X-Approval-Token": "test-token"})
        assert state.status_code == 200
        assert state.json()["pending"] == []
        page = await http.get("/?t=test-token")
        assert page.status_code == 200
        assert "approval console" in page.text.lower()


async def test_token_file_is_written_privately(console_setup: Setup) -> None:
    path = console_setup.settings.state_dir / "approval-console.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["token"] == "test-token"
    assert payload["url"].startswith("http://127.0.0.1:")


async def test_console_approves_a_pending_request(console_setup: Setup) -> None:
    approval = await console_setup.manager.request(
        ToolRequest(
            tool="send_message",
            endpoint_id="messages.create",
            risk=Risk.WRITE,
            summary="Send a message",
            target="channel_id=123",
            args={"channel_id": "123", "content": "hi"},
        )
    )
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        response = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            json={"id": approval.id},
        )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"


async def test_console_denies_a_pending_request(console_setup: Setup) -> None:
    approval = await console_setup.manager.request(
        ToolRequest(
            tool="delete_message",
            endpoint_id="messages.delete",
            risk=Risk.DESTRUCTIVE,
            summary="Delete a message",
            target="channel_id=123",
            args={"channel_id": "123", "message_id": "456"},
        )
    )
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        response = await http.post(
            "/api/deny",
            headers={"X-Approval-Token": "test-token"},
            json={"id": approval.id, "reason": "no"},
        )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "denied"


async def test_console_blocks_sensitive_without_typed_confirmation(
    console_setup: Setup,
) -> None:
    approval = await console_setup.manager.request(
        ToolRequest(
            tool="update_my_profile",
            endpoint_id="users.update_profile",
            risk=Risk.SENSITIVE,
            summary="Change the profile",
            target="",
            args={"bio": "hi"},
        )
    )
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        response = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            json={"id": approval.id, "confirmation": "yes"},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "approval_confirmation_required"
        ok = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            json={"id": approval.id, "confirmation": "APPROVE"},
        )
    assert ok.status_code == 200, ok.text


async def test_console_rejects_replayed_approval(console_setup: Setup) -> None:
    approval = await console_setup.manager.request(
        ToolRequest(
            tool="send_message",
            endpoint_id="messages.create",
            risk=Risk.WRITE,
            summary="Send",
            target="",
            args={"channel_id": "123", "content": "hi"},
        )
    )
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        first = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            json={"id": approval.id},
        )
        second = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            json={"id": approval.id},
        )
    assert first.status_code == 200
    assert second.status_code == 409


async def test_console_rejects_bad_body(console_setup: Setup) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        bad = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            content=b"not json",
        )
        assert bad.status_code == 400
        wrong_id = await http.post(
            "/api/approve",
            headers={"X-Approval-Token": "test-token"},
            json={"id": "not-an-approval"},
        )
        assert wrong_id.status_code == 400
