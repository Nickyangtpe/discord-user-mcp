"""The local approval console: loopback only, token gated, cannot be driven by MCP."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from discord_user_mcp.config import load_dashboard_settings
from discord_user_mcp.security.approval import ApprovalManager, ApprovalStore, ToolRequest
from discord_user_mcp.security.audit import AuditLogger
from discord_user_mcp.security.console import ApprovalConsole, _ConsoleServer
from discord_user_mcp.security.permissions import Risk

from conftest import make_settings

HEADERS = {"X-Approval-Token": "test-token"}


@pytest.mark.parametrize("error", [ConnectionResetError(), BrokenPipeError()])
def test_console_suppresses_expected_disconnects(error: Exception) -> None:
    with patch("discord_user_mcp.security.console.sys.exc_info", return_value=(type(error), error, None)):
        with patch("http.server.ThreadingHTTPServer.handle_error") as report:
            _ConsoleServer.handle_error(Mock(), None, ("127.0.0.1", 12345))
    report.assert_not_called()


def test_console_reports_unexpected_connection_errors() -> None:
    error = RuntimeError("unexpected failure")
    with patch("discord_user_mcp.security.console.sys.exc_info", return_value=(type(error), error, None)):
        with patch("http.server.ThreadingHTTPServer.handle_error") as report:
            # Use a real instance without binding a listening socket.
            server = object.__new__(_ConsoleServer)
            server.handle_error(None, ("127.0.0.1", 12345))
    report.assert_called_once_with(None, ("127.0.0.1", 12345))


class Setup:
    def __init__(self, state_dir: Path, **overrides: object) -> None:
        self.settings = make_settings(state_dir, **overrides)
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


async def test_safe_dashboard_address_opens_a_locked_landing_page(
    console_setup: Setup,
) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        page = await http.get("/?request=ap_example")
        api = await http.get("/api/status")
    assert page.status_code == 200
    assert "Dashboard locked" in page.text
    assert "approval-console.json" in page.text
    assert "requestId" in page.text
    assert "test-token" not in page.text
    assert api.status_code == 401


async def test_console_accepts_token_in_header_and_query(console_setup: Setup) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        state = await http.get("/api/state", headers={"X-Approval-Token": "test-token"})
        assert state.status_code == 200
        assert state.json()["pending"] == []
        page = await http.get("/?t=test-token")
        assert page.status_code == 200
        assert "dashboard" in page.text.lower()


async def test_dashboard_page_is_multilingual_and_hardened(console_setup: Setup) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        page = await http.get("/?t=test-token")
    assert page.status_code == 200
    assert '<option value="zh-TW">繁體中文</option>' in page.text
    assert '<option value="en">English</option>' in page.text
    assert "discord-mcp-language" in page.text
    assert "test-token" not in page.text
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert "access-control-allow-origin" not in page.headers


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


async def test_request_id_cannot_unlock_or_approve(console_setup: Setup) -> None:
    approval = await console_setup.manager.request(
        ToolRequest(
            tool="send_message", endpoint_id="messages.create", risk=Risk.WRITE,
            summary="Send a message", target="channel_id=123",
            args={"channel_id": "123", "content": "hi"},
        )
    )
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        assert (await http.get(f"/?request={approval.id}")).status_code == 200
        assert (await http.get(f"/api/state?request={approval.id}")).status_code == 401
        assert (await http.get(f"/?t={approval.id}")).status_code == 401
        for headers in ({}, {"X-Approval-Token": approval.id}):
            response = await http.post(
                f"/api/approve?request={approval.id}", headers=headers,
                json={"id": approval.id},
            )
            assert response.status_code == 401
            assert response.headers["connection"] == "close"
    assert console_setup.manager.check(approval.id)["status"] == "pending"


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


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------


async def test_dashboard_endpoints_require_the_console_token(
    console_setup: Setup,
) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        for path in ("/api/status", "/api/approvals", "/api/audit", "/api/settings"):
            assert (await http.get(path)).status_code == 401
        assert (
            await http.post("/api/settings", json={"log_level": "DEBUG"})
        ).status_code == 401


async def test_dashboard_status_reports_server_state(console_setup: Setup) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        response = await http.get("/api/status", headers=HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["server"]["version"] == "0.1.0"
    assert body["mode"]["read_only"] is False
    assert body["approvals"]["pending"] == 0
    assert body["registry"]["total"] > 0
    assert body["token"]["bot_tokens_supported"] is False
    assert body["console"]["url_without_token"].startswith("http://127.0.0.1:")
    assert body["console"]["token_required"] is True


async def test_dashboard_lists_pending_then_history_and_audit(
    console_setup: Setup,
) -> None:
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
        pending = await http.get(
            "/api/approvals?status=pending&limit=10", headers=HEADERS
        )
        assert pending.status_code == 200, pending.text
        assert [item["approval_id"] for item in pending.json()["approvals"]] == [
            approval.id
        ]

        approved = await http.post("/api/approve", headers=HEADERS, json={"id": approval.id})
        assert approved.status_code == 200, approved.text

        # The execution task is scheduled on the test loop.
        await asyncio.gather(*tuple(console_setup.manager._tasks))

        history = await http.get("/api/approvals?limit=10", headers=HEADERS)
        assert history.status_code == 200, history.text
        record = history.json()["approvals"][0]
        assert record["approval_id"] == approval.id
        assert record["status"] == "completed"
        assert record["result"] == {"executed": "send_message"}

        audit = await http.get("/api/audit?limit=50", headers=HEADERS)
    assert audit.status_code == 200, audit.text
    events = [entry["event"] for entry in audit.json()["entries"]]
    assert "approval_requested" in events
    assert "approval_granted" in events
    assert "execution_completed" in events


async def test_dashboard_settings_update_persists_and_is_audited(
    console_setup: Setup,
) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        response = await http.post(
            "/api/settings",
            headers=HEADERS,
            json={"approval_ttl_seconds": 120, "audit_enabled": False},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["settings"]["approval_ttl_seconds"] == 120
    assert body["settings"]["audit_enabled"] is False
    assert set(body["changed"]) == {"approval_ttl_seconds", "audit_enabled"}
    assert body["restart_required"] == []

    # Applied live, not only written to disk.
    assert console_setup.settings.approval.ttl_seconds == 120
    assert console_setup.audit.enabled is False

    stored = load_dashboard_settings(console_setup.settings.state_dir)
    assert stored is not None
    assert stored.approval_ttl_seconds == 120
    assert stored.audit_enabled is False

    events = [entry["event"] for entry in console_setup.audit.tail(20)]
    assert "dashboard_settings_changed" in events

    # Turning auditing back on is applied immediately too.
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        back = await http.post(
            "/api/settings", headers=HEADERS, json={"audit_enabled": True}
        )
    assert back.status_code == 200, back.text
    assert console_setup.audit.enabled is True


async def test_dashboard_settings_reject_locked_unknown_and_invalid(
    console_setup: Setup,
) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        for payload in (
            {"token": "x"},
            {"api_base": "https://example.invalid"},
            {"console_port": 8080},
            {"nonsense": 1},
            {"approval_ttl_seconds": 5},
            {"read_only": "yes"},
        ):
            response = await http.post("/api/settings", headers=HEADERS, json=payload)
            assert response.status_code == 400, (payload, response.text)
    # Nothing was partially applied.
    assert console_setup.settings.approval.ttl_seconds == 300
    assert console_setup.settings.http.base_url.startswith("https://discord.com/")


async def test_dashboard_requires_typed_confirmation_to_enable_writes(
    tmp_path: Path,
) -> None:
    setup = Setup(tmp_path / "readonly", read_only=True)
    setup.manager.bind_loop(asyncio.get_running_loop())
    try:
        async with httpx.AsyncClient(base_url=setup.console.base_url) as http:
            denied = await http.post(
                "/api/settings", headers=HEADERS, json={"read_only": False}
            )
            assert denied.status_code == 409, denied.text
            assert denied.json()["code"] == "settings_confirmation_required"
            assert setup.settings.read_only is True

            wrong = await http.post(
                "/api/settings",
                headers=HEADERS,
                json={"read_only": False, "confirmation": "yes"},
            )
            assert wrong.status_code == 409
            assert setup.settings.read_only is True

            ok = await http.post(
                "/api/settings",
                headers=HEADERS,
                json={"read_only": False, "confirmation": "ENABLE WRITES"},
            )
            assert ok.status_code == 200, ok.text
            assert setup.settings.read_only is False
            assert load_dashboard_settings(setup.settings.state_dir).read_only is False
    finally:
        setup.console.stop()


async def test_dashboard_cannot_override_an_environment_read_only_lock(
    tmp_path: Path,
) -> None:
    setup = Setup(tmp_path / "locked", read_only=True)
    setup.console.read_only_locked = True
    setup.manager.bind_loop(asyncio.get_running_loop())
    try:
        async with httpx.AsyncClient(base_url=setup.console.base_url) as http:
            response = await http.post(
                "/api/settings",
                headers=HEADERS,
                json={"read_only": False, "confirmation": "ENABLE WRITES"},
            )
    finally:
        setup.console.stop()
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "read_only_locked"
    assert setup.settings.read_only is True


async def test_dashboard_settings_snapshot_never_contains_the_token(
    console_setup: Setup,
) -> None:
    async with httpx.AsyncClient(base_url=console_setup.console.base_url) as http:
        response = await http.get("/api/settings", headers=HEADERS)
    assert response.status_code == 200, response.text
    text = response.text
    assert console_setup.settings.token is not None
    assert console_setup.settings.token.get_secret_value() not in text
    assert "token" not in response.json()["settings"]
