"""Tool dispatch: reads run, writes stop at the gate, dry runs never execute."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from discord_user_mcp.tools import TOOL_SPECS
from discord_user_mcp.tools.system import (
    cancel_approval,
    check_approval,
    get_api_endpoint,
    get_server_status,
    search_api_endpoints,
)

from conftest import Harness, TEST_TOKEN, default_handler, make_settings


async def test_read_tool_calls_discord(harness) -> None:
    result = await TOOL_SPECS["get_current_user"].wrapper()
    assert result["status"] == "ok"
    assert result["data"]["username"] == "tester"
    assert [str(request.url.path) for request in harness.requests] == ["/api/v9/users/@me"]


async def test_write_tool_creates_approval_and_sends_nothing(harness) -> None:
    before = len(harness.requests)
    result = await TOOL_SPECS["send_message"].wrapper(channel_id="123456789012345678", content="hi")
    assert result["status"] == "approval_required"
    assert result["approval_id"].startswith("ap_")
    assert result["risk"] == "write"
    assert result["arguments"]["content"] == "hi"
    assert "console" in result and result["console"]["enabled"] is False
    assert len(harness.requests) == before
    pending = harness.store.list(statuses=["pending"])
    assert [record.id for record in pending] == [result["approval_id"]]


async def test_mutation_returns_request_scoped_safe_dashboard_url(harness) -> None:
    class Dashboard:
        running = True
        safe_url = "http://127.0.0.1:54321/"

    harness.context.console = Dashboard()
    result = await TOOL_SPECS["send_message"].wrapper(
        channel_id="123456789012345678", content="hi"
    )
    info = result["console"]
    assert info["request_id"] == result["approval_id"]
    assert info["dashboard_url"] == (
        f"http://127.0.0.1:54321/?request={result['approval_id']}"
    )
    assert "t" not in parse_qs(urlparse(info["dashboard_url"]).query)
    assert info["unlock_required"] is True


async def test_dry_run_does_not_create_an_approval(harness) -> None:
    result = await TOOL_SPECS["send_message"].wrapper(
        channel_id="123456789012345678", content="hi", dry_run=True
    )
    assert result["status"] == "dry_run"
    assert result["request"]["method"] == "POST"
    assert result["request"]["path"] == "/channels/123456789012345678/messages"
    assert result["approval_would_be_required"] is True
    assert harness.store.list() == []
    assert harness.requests == []


async def test_read_only_mode_blocks_writes(tmp_path: Path) -> None:
    settings = make_settings(tmp_path / "state", read_only=True)
    async with Harness(settings, default_handler) as gate:
        result = await TOOL_SPECS["send_message"].wrapper(
            channel_id="123456789012345678", content="hi"
        )
    assert result["status"] == "error"
    assert result["error"]["code"] == "read_only_mode"


async def test_invalid_path_parameter_is_a_validation_error(harness) -> None:
    result = await TOOL_SPECS["get_channel"].wrapper(channel_id="not-an-id")
    assert result["status"] == "error"
    assert result["error"]["code"] == "validation_error"
    assert harness.requests == []


async def test_check_approval_reports_pending_then_completed(harness) -> None:
    created = await TOOL_SPECS["send_message"].wrapper(
        channel_id="123456789012345678", content="hello"
    )
    pending = (await check_approval(created["approval_id"]))["data"]
    assert pending["status"] == "pending"
    assert "dashboard" in pending["message"]

    await harness.approvals.approve(
        created["approval_id"], actor="console:test", confirmation=None
    )
    import asyncio

    for _ in range(200):
        record = harness.store.get(created["approval_id"])
        if record.status == "completed":
            break
        await asyncio.sleep(0.01)
    done = (await check_approval(created["approval_id"]))["data"]
    assert done["status"] == "completed"
    assert done["result"] == {"executed": "send_message"}


async def test_cancel_approval_prevents_execution(harness) -> None:
    created = await TOOL_SPECS["send_message"].wrapper(
        channel_id="123456789012345678", content="hello"
    )
    result = (await cancel_approval(created["approval_id"]))["data"]
    assert result["status"] == "cancelled"
    assert harness.store.get(created["approval_id"]).status == "cancelled"


async def test_system_status_never_exposes_the_token(harness) -> None:
    result = (await get_server_status())["data"]
    assert TEST_TOKEN not in repr(result)
    assert result["token"]["configured"] is True
    assert result["token"]["bot_tokens_supported"] is False
    assert result["registry"]["by_status"]["implemented"] >= 100


async def test_search_and_get_registry_entries(harness) -> None:
    found = (
        await search_api_endpoints(query="scheduled event", status="implemented", limit=10)
    )["data"]
    assert found["total"] >= 1
    ids = [entry["id"] for entry in found["endpoints"]]
    assert "events.create" in ids
    detail = (await get_api_endpoint("events.create"))["data"]
    assert detail["method"] == "POST"
    assert detail["params"]["json"]
    assert detail["source"].startswith("https://docs.discord.food/")


async def test_unknown_endpoint_id_is_reported(harness) -> None:
    result = await get_api_endpoint("does.not.exist")
    assert result["status"] == "error"
    assert result["error"]["code"] == "validation_error"


async def test_every_tool_has_a_useful_description() -> None:
    for name, spec in TOOL_SPECS.items():
        assert len(spec.description) >= 30, name
        assert spec.summary, name
        assert spec.risk.requires_approval == (spec.risk.value != "read"), name


async def test_sensitive_tools_are_flagged_for_typed_confirmation() -> None:
    for name, spec in TOOL_SPECS.items():
        if spec.risk.value in {"sensitive", "destructive", "admin"}:
            assert spec.risk.requires_typed_confirmation, name

async def test_reaction_path_encodes_unicode_emoji_once(harness) -> None:
    result = await TOOL_SPECS["list_reactions"].wrapper(
        channel_id="123456789012345678",
        message_id="223456789012345678",
        emoji="\U0001F44D",
    )
    assert result["status"] == "ok"
    assert "%F0%9F%91%8D" in harness.requests[-1].url.raw_path.decode()
    assert "%25" not in harness.requests[-1].url.raw_path.decode()


async def test_reaction_write_is_gated_with_a_custom_emoji_path(harness) -> None:
    result = await TOOL_SPECS["add_reaction"].wrapper(
        channel_id="123456789012345678",
        message_id="223456789012345678",
        emoji="wave:123456789012345678",
    )
    assert result["status"] == "approval_required"
    assert harness.store.list(statuses=["pending"])
    assert harness.requests == []


async def test_invite_code_is_not_validated_as_a_snowflake(harness) -> None:
    result = await TOOL_SPECS["get_invite"].wrapper(invite_code="aBcD1234")
    assert result["status"] == "ok"
    assert harness.requests[-1].url.path.endswith("/invites/aBcD1234")

async def test_reorder_guild_roles_dry_run_shows_the_documented_array(harness) -> None:
    result = await TOOL_SPECS["reorder_guild_roles"].wrapper(
        guild_id="123456789012345678",
        positions=[{"id": "223456789012345678", "position": 3}],
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["request"]["method"] == "PATCH"
    assert result["request"]["path"] == "/guilds/123456789012345678/roles"
    assert result["request"]["arguments"]["positions"][0]["id"] == "223456789012345678"


async def test_reorder_guild_roles_is_gated_and_rejects_bad_positions(harness) -> None:
    result = await TOOL_SPECS["reorder_guild_roles"].wrapper(
        guild_id="123456789012345678",
        positions=[{"id": "223456789012345678", "position": 3}],
    )
    assert result["status"] == "approval_required"
    assert result["risk"] == "admin"
    assert harness.requests == []
    bad = await TOOL_SPECS["reorder_guild_roles"].wrapper(
        guild_id="123456789012345678",
        positions=[{"id": "not-an-id", "position": 3}],
    )
    assert bad["status"] == "error"
    assert bad["error"]["code"] == "validation_error"
    assert harness.store.list(statuses=["pending"])


async def test_update_guild_role_never_sends_an_undocumented_position(harness) -> None:
    result = await TOOL_SPECS["update_guild_role"].wrapper(
        guild_id="123456789012345678",
        role_id="223456789012345678",
        name="new name",
    )
    assert result["status"] == "approval_required"
    assert "position" not in result["arguments"]
