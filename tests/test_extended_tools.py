"""Every added endpoint exercises real tool code against mock HTTP, never Discord."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import sqlite3

import pytest

from discord_user_mcp.runtime import execute_approved
from discord_user_mcp.api.errors import ApprovalAlreadyDecided, ApprovalConfirmationRequired, ApprovalExpired
from discord_user_mcp.server import build_server
from discord_user_mcp.tools import TOOL_SPECS
from discord_user_mcp.tools.extended import CATALOG
from conftest import Harness, json_response

ID = "123456789012345678"
STAMP = "2026-11-21T12:00:00+00:00"
READS = [item for item in CATALOG if item.get("risk", "read") == "read"]
WRITES = [item for item in CATALOG if item.get("risk", "read") != "read"]


def arguments(item: dict) -> dict:
    args = {
        key: "sample-code" if key.endswith("_code") else ID
        for key in re.findall(r"\{([^}]+)\}", item["path"])
    }
    samples = {
        "snowflake": ID, "snowflakes": [ID], "text": "example", "name": "example",
        "tag_name": "example", "emoji_name": "wave", "description": "example",
        "topic": "Discussion", "code": "sample-code", "locale": "en-US",
        "timestamp": STAMP, "bool": False, "limit50": 25, "limit100": 25,
        "limit1000": 25, "offset": 0, "nonnegative": 0, "volume": 0.5,
        "privacy_level": 2, "expire_behavior": 1, "grace_period": 7,
        "role_ids": [ID], "asset_name": "sample", "sticker_name": "sample",
        "sticker_description": "sample", "sticker_tags": "sample",
        "template_description": "sample", "welcome_description": "sample",
    }
    aliases = item.get("body_aliases", {})
    for section in ("query", "body"):
        for key, kind in item.get(section, {}).items():
            if key in {"after", "emoji_name"}:
                continue  # Do not choose conflicting pagination or emoji fields.
            args[aliases.get(key, key) if section == "body" else key] = samples[kind]
    return args


def check_request(harness, item: dict, args: dict) -> None:
    assert len(harness.requests) == 1
    request = harness.requests[0]
    expected = re.sub(r"\{([^}]+)\}", lambda m: args[m[1]], item["path"])
    assert request.url.path == "/api/v9" + expected
    assert request.method == item["method"]
    for key in item.get("query", {}):
        if args.get(key) is not None:
            value = args[key]
            if isinstance(value, bool):
                assert request.url.params[key] == str(value).lower()
            elif isinstance(value, list):
                assert request.url.params.get_list(key) == value
            else:
                assert request.url.params[key] == str(value)
        else:
            assert key not in request.url.params
    aliases = item.get("body_aliases", {})
    if item.get("body"):
        expected_body = {k: args[aliases.get(k, k)] for k in item["body"]
                         if args.get(aliases.get(k, k)) is not None}
        assert json.loads(request.content) == expected_body
    else:
        assert request.content == b""


@pytest.mark.parametrize("item", READS, ids=lambda item: item["name"])
async def test_each_added_read_routes_and_serializes(harness, item) -> None:
    args = arguments(item)
    result = await TOOL_SPECS[item["name"]].wrapper(**args)
    assert result["status"] == "ok", result
    assert harness.store.list() == []
    check_request(harness, item, args)


@pytest.mark.parametrize("item", WRITES, ids=lambda item: item["name"])
async def test_each_added_mutation_requires_approval_and_runs_real_code(harness, item) -> None:
    harness.approvals.executor = execute_approved
    args = arguments(item)
    result = await TOOL_SPECS[item["name"]].wrapper(**args)
    assert result["status"] == "approval_required", result
    assert result["risk"] == item["risk"]
    assert harness.requests == []
    confirmation = "APPROVE" if result["requires_typed_confirmation"] else None
    if confirmation:
        with pytest.raises(ApprovalConfirmationRequired):
            await harness.approvals.approve(result["approval_id"], actor="console:test", confirmation="yes")
        assert harness.requests == []
    await harness.approvals.approve(result["approval_id"], actor="console:test", confirmation=confirmation)
    async with asyncio.timeout(3):
        while harness.store.get(result["approval_id"]).status in {"approved", "executing"}:
            await asyncio.sleep(0.005)
    assert harness.store.get(result["approval_id"]).status == "completed"
    check_request(harness, item, args)
    with pytest.raises(ApprovalAlreadyDecided):
        await harness.approvals.approve(result["approval_id"], actor="console:test", confirmation=confirmation)
    assert len(harness.requests) == 1


@pytest.mark.parametrize("item", WRITES, ids=lambda item: item["name"])
async def test_each_added_mutation_dry_run_denial_and_read_only(harness, item) -> None:
    spec = TOOL_SPECS[item["name"]]
    args = arguments(item)
    result = await spec.wrapper(**args, dry_run=True)
    assert result["status"] == "dry_run", result
    assert harness.requests == []
    assert harness.store.list() == []
    result = await spec.wrapper(**args)
    await harness.approvals.deny(result["approval_id"], actor="console:test")
    assert harness.store.get(result["approval_id"]).status == "denied"
    assert harness.requests == []
    harness.settings.read_only = True
    blocked = await spec.wrapper(**args)
    assert blocked["error"]["code"] == "read_only_mode"
    assert len(harness.store.list()) == 1
    assert harness.requests == []


@pytest.mark.parametrize("item", WRITES, ids=lambda item: item["name"])
async def test_each_added_mutation_expiry_and_argument_tampering(harness, item) -> None:
    harness.approvals.executor = execute_approved
    spec = TOOL_SPECS[item["name"]]
    args = arguments(item)
    proposal = await spec.wrapper(**args)
    confirmation = "APPROVE" if proposal["requires_typed_confirmation"] else None
    with sqlite3.connect(harness.store.path) as conn:
        conn.execute("UPDATE approvals SET expires_at=0 WHERE id=?", (proposal["approval_id"],))
    with pytest.raises(ApprovalExpired):
        await harness.approvals.approve(proposal["approval_id"], actor="console:test", confirmation=confirmation)
    assert harness.store.get(proposal["approval_id"]).status == "expired"
    assert harness.requests == []

    proposal = await spec.wrapper(**args)
    await harness.approvals.approve(proposal["approval_id"], actor="console:test", confirmation=confirmation)
    # Modify the test database before the queued execution task gets control.
    with sqlite3.connect(harness.store.path) as conn:
        conn.execute("UPDATE approvals SET args_json=? WHERE id=?",
                     (json.dumps({**args, "extra_field": "tampered"}), proposal["approval_id"]))
    async with asyncio.timeout(3):
        while harness.store.get(proposal["approval_id"]).status in {"approved", "executing"}:
            await asyncio.sleep(0.005)
    record = harness.store.get(proposal["approval_id"])
    assert record.status == "failed"
    assert record.error["code"] == "approval_arguments_tampered"
    assert harness.requests == []


@pytest.mark.parametrize("name,args", [
    ("get_guild_ban", {"guild_id": "invalid", "user_id": ID}),
    ("search_discoverable_guilds", {"query": "x", "limit": 101}),
    ("list_private_archived_threads", {"channel_id": ID, "before": "not-a-date"}),
    ("list_private_archived_threads", {"channel_id": ID, "before": "2026-11-21T12:00:00"}),
    ("list_guild_join_requests", {"guild_id": ID, "before": ID, "after": ID}),
    ("list_my_scheduled_events", {"guild_ids": ["invalid"]}),
    ("create_forum_tag", {"channel_id": ID, "name": "x" * 21}),
    ("create_forum_tag", {"channel_id": ID, "name": "tag", "emoji_id": ID, "emoji_name": "wave"}),
    ("update_guild_emoji", {"guild_id": ID, "emoji_id": ID, "roles": ["invalid"]}),
    ("update_guild_emoji", {"guild_id": ID, "emoji_id": ID, "name": "x"}),
    ("update_guild_template", {"guild_id": ID, "template_code": "code", "description": "x" * 121}),
    ("update_guild_sticker", {"guild_id": ID, "sticker_id": ID, "name": "x" * 31}),
    ("update_guild_welcome_screen", {"guild_id": ID, "description": "x" * 141}),
    ("update_guild_widget", {"guild_id": ID}),
    ("update_guild_soundboard_sound", {"guild_id": ID, "sound_id": ID, "volume": 1.1}),
    ("update_guild_soundboard_sound", {"guild_id": ID, "sound_id": ID, "volume": "0.5"}),
    ("update_stage_instance", {"channel_id": ID, "privacy_level": 1}),
    ("update_guild_integration", {"guild_id": ID, "integration_id": ID, "expire_grace_period": 2}),
])
async def test_invalid_arguments_never_reach_gate_or_http(harness, name, args) -> None:
    result = await TOOL_SPECS[name].wrapper(**args)
    assert result["status"] == "error", result
    assert result["error"]["code"] == "validation_error"
    assert harness.requests == []
    assert harness.store.list() == []


async def test_extra_arguments_cannot_select_an_arbitrary_route(harness) -> None:
    with pytest.raises(TypeError):
        await TOOL_SPECS["get_guild_ban"].wrapper(guild_id=ID, user_id=ID, url="https://example.com")
    assert harness.requests == []


async def test_connection_secrets_never_reach_the_ai(settings) -> None:
    payload = [{"name": "linked-account", "access_token": "third-party-access-value",
                "integrations": [{"refresh_token": "third-party-refresh-value",
                                  "client_secret": "third-party-client-secret"}]}]
    async with Harness(settings, lambda request: json_response(payload)) as harness:
        result = await TOOL_SPECS["list_my_connections"].wrapper()
    assert result["status"] == "ok"
    assert result["data"][0]["name"] == "linked-account"
    assert result["data"][0]["access_token"] == "[REDACTED]"
    assert "third-party" not in repr(result)


async def test_validation_errors_do_not_echo_rejected_credentials(harness) -> None:
    result = await TOOL_SPECS["update_guild_soundboard_sound"].wrapper(
        guild_id=ID, sound_id=ID, volume="misplaced-private-value")
    assert result["error"]["code"] == "validation_error"
    assert "misplaced-private-value" not in repr(result)
    result = await TOOL_SPECS["list_private_archived_threads"].wrapper(
        channel_id=ID, before="misplaced-private-value")
    assert result["error"]["code"] == "validation_error"
    assert "misplaced-private-value" not in repr(result)


async def test_explicit_empty_role_list_is_not_discarded(harness) -> None:
    harness.approvals.executor = execute_approved
    spec = TOOL_SPECS["update_guild_emoji"]
    args = {"guild_id": ID, "emoji_id": ID, "roles": []}
    proposed = await spec.wrapper(**args)
    assert proposed["status"] == "approval_required"
    assert proposed["arguments"]["roles"] == []
    assert harness.requests == []
    await harness.approvals.approve(proposed["approval_id"], actor="console:test", confirmation="APPROVE")
    async with asyncio.timeout(3):
        while harness.store.get(proposed["approval_id"]).status in {"approved", "executing"}:
            await asyncio.sleep(0.005)
    assert harness.store.get(proposed["approval_id"]).status == "completed"
    assert json.loads(harness.requests[0].content) == {"roles": []}


async def test_all_added_tools_have_concrete_fastmcp_schemas(harness) -> None:
    server = build_server(harness.context)
    listed = {tool.name: tool for tool in await server.list_tools()}
    for item in CATALOG:
        schema = listed[item["name"]].inputSchema
        parameters = inspect.signature(TOOL_SPECS[item["name"]].wrapper).parameters
        assert set(schema.get("properties", {})) == set(parameters)
        assert not {"kwargs", "method", "path", "url", "payload"} & set(parameters)
        for key in re.findall(r"\{([^}]+)\}", item["path"]):
            assert key in schema["required"]
        if item.get("risk", "read") != "read":
            assert schema["properties"]["dry_run"]["type"] == "boolean"
