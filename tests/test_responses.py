"""Real serialization and dispatch tests for model-selected response budgets."""

import asyncio
import json
import random

import pytest
from mcp.server.fastmcp.utilities.func_metadata import _convert_to_content

from conftest import Harness, json_response
from discord_user_mcp.runtime import execute_approved
from discord_user_mcp.server import build_server
from discord_user_mcp.tools import TOOL_SPECS
from discord_user_mcp.utils.responses import (
    DEFAULT_RESPONSE_BYTES, HARD_RESPONSE_BYTES, encoded, limit_response, resolve_budget,
)

ID = "123456789012345678"


def assert_bounded(result, maximum):
    raw = encoded(result)
    assert len(raw) <= maximum
    assert result["response"]["returned_bytes"] == len(raw)
    assert result["response"]["effective_max_bytes"] == maximum
    content = _convert_to_content(result)
    assert len(content) == 1
    assert content[0].text.encode("utf-8") == raw


@pytest.mark.parametrize("data", [
    "中😀\\\"\n\t" * 10000,
    [{"nested": [{"huge": "中" * 100000}]}],
    {"huge": ["x" * 20000] * 20, "later": "value"},
    list(range(50000)),
    {"x" * 10000: "value", "short": "value"},
])
@pytest.mark.parametrize("budget", [1024, 2048, 8192])
def test_nested_content_never_exceeds_full_envelope_budget(data, budget):
    original = {"status": "ok", "tool": "example", "data": data}
    result = limit_response(original, maximum=budget, requested=budget)
    assert_bounded(result, budget)
    assert result["status"] == "ok"
    assert result["tool"] == "example"
    assert result["response"]["truncated"] is True
    assert result["response"]["original_bytes"] == len(encoded(original))
    assert "response" not in original  # no mutation of stored approval data


def test_small_payload_is_unchanged_and_metadata_is_exact():
    original = {"status": "ok", "data": {"unicode": "繁體中文😀", "escape": "\n\\\""}}
    result = limit_response(original, maximum=1024)
    assert result["data"] == original["data"]
    assert result["response"]["truncated"] is False
    assert result["response"]["original_bytes"] == len(encoded(original))
    assert_bounded(result, 1024)


def test_envelope_and_metadata_count_toward_budget():
    original = {"status": "ok", "data": "x" * 800}
    assert len(encoded(original)) < 1024
    result = limit_response(original, maximum=1024)
    assert result["response"]["truncated"] is True
    assert_bounded(result, 1024)


def test_approval_control_fields_survive_large_arguments():
    original = {"arguments": {"content": "x" * 100000}, "status": "approval_required",
                "tool": "send_message", "approval_id": "ap_example", "risk": "write",
                "requires_typed_confirmation": False, "expires_in_seconds": 300}
    result = limit_response(original, maximum=1024)
    for key in ("status", "tool", "approval_id", "risk", "requires_typed_confirmation", "expires_in_seconds"):
        assert result[key] == original[key]
    assert_bounded(result, 1024)


def test_random_nested_values_have_exact_serialized_sizes():
    rng = random.Random(42)
    def value(depth=0):
        if depth > 4 or rng.random() < .4:
            return rng.choice([None, True, 123, "中😀\n\\\"" * rng.randrange(1, 300)])
        if rng.random() < .5:
            return [value(depth + 1) for _ in range(rng.randrange(1, 8))]
        return {f"k{i}": value(depth + 1) for i in range(rng.randrange(1, 8))}
    for _ in range(100):
        budget = rng.randrange(1024, 10000)
        result = limit_response({"status": "ok", "data": value()}, maximum=budget)
        assert_bounded(result, budget)


def test_circular_content_fails_closed():
    circular = []
    circular.append(circular)
    result = limit_response({"status": "ok", "data": circular}, maximum=1024)
    assert result["error"]["code"] == "response_serialization_error"
    assert_bounded(result, 1024)


@pytest.mark.parametrize("bad", [True, False, 0, 1023, -1, HARD_RESPONSE_BYTES + 1, 2048.0, "2048", {}, []])
async def test_invalid_budgets_never_reach_http_or_approval(harness, bad):
    result = await TOOL_SPECS["send_message"].wrapper(channel_id=ID, content="hello", response_max_bytes=bad)
    assert result["error"]["code"] == "validation_error"
    assert harness.requests == []
    assert harness.store.list() == []


@pytest.mark.parametrize("requested,effective", [(None, 4096), (1024, 1024), (8192, 8192), (HARD_RESPONSE_BYTES, 8192)])
async def test_default_explicit_and_operator_clamped_budgets(settings, requested, effective):
    settings.response_default_bytes = 4096
    settings.response_max_bytes = 8192
    async with Harness(settings, lambda request: json_response({"large": "中" * 10000})) as harness:
        result = await TOOL_SPECS["get_current_user"].wrapper(response_max_bytes=requested)
        assert_bounded(result, effective)
        assert result["response"]["requested_max_bytes"] == requested
        assert result["response"]["server_max_bytes"] == 8192
        assert "response_max_bytes" not in harness.requests[0].url.params


async def test_default_allows_more_than_old_one_mib_limit(settings):
    large = "x" * (2 * 1024 * 1024)
    async with Harness(settings, lambda request: json_response({"large": large})):
        result = await TOOL_SPECS["get_current_user"].wrapper()
        assert result["data"]["large"] == large
        assert result["response"]["truncated"] is False
        assert_bounded(result, DEFAULT_RESPONSE_BYTES)


async def test_fastmcp_validates_and_converts_selected_budget(harness):
    server = build_server(harness.context)
    content = await server.call_tool("get_current_user", {"response_max_bytes": 1024})
    # FastMCP may return content together with structured content.
    blocks = content[0] if isinstance(content, tuple) else content
    result = json.loads(blocks[0].text)
    assert len(blocks[0].text.encode("utf-8")) <= 1024
    assert_bounded(result, 1024)
    for bad in (True, "2048", 1023, HARD_RESPONSE_BYTES + 1):
        before = len(harness.requests)
        with pytest.raises(Exception):
            await server.call_tool("get_current_user", {"response_max_bytes": bad})
        assert len(harness.requests) == before


async def test_larger_approval_collection_does_not_repeat_mutation(settings):
    large = "中😀" * 10000
    async with Harness(settings, lambda request: json_response({"id": ID, "content": large})) as harness:
        harness.approvals.executor = execute_approved
        proposed = await TOOL_SPECS["send_message"].wrapper(
            channel_id=ID, content="hello", response_max_bytes=1024)
        approval_id = proposed["approval_id"]
        assert proposed["status"] == "approval_required"
        record = harness.store.get(approval_id)
        assert "response_max_bytes" not in record.args
        await harness.approvals.approve(approval_id, actor="console:test", confirmation=None)
        async with asyncio.timeout(3):
            while harness.store.get(approval_id).status in {"approved", "executing"}:
                await asyncio.sleep(.005)
        assert harness.store.get(approval_id).status == "completed"
        small = await TOOL_SPECS["check_approval"].wrapper(approval_id=approval_id, response_max_bytes=1024)
        big = await TOOL_SPECS["check_approval"].wrapper(approval_id=approval_id, response_max_bytes=200000)
        assert small["response"]["truncated"] is True
        assert small["data"]["approval_id"] == approval_id
        assert small["data"]["status"] == "completed"
        assert big["response"]["truncated"] is False
        assert big["data"]["status"] == "completed"
        assert big["data"]["result"]["content"] == large
        assert_bounded(small, 1024)
        assert_bounded(big, 200000)
        assert len(harness.requests) == 1
        assert "response_max_bytes" not in json.loads(harness.requests[0].content)


def test_budget_resolution_defaults_and_clamps():
    assert resolve_budget(None, default=4096, maximum=8192) == 4096
    assert resolve_budget(16384, default=4096, maximum=8192) == 8192
