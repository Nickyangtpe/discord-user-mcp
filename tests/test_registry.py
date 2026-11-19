"""Registry consistency.

The registry is the contract: no tool may call an endpoint it does not declare,
no risk may differ from the curated classification, and no entry may claim to
be implemented without a tool behind it.
"""

from __future__ import annotations

import pytest

from discord_user_mcp.api.registry import get_registry
from discord_user_mcp.tools.specs import TOOL_SPECS

LOCAL_TOOLS = {
    "get_server_status",
    "search_api_endpoints",
    "get_api_endpoint",
    "list_approvals",
    "check_approval",
    "cancel_approval",
    "get_audit_log",
    "get_rate_limit_status",
}


@pytest.fixture(scope="module")
def registry():
    return get_registry()


def test_registry_is_generated_and_substantial(registry) -> None:
    assert len(registry) > 900
    stats = registry.stats()
    assert stats["by_status"]["implemented"] >= 100
    assert stats["by_status"]["unsupported"] >= 100


def test_every_tool_maps_to_a_declared_endpoint(registry) -> None:
    mapping = registry.tool_endpoints()
    for name, spec in TOOL_SPECS.items():
        if name in LOCAL_TOOLS:
            assert spec.endpoint_id is None, f"{name} is local but declares {spec.endpoint_id}"
            continue
        assert name in mapping, f"tool {name} is not listed by any registry endpoint"
        assert spec.endpoint_id == mapping[name].id, (
            f"tool {name} points at {spec.endpoint_id}, registry says {mapping[name].id}"
        )


def test_every_registry_tool_exists_in_code(registry) -> None:
    for name in registry.tool_endpoints():
        assert name in TOOL_SPECS, f"registry lists tool {name} but no tool defines it"


def test_tool_risk_matches_registry(registry) -> None:
    mapping = registry.tool_endpoints()
    for name, endpoint in mapping.items():
        assert endpoint.risk is not None, f"{name} has no risk classification"
        assert TOOL_SPECS[name].risk is endpoint.risk, (
            f"{name}: tool says {TOOL_SPECS[name].risk.value}, "
            f"registry says {endpoint.risk.value}"
        )


def test_implemented_entries_have_risk_and_tools(registry) -> None:
    for endpoint in registry:
        if endpoint.status == "implemented":
            assert endpoint.risk is not None, endpoint.id
            assert endpoint.tools, endpoint.id
            assert endpoint.params is not None
        if endpoint.tools:
            assert endpoint.status == "implemented", endpoint.id
        if endpoint.status == "unsupported":
            assert endpoint.limitations, f"{endpoint.id} is unsupported without a reason"


def test_endpoint_ids_and_paths_are_unique(registry) -> None:
    ids = [endpoint.id for endpoint in registry]
    assert len(ids) == len(set(ids))
    routes = [(endpoint.method, endpoint.path) for endpoint in registry]
    assert len(routes) == len(set(routes))


def test_every_entry_cites_the_docs(registry) -> None:
    for endpoint in registry:
        assert endpoint.source.startswith("https://docs.discord.food/"), endpoint.id


def test_no_arbitrary_http_tool() -> None:
    """There must be no tool that takes a raw method/url and sends it."""
    forbidden = {"request", "http_request", "raw_request", "fetch", "call_endpoint"}
    assert not (forbidden & set(TOOL_SPECS))


def test_approving_endpoints_are_not_tools() -> None:
    """Nothing in MCP may approve: no tool name may imply it."""
    for name in TOOL_SPECS:
        assert "approve" not in name, f"{name} looks like it could approve its own call"
