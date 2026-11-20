"""Local server tools: health, registry inspection, approvals and audit.

These tools never talk to Discord and never approve anything. ``cancel_approval``
can only move a *pending* request to ``cancelled`` - it can never authorise an
operation.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal

from pydantic import Field

from ..api.errors import ValidationError
from ..api.registry import Endpoint, get_registry
from ..security.approval import iso
from ..security.permissions import Risk, describe_policy
from ..tools.specs import TOOL_SPECS, define_tool

APPROVAL_STATUSES = Literal[
    "pending", "approved", "executing", "completed", "failed", "denied", "expired", "cancelled"
]


def _context():
    """Late import: runtime imports this package, so importing it here would cycle."""
    from ..runtime import get_context

    return get_context()


def _endpoint_public(endpoint: Endpoint, *, include_params: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": endpoint.id,
        "method": endpoint.method,
        "path": endpoint.path,
        "category": endpoint.category,
        "status": endpoint.status,
        "risk": endpoint.risk.value if endpoint.risk else None,
        "title": endpoint.title,
        "summary": endpoint.summary,
        "tools": endpoint.tools,
        "deprecated": endpoint.deprecated,
        "oauth2_scope": endpoint.oauth2_scope,
        "limitations": endpoint.limitations,
        "source": endpoint.source,
    }
    if include_params:
        payload["params"] = {
            section: [param.model_dump() for param in params]
            for section, params in endpoint.params.items()
            if params
        }
    return payload


@define_tool(
    name="get_server_status",
    description=(
        "Health check for this MCP server: whether the token was verified, which account is "
        "connected, read-only mode, approval TTL, tool and endpoint counts, and current rate "
        "limit state. It also returns mode.approval_console.dashboard_url, a safe locked "
        "Dashboard address that can be shown to the human (it never contains the access token). "
        "Call this first when something looks wrong. Local only; no Discord request."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Read server health and identity",
)
async def get_server_status() -> Any:
    context = _context()
    registry = get_registry()
    approvals = context.approvals
    pending = approvals.list(statuses=["pending"], limit=200)
    return {
        "ok": True,
        "server": {
            "version": "0.1.0",
            "uptime_seconds": int(time.time() - context.started_at),
            "started_at": iso(context.started_at),
        },
        "identity": context.identity,
        "token": {
            "configured": context.settings.token is not None,
            "source": context.settings.token_source,
            "fingerprint": context.client.token_fingerprint(),
            "bot_tokens_supported": False,
        },
        "mode": {
            "read_only": context.settings.read_only,
            "approval_ttl_seconds": context.settings.approval.ttl_seconds,
            "approval_console": context.console_info(),
            "uploads_enabled": context.settings.upload.enabled,
        },
        "tools": {"registered": len(TOOL_SPECS)},
        "registry": registry.stats(),
        "approvals": {"pending": len(pending)},
        "rate_limits": {
            "global_blocked_for_seconds": context.client.limiter.global_blocked_for,
            "tracked_routes": len(context.client.limiter.snapshot()),
        },
        "approval_policy": describe_policy(),
    }


@define_tool(
    name="search_api_endpoints",
    description=(
        "Search the packaged Discord API endpoint registry. Filter by category, status "
        "(implemented/documented/unsupported), risk (read/write/admin/destructive/sensitive) or "
        "a free-text query. Use this before concluding that something is unsupported: the "
        "registry records the reason every excluded endpoint is excluded. Local only."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Search the endpoint registry for {query}",
)
async def search_api_endpoints(
    query: Annotated[str | None, Field(max_length=120)] = None,
    category: Annotated[str | None, Field(max_length=40)] = None,
    status: Annotated[
        Literal["implemented", "documented", "unsupported"] | None, Field()
    ] = None,
    risk: Annotated[
        Literal["read", "write", "admin", "destructive", "sensitive"] | None, Field()
    ] = None,
    limit: Annotated[int, Field(ge=1, le=200)] = 50,
    offset: Annotated[int, Field(ge=0)] = 0,
) -> Any:
    registry = get_registry()
    rows, total = registry.search(
        category=category, status=status, risk=risk, query=query, limit=limit, offset=offset
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(rows) < total,
        "endpoints": [_endpoint_public(row, include_params=False) for row in rows],
    }


@define_tool(
    name="get_api_endpoint",
    description=(
        "Get one registry entry with its full documented parameter list, risk, status, "
        "limitations and source link. Pass the endpoint id from search_api_endpoints. "
        "Local only."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Read registry entry {endpoint_id}",
    target_fields=("endpoint_id",),
)
async def get_api_endpoint(
    endpoint_id: Annotated[str, Field(min_length=2, max_length=120)],
) -> Any:
    try:
        endpoint = get_registry().get(endpoint_id)
    except KeyError as exc:
        raise ValidationError(f"Unknown endpoint id {endpoint_id!r}") from exc
    return _endpoint_public(endpoint, include_params=True)


@define_tool(
    name="list_approvals",
    description=(
        "List approval requests, newest first, with status, risk, arguments and target. "
        "Read-only; this cannot approve anything. Use it to find the id of a pending request."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="List approval requests",
)
async def list_approvals(
    status: Annotated[APPROVAL_STATUSES | None, Field(description="Filter by status")] = None,
    limit: Annotated[int, Field(ge=1, le=200)] = 50,
) -> Any:
    context = _context()
    statuses = [status] if status else None
    records = context.approvals.list(statuses=statuses, limit=limit)
    return {"count": len(records), "approvals": records}


@define_tool(
    name="check_approval",
    description=(
        "Collect the outcome of an approval request. While the status is pending, a human has "
        "not decided yet - tell the user to open the approval console and do not retry the "
        "tool. Once completed, data holds the Discord response; once failed, error explains "
        "why. Each approval executes at most once."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Check approval {approval_id}",
    target_fields=("approval_id",),
)
async def check_approval(
    approval_id: Annotated[str, Field(min_length=6, max_length=80, pattern=r"^ap_")],
) -> Any:
    context = _context()
    record = context.approvals.check(approval_id)
    if record["status"] == "pending":
        record["console"] = context.console_info(approval_id)
        record["message"] = (
            "Still waiting for a human decision. Give the operator console.dashboard_url and "
            "ask them to open the local dashboard; do not retry the original tool call, which "
            "would create a second request."
        )
    return record


@define_tool(
    name="cancel_approval",
    description=(
        "Cancel a *pending* approval request so it can never execute. This is the only "
        "approval-related state change available to the AI, and it can only deny/cancel - "
        "approving is impossible through MCP."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Cancel pending approval {approval_id}",
    target_fields=("approval_id",),
)
async def cancel_approval(
    approval_id: Annotated[str, Field(min_length=6, max_length=80, pattern=r"^ap_")],
) -> Any:
    context = _context()
    return await context.approvals.cancel(approval_id, actor="mcp-client:cancel")


@define_tool(
    name="get_audit_log",
    description=(
        "Read the tail of the local audit log: approval requests, decisions and executions. "
        "Every entry is redacted. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Read the last {limit} audit entries",
)
async def get_audit_log(
    limit: Annotated[int, Field(ge=1, le=200)] = 50,
) -> Any:
    context = _context()
    entries = context.audit.tail(limit=limit)
    return {"count": len(entries), "entries": entries}


@define_tool(
    name="get_rate_limit_status",
    description=(
        "Show the rate limit buckets this server has observed, plus any active global block. "
        "Read-only and local; useful when a call had to wait."
    ),
    risk=Risk.READ,
    endpoint_id=None,
    summary="Show rate limit state",
)
async def get_rate_limit_status() -> Any:
    limiter = _context().client.limiter
    return {
        "global_blocked_for_seconds": limiter.global_blocked_for,
        "routes": limiter.snapshot(),
    }


__all__ = [
    "cancel_approval",
    "check_approval",
    "get_api_endpoint",
    "get_audit_log",
    "get_rate_limit_status",
    "get_server_status",
    "list_approvals",
    "search_api_endpoints",
]
