"""Runtime wiring: one app context, one gate, one dispatcher.

``dispatch`` is the only path from an MCP tool call to a Discord request.
Read-only tools run immediately; everything else becomes a pending approval
and returns without touching the network.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .api.client import DiscordClient
from .api.errors import (
    DiscordUserMCPError,
    ReadOnlyModeError,
    ValidationError,
)
from .api.registry import Endpoint, Registry, get_registry
from .config import Settings
from .security.approval import ApprovalManager, ToolRequest, iso
from .security.audit import AuditLogger
from .security.permissions import Risk
from .tools.specs import TOOL_SPECS, ToolSpec
from .utils.ids import InvalidArgument

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 1024 * 1024


@dataclass
class AppContext:
    settings: Settings
    client: DiscordClient
    audit: AuditLogger
    approvals: ApprovalManager
    registry: Registry = field(default_factory=get_registry)
    identity: dict[str, object] | None = None
    tool_count: int = 0
    started_at: float = field(default_factory=time.time)
    console: Any = None

    def console_info(self, request_id: str | None = None) -> dict[str, Any]:
        if self.console is None or not getattr(self.console, "running", False):
            return {
                "enabled": False,
                "message": "The local dashboard is not running; no operation can be approved.",
            }
        safe_url = self.console.safe_url
        token_file = getattr(self.console, "token_file", None)
        request_url = (
            f"{safe_url}?request={quote(request_id, safe='')}" if request_id else safe_url
        )
        payload = {
            "enabled": True,
            "dashboard_url": request_url,
            "url_without_token": safe_url,
            "request_id": request_id,
            "unlock_required": True,
            "message": (
                "Give dashboard_url to the human operator. It contains only the request ID "
                "and opens a safe locked page. "
                "The authenticated URL and per-process access token are printed to the "
                "server's stderr and written to approval-console.json in the state "
                "directory; the token itself is deliberately not exposed to the AI."
            ),
        }
        if token_file is not None:
            payload["token_file"] = str(token_file)
            payload["message"] = (
                "Give dashboard_url to the human operator. It contains only the request ID "
                "and opens a safe locked page. The authenticated URL and per-process access "
                f"token are printed to the server's stderr and written to {token_file}; tell "
                "the human that path if they cannot find the token. The token itself is "
                "deliberately not exposed to the AI."
            )
        return payload


_CTX: AppContext | None = None


def set_context(context: AppContext) -> AppContext:
    global _CTX
    _CTX = context
    return context


def get_context() -> AppContext:
    if _CTX is None:
        raise RuntimeError("server context is not initialised")
    return _CTX


def clear_context() -> None:
    global _CTX
    _CTX = None


# --------------------------------------------------------------------------
# Response envelopes
# --------------------------------------------------------------------------


def _ok(spec: ToolSpec, data: Any) -> dict[str, Any]:
    return {
        "status": "ok",
        "tool": spec.name,
        "endpoint": spec.endpoint_id or "local",
        "data": cap_payload(data),
    }


def _error(spec: ToolSpec, error: DiscordUserMCPError) -> dict[str, Any]:
    return {"status": "error", "tool": spec.name, "error": error.to_dict()}


def cap_payload(payload: Any) -> Any:
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return payload
    if len(encoded.encode("utf-8")) <= MAX_RESPONSE_BYTES:
        return payload
    if isinstance(payload, list):
        preview: Any = payload[:5]
    elif isinstance(payload, dict):
        preview = dict(list(payload.items())[:8])
    else:
        preview = str(payload)[:1000]
    return {
        "truncated": True,
        "reason": f"response exceeded {MAX_RESPONSE_BYTES} bytes",
        "hint": "Narrow the request (smaller limit, cursor, or search filters).",
        "approx_bytes": len(encoded.encode("utf-8")),
        "preview": preview,
    }


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


def _path_parameter_names(endpoint: Endpoint) -> set[str]:
    import re

    return set(re.findall(r"\{([^}]+)\}", endpoint.path))


def _is_snowflake_parameter(name: str) -> bool:
    return name == "id" or name.endswith("_id")


def _dry_run(spec: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
    endpoint = get_registry().get(spec.endpoint_id)
    path = Registry.render_path(endpoint, args)
    return {
        "status": "dry_run",
        "tool": spec.name,
        "request": {
            "method": endpoint.method,
            "path": path,
            "arguments": args,
        },
        "approval_would_be_required": spec.risk.requires_approval,
        "note": (
            "Dry run only. No request was sent to Discord and no approval was created. "
            "Run the tool again with dry_run=false (and human approval) to execute it."
        ),
    }


async def dispatch(spec: ToolSpec, call_args: dict[str, Any]) -> dict[str, Any]:
    context = get_context()
    args = dict(call_args)
    dry_run = bool(args.pop("dry_run", False))
    try:
        endpoint = None
        if spec.endpoint_id:
            endpoint = get_registry().get(spec.endpoint_id)
            for name in _path_parameter_names(endpoint):
                if not _is_snowflake_parameter(name):
                    continue
                if name in args and args[name] is not None:
                    value = str(args[name])
                    if not value.isdigit() or not 5 <= len(value) <= 20:
                        raise InvalidArgument(f"path parameter {name} must be a snowflake id")

        if spec.validate is not None:
            spec.validate(args)

        if spec.risk is Risk.READ:
            data = await spec.func(**args)  # type: ignore[misc]
            return _ok(spec, data)

        if dry_run:
            return _dry_run(spec, args)

        if context.settings.read_only:
            raise ReadOnlyModeError()

        approval = await context.approvals.request(
            ToolRequest(
                tool=spec.name,
                endpoint_id=spec.endpoint_id,
                risk=spec.risk,
                summary=spec.render_summary(args),
                target=spec.render_target(args),
                args=args,
            )
        )
        public = approval.public()
        return {
            "status": "approval_required",
            "tool": spec.name,
            "approval_id": public["approval_id"],
            "risk": public["risk"],
            "risk_label": public["risk_label"],
            "summary": public["summary"],
            "target": public["target"],
            "arguments": public["args"],
            "args_hash": public["args_hash"],
            "expires_at": public["expires_at"],
            "expires_in_seconds": public["expires_in_seconds"],
            "requires_typed_confirmation": public["requires_typed_confirmation"],
            "console": context.console_info(public["approval_id"]),
            "next_step": (
                "Nothing has been sent to Discord. A human must approve this exact request in "
                "the local dashboard. Show them console.dashboard_url (it contains this request "
                "ID, never the dashboard token). After they decide, call check_approval with "
                f"approval_id={public['approval_id']} to collect the result."
            ),
            "do_not": "Do not retry this tool call; that creates a second pending request.",
        }
    except InvalidArgument as exc:
        return _error(spec, ValidationError(str(exc)))
    except DiscordUserMCPError as exc:
        return _error(spec, exc)
    except ValueError as exc:
        return _error(spec, ValidationError(str(exc)))
    except Exception as exc:  # noqa: BLE001 - never leak internals
        logger.exception("tool %s failed unexpectedly", spec.name)
        return {
            "status": "error",
            "tool": spec.name,
            "error": {
                "code": "internal_error",
                "message": f"Unexpected server error ({type(exc).__name__}). See server logs.",
                "retryable": False,
            },
        }


async def execute_approved(tool: str, args: dict[str, Any]) -> Any:
    """Run a previously approved tool. Only the approval manager calls this."""
    spec = TOOL_SPECS.get(tool)
    if spec is None:
        raise ValidationError(f"Unknown tool {tool!r} in approval record")
    if spec.func is None:  # pragma: no cover - registration always sets it
        raise ValidationError(f"Tool {tool!r} has no implementation")
    return await spec.func(**args)


__all__ = [
    "AppContext",
    "clear_context",
    "dispatch",
    "execute_approved",
    "get_context",
    "set_context",
    "_dry_run",
    "iso",
]
