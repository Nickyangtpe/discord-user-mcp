"""Shared helpers for tool modules.

Every HTTP call goes through :func:`call`, which renders the path from the
packaged endpoint registry. A tool therefore cannot drift from the documented
endpoint it claims to implement.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Mapping, Sequence

from pydantic import Field

from ..api.client import DiscordClient
from ..api.registry import Registry, get_registry
from ..utils.ids import InvalidArgument, message_content, snowflake

Snowflake = Annotated[
    str,
    Field(min_length=5, max_length=20, pattern=r"^\d+$", description="Discord snowflake id"),
]
OptSnowflake = Annotated[
    str | None,
    Field(default=None, description="Optional Discord snowflake id"),
]
Content = Annotated[str, Field(min_length=1, max_length=2000)]

MAX_RESPONSE_BYTES = 1024 * 1024


def client() -> DiscordClient:
    from ..runtime import get_context

    return get_context().client


def registry() -> Registry:
    return get_registry()


async def call(
    endpoint_id: str,
    *,
    path_params: Mapping[str, Any] | None = None,
    params: Mapping[str, Any] | None = None,
    payload: Any = None,
    files: Sequence[tuple[str, tuple[str, bytes, str]]] | None = None,
    audit_reason: str | None = None,
) -> Any:
    endpoint = registry().get(endpoint_id)
    path = Registry.render_path(endpoint, dict(path_params or {}))
    return await client().request(
        endpoint.method,
        path,
        params=params,
        payload=payload,
        files=files,
        audit_reason=audit_reason,
    )


def cap(payload: Any) -> Any:
    """Keep a single tool response below 1 MiB of JSON.

    The cap is explicit in the payload so the agent knows data was dropped and
    can narrow the query instead of assuming the list is complete.
    """
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return payload
    if len(encoded.encode("utf-8")) <= MAX_RESPONSE_BYTES:
        return payload
    preview = payload
    if isinstance(payload, list):
        preview = payload[:5]
    elif isinstance(payload, dict):
        preview = {key: value for key, value in list(payload.items())[:8]}
    return {
        "truncated": True,
        "reason": f"response exceeded {MAX_RESPONSE_BYTES} bytes",
        "hint": "Narrow the request (smaller limit, pagination cursor, or search filters).",
        "approx_bytes": len(encoded.encode("utf-8")),
        "preview": preview,
    }


def validate(fn, *values: tuple[str, str]) -> None:
    for field, value in values:
        if value is not None:
            snowflake(value, field)


def content_or_none(value: str | None, *, field: str = "content", limit: int = 2000) -> str | None:
    if value is None:
        return None
    return message_content(value, field=field, limit=limit)


def clean_params(mapping: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value is not None}


__all__ = [
    "Content",
    "InvalidArgument",
    "OptSnowflake",
    "Snowflake",
    "call",
    "cap",
    "clean_params",
    "client",
    "content_or_none",
    "registry",
    "validate",
]
