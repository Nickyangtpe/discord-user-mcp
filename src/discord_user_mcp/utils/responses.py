"""Bound the actual UTF-8 JSON tool content, including nested data and metadata."""

from __future__ import annotations

import json
from typing import Any

from pydantic_core import to_json

MIN_RESPONSE_BYTES = 1024
DEFAULT_RESPONSE_BYTES = 4 * 1024 * 1024
HARD_RESPONSE_BYTES = 16 * 1024 * 1024
_OMIT = object()
_PRIORITY = ("response", "status", "tool", "endpoint", "approval_id", "risk",
             "risk_label", "requires_typed_confirmation", "expires_at",
             "expires_in_seconds", "console", "error", "next_step", "do_not")


def encoded(value: Any) -> bytes:
    # Match FastMCP's TextContent serialization, not just compact JSON. The
    # JSON-RPC transport framing around that content is outside this budget.
    return to_json(value, fallback=str, indent=2)


def _size(value: Any, depth: int = 0) -> int:
    raw = encoded(value)
    return len(raw) + raw.count(b"\n") * 2 * depth


def _fit(value: Any, budget: int, depth: int = 0) -> Any:
    if budget < 2:
        return _OMIT
    if depth > 32:
        value = "[depth limit]"
    if _size(value, depth) <= budget:
        return value
    if isinstance(value, str):
        low, high = 0, min(len(value), budget)
        while low < high:
            middle = (low + high + 1) // 2
            if _size(value[:middle] + "…") <= budget:
                low = middle
            else:
                high = middle - 1
        clipped = value[:low] + "…"
        return clipped if _size(clipped) <= budget else ""
    if isinstance(value, (dict, list)):
        is_object = isinstance(value, dict)
        result: Any = {} if is_object else []
        # Nonempty container: opening brace/newline, final newline/indent/brace.
        used = 4 + 2 * depth
        keys = ([key for key in _PRIORITY if key in value] +
                [key for key in value if key not in _PRIORITY]) if is_object else range(len(value))
        for key in keys:
            overhead = 2 * (depth + 1) + (2 if result else 0)
            if is_object:
                overhead += _size(str(key)) + 2  # key + ': '
            remaining = budget - used - overhead
            if remaining < 2:
                if not is_object:
                    break
                continue
            child = _fit(value[key], remaining, depth + 1)
            if child is _OMIT:
                if not is_object:
                    break
                continue
            if is_object:
                result[key] = child
            else:
                result.append(child)
            used += overhead + _size(child, depth + 1)
        return result
    return None if budget >= 4 else _OMIT


def resolve_budget(requested: int | None, *, default: int, maximum: int) -> int:
    if requested is not None and (
        type(requested) is not int or not MIN_RESPONSE_BYTES <= requested <= HARD_RESPONSE_BYTES
    ):
        raise ValueError(f"response_max_bytes must be an integer between {MIN_RESPONSE_BYTES} and {HARD_RESPONSE_BYTES}")
    return min(default if requested is None else requested, maximum, HARD_RESPONSE_BYTES)


def limit_response(result: dict[str, Any], *, maximum: int,
                   requested: int | None = None, server_maximum: int = HARD_RESPONSE_BYTES) -> dict[str, Any]:
    """Keep control fields and a bounded structural prefix; never return oversized previews."""
    if not MIN_RESPONSE_BYTES <= maximum <= HARD_RESPONSE_BYTES:
        raise ValueError("invalid response budget")
    try:
        raw = encoded(result)
        normalized = json.loads(raw)
    except (ValueError, TypeError, OverflowError):
        normalized = {"status": "error", "tool": result.get("tool", "unknown"),
                      "error": {"code": "response_serialization_error",
                                "message": "Tool result could not be safely serialized."}}
        raw = encoded(normalized)
    metadata = {
        "truncated": False,
        "requested_max_bytes": requested,
        "effective_max_bytes": maximum,
        "server_max_bytes": server_maximum,
        "original_bytes": len(raw),
        "returned_bytes": maximum,  # reserve enough digits before trimming
    }
    normalized["response"] = metadata
    if _size(normalized) > maximum:
        metadata["truncated"] = True
        metadata["hint"] = (
            "Partial response. Increase response_max_bytes within server_max_bytes, "
            "or narrow/paginate the query. Never repeat a mutation; collect it with check_approval."
        )
        normalized = _fit(normalized, maximum)
    # The reserved maximum has at least as many digits as the actual size.
    for _ in range(4):
        size = _size(normalized)
        if normalized["response"]["returned_bytes"] == size:
            break
        normalized["response"]["returned_bytes"] = size
    if _size(normalized) > maximum:  # fail closed even if serialization changes
        raise ValueError("response limiter could not enforce its budget")
    return normalized
