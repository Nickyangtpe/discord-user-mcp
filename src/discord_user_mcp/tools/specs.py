"""Tool metadata and the decorator that funnels every call through the gate."""

from __future__ import annotations

import functools
import inspect
import logging
import re
from dataclasses import dataclass, field
from typing import Annotated, Any, Awaitable, Callable

from pydantic import Field

from ..security.permissions import Risk
from ..utils.responses import HARD_RESPONSE_BYTES, MIN_RESPONSE_BYTES

logger = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


@dataclass
class ToolSpec:
    name: str
    description: str
    risk: Risk
    endpoint_id: str | None
    summary: str
    target_fields: tuple[str, ...] = ()
    func: Callable[..., Awaitable[Any]] | None = None
    wrapper: Callable[..., Awaitable[Any]] | None = None
    validate: Callable[[dict[str, Any]], None] | None = None
    requires_dry_run: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def render_summary(self, args: dict[str, Any]) -> str:
        def repl(match: re.Match[str]) -> str:
            value = args.get(match.group(1))
            if isinstance(value, (list, tuple)):
                return ", ".join(str(item) for item in value)[:120]
            if isinstance(value, dict):
                return "(object)"
            return str(value) if value is not None else "?"

        return _PLACEHOLDER.sub(repl, self.summary)[:300]

    def render_target(self, args: dict[str, Any]) -> str:
        parts = []
        for name in self.target_fields:
            if name in args and args[name] is not None:
                parts.append(f"{name}={args[name]}")
        return ", ".join(parts)[:300]


TOOL_SPECS: dict[str, ToolSpec] = {}


def define_tool(
    *,
    name: str,
    description: str,
    risk: Risk,
    endpoint_id: str | None,
    summary: str,
    target_fields: tuple[str, ...] = (),
    requires_dry_run: bool = False,
    validate: Callable[[dict[str, Any]], None] | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorate an async function as an MCP tool with a fixed risk level."""

    def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        if name in TOOL_SPECS:
            raise ValueError(f"duplicate tool name {name}")
        signature = inspect.signature(func)
        annotations = inspect.get_annotations(func, eval_str=True)
        signature = signature.replace(
            parameters=[parameter.replace(annotation=annotations.get(parameter.name, parameter.annotation))
                        for parameter in signature.parameters.values()],
            return_annotation=annotations.get("return", signature.return_annotation),
        )
        budget_type = Annotated[int | None, Field(
            ge=MIN_RESPONSE_BYTES, le=HARD_RESPONSE_BYTES, strict=True,
            description="Maximum UTF-8 JSON response bytes for this call. Omit for the server default. "
                        "Clamped to the operator's ceiling; includes tool envelope and response metadata.",
        )]
        signature = signature.replace(parameters=[*signature.parameters.values(), inspect.Parameter(
            "response_max_bytes", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=budget_type
        )])
        spec: ToolSpec

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            call_args = dict(bound.arguments)
            # Late import: runtime imports TOOL_SPECS, so a module-level import
            # here would be circular.
            from ..runtime import dispatch, get_context
            from ..utils.responses import limit_response, resolve_budget

            requested = call_args.pop("response_max_bytes")
            settings = get_context().settings
            try:
                maximum = resolve_budget(requested, default=settings.response_default_bytes,
                                         maximum=settings.response_max_bytes)
            except ValueError as exc:
                result = {"status": "error", "tool": name,
                          "error": {"code": "validation_error", "message": str(exc), "retryable": False}}
                return limit_response(result, maximum=min(settings.response_default_bytes, settings.response_max_bytes),
                                      server_maximum=settings.response_max_bytes)
            result = await dispatch(spec, call_args)
            return limit_response(result, maximum=maximum, requested=requested,
                                  server_maximum=settings.response_max_bytes)

        wrapper.__signature__ = signature  # type: ignore[attr-defined]
        wrapper.__annotations__ = {**annotations, "response_max_bytes": budget_type}

        spec = ToolSpec(
            name=name,
            description=description,
            risk=risk,
            endpoint_id=endpoint_id,
            summary=summary,
            target_fields=target_fields,
            func=func,
            wrapper=wrapper,
            validate=validate,
            requires_dry_run=requires_dry_run,
        )
        wrapper.__discord_tool__ = spec  # type: ignore[attr-defined]
        TOOL_SPECS[name] = spec
        return wrapper

    return decorator


READ = Risk.READ
WRITE = Risk.WRITE
DESTRUCTIVE = Risk.DESTRUCTIVE
SENSITIVE = Risk.SENSITIVE
ADMIN = Risk.ADMIN
