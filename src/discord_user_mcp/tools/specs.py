"""Tool metadata and the decorator that funnels every call through the gate."""

from __future__ import annotations

import functools
import inspect
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..security.permissions import Risk

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
        spec: ToolSpec

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            call_args = dict(bound.arguments)
            # Late import: runtime imports TOOL_SPECS, so a module-level import
            # here would be circular.
            from ..runtime import dispatch

            return await dispatch(spec, call_args)

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
