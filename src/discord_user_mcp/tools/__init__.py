"""MCP tool definitions.

Importing this package registers every tool in :data:`discord_user_mcp.tools.specs.TOOL_SPECS`.
"""

from __future__ import annotations

from . import (  # noqa: F401 - imported for registration side effects
    applications,
    channel,
    dm,
    events,
    extended,
    guild,
    message,
    settings,
    system,
    user,
)
from .specs import TOOL_SPECS, ToolSpec

__all__ = ["TOOL_SPECS", "ToolSpec"]
