"""Discord User MCP - a Model Context Protocol server for the Discord user API.

The server exposes a curated set of Discord HTTP API operations, but every
operation that can change remote state is gated behind a human approval
console that runs inside this process.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.3.0"
