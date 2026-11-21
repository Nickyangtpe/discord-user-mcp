"""MCP server entry point.

``python -m discord_user_mcp.server`` (or the ``discord-user-mcp`` script) starts
a stdio MCP server. stdout carries the protocol only; everything a human needs
to see goes to stderr.

Startup order matters:

1. Load and validate configuration. A bot token is rejected outright.
2. Build the HTTP client, audit log, approval store and approval console.
3. Optionally verify the token against ``GET /users/@me``.
4. Register every tool on FastMCP.
5. Bind the approval gate to the running event loop and start the console.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Iterable

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import __version__
from .api.client import DiscordClient
from .api.errors import ConfigError, DiscordUserMCPError
from .api.registry import get_registry
from .auth.credentials import startup_check
from .config import (
    Settings,
    apply_dashboard_settings,
    load_dashboard_settings,
    load_env_file,
)
from .runtime import AppContext, clear_context, execute_approved, set_context
from .security.approval import ApprovalManager, ApprovalStore
from .security.audit import AuditLogger
from .security.console import ApprovalConsole
from .security.permissions import Risk
from .tools.specs import TOOL_SPECS
from .utils.redact import configure_logging, register_secret

logger = logging.getLogger(__name__)

SERVER_NAME = "discord-user-mcp"

INSTRUCTIONS = """\
This server operates a real Discord **user** account through the Discord user HTTP API.

Read this before calling anything:

1. Read-only tools (risk "read") run immediately and cost nothing.
2. Every tool that changes Discord state (risk write/admin/destructive/sensitive) does NOT
   execute when you call it. It creates a pending approval and returns
   `status: "approval_required"` with an `approval_id`.
3. A human must approve that exact request in the local dashboard. You cannot approve,
   and there is no tool to do so. Never claim an operation succeeded because you called it.
4. Give the human `console.dashboard_url` from the response. It contains the request ID but
   never the dashboard access token; do not invent a port or ask for that token in chat.
5. Use `check_approval` with the `approval_id` to collect the result. Do not retry the original
   call: that only creates a second pending request.
6. High-risk operations (admin, destructive, sensitive) additionally require the operator to
   type APPROVE. `cancel_approval` only cancels pending requests.
7. This server uses a user token. Bot tokens are not supported and will be rejected.

Typical flow: list_my_guilds -> list_guild_channels -> list_messages -> send_message
(wait for approval) -> check_approval.
"""


def _annotations(risk: Risk, title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title,
        readOnlyHint=risk is Risk.READ,
        destructiveHint=risk in {Risk.DESTRUCTIVE, Risk.SENSITIVE},
        idempotentHint=risk is Risk.READ,
        openWorldHint=True,
    )


def build_server(context: AppContext) -> FastMCP:
    """Register every tool in :data:`TOOL_SPECS` on a fresh FastMCP instance."""
    mcp = FastMCP(
        name=SERVER_NAME,
        instructions=INSTRUCTIONS,
        log_level=context.settings.log_level.upper(),
    )
    for name in sorted(TOOL_SPECS):
        spec = TOOL_SPECS[name]
        if spec.wrapper is None:  # pragma: no cover - registration always sets it
            raise ConfigError(f"tool {name} has no implementation")
        mcp.add_tool(
            spec.wrapper,
            name=spec.name,
            title=spec.name.replace("_", " "),
            description=spec.description,
            annotations=_annotations(spec.risk, spec.name.replace("_", " ")),
        )
    logger.info("registered %d MCP tools", len(TOOL_SPECS))
    return mcp


def _banner(context: AppContext, *, auth_note: str | None) -> str:
    settings = context.settings
    lines = [
        "",
        f"  {SERVER_NAME} {__version__} - Discord user API MCP server",
        f"  tools: {len(TOOL_SPECS)}   read-only: {'yes' if settings.read_only else 'no'}"
        f"   approval TTL: {settings.approval.ttl_seconds}s",
        f"  token source: {settings.token_source}   fingerprint: {context.client.token_fingerprint()}",
        "  credential type: Discord USER token (bot tokens are not supported)",
    ]
    if context.identity:
        lines.append(
            "  authenticated as: "
            f"{context.identity.get('username')} ({context.identity.get('user_id')})"
        )
    if auth_note:
        lines.append(f"  note: {auth_note}")
    if context.console is not None and context.console.running:
        lines.append("")
        lines.append("  LOCAL DASHBOARD (status, approvals, activity and settings):")
        lines.append(f"    {context.console.url}")
        if settings.approval.write_token_file:
            lines.append(f"    token file: {context.console.token_file} (keep private)")
        else:
            lines.append(
                "    token file: disabled (DISCORD_MCP_CONSOLE_TOKEN_FILE=0); "
                "copy the URL above now"
            )
    else:
        lines.append("")
        lines.append(
            "  WARNING: the local dashboard is disabled. Every mutating tool will refuse to run."
        )
    lines.append("")
    return "\n".join(lines)


async def run(settings: Settings | None = None, *, mcp: FastMCP | None = None) -> None:
    """Start the stdio server. Kept importable so tests can drive it in-process."""
    settings = settings or Settings.from_env()
    # Dashboard changes made in a previous run win over .env defaults, except
    # that an environment-level read-only lock cannot be undone from the page.
    read_only_locked = settings.read_only
    try:
        stored = load_dashboard_settings(settings.state_dir)
    except ConfigError as exc:
        logger.warning("ignoring dashboard settings: %s", exc)
        stored = None
    if stored is not None:
        apply_dashboard_settings(settings, stored)
    if read_only_locked:
        settings.read_only = True
    configure_logging(settings.log_level)
    if settings.token is not None:
        register_secret(settings.token.get_secret_value())
    settings.ensure_dirs()

    client = DiscordClient(settings)
    audit = AuditLogger(settings.state_dir / "audit.jsonl", enabled=settings.audit_enabled)
    store = ApprovalStore(settings.state_dir / "approvals.sqlite3")
    approvals = ApprovalManager(settings, store, audit, executor=execute_approved)
    console = ApprovalConsole(settings, approvals, tool_count=len(TOOL_SPECS))
    console.read_only_locked = read_only_locked
    approvals.console = console

    context = AppContext(
        settings=settings,
        client=client,
        audit=audit,
        approvals=approvals,
        registry=get_registry(),
        tool_count=len(TOOL_SPECS),
        console=console,
    )
    console.context = context
    set_context(context)

    auth_note: str | None = None
    if settings.require_startup_auth_check:
        ok, identity, note = await startup_check(client)
        context.identity = identity
        auth_note = note if not ok else None
    else:
        auth_note = "startup token verification skipped (DISCORD_MCP_SKIP_AUTH_CHECK)"

    server = mcp or build_server(context)
    loop = asyncio.get_running_loop()
    approvals.bind_loop(loop)
    if settings.approval.console_enabled:
        console.start(loop)

    sys.stderr.write(_banner(context, auth_note=auth_note))
    sys.stderr.flush()

    try:
        await server.run_stdio_async()
    finally:
        console.stop()
        await client.close()
        clear_context()


def _print_check(settings: Settings, identity: dict[str, object] | None, note: str | None) -> None:
    registry = get_registry()
    stats = registry.stats()
    print(f"{SERVER_NAME} {__version__}")
    print(f"python: {sys.version.split()[0]}")
    print(f"state dir: {settings.state_dir}")
    print(f"api base: {settings.http.base_url}")
    print(f"token source: {settings.token_source}")
    print(f"tools: {len(TOOL_SPECS)}")
    print(
        "registry: {total} endpoints ({implemented} implemented, {documented} documented, "
        "{unsupported} unsupported)".format(
            total=stats["total"],
            implemented=stats["by_status"]["implemented"],
            documented=stats["by_status"]["documented"],
            unsupported=stats["by_status"]["unsupported"],
        )
    )
    if identity:
        print(f"authenticated as: {identity.get('username')} ({identity.get('user_id')})")
    if note:
        print(f"note: {note}")


async def _check(settings: Settings) -> int:
    configure_logging(settings.log_level)
    client = DiscordClient(settings)
    identity = None
    note = None
    try:
        if settings.require_startup_auth_check:
            try:
                ok, identity, note = await startup_check(client)
            except ConfigError as exc:
                print(f"FAILED: {exc}", file=sys.stderr)
                return 2
        _print_check(settings, identity, note)
        return 0
    finally:
        await client.close()


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=SERVER_NAME,
        description="MCP server for the Discord user API, with a mandatory human approval gate.",
    )
    parser.add_argument("--version", action="version", version=f"{SERVER_NAME} {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate configuration and the token, print a summary, then exit.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        # A .env next to the working directory is the documented way to configure
        # the server; real environment variables still take precedence.
        env_file = os.environ.get("DISCORD_MCP_ENV_FILE", ".env")
        if env_file.strip().lower() not in {"0", "off", "false", "no"}:
            load_env_file(env_file.strip() or ".env")
        settings = Settings.from_env()
        if settings.token is None:
            raise ConfigError(
                "No Discord user token configured. Set DISCORD_USER_TOKEN (or "
                "DISCORD_USER_TOKEN_FILE), or write the token to "
                f"{settings.state_dir / 'token'}."
            )
        if args.check:
            return asyncio.run(_check(settings))
        asyncio.run(run(settings))
        return 0
    except ConfigError as exc:
        print(f"{SERVER_NAME}: {exc}", file=sys.stderr)
        return 2
    except DiscordUserMCPError as exc:
        print(f"{SERVER_NAME}: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        return 130


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
