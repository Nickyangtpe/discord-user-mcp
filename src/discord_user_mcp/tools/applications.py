"""Slash-command discovery tools.

These only read the application command index. Registering or editing
application commands requires an application (bot) account, which this
project deliberately does not support.
"""

from __future__ import annotations

from typing import Any

from ..security.permissions import Risk
from ._common import Snowflake, call
from .specs import define_tool


@define_tool(
    name="get_guild_application_commands",
    description=(
        "List the slash commands available to the account in a guild, including each "
        "command's id, application, description and options. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="applications.commands.guild",
    summary="List slash commands available in guild {guild_id}",
    target_fields=("guild_id",),
)
async def get_guild_application_commands(guild_id: Snowflake) -> Any:
    return await call("applications.commands.guild", path_params={"guild_id": guild_id})


@define_tool(
    name="get_user_application_commands",
    description=(
        "List the slash commands available to the account in DMs and user-installed apps. "
        "Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="applications.commands.user",
    summary="List the account's user-installable slash commands",
)
async def get_user_application_commands() -> Any:
    return await call("applications.commands.user")


__all__ = ["get_guild_application_commands", "get_user_application_commands"]
