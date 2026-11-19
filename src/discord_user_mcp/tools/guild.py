"""Guild, member, role, ban and audit-log tools."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field, ValidationError as PydanticValidationError

from ..security.permissions import Risk
from ._common import Snowflake, call, clean_params
from .specs import define_tool

APPROVAL = "Requires explicit human approval in the approval console."
REASON = Annotated[
    str | None, Field(max_length=512, description="Audit log reason shown to guild moderators")
]
PermissionBits = Annotated[
    str | int | None, Field(description="Permission bitfield as a decimal string")
]


class RolePosition(BaseModel):
    """One move in a role reorder request."""

    id: Snowflake
    position: Annotated[int, Field(ge=0, description="New sorting position")]


def _validate_role_positions(args: dict[str, Any]) -> None:
    """Reject a malformed reorder before a human is asked to approve it."""
    from ..api.errors import ValidationError

    for index, move in enumerate(args.get("positions") or []):
        data = move.model_dump() if isinstance(move, RolePosition) else move
        try:
            RolePosition(**data)
        except PydanticValidationError as exc:
            raise ValidationError(f"positions[{index}] is invalid: {exc}") from exc


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------


@define_tool(
    name="list_my_guilds",
    description=(
        "List every guild the account belongs to, with the account's permissions and nickname "
        "in each. Read-only. Start here to discover guild ids."
    ),
    risk=Risk.READ,
    endpoint_id="guilds.list_mine",
    summary="List the account's guilds",
)
async def list_my_guilds() -> Any:
    return await call("guilds.list_mine")


@define_tool(
    name="get_guild",
    description="Get a guild's settings, features, channels summary and member counts. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.get",
    summary="Read guild {guild_id}",
    target_fields=("guild_id",),
)
async def get_guild(
    guild_id: Snowflake,
    with_counts: Annotated[bool, Field(description="Include approximate member counts")] = True,
) -> Any:
    return await call("guilds.get", path_params={"guild_id": guild_id}, params={"with_counts": with_counts})


@define_tool(
    name="get_guild_preview",
    description="Get the public preview of a discoverable guild (no membership required). Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.preview",
    summary="Preview guild {guild_id}",
    target_fields=("guild_id",),
)
async def get_guild_preview(guild_id: Snowflake) -> Any:
    return await call("guilds.preview", path_params={"guild_id": guild_id})


@define_tool(
    name="list_guild_channels",
    description=(
        "List every channel and thread in a guild with ids, names, types, positions and parent "
        "categories. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="guilds.channels.list",
    summary="List channels in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_channels(guild_id: Snowflake) -> Any:
    return await call("guilds.channels.list", path_params={"guild_id": guild_id})


@define_tool(
    name="list_guild_members",
    description=(
        "Page through guild members. Discord returns at most 1000 per call; use the returned "
        "next_after id as `after` to continue. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="guilds.members.list",
    summary="List members of guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_members(
    guild_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    after: Snowflake | None = None,
) -> Any:
    members = await call(
        "guilds.members.list",
        path_params={"guild_id": guild_id},
        params=clean_params({"limit": limit, "after": after}),
    )
    if isinstance(members, list) and len(members) == limit:
        return {"members": members, "next_after": members[-1].get("user", {}).get("id")}
    return {"members": members, "next_after": None}


@define_tool(
    name="get_guild_member",
    description="Get one guild member: nickname, roles, join date, timeout and flags. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.members.get",
    summary="Read member {user_id} in guild {guild_id}",
    target_fields=("guild_id", "user_id"),
)
async def get_guild_member(guild_id: Snowflake, user_id: Snowflake) -> Any:
    return await call(
        "guilds.members.get", path_params={"guild_id": guild_id, "user_id": user_id}
    )


@define_tool(
    name="get_my_guild_member",
    description="Get the account's own member object (roles, nickname) in a guild. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.members.me",
    summary="Read the account's membership in guild {guild_id}",
    target_fields=("guild_id",),
)
async def get_my_guild_member(guild_id: Snowflake) -> Any:
    return await call("guilds.members.me", path_params={"guild_id": guild_id})


@define_tool(
    name="search_guild_members",
    description=(
        "Search guild members by username or nickname prefix. Read-only. Useful in large guilds "
        "where listing everyone is expensive."
    ),
    risk=Risk.READ,
    endpoint_id="guilds.members.search",
    summary="Search members of guild {guild_id} for {query}",
    target_fields=("guild_id", "query"),
)
async def search_guild_members(
    guild_id: Snowflake,
    query: Annotated[str, Field(min_length=1, max_length=100)],
    limit: Annotated[int, Field(ge=1, le=1000)] = 50,
) -> Any:
    return await call(
        "guilds.members.search",
        path_params={"guild_id": guild_id},
        payload={"query": query, "limit": limit},
    )


@define_tool(
    name="list_guild_roles",
    description="List a guild's roles with ids, colours, permissions and hierarchy position. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.roles.list",
    summary="List roles in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_roles(guild_id: Snowflake) -> Any:
    return await call("guilds.roles.list", path_params={"guild_id": guild_id})


@define_tool(
    name="get_guild_role",
    description="Get one guild role by id. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.roles.get",
    summary="Read role {role_id} in guild {guild_id}",
    target_fields=("guild_id", "role_id"),
)
async def get_guild_role(guild_id: Snowflake, role_id: Snowflake) -> Any:
    return await call(
        "guilds.roles.get", path_params={"guild_id": guild_id, "role_id": role_id}
    )


@define_tool(
    name="list_guild_bans",
    description="List banned users with ban reasons. Requires BAN_MEMBERS. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.bans.list",
    summary="List bans in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_bans(
    guild_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    after: Snowflake | None = None,
) -> Any:
    return await call(
        "guilds.bans.list",
        path_params={"guild_id": guild_id},
        params=clean_params({"limit": limit, "after": after}),
    )


@define_tool(
    name="list_guild_invites",
    description="List invites created for a guild. Requires MANAGE_GUILD. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.invites.list",
    summary="List invites in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_invites(guild_id: Snowflake) -> Any:
    return await call("guilds.invites.list", path_params={"guild_id": guild_id})


@define_tool(
    name="get_guild_audit_log",
    description=(
        "Read the guild audit log (who changed what). Requires VIEW_AUDIT_LOG. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="guilds.audit_log",
    summary="Read the audit log of guild {guild_id}",
    target_fields=("guild_id",),
)
async def get_guild_audit_log(
    guild_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=100)] = 50,
    before: Snowflake | None = None,
    user_id: Snowflake | None = None,
    action_type: Annotated[int | None, Field(ge=1)] = None,
) -> Any:
    return await call(
        "guilds.audit_log",
        path_params={"guild_id": guild_id},
        params=clean_params(
            {"limit": limit, "before": before, "user_id": user_id, "action_type": action_type}
        ),
    )


@define_tool(
    name="list_guild_emojis",
    description="List a guild's custom emoji. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.emojis.list",
    summary="List emoji in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_emojis(guild_id: Snowflake) -> Any:
    return await call("guilds.emojis.list", path_params={"guild_id": guild_id})


@define_tool(
    name="list_guild_stickers",
    description="List a guild's stickers. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.stickers.list",
    summary="List stickers in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_stickers(guild_id: Snowflake) -> Any:
    return await call("guilds.stickers.list", path_params={"guild_id": guild_id})


@define_tool(
    name="list_guild_active_threads",
    description="List active threads across a guild. Read-only.",
    risk=Risk.READ,
    endpoint_id="guilds.threads.active",
    summary="List active threads in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_guild_active_threads(guild_id: Snowflake) -> Any:
    return await call("guilds.threads.active", path_params={"guild_id": guild_id})


# --------------------------------------------------------------------------
# Guild settings
# --------------------------------------------------------------------------


@define_tool(
    name="update_guild",
    description=(
        "Change guild settings: name, description, icon/banner, AFK channel, system channel, "
        "verification level or explicit-content filter. Only supplied fields change. "
        + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="guilds.update",
    summary="Update settings of guild {guild_id}",
    target_fields=("guild_id",),
    requires_dry_run=True,
)
async def update_guild(
    guild_id: Snowflake,
    name: Annotated[str | None, Field(min_length=2, max_length=100)] = None,
    description: Annotated[str | None, Field(max_length=300)] = None,
    icon: Annotated[str | None, Field(description="Data URI image, or null to remove")] = None,
    banner: Annotated[str | None, Field(description="Data URI image, or null to remove")] = None,
    afk_channel_id: Snowflake | None = None,
    afk_timeout: Annotated[int | None, Field(ge=60, le=3600)] = None,
    system_channel_id: Snowflake | None = None,
    verification_level: Annotated[int | None, Field(ge=0, le=4)] = None,
    explicit_content_filter: Annotated[int | None, Field(ge=0, le=2)] = None,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "name": name,
            "description": description,
            "icon": icon,
            "banner": banner,
            "afk_channel_id": afk_channel_id,
            "afk_timeout": afk_timeout,
            "system_channel_id": system_channel_id,
            "verification_level": verification_level,
            "explicit_content_filter": explicit_content_filter,
        }
    )
    if not payload:
        from ..api.errors import ValidationError

        raise ValidationError("Provide at least one guild field to change")
    return await call(
        "guilds.update", path_params={"guild_id": guild_id}, payload=payload, audit_reason=audit_reason
    )


@define_tool(
    name="leave_guild",
    description=(
        "Leave a guild. The account loses access to its channels immediately. "
        "Requires ownership transfer first if the account owns the guild. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="guilds.leave",
    summary="Leave guild {guild_id}",
    target_fields=("guild_id",),
    requires_dry_run=True,
)
async def leave_guild(guild_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("guilds.leave", path_params={"guild_id": guild_id})


# --------------------------------------------------------------------------
# Members
# --------------------------------------------------------------------------


@define_tool(
    name="update_guild_member",
    description=(
        "Change another member: nickname, role list, server mute/deafen, or timeout until a "
        "timestamp. Requires the matching permissions. " + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="guilds.members.update",
    summary="Update member {user_id} in guild {guild_id}",
    target_fields=("guild_id", "user_id"),
    requires_dry_run=True,
)
async def update_guild_member(
    guild_id: Snowflake,
    user_id: Snowflake,
    nick: Annotated[str | None, Field(max_length=32)] = None,
    roles: Annotated[list[str] | None, Field(description="Full replacement role id list")] = None,
    mute: bool | None = None,
    deaf: bool | None = None,
    communication_disabled_until: Annotated[
        str | None, Field(description="ISO8601 timeout end, or null to clear")
    ] = None,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "nick": nick,
            "roles": roles,
            "mute": mute,
            "deaf": deaf,
            "communication_disabled_until": communication_disabled_until,
        }
    )
    if not payload:
        from ..api.errors import ValidationError

        raise ValidationError("Provide at least one member field to change")
    return await call(
        "guilds.members.update",
        path_params={"guild_id": guild_id, "user_id": user_id},
        payload=payload,
        audit_reason=audit_reason,
    )


@define_tool(
    name="set_my_guild_nickname",
    description="Change the account's own nickname in a guild. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="guilds.members.nick",
    summary="Set own nickname in guild {guild_id}",
    target_fields=("guild_id",),
    requires_dry_run=True,
)
async def set_my_guild_nickname(
    guild_id: Snowflake,
    nick: Annotated[str | None, Field(max_length=32, description="New nickname, or null")],
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.members.nick", path_params={"guild_id": guild_id}, payload={"nick": nick}
    )


@define_tool(
    name="kick_guild_member",
    description="Kick a member from a guild. They can rejoin with an invite. " + APPROVAL,
    risk=Risk.DESTRUCTIVE,
    endpoint_id="guilds.members.kick",
    summary="Kick {user_id} from guild {guild_id}",
    target_fields=("guild_id", "user_id"),
    requires_dry_run=True,
)
async def kick_guild_member(
    guild_id: Snowflake,
    user_id: Snowflake,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.members.kick",
        path_params={"guild_id": guild_id, "user_id": user_id},
        audit_reason=audit_reason,
    )


@define_tool(
    name="add_role_to_member",
    description="Give a role to a member. Requires MANAGE_ROLES and role hierarchy. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="guilds.members.roles.add",
    summary="Add role {role_id} to {user_id} in guild {guild_id}",
    target_fields=("guild_id", "user_id", "role_id"),
    requires_dry_run=True,
)
async def add_role_to_member(
    guild_id: Snowflake,
    user_id: Snowflake,
    role_id: Snowflake,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.members.roles.add",
        path_params={"guild_id": guild_id, "user_id": user_id, "role_id": role_id},
        audit_reason=audit_reason,
    )


@define_tool(
    name="remove_role_from_member",
    description="Take a role away from a member. Requires MANAGE_ROLES. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="guilds.members.roles.remove",
    summary="Remove role {role_id} from {user_id} in guild {guild_id}",
    target_fields=("guild_id", "user_id", "role_id"),
    requires_dry_run=True,
)
async def remove_role_from_member(
    guild_id: Snowflake,
    user_id: Snowflake,
    role_id: Snowflake,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.members.roles.remove",
        path_params={"guild_id": guild_id, "user_id": user_id, "role_id": role_id},
        audit_reason=audit_reason,
    )


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------


@define_tool(
    name="create_guild_role",
    description="Create a guild role with a name, colour and permissions. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="guilds.roles.create",
    summary="Create a role in guild {guild_id}",
    target_fields=("guild_id",),
    requires_dry_run=True,
)
async def create_guild_role(
    guild_id: Snowflake,
    name: Annotated[str, Field(min_length=1, max_length=100)],
    permissions: PermissionBits = None,
    color: Annotated[int, Field(ge=0, le=0xFFFFFF)] = 0,
    hoist: bool = False,
    mentionable: bool = False,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "name": name,
            "permissions": permissions,
            "color": color,
            "hoist": hoist,
            "mentionable": mentionable,
        }
    )
    return await call(
        "guilds.roles.create",
        path_params={"guild_id": guild_id},
        payload=payload,
        audit_reason=audit_reason,
    )


@define_tool(
    name="update_guild_role",
    description="Change a role's name, colour, permissions, hoist or mentionable flag. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="guilds.roles.update",
    summary="Update role {role_id} in guild {guild_id}",
    target_fields=("guild_id", "role_id"),
    requires_dry_run=True,
)
async def update_guild_role(
    guild_id: Snowflake,
    role_id: Snowflake,
    name: Annotated[str | None, Field(min_length=1, max_length=100)] = None,
    permissions: PermissionBits = None,
    color: Annotated[int | None, Field(ge=0, le=0xFFFFFF)] = None,
    hoist: bool | None = None,
    mentionable: bool | None = None,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "name": name,
            "permissions": permissions,
            "color": color,
            "hoist": hoist,
            "mentionable": mentionable,
        }
    )
    if not payload:
        from ..api.errors import ValidationError

        raise ValidationError("Provide at least one role field to change")
    return await call(
        "guilds.roles.update",
        path_params={"guild_id": guild_id, "role_id": role_id},
        payload=payload,
        audit_reason=audit_reason,
    )


@define_tool(
    name="reorder_guild_roles",
    description=(
        "Change the hierarchy position of one or more roles in a guild. Discord only applies "
        "moves below the account's highest role; a role above it is left where it is. "
        + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="guilds.guild.roles.patch",
    summary="Reorder roles in guild {guild_id}",
    target_fields=("guild_id",),
    requires_dry_run=True,
    validate=_validate_role_positions,
)
async def reorder_guild_roles(
    guild_id: Snowflake,
    positions: Annotated[
        list[RolePosition],
        Field(
            min_length=1,
            max_length=50,
            description='Ordered moves: [{"id": "<role id>", "position": 3}, ...]',
        ),
    ],
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    moves = [
        move.model_dump() if isinstance(move, RolePosition) else RolePosition(**move).model_dump()
        for move in positions
    ]
    return await call(
        "guilds.guild.roles.patch",
        path_params={"guild_id": guild_id},
        payload=moves,
        audit_reason=audit_reason,
    )


@define_tool(
    name="delete_guild_role",
    description=(
        "Delete a role. Members lose it immediately and channel overwrites that reference it "
        "remain. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="guilds.roles.delete",
    summary="Delete role {role_id} in guild {guild_id}",
    target_fields=("guild_id", "role_id"),
    requires_dry_run=True,
)
async def delete_guild_role(
    guild_id: Snowflake,
    role_id: Snowflake,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.roles.delete",
        path_params={"guild_id": guild_id, "role_id": role_id},
        audit_reason=audit_reason,
    )


# --------------------------------------------------------------------------
# Bans
# --------------------------------------------------------------------------


@define_tool(
    name="ban_guild_member",
    description=(
        "Ban a user from a guild, optionally deleting recent messages. Requires BAN_MEMBERS. "
        + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="guilds.bans.create",
    summary="Ban {user_id} from guild {guild_id}",
    target_fields=("guild_id", "user_id"),
    requires_dry_run=True,
)
async def ban_guild_member(
    guild_id: Snowflake,
    user_id: Snowflake,
    delete_message_seconds: Annotated[
        int, Field(ge=0, le=604800, description="Delete messages from the last N seconds")
    ] = 0,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.bans.create",
        path_params={"guild_id": guild_id, "user_id": user_id},
        payload={"delete_message_seconds": delete_message_seconds},
        audit_reason=audit_reason,
    )


@define_tool(
    name="unban_guild_member",
    description="Lift a guild ban. Requires BAN_MEMBERS. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="guilds.bans.delete",
    summary="Unban {user_id} in guild {guild_id}",
    target_fields=("guild_id", "user_id"),
    requires_dry_run=True,
)
async def unban_guild_member(
    guild_id: Snowflake,
    user_id: Snowflake,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "guilds.bans.delete",
        path_params={"guild_id": guild_id, "user_id": user_id},
        audit_reason=audit_reason,
    )
