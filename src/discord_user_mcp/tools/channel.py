"""Channel, thread, invite and pin tools."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from ..security.permissions import Risk
from ._common import Snowflake, call, clean_params
from .specs import define_tool

APPROVAL = "Requires explicit human approval in the approval console."
REASON = Annotated[
    str | None, Field(max_length=512, description="Audit log reason shown to guild moderators")
]
ChannelType = Annotated[
    int,
    Field(
        ge=0,
        le=16,
        description="0 text, 2 voice, 4 category, 5 announcement, 13 stage, 15 forum, 16 media",
    ),
]


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------


@define_tool(
    name="get_channel",
    description=(
        "Get one channel, DM, group DM or thread by id: name, type, topic, parent, slowmode, "
        "recipients and thread metadata. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="channels.get",
    summary="Read channel {channel_id}",
    target_fields=("channel_id",),
)
async def get_channel(channel_id: Snowflake) -> Any:
    return await call("channels.get", path_params={"channel_id": channel_id})


@define_tool(
    name="list_private_channels",
    description="List the account's DM and group DM channels with their recipients. Read-only.",
    risk=Risk.READ,
    endpoint_id="channels.private.list",
    summary="List DM and group DM channels",
)
async def list_private_channels() -> Any:
    return await call("channels.private.list")


@define_tool(
    name="get_dm_channel",
    description=(
        "Get the existing DM channel with a user, if one has been opened. Read-only; use "
        "open_dm to create one."
    ),
    risk=Risk.READ,
    endpoint_id="channels.dm.get",
    summary="Find the DM channel with {user_id}",
    target_fields=("user_id",),
)
async def get_dm_channel(user_id: Snowflake) -> Any:
    return await call("channels.dm.get", path_params={"user_id": user_id})


@define_tool(
    name="list_channel_pins",
    description="List up to 50 pinned messages in a channel. Read-only.",
    risk=Risk.READ,
    endpoint_id="channels.pins.list",
    summary="List pinned messages in {channel_id}",
    target_fields=("channel_id",),
)
async def list_channel_pins(channel_id: Snowflake) -> Any:
    return await call("channels.pins.list", path_params={"channel_id": channel_id})


@define_tool(
    name="list_channel_invites",
    description="List invite codes for a channel. Read-only.",
    risk=Risk.READ,
    endpoint_id="channels.invites.list",
    summary="List invites for {channel_id}",
    target_fields=("channel_id",),
)
async def list_channel_invites(channel_id: Snowflake) -> Any:
    return await call("channels.invites.list", path_params={"channel_id": channel_id})


@define_tool(
    name="get_invite",
    description="Inspect an invite code: guild, channel, inviter and approximate member counts. Read-only.",
    risk=Risk.READ,
    endpoint_id="invites.get",
    summary="Inspect invite {invite_code}",
    target_fields=("invite_code",),
)
async def get_invite(invite_code: str, with_counts: bool = True) -> Any:
    return await call(
        "invites.get", path_params={"invite_code": invite_code}, params={"with_counts": with_counts}
    )


# --------------------------------------------------------------------------
# Channel management
# --------------------------------------------------------------------------


@define_tool(
    name="create_guild_channel",
    description=(
        "Create a guild channel, category, forum, voice or stage channel. Returns the new "
        "channel object. " + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="channels.create",
    summary="Create a channel in guild {guild_id}",
    target_fields=("guild_id", "name"),
    requires_dry_run=True,
)
async def create_guild_channel(
    guild_id: Snowflake,
    name: Annotated[str, Field(min_length=1, max_length=100)],
    type: ChannelType = 0,
    parent_id: Snowflake | None = None,
    topic: Annotated[str | None, Field(max_length=1024)] = None,
    nsfw: bool = False,
    position: Annotated[int | None, Field(ge=0)] = None,
    rate_limit_per_user: Annotated[int, Field(ge=0, le=21600)] = 0,
    permission_overwrites: Annotated[
        list[dict] | None, Field(description="Array of overwrite objects")
    ] = None,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "name": name,
            "type": type,
            "parent_id": parent_id,
            "topic": topic,
            "nsfw": nsfw,
            "position": position,
            "rate_limit_per_user": rate_limit_per_user,
            "permission_overwrites": permission_overwrites,
        }
    )
    return await call(
        "channels.create",
        path_params={"guild_id": guild_id},
        payload=payload,
        audit_reason=audit_reason,
    )


@define_tool(
    name="update_channel",
    description=(
        "Change a channel, thread or group DM: name, topic, type, parent, slowmode, NSFW flag, "
        "archive/lock state, icon or permission overwrites. Only supplied fields change. "
        + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="channels.update",
    summary="Update channel {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def update_channel(
    channel_id: Snowflake,
    name: Annotated[str | None, Field(min_length=1, max_length=100)] = None,
    topic: Annotated[str | None, Field(max_length=1024)] = None,
    type: ChannelType | None = None,
    position: Annotated[int | None, Field(ge=0)] = None,
    nsfw: bool | None = None,
    rate_limit_per_user: Annotated[int | None, Field(ge=0, le=21600)] = None,
    parent_id: Snowflake | None = None,
    archived: bool | None = None,
    locked: bool | None = None,
    invitable: bool | None = None,
    auto_archive_duration: Annotated[int | None, Field(description="60, 1440, 4320 or 10080")] = None,
    permission_overwrites: Annotated[list[dict] | None, Field(description="Replacement overwrite array")] = None,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "name": name,
            "topic": topic,
            "type": type,
            "position": position,
            "nsfw": nsfw,
            "rate_limit_per_user": rate_limit_per_user,
            "parent_id": parent_id,
            "archived": archived,
            "locked": locked,
            "invitable": invitable,
            "auto_archive_duration": auto_archive_duration,
            "permission_overwrites": permission_overwrites,
        }
    )
    if not payload:
        from ..api.errors import ValidationError

        raise ValidationError("Provide at least one channel field to change")
    return await call(
        "channels.update",
        path_params={"channel_id": channel_id},
        payload=payload,
        audit_reason=audit_reason,
    )


@define_tool(
    name="delete_channel",
    description=(
        "Delete a guild channel or thread. Messages in it become inaccessible. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="channels.delete",
    summary="Delete channel {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def delete_channel(channel_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("channels.delete", path_params={"channel_id": channel_id})


@define_tool(
    name="reorder_channels",
    description=(
        "Change channel positions (drag order) and parents. Pass a list of "
        "{id, position, parent_id?, lock_permissions?} objects. " + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="channels.positions",
    summary="Reorder channels in guild {guild_id}",
    target_fields=("guild_id",),
    requires_dry_run=True,
)
async def reorder_channels(
    guild_id: Snowflake,
    positions: Annotated[list[dict], Field(min_length=1, max_length=100)],
    dry_run: bool = False,
) -> Any:
    return await call(
        "channels.positions", path_params={"guild_id": guild_id}, payload=positions
    )


@define_tool(
    name="update_channel_permissions",
    description=(
        "Create or replace a permission overwrite for a role (type 0) or member (type 1). "
        "allow/deny are permission bitfields as decimal strings. " + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="channels.permissions.set",
    summary="Set permissions on {channel_id} for {overwrite_id}",
    target_fields=("channel_id", "overwrite_id"),
    requires_dry_run=True,
)
async def update_channel_permissions(
    channel_id: Snowflake,
    overwrite_id: Snowflake,
    type: Annotated[int, Field(ge=0, le=1, description="0 role, 1 member")],
    allow: Annotated[str, Field(description="Allowed permission bitfield")] = "0",
    deny: Annotated[str, Field(description="Denied permission bitfield")] = "0",
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "channels.permissions.set",
        path_params={"channel_id": channel_id, "overwrite_id": overwrite_id},
        payload={"type": type, "allow": allow, "deny": deny},
        audit_reason=audit_reason,
    )


@define_tool(
    name="delete_channel_permission",
    description="Delete a permission overwrite from a channel. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="channels.permissions.delete",
    summary="Delete the overwrite for {overwrite_id} on {channel_id}",
    target_fields=("channel_id", "overwrite_id"),
    requires_dry_run=True,
)
async def delete_channel_permission(
    channel_id: Snowflake,
    overwrite_id: Snowflake,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    return await call(
        "channels.permissions.delete",
        path_params={"channel_id": channel_id, "overwrite_id": overwrite_id},
        audit_reason=audit_reason,
    )


@define_tool(
    name="create_channel_invite",
    description=(
        "Create an invite code for a channel. max_age is seconds (0 = never expires). " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="channels.invites.create",
    summary="Create an invite for {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def create_channel_invite(
    channel_id: Snowflake,
    max_age: Annotated[int, Field(ge=0, le=604800, description="Seconds until expiry; 0 = never")] = 86400,
    max_uses: Annotated[int, Field(ge=0, le=100, description="0 = unlimited")] = 0,
    temporary: bool = False,
    unique: bool = False,
    audit_reason: REASON = None,
    dry_run: bool = False,
) -> Any:
    payload = {
        "max_age": max_age,
        "max_uses": max_uses,
        "temporary": temporary,
        "unique": unique,
    }
    return await call(
        "channels.invites.create",
        path_params={"channel_id": channel_id},
        payload=payload,
        audit_reason=audit_reason,
    )


@define_tool(
    name="delete_invite",
    description="Revoke an invite code so it can no longer be used. " + APPROVAL,
    risk=Risk.DESTRUCTIVE,
    endpoint_id="invites.delete",
    summary="Revoke invite {invite_code}",
    target_fields=("invite_code",),
    requires_dry_run=True,
)
async def delete_invite(
    invite_code: str, audit_reason: REASON = None, dry_run: bool = False
) -> Any:
    return await call(
        "invites.delete", path_params={"invite_code": invite_code}, audit_reason=audit_reason
    )


@define_tool(
    name="pin_message",
    description="Pin a message in a channel. Requires MANAGE_MESSAGES in guilds. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="channels.pins.pin",
    summary="Pin message {message_id} in {channel_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def pin_message(channel_id: Snowflake, message_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "channels.pins.pin", path_params={"channel_id": channel_id, "message_id": message_id}
    )


@define_tool(
    name="unpin_message",
    description="Unpin a message. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="channels.pins.unpin",
    summary="Unpin message {message_id} in {channel_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def unpin_message(channel_id: Snowflake, message_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "channels.pins.unpin", path_params={"channel_id": channel_id, "message_id": message_id}
    )


@define_tool(
    name="trigger_typing",
    description=(
        "Show the typing indicator in a channel. It is still a remote state change, so it goes "
        "through the approval gate like every other write. " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="channels.typing",
    summary="Trigger typing in {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def trigger_typing(channel_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("channels.typing", path_params={"channel_id": channel_id})


@define_tool(
    name="mark_channel_read",
    description=(
        "Move the account's read state in a channel up to a message id, clearing unread badges. "
        + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="channels.ack",
    summary="Mark {channel_id} read up to {message_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def mark_channel_read(
    channel_id: Snowflake, message_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "channels.ack",
        path_params={"channel_id": channel_id, "message_id": message_id},
        payload={"manual": True, "mention_count": 0},
    )


# --------------------------------------------------------------------------
# Threads
# --------------------------------------------------------------------------


@define_tool(
    name="start_thread_from_message",
    description=(
        "Start a public thread whose first message is an existing message. " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="channels.threads.create_from_message",
    summary="Start a thread from message {message_id} in {channel_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def start_thread_from_message(
    channel_id: Snowflake,
    message_id: Snowflake,
    name: Annotated[str, Field(min_length=1, max_length=100)],
    auto_archive_duration: Annotated[int, Field(description="60, 1440, 4320 or 10080")] = 1440,
    rate_limit_per_user: Annotated[int, Field(ge=0, le=21600)] = 0,
    dry_run: bool = False,
) -> Any:
    return await call(
        "channels.threads.create_from_message",
        path_params={"channel_id": channel_id, "message_id": message_id},
        payload={
            "name": name,
            "auto_archive_duration": auto_archive_duration,
            "rate_limit_per_user": rate_limit_per_user,
        },
    )


@define_tool(
    name="create_thread",
    description=(
        "Create a standalone thread or forum post. For forum/media channels include "
        "message_content (and optional attachments). type 11 = public thread, 12 = private thread. "
        + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="channels.threads.create",
    summary="Create a thread in {channel_id}",
    target_fields=("channel_id", "name"),
    requires_dry_run=True,
)
async def create_thread(
    channel_id: Snowflake,
    name: Annotated[str, Field(min_length=1, max_length=100)],
    type: Annotated[int, Field(ge=10, le=12)] = 11,
    auto_archive_duration: Annotated[int, Field(description="60, 1440, 4320 or 10080")] = 1440,
    rate_limit_per_user: Annotated[int, Field(ge=0, le=21600)] = 0,
    invitable: bool = True,
    message_content: Annotated[
        str | None, Field(max_length=2000, description="First message (required for forum posts)")
    ] = None,
    applied_tags: Annotated[list[str] | None, Field(description="Forum tag ids")] = None,
    dry_run: bool = False,
) -> Any:
    payload: dict[str, Any] = {
        "name": name,
        "type": type,
        "auto_archive_duration": auto_archive_duration,
        "rate_limit_per_user": rate_limit_per_user,
        "invitable": invitable,
    }
    if message_content is not None:
        payload["message"] = {"content": message_content}
    if applied_tags:
        payload["applied_tags"] = applied_tags
    return await call(
        "channels.threads.create", path_params={"channel_id": channel_id}, payload=payload
    )


@define_tool(
    name="list_active_threads",
    description="List active threads in a channel. Read-only.",
    risk=Risk.READ,
    endpoint_id="channels.threads.active",
    summary="List active threads in {channel_id}",
    target_fields=("channel_id",),
)
async def list_active_threads(channel_id: Snowflake) -> Any:
    return await call("channels.threads.active", path_params={"channel_id": channel_id})


@define_tool(
    name="list_archived_threads",
    description="Page through archived public threads of a channel. Read-only.",
    risk=Risk.READ,
    endpoint_id="channels.threads.archived",
    summary="List archived threads in {channel_id}",
    target_fields=("channel_id",),
)
async def list_archived_threads(
    channel_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=100)] = 50,
    before: Annotated[str | None, Field(description="ISO8601 archive timestamp cursor")] = None,
) -> Any:
    return await call(
        "channels.threads.archived",
        path_params={"channel_id": channel_id},
        params=clean_params({"limit": limit, "before": before}),
    )


@define_tool(
    name="search_threads",
    description=(
        "Search threads in a forum/media channel by name, tag or archive state. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="channels.threads.search",
    summary="Search threads in {channel_id}",
    target_fields=("channel_id",),
)
async def search_threads(
    channel_id: Snowflake,
    name: Annotated[str | None, Field(max_length=100)] = None,
    tag: Annotated[str | None, Field(description="Forum tag id")] = None,
    archived: bool | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 25,
    offset: Annotated[int, Field(ge=0)] = 0,
    sort_by: Annotated[str | None, Field(description="last_message_time or creation_time")] = None,
    sort_order: Annotated[str | None, Field(description="asc or desc")] = None,
) -> Any:
    return await call(
        "channels.threads.search",
        path_params={"channel_id": channel_id},
        params=clean_params(
            {
                "name": name,
                "tag": tag,
                "archived": archived,
                "limit": limit,
                "offset": offset,
                "sort_by": sort_by,
                "sort_order": sort_order,
            }
        ),
    )


@define_tool(
    name="list_thread_members",
    description="List members of a thread. Read-only.",
    risk=Risk.READ,
    endpoint_id="channels.threads.members.list",
    summary="List members of thread {channel_id}",
    target_fields=("channel_id",),
)
async def list_thread_members(
    channel_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=100)] = 100,
    after: Snowflake | None = None,
    with_member: bool = True,
) -> Any:
    return await call(
        "channels.threads.members.list",
        path_params={"channel_id": channel_id},
        params=clean_params({"limit": limit, "after": after, "with_member": with_member}),
    )


@define_tool(
    name="join_thread",
    description="Join a thread so it appears in the account's thread list. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="channels.threads.join",
    summary="Join thread {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def join_thread(channel_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("channels.threads.join", path_params={"channel_id": channel_id})


@define_tool(
    name="leave_thread",
    description="Leave a thread. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="channels.threads.leave",
    summary="Leave thread {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def leave_thread(channel_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("channels.threads.leave", path_params={"channel_id": channel_id})


@define_tool(
    name="add_thread_member",
    description="Add another user to a thread. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="channels.threads.members.add",
    summary="Add {user_id} to thread {channel_id}",
    target_fields=("channel_id", "user_id"),
    requires_dry_run=True,
)
async def add_thread_member(
    channel_id: Snowflake, user_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "channels.threads.members.add",
        path_params={"channel_id": channel_id, "user_id": user_id},
    )


@define_tool(
    name="remove_thread_member",
    description="Remove a user from a thread. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="channels.threads.members.remove",
    summary="Remove {user_id} from thread {channel_id}",
    target_fields=("channel_id", "user_id"),
    requires_dry_run=True,
)
async def remove_thread_member(
    channel_id: Snowflake, user_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "channels.threads.members.remove",
        path_params={"channel_id": channel_id, "user_id": user_id},
    )
