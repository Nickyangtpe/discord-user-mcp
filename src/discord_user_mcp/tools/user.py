"""User, profile, note and relationship tools."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from ..security.permissions import Risk
from ._common import Snowflake, call, clean_params
from .specs import define_tool

APPROVAL = "Requires explicit human approval in the approval console."


# --------------------------------------------------------------------------
# Identity and profiles
# --------------------------------------------------------------------------


@define_tool(
    name="get_current_user",
    description=(
        "Return the Discord account this server is authenticated as, plus cached identity "
        "information from startup. Read-only; safe to call first to verify the connection."
    ),
    risk=Risk.READ,
    endpoint_id="users.me",
    summary="Read the authenticated account",
)
async def get_current_user() -> Any:
    return await call("users.me")


@define_tool(
    name="get_user",
    description=(
        "Get a user's account object by id (username, display name, avatar, flags). "
        "Read-only. For bio, banner and mutuals use get_user_profile."
    ),
    risk=Risk.READ,
    endpoint_id="users.get",
    summary="Read user {user_id}",
    target_fields=("user_id",),
)
async def get_user(user_id: Snowflake) -> Any:
    return await call("users.get", path_params={"user_id": user_id})


@define_tool(
    name="get_user_profile",
    description=(
        "Get a user's full profile: bio, banner, accent colour, badges, connections, mutual "
        "guilds and mutual friends. Read-only. Pass guild_id to include guild-specific member "
        "data and roles."
    ),
    risk=Risk.READ,
    endpoint_id="users.profile",
    summary="Read the profile of {user_id}",
    target_fields=("user_id",),
)
async def get_user_profile(
    user_id: Snowflake,
    guild_id: Snowflake | None = None,
    with_mutual_guilds: bool = True,
    with_mutual_friends: bool = False,
) -> Any:
    params = clean_params(
        {
            "guild_id": guild_id,
            "with_mutual_guilds": with_mutual_guilds,
            "with_mutual_friends": with_mutual_friends,
        }
    )
    return await call("users.profile", path_params={"user_id": user_id}, params=params)


@define_tool(
    name="list_mutual_relationships",
    description=(
        "List the relationships (friends/requests/blocks) shared with another user. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="users.mutual_relationships",
    summary="List mutual relationships with {user_id}",
    target_fields=("user_id",),
)
async def list_mutual_relationships(user_id: Snowflake) -> Any:
    return await call("users.mutual_relationships", path_params={"user_id": user_id})


@define_tool(
    name="list_mentions",
    description=(
        "List recent messages that mention the account. Read-only. Optionally filter to one "
        "guild, role mentions or @everyone mentions."
    ),
    risk=Risk.READ,
    endpoint_id="users.mentions",
    summary="List recent mentions",
)
async def list_mentions(
    limit: Annotated[int, Field(ge=1, le=100, description="How many mentions to return")] = 25,
    before: Snowflake | None = None,
    guild_id: Snowflake | None = None,
    roles: bool | None = None,
    everyone: bool | None = None,
) -> Any:
    params = clean_params(
        {"limit": limit, "before": before, "guild_id": guild_id, "roles": roles, "everyone": everyone}
    )
    return await call("users.mentions", params=params)


@define_tool(
    name="list_my_notes",
    description="List the private notes the account keeps about other users. Read-only.",
    risk=Risk.READ,
    endpoint_id="users.notes.list",
    summary="List private user notes",
)
async def list_my_notes() -> Any:
    return await call("users.notes.list")


@define_tool(
    name="set_user_note",
    description=(
        "Create, replace or clear the private note about a user (max 256 characters, empty "
        "string clears it). Only the account owner can see notes. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="users.notes.set",
    summary="Set the private note on user {user_id}",
    target_fields=("user_id",),
    requires_dry_run=True,
)
async def set_user_note(
    user_id: Snowflake,
    note: Annotated[str, Field(max_length=256, description="Note text; empty string clears it")],
    dry_run: bool = False,
) -> Any:
    return await call("users.notes.set", path_params={"user_id": user_id}, payload={"note": note})


# --------------------------------------------------------------------------
# Account / profile edits
# --------------------------------------------------------------------------


@define_tool(
    name="update_my_account",
    description=(
        "Change the account's global display name (not the unique username). Pass null to "
        "reset it. This is an account-level change. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="users.update_account",
    summary="Change the account global display name",
    requires_dry_run=True,
)
async def update_my_account(
    global_name: Annotated[
        str | None, Field(max_length=32, description="New display name, or null to reset")
    ] = None,
    dry_run: bool = False,
) -> Any:
    return await call("users.update_account", payload={"global_name": global_name})


@define_tool(
    name="update_my_profile",
    description=(
        "Change the account's profile: bio, banner, accent colour, pronouns or profile effect. "
        "Only supplied fields are changed. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="users.update_profile",
    summary="Change the account profile",
    requires_dry_run=True,
)
async def update_my_profile(
    bio: Annotated[str | None, Field(max_length=190, description="Profile bio")] = None,
    banner: Annotated[
        str | None, Field(description="Data URI (data:image/...) or null to remove the banner")
    ] = None,
    accent_color: Annotated[
        int | None, Field(ge=0, le=0xFFFFFF, description="Accent colour as an integer")
    ] = None,
    pronouns: Annotated[str | None, Field(max_length=40)] = None,
    profile_effect_id: Annotated[str | None, Field(description="Profile effect SKU id")] = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "bio": bio,
            "banner": banner,
            "accent_color": accent_color,
            "pronouns": pronouns,
            "profile_effect_id": profile_effect_id,
        }
    )
    if not payload:
        from ..api.errors import ValidationError

        raise ValidationError("Provide at least one profile field to change")
    return await call("users.update_profile", payload=payload)


# --------------------------------------------------------------------------
# Relationships
# --------------------------------------------------------------------------


@define_tool(
    name="list_relationships",
    description=(
        "List the account's relationships: friends (type 1), blocked users (2), incoming "
        "requests (3) and outgoing requests (4). Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="relationships.list",
    summary="List friends, requests and blocks",
)
async def list_relationships() -> Any:
    return await call("relationships.list")


@define_tool(
    name="send_friend_request",
    description=(
        "Send a friend request by username. With the unique-username system the discriminator "
        "is optional. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="relationships.send_request",
    summary="Send a friend request to {username}",
    target_fields=("username",),
    requires_dry_run=True,
)
async def send_friend_request(
    username: Annotated[str, Field(min_length=2, max_length=64)],
    discriminator: Annotated[
        str | None, Field(pattern=r"^\d{4}$", description="Legacy 4-digit tag, if any")
    ] = None,
    note: Annotated[str | None, Field(max_length=256)] = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params({"username": username, "discriminator": discriminator, "note": note})
    return await call("relationships.send_request", payload=payload)


@define_tool(
    name="accept_friend_request",
    description=(
        "Accept an incoming friend request. Only works when that user actually has a pending "
        "request to this account; Discord returns 400 otherwise. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="relationships.create",
    summary="Accept the friend request from {user_id}",
    target_fields=("user_id",),
    requires_dry_run=True,
)
async def accept_friend_request(user_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "relationships.create", path_params={"user_id": user_id}, payload={"type": 1}
    )


@define_tool(
    name="set_relationship_nickname",
    description=(
        "Change the local nickname shown for a friend (empty string clears it). " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="relationships.update",
    summary="Set the local nickname for {user_id}",
    target_fields=("user_id",),
    requires_dry_run=True,
)
async def set_relationship_nickname(
    user_id: Snowflake,
    nickname: Annotated[str, Field(max_length=64)],
    dry_run: bool = False,
) -> Any:
    return await call(
        "relationships.update", path_params={"user_id": user_id}, payload={"nickname": nickname}
    )


@define_tool(
    name="remove_relationship",
    description=(
        "Remove a relationship: unfriend a friend, cancel an outgoing request, decline an "
        "incoming request or unblock a user. Destructive and not undoable from here. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="relationships.delete",
    summary="Remove the relationship with {user_id}",
    target_fields=("user_id",),
    requires_dry_run=True,
)
async def remove_relationship(user_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("relationships.delete", path_params={"user_id": user_id})


@define_tool(
    name="block_user",
    description=(
        "Block a user, which also removes any friendship and prevents DMs. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="relationships.create",
    summary="Block user {user_id}",
    target_fields=("user_id",),
    requires_dry_run=True,
)
async def block_user(user_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "relationships.create", path_params={"user_id": user_id}, payload={"type": 2}
    )
