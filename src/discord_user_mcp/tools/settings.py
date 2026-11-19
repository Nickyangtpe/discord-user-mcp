"""Client settings, custom status and notification-center tools."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from ..api.errors import ValidationError
from ..security.permissions import Risk
from ._common import Snowflake, call, clean_params
from .specs import define_tool

APPROVAL = "Requires explicit human approval in the approval console."
StatusText = Annotated[
    str | None,
    Field(max_length=128, description="Custom status text; null clears the status"),
]


@define_tool(
    name="get_my_settings",
    description=(
        "Read the account's client settings: theme, locale, status, developer mode, compact "
        "messages, friend request flags and custom status. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="settings.get",
    summary="Read the account's client settings",
)
async def get_my_settings() -> Any:
    return await call("settings.get")


@define_tool(
    name="update_my_settings",
    description=(
        "Change client settings for the account: presence status (online/idle/dnd/invisible), "
        "theme, locale, compact messages, embed rendering, NSFW visibility, developer mode. "
        "Only supplied fields change. This affects what the account's clients display. "
        + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="settings.update",
    summary="Change client settings",
    requires_dry_run=True,
)
async def update_my_settings(
    status: Annotated[
        str | None, Field(pattern=r"^(online|idle|dnd|invisible)$", description="Presence status")
    ] = None,
    theme: Annotated[str | None, Field(pattern=r"^(dark|light|darker|midnight)$")] = None,
    locale: Annotated[str | None, Field(max_length=20, description="e.g. en-US")] = None,
    message_display_compact: bool | None = None,
    render_embeds: bool | None = None,
    render_reactions: bool | None = None,
    view_nsfw_guilds: bool | None = None,
    developer_mode: bool | None = None,
    explicit_content_filter: Annotated[int | None, Field(ge=0, le=2)] = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "status": status,
            "theme": theme,
            "locale": locale,
            "message_display_compact": message_display_compact,
            "render_embeds": render_embeds,
            "render_reactions": render_reactions,
            "view_nsfw_guilds": view_nsfw_guilds,
            "developer_mode": developer_mode,
            "explicit_content_filter": explicit_content_filter,
        }
    )
    if not payload:
        raise ValidationError("Provide at least one setting to change")
    return await call("settings.update", payload=payload)


@define_tool(
    name="set_custom_status",
    description=(
        "Set, change or clear the account's custom status (text, optional emoji and optional "
        "expiry). An empty text with no emoji clears it. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="settings.update",
    summary="Set the custom status",
    requires_dry_run=True,
)
async def set_custom_status(
    text: StatusText = None,
    emoji_name: Annotated[
        str | None, Field(max_length=64, description="Unicode emoji character")
    ] = None,
    emoji_id: Annotated[
        str | None, Field(description="Id of a guild custom emoji (not with emoji_name)")
    ] = None,
    expires_at: Annotated[
        str | None, Field(description="ISO8601 expiry, or null for no expiry")
    ] = None,
    dry_run: bool = False,
) -> Any:
    if emoji_name and emoji_id:
        raise ValidationError("Set at most one of emoji_name and emoji_id")
    if text is None and emoji_name is None and emoji_id is None:
        payload: dict[str, Any] = {"custom_status": None}
    else:
        custom: dict[str, Any] = {}
        if text is not None:
            custom["text"] = text
        if emoji_name:
            custom["emoji_name"] = emoji_name
        if emoji_id:
            custom["emoji_id"] = emoji_id
        if expires_at is not None:
            custom["expires_at"] = expires_at
        payload = {"custom_status": custom}
    return await call("settings.update", payload=payload)


@define_tool(
    name="update_my_notification_settings",
    description=(
        "Replace the account's global notification settings flags bitfield. The documented "
        "bits are 1<<4 (USE_NEW_NOTIFICATIONS: separate unreads from the message notification "
        "level) and 1<<5 (MENTION_ON_ALL_MESSAGES). Read the current value with "
        "get_my_settings first, because this replaces the whole field. " + APPROVAL
    ),
    risk=Risk.SENSITIVE,
    endpoint_id="settings.notifications.update",
    summary="Set notification settings flags to {flags}",
    requires_dry_run=True,
)
async def update_my_notification_settings(
    flags: Annotated[
        int,
        Field(
            ge=0,
            le=2**31,
            description="Notification settings bitfield, e.g. 16 (USE_NEW_NOTIFICATIONS)",
        ),
    ],
    dry_run: bool = False,
) -> Any:
    return await call("settings.notifications.update", payload={"flags": flags})


@define_tool(
    name="list_notifications",
    description=(
        "List notification-center items (mentions, replies, friend requests and system "
        "notices). Read-only. Use cursor pagination with after."
    ),
    risk=Risk.READ,
    endpoint_id="notifications.list",
    summary="List notification-center items",
)
async def list_notifications(
    limit: Annotated[int, Field(ge=1, le=100)] = 25,
    after: Annotated[str | None, Field(description="Cursor from the previous page")] = None,
    with_mentions: bool = True,
) -> Any:
    return await call(
        "notifications.list",
        params=clean_params({"limit": limit, "after": after, "with_mentions": with_mentions}),
    )


@define_tool(
    name="ack_notification",
    description=(
        "Acknowledge one notification-center item so it stops counting as unread. "
        + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="notifications.ack",
    summary="Acknowledge notification {notification_id}",
    target_fields=("notification_id",),
    requires_dry_run=True,
)
async def ack_notification(notification_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "notifications.ack", path_params={"notification_id": notification_id}
    )


__all__ = [
    "ack_notification",
    "get_my_settings",
    "list_notifications",
    "set_custom_status",
    "update_my_notification_settings",
    "update_my_settings",
]
