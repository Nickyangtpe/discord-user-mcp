"""Message, search, reaction and poll tools."""

from __future__ import annotations

import secrets
from typing import Annotated, Any

from pydantic import Field

from ..api.errors import ValidationError
from ..security.permissions import Risk
from ..utils.ids import emoji_path
from ._common import Snowflake, call, clean_params
from .specs import define_tool
from .uploads import load_files

APPROVAL = "Requires explicit human approval in the approval console."
MAX_EMBED_CHARS = 6000


def _validate_embeds(embeds: list[dict] | None) -> list[dict] | None:
    if not embeds:
        return None
    if len(embeds) > 10:
        raise ValidationError("Discord accepts at most 10 embeds per message")
    total = 0
    for embed in embeds:
        if not isinstance(embed, dict):
            raise ValidationError("Each embed must be a JSON object")
        total += len(str(embed.get("title", "")))
        total += len(str(embed.get("description", "")))
        footer = embed.get("footer") or {}
        total += len(str(footer.get("text", "")))
        author = embed.get("author") or {}
        total += len(str(author.get("name", "")))
        for field in embed.get("fields") or []:
            total += len(str(field.get("name", ""))) + len(str(field.get("value", "")))
    if total > MAX_EMBED_CHARS:
        raise ValidationError(f"Embed text totals {total} characters; Discord allows {MAX_EMBED_CHARS}")
    return embeds


def _reaction_path(channel_id: str, message_id: str, emoji: str) -> dict[str, str]:
    return {"channel_id": channel_id, "message_id": message_id, "emoji": emoji_path(emoji)}


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------


@define_tool(
    name="list_messages",
    description=(
        "Read channel history, newest first by default. Use before/after/around with a message "
        "id to page. limit is 1-100. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="messages.list",
    summary="List messages in {channel_id}",
    target_fields=("channel_id",),
)
async def list_messages(
    channel_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=100)] = 50,
    before: Snowflake | None = None,
    after: Snowflake | None = None,
    around: Snowflake | None = None,
) -> Any:
    if sum(value is not None for value in (before, after, around)) > 1:
        raise ValidationError("Use only one of before, after or around")
    return await call(
        "messages.list",
        path_params={"channel_id": channel_id},
        params=clean_params(
            {"limit": limit, "before": before, "after": after, "around": around}
        ),
    )


@define_tool(
    name="get_message",
    description="Get one message by id, including reactions and attachments. Read-only.",
    risk=Risk.READ,
    endpoint_id="messages.get",
    summary="Read message {message_id} in {channel_id}",
    target_fields=("channel_id", "message_id"),
)
async def get_message(channel_id: Snowflake, message_id: Snowflake) -> Any:
    return await call(
        "messages.get", path_params={"channel_id": channel_id, "message_id": message_id}
    )


@define_tool(
    name="search_guild_messages",
    description=(
        "Search messages across a guild. Supports content, author, mentions, attachments, "
        "pinned state and pagination. Discord may answer HTTP 202 while the guild index is "
        "still being built; retry after the given delay. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="messages.search.guild",
    summary="Search messages in guild {guild_id}",
    target_fields=("guild_id",),
)
async def search_guild_messages(
    guild_id: Snowflake,
    content: Annotated[str | None, Field(max_length=1024)] = None,
    channel_id: Snowflake | None = None,
    author_id: Snowflake | None = None,
    author_type: Annotated[str | None, Field(description="user or bot")] = None,
    mentions: Snowflake | None = None,
    mention_everyone: bool | None = None,
    has: Annotated[
        str | None, Field(description="link, embed, file, image, sound, video, poll, snapshot")
    ] = None,
    pinned: bool | None = None,
    min_id: Snowflake | None = None,
    max_id: Snowflake | None = None,
    limit: Annotated[int, Field(ge=1, le=25)] = 25,
    offset: Annotated[int | None, Field(ge=0)] = None,
    sort_by: Annotated[str | None, Field(description="timestamp or relevance")] = None,
    sort_order: Annotated[str | None, Field(description="asc or desc")] = None,
    include_nsfw: bool | None = None,
) -> Any:
    return await call(
        "messages.search.guild",
        path_params={"guild_id": guild_id},
        params=clean_params(
            {
                "content": content,
                "channel_id": channel_id,
                "author_id": author_id,
                "author_type": author_type,
                "mentions": mentions,
                "mention_everyone": mention_everyone,
                "has": has,
                "pinned": pinned,
                "min_id": min_id,
                "max_id": max_id,
                "limit": limit,
                "offset": offset,
                "sort_by": sort_by,
                "sort_order": sort_order,
                "include_nsfw": include_nsfw,
            }
        ),
    )


@define_tool(
    name="search_channel_messages",
    description=(
        "Search messages inside one channel or DM. Same filters as the guild search. Read-only."
    ),
    risk=Risk.READ,
    endpoint_id="messages.search.channel",
    summary="Search messages in {channel_id}",
    target_fields=("channel_id",),
)
async def search_channel_messages(
    channel_id: Snowflake,
    content: Annotated[str | None, Field(max_length=1024)] = None,
    author_id: Snowflake | None = None,
    has: Annotated[str | None, Field(description="link, embed, file, image, sound, video")] = None,
    pinned: bool | None = None,
    min_id: Snowflake | None = None,
    max_id: Snowflake | None = None,
    limit: Annotated[int, Field(ge=1, le=25)] = 25,
    offset: Annotated[int | None, Field(ge=0)] = None,
) -> Any:
    return await call(
        "messages.search.channel",
        path_params={"channel_id": channel_id},
        params=clean_params(
            {
                "content": content,
                "author_id": author_id,
                "has": has,
                "pinned": pinned,
                "min_id": min_id,
                "max_id": max_id,
                "limit": limit,
                "offset": offset,
            }
        ),
    )


@define_tool(
    name="list_reactions",
    description="List the users who reacted to a message with one emoji. Read-only.",
    risk=Risk.READ,
    endpoint_id="messages.reactions.list",
    summary="List reactions {emoji} on message {message_id}",
    target_fields=("channel_id", "message_id"),
)
async def list_reactions(
    channel_id: Snowflake,
    message_id: Snowflake,
    emoji: Annotated[str, Field(description="Unicode emoji or custom emoji as name:id")],
    limit: Annotated[int, Field(ge=1, le=100)] = 25,
    after: Snowflake | None = None,
) -> Any:
    return await call(
        "messages.reactions.list",
        path_params=_reaction_path(channel_id, message_id, emoji),
        params=clean_params({"limit": limit, "after": after}),
    )


@define_tool(
    name="list_poll_voters",
    description="List users who picked one answer in a poll. Read-only.",
    risk=Risk.READ,
    endpoint_id="messages.polls.voters",
    summary="List voters for answer {answer_id} on poll {message_id}",
    target_fields=("channel_id", "message_id"),
)
async def list_poll_voters(
    channel_id: Snowflake,
    message_id: Snowflake,
    answer_id: Annotated[int, Field(ge=0)],
    limit: Annotated[int, Field(ge=1, le=100)] = 25,
    after: Snowflake | None = None,
) -> Any:
    return await call(
        "messages.polls.voters",
        path_params={"channel_id": channel_id, "message_id": message_id, "answer_id": str(answer_id)},
        params=clean_params({"limit": limit, "after": after}),
    )


# --------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------


@define_tool(
    name="send_message",
    description=(
        "Send a message to a channel or DM. Supports plain content, embeds, stickers, replies "
        "and file attachments from an allowed upload directory. A unique nonce is attached so "
        "a retry cannot post twice. " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="messages.create",
    summary="Send a message to {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def send_message(
    channel_id: Snowflake,
    content: Annotated[str | None, Field(max_length=2000, description="Message text")] = None,
    reply_to_message_id: Snowflake | None = None,
    embeds: Annotated[list[dict] | None, Field(description="Up to 10 rich embeds")] = None,
    sticker_ids: Annotated[list[str] | None, Field(description="Sticker ids")] = None,
    attachment_paths: Annotated[
        list[str] | None, Field(description="Local file paths under an allowed upload root")
    ] = None,
    tts: bool = False,
    suppress_embeds: bool = False,
    allowed_mentions: Annotated[dict | None, Field(description="allowed_mentions object")] = None,
    nonce: Annotated[str | None, Field(max_length=25, description="Idempotency nonce")] = None,
    dry_run: bool = False,
) -> Any:
    embeds = _validate_embeds(embeds)
    if not any([content, embeds, sticker_ids, attachment_paths]):
        raise ValidationError(
            "Provide at least one of content, embeds, sticker_ids or attachment_paths"
        )
    from ..runtime import get_context

    settings = get_context().settings
    files = load_files(settings, attachment_paths or [])
    payload: dict[str, Any] = {
        "content": content or "",
        "tts": tts,
        "nonce": nonce or str(secrets.randbelow(10**18)),
    }
    if embeds:
        payload["embeds"] = embeds
    if sticker_ids:
        payload["sticker_ids"] = sticker_ids
    if allowed_mentions is not None:
        payload["allowed_mentions"] = allowed_mentions
    if suppress_embeds:
        payload["flags"] = 1 << 2
    if reply_to_message_id:
        payload["message_reference"] = {
            "type": 0,
            "message_id": reply_to_message_id,
            "channel_id": channel_id,
            "fail_if_not_exists": False,
        }
    return await call(
        "messages.create", path_params={"channel_id": channel_id}, payload=payload, files=files
    )


@define_tool(
    name="forward_message",
    description=(
        "Forward an existing message into another channel using a snapshot reference. "
        + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="messages.create",
    summary="Forward message {message_id} to {channel_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def forward_message(
    channel_id: Snowflake,
    message_id: Snowflake,
    source_channel_id: Snowflake,
    content: Annotated[str | None, Field(max_length=2000)] = None,
    dry_run: bool = False,
) -> Any:
    payload: dict[str, Any] = {
        "content": content or "",
        "nonce": str(secrets.randbelow(10**18)),
        "message_reference": {
            "type": 1,
            "message_id": message_id,
            "channel_id": source_channel_id,
        },
    }
    return await call(
        "messages.create", path_params={"channel_id": channel_id}, payload=payload
    )


@define_tool(
    name="edit_message",
    description=(
        "Edit a message the account authored: content, embeds or embed suppression. Only "
        "supplied fields change. " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="messages.edit",
    summary="Edit message {message_id} in {channel_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def edit_message(
    channel_id: Snowflake,
    message_id: Snowflake,
    content: Annotated[str | None, Field(max_length=2000)] = None,
    embeds: Annotated[list[dict] | None, Field(description="Replacement embeds")] = None,
    suppress_embeds: bool | None = None,
    dry_run: bool = False,
) -> Any:
    embeds = _validate_embeds(embeds)
    payload = clean_params({"content": content, "embeds": embeds})
    if suppress_embeds is not None:
        payload["flags"] = (1 << 2) if suppress_embeds else 0
    if not payload:
        raise ValidationError("Provide content, embeds or suppress_embeds")
    return await call(
        "messages.edit",
        path_params={"channel_id": channel_id, "message_id": message_id},
        payload=payload,
    )


@define_tool(
    name="delete_message",
    description=(
        "Delete a message. In guilds this needs MANAGE_MESSAGES to delete someone else's "
        "message; deleting your own always works. Irreversible. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="messages.delete",
    summary="Delete message {message_id} in {channel_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def delete_message(
    channel_id: Snowflake, message_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "messages.delete", path_params={"channel_id": channel_id, "message_id": message_id}
    )


@define_tool(
    name="add_reaction",
    description="Add a reaction to a message as the account. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="messages.reactions.add",
    summary="React with {emoji} to message {message_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def add_reaction(
    channel_id: Snowflake,
    message_id: Snowflake,
    emoji: Annotated[str, Field(description="Unicode emoji or custom emoji as name:id")],
    burst: bool = False,
    dry_run: bool = False,
) -> Any:
    return await call(
        "messages.reactions.add",
        path_params=_reaction_path(channel_id, message_id, emoji),
        params={"type": 1} if burst else None,
    )


@define_tool(
    name="remove_own_reaction",
    description="Remove one of the account's own reactions from a message. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="messages.reactions.remove_own",
    summary="Remove own reaction {emoji} from message {message_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def remove_own_reaction(
    channel_id: Snowflake,
    message_id: Snowflake,
    emoji: Annotated[str, Field(description="Unicode emoji or custom emoji as name:id")],
    reaction_type: Annotated[int, Field(ge=0, le=1, description="0 normal, 1 burst")] = 0,
    dry_run: bool = False,
) -> Any:
    params = _reaction_path(channel_id, message_id, emoji)
    params["reaction_type"] = str(reaction_type)
    return await call("messages.reactions.remove_own", path_params=params)


@define_tool(
    name="remove_user_reaction",
    description=(
        "Remove another user's reaction. Requires MANAGE_MESSAGES. " + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="messages.reactions.remove_user",
    summary="Remove {user_id}'s reaction {emoji} from message {message_id}",
    target_fields=("channel_id", "message_id", "user_id"),
    requires_dry_run=True,
)
async def remove_user_reaction(
    channel_id: Snowflake,
    message_id: Snowflake,
    user_id: Snowflake,
    emoji: Annotated[str, Field(description="Unicode emoji or custom emoji as name:id")],
    reaction_type: Annotated[int, Field(ge=0, le=1)] = 0,
    dry_run: bool = False,
) -> Any:
    params = _reaction_path(channel_id, message_id, emoji)
    params["reaction_type"] = str(reaction_type)
    params["user_id"] = user_id
    return await call("messages.reactions.remove_user", path_params=params)


@define_tool(
    name="remove_emoji_reactions",
    description="Remove every reaction of one emoji. Requires MANAGE_MESSAGES. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="messages.reactions.remove_emoji",
    summary="Remove all {emoji} reactions from message {message_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def remove_emoji_reactions(
    channel_id: Snowflake,
    message_id: Snowflake,
    emoji: Annotated[str, Field(description="Unicode emoji or custom emoji as name:id")],
    dry_run: bool = False,
) -> Any:
    return await call(
        "messages.reactions.remove_emoji",
        path_params=_reaction_path(channel_id, message_id, emoji),
    )


@define_tool(
    name="remove_all_reactions",
    description="Remove every reaction on a message. Requires MANAGE_MESSAGES. " + APPROVAL,
    risk=Risk.ADMIN,
    endpoint_id="messages.reactions.remove_all",
    summary="Remove all reactions from message {message_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def remove_all_reactions(
    channel_id: Snowflake, message_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "messages.reactions.remove_all",
        path_params={"channel_id": channel_id, "message_id": message_id},
    )


@define_tool(
    name="vote_poll",
    description="Vote in a poll with one or more answer ids. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="messages.polls.vote",
    summary="Vote on poll {message_id}",
    target_fields=("channel_id", "message_id"),
    requires_dry_run=True,
)
async def vote_poll(
    channel_id: Snowflake,
    message_id: Snowflake,
    answer_ids: Annotated[list[int], Field(min_length=1, max_length=20)],
    dry_run: bool = False,
) -> Any:
    if any(answer < 0 for answer in answer_ids):
        raise ValidationError("answer_ids must be non-negative integers")
    return await call(
        "messages.polls.vote",
        path_params={"channel_id": channel_id, "message_id": message_id},
        payload={"answer_ids": answer_ids},
    )
