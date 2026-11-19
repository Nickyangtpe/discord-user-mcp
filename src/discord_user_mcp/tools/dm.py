"""Direct message and group DM tools."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from ..api.errors import ValidationError
from ..security.permissions import Risk
from ..utils.ids import snowflake_list
from ._common import Snowflake, call, clean_params
from .specs import define_tool

APPROVAL = "Requires explicit human approval in the approval console."


@define_tool(
    name="open_dm",
    description=(
        "Open (or reuse) the direct message channel with a user and return its channel id. "
        "Sending a message still needs send_message and its own approval. " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="dms.open",
    summary="Open a DM with {user_id}",
    target_fields=("user_id",),
    requires_dry_run=True,
)
async def open_dm(user_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("dms.open", payload={"recipient_id": user_id})


@define_tool(
    name="create_group_dm",
    description=(
        "Create a group DM with 1-9 other users, optionally naming it. Returns the new "
        "group channel. " + APPROVAL
    ),
    risk=Risk.WRITE,
    endpoint_id="dms.open",
    summary="Create a group DM with {user_ids}",
    target_fields=("user_ids",),
    requires_dry_run=True,
)
async def create_group_dm(
    user_ids: Annotated[
        list[str], Field(min_length=1, max_length=9, description="Other participants' user ids")
    ],
    name: Annotated[str | None, Field(max_length=100, description="Optional group name")] = None,
    dry_run: bool = False,
) -> Any:
    recipients = snowflake_list(user_ids, field="user_ids", limit=9)
    payload: dict[str, Any] = {"recipients": recipients}
    if name:
        payload["name"] = name
    return await call("dms.open", payload=payload)


@define_tool(
    name="add_group_dm_recipient",
    description="Add a user to an existing group DM. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="dms.recipients.add",
    summary="Add {user_id} to group DM {channel_id}",
    target_fields=("channel_id", "user_id"),
    requires_dry_run=True,
)
async def add_group_dm_recipient(
    channel_id: Snowflake, user_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "dms.recipients.add", path_params={"channel_id": channel_id, "user_id": user_id}
    )


@define_tool(
    name="remove_group_dm_recipient",
    description="Remove a user from a group DM. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="dms.recipients.remove",
    summary="Remove {user_id} from group DM {channel_id}",
    target_fields=("channel_id", "user_id"),
    requires_dry_run=True,
)
async def remove_group_dm_recipient(
    channel_id: Snowflake, user_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "dms.recipients.remove", path_params={"channel_id": channel_id, "user_id": user_id}
    )


@define_tool(
    name="leave_group_dm",
    description=(
        "Leave a group DM. The channel disappears from the account's list; other members keep "
        "their copy. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="channels.delete",
    summary="Leave group DM {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def leave_group_dm(channel_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("channels.delete", path_params={"channel_id": channel_id})


@define_tool(
    name="close_dm",
    description=(
        "Close a 1:1 DM channel, removing it from the account's channel list. The other "
        "participant is not notified and can reopen it by messaging again. " + APPROVAL
    ),
    risk=Risk.DESTRUCTIVE,
    endpoint_id="channels.delete",
    summary="Close DM {channel_id}",
    target_fields=("channel_id",),
    requires_dry_run=True,
)
async def close_dm(channel_id: Snowflake, dry_run: bool = False) -> Any:
    return await call("channels.delete", path_params={"channel_id": channel_id})


__all__ = [
    "add_group_dm_recipient",
    "close_dm",
    "create_group_dm",
    "leave_group_dm",
    "open_dm",
    "remove_group_dm_recipient",
]
