"""Guild scheduled event tools."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from ..api.errors import ValidationError
from ..security.permissions import Risk
from ._common import Snowflake, call, clean_params
from .specs import define_tool

APPROVAL = "Requires explicit human approval in the approval console."
PrivacyLevel = Literal[2]
EntityType = Annotated[
    int,
    Field(
        ge=1,
        le=3,
        description="1 stage instance, 2 voice channel, 3 external (needs entity_metadata)",
    ),
]


@define_tool(
    name="list_scheduled_events",
    description="List a guild's scheduled events with subscriber counts. Read-only.",
    risk=Risk.READ,
    endpoint_id="events.list",
    summary="List scheduled events in guild {guild_id}",
    target_fields=("guild_id",),
)
async def list_scheduled_events(guild_id: Snowflake, with_user_count: bool = True) -> Any:
    return await call(
        "events.list",
        path_params={"guild_id": guild_id},
        params={"with_user_count": with_user_count},
    )


@define_tool(
    name="get_scheduled_event",
    description="Get one scheduled event by id. Read-only.",
    risk=Risk.READ,
    endpoint_id="events.get",
    summary="Read scheduled event {event_id} in guild {guild_id}",
    target_fields=("guild_id", "event_id"),
)
async def get_scheduled_event(
    guild_id: Snowflake, event_id: Snowflake, with_user_count: bool = True
) -> Any:
    return await call(
        "events.get",
        path_params={"guild_id": guild_id, "event_id": event_id},
        params={"with_user_count": with_user_count},
    )


@define_tool(
    name="list_event_users",
    description="List users interested in a scheduled event. Read-only.",
    risk=Risk.READ,
    endpoint_id="events.users.list",
    summary="List subscribers of event {event_id}",
    target_fields=("guild_id", "event_id"),
)
async def list_event_users(
    guild_id: Snowflake,
    event_id: Snowflake,
    limit: Annotated[int, Field(ge=1, le=100)] = 100,
    after: Snowflake | None = None,
    with_member: bool = True,
) -> Any:
    return await call(
        "events.users.list",
        path_params={"guild_id": guild_id, "event_id": event_id},
        params=clean_params({"limit": limit, "after": after, "with_member": with_member}),
    )


@define_tool(
    name="create_scheduled_event",
    description=(
        "Create a guild scheduled event. Stage (entity_type 1) and voice (2) events need a "
        "channel_id; external events (3) need entity_metadata "
        '{"location": "..."} plus scheduled_end_time. Times are ISO8601. ' + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="events.create",
    summary="Create a scheduled event in guild {guild_id}",
    target_fields=("guild_id", "name"),
    requires_dry_run=True,
)
async def create_scheduled_event(
    guild_id: Snowflake,
    name: Annotated[str, Field(min_length=1, max_length=100)],
    scheduled_start_time: Annotated[str, Field(description="ISO8601 start time (UTC)")],
    entity_type: EntityType,
    channel_id: Snowflake | None = None,
    entity_metadata: Annotated[
        dict | None, Field(description='External events: {"location": "..."}')
    ] = None,
    scheduled_end_time: Annotated[str | None, Field(description="ISO8601 end time")] = None,
    description: Annotated[str | None, Field(max_length=1000)] = None,
    image: Annotated[str | None, Field(description="Data URI cover image")] = None,
    privacy_level: PrivacyLevel = 2,
    dry_run: bool = False,
) -> Any:
    if entity_type == 3:
        if not entity_metadata or "location" not in entity_metadata:
            raise ValidationError(
                'External events (entity_type 3) require entity_metadata={"location": "..."}'
            )
    elif not channel_id:
        raise ValidationError("Stage and voice events require a channel_id")
    payload = clean_params(
        {
            "name": name,
            "scheduled_start_time": scheduled_start_time,
            "entity_type": entity_type,
            "channel_id": channel_id,
            "entity_metadata": entity_metadata,
            "scheduled_end_time": scheduled_end_time,
            "description": description,
            "image": image,
            "privacy_level": privacy_level,
        }
    )
    return await call(
        "events.create", path_params={"guild_id": guild_id}, payload=payload
    )


@define_tool(
    name="update_scheduled_event",
    description=(
        "Change a scheduled event: name, description, start/end time, channel, entity type, "
        "status (1 scheduled, 2 active, 3 completed, 4 cancelled) or cover image. Only supplied "
        "fields change. " + APPROVAL
    ),
    risk=Risk.ADMIN,
    endpoint_id="events.update",
    summary="Update scheduled event {event_id} in guild {guild_id}",
    target_fields=("guild_id", "event_id"),
    requires_dry_run=True,
)
async def update_scheduled_event(
    guild_id: Snowflake,
    event_id: Snowflake,
    name: Annotated[str | None, Field(min_length=1, max_length=100)] = None,
    description: Annotated[str | None, Field(max_length=1000)] = None,
    scheduled_start_time: Annotated[str | None, Field(description="ISO8601 start time")] = None,
    scheduled_end_time: Annotated[str | None, Field(description="ISO8601 end time")] = None,
    channel_id: Snowflake | None = None,
    entity_type: Annotated[int | None, Field(ge=1, le=3)] = None,
    entity_metadata: Annotated[dict | None, Field(description="For external events")] = None,
    status: Annotated[int | None, Field(ge=1, le=4)] = None,
    image: Annotated[str | None, Field(description="Data URI cover image")] = None,
    dry_run: bool = False,
) -> Any:
    payload = clean_params(
        {
            "name": name,
            "description": description,
            "scheduled_start_time": scheduled_start_time,
            "scheduled_end_time": scheduled_end_time,
            "channel_id": channel_id,
            "entity_type": entity_type,
            "entity_metadata": entity_metadata,
            "status": status,
            "image": image,
        }
    )
    if not payload:
        raise ValidationError("Provide at least one event field to change")
    return await call(
        "events.update",
        path_params={"guild_id": guild_id, "event_id": event_id},
        payload=payload,
    )


@define_tool(
    name="delete_scheduled_event",
    description="Delete a scheduled event. Subscribers lose it permanently. " + APPROVAL,
    risk=Risk.DESTRUCTIVE,
    endpoint_id="events.delete",
    summary="Delete scheduled event {event_id} in guild {guild_id}",
    target_fields=("guild_id", "event_id"),
    requires_dry_run=True,
)
async def delete_scheduled_event(
    guild_id: Snowflake, event_id: Snowflake, dry_run: bool = False
) -> Any:
    return await call(
        "events.delete", path_params={"guild_id": guild_id, "event_id": event_id}
    )


@define_tool(
    name="rsvp_event",
    description="Mark the account as interested in a scheduled event. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="events.rsvp",
    summary="RSVP to event {event_id}",
    target_fields=("guild_id", "event_id"),
    requires_dry_run=True,
)
async def rsvp_event(guild_id: Snowflake, event_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "events.rsvp", path_params={"guild_id": guild_id, "event_id": event_id}
    )


@define_tool(
    name="unrsvp_event",
    description="Remove the account's interest in a scheduled event. " + APPROVAL,
    risk=Risk.WRITE,
    endpoint_id="events.rsvp.delete",
    summary="Un-RSVP from event {event_id}",
    target_fields=("guild_id", "event_id"),
    requires_dry_run=True,
)
async def unrsvp_event(guild_id: Snowflake, event_id: Snowflake, dry_run: bool = False) -> Any:
    return await call(
        "events.rsvp.delete", path_params={"guild_id": guild_id, "event_id": event_id}
    )


__all__ = [
    "create_scheduled_event",
    "delete_scheduled_event",
    "get_scheduled_event",
    "list_event_users",
    "list_scheduled_events",
    "rsvp_event",
    "unrsvp_event",
    "update_scheduled_event",
]
