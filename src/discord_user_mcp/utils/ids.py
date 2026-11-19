"""Snowflake and Discord-specific value validation shared by all tools."""

from __future__ import annotations

import re

_SNOWFLAKE = re.compile(r"^\d{5,20}$")
_TAG = re.compile(r"^(?P<name>[a-z0-9_.]{1,32})(?P<discriminator>#\d{4})?$", re.I)


class InvalidArgument(ValueError):
    """Raised when a tool argument is not a valid Discord value."""


def snowflake(value: str, field: str = "id") -> str:
    if not isinstance(value, str) or not _SNOWFLAKE.match(value.strip()):
        raise InvalidArgument(f"{field} must be a Discord snowflake (digits only), got {value!r}")
    return value.strip()


def message_content(value: str, *, field: str = "content", limit: int = 2000) -> str:
    if not isinstance(value, str):
        raise InvalidArgument(f"{field} must be a string")
    if not value.strip():
        raise InvalidArgument(f"{field} must not be empty or whitespace only")
    if len(value) > limit:
        raise InvalidArgument(f"{field} is {len(value)} characters, Discord allows at most {limit}")
    return value


def emoji_path(value: str) -> str:
    """Return the reaction emoji in the form the API expects in a path.

    Custom emoji are ``name:id``; unicode emoji are returned as-is and the
    registry's path renderer percent-encodes them exactly once. Quoting here as
    well would double-encode and Discord would reject the route.
    """
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgument("emoji must be a unicode emoji or a custom emoji as 'name:id'")
    value = value.strip().strip(":")
    if re.fullmatch(r"[A-Za-z0-9_]{1,64}:\d{5,20}", value):
        return value
    if re.fullmatch(r"\d{5,20}", value):
        # Bare custom emoji id is accepted as a shorthand.
        return f"_:{value}"
    return value


def snowflake_list(values: list[str], *, field: str, limit: int = 100) -> list[str]:
    if not isinstance(values, list) or not values:
        raise InvalidArgument(f"{field} must be a non-empty list of snowflakes")
    if len(values) > limit:
        raise InvalidArgument(f"{field} accepts at most {limit} entries")
    return [snowflake(value, f"{field}[]") for value in values]
