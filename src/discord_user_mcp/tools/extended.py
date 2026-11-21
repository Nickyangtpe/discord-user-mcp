"""Typed, endpoint-specific tools from a fixed reviewed catalog.

No caller can supply a method, route, arbitrary body or extra wire field.
Generated signatures are real MCP schemas, and the same validation runs before
an approval is created and again before execution.
"""

from __future__ import annotations

import inspect
import json
import re
from datetime import datetime
from importlib import resources
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, ConfigDict, Field, ValidationError as ModelError, create_model

from ..api.errors import ValidationError
from ..api.registry import get_registry
from ..security.permissions import Risk
from ..utils.redact import redact_value
from ._common import Snowflake, call
from .specs import define_tool


def _timestamp(value: str) -> str:
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must be ISO 8601 with a timezone") from None
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value


TYPES = {
    "snowflake": Snowflake,
    "snowflakes": Annotated[list[Snowflake], Field(min_length=1, max_length=100)],
    "role_ids": Annotated[list[Snowflake], Field(max_length=100)],
    "text": Annotated[str, Field(min_length=1, max_length=1024)],
    "name": Annotated[str, Field(min_length=1, max_length=100)],
    "asset_name": Annotated[str, Field(min_length=2, max_length=32)],
    "sticker_name": Annotated[str, Field(min_length=2, max_length=30)],
    "sticker_description": Annotated[str, Field(max_length=100)],
    "sticker_tags": Annotated[str, Field(min_length=1, max_length=200)],
    "template_description": Annotated[str, Field(max_length=120)],
    "welcome_description": Annotated[str, Field(max_length=140)],
    "tag_name": Annotated[str, Field(min_length=1, max_length=20)],
    "emoji_name": Annotated[str, Field(min_length=1, max_length=32)],
    "description": Annotated[str, Field(max_length=1024)],
    "topic": Annotated[str, Field(min_length=1, max_length=120)],
    "code": Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")],
    "locale": Annotated[str, Field(min_length=2, max_length=16, pattern=r"^[A-Za-z-]+$")],
    "timestamp": Annotated[str, Field(max_length=64), AfterValidator(_timestamp)],
    "bool": bool,
    "limit50": Annotated[int, Field(ge=1, le=50)],
    "limit100": Annotated[int, Field(ge=1, le=100)],
    "limit1000": Annotated[int, Field(ge=1, le=1000)],
    "offset": Annotated[int, Field(ge=0, le=100000)],
    "nonnegative": Annotated[int, Field(ge=0, le=2147483647)],
    "volume": Annotated[float, Field(ge=0, le=1)],
    "privacy_level": Literal[2],
    "expire_behavior": Literal[0, 1],
    "grace_period": Literal[1, 3, 7, 14, 30],
}

CATALOG = json.loads(
    resources.files("discord_user_mcp.api").joinpath("extended_tools.json").read_text("utf-8")
)


def _register(item: dict[str, Any]) -> None:
    name = item["name"]
    endpoint_id = "extended." + name
    endpoint = get_registry().get(endpoint_id)
    risk = Risk(item.get("risk", "read"))
    if endpoint.method != "GET" and risk is Risk.READ:
        raise ValueError(f"mutating endpoint {name} cannot be classified read-only")
    if (endpoint.method, endpoint.path, endpoint.risk) != (item["method"], item["path"], risk):
        raise ValueError(f"catalog/registry mismatch for {name}")
    paths = re.findall(r"\{([^}]+)\}", endpoint.path)
    fields: dict[str, tuple[Any, Any]] = {}
    required = set(item.get("required", []))
    for key in paths:
        fields[key] = (TYPES["code"] if key.endswith("_code") else Snowflake, ...)
    aliases = item.get("body_aliases", {})
    for section in ("query", "body"):
        for wire_name, type_name in item.get(section, {}).items():
            key = aliases.get(wire_name, wire_name) if section == "body" else wire_name
            if key in fields:
                raise ValueError(f"duplicate argument {key} in {name}")
            annotation = TYPES[type_name]
            fields[key] = (annotation, ...) if wire_name in required else (annotation | None, None)
    if risk.requires_approval:
        fields["dry_run"] = (bool, False)
    model = create_model(name + "Arguments", __config__=ConfigDict(extra="forbid", strict=True), **fields)

    def validate_args(args: dict[str, Any]) -> dict[str, Any]:
        try:
            values = model.model_validate(args).model_dump()
        except ModelError as exc:
            # Omit rejected values from error messages: a misplaced credential
            # must not be echoed back to the AI or logged in an exception.
            issues = "; ".join(
                f"{'.'.join(map(str, e['loc']))}: {e['msg']}"
                for e in exc.errors(include_input=False, include_url=False)
            )
            raise ValidationError(issues) from None
        for group in item.get("exclusive", []):
            if sum(values.get(key) is not None for key in group) > 1:
                raise ValidationError("Use only one of " + ", ".join(group))
        if values.get("before") is not None and values.get("after") is not None:
            raise ValidationError("Use only one pagination cursor: before or after")
        if item.get("body") and endpoint.method == "PATCH":
            if not any(values.get(aliases.get(k, k)) is not None for k in item["body"]):
                raise ValidationError("Supply at least one field to update")
        return values

    async def operation(**kwargs: Any) -> Any:
        values = validate_args(kwargs)
        query = {
            k: values[k] for k in item.get("query", {}) if values[k] is not None
        }
        payload = {
            k: values[aliases.get(k, k)]
            for k in item.get("body", {}) if values[aliases.get(k, k)] is not None
        }
        result = await call(
            endpoint_id,
            path_params={k: values[k] for k in paths},
            params=query or None,
            payload=payload if item.get("body") else None,
        )
        # Connections can contain third-party access_token fields even on GET.
        # Filter all extended responses, including nested integrations.
        return redact_value(result)

    operation.__name__ = name
    operation.__annotations__ = {k: annotation for k, (annotation, _) in fields.items()}
    operation.__annotations__["return"] = Any
    operation.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [inspect.Parameter(k, inspect.Parameter.KEYWORD_ONLY,
                           annotation=annotation,
                           default=inspect.Parameter.empty if default is ... else default)
         for k, (annotation, default) in fields.items()], return_annotation=Any
    )
    description = endpoint.title + ". " + (
        "Read-only; requires access to the resource."
        if risk is Risk.READ else
        "Creates an expiring, parameter-bound human approval; sends nothing until approved."
    ) + " Availability depends on Discord permissions and rollout."
    if item.get("body"):
        description += " Exposes only the documented fields in this schema; null/omitted fields are not sent."
    wrapper = define_tool(
        name=name, description=description, risk=risk, endpoint_id=endpoint_id,
        summary=endpoint.title + (" in {" + paths[0] + "}" if paths else ""),
        target_fields=tuple(paths) + tuple(aliases.values()), validate=validate_args,
    )(operation)
    globals()[name] = wrapper


for _item in CATALOG:
    _register(_item)
