"""Token validation.

The only credential this project accepts is a Discord **user** token. A bot
token cannot work here: we never add the ``Bot `` prefix, and a bot
application token cannot authenticate ``GET /users/@me`` as the user.

``verify_identity`` is the authoritative check. It runs at startup (unless
explicitly skipped) and returns non-secret identity data for diagnostics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..api.client import DiscordClient
from ..api.errors import AuthenticationError, ConfigError, ForbiddenError

logger = logging.getLogger(__name__)


@dataclass
class Identity:
    user_id: str
    username: str
    global_name: str | None
    is_bot: bool

    def public(self) -> dict[str, object]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "global_name": self.global_name,
            "account_type": "bot" if self.is_bot else "user",
        }


async def verify_identity(client: DiscordClient) -> Identity:
    """Fetch ``/users/@me`` and refuse anything that is not a user account."""
    user = await client.request("GET", "/users/@me")
    if not isinstance(user, dict) or "id" not in user:
        raise ConfigError("Discord returned an unexpected payload for /users/@me")
    identity = Identity(
        user_id=str(user.get("id")),
        username=str(user.get("username", "")),
        global_name=user.get("global_name"),
        is_bot=bool(user.get("bot")),
    )
    if identity.is_bot:
        raise ConfigError(
            "This token authenticates a bot account. This project requires a Discord USER "
            "token and will not run as a bot."
        )
    return identity


async def startup_check(client: DiscordClient) -> tuple[bool, dict[str, object] | None, str | None]:
    """Return ``(ok, identity, note)`` without ever raising for network trouble.

    A 401 is fatal (bad token). A network failure is surfaced as a warning so
    the server can still start and expose its registry.
    """
    try:
        identity = await verify_identity(client)
    except AuthenticationError as exc:
        raise ConfigError(
            "The configured Discord user token is not valid (HTTP 401). "
            "Update DISCORD_USER_TOKEN and restart."
        ) from exc
    except ForbiddenError as exc:
        raise ConfigError(
            "Discord refused the token check (HTTP 403). The account may be locked or "
            "require an interactive verification step in the official client."
        ) from exc
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - network / DNS / timeout
        logger.warning("could not verify the token at startup (%s); continuing", type(exc).__name__)
        return False, None, f"startup verification failed: {type(exc).__name__}"
    logger.info(
        "authenticated as %s (%s)",
        identity.username,
        identity.user_id,
    )
    return True, identity.public(), None
