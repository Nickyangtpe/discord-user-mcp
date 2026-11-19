"""Error taxonomy.

Every error carries a stable machine readable ``code`` so an agent can branch
on it, plus a human message. Error payloads are safe to log: they never
contain the Authorization header or the token.
"""

from __future__ import annotations

from typing import Any, Mapping


class DiscordUserMCPError(Exception):
    """Base class for every error this server raises deliberately."""

    code: str = "internal_error"
    retryable: bool = False
    http_status: int | None = None

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        details: Any = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status if status is not None else self.http_status
        self.details = details
        self.retry_after = retry_after

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.status is not None:
            payload["http_status"] = self.status
        if self.retry_after is not None:
            payload["retry_after"] = self.retry_after
        if self.details is not None:
            payload["details"] = self.details
        return payload

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


# --------------------------------------------------------------------------
# Configuration / local state
# --------------------------------------------------------------------------


class ConfigError(DiscordUserMCPError):
    code = "config_error"


class ValidationError(DiscordUserMCPError):
    code = "validation_error"


class UploadError(DiscordUserMCPError):
    code = "upload_rejected"


class ReadOnlyModeError(DiscordUserMCPError):
    code = "read_only_mode"

    def __init__(self) -> None:
        super().__init__(
            "This server is running in read-only mode (DISCORD_MCP_READ_ONLY=1); "
            "every mutating tool is disabled."
        )


# --------------------------------------------------------------------------
# Approval gate
# --------------------------------------------------------------------------


class ApprovalError(DiscordUserMCPError):
    code = "approval_error"


class ApprovalNotFound(ApprovalError):
    code = "approval_not_found"


class ApprovalExpired(ApprovalError):
    code = "approval_expired"


class ApprovalAlreadyDecided(ApprovalError):
    code = "approval_already_decided"


class ApprovalConfirmationRequired(ApprovalError):
    code = "approval_confirmation_required"


class ApprovalTampered(ApprovalError):
    code = "approval_arguments_tampered"


class ApprovalConsoleUnavailable(ApprovalError):
    code = "approval_console_unavailable"


# --------------------------------------------------------------------------
# Discord HTTP API
# --------------------------------------------------------------------------


class DiscordAPIError(DiscordUserMCPError):
    code = "discord_api_error"


class AuthenticationError(DiscordAPIError):
    code = "discord_unauthorized"


class ForbiddenError(DiscordAPIError):
    code = "discord_forbidden"


class NotFoundError(DiscordAPIError):
    code = "discord_not_found"


class PayloadRejected(DiscordAPIError):
    code = "discord_rejected_payload"


class RateLimitedError(DiscordAPIError):
    code = "discord_rate_limited"
    retryable = True


class DiscordServerError(DiscordAPIError):
    code = "discord_server_error"
    retryable = True


class NetworkError(DiscordAPIError):
    code = "discord_network_error"
    retryable = True


def _discord_message(payload: Any) -> str | None:
    if isinstance(payload, Mapping):
        message = payload.get("message")
        if isinstance(message, str) and message:
            return message
    return None


def from_http_response(
    status: int,
    payload: Any,
    headers: Mapping[str, str] | None = None,
    *,
    method: str,
    path: str,
) -> DiscordAPIError:
    headers = headers or {}
    message = _discord_message(payload)
    code_number = payload.get("code") if isinstance(payload, Mapping) else None
    details = {"discord_code": code_number} if code_number is not None else None
    if isinstance(payload, Mapping) and payload.get("errors"):
        details = {**(details or {}), "errors": payload["errors"]}

    if status == 401:
        return AuthenticationError(
            "Discord rejected the user token (HTTP 401). The token is invalid, expired, "
            "or was revoked. Update DISCORD_USER_TOKEN and restart the server.",
            status=status,
        )
    if status == 403:
        content_type = (headers.get("content-type") or "").lower()
        if "text/html" in content_type:
            return ForbiddenError(
                "Discord returned an HTML 403 (Cloudflare or a platform security check). "
                "This server does not and will not attempt to bypass those checks.",
                status=status,
            )
        return ForbiddenError(
            message
            or "Discord refused the request (HTTP 403): missing permission, blocked by a "
            "platform check, or the target is not accessible to this account.",
            status=status,
            details=details,
        )
    if status == 404:
        return NotFoundError(
            message or "Discord returned 404: the resource does not exist or is not visible.",
            status=status,
            details=details,
        )
    if status == 429:
        retry_after = None
        if isinstance(payload, Mapping):
            try:
                retry_after = float(payload.get("retry_after"))
            except (TypeError, ValueError):
                retry_after = None
        return RateLimitedError(
            "Discord rate limited the request (HTTP 429) and retries were exhausted.",
            status=status,
            retry_after=retry_after,
            details=details,
        )
    if 500 <= status <= 599:
        return DiscordServerError(
            message or f"Discord server error (HTTP {status}) after retries.",
            status=status,
            details=details,
        )
    if 400 <= status <= 499:
        return PayloadRejected(
            message or f"Discord rejected the request body (HTTP {status}).",
            status=status,
            details=details,
        )
    return DiscordAPIError(
        message or f"Unexpected Discord response (HTTP {status}) for {method} {path}.",
        status=status,
        details=details,
    )
