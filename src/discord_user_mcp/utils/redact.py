"""Keep secrets out of logs, error payloads and audit records."""

from __future__ import annotations

import logging
import re
from typing import Iterable

REDACTED = "[REDACTED]"

_SECRETS: set[str] = set()
# A Discord token is three dot separated base64url-ish chunks, sometimes with
# an ``mfa.`` prefix. Matching the shape catches leaked values even when the
# exact token was never registered.
_TOKEN_SHAPE = re.compile(r"(?i)\b(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{20,}\b")
_AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization)\b\s*[:=]\s*\S+")
_SENSITIVE_KEYS = re.compile(
    r"(?i)\b(password|passwd|secret|token|cookie|authorization|session_id|mfa_code)\b\s*[:=]\s*(\"[^\"]*\"|'[^']*'|\S+)"
)


def register_secret(value: str | None) -> None:
    """Remember a secret so every log line and payload can scrub it."""
    if value and len(value) >= 8:
        _SECRETS.add(value)


def redact(text: str) -> str:
    if not text:
        return text
    for secret in _SECRETS:
        if secret in text:
            text = text.replace(secret, REDACTED)
    text = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}: {REDACTED}", text)
    text = _TOKEN_SHAPE.sub(REDACTED, text)
    text = _SENSITIVE_KEYS.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return text


def redact_value(value: object, *, depth: int = 0) -> object:
    """Recursively scrub strings inside JSON-like structures."""
    if depth > 12:
        return value
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if str(key).lower() in {"token", "authorization", "password", "secret", "cookie"}:
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact_value(item, depth=depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_value(item, depth=depth + 1) for item in value]
    return value


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs registered secrets from every record."""

    def __init__(self, extra_secrets: Iterable[str] = ()) -> None:
        super().__init__()
        for secret in extra_secrets:
            register_secret(secret)

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - logging API
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        record.msg = redact(message)
        record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s | %(message)s", "%H:%M:%S")
    )
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # httpx logs full request URLs; keep it quiet unless explicitly debugging.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
