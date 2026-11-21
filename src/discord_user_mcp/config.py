"""Configuration loading.

A user token is the only supported credential. Bot tokens are rejected by
name *and* by a live check at startup (a bot token cannot authenticate as a
user through ``/users/@me`` without the ``Bot `` prefix).

Nothing here ever logs or returns the token. ``Settings.token`` is a
``SecretStr`` and the raw value is only handed to the HTTP client.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Mapping, MutableMapping

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .api.errors import ConfigError
from .utils.redact import register_secret
from .utils.responses import DEFAULT_RESPONSE_BYTES, HARD_RESPONSE_BYTES, MIN_RESPONSE_BYTES

APP_NAME = "discord-user-mcp"
DEFAULT_API_BASE = "https://discord.com/api/v9"
TOKEN_ENV_VARS = ("DISCORD_USER_TOKEN", "DISCORD_USER_TOKEN_FILE", "DISCORD_TOKEN")


def default_state_dir() -> Path:
    override = os.environ.get("DISCORD_MCP_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / APP_NAME


def load_env_file(
    path: str | Path = ".env", environ: MutableMapping[str, str] | None = None
) -> list[str]:
    """Load ``KEY=VALUE`` pairs from a dotenv file into the environment.

    Real environment variables always win, so a shell export overrides the file.
    The parser intentionally supports only the subset a dotenv needs: comments,
    blank lines, an optional ``export`` prefix, and single or double quoted
    values. A missing file is not an error. Returns the keys that were set.
    """
    env = os.environ if environ is None else environ
    file = Path(path)
    if not file.is_file():
        return []
    loaded: list[str] = []
    # utf-8-sig: Windows editors like Notepad may prefix the file with a BOM.
    for raw in file.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key not in env:
            env[key] = value
            loaded.append(key)
    return loaded


def _env_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from exc


def _env_float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a number, got {raw!r}") from exc


_TOKEN_CHARS = re.compile(r"^[\w.\-]+$")


def validate_user_token(token: str) -> str:
    """Reject clearly wrong credentials early, with actionable messages."""
    value = token.strip()
    if not value:
        raise ConfigError("Discord user token is empty")
    lowered = value.lower()
    if lowered.startswith("bot "):
        raise ConfigError(
            "A 'Bot ' prefixed token was supplied. This server only supports a Discord "
            "USER token; bot tokens are not a supported substitute."
        )
    if lowered.startswith("bearer "):
        raise ConfigError("Supply the raw token value, not an 'Bearer ' prefixed header value")
    if value in {"your_token_here", "changeme", "paste_token_here"}:
        raise ConfigError("The configured token is still a placeholder value")
    if not _TOKEN_CHARS.match(value):
        raise ConfigError("Token contains characters that are not valid in a Discord token")
    parts = value.removeprefix("mfa.").split(".")
    if len(parts) not in {2, 3}:
        raise ConfigError(
            "Token does not look like a Discord token (expected 2-3 dot separated parts)"
        )
    return value


def _read_token_file(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read token file at {path}: {exc.strerror}") from exc
    token = raw.strip()
    if not token:
        raise ConfigError(f"Token file at {path} is empty")
    return token


def resolve_token(env: Mapping[str, str], state_dir: Path) -> tuple[SecretStr | None, str]:
    """Return ``(token, source)`` without ever exposing the value."""
    if env.get("DISCORD_BOT_TOKEN") and not env.get("DISCORD_USER_TOKEN"):
        raise ConfigError(
            "DISCORD_BOT_TOKEN is set but no user token is configured. This project "
            "deliberately does not support bot tokens; export DISCORD_USER_TOKEN instead."
        )

    raw = env.get("DISCORD_USER_TOKEN")
    if raw:
        return SecretStr(validate_user_token(raw)), "env:DISCORD_USER_TOKEN"

    token_file = env.get("DISCORD_USER_TOKEN_FILE")
    if token_file:
        path = Path(token_file).expanduser()
        return SecretStr(validate_user_token(_read_token_file(path))), f"file:{path.name}"

    legacy = env.get("DISCORD_TOKEN")
    if legacy:
        return SecretStr(validate_user_token(legacy)), "env:DISCORD_TOKEN"

    default_file = state_dir / "token"
    if default_file.exists():
        return SecretStr(validate_user_token(_read_token_file(default_file))), "state:token"

    return None, "unset"


class ApprovalSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttl_seconds: int = Field(default=300, ge=30, le=3600)
    console_enabled: bool = True
    console_host: str = "127.0.0.1"
    console_port: int = Field(default=0, ge=0, le=65535)
    write_token_file: bool = True
    token_ttl_hint_seconds: int = Field(default=600, ge=60)

    @field_validator("console_host")
    @classmethod
    def _loopback_only(cls, value: str) -> str:
        if value not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError(
                "The approval console must bind to loopback (127.0.0.1/::1) only; "
                "exposing it on the network would let anyone approve operations"
            )
        return value


class HttpSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: str = DEFAULT_API_BASE
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_retries: int = Field(default=3, ge=0, le=10)
    max_rate_limit_retries: int = Field(default=5, ge=0, le=20)
    api_version: int = Field(default=9, ge=8, le=10)


class UploadSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_roots: list[Path] = Field(default_factory=list)
    max_bytes: int = Field(default=25 * 1024 * 1024, ge=1)
    max_files: int = Field(default=10, ge=1, le=10)
    enabled: bool = True


class Settings(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    token: SecretStr | None = None
    token_source: str = "unset"
    state_dir: Path = Field(default_factory=default_state_dir)
    read_only: bool = False
    require_startup_auth_check: bool = True
    log_level: str = "INFO"
    audit_enabled: bool = True
    response_default_bytes: int = Field(default=DEFAULT_RESPONSE_BYTES, ge=MIN_RESPONSE_BYTES, le=HARD_RESPONSE_BYTES, strict=True)
    response_max_bytes: int = Field(default=HARD_RESPONSE_BYTES, ge=MIN_RESPONSE_BYTES, le=HARD_RESPONSE_BYTES, strict=True)
    approval: ApprovalSettings = Field(default_factory=ApprovalSettings)
    http: HttpSettings = Field(default_factory=HttpSettings)
    upload: UploadSettings = Field(default_factory=UploadSettings)

    @model_validator(mode="after")
    def _response_budget_order(self) -> "Settings":
        if self.response_default_bytes > self.response_max_bytes:
            raise ValueError("response_default_bytes cannot exceed response_max_bytes")
        return self

    def require_token(self) -> str:
        if self.token is None:
            raise ConfigError(
                "No Discord user token configured. Set DISCORD_USER_TOKEN, "
                "DISCORD_USER_TOKEN_FILE, or place the token in "
                f"{self.state_dir / 'token'}."
            )
        return self.token.get_secret_value()

    def ensure_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "uploads").mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)
        state_dir = Path(env.get("DISCORD_MCP_STATE_DIR") or default_state_dir()).expanduser()
        token, source = resolve_token(env, state_dir)
        if token is not None:
            register_secret(token.get_secret_value())

        upload_roots = env.get("DISCORD_MCP_UPLOAD_ROOTS", "")
        roots = [Path(part).expanduser() for part in upload_roots.split(os.pathsep) if part.strip()]
        if not roots:
            roots = [state_dir / "uploads"]

        api_version = _env_int(env, "DISCORD_MCP_API_VERSION", 9)
        base = env.get("DISCORD_MCP_API_BASE") or f"https://discord.com/api/v{api_version}"

        approval = ApprovalSettings(
            ttl_seconds=_env_int(env, "DISCORD_MCP_APPROVAL_TTL", 300),
            console_enabled=_env_bool(env, "DISCORD_MCP_CONSOLE_ENABLED", True),
            console_host=env.get("DISCORD_MCP_CONSOLE_HOST", "127.0.0.1"),
            console_port=_env_int(env, "DISCORD_MCP_CONSOLE_PORT", 0),
            write_token_file=_env_bool(env, "DISCORD_MCP_CONSOLE_TOKEN_FILE", True),
        )
        http = HttpSettings(
            base_url=base,
            timeout_seconds=_env_float(env, "DISCORD_MCP_TIMEOUT", 30.0),
            connect_timeout_seconds=_env_float(env, "DISCORD_MCP_CONNECT_TIMEOUT", 10.0),
            max_retries=_env_int(env, "DISCORD_MCP_MAX_RETRIES", 3),
            max_rate_limit_retries=_env_int(env, "DISCORD_MCP_MAX_429_RETRIES", 5),
            api_version=api_version,
        )
        upload = UploadSettings(
            allowed_roots=roots,
            max_bytes=_env_int(env, "DISCORD_MCP_MAX_UPLOAD_BYTES", 25 * 1024 * 1024),
            max_files=_env_int(env, "DISCORD_MCP_MAX_UPLOAD_FILES", 10),
            enabled=_env_bool(env, "DISCORD_MCP_UPLOADS_ENABLED", True),
        )
        return cls(
            token=token,
            token_source=source,
            state_dir=state_dir,
            read_only=_env_bool(env, "DISCORD_MCP_READ_ONLY", False),
            require_startup_auth_check=not _env_bool(env, "DISCORD_MCP_SKIP_AUTH_CHECK", False),
            log_level=env.get("DISCORD_MCP_LOG_LEVEL", "INFO"),
            audit_enabled=_env_bool(env, "DISCORD_MCP_AUDIT", True),
            response_default_bytes=_env_int(env, "DISCORD_MCP_RESPONSE_DEFAULT_BYTES", DEFAULT_RESPONSE_BYTES),
            response_max_bytes=_env_int(env, "DISCORD_MCP_RESPONSE_MAX_BYTES", HARD_RESPONSE_BYTES),
            approval=approval,
            http=http,
            upload=upload,
        )


def console_token_from_env(environ: Mapping[str, str] | None = None) -> str | None:
    """Allow pinning the console token (tests/automation); otherwise random."""
    env = dict(os.environ if environ is None else environ)
    value = env.get("DISCORD_MCP_CONSOLE_TOKEN")
    return value or None


# --------------------------------------------------------------------------
# Dashboard settings
# --------------------------------------------------------------------------

DASHBOARD_SETTINGS_FILENAME = "dashboard-settings.json"
DASHBOARD_CONFIRMATION_PHRASE = "ENABLE WRITES"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# Fields a page served by the server may never change. Retargeting the API
# base or moving the console off loopback from that page would let a single
# click exfiltrate the token or expose approvals on the network.
DASHBOARD_LOCKED_KEYS = (
    "token",
    "api_base",
    "console_host",
    "console_port",
    "state_dir",
)


class DashboardSettings(BaseModel):
    """The settings a human may edit from the local dashboard.

    Persisted to ``<state>/dashboard-settings.json`` and applied at startup
    before logging and the HTTP client are built. Fields that only matter at
    startup (``require_startup_auth_check``) are labelled as such in the UI.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    read_only: bool = False
    log_level: str = "INFO"
    audit_enabled: bool = True
    require_startup_auth_check: bool = True
    approval_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    uploads_enabled: bool = True
    upload_max_bytes: int = Field(default=25 * 1024 * 1024, ge=1, le=1024 * 1024 * 1024)
    upload_max_files: int = Field(default=10, ge=1, le=10)
    http_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    http_max_429_retries: int = Field(default=5, ge=0, le=20)
    response_default_bytes: int = Field(default=DEFAULT_RESPONSE_BYTES, ge=MIN_RESPONSE_BYTES, le=HARD_RESPONSE_BYTES)
    response_max_bytes: int = Field(default=HARD_RESPONSE_BYTES, ge=MIN_RESPONSE_BYTES, le=HARD_RESPONSE_BYTES)

    @model_validator(mode="after")
    def _response_budget_order(self) -> "DashboardSettings":
        if self.response_default_bytes > self.response_max_bytes:
            raise ValueError("response_default_bytes cannot exceed response_max_bytes")
        return self

    @field_validator("log_level")
    @classmethod
    def _known_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in LOG_LEVELS:
            raise ValueError(f"log_level must be one of {', '.join(LOG_LEVELS)}")
        return level


def dashboard_settings_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / DASHBOARD_SETTINGS_FILENAME


def dashboard_settings_from(settings: Settings) -> DashboardSettings:
    """Snapshot the editable subset of a live :class:`Settings`."""
    return DashboardSettings(
        read_only=settings.read_only,
        log_level=settings.log_level,
        audit_enabled=settings.audit_enabled,
        require_startup_auth_check=settings.require_startup_auth_check,
        approval_ttl_seconds=settings.approval.ttl_seconds,
        uploads_enabled=settings.upload.enabled,
        upload_max_bytes=settings.upload.max_bytes,
        upload_max_files=settings.upload.max_files,
        http_timeout_seconds=settings.http.timeout_seconds,
        http_max_retries=settings.http.max_retries,
        http_max_429_retries=settings.http.max_rate_limit_retries,
        response_default_bytes=settings.response_default_bytes,
        response_max_bytes=settings.response_max_bytes,
    )


def apply_dashboard_settings(settings: Settings, value: DashboardSettings) -> Settings:
    """Copy dashboard values onto a live settings object, in place.

    Token, API base and console bind address are intentionally not touched, so
    a dashboard request can never redirect credentials or widen exposure.
    """
    settings.read_only = value.read_only
    settings.log_level = value.log_level
    settings.audit_enabled = value.audit_enabled
    settings.require_startup_auth_check = value.require_startup_auth_check
    settings.approval.ttl_seconds = value.approval_ttl_seconds
    settings.upload.enabled = value.uploads_enabled
    settings.upload.max_bytes = value.upload_max_bytes
    settings.upload.max_files = value.upload_max_files
    settings.http.timeout_seconds = value.http_timeout_seconds
    settings.http.max_retries = value.http_max_retries
    settings.http.max_rate_limit_retries = value.http_max_429_retries
    # Legacy dashboard files lack these fields; preserve new environment limits.
    if "response_default_bytes" in value.model_fields_set:
        settings.response_default_bytes = value.response_default_bytes
    if "response_max_bytes" in value.model_fields_set:
        settings.response_max_bytes = value.response_max_bytes
    return settings


def load_dashboard_settings(state_dir: str | Path) -> DashboardSettings | None:
    """Read persisted dashboard settings. Missing file means "not configured"."""
    path = dashboard_settings_path(state_dir)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"Could not read dashboard settings {path}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise ConfigError(f"Dashboard settings {path} are not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"Dashboard settings {path} must be a JSON object")
    try:
        return DashboardSettings.model_validate(payload)
    except ValueError as exc:
        raise ConfigError(f"Dashboard settings {path} are invalid: {exc}") from exc


def save_dashboard_settings(
    state_dir: str | Path, value: DashboardSettings
) -> Path:
    """Write settings atomically with owner-only permissions.

    The file holds no secret (the token is never included), but it does decide
    whether writes are allowed and where approvals expire, so it stays 0600.
    """
    path = dashboard_settings_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(value.model_dump(), indent=2, sort_keys=True) + "\n"
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(body, encoding="utf-8")
    try:
        os.chmod(temp, 0o600)
    except OSError:  # pragma: no cover - chmod is a no-op on some filesystems
        pass
    os.replace(temp, path)
    return path
