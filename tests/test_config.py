"""Configuration and credential tests: user tokens only, safe defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from discord_user_mcp.api.errors import ConfigError
from discord_user_mcp.config import (
    ApprovalSettings,
    Settings,
    load_env_file,
    resolve_token,
    validate_user_token,
)

VALID = "A" * 24 + "." + "B" * 6 + "." + "C" * 27


def test_accepts_plain_user_token() -> None:
    assert validate_user_token(VALID) == VALID
    assert validate_user_token("  " + VALID + "\n") == VALID


def test_accepts_two_part_token() -> None:
    assert validate_user_token("a" * 24 + "." + "b" * 30)


def test_accepts_mfa_prefixed_token() -> None:
    assert validate_user_token("mfa." + VALID).startswith("mfa.")


@pytest.mark.parametrize(
    "bad",
    [
        "Bot " + VALID,
        "BOT " + VALID,
        "bearer " + VALID,
        "your_token_here",
        "",
        "   ",
        "not a token with spaces",
        "one-part-token",
        "abcd.efgh.ijkl.mnop.qrst",
    ],
)
def test_rejects_non_user_tokens(bad: str) -> None:
    with pytest.raises(ConfigError):
        validate_user_token(bad)


def test_bot_token_env_without_user_token_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="user token"):
        resolve_token({"DISCORD_BOT_TOKEN": VALID}, tmp_path)


def test_token_file_is_read(tmp_path: Path) -> None:
    path = tmp_path / "token.txt"
    path.write_text(VALID, encoding="utf-8")
    token, source = resolve_token({"DISCORD_USER_TOKEN_FILE": str(path)}, tmp_path)
    assert token is not None and token.get_secret_value() == VALID
    assert source == "file:token.txt"


def test_missing_token_is_none(tmp_path: Path) -> None:
    token, source = resolve_token({}, tmp_path)
    assert token is None and source == "unset"


def test_settings_from_env(tmp_path: Path) -> None:
    settings = Settings.from_env(
        {
            "DISCORD_USER_TOKEN": VALID,
            "DISCORD_MCP_STATE_DIR": str(tmp_path),
            "DISCORD_MCP_APPROVAL_TTL": "120",
            "DISCORD_MCP_READ_ONLY": "1",
            "DISCORD_MCP_MAX_UPLOAD_FILES": "3",
            "DISCORD_MCP_API_BASE": "http://127.0.0.1:9999/api/v9",
        }
    )
    assert settings.token is not None
    assert settings.approval.ttl_seconds == 120
    assert settings.read_only is True
    assert settings.upload.max_files == 3
    assert settings.http.base_url == "http://127.0.0.1:9999/api/v9"
    assert settings.state_dir == tmp_path


def test_console_must_bind_loopback() -> None:
    with pytest.raises(ValueError, match="loopback"):
        ApprovalSettings(console_host="0.0.0.0")
    assert ApprovalSettings(console_host="127.0.0.1").console_host == "127.0.0.1"


def test_require_token_explains_missing_token(tmp_path: Path) -> None:
    settings = Settings(state_dir=tmp_path)
    with pytest.raises(ConfigError, match="DISCORD_USER_TOKEN"):
        settings.require_token()


def test_load_env_file_sets_only_missing_keys(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "# comment\n\n"
        "DISCORD_MCP_APPROVAL_TTL=120\n"
        "export DISCORD_MCP_READ_ONLY='1'\n"
        'DISCORD_MCP_LOG_LEVEL="DEBUG"\n'
        "DISCORD_MCP_KEEP=from_file\n"
        "not a pair\n",
        encoding="utf-8",
    )
    env = {"DISCORD_MCP_KEEP": "from_shell"}
    loaded = load_env_file(path, env)
    assert env["DISCORD_MCP_APPROVAL_TTL"] == "120"
    assert env["DISCORD_MCP_READ_ONLY"] == "1"
    assert env["DISCORD_MCP_LOG_LEVEL"] == "DEBUG"
    # The shell wins over the file.
    assert env["DISCORD_MCP_KEEP"] == "from_shell"
    assert "DISCORD_MCP_KEEP" not in loaded
    assert "not a pair" not in " ".join(loaded)


def test_load_env_file_missing_file_is_a_no_op(tmp_path: Path) -> None:
    env: dict[str, str] = {}
    assert load_env_file(tmp_path / "missing.env", env) == []
    assert env == {}


def test_load_env_file_handles_a_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_bytes(b"\xef\xbb\xbfDISCORD_MCP_APPROVAL_TTL=60\n")
    env: dict[str, str] = {}
    assert load_env_file(path, env) == ["DISCORD_MCP_APPROVAL_TTL"]
    assert env["DISCORD_MCP_APPROVAL_TTL"] == "60"


def test_env_file_values_flow_into_settings(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        f"DISCORD_USER_TOKEN={VALID}\n"
        f"DISCORD_MCP_STATE_DIR={tmp_path / 'state'}\n"
        "DISCORD_MCP_APPROVAL_TTL=90\n",
        encoding="utf-8",
    )
    env: dict[str, str] = {}
    load_env_file(path, env)
    settings = Settings.from_env(env)
    assert settings.token is not None
    assert settings.approval.ttl_seconds == 90
    assert settings.state_dir == tmp_path / "state"
