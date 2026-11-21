"""Response budget configuration, persistence and legacy dashboard migration."""

import json

import pytest
from pydantic import ValidationError

from discord_user_mcp.config import (
    DashboardSettings, Settings, apply_dashboard_settings, dashboard_settings_from,
    dashboard_settings_path, load_dashboard_settings, save_dashboard_settings,
)
from discord_user_mcp.utils.responses import DEFAULT_RESPONSE_BYTES, HARD_RESPONSE_BYTES


def test_response_configuration_defaults(settings):
    assert settings.response_default_bytes == DEFAULT_RESPONSE_BYTES
    assert settings.response_max_bytes == HARD_RESPONSE_BYTES
    snapshot = dashboard_settings_from(settings)
    assert snapshot.response_default_bytes == DEFAULT_RESPONSE_BYTES
    assert snapshot.response_max_bytes == HARD_RESPONSE_BYTES


@pytest.mark.parametrize("model", [Settings, DashboardSettings])
@pytest.mark.parametrize("values", [
    {"response_default_bytes": 1023},
    {"response_max_bytes": HARD_RESPONSE_BYTES + 1},
    {"response_default_bytes": 8192, "response_max_bytes": 4096},
    {"response_default_bytes": True},
    {"response_default_bytes": "4096"},
    {"response_max_bytes": 16777216.0},
])
def test_invalid_budget_settings_are_rejected(model, values):
    with pytest.raises(ValidationError):
        model(**values)


def test_environment_budget_settings(tmp_path):
    settings = Settings.from_env({
        "DISCORD_MCP_STATE_DIR": str(tmp_path),
        "DISCORD_MCP_RESPONSE_DEFAULT_BYTES": "4096",
        "DISCORD_MCP_RESPONSE_MAX_BYTES": "8192",
    })
    assert settings.response_default_bytes == 4096
    assert settings.response_max_bytes == 8192
    with pytest.raises(ValidationError):
        Settings.from_env({"DISCORD_MCP_STATE_DIR": str(tmp_path),
                          "DISCORD_MCP_RESPONSE_DEFAULT_BYTES": "8192",
                          "DISCORD_MCP_RESPONSE_MAX_BYTES": "4096"})


def test_response_limits_persist_and_apply_live(settings):
    candidate = DashboardSettings(response_default_bytes=4096, response_max_bytes=8192)
    save_dashboard_settings(settings.state_dir, candidate)
    restored = load_dashboard_settings(settings.state_dir)
    assert restored == candidate
    apply_dashboard_settings(settings, restored)
    assert settings.response_default_bytes == 4096
    assert settings.response_max_bytes == 8192


def test_legacy_dashboard_preserves_new_environment_limits(settings):
    settings.response_default_bytes = 4096
    settings.response_max_bytes = 8192
    path = dashboard_settings_path(settings.state_dir)
    path.write_text(json.dumps({"read_only": True}), encoding="utf-8")
    restored = load_dashboard_settings(settings.state_dir)
    apply_dashboard_settings(settings, restored)
    assert settings.read_only is True
    assert settings.response_default_bytes == 4096
    assert settings.response_max_bytes == 8192
