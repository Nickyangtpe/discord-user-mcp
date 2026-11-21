"""The single agent-facing skill stays complete and preserves the approval boundary."""

from __future__ import annotations

from pathlib import Path

from discord_user_mcp.tools import TOOL_SPECS


SKILL = Path(__file__).parents[1] / "skills" / "discord-user" / "SKILL.md"


def test_skill_is_a_single_file_that_routes_every_registered_tool() -> None:
    text = SKILL.read_text(encoding="utf-8")
    missing = [name for name in sorted(TOOL_SPECS) if f"`{name}`" not in text]
    assert missing == []
    # The merged skill must not depend on a second file the client may not load.
    for name in ("API_GUIDE", "API_GUIDE.md"):
        assert name not in text


def test_skill_reports_only_the_safe_dashboard_url() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "`console.dashboard_url`" in text
    assert "request ID" in text
    assert "Never request, print, or repeat" in text
    assert "token_file" in text
