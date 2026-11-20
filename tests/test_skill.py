"""The agent-facing skill stays complete and preserves the approval boundary."""

from __future__ import annotations

from pathlib import Path

from discord_user_mcp.tools import TOOL_SPECS


SKILL_DIR = Path(__file__).parents[1] / "skills" / "discord-user"


def _skill_text() -> str:
    return "\n".join(
        (SKILL_DIR / name).read_text(encoding="utf-8")
        for name in ("SKILL.md", "API_GUIDE.md")
    )


def test_api_guide_routes_every_registered_tool() -> None:
    text = _skill_text()
    missing = [name for name in sorted(TOOL_SPECS) if f"`{name}`" not in text]
    assert missing == []


def test_skill_reports_only_the_safe_dashboard_url() -> None:
    text = _skill_text()
    assert "`console.dashboard_url`" in text
    assert "request ID" in text
    assert "Never request, print, or repeat" in text
    assert "request ID only, no access token" in text
