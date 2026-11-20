"""Run the real dashboard translation functions without a Discord connection."""

from pathlib import Path
import shutil
import subprocess

import pytest

from discord_user_mcp.security.console import LOCKED_PAGE, PAGE


@pytest.mark.parametrize("page,mode", [(PAGE, "dashboard"), (LOCKED_PAGE, "locked")], ids=["dashboard", "locked"])
def test_dashboard_locale_switch_preserves_inputs_and_translates_dynamic_text(page: str, mode: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the dashboard JavaScript regression test")
    script = page.split("<script>", 1)[1].split("</script>", 1)[0]
    result = subprocess.run(
        [node, str(Path(__file__).with_name("dashboard_i18n.cjs")), mode],
        input=script, text=True, encoding="utf-8", capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
