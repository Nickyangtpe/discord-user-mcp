"""End-to-end: a real MCP stdio session against a stub Discord HTTP server.

This is the test that proves the whole chain works: MCP client -> tool ->
approval gate -> local console -> HTTP request -> Discord stub -> result back
through ``check_approval``. No real token and no real Discord traffic.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from urllib.parse import urlsplit

from conftest import TEST_TOKEN

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class StubDiscord:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes]] = []
        self.lock = threading.Lock()
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # noqa: A003
                pass

            def _reply(self, status: int, payload: Any) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                with stub.lock:
                    stub.requests.append(("GET", self.path, b""))
                if self.path.endswith("/users/@me"):
                    self._reply(200, {"id": "1" * 18, "username": "e2e-user", "bot": False})
                    return
                self._reply(404, {"message": "not found", "code": 10003})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                with stub.lock:
                    stub.requests.append(("POST", self.path, body))
                if "/channels/" in self.path and self.path.endswith("/messages"):
                    payload = json.loads(body or b"{}")
                    self._reply(
                        200,
                        {
                            "id": "2" * 18,
                            "channel_id": "3" * 18,
                            "content": payload.get("content", ""),
                            "author": {"id": "1" * 18, "username": "e2e-user"},
                        },
                    )
                    return
                self._reply(404, {"message": "not found", "code": 10003})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}/api/v9"
        self.posts = lambda: [r for r in self.requests if r[0] == "POST"]  # noqa: E731

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def payload_of(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured:
        if set(structured) == {"result"}:
            return structured["result"]
        return structured
    return json.loads(result.content[0].text)


def data_of(result: Any) -> Any:
    """Unwrap the standard tool envelope for read-only tools."""
    payload = payload_of(result)
    if isinstance(payload, dict) and payload.get("status") == "ok" and "data" in payload:
        return payload["data"]
    return payload


def wait_for_console(state_dir: Path, timeout: float = 20.0) -> dict[str, Any]:
    path = state_dir / "approval-console.json"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                pass
        time.sleep(0.1)
    raise AssertionError("the approval console never wrote its token file")


@pytest.mark.asyncio
async def test_full_approval_round_trip(tmp_path: Path) -> None:
    stub = StubDiscord()
    state_dir = tmp_path / "state"
    env = {
        **os.environ,
        "PYTHONPATH": str(SRC),
        "DISCORD_USER_TOKEN": TEST_TOKEN,
        "DISCORD_MCP_API_BASE": stub.base_url,
        "DISCORD_MCP_STATE_DIR": str(state_dir),
        "DISCORD_MCP_CONSOLE_TOKEN": "e2e-console-token",
        "DISCORD_MCP_LOG_LEVEL": "WARNING",
    }
    params = StdioServerParameters(
        command=os.sys.executable,
        args=["-m", "discord_user_mcp.server"],
        env=env,
        cwd=str(ROOT),
    )
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = await session.list_tools()
                assert len(tools.tools) >= 110
                assert not any("approve" in tool.name for tool in tools.tools)

                me = payload_of(await session.call_tool("get_current_user", {}))
                assert me["status"] == "ok"
                assert me["data"]["username"] == "e2e-user"

                created = payload_of(
                    await session.call_tool(
                        "send_message",
                        {
                            "channel_id": "3" * 18,
                            "content": "hello from e2e",
                        },
                    )
                )
                assert created["status"] == "approval_required"
                approval_id = created["approval_id"]
                assert stub.posts() == []

                console = wait_for_console(state_dir)
                console_port = urlsplit(console["url"]).port
                headers = {"X-Approval-Token": "e2e-console-token"}
                async with httpx.AsyncClient() as http:
                    response = await http.post(
                        f"http://127.0.0.1:{console_port}/api/approve",
                        headers=headers,
                        json={"id": approval_id},
                        timeout=20,
                    )
                assert response.status_code == 200, response.text

                final: dict[str, Any] = {}
                for _ in range(150):
                    final = data_of(
                        await session.call_tool("check_approval", {"approval_id": approval_id})
                    )
                    if final["status"] in {"completed", "failed", "denied"}:
                        break
                    await asyncio.sleep(0.1)
                assert final["status"] == "completed", final
                assert final["result"]["content"] == "hello from e2e"
                posts = stub.posts()
                assert len(posts) == 1
                assert json.loads(posts[0][2])["content"] == "hello from e2e"
    finally:
        stub.close()
