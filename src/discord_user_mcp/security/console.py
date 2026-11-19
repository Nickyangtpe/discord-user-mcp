"""Local human approval console.

An MCP client is not guaranteed to have a confirmation UI, so the server ships
its own: a loopback-only HTTP page with a random per-process token.

Security properties
-------------------
* Binds to 127.0.0.1 (a non-loopback host is rejected by config validation).
* Every request needs the console token, compared in constant time.
* There is no CORS header, so a web page cannot read responses.
* The token is printed to stderr and (optionally) written to
  ``<state>/approval-console.json`` with 0600 permissions. It is never exposed
  through any MCP tool.
* Failed authentication attempts are rate limited.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..api.errors import ApprovalError, DiscordUserMCPError
from ..config import Settings, console_token_from_env
from .approval import ApprovalManager

logger = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
MAX_FAILED_ATTEMPTS = 20
FAILED_WINDOW_SECONDS = 60.0

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Discord MCP approval console</title>
<style>
  :root { color-scheme: dark; --bg:#111318; --panel:#191c23; --line:#2a2f3a;
          --text:#e6e8ee; --muted:#9aa3b2; --ok:#3ddc84; --no:#ff5d5d; --warn:#ffb020; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font:14px/1.5 ui-sans-serif, system-ui, "Segoe UI", sans-serif; }
  header { padding:18px 22px; border-bottom:1px solid var(--line);
           display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; }
  h1 { font-size:16px; margin:0; font-weight:600; letter-spacing:.2px; }
  .sub { color:var(--muted); font-size:12px; }
  main { padding:20px; max-width:980px; margin:0 auto; display:grid; gap:16px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
  .card.pending { border-left:4px solid var(--warn); }
  .row { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; align-items:center; }
  .tool { font-family:ui-monospace, Consolas, monospace; font-size:14px; }
  .badge { font-size:11px; text-transform:uppercase; letter-spacing:.6px;
           padding:2px 8px; border-radius:999px; border:1px solid var(--line); }
  .badge.read { color:var(--ok); } .badge.write { color:#7cc4ff; }
  .badge.admin { color:var(--warn); } .badge.destructive { color:var(--no); }
  .badge.sensitive { color:#ff9de2; }
  .target { color:var(--muted); margin:6px 0 10px; }
  pre { background:#0d0f13; border:1px solid var(--line); border-radius:8px;
        padding:12px; overflow:auto; max-height:320px; font-size:12px; }
  .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; }
  button { border-radius:8px; border:1px solid var(--line); background:#222734;
           color:var(--text); padding:9px 16px; cursor:pointer; font-size:13px; }
  button.ok { background:#12351f; border-color:#1f6b3c; color:#9df5bd; }
  button.no { background:#3a1616; border-color:#7a2a2a; color:#ffb3b3; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  input[type=text] { background:#0d0f13; border:1px solid var(--line); color:var(--text);
                     border-radius:8px; padding:9px 12px; font-family:ui-monospace, monospace; }
  .empty { color:var(--muted); text-align:center; padding:28px 0; }
  .toast { position:fixed; right:18px; bottom:18px; background:#20242e; border:1px solid var(--line);
           padding:12px 16px; border-radius:10px; display:none; max-width:420px; }
  .toast.show { display:block; }
  footer { color:var(--muted); font-size:12px; padding:0 22px 28px; max-width:980px; margin:0 auto; }
  code { font-family:ui-monospace, Consolas, monospace; }
</style>
</head>
<body>
<header>
  <div>
    <h1>Discord MCP &middot; approval console</h1>
    <div class="sub">Nothing is sent to Discord until you approve it here.</div>
  </div>
  <div class="sub" id="status">connecting…</div>
</header>
<main>
  <div id="pending"></div>
  <div>
    <div class="sub" style="margin-bottom:8px">Recent decisions</div>
    <div id="recent" class="card"></div>
  </div>
</main>
<footer>
  Every approval is single-use and expires. Approving never happens through the
  AI client: only this page can authorise an operation.
</footer>
<div class="toast" id="toast"></div>
<script>
const token = new URLSearchParams(location.search).get('t') || '';
const pendingEl = document.getElementById('pending');
const recentEl = document.getElementById('recent');
const statusEl = document.getElementById('status');
const toastEl = document.getElementById('toast');

function toast(msg, bad) {
  toastEl.textContent = msg;
  toastEl.style.borderColor = bad ? '#7a2a2a' : '#1f6b3c';
  toastEl.classList.add('show');
  setTimeout(() => toastEl.classList.remove('show'), 4000);
}

async function api(path, options) {
  const opts = options || {};
  opts.headers = Object.assign({'X-Approval-Token': token}, opts.headers || {});
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.message || ('HTTP ' + res.status));
  return body;
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function render(a) {
  const card = el('div', 'card pending');
  const row = el('div', 'row');
  const left = el('div');
  left.appendChild(el('div', 'tool', a.tool));
  left.appendChild(el('div', 'sub', a.summary));
  row.appendChild(left);
  row.appendChild(el('span', 'badge ' + a.risk, a.risk));
  card.appendChild(row);
  card.appendChild(el('div', 'target', 'target: ' + (a.target || 'n/a') +
    '  •  expires in ' + a.expires_in_seconds + 's  •  id ' + a.approval_id.slice(0, 12)));
  const pre = el('pre');
  pre.textContent = JSON.stringify(a.args, null, 2);
  card.appendChild(pre);

  const actions = el('div', 'actions');
  const approve = el('button', 'ok', 'Approve and execute');
  const deny = el('button', 'no', 'Deny');
  let confirmInput = null;
  if (a.requires_typed_confirmation) {
    confirmInput = el('input');
    confirmInput.type = 'text';
    confirmInput.placeholder = 'type ' + a.approval_phrase;
    confirmInput.setAttribute('aria-label', 'confirmation phrase');
    actions.appendChild(confirmInput);
    approve.disabled = true;
    confirmInput.addEventListener('input', () => {
      approve.disabled = confirmInput.value.trim() !== a.approval_phrase;
    });
  }
  approve.addEventListener('click', async () => {
    approve.disabled = true;
    try {
      await api('/api/approve', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: a.approval_id, confirmation: confirmInput ? confirmInput.value : null})
      });
      toast('Approved. The server is executing it now.');
      refresh();
    } catch (err) { toast(err.message, true); approve.disabled = false; }
  });
  deny.addEventListener('click', async () => {
    deny.disabled = true; approve.disabled = true;
    try {
      await api('/api/deny', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: a.approval_id, reason: 'denied in console'})
      });
      toast('Denied. Nothing was sent to Discord.');
      refresh();
    } catch (err) { toast(err.message, true); deny.disabled = false; }
  });
  actions.appendChild(approve);
  actions.appendChild(deny);
  card.appendChild(actions);
  return card;
}

function renderRecent(items) {
  recentEl.textContent = '';
  if (!items.length) { recentEl.appendChild(el('div', 'empty', 'No decisions yet.')); return; }
  items.forEach(a => {
    const row = el('div', 'row');
    row.style.padding = '6px 0';
    const left = el('div');
    left.appendChild(el('span', 'tool', a.tool + ' '));
    left.appendChild(el('span', 'sub', '· ' + (a.target || '') + ' · ' + (a.decided_at || a.created_at)));
    row.appendChild(left);
    row.appendChild(el('span', 'badge ' + a.risk, a.status));
    recentEl.appendChild(row);
  });
}

async function refresh() {
  try {
    const state = await api('/api/state');
    statusEl.textContent = state.server.tool_count + ' tools · read-only: ' +
      (state.server.read_only ? 'yes' : 'no') + ' · ' + state.pending.length + ' pending';
    pendingEl.textContent = '';
    if (!state.pending.length) {
      const empty = el('div', 'card');
      empty.appendChild(el('div', 'empty', 'Nothing waiting for approval.'));
      pendingEl.appendChild(empty);
    } else {
      state.pending.forEach(a => pendingEl.appendChild(render(a)));
    }
    renderRecent(state.recent);
  } catch (err) {
    statusEl.textContent = 'not connected: ' + err.message;
  }
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "DiscordMCPApproval/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Never log the query string: it carries the console token.
        path = urlparse(self.path).path
        logger.debug("approval console %s %s", self.command, path)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _error(self, status: int, message: str, code: str = "console_error") -> None:
        self._json(status, {"code": code, "message": message})

    def _auth_ok(self) -> bool:
        console = self.server.console  # type: ignore[attr-defined]
        if console.locked_out(self.client_address[0]):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "Too many failed attempts; wait a minute.")
            return False
        supplied = self.headers.get("X-Approval-Token") or ""
        if not supplied:
            query = parse_qs(urlparse(self.path).query)
            supplied = (query.get("t") or [""])[0]
        if hmac.compare_digest(supplied, console.token):
            console.note_success(self.client_address[0])
            return True
        console.note_failure(self.client_address[0])
        self._error(HTTPStatus.UNAUTHORIZED, "Missing or invalid approval console token.")
        return False

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise ValueError("body must be JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("body must be a JSON object")
        return payload

    def _call_manager(self, coro: Any) -> tuple[bool, Any]:
        console = self.server.console  # type: ignore[attr-defined]
        future = asyncio.run_coroutine_threadsafe(coro, console.loop)
        try:
            return True, future.result(timeout=20)
        except DiscordUserMCPError as exc:
            return False, exc
        except Exception as exc:  # noqa: BLE001
            return False, exc

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            if not self._auth_ok():
                return
            self._send(HTTPStatus.OK, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if path == "/api/state":
            if not self._auth_ok():
                return
            console = self.server.console  # type: ignore[attr-defined]
            pending = console.manager.list(statuses=["pending"], limit=50)
            recent = [
                item
                for item in console.manager.list(limit=20)
                if item["status"] != "pending"
            ][:12]
            self._json(
                HTTPStatus.OK,
                {
                    "server": {
                        "tool_count": console.tool_count,
                        "read_only": console.read_only,
                        "approval_ttl_seconds": console.ttl_seconds,
                    },
                    "pending": pending,
                    "recent": recent,
                },
            )
            return
        self._error(HTTPStatus.NOT_FOUND, "not found")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path not in {"/api/approve", "/api/deny", "/api/cancel"}:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self._auth_ok():
            return
        try:
            payload = self._body()
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        approval_id = payload.get("id")
        if not isinstance(approval_id, str) or not approval_id.startswith("ap_"):
            self._error(HTTPStatus.BAD_REQUEST, "id must be an approval id")
            return
        actor = f"console:{self.client_address[0]}"
        console = self.server.console  # type: ignore[attr-defined]
        manager: ApprovalManager = console.manager

        if path == "/api/approve":
            ok, result = self._call_manager(
                manager.approve(
                    approval_id,
                    actor=actor,
                    confirmation=payload.get("confirmation"),
                    note=payload.get("note"),
                )
            )
        elif path == "/api/deny":
            ok, result = self._call_manager(
                manager.deny(approval_id, actor=actor, reason=payload.get("reason"))
            )
        else:
            ok, result = self._call_manager(manager.cancel(approval_id, actor=actor))

        if ok:
            self._json(HTTPStatus.OK, result)
            return
        if isinstance(result, ApprovalError):
            self._json(HTTPStatus.CONFLICT, result.to_dict())
            return
        self._error(HTTPStatus.BAD_REQUEST, str(result), "approval_failed")


class _ConsoleServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that can also bind the IPv6 loopback."""

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, handler)


class ApprovalConsole:
    def __init__(
        self,
        settings: Settings,
        manager: ApprovalManager,
        *,
        token: str | None = None,
        tool_count: int = 0,
    ) -> None:
        self.settings = settings
        self.manager = manager
        self.token = token or console_token_from_env() or secrets.token_urlsafe(32)
        self.tool_count = tool_count
        self.read_only = settings.read_only
        self.ttl_seconds = settings.approval.ttl_seconds
        self.loop: asyncio.AbstractEventLoop | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._server is not None:
            return
        self.loop = loop
        host = self.settings.approval.console_host
        if host == "localhost":
            host = "127.0.0.1"
        server = _ConsoleServer((host, self.settings.approval.console_port), _Handler)
        server.daemon_threads = True
        server.console = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="approval-console", daemon=True)
        self._thread.start()
        self._write_token_file()
        logger.warning("Approval console ready: %s", self.url)
        logger.warning(
            "Open that URL to approve or deny pending Discord operations. "
            "The token in it is the only way in; it is never exposed to the AI."
        )

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        host = self.settings.approval.console_host
        if host == "localhost":
            host = "127.0.0.1"
        if ":" in host:
            return f"http://[{host}]:{self.port}/"
        return f"http://{host}:{self.port}/"

    @property
    def url(self) -> str:
        return f"{self.base_url}?t={self.token}"

    @property
    def safe_url(self) -> str:
        return self.base_url

    def _write_token_file(self) -> None:
        if not self.settings.approval.write_token_file:
            return
        path = Path(self.settings.state_dir) / "approval-console.json"
        payload = {
            "url": self.url,
            "token": self.token,
            "pid": os.getpid(),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": "Anyone who can read this file can approve operations. Keep it private.",
        }
        try:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError as exc:  # pragma: no cover
            logger.warning("could not write approval console token file: %s", exc)

    # -- brute force protection -------------------------------------------

    def locked_out(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            attempts = [t for t in self._failures.get(ip, []) if now - t < FAILED_WINDOW_SECONDS]
            self._failures[ip] = attempts
            return len(attempts) >= MAX_FAILED_ATTEMPTS

    def note_failure(self, ip: str) -> None:
        with self._lock:
            self._failures.setdefault(ip, []).append(time.time())

    def note_success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)
