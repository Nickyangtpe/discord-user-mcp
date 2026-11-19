# discord-user-mcp

An MCP server that exposes the **Discord user API** to an AI agent, with a hard,
server-side **human approval gate** in front of every state-changing operation.

It is a Python 3.12 project built on FastMCP (MCP SDK), httpx and Pydantic. It
speaks HTTP only: no gateway, no voice, no bot account.

> **Read this first.** Automating a normal Discord account (a "self-bot") violates
> Discord's Terms of Service and can get the account banned. Use this only on an
> account you are willing to lose, never against other people's servers, and never
> to evade rate limits, captchas or other platform controls. This project does not
> bypass any of them; when Discord blocks a request it reports the block.

---

## Why an approval gate

An MCP client cannot be trusted to be the last line of defence: the model can be
talked into anything, and many clients have no confirmation UI at all. So the gate
lives **inside the server process**, not in the client and not in the prompt.

```
agent calls send_message
        |
        v
dispatch() --- risk=read? --- yes --> HTTP request --> result
        |
        no
        v
create pending approval (SQLite)  <-- no HTTP request is made
        |
        v
return {status: "approval_required", approval_id, arguments, args_hash}

     ... a human opens the local console ...

approve(id) -- single-use SQL transition --> re-hash stored args --> execute
        |
        v
agent calls check_approval(id) --> completed / failed / denied / expired
```

Properties this design gives you:

| Property | How |
|---|---|
| The AI cannot approve its own call | There is no MCP tool that approves. `cancel_approval` can only cancel. |
| No request before approval | A mutating tool only writes a pending row; the HTTP client is not touched. |
| Approval is for the exact call | Arguments are stored and hashed; execution uses the stored arguments. |
| No parameter swapping | The digest is recomputed before execution; a mismatch fails the row. |
| No replay | `UPDATE ... WHERE status='pending'` makes decisions single-shot; the executor claims `approved -> executing` atomically. |
| No stale approvals | Pending rows expire (default 5 min) and expiry is enforced again at execution. |
| High-risk needs more than a click | `admin`, `destructive` and `sensitive` require the operator to type `APPROVE`. |
| A restart cannot resurrect work | On startup, `approved`/`executing` rows are marked `failed`. |
| The console is local | It binds to loopback, requires a random per-process token, sends no CORS headers and rate-limits failed attempts. |
| No token leak | The token is a `SecretStr`, never logged, redacted from every audit entry, and the console token is never exposed to MCP. |
| Auditable | JSONL audit log of requests, decisions and executions, with redaction. |
| Read-only switch | `DISCORD_MCP_READ_ONLY=1` disables every mutating tool. |

Threat model, honestly: this protects against a misled or over-eager agent and
against a client that silently auto-approves. It does not protect against malware
already running as your user, someone who can read your environment variables, or
someone who can read `approval-console.json`. Run it on a machine you control.

---

## Requirements

- Python **3.12+** (the repository is developed against the Windows embeddable
  build, see below)
- `mcp`, `httpx`, `pydantic`; `pytest` + `pytest-asyncio` for the tests
- A Discord **user** token. Bot tokens are explicitly unsupported.

## Install

Standard install:

```bash
pip install -e .
python -m discord_user_mcp --check     # validate config + token
python -m discord_user_mcp            # start the MCP server on stdio
```

Windows embeddable Python (what this repo was built with, no installer needed):

```powershell
# 1. Download the official zip and verify it
Invoke-WebRequest https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip -OutFile py312.zip
Get-FileHash py312.zip -Algorithm SHA256
# 4ACBED6DD1C744B0376E3B1CF57CE906F9DC9E95E68824584C8099A63025A3C3

Expand-Archive py312.zip -DestinationPath .python-embed
# .python-embed/python312._pth must contain, in order:
#   python312.zip
#   .
#   Lib\site-packages
#   ..\src
#   import site

uv pip install --python-version 3.12 --target .python-embed\Lib\site-packages `
  "mcp>=1.9,<2" "httpx>=0.27,<1" "pydantic>=2.7,<3" "pytest>=8.2" "pytest-asyncio>=0.23"

.\.python-embed\python.exe -m pytest
.\.python-embed\python.exe -m discord_user_mcp --check
```

## Configure

Copy `.env.example` to `.env` (or export the variables) and set
`DISCORD_USER_TOKEN`. `.env` is read from the working directory at startup;
real environment variables take precedence, and `DISCORD_MCP_ENV_FILE=0`
turns the file off. The most important knobs:

| Variable | Default | Meaning |
|---|---|---|
| `DISCORD_USER_TOKEN` / `DISCORD_USER_TOKEN_FILE` | unset | The user token. A `Bot ` prefix is rejected. |
| `DISCORD_MCP_STATE_DIR` | `%LOCALAPPDATA%\discord-user-mcp` | Approvals DB, audit log, console token, default uploads. |
| `DISCORD_MCP_APPROVAL_TTL` | `300` | Seconds a pending approval stays valid (30-3600). |
| `DISCORD_MCP_CONSOLE_ENABLED` | `1` | If `0`, every mutating tool refuses to run. |
| `DISCORD_MCP_CONSOLE_HOST` / `_PORT` | `127.0.0.1` / `0` | Loopback only; a non-loopback host is rejected. |
| `DISCORD_MCP_READ_ONLY` | `0` | `1` disables all writes. |
| `DISCORD_MCP_UPLOAD_ROOTS` | `<state>/uploads` | Allow-list for attachment paths (`os.pathsep` separated). |
| `DISCORD_MCP_MAX_UPLOAD_BYTES` | `26214400` | Per-file and total attachment cap. |
| `DISCORD_MCP_API_BASE` | `https://discord.com/api/v9` | Point at a stub for tests. |
| `DISCORD_MCP_AUDIT` | `1` | JSONL audit log on/off. |
| `DISCORD_MCP_ENV_FILE` | `.env` | dotenv path read at startup; `0` disables it. |

## Register with an MCP client

Most clients take a command plus its environment. Example:

```json
{
  "mcpServers": {
    "discord-user": {
      "command": "C:\\path\\to\\DiscordMCP\\.python-embed\\python.exe",
      "args": ["-m", "discord_user_mcp"],
      "env": {
        "PYTHONPATH": "C:\\path\\to\\DiscordMCP\\src",
        "DISCORD_USER_TOKEN": "<your user token>",
        "DISCORD_MCP_STATE_DIR": "C:\\Users\\<you>\\AppData\\Local\\discord-user-mcp"
      }
    }
  }
}
```

At startup the server prints to **stderr**:

```
  discord-user-mcp 0.1.0 - Discord user API MCP server
  tools: 118   read-only: no   approval TTL: 300s
  token source: env:DISCORD_USER_TOKEN   fingerprint: sha256:1a2b3c4d5e6f
  credential type: Discord USER token (bot tokens are not supported)
  authenticated as: yourname (123456789012345678)

  APPROVAL CONSOLE (open this to approve or deny operations):
    http://127.0.0.1:54321/?t=<random token>
    also written to ...\approval-console.json (keep private)
```

stdout is reserved for the MCP protocol.

## Approving an operation

1. The agent calls a mutating tool and gets `status: "approval_required"` with the
   full arguments, a risk label and an expiry.
2. Open the console URL. The page lists pending requests with their exact
   parameters. Approve, deny, or (for high-risk) type `APPROVE` first.
3. Approving schedules execution **inside the server**; the agent never sends the
   request itself.
4. The agent calls `check_approval(approval_id)` to collect the result. The status
   moves `pending -> approved -> executing -> completed | failed`, or to
   `denied` / `cancelled` / `expired`.

If the console is closed or disabled, nothing can be approved. That is deliberate.

## Tools

118 MCP tools: 54 read-only and 64 gated. By risk:

| Risk | Count | Gate |
|---|---|---|
| `read` | 54 | runs immediately |
| `write` | 25 | approval |
| `admin` | 18 | approval + typed `APPROVE` |
| `destructive` | 11 | approval + typed `APPROVE` |
| `sensitive` | 10 | approval + typed `APPROVE` |

Coverage by area: guilds and members (23), threads (11), messages (10), channels
(9), scheduled events (8), reactions (6), relationships (6), DMs (5), invites (5),
users and profiles (7), settings (3), slash-command discovery (2), notifications
(2), search (2), audit log, emoji, stickers, read state.

Every mutating tool accepts `dry_run=true`, which shows the exact method, path and
payload an approval would authorise without creating a request.

Local tools (no Discord traffic): `get_server_status`, `search_api_endpoints`,
`get_api_endpoint`, `list_approvals`, `check_approval`, `cancel_approval`,
`get_audit_log`, `get_rate_limit_status`.

### The endpoint registry

`src/discord_user_mcp/api/registry_data.json` describes **979 documented
endpoints** parsed from the community user-API documentation at
<https://docs.discord.food> (the `discord-userdoccers` MDX sources):

| Status | Count | Meaning |
|---|---|---|
| `implemented` | 104 | has one or more MCP tools |
| `documented` | 667 | real endpoint, not exposed as a tool in this build |
| `unsupported` | 208 | deliberately excluded, with the reason recorded |

The registry is generated by `tools/build_registry.py` from
`research/endpoint-inventory.json` plus `research/registry_overrides.json`. The
build **fails** if an override names an endpoint the documentation does not
contain, so no fabricated endpoint can enter the registry. Tests enforce that
every tool maps to a declared endpoint, that no endpoint is claimed without a
tool, and that every tool's risk matches the curated classification.

Use `search_api_endpoints` / `get_api_endpoint` to ask the server what exists
before concluding something is impossible.

### Notable exclusions (with reasons in the registry)

Billing, payment sources, subscriptions, gifts and Nitro (money); MFA
enrolment/disable, phone/email verification, captcha and device login (security
flows that must stay human); account delete/disable; the gateway and realtime
events; voice (needs WebSocket + UDP/RTP); interactions; OAuth2
client-credentials; bulk delete (bot-only in practice); reports and Family
Center; quests and collectibles.

Because there is no gateway, this server is **request/response only**. It does
not receive message events, typing events or presence updates; the agent must
poll with read tools.

## HTTP behaviour

- `Authorization` carries the **raw user token**; the `Bot ` prefix is never used.
- `401` is never retried (the token is wrong); the error tells you to replace it.
- `429` is retried after Discord's `retry_after`, per bucket **and** globally, and
  the bucket is remembered so later calls wait instead of hammering.
- `5xx` is retried with exponential backoff and jitter.
- Network errors are retried only for idempotent methods. A failed `POST` is
  reported with a warning that it may already have been applied.
- Responses over 1 MiB are replaced by an explicit
  `{truncated: true, approx_bytes, preview}` envelope rather than silently cut.
- Attachments may only be read from `DISCORD_MCP_UPLOAD_ROOTS`.

## Error shape

Tools return either `{"status": "ok", "data": ...}` or:

```json
{
  "status": "error",
  "tool": "send_message",
  "error": {
    "code": "discord_forbidden",
    "message": "Discord refused the request (HTTP 403): ...",
    "retryable": false,
    "http_status": 403
  }
}
```

Stable codes: `config_error`, `validation_error`, `read_only_mode`,
`upload_rejected`, `approval_not_found`, `approval_expired`,
`approval_already_decided`, `approval_confirmation_required`,
`approval_arguments_tampered`, `approval_console_unavailable`,
`discord_unauthorized`, `discord_forbidden`,
`discord_not_found`, `discord_rejected_payload`, `discord_rate_limited`,
`discord_server_error`, `discord_network_error`, `internal_error`.

## Tests

```powershell
.\.python-embed\python.exe -m pytest -q
```

97 tests, all against mocks and a stub Discord server (no token, no network):

- configuration and token rejection (bot tokens, placeholders, loopback console)
- registry consistency (tool ↔ endpoint, risk equality, no invented endpoints)
- HTTP behaviour (401 no-retry, 429 honouring `retry_after`, 5xx backoff,
  no POST retry on network errors, header shape, response cap)
- approval gate (approve, deny, expiry, tampering, replay, single execution,
  restart fail-closed, audit trail)
- console (token required, wrong token, typed confirmation, replay, bad bodies)
- tool dispatch (reads run, writes stop, dry runs create nothing, read-only mode)
- upload path restriction and size limits
- redaction and audit logging
- an end-to-end stdio session: MCP client → gate → console approval → stub HTTP
  request → `check_approval` result

## Project layout

```
src/discord_user_mcp/
  server.py            FastMCP wiring, startup order, banner, CLI
  runtime.py           the only path from a tool call to HTTP
  config.py            env parsing, token resolution, loopback validation
  api/
    client.py          httpx client: auth, retries, rate limits, caps
    errors.py          error taxonomy
    ratelimit.py       per-bucket and global accounting
    registry.py        endpoint model, search, path rendering
    registry_data.json generated registry (979 endpoints)
  security/
    permissions.py     fixed risk classification
    approval.py        SQLite approval state machine
    console.py         loopback approval UI + JSON API
    audit.py           redacted JSONL audit log
  auth/credentials.py  user-token verification
  tools/               118 tool definitions by area
  utils/               snowflake/emoji validation, redaction
tools/                 registry + inventory builders (development only)
research/              extracted docs inventory and curation overrides
skills/discord-user/   agent-facing skill instructions
tests/                 pytest suite
```

## Provenance and licence

Endpoint shapes come from the community-maintained
[discord-userdoccers](https://github.com/discord-userdoccers/discord-userdoccers)
documentation (MIT), served as <https://docs.discord.food>. The extraction and
curation tools are in `tools/` and the provenance is recorded in every registry
entry (`source` field). No Discord code or assets are included.

This project is MIT licensed. Using it may violate Discord's Terms of Service;
that risk is the operator's.
