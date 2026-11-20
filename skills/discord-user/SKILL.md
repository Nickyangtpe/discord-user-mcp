---
name: discord-user
description: Operate a Discord user account through the discord-user-mcp server. Use when the user asks you to read or change something on their own Discord account (guilds, channels, messages, DMs, friends, roles, scheduled events), when you need to find the right tool for a Discord operation, or when a Discord tool returned approval_required and you must wait for the human approval dashboard. Covers the approval protocol, risk levels, pagination, registry lookup and error codes.
---

# Discord user operations

This skill is for the `discord-user-mcp` MCP server. It authenticates with a
Discord **user** token and changes a real account. There is no bot account and no
gateway: everything is request/response, so you see only what you ask for.

## The one rule

You cannot perform a write. You can only **propose** one.

Every tool with risk `write`, `admin`, `destructive` or `sensitive` creates a
pending approval and returns without contacting Discord. A human approves it in a
local dashboard. Until `check_approval` reports `completed`, the operation has **not
happened**. Never tell the user it did.

## Standard loop

1. **Orient.** `get_server_status` (token verified? read-only? console running?) and
   `get_current_user` (which account is this?).
2. **Discover ids.** `list_my_guilds` → `list_guild_channels` → `get_channel` /
   `list_messages`. Ids are snowflakes (digits); never invent one.
3. **Read first.** Confirm names, permissions and targets with a read tool before
   proposing a change. Do not guess a channel id or role id.
4. **Propose the change.** Call the mutating tool once. Use `dry_run=true` first
   when you want to show the user the exact request without creating a request.
5. **Report the approval id and what it authorises.** The response contains the
   full arguments, the risk label, the expiry and the dashboard status. Ask the
   operator to approve it in the dashboard.
6. **Poll.** `check_approval(approval_id)` until the status is terminal:
   `completed` (use `result`), `failed` (read `error`), `denied`, `cancelled` or
   `expired`.

Do **not** retry the original tool call while a request is pending: that creates a
second pending approval and duplicates any side effect once both are approved.

## Risk levels

| Risk | Examples | Approval |
|---|---|---|
| `read` | list messages, get guild, search, list roles | none, runs immediately |
| `write` | send/edit message, react, pin, create invite, join thread | console click |
| `admin` | create/update channel, roles, permissions, kick, ban settings, guild update | click + type `APPROVE` |
| `destructive` | delete message/channel/role/event, leave guild, ban, kick | click + type `APPROVE` |
| `sensitive` | profile, relationships, blocks, notes, settings, custom status | click + type `APPROVE` |

The risk is fixed in code and in the registry; you cannot lower it and there is no
parameter that skips the gate.

The dashboard is human-only. Its URL token is never returned through MCP, and the
agent cannot use it to approve requests or change dashboard settings.

## If you are unsure a tool exists

Ask the registry instead of guessing:

- `search_api_endpoints(query="scheduled event", status="implemented")`
- `search_api_endpoints(status="unsupported")` to see what is excluded and why
- `get_api_endpoint("<id>")` for the documented parameters, risk and source link

Statuses: `implemented` (a tool exists), `documented` (real endpoint, no tool in
this build), `unsupported` (deliberately excluded, with a reason). If something is
`documented` or `unsupported`, say so; do not pretend you can do it.

Known limits: no gateway, so no live events (poll with read tools); no voice; no
billing/Nitro/payments; no MFA, captcha, phone/email verification or device login;
no account deletion; no OAuth2; no bulk delete. Discord's own platform checks are
never bypassed: a 403 with HTML means a security check blocked the request.

## Pagination and size

- `list_messages`: 1-100 per page, use `before` / `after` / `around` (only one).
- `list_guild_members`: up to 1000, continue with the returned `next_after`.
- Search endpoints: up to 25 per page with `offset`; a guild index that is still
  building answers HTTP 202 - retry later instead of assuming no results.
- Responses above 1 MiB return `{truncated: true, preview, approx_bytes}`. Narrow
  the query rather than treating the preview as complete.

## Errors and what to do

| Code | Meaning | Action |
|---|---|---|
| `validation_error` | bad snowflake, missing field, limit exceeded | fix the arguments, do not retry unchanged |
| `read_only_mode` | server started with `DISCORD_MCP_READ_ONLY=1` | tell the user writes are disabled |
| `upload_rejected` | file outside the allowed roots, too large, too many | ask the user to move it or raise the limit |
| `discord_unauthorized` | 401, token invalid/revoked | stop; the operator must replace the token and restart |
| `discord_forbidden` | 403, missing permission or platform check | report it; never attempt to bypass |
| `discord_not_found` | 404 | re-discover the id; the object may be gone or invisible |
| `discord_rate_limited` | 429 after retries | wait `retry_after`, then retry once |
| `discord_network_error` | timeout/reset | for POST, check the target before retrying - it may have been applied |
| `approval_confirmation_required` | high risk without the phrase | the human must type `APPROVE` in the console |
| `approval_expired` | TTL passed | propose it again only if the user still wants it |
| `approval_already_decided` | replay or already executed | do not re-approve; check the existing result |
| `approval_arguments_tampered` | stored arguments changed | treat as a security event and report it |
| `approval_console_unavailable` | the console is disabled or not running | nothing can be approved; tell the user to restart the server |

## Etiquette

- Read before writing; show the user the target name, not just an id.
- One change per approval. Do not batch unrelated destructive actions.
- Prefer the least destructive tool (`edit_message` before `delete_message`,
  `kick` before `ban`, `close_dm` before leaving a group).
- If the user asks for something the registry marks unsupported, explain the
  reason instead of looking for a workaround.
- Never ask for, print, log or repeat the token, and never ask the user to paste
  it into chat; it belongs in the server's environment or state directory.
- `cancel_approval` is available to you, but only for **pending** requests. Use it
  when the user changes their mind before approval. Approving is impossible from
  MCP by design.
