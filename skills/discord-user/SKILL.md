---
name: discord-user
description: Route Discord user-account requests to the correct discord-user-mcp tools quickly. Use for guilds, channels, messages, DMs, members, roles, threads, reactions, invites, scheduled events, friends, profiles, settings, endpoint discovery, approvals, and dashboard guidance. Enforces read-before-write, human approval, safe dashboard-link reporting, pagination, and error handling.
---

# Discord user API router

Use this skill with the `discord-user-mcp` server. It authenticates a real
Discord **user** account. Bot tokens, arbitrary HTTP, gateway events, and bypasses
for Discord security checks are not available.

## Non-negotiable safety

- A write is only a **proposal**. Tools with risk `write`, `admin`,
  `destructive`, or `sensitive` create a pending approval without contacting
  Discord.
- Only the human dashboard can approve. Never claim success until
  `check_approval` returns `completed`.
- Call a mutating tool once. Calling it again creates another approval and can
  duplicate the effect.
- Verify names and IDs with a read tool before proposing a change. Never invent
  a snowflake.
- Never request, print, or repeat a Discord token or dashboard access token in
  chat.

## Start fast

At the start of a Discord task, call `get_server_status` once unless a recent
result is already present. Check:

1. `identity` — which account is connected.
2. `mode.read_only` — whether writes are disabled.
3. `mode.approval_console.enabled` — whether approval is possible.
4. `mode.approval_console.dashboard_url` — the safe local dashboard address.

If the user asks for the dashboard, or a call returns `approval_required`, quote
`dashboard_url` directly. Never invent a port. The safe address opens a locked
local page and contains no credential. The authenticated link/access token is
available only in the server startup output and local `approval-console.json`.

Use this response shape for pending work:

```text
Waiting for your approval: <plain-language operation>
Target: <verified name and id>
Risk: <risk> · Expires: <expires_at>
Approval ID: <approval_id>
Dashboard: <console.dashboard_url>

Open the dashboard locally and unlock it using the server startup link or
approval-console.json. I cannot access that credential. Tell me after you decide.
```

The mutation response already contains `console.dashboard_url`; use that value.
Fall back to the value from `get_server_status` only if needed.

The request-specific URL may contain `?request=ap_...`; this is navigation only,
not authentication. In the dashboard, identity, target/approval IDs, token
fingerprints, actors and local paths are masked until the human clicks to reveal
them. Exact arguments remain behind **Technical details**. Do not ask the user to
copy any revealed secret back into chat.

## Intent → tool router

Use this table before searching the endpoint registry.

| Intent | Discover / verify first | Primary tools |
|---|---|---|
| Server, dashboard, approvals | `get_server_status`, `list_approvals`, `check_approval` | `cancel_approval`, `get_audit_log`, `get_rate_limit_status` |
| Current account or another user | `get_current_user`, `get_user`, `get_user_profile` | `update_my_account`, `update_my_profile`, `set_custom_status` |
| Guilds and channels | `list_my_guilds`, `get_guild`, `list_guild_channels`, `get_channel` | `create_guild_channel`, `update_channel`, `delete_channel`, `reorder_channels`, channel-permission tools |
| Messages and search | `list_messages`, `get_message`, `search_channel_messages`, `search_guild_messages`, `list_mentions` | `send_message`, `edit_message`, `delete_message`, `forward_message`, `trigger_typing` |
| DMs and group DMs | `list_private_channels`, `get_dm_channel` | `open_dm`, `close_dm`, `create_group_dm`, recipient tools, `leave_group_dm` |
| Members and moderation | `list_guild_members`, `search_guild_members`, `get_guild_member`, `get_my_guild_member` | `update_guild_member`, `set_my_guild_nickname`, `kick_guild_member`, `ban_guild_member`, `unban_guild_member` |
| Roles | `list_guild_roles`, `get_guild_role` | `create_guild_role`, `update_guild_role`, `delete_guild_role`, `reorder_guild_roles`, add/remove role tools |
| Threads | `list_active_threads`, `list_archived_threads`, `list_guild_active_threads`, `search_threads` | `create_thread`, `start_thread_from_message`, `join_thread`, `leave_thread`, thread-member tools |
| Reactions, pins, polls | `list_reactions`, `list_channel_pins`, `list_poll_voters` | reaction-removal tools, `add_reaction`, `pin_message`, `unpin_message`, `vote_poll` |
| Invites | `list_channel_invites`, `list_guild_invites`, `get_invite` | `create_channel_invite`, `delete_invite` |
| Scheduled events | `list_scheduled_events`, `get_scheduled_event`, `list_event_users` | `create_scheduled_event`, `update_scheduled_event`, `delete_scheduled_event`, `rsvp_event`, `unrsvp_event` |
| Friends and relationships | `list_relationships`, `list_mutual_relationships` | `send_friend_request`, `accept_friend_request`, `remove_relationship`, `block_user`, `set_relationship_nickname` |
| User settings, notes, notifications | `get_my_settings`, `list_my_notes`, `list_notifications` | `update_my_settings`, `update_my_notification_settings`, `set_user_note`, `ack_notification` |
| Emoji, stickers, audit, commands | `list_guild_emojis`, `list_guild_stickers`, `get_guild_audit_log`, application-command tools | read first; use registry if no listed mutation fits |

For the complete grouped catalog and short recipes, read `API_GUIDE.md` beside
this file. Do not load it when the table above already answers the request.

## Common recipes

### Read, send, edit, or delete a message

1. Resolve the guild/channel with `list_my_guilds` and
   `list_guild_channels`, unless verified IDs were supplied.
2. Use `get_message` for a supplied Discord message URL or message ID; use
   `list_messages` / search tools for discovery.
3. For a change, call exactly one of `send_message`, `edit_message`,
   `delete_message`, or `forward_message`.
4. Report the approval details and `console.dashboard_url`; after the human
   decides, call `check_approval`.

A message URL has guild, channel, and message IDs. Parse them, then verify the
message with `get_message`; do not treat the URL alone as proof of the target.

### Change a guild, channel, member, permission, or role

Read the current object and its containing guild first. For member changes, also
read the member; for role changes, list roles; for permission changes, read the
channel. Use `dry_run=true` before complex admin/destructive calls when the user
would benefit from seeing the exact path and arguments.

### DM or relationship action

Resolve the user with `get_user` / `get_user_profile`, then inspect existing
private channels or relationships. Relationship/profile/account changes are
`sensitive` and require the human to type `APPROVE` in the dashboard.

### Thread or scheduled-event action

Resolve the parent channel or guild, list existing threads/events, then act on
the verified ID. Do not create a replacement merely because a search returned
no first-page result; paginate or use the more specific get tool.

## Tool and response discipline

- Read tools return `{"status":"ok","data":...}`; inspect `data`, not only the
  envelope.
- Mutations return `status: "approval_required"`; this means **nothing has been
  sent to Discord**.
- `dry_run=true` sends nothing and creates no approval. Use the real call once
  after the user confirms the proposed parameters.
- When an approval is pending, wait for the human. Check it after they say they
  decided; do not busy-loop and do not retry the original mutation.
- Terminal states: `completed`, `failed`, `denied`, `cancelled`, `expired`.
- `cancel_approval` can only make a pending request safer; it can never approve.

## Registry fallback

Do not search the registry when the intent router identifies a tool. When the
request is unfamiliar:

1. `search_api_endpoints(query="...", status="implemented")`
2. `get_api_endpoint("<endpoint id>")` for exact method, parameters, risk,
   limitations, and source.
3. If only `documented` or `unsupported` entries exist, explain that no tool is
   available. Never fabricate a tool or raw HTTP call.

Registry statuses:

- `implemented`: one or more MCP tools exist.
- `documented`: real endpoint, not exposed as a tool in this build.
- `unsupported`: deliberately excluded; report its recorded limitation.

## Risk levels

| Risk | Typical operations | Human action |
|---|---|---|
| `read` | list/get/search | none |
| `write` | send/edit/react/pin/join | click Allow |
| `admin` | channels, roles, permissions, guild administration | type `APPROVE` |
| `destructive` | delete/leave/kick/ban | type `APPROVE` |
| `sensitive` | account/profile/friends/blocks/notes/settings | type `APPROVE` |

Risk is fixed in code and registry data. Never imply it can be downgraded.

## Pagination and response size

- `list_messages`: 1–100; use only one of `before`, `after`, or `around`.
- `list_guild_members`: up to 1000; continue with returned `next_after`.
- Search: up to 25 per page with `offset`; HTTP 202 can mean the guild index is
  still building, not that no result exists.
- Responses above 1 MiB return `truncated: true`; narrow or paginate the query.

## Error routing

| Code | Action |
|---|---|
| `validation_error` | correct arguments; do not retry unchanged |
| `read_only_mode` | explain that writes are disabled |
| `upload_rejected` | use an allowed path or lower file count/size |
| `discord_unauthorized` | stop; operator must replace the token and restart |
| `discord_forbidden` | report permission/platform check; never bypass |
| `discord_not_found` | rediscover and verify the ID |
| `discord_rate_limited` | wait for `retry_after`, then retry once |
| `discord_network_error` | for a mutation, inspect the target before any retry |
| `approval_expired` | propose again only if the user still wants it |
| `approval_already_decided` | collect the existing result; never replay |
| `approval_arguments_tampered` | stop and report a security event |
| `approval_console_unavailable` | dashboard is disabled/unavailable; no write can be approved |

Known limits: no gateway/live events, voice, billing/Nitro/payments, MFA,
captcha, phone/email verification, device login, account deletion, OAuth2, or
bulk delete. Never work around Discord platform security checks.
