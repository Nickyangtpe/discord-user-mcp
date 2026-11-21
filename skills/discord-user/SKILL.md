---
name: discord-user
description: Route Discord user-account requests to the correct discord-user-mcp tools quickly. Use for guilds, channels, messages, DMs, members, roles, threads, reactions, invites, scheduled events, friends, profiles, settings, endpoint discovery, approvals, and dashboard guidance. Enforces read-before-write, human approval, safe dashboard-link reporting, pagination, and error handling.
---

# Discord user API skill

One file: intent router first, complete tool catalog second. Use this skill with
the `discord-user-mcp` server. It authenticates a real Discord **user** account.
Bot tokens, arbitrary HTTP, gateway events, and bypasses for Discord security
checks are not available.

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
`mode.approval_console.token_file` (and `console.token_file`) gives that file's
full path, which you may tell the user when they cannot find it — the path is
not a secret, the file contents are.

Use this response shape for pending work:

```text
Waiting for your approval: <plain-language operation>
Target: <verified name and id>
Risk: <risk> · Expires: <expires_at>
Approval ID: <approval_id>
Dashboard: <console.dashboard_url>
Token file: <console.token_file>

Open the dashboard locally and unlock it using the server startup link or that
token file. I cannot access the credential. Tell me after you decide.
```

The mutation response already contains `console.dashboard_url`; use that value.
Fall back to `get_server_status` only if needed.

The request-specific URL contains the request ID only, no access token; the
`?request=ap_...` parameter is navigation only, not authentication. In the dashboard, identity, target/approval IDs, token
fingerprints, actors and local paths are masked until the human clicks to reveal
them. Exact arguments remain behind **Technical details**. Do not ask the user to
copy any revealed secret back into chat.

## Intent → tool router

Use this table before searching the endpoint registry. The catalog below lists
every remaining tool.

| Intent | Discover / verify first | Primary tools |
|---|---|---|
| Server, dashboard, approvals | `get_server_status`, `list_approvals`, `check_approval` | `cancel_approval`, `get_audit_log`, `get_rate_limit_status` |
| Current account or another user | `get_current_user`, `get_user`, `get_user_profile` | `update_my_account`, `update_my_profile`, `set_custom_status` |
| Guilds and channels | `list_my_guilds`, `get_guild`, `list_guild_channels`, `get_channel` | `create_guild_channel`, `update_channel`, `delete_channel`, `reorder_channels` |
| Messages and search | `list_messages`, `get_message`, `search_channel_messages`, `search_guild_messages`, `list_mentions` | `send_message`, `edit_message`, `delete_message`, `forward_message`, `trigger_typing` |
| DMs and group DMs | `list_private_channels`, `get_dm_channel` | `open_dm`, `close_dm`, `create_group_dm`, `leave_group_dm` |
| Members and moderation | `list_guild_members`, `search_guild_members`, `get_guild_member`, `get_my_guild_member` | `update_guild_member`, `kick_guild_member`, `ban_guild_member`, `unban_guild_member` |
| Roles | `list_guild_roles`, `get_guild_role` | `create_guild_role`, `update_guild_role`, `delete_guild_role`, `reorder_guild_roles` |
| Threads | `list_active_threads`, `list_archived_threads`, `list_guild_active_threads`, `search_threads` | `create_thread`, `start_thread_from_message`, `join_thread`, `leave_thread` |
| Reactions, pins, polls | `list_reactions`, `list_channel_pins`, `list_poll_voters` | `add_reaction`, `pin_message`, `unpin_message`, `vote_poll` |
| Invites | `list_channel_invites`, `list_guild_invites`, `get_invite` | `create_channel_invite`, `delete_invite` |
| Scheduled events | `list_scheduled_events`, `get_scheduled_event`, `list_event_users` | `create_scheduled_event`, `update_scheduled_event`, `delete_scheduled_event`, `rsvp_event`, `unrsvp_event` |
| Friends and relationships | `list_relationships`, `list_mutual_relationships` | `send_friend_request`, `accept_friend_request`, `remove_relationship`, `block_user` |
| User settings, notes, notifications | `get_my_settings`, `list_my_notes`, `list_notifications` | `update_my_settings`, `update_my_notification_settings`, `set_user_note`, `ack_notification` |
| Emoji, stickers, audit, commands | `list_guild_emojis`, `list_guild_stickers`, `get_guild_audit_log` | `get_guild_application_commands`, `get_user_application_commands` |
| Forum tags, announcement publishing | `get_channel`, `get_message` | `create_forum_tag`, `update_forum_tag`, `delete_forum_tag`, `follow_announcement_channel`, `crosspost_message` |
| AutoMod and server incident controls | `list_guild_automod_rules`, `get_guild_automod_rule` | `delete_guild_automod_rule`, `update_guild_incident_actions` |
| Templates, widgets, welcome screens | `list_guild_templates`, `get_guild_widget_settings`, `get_guild_welcome_screen` | `create_guild_template`, `update_guild_template`, `sync_guild_template`, `update_guild_widget` |
| Discovery and app directory | `search_discoverable_guilds`, `search_published_guilds`, `search_application_directory` | `get_guild_profile`, `get_application_directory_entry`, `list_similar_applications` |
| Saved messages and linked accounts | `list_saved_messages`, `list_my_connections`, `get_user_note` | `save_message`, `unsave_message`, `ignore_user`, `unignore_user` |

If neither the router nor the catalog names the operation, use the registry
fallback below instead of improvising.

## Complete tool catalog

All 257 tools this server exposes, grouped by domain. Risk is fixed in code; the
`read`/`write` split below is informative only.

### Local server and approvals (read)

- `get_server_status`, `search_api_endpoints`, `get_api_endpoint`
- `list_approvals`, `check_approval`, `get_audit_log`, `get_rate_limit_status`
- `cancel_approval` (cancels a pending request; never approves)

### Users, account, profile, settings

**Read:** `get_current_user`, `get_user`, `get_user_profile`, `get_my_settings`,
`list_my_notes`, `list_notifications`

**Change:**
- `update_my_account`, `update_my_profile`, `set_custom_status`
- `update_my_settings`, `update_my_notification_settings`
- `set_user_note`, `ack_notification`

Account, profile, relationship, note and settings changes are sensitive. Show
the exact proposed fields, but never echo secrets or credentials.

### Guilds and channels

**Read:** `list_my_guilds`, `get_guild`, `get_guild_preview`,
`list_guild_channels`, `get_channel`, `list_guild_bans`, `list_guild_roles`,
`list_guild_emojis`, `list_guild_stickers`, `get_guild_audit_log`

**Change:**
- `update_guild`, `leave_guild`
- `create_guild_channel`, `update_channel`, `delete_channel`, `reorder_channels`
- `update_channel_permissions`, `delete_channel_permission`

Before changing a channel, verify both its guild and current channel object.
Before deleting or leaving, state the verified name and ID.

### Messages, search, pins, polls

**Read:** `list_messages`, `get_message`, `search_channel_messages`,
`search_guild_messages`, `list_mentions`, `list_channel_pins`,
`list_poll_voters`

**Change:** `send_message`, `edit_message`, `delete_message`, `forward_message`,
`trigger_typing`, `mark_channel_read`, `pin_message`, `unpin_message`,
`vote_poll`

For edit/delete/forward/pin, call `get_message` first. If the user provides a
Discord message URL, parse guild/channel/message IDs and verify the message
before proposing the mutation.

### Direct messages and group DMs

**Read:** `list_private_channels`, `get_dm_channel`

**Change:** `open_dm`, `close_dm`, `create_group_dm`,
`add_group_dm_recipient`, `remove_group_dm_recipient`, `leave_group_dm`

Do not create a new DM if an existing channel can be verified and reused.

### Members, moderation, roles

**Members read:** `list_guild_members`, `search_guild_members`,
`get_guild_member`, `get_my_guild_member`

**Members change:** `update_guild_member`, `set_my_guild_nickname`,
`kick_guild_member`, `ban_guild_member`, `unban_guild_member`

**Roles:** `list_guild_roles`, `get_guild_role`, `create_guild_role`,
`update_guild_role`, `delete_guild_role`, `reorder_guild_roles`,
`add_role_to_member`, `remove_role_from_member`

Always resolve guild, member, and role separately. Do not infer a role from its
color, position, or a similar name.

### Threads

**Read:** `list_active_threads`, `list_archived_threads`,
`list_guild_active_threads`, `search_threads`, `list_thread_members`

**Change:** `create_thread`, `start_thread_from_message`, `join_thread`,
`leave_thread`, `add_thread_member`, `remove_thread_member`

Verify the parent channel or source message before creating a thread.

### Reactions

**Read:** `list_reactions`

**Change:** `add_reaction`, `remove_own_reaction`, `remove_user_reaction`,
`remove_all_reactions`, `remove_emoji_reactions`

Emoji encoding is handled by the tool. Use the schema rather than constructing a
URL yourself.

### Invites and scheduled events

**Invites:** `list_channel_invites`, `list_guild_invites`, `get_invite`,
`create_channel_invite`, `delete_invite`

**Events:** `list_scheduled_events`, `get_scheduled_event`, `list_event_users`,
`create_scheduled_event`, `update_scheduled_event`, `delete_scheduled_event`,
`rsvp_event`, `unrsvp_event`

Inspect an invite before deletion and report its destination, not only its code.
Check current event times and location before proposing updates.

### Friends, relationships, commands

**Read:** `list_relationships`, `list_mutual_relationships`,
`get_guild_application_commands`, `get_user_application_commands`

**Change:** `send_friend_request`, `accept_friend_request`,
`remove_relationship`, `block_user`, `set_relationship_nickname`

These are sensitive operations. Verify the user ID/profile and require typed
human approval.

### Extended guild reads

`get_guild_ban`, `search_guild_bans`, `get_basic_guild`, `get_guild_onboarding`,
`get_guild_welcome_screen`, `get_guild_new_member_welcome`,
`list_guild_new_member_actions`, `get_guild_widget_settings`, `get_guild_widget`,
`get_guild_vanity_invite`, `get_guild_template`, `list_guild_templates`,
`get_guild_role_member_counts`, `list_guild_role_members`,
`list_guild_role_connections`, `get_guild_role_connection_config`,
`get_guild_role_connection_eligibility`, `list_guild_top_read_channels`,
`list_guild_top_games`, `get_guild_discovery_metadata`,
`get_guild_discovery_requirements`, `get_guild_profile`

### Guild join requests and AutoMod

**Read:** `list_guild_join_requests`, `get_my_guild_join_request`,
`get_guild_join_request_cooldown`, `list_user_guild_join_requests`,
`get_guild_join_request`, `list_my_join_request_guilds`,
`list_guild_automod_rules`, `get_guild_automod_rule`

**Change:** `delete_guild_automod_rule`, `update_guild_incident_actions`

Reading join requests does not grant membership or bypass verification. Do not
automate any platform security challenge returned by `accept_invite`.

### Emoji, sticker, soundboard and stage details

**Read:** `get_guild_emoji`, `get_emoji_guild`, `get_emoji_source`,
`list_guild_top_emojis`, `get_guild_sticker`, `get_sticker`, `get_sticker_guild`,
`list_sticker_packs`, `get_sticker_pack`, `list_guild_soundboard_sounds`,
`get_guild_soundboard_sound`, `list_default_soundboard_sounds`,
`get_soundboard_sound_guild`, `get_stage_instance`

**Change:** `update_guild_emoji`, `delete_guild_emoji`, `update_guild_sticker`,
`delete_guild_sticker`, `update_guild_soundboard_sound`,
`delete_guild_soundboard_sound`, `update_stage_instance`, `delete_stage_instance`

These stage tools manage HTTP metadata only; they cannot join voice or stream
audio. Soundboard tools do not play sounds. Updates expose a bounded subset of
documented fields, not arbitrary JSON.

### Extended channels, threads and messages

**Read:** `get_thread_member`, `list_private_archived_threads`,
`list_joined_private_archived_threads`, `list_message_pins`,
`get_message_interaction_data`, `list_conversation_summaries`,
`get_channel_media_preview`

**Change:** `create_forum_tag`, `update_forum_tag`, `delete_forum_tag`,
`update_thread_settings`, `follow_announcement_channel`, `crosspost_message`,
`end_poll`, `save_message`, `unsave_message`, `delete_recent_mention`,
`ack_channel_pins`, `mark_guild_read`

Forum tags accept either `emoji_id` or `emoji_name`, not both. Private archived
threads require permission; an empty list does not prove no private threads
exist. Use `widget_channel_id` for `update_guild_widget` to distinguish the widget
destination from the resource path. Crossposting publishes an existing message
to followers; read it before asking for approval.

### Templates, widgets, welcome screens and integrations

**Read:** `list_channel_integrations`, `list_guild_integrations`,
`list_my_integration_application_ids`

**Change:** `create_guild_template`, `update_guild_template`,
`sync_guild_template`, `delete_guild_template`, `update_guild_widget`,
`update_guild_vanity_invite`, `update_guild_welcome_screen`,
`delete_channel_integration`, `delete_guild_integration`,
`sync_guild_integration`, `update_guild_integration`

Deleting an integration can remove associated roles or webhooks. Inspect it and
state that impact before proposing deletion.

### Extended invites and event participation

**Read:** `list_invite_friend_members`, `list_invite_target_users`,
`get_invite_target_users_job_status`, `list_my_invites`,
`get_scheduled_event_user_counts`, `list_scheduled_event_exception_users`,
`list_my_scheduled_events`

**Change:** `accept_invite`

`list_my_scheduled_events` requires `guild_ids`. Read the invite destination
before accepting it. Invite codes are strings, not snowflake IDs.

### Account context, connections and notification snapshots

**Read:** `get_user_note`, `list_saved_messages`, `list_recent_avatars`,
`list_channel_affinities`, `list_guild_affinities`, `list_user_affinities`,
`list_friend_suggestions`, `list_game_relationships`, `get_my_consents`,
`get_my_email_settings`, `list_notification_settings_snapshots`,
`list_my_connections`, `list_my_linked_connections`

**Change:** `ignore_user`, `unignore_user`, `remove_friend_suggestion`,
`delete_notification`, `create_notification_settings_snapshot`,
`delete_notification_settings_snapshot`, `restore_notification_settings_snapshot`

Connection access/refresh tokens and client secrets are redacted from results.
Never request them or use a different endpoint to recover them. Restoring a
snapshot changes notification preferences and requires typed approval.

### Discovery, applications, games and activity statistics

**Read:** `list_directory_entries`, `get_directory_counts`,
`list_partial_directory_entries`, `get_directory_entry`,
`search_discoverable_guilds`, `list_discovery_categories`,
`search_published_guilds`, `get_discovery_slug`,
`get_application_directory_entry`, `list_similar_applications`,
`list_application_directory_categories`, `search_application_directory`,
`get_channel_application_command_index`, `get_application_command_index`,
`get_public_application`, `list_application_assets`,
`list_user_application_role_connections`, `get_user_application_role_connection`,
`list_detectable_games`, `list_detectable_game_exclusions`, `get_game`,
`list_game_announcements`, `list_my_activity_statistics`,
`list_application_activity_statistics`

These are HTTP reads, not live presence or a gateway subscription. Discovery
results can be gated by Discord rollout. `list_game_announcements` requires
`limit`. Use the actual tool schema for pagination bounds and optional fields.

## Common recipes

### Read, send, edit, or delete a message

1. Resolve the guild/channel with `list_my_guilds` and `list_guild_channels`,
   unless verified IDs were supplied.
2. Use `get_message` for a supplied message URL or ID; use `list_messages` or a
   search tool for discovery.
3. For a change, call exactly one of `send_message`, `edit_message`,
   `delete_message`, or `forward_message`.
4. Report the approval details and `console.dashboard_url`; after the human
   decides, call `check_approval`.

A message URL has guild, channel, and message IDs. Parse them, then verify the
message; do not treat the URL alone as proof of the target.

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
the verified ID. Do not create a replacement merely because a search returned no
first-page result; paginate or use the more specific get tool.

### Choosing list, get, and search

1. Use **get** when an exact verified ID is known.
2. Use **list** to establish context or paginate a collection.
3. Use **search** for names/text, then verify the selected result with a get tool
   when available.
4. Use a mutation only after the target is unambiguous.

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

Do not search the registry when the router or catalog identifies a tool. When the
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
- Every tool accepts optional `response_max_bytes`. Choose a budget appropriate
  to the task: 4 MiB by default, up to the operator's ceiling (absolute maximum
  16 MiB). Valid requests are integers from 1024 to 16777216 bytes. For example,
  use `response_max_bytes=8388608` when a larger read is needed; smaller focused
  reads generally need less. Omit the parameter to use the server default.
- `get_server_status` exposes `data.response_limits`. Requests above the
  operator ceiling are clamped, not permission to increase it. Only the human
  dashboard/configuration can change these limits.
- The budget covers UTF-8 JSON tool content, including the envelope and root
  `response` metadata, not JSON-RPC framing. Inspect `response.truncated`,
  `effective_max_bytes`, `server_max_bytes`, `original_bytes`, and `returned_bytes`.
  A truncated structural prefix is incomplete even if its JSON is valid.
- If truncated, increase the budget within the ceiling or narrow/paginate reads.
  For a completed mutation, call `check_approval` with the same approval ID and
  a larger budget. Never repeat the mutation to collect a larger response.
- Budgets affect presentation only: they are not Discord arguments, do not alter
  approved parameters, and cannot bypass the human approval gate.

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
