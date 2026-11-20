# Discord User MCP API guide

Use this catalog only after the short router in `SKILL.md`. Tool names below are
the actual MCP names. Never replace them with guessed names or arbitrary HTTP.

## Local server, registry, approvals

**Start:** `get_server_status`

- Registry: `search_api_endpoints`, `get_api_endpoint`
- Approval state: `list_approvals`, `check_approval`, `cancel_approval`
- Diagnostics: `get_audit_log`, `get_rate_limit_status`

`get_server_status.mode.approval_console.dashboard_url` is the safe base
dashboard address. A mutating response returns a request-scoped
`console.dashboard_url` containing `?request=ap_...`, never the dashboard access
token. Prefer the request-scoped URL when reporting a pending operation.

## Users, account, profile, settings

**Identify:** `get_current_user` → `get_user` → `get_user_profile`

- Account/profile changes: `update_my_account`, `update_my_profile`,
  `set_custom_status`
- Settings: `get_my_settings`, `update_my_settings`,
  `update_my_notification_settings`
- Notes: `list_my_notes`, `set_user_note`
- Notifications: `list_notifications`, `ack_notification`

Account, profile, relationship, note, and settings changes are sensitive. Show
the exact proposed fields, but never echo secrets or credentials.

## Guilds and channels

**Discover:** `list_my_guilds` → `get_guild` / `get_guild_preview` →
`list_guild_channels` → `get_channel`

- Guild: `update_guild`, `leave_guild`
- Channel lifecycle: `create_guild_channel`, `update_channel`, `delete_channel`
- Ordering: `reorder_channels`
- Permissions: `update_channel_permissions`, `delete_channel_permission`

Before changing a channel, verify both its guild and current channel object.
Before deleting or leaving, state the verified name and ID and use a dry run when
the impact is not obvious.

## Messages, search, pins, polls

**Read/discover:**

- `list_messages`, `get_message`
- `search_channel_messages`, `search_guild_messages`, `list_mentions`
- `list_channel_pins`, `list_poll_voters`

**Change:**

- `send_message`, `edit_message`, `delete_message`, `forward_message`
- `trigger_typing`, `mark_channel_read`
- `pin_message`, `unpin_message`, `vote_poll`

For edit/delete/forward/pin operations, call `get_message` first. If the user
provides a Discord message URL, parse guild/channel/message IDs and verify the
message before proposing the mutation.

## Direct messages and group DMs

**Discover:** `list_private_channels`, `get_dm_channel`, and the relevant user
tools.

- One-to-one: `open_dm`, `close_dm`
- Group: `create_group_dm`, `add_group_dm_recipient`,
  `remove_group_dm_recipient`, `leave_group_dm`

Do not create a new DM if an existing channel can be verified and reused.

## Members, moderation, roles

**Members:** `list_guild_members`, `search_guild_members`, `get_guild_member`,
`get_my_guild_member`

- Member changes: `update_guild_member`, `set_my_guild_nickname`
- Moderation: `list_guild_bans`, `kick_guild_member`, `ban_guild_member`,
  `unban_guild_member`

**Roles:** `list_guild_roles`, `get_guild_role`

- Role lifecycle: `create_guild_role`, `update_guild_role`, `delete_guild_role`
- Ordering: `reorder_guild_roles`
- Assignment: `add_role_to_member`, `remove_role_from_member`

Always resolve the guild, member, and role separately. Do not infer a role from
its color, position, or a similar name.

## Threads

**Discover:** `list_active_threads`, `list_archived_threads`,
`list_guild_active_threads`, `search_threads`

- Create: `create_thread`, `start_thread_from_message`
- Membership: `join_thread`, `leave_thread`, `list_thread_members`,
  `add_thread_member`, `remove_thread_member`

Verify the parent channel or source message before creating a thread.

## Reactions

**Read:** `list_reactions`

- Add: `add_reaction`
- Remove own/specific: `remove_own_reaction`, `remove_user_reaction`
- Remove sets: `remove_all_reactions`, `remove_emoji_reactions`

Emoji input may require encoding handled by the tool. Use the schema rather than
constructing a URL yourself.

## Invites

**Read:** `list_channel_invites`, `list_guild_invites`, `get_invite`

**Change:** `create_channel_invite`, `delete_invite`

Inspect an invite before deletion and report the destination, not only its code.

## Scheduled events

**Read:** `list_scheduled_events`, `get_scheduled_event`, `list_event_users`

**Change:** `create_scheduled_event`, `update_scheduled_event`,
`delete_scheduled_event`, `rsvp_event`, `unrsvp_event`

Check current event times and location before proposing updates.

## Friends and relationships

**Read:** `list_relationships`, `list_mutual_relationships`, plus `get_user` and
`get_user_profile`

**Change:** `send_friend_request`, `accept_friend_request`,
`remove_relationship`, `block_user`, `set_relationship_nickname`

These are sensitive operations. Verify the user ID/profile and require typed
human approval.

## Guild assets, audit, application commands

- Assets: `list_guild_emojis`, `list_guild_stickers`
- Audit: `get_guild_audit_log`
- Commands: `get_guild_application_commands`, `get_user_application_commands`

These tools are primarily discovery/read surfaces. If a requested mutation is
not listed, use the endpoint registry and report `documented`/`unsupported`
honestly rather than improvising a call.

## Choosing list, get, and search

1. Use **get** when an exact verified ID is known.
2. Use **list** to establish context or paginate a collection.
3. Use **search** for names/text, then verify the selected result with a get tool
   when available.
4. Use a mutation only after the target is unambiguous.

## Approval handoff

After any mutation returns `approval_required`, surface:

- plain-language operation and verified target;
- risk and expiry;
- approval ID;
- `console.dashboard_url` (request ID only, no access token).

The human opens that address, unlocks locally, reviews hidden values/technical
details, and decides. Then call `check_approval` once the human says they have
acted.
