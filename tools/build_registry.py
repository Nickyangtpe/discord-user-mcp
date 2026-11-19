"""Build the packaged endpoint registry from the extracted documentation.

Inputs
    research/endpoint-inventory.json   parsed from docs.discord.food MDX sources
    research/registry_overrides.json   curation: ids, risk, status, tools

Output
    src/discord_user_mcp/api/registry_data.json

The build fails loudly if an override names an endpoint that the documentation
does not contain, or if two endpoints claim the same id. That is the guard
against inventing endpoints.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "research" / "endpoint-inventory.json"
OVERRIDES = ROOT / "research" / "registry_overrides.json"
OUT = ROOT / "src" / "discord_user_mcp" / "api" / "registry_data.json"

VALID_RISKS = {"read", "write", "destructive", "sensitive", "admin"}
VALID_STATUS = {"implemented", "documented", "unsupported"}

PAGE_CATEGORY = {
    "user": "user",
    "relationships": "relationships",
    "guild": "guild",
    "channel": "channel",
    "message": "message",
    "invite": "invite",
    "user-settings": "settings",
    "guild-scheduled-event": "events",
    "presence": "presence",
    "audit-log": "audit_log",
    "emoji": "emoji",
    "sticker": "sticker",
    "application-commands": "applications",
    "application": "application",
    "notification-center": "notifications",
    "components": "components",
    "webhook": "webhook",
    "voice": "voice",
    "permissions": "permissions",
    "threads": "thread",
    "read-state": "read_state",
    "gateway": "gateway",
    "interactions": "interactions",
    "oauth2": "oauth2",
    "billing": "billing",
    "payment": "billing",
    "subscription": "billing",
    "store": "store",
    "entitlement": "store",
    "quests": "quests",
    "collectibles": "collectibles",
    "family-center": "family_center",
    "reports": "reports",
    "safety-hub": "safety",
    "phone-verification": "security",
    "email-verification": "security",
    "captcha-handling": "security",
    "remote-authentication": "security",
    "auto-moderation": "automod",
    "guild-template": "guild",
    "stage-instance": "stage",
    "soundboard": "soundboard",
    "widgets": "widgets",
    "lobby": "lobby",
    "game-invite": "game",
    "game": "game",
    "discovery": "discovery",
    "directory-entry": "discovery",
    "guild-analytics": "analytics",
    "team": "application",
    "integration": "integration",
    "connected-accounts": "connections",
    "premium-referral": "billing",
    "promotion": "promotion",
    "checkpoint": "security",
    "ai": "ai",
}

PAGE_POLICY_REASON = {
    "billing": "Financial endpoints (Nitro, payment sources, invoices) are excluded by policy so an agent can never spend money or read payment data.",
    "payment": "Payment endpoints are excluded by policy.",
    "subscription": "Subscription management is excluded by policy (can spend money).",
    "store": "Store and entitlement endpoints are excluded by policy (purchases).",
    "quests": "Quest endpoints grant promotional rewards; out of scope.",
    "collectibles": "Collectible purchases are excluded (spending money).",
    "family-center": "Family Center controls other people's accounts; excluded by policy.",
    "reports": "Reporting/moderation tooling is out of scope for an agent acting as the account owner.",
    "safety-hub": "Safety tooling can restrict accounts; out of scope.",
    "security": "Platform security flows (captcha, phone/email verification, device login) must be completed by the human owner and are never automated.",
    "oauth2": "OAuth2 flows need an application client secret and a browser redirect; this server only supports user tokens.",
    "voice": "Voice needs the gateway WebSocket plus UDP/RTP; a synchronous HTTP server cannot join, speak or listen.",
    "gateway": "Gateway endpoints require a persistent WebSocket session; this server is HTTP-only by design.",
    "interactions": "Requires interaction tokens delivered over the gateway.",
    "promotion": "Promotional endpoints can grant paid perks; excluded.",
}

SECTION_MAP = {
    "Query String Params": "query",
    "JSON Params": "json",
    "JSON Body": "json",
    "JSON/Form Params": "json",
    "Extra JSON Params": "json",
    "Form Params": "form",
}

RENAME_PARAMS = {
    "guild_scheduled_event_id": "event_id",
    "notification_center_item_id": "notification_id",
    "poll_answer_id": "answer_id",
    "payment_source_id": "payment_source_id",
}


def convert_path(url: str) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(1)
        name = raw
        if name.endswith(".id"):
            name = name[: -len(".id")] + "_id"
        elif name.endswith(".code"):
            name = name[: -len(".code")] + "_code"
        name = name.replace(".", "_")
        return "{" + RENAME_PARAMS.get(name, name) + "}"

    return re.sub(r"\{([^}]+)\}", repl, url)


def slug_id(method: str, path: str) -> str:
    cleaned = re.sub(r"[{}]", "", path)
    cleaned = cleaned.replace("/", ".").replace("@me", "me").replace("_id", "").strip(".")
    cleaned = re.sub(r"\.+", ".", cleaned).lower()
    return f"{cleaned}.{method.lower()}"


def parse_params(entry: dict, *, include_response: bool) -> dict:
    params: dict[str, list[dict]] = {}
    for section, rows in (entry.get("params") or {}).items():
        target = SECTION_MAP.get(section)
        if target is None:
            if section == "Response Body" and include_response:
                params["response"] = [
                    {
                        "name": row["name"],
                        "type": row["type"],
                        "required": row["required"],
                        "description": row["description"],
                    }
                    for row in rows
                ]
            continue
        bucket = params.setdefault(target, [])
        for row in rows:
            bucket.append(
                {
                    "name": row["name"],
                    "type": row["type"],
                    "required": row["required"],
                    "description": row["description"],
                }
            )
    return params


def main() -> int:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    overrides = json.loads(OVERRIDES.read_text(encoding="utf-8"))
    by_key = {(e["method"], e["url"]): e for e in inventory["endpoints"]}

    curated: dict[tuple[str, str], dict] = {}
    problems: list[str] = []
    seen_ids: set[str] = set()

    for section, default_status in (("implemented", "implemented"), ("unsupported", "unsupported")):
        for item in overrides.get(section, []):
            key = (item["method"], item["url"])
            doc = by_key.get(key)
            if doc is None:
                problems.append(f"override {item['id']}: {key} is not in the docs inventory")
                continue
            if key in curated:
                problems.append(f"override {item['id']}: duplicate {key}")
                continue
            if item["id"] in seen_ids:
                problems.append(f"duplicate endpoint id {item['id']}")
                continue
            seen_ids.add(item["id"])
            risk = item.get("risk")
            if section == "implemented" and risk not in VALID_RISKS:
                problems.append(f"{item['id']}: invalid risk {risk!r}")
            curated[key] = {
                "id": item["id"],
                "status": item.get("status", default_status),
                "risk": risk if section == "implemented" else None,
                "category": item.get("category") or PAGE_CATEGORY.get(doc["page"], doc["page"]),
                "tools": item.get("tools", []),
                "summary": item.get("summary") or doc.get("title") or "",
                "limitations": item.get("reason")
                or (
                    "Not exposed as an MCP tool in this build; documented for completeness."
                ),
                "doc": doc,
            }

    entries: list[dict] = []
    for item in curated.values():
        doc = item["doc"]
        entries.append(
            {
                "id": item["id"],
                "method": doc["method"],
                "path": convert_path(doc["url"]),
                "category": item["category"],
                "title": doc.get("title", ""),
                "summary": item["summary"],
                "risk": item["risk"],
                "status": item["status"],
                "tools": item["tools"],
                "params": parse_params(doc, include_response=item["status"] == "implemented"),
                "oauth2_scope": doc.get("oauth2_scope"),
                "supports_bot": doc.get("supports_bot", False),
                "deprecated": doc.get("deprecated", False),
                "limitations": item["limitations"],
                "source": doc["source"],
            }
        )

    for doc in inventory["endpoints"]:
        key = (doc["method"], doc["url"])
        if key in curated:
            continue
        category = PAGE_CATEGORY.get(doc["page"], doc["page"])
        policy = PAGE_POLICY_REASON.get(doc["page"])
        status = "unsupported" if policy else "documented"
        entry_id = slug_id(doc["method"], convert_path(doc["url"]))
        while entry_id in seen_ids:
            entry_id += "x"
        seen_ids.add(entry_id)
        entries.append(
            {
                "id": entry_id,
                "method": doc["method"],
                "path": convert_path(doc["url"]),
                "category": category,
                "title": doc.get("title", ""),
                "summary": (doc.get("description") or doc.get("title") or "")[:280],
                "risk": None,
                "status": status,
                "tools": [],
                "params": parse_params(doc, include_response=False),
                "oauth2_scope": doc.get("oauth2_scope"),
                "supports_bot": doc.get("supports_bot", False),
                "deprecated": doc.get("deprecated", False),
                "limitations": policy
                or "Documented in the community user-API docs; this build does not expose it as a tool.",
                "source": doc["source"],
            }
        )

    for entry in entries:
        if entry["status"] not in VALID_STATUS:
            problems.append(f"{entry['id']}: bad status {entry['status']}")

    if problems:
        print("Registry build failed:", file=sys.stderr)
        for problem in problems:
            print(" -", problem, file=sys.stderr)
        return 1

    entries.sort(key=lambda e: (e["category"], e["path"], e["method"]))
    payload = {
        "generated_from": inventory.get("generated_from"),
        "docs_note": (
            "Endpoint shapes come from the community-maintained user-API documentation "
            "at docs.discord.food (MIT). Status/risk/tool mapping is this project's curation."
        ),
        "count": len(entries),
        "entries": entries,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    implemented = sum(1 for e in entries if e["status"] == "implemented")
    unsupported = sum(1 for e in entries if e["status"] == "unsupported")
    documented = sum(1 for e in entries if e["status"] == "documented")
    print(
        f"registry: {len(entries)} endpoints "
        f"({implemented} implemented, {documented} documented, {unsupported} unsupported) -> {OUT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
