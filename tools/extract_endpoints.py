"""Extract every endpoint documented on docs.discord.food into JSON.

Development-time provenance tool. It downloads the community-maintained
`discord-userdoccers` MDX sources (the same content served by
https://docs.discord.food) and parses each ``<RouteHeader>`` block together
with the parameter tables that follow it.

Usage:
    python tools/extract_endpoints.py --out research/endpoint-inventory.json
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

RAW = "https://raw.githubusercontent.com/discord-userdoccers/discord-userdoccers/master/"
PAGES_API = (
    "https://api.github.com/repos/discord-userdoccers/discord-userdoccers/git/trees/master?recursive=1"
)

ROUTE_RE = re.compile(r"<RouteHeader(?P<attrs>.*?)>(?P<body>.*?)</RouteHeader>", re.S)
TABLE_ROW_RE = re.compile(r"^\|\s*(?P<field>[^|]+?)\s*\|\s*(?P<type>[^|]+?)\s*\|\s*(?P<desc>.*?)\s*\|$")
SECTION_RE = re.compile(r"^######\s+(?P<name>.+?)\s*$")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "discord-user-mcp-registry-builder"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL
        return resp.read().decode("utf-8")


def list_pages() -> list[str]:
    tree = json.loads(fetch(PAGES_API))
    return [
        item["path"]
        for item in tree.get("tree", [])
        if item["type"] == "blob" and item["path"].startswith("pages/") and item["path"].endswith(".mdx")
    ]


def parse_attrs(attrs: str) -> dict:
    flags = {}
    for name in ("supportsBot", "supportsAuditReason", "unauthenticated", "mfa", "deprecated"):
        if re.search(rf"\b{name}\b", attrs):
            flags[name] = True
    method = re.search(r'method="([A-Z]+)"', attrs)
    url = re.search(r'url="([^"]+)"', attrs)
    oauth = re.search(r'supportsOAuth2="([^"]+)"', attrs)
    return {
        "method": method.group(1) if method else None,
        "url": url.group(1) if url else None,
        "oauth2_scope": oauth.group(1) if oauth else None,
        **flags,
    }


def parse_param_table(lines: list[str]) -> list[dict]:
    params = []
    for line in lines:
        m = TABLE_ROW_RE.match(line)
        if not m:
            continue
        field = m.group("field").strip()
        if field.lower() == "field" or set(field) <= {"-", " "}:
            continue
        required = not field.endswith("?")
        params.append(
            {
                "name": field.rstrip("?"),
                "type": m.group("type").strip(),
                "required": required,
                "description": re.sub(r"\s+", " ", m.group("desc")).strip(),
            }
        )
    return params


def parse_page(path: str, text: str) -> list[dict]:
    page_name = Path(path).stem
    out = []
    for match in ROUTE_RE.finditer(text):
        attrs = parse_attrs(match.group("attrs"))
        if not attrs["method"] or not attrs["url"]:
            continue
        body = match.group("body")
        lines = body.splitlines()
        title = next((ln.strip() for ln in lines if ln.strip()), "")

        # Parameter tables live between this route header and the next one.
        tail = text[match.end() :]
        next_header = tail.find("<RouteHeader")
        region = tail if next_header == -1 else tail[:next_header]
        sections: dict[str, list[dict]] = {}
        current = None
        bucket: list[str] = []
        for line in region.splitlines():
            sec = SECTION_RE.match(line)
            if sec:
                name = sec.group("name")
                if "Params" in name or "Body" in name:
                    current = name
                    bucket = []
                    sections.setdefault(name, [])
                else:
                    current = None
                continue
            if line.startswith("#") or line.startswith("<Alert") or line.startswith("<RouteHeader"):
                current = None
                continue
            if current and line.strip().startswith("|"):
                bucket.append(line)
                sections[current] = parse_param_table(bucket)
        description = []
        for line in region.splitlines():
            if line.startswith("#") or line.startswith("<") or line.strip().startswith("|"):
                if description:
                    break
                continue
            if line.strip():
                description.append(line.strip())
        out.append(
            {
                "page": page_name,
                "title": title,
                "method": attrs["method"],
                "url": attrs["url"],
                "oauth2_scope": attrs["oauth2_scope"],
                "supports_bot": bool(attrs.get("supportsBot")),
                "supports_audit_reason": bool(attrs.get("supportsAuditReason")),
                "unauthenticated": bool(attrs.get("unauthenticated")),
                "mfa": bool(attrs.get("mfa")),
                "deprecated": bool(attrs.get("deprecated")),
                "description": re.sub(r"\s+", " ", " ".join(description))[:600],
                "params": sections,
                "source": f"https://docs.discord.food/resources/{page_name}",
            }
        )
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="research/endpoint-inventory.json")
    parser.add_argument("--cache", default="research/.mdx-cache")
    args = parser.parse_args()

    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    pages = list_pages()
    records: list[dict] = []
    for page in pages:
        local = cache / page.replace("/", "__")
        if local.exists():
            text = local.read_text(encoding="utf-8")
        else:
            text = fetch(RAW + page)
            local.write_text(text, encoding="utf-8")
        records.extend(parse_page(page, text))

    seen = set()
    unique = []
    for record in records:
        key = (record["method"], record["url"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "generated_from": RAW,
                "license_note": "Community documentation (MIT, discord-userdoccers). Parsed locally; no game data.",
                "count": len(unique),
                "endpoints": unique,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"pages={len(pages)} endpoints={len(unique)} -> {out}")


if __name__ == "__main__":
    main()
