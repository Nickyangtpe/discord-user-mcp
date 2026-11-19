"""Redaction and audit logging: a token must never reach a log or a file."""

from __future__ import annotations

import json
from pathlib import Path

from discord_user_mcp.security.audit import AuditLogger
from discord_user_mcp.utils.redact import (
    REDACTED,
    redact,
    redact_value,
    register_secret,
)

from conftest import TEST_TOKEN


def test_registered_secret_is_scrubbed() -> None:
    register_secret(TEST_TOKEN)
    assert TEST_TOKEN not in redact(f"Authorization: {TEST_TOKEN}")
    assert REDACTED in redact(f"token={TEST_TOKEN}")


def test_token_shaped_string_is_scrubbed_even_if_unknown() -> None:
    unknown = "mfa." + "Z" * 24 + "." + "Y" * 6 + "." + "X" * 27
    assert unknown not in redact(f"leaked {unknown}")


def test_nested_values_are_redacted() -> None:
    payload = {
        "content": "hi",
        "headers": {"authorization": TEST_TOKEN},
        "token": TEST_TOKEN,
        "items": [f"x {TEST_TOKEN}"],
    }
    cleaned = redact_value(payload)
    text = json.dumps(cleaned)
    assert TEST_TOKEN not in text
    assert cleaned["content"] == "hi"


def test_audit_log_never_writes_the_token(tmp_path: Path) -> None:
    register_secret(TEST_TOKEN)
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.record(
        "approval_requested",
        tool="send_message",
        args={"content": f"oops {TEST_TOKEN}"},
        note=f"Authorization: {TEST_TOKEN}",
    )
    audit.record("approval_granted", approval_id="ap_1", actor="console:test")
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert TEST_TOKEN not in raw
    entries = audit.tail(10)
    assert entries[0]["event"] == "approval_requested"
    assert "args_preview" in entries[0]
    assert TEST_TOKEN not in json.dumps(entries)


def test_audit_tail_is_bounded(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    for index in range(20):
        audit.record("tick", index=index)
    assert len(audit.tail(5)) == 5


def test_audit_can_be_disabled(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.jsonl", enabled=False)
    audit.record("tick", value=1)
    assert not (tmp_path / "audit.jsonl").exists()
    assert audit.tail() == []
