"""Approval gate: approve, deny, expiry, tampering, replay, single execution."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from discord_user_mcp.api.errors import (
    ApprovalAlreadyDecided,
    ApprovalConfirmationRequired,
    ApprovalExpired,
    ApprovalNotFound,
    ConfigError,
)
from discord_user_mcp.security.approval import (
    ApprovalManager,
    ApprovalStore,
    ToolRequest,
    args_digest,
)
from discord_user_mcp.security.audit import AuditLogger
from discord_user_mcp.security.permissions import Risk

from conftest import make_settings


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class Gate:
    def __init__(self, state_dir: Path, *, ttl: int = 300) -> None:
        self.settings = make_settings(state_dir, approval={"ttl_seconds": ttl})
        self.clock = Clock()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.audit = AuditLogger(state_dir / "audit.jsonl")
        self.store = ApprovalStore(state_dir / "approvals.sqlite3")

        async def executor(tool: str, args: dict[str, Any]) -> Any:
            self.calls.append((tool, args))
            return {"sent": True, "tool": tool}

        self.manager = ApprovalManager(
            self.settings,
            self.store,
            self.audit,
            executor=executor,
            clock=self.clock,
        )
        self.manager.bind_loop(asyncio.get_running_loop())

    async def request(self, **overrides: Any):
        payload = {
            "tool": "send_message",
            "endpoint_id": "messages.create",
            "risk": Risk.WRITE,
            "summary": "Send a message to 123",
            "target": "channel_id=123",
            "args": {"channel_id": "123", "content": "hello"},
        }
        payload.update(overrides)
        return await self.manager.request(ToolRequest(**payload))


async def wait_for(store: ApprovalStore, approval_id: str, status: str, timeout: float = 5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        record = store.get(approval_id)
        if record and record.status == status:
            return record
        await asyncio.sleep(0.02)
    raise AssertionError(
        f"approval {approval_id} never reached {status} (now {store.get(approval_id).status})"
    )


async def test_request_creates_pending_without_executing(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    assert approval.status == "pending"
    assert approval.id.startswith("ap_")
    assert gate.calls == []
    public = approval.public(now=gate.clock.now)
    assert public["expires_in_seconds"] == 300
    assert public["args_hash"] == args_digest(approval.args)


async def test_approve_executes_once(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    done = await wait_for(gate.store, approval.id, "completed")
    assert done.result == {"sent": True, "tool": "send_message"}
    assert gate.calls == [("send_message", {"channel_id": "123", "content": "hello"})]
    # Executing again is impossible: the row is no longer 'approved'.
    assert gate.store.claim_execution(approval.id, gate.clock.now) is False
    await gate.manager._execute(approval.id)
    assert len(gate.calls) == 1


async def test_approve_twice_is_rejected(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    with pytest.raises(ApprovalAlreadyDecided):
        await gate.manager.approve(approval.id, actor="console:test", confirmation=None)


async def test_deny_never_executes(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    await gate.manager.deny(approval.id, actor="console:test", reason="no")
    record = gate.store.get(approval.id)
    assert record.status == "denied"
    await asyncio.sleep(0.05)
    assert gate.calls == []
    with pytest.raises(ApprovalAlreadyDecided):
        await gate.manager.approve(approval.id, actor="console:test", confirmation=None)


async def test_expired_approval_cannot_be_approved(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state", ttl=30)
    approval = await gate.request()
    gate.clock.now += 31
    with pytest.raises(ApprovalExpired):
        await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    assert gate.store.get(approval.id).status == "expired"
    assert gate.calls == []


async def test_expired_pending_never_executes_even_if_row_says_approved(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state", ttl=30)
    approval = await gate.request()
    gate.clock.now += 31
    # Force the row into 'approved' behind the manager's back.
    with sqlite3.connect(gate.store.path) as conn:
        conn.execute("UPDATE approvals SET status='approved' WHERE id=?", (approval.id,))
    await gate.manager._execute(approval.id)
    # The gate executes only rows it decided on; a stale pending row cannot run.
    assert gate.store.get(approval.id).status == "expired"
    assert gate.calls == []


async def test_sensitive_risk_requires_typed_confirmation(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request(risk=Risk.SENSITIVE, tool="update_my_profile")
    with pytest.raises(ApprovalConfirmationRequired):
        await gate.manager.approve(approval.id, actor="console:test", confirmation="yes")
    assert gate.store.get(approval.id).status == "pending"
    await gate.manager.approve(approval.id, actor="console:test", confirmation="APPROVE")
    await wait_for(gate.store, approval.id, "completed")


async def test_arguments_tampered_after_approval_do_not_execute(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    # The execution task has not been scheduled onto the loop yet, so the row
    # can be tampered with between the human decision and the execution.
    with sqlite3.connect(gate.store.path) as conn:
        conn.execute(
            "UPDATE approvals SET args_json=? WHERE id=?",
            (json.dumps({"channel_id": "123", "content": "evil"}), approval.id),
        )
    for _ in range(200):
        record = gate.store.get(approval.id)
        if record.status in {"completed", "failed"}:
            break
        await asyncio.sleep(0.01)
    assert record.status == "failed"
    assert record.error and record.error["code"] == "approval_arguments_tampered"
    assert gate.calls == []


async def test_replay_of_completed_approval_cannot_execute(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    await wait_for(gate.store, approval.id, "completed")
    with pytest.raises(ApprovalAlreadyDecided):
        await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    with pytest.raises(ApprovalAlreadyDecided):
        await gate.manager.cancel(approval.id, actor="console:mcp")
    assert len(gate.calls) == 1


async def test_cancel_pending_is_safe(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    result = await gate.manager.cancel(approval.id, actor="mcp-client:cancel")
    assert result["status"] == "cancelled"
    assert gate.store.get(approval.id).status == "cancelled"
    assert gate.calls == []


async def test_unknown_approval_id(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    with pytest.raises(ApprovalNotFound):
        gate.manager.check("ap_doesnotexist")


async def test_approval_without_a_loop_fails_closed(tmp_path: Path) -> None:
    """If the gate is not bound to a running loop, it must refuse to approve."""
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    gate.manager._loop = None
    with pytest.raises(ConfigError, match="finished starting"):
        await gate.manager.approve(approval.id, actor="console:test", confirmation=None)
    assert gate.store.get(approval.id).status == "pending"
    assert gate.calls == []


async def test_restart_marks_inflight_approvals_failed(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    with sqlite3.connect(gate.store.path) as conn:
        conn.execute("UPDATE approvals SET status='executing' WHERE id=?", (approval.id,))
    ApprovalManager(gate.settings, gate.store, gate.audit, executor=gate.manager.executor)
    assert gate.store.get(approval.id).status == "failed"


async def test_audit_log_records_decisions(tmp_path: Path) -> None:
    gate = Gate(tmp_path / "state")
    approval = await gate.request()
    await gate.manager.deny(approval.id, actor="console:test", reason="not now")
    events = [entry["event"] for entry in gate.audit.tail(20)]
    assert "approval_requested" in events
    assert "approval_denied" in events
