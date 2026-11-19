"""The mandatory human approval gate.

Nothing that changes Discord state is sent until a human has approved the
exact operation in the local approval console. The gate lives in the server
core, so it applies to direct MCP tool calls, scripted clients and tests.

Guarantees
----------
* A mutating tool call only creates a *pending* record. No HTTP request is made.
* The record stores the exact tool name and arguments, plus a SHA-256 digest.
* Approval can only be granted through the local console (there is no MCP tool
  that approves anything).
* ``UPDATE ... WHERE status='pending'`` makes decisions single-shot: approving
  twice, replaying an approval id or reusing a completed one is impossible.
* Execution re-verifies the stored digest and uses the *stored* arguments, so
  changing parameters after approval invalidates the record.
* Records expire (default 5 minutes) and expired records can never execute.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..api.errors import (
    ApprovalAlreadyDecided,
    ApprovalConfirmationRequired,
    ApprovalExpired,
    ApprovalNotFound,
    ApprovalTampered,
    ConfigError,
)
from ..config import Settings
from ..security.permissions import APPROVAL_PHRASE, Risk
from ..utils.redact import redact_value
from .audit import AuditLogger

logger = logging.getLogger(__name__)

MAX_RESULT_BYTES = 256 * 1024


def canonical_args(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def args_digest(args: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_args(args).encode("utf-8")).hexdigest()


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class Approval:
    id: str
    tool: str
    endpoint_id: str
    risk: Risk
    summary: str
    target: str
    args: dict[str, Any]
    args_hash: str
    status: str
    created_at: float
    expires_at: float
    decided_at: float | None = None
    decided_by: str | None = None
    decision_note: str | None = None
    executed_at: float | None = None
    result: Any = None
    error: dict[str, Any] | None = None

    def public(self, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        return {
            "approval_id": self.id,
            "tool": self.tool,
            "endpoint": self.endpoint_id,
            "risk": self.risk.value,
            "risk_label": self.risk.label,
            "summary": self.summary,
            "target": self.target,
            "status": self.status,
            "args": self.args,
            "args_hash": self.args_hash,
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
            "expires_in_seconds": max(0, int(self.expires_at - now)),
            "requires_typed_confirmation": self.risk.requires_typed_confirmation,
            "approval_phrase": APPROVAL_PHRASE if self.risk.requires_typed_confirmation else None,
            "decided_at": iso(self.decided_at),
            "decided_by": self.decided_by,
            "decision_note": self.decision_note,
            "executed_at": iso(self.executed_at),
            "result": self.result,
            "error": self.error,
        }


class ApprovalStore:
    """SQLite persistence so an approval survives a tool-loop restart."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    tool TEXT NOT NULL,
                    endpoint_id TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    args_json TEXT NOT NULL,
                    args_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    decided_at REAL,
                    decided_by TEXT,
                    decision_note TEXT,
                    executed_at REAL,
                    result_json TEXT,
                    error_json TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at)")

    # -- writes ------------------------------------------------------------

    def create(self, approval: Approval) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (id, tool, endpoint_id, risk, summary, target,
                    args_json, args_hash, status, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.id,
                    approval.tool,
                    approval.endpoint_id,
                    approval.risk.value,
                    approval.summary,
                    approval.target,
                    canonical_args(approval.args),
                    approval.args_hash,
                    approval.status,
                    approval.created_at,
                    approval.expires_at,
                ),
            )

    def decide(self, approval_id: str, status: str, actor: str, note: str | None, now: float) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE approvals
                   SET status = ?, decided_at = ?, decided_by = ?, decision_note = ?
                 WHERE id = ? AND status = 'pending' AND expires_at > ?
                """,
                (status, now, actor, note, approval_id, now),
            )
            return cursor.rowcount == 1

    def claim_execution(self, approval_id: str, now: float) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status = 'executing', executed_at = ? WHERE id = ? AND status = 'approved'",
                (now, approval_id),
            )
            return cursor.rowcount == 1

    def finish(
        self,
        approval_id: str,
        status: str,
        *,
        result: Any = None,
        error: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> None:
        result_json = None
        if result is not None:
            dumped = json.dumps(redact_value(result), ensure_ascii=False, default=str)
            if len(dumped.encode("utf-8")) > MAX_RESULT_BYTES:
                dumped = json.dumps(
                    {"truncated": True, "reason": "result exceeded 256KiB, fetch with a narrower query"}
                )
            result_json = dumped
        error_json = json.dumps(redact_value(error), ensure_ascii=False) if error else None
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE approvals SET status = ?, result_json = ?, error_json = ?, executed_at = COALESCE(?, executed_at) WHERE id = ?",
                (status, result_json, error_json, now, approval_id),
            )

    def expire_stale(self, now: float) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?",
                (now,),
            )
            return cursor.rowcount

    def mark_orphaned(self) -> int:
        """On restart, approved-but-unexecuted rows cannot run: fail them closed."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status = 'failed', error_json = ? WHERE status IN ('approved','executing')",
                (json.dumps({"code": "server_restarted", "message": "Server restarted before execution"}),),
            )
            return cursor.rowcount

    # -- reads -------------------------------------------------------------

    def get(self, approval_id: str) -> Approval | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return self._row(row) if row else None

    def list(self, *, statuses: list[str] | None = None, limit: int = 50) -> list[Approval]:
        query = "SELECT * FROM approvals"
        params: list[Any] = []
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            query += f" WHERE status IN ({placeholders})"
            params.extend(statuses)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 200)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row: sqlite3.Row) -> Approval:
        result = json.loads(row["result_json"]) if row["result_json"] else None
        error = json.loads(row["error_json"]) if row["error_json"] else None
        return Approval(
            id=row["id"],
            tool=row["tool"],
            endpoint_id=row["endpoint_id"],
            risk=Risk.coerce(row["risk"]),
            summary=row["summary"],
            target=row["target"],
            args=json.loads(row["args_json"]),
            args_hash=row["args_hash"],
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_note=row["decision_note"],
            executed_at=row["executed_at"],
            result=result,
            error=error,
        )


@dataclass
class ToolRequest:
    """What the gate needs to know about a tool call."""

    tool: str
    endpoint_id: str
    risk: Risk
    summary: str
    target: str
    args: dict[str, Any]
    extra: dict[str, Any] = field(default_factory=dict)


Executor = Callable[[str, dict[str, Any]], Awaitable[Any]]


class ApprovalManager:
    def __init__(
        self,
        settings: Settings,
        store: ApprovalStore,
        audit: AuditLogger,
        executor: Executor,
        *,
        console: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.store = store
        self.audit = audit
        self.executor = executor
        self.console = console
        self._clock = clock
        self._tasks: set[asyncio.Task] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        orphaned = store.mark_orphaned()
        if orphaned:
            logger.warning("%d approval(s) were interrupted by a restart and were marked failed", orphaned)

    # -- lifecycle ---------------------------------------------------------

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        if self.console is not None:
            self.console.start(loop)

    def ensure_console(self) -> None:
        if not self.settings.approval.console_enabled:
            raise ConfigError(
                "The approval console is disabled, so no mutating operation can ever be approved. "
                "Re-enable it with DISCORD_MCP_CONSOLE_ENABLED=1."
            )
        if self._loop is None:
            raise ConfigError("Approval gate used before the server finished starting")
        if self.console is not None and not self.console.running:
            self.console.start(self._loop)

    # -- gate --------------------------------------------------------------

    async def request(self, request: ToolRequest) -> Approval:
        self.ensure_console()
        now = self._clock()
        self.store.expire_stale(now)
        approval = Approval(
            id="ap_" + secrets.token_urlsafe(18),
            tool=request.tool,
            endpoint_id=request.endpoint_id,
            risk=request.risk,
            summary=request.summary,
            target=request.target,
            args=request.args,
            args_hash=args_digest(request.args),
            status="pending",
            created_at=now,
            expires_at=now + self.settings.approval.ttl_seconds,
        )
        self.store.create(approval)
        self.audit.record(
            "approval_requested",
            approval_id=approval.id,
            tool=approval.tool,
            endpoint=approval.endpoint_id,
            risk=approval.risk.value,
            summary=approval.summary,
            target=approval.target,
            args=approval.args,
            args_hash=approval.args_hash,
            expires_at=iso(approval.expires_at),
        )
        logger.info(
            "approval %s pending: %s (%s) - open the approval console to decide",
            approval.id,
            approval.summary,
            approval.risk.value,
        )
        return approval

    def get(self, approval_id: str) -> Approval:
        self.store.expire_stale(self._clock())
        approval = self.store.get(approval_id)
        if approval is None:
            raise ApprovalNotFound(f"No approval with id {approval_id!r}")
        return approval

    def check(self, approval_id: str) -> dict[str, Any]:
        approval = self.get(approval_id)
        return approval.public()

    def list(self, *, statuses: list[str] | None = None, limit: int = 50) -> list[dict[str, Any]]:
        self.store.expire_stale(self._clock())
        return [record.public() for record in self.store.list(statuses=statuses, limit=limit)]

    async def approve(self, approval_id: str, *, actor: str, confirmation: str | None, note: str | None = None) -> dict[str, Any]:
        approval = self.get(approval_id)
        self.ensure_console()
        if approval.status == "expired" or (
            approval.status == "pending" and self._clock() >= approval.expires_at
        ):
            self.store.expire_stale(self._clock())
            raise ApprovalExpired(f"Approval {approval_id} expired before it was approved.")
        if approval.status in {"denied", "expired", "cancelled", "completed", "failed", "executing", "approved"}:
            raise ApprovalAlreadyDecided(
                f"Approval {approval_id} is already {approval.status}; it cannot be approved again."
            )
        if approval.risk.requires_typed_confirmation:
            if (confirmation or "").strip() != APPROVAL_PHRASE:
                raise ApprovalConfirmationRequired(
                    f"This operation is classified {approval.risk.value!r}. "
                    f"Type {APPROVAL_PHRASE} to confirm it explicitly."
                )
        now = self._clock()
        if not self.store.decide(approval_id, "approved", actor, note, now):
            raise ApprovalAlreadyDecided(
                f"Approval {approval_id} was already decided or expired."
            )
        self.audit.record(
            "approval_granted",
            approval_id=approval_id,
            tool=approval.tool,
            risk=approval.risk.value,
            actor=actor,
            args_hash=approval.args_hash,
            note=note,
        )
        logger.info("approval %s granted by %s; executing", approval_id, actor)
        self._schedule_execution(approval_id)
        return {"approval_id": approval_id, "status": "approved", "execution": "scheduled"}

    async def deny(self, approval_id: str, *, actor: str, reason: str | None = None) -> dict[str, Any]:
        approval = self.get(approval_id)
        if approval.status != "pending":
            raise ApprovalAlreadyDecided(
                f"Approval {approval_id} is already {approval.status}; it cannot be denied."
            )
        if not self.store.decide(approval_id, "denied", actor, reason, self._clock()):
            raise ApprovalAlreadyDecided(f"Approval {approval_id} was already decided or expired.")
        self.audit.record(
            "approval_denied",
            approval_id=approval_id,
            tool=approval.tool,
            risk=approval.risk.value,
            actor=actor,
            note=reason,
        )
        logger.info("approval %s denied by %s", approval_id, actor)
        return {"approval_id": approval_id, "status": "denied"}

    async def cancel(self, approval_id: str, *, actor: str) -> dict[str, Any]:
        """Cancelling a *pending* request is always safe; it never executes."""
        approval = self.get(approval_id)
        if approval.status != "pending":
            raise ApprovalAlreadyDecided(f"Approval {approval_id} is already {approval.status}.")
        if not self.store.decide(approval_id, "cancelled", actor, "cancelled before decision", self._clock()):
            raise ApprovalAlreadyDecided(f"Approval {approval_id} was already decided or expired.")
        self.audit.record("approval_cancelled", approval_id=approval_id, tool=approval.tool, actor=actor)
        return {"approval_id": approval_id, "status": "cancelled"}

    # -- execution ---------------------------------------------------------

    def _schedule_execution(self, approval_id: str) -> None:
        if self._loop is None or not self._loop.is_running():
            # Fail closed: never run an approved operation outside the event loop.
            self.store.finish(
                approval_id,
                "failed",
                error={"code": "no_event_loop", "message": "Event loop unavailable"},
                now=self._clock(),
            )
            return
        task = self._loop.create_task(self._execute(approval_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _execute(self, approval_id: str) -> None:
        approval = self.store.get(approval_id)
        if approval is None:
            return
        if approval.status != "approved":
            logger.warning("approval %s is %s, refusing to execute", approval_id, approval.status)
            return
        # Expiry is enforced at execution time as well as at decision time, so a
        # row forced into 'approved' after its window can never run.
        if self._clock() >= approval.expires_at:
            self.store.finish(
                approval_id,
                "expired",
                error={
                    "code": "approval_expired",
                    "message": "The approval expired before it could be executed",
                },
                now=self._clock(),
            )
            self.audit.record("approval_expired", approval_id=approval_id, tool=approval.tool)
            return
        # Integrity: the stored arguments must still match the approved digest.
        if args_digest(approval.args) != approval.args_hash:
            self.store.finish(
                approval_id,
                "failed",
                error={
                    "code": "approval_arguments_tampered",
                    "message": "Stored arguments no longer match the approved digest",
                },
                now=self._clock(),
            )
            self.audit.record("approval_tampered", approval_id=approval_id, tool=approval.tool)
            return
        if not self.store.claim_execution(approval_id, self._clock()):
            return
        try:
            result = await self.executor(approval.tool, approval.args)
        except Exception as exc:  # noqa: BLE001 - every failure is reported, never retried
            error = getattr(exc, "to_dict", None)
            payload = error() if callable(error) else {"code": "execution_error", "message": str(exc)}
            self.store.finish(approval_id, "failed", error=payload, now=self._clock())
            self.audit.record(
                "execution_failed",
                approval_id=approval_id,
                tool=approval.tool,
                risk=approval.risk.value,
                error=payload,
            )
            logger.error("approval %s execution failed: %s", approval_id, payload.get("message"))
            return
        self.store.finish(approval_id, "completed", result=result, now=self._clock())
        self.audit.record(
            "execution_completed",
            approval_id=approval_id,
            tool=approval.tool,
            endpoint=approval.endpoint_id,
            risk=approval.risk.value,
            result=result,
        )
        logger.info("approval %s executed successfully", approval_id)


__all__ = [
    "Approval",
    "ApprovalManager",
    "ApprovalStore",
    "ToolRequest",
    "args_digest",
    "canonical_args",
    "iso",
]
