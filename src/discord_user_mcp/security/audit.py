"""Append-only audit log for every approval decision and execution.

The log is JSONL, rotated at a size limit, and every value passes through the
redaction helpers so a token can never be written to disk here.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from ..utils.redact import redact_value

logger = logging.getLogger(__name__)

_MAX_PREVIEW = 600


class AuditLogger:
    def __init__(self, path: Path, *, enabled: bool = True, max_bytes: int = 5 * 1024 * 1024) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        if enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        if not self.enabled:
            return
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
        }
        for key, value in fields.items():
            if key in {"args"} and isinstance(value, dict):
                entry["args_hash"] = entry.get("args_hash")
                entry["args_preview"] = self._preview(value)
            else:
                entry[key] = redact_value(value)
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        with self._lock:
            try:
                self._rotate_if_needed()
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError as exc:  # pragma: no cover - disk problems
                logger.error("could not write audit log: %s", exc)

    def _preview(self, args: dict[str, Any]) -> dict[str, Any]:
        preview: dict[str, Any] = {}
        for key, value in args.items():
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
            if len(text) > _MAX_PREVIEW:
                text = text[:_MAX_PREVIEW] + "...(truncated)"
            preview[key] = text
        return redact_value(preview)

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                backup = self.path.with_suffix(self.path.suffix + ".1")
                if backup.exists():
                    backup.unlink()
                os.replace(self.path, backup)
        except OSError:  # pragma: no cover - best effort
            pass

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.enabled or not self.path.exists():
            return []
        limit = max(1, min(limit, 500))
        with self._lock:
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    lines = handle.readlines()
            except OSError:
                return []
        rows = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        return rows
