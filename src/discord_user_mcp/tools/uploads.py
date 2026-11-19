"""Attachment loading with a strict allow-list.

Uploads can exfiltrate local files, so paths are resolved and must live under
a configured root (default: ``<state>/uploads``). Nothing outside those roots
is ever read.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Sequence

from ..api.errors import UploadError
from ..config import Settings

MimeFiles = list[tuple[str, tuple[str, bytes, str]]]


def load_files(settings: Settings, paths: Sequence[str]) -> MimeFiles:
    if not paths:
        return []
    if not settings.upload.enabled:
        raise UploadError("Uploads are disabled (DISCORD_MCP_UPLOADS_ENABLED=0)")
    if len(paths) > settings.upload.max_files:
        raise UploadError(
            f"At most {settings.upload.max_files} files per message; got {len(paths)}"
        )

    roots = [Path(root).expanduser().resolve() for root in settings.upload.allowed_roots]
    if not roots:
        raise UploadError("No upload roots configured; refusing to read local files")

    files: MimeFiles = []
    total = 0
    for index, raw in enumerate(paths):
        candidate = Path(raw).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise UploadError(f"Attachment not found or unreadable: {raw}") from exc
        if not resolved.is_file():
            raise UploadError(f"Attachment is not a regular file: {raw}")
        if not any(_is_within(resolved, root) for root in roots):
            allowed = ", ".join(str(root) for root in roots)
            raise UploadError(
                f"Refusing to read {raw}: attachments must live under an allowed root ({allowed}). "
                "Set DISCORD_MCP_UPLOAD_ROOTS to add a directory."
            )
        size = resolved.stat().st_size
        if size > settings.upload.max_bytes:
            raise UploadError(
                f"{resolved.name} is {size} bytes, above the {settings.upload.max_bytes} byte limit"
            )
        total += size
        if total > settings.upload.max_bytes:
            raise UploadError(
                f"Attachments total {total} bytes, above the {settings.upload.max_bytes} byte limit"
            )
        data = resolved.read_bytes()
        mime = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
        files.append((f"files[{index}]", (resolved.name, data, mime)))
    return files


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
