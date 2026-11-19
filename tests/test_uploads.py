"""Uploads may only read files under an explicitly allowed root."""

from __future__ import annotations

from pathlib import Path

import pytest

from discord_user_mcp.api.errors import UploadError
from discord_user_mcp.tools.uploads import load_files

from conftest import make_settings


@pytest.fixture
def roots(tmp_path: Path):
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    settings = make_settings(
        tmp_path / "state",
        upload={"allowed_roots": [upload_root], "max_bytes": 1024, "max_files": 2},
    )
    return settings, upload_root


def test_reads_a_file_inside_the_root(roots) -> None:
    settings, upload_root = roots
    target = upload_root / "note.txt"
    target.write_text("hello", encoding="utf-8")
    files = load_files(settings, [str(target)])
    assert files[0][0] == "files[0]"
    assert files[0][1][0] == "note.txt"
    assert files[0][1][1] == b"hello"
    assert files[0][1][2].startswith("text/plain")


def test_rejects_a_file_outside_the_root(roots, tmp_path: Path) -> None:
    settings, _ = roots
    secret = tmp_path / "secret.txt"
    secret.write_text("do not read", encoding="utf-8")
    with pytest.raises(UploadError, match="allowed root"):
        load_files(settings, [str(secret)])


def test_rejects_path_traversal(roots) -> None:
    settings, upload_root = roots
    target = upload_root / ".." / "escape.txt"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(UploadError):
        load_files(settings, [str(target)])


def test_rejects_missing_file(roots) -> None:
    settings, upload_root = roots
    with pytest.raises(UploadError, match="not found"):
        load_files(settings, [str(upload_root / "missing.bin")])


def test_rejects_a_directory(roots) -> None:
    settings, upload_root = roots
    nested = upload_root / "dir"
    nested.mkdir()
    with pytest.raises(UploadError, match="regular file"):
        load_files(settings, [str(nested)])


def test_enforces_size_limit(roots) -> None:
    settings, upload_root = roots
    target = upload_root / "big.bin"
    target.write_bytes(b"x" * 2048)
    with pytest.raises(UploadError, match="limit"):
        load_files(settings, [str(target)])


def test_enforces_file_count(roots) -> None:
    settings, upload_root = roots
    paths = []
    for index in range(3):
        path = upload_root / f"f{index}.txt"
        path.write_text("x", encoding="utf-8")
        paths.append(str(path))
    with pytest.raises(UploadError, match="At most"):
        load_files(settings, paths)


def test_uploads_can_be_disabled(tmp_path: Path) -> None:
    settings = make_settings(tmp_path / "state", upload={"enabled": False})
    with pytest.raises(UploadError, match="disabled"):
        load_files(settings, ["anything.txt"])
