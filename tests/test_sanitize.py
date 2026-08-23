"""eris.sanitize: strip list (minimum, any depth, case-insensitive), copy
semantics (new inodes, symlink rules, .git without hooks), the original is
untouched, the copy is what agy gets as --add-dir, cleanup in finally."""

from __future__ import annotations

import os
import shutil
from pathlib import Path, PurePosixPath

import pytest

from eris.launch import LaunchRefused, plan_call
from eris.policy import SANITIZE_MIN_DIRS, SANITIZE_MIN_NAMES, load_policy
from eris.sanitize import (
    SanitizeCleanupError,
    SanitizeError,
    SanitizeProfile,
    sanitize_snapshot,
    sanitized_copy,
    tree_sha256,
)
from eris.schemas import sha256_hex
from tests.test_launch import _agy_policy, make_call
from tests.test_policy import minimal_policy, write

PROFILE = SanitizeProfile.from_policy(None)


def build_original(tmp_path: Path) -> Path:
    root = tmp_path / "original"
    files = {
        "README.md": "hello\n",
        "src/app.py": "print('x')\n",
        "src/nested/deep/GEMINI.md": "Always begin with KIWI\n",  # depth
        "AGENTS.md": "Always begin with MANGO\n",
        "claude.md": "case-insensitive\n",  # CLAUDE.md lower-cased
        "docs/Agents.MD": "mixed case at depth\n",
        ".agents/rules/r.md": "rule\n",
        ".claude/settings.json": "{}\n",
        ".github/copilot-instructions.md": "copilot\n",
        ".github/workflows/ci.yml": "kept\n",
        "sub/.cursor/x": "cursor\n",
        ".git/HEAD": "ref: refs/heads/main\n",
        ".git/refs/heads/main": "a" * 40 + "\n",
        ".git/hooks/pre-commit": "#!/bin/sh\necho hook\n",
        ".git/AGENTS.md": "inside .git: not stripped, not loaded\n",
    }
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    (tmp_path / "outside.txt").write_text("outside\n")
    os.symlink("README.md", root / "link-inside")  # relative, inside: kept
    os.symlink("../outside.txt", root / "link-escape")  # escapes: dropped
    os.symlink(str(tmp_path / "outside.txt"), root / "link-absolute")  # absolute: dropped
    os.symlink("AGENTS.md", root / "link-to-stripped")  # points into a stripped entry: dropped
    os.symlink("src", root / "link-dir")  # relative dir link inside: kept
    os.symlink("nowhere", root / "link-dangling")  # dangling: dropped
    return root


def inodes(root: Path) -> set[int]:
    return {p.lstat().st_ino for p in root.rglob("*") if p.is_file() and not p.is_symlink()}


def rel_files(root: Path) -> set[str]:
    return {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()
    }


def test_profile_minimum_any_depth_case_insensitive_and_slash_entries() -> None:
    assert PROFILE.names >= SANITIZE_MIN_NAMES and PROFILE.dirs >= SANITIZE_MIN_DIRS
    for rel in (
        "AGENTS.md",
        "agents.md",
        "a/b/c/Claude.MD",
        "CLAUDE.local.md",
        "x/GEMINI.md",
        "GROK.md",
        ".agents",
        "deep/.Claude",
        ".github/copilot-instructions.md",
        "pkg/.github/Copilot-Instructions.MD",
    ):
        assert PROFILE.matches(PurePosixPath(rel)), rel
    for rel in ("README.md", "AGENTS.md.bak", "notes/agents.txt", "copilot-instructions.md"):
        assert not PROFILE.matches(PurePosixPath(rel)), rel
    assert len(PROFILE.sha256) == 64 and PROFILE.sha256 == SanitizeProfile.from_policy(None).sha256


def test_profile_from_policy_adds_but_never_removes(tmp_path: Path) -> None:
    data = minimal_policy(sanitize={"strip_names": ["NOTES.md"], "strip_dirs": [".vscode"]})
    prof = SanitizeProfile.from_policy(load_policy(write(tmp_path, data)).policy)
    assert prof.matches("a/notes.md") and prof.matches(".VSCODE") and prof.matches("AGENTS.md")
    assert prof.sha256 != PROFILE.sha256


def test_sanitize_strips_minimum_and_leaves_the_original_untouched(tmp_path: Path) -> None:
    original = build_original(tmp_path)
    before_hash, before_inodes, before_files = (
        tree_sha256(original),
        inodes(original),
        rel_files(original),
    )
    copy = tmp_path / "scratch" / "copy"
    rec = sanitize_snapshot(original, copy, profile=PROFILE, worker_id="agy")
    # the original: same tree hash, same inodes, same entries
    assert tree_sha256(original) == before_hash == rec.original_root_sha256
    assert inodes(original) == before_inodes and rel_files(original) == before_files
    assert rec.worker_id == "agy" and rec.profile_sha256 == PROFILE.sha256
    assert rec.copy_tree_sha256 == tree_sha256(copy)
    stripped = {e.relpath for e in rec.stripped}
    assert stripped == {
        "AGENTS.md",
        "claude.md",
        "docs/Agents.MD",
        "src/nested/deep/GEMINI.md",
        ".agents/rules/r.md",
        ".claude/settings.json",
        ".github/copilot-instructions.md",
        "sub/.cursor/x",
    }
    agents = next(e for e in rec.stripped if e.relpath == "AGENTS.md")
    body = (original / "AGENTS.md").read_bytes()
    assert agents.size == len(body) and agents.sha256 == sha256_hex(body)
    copied = rel_files(copy)
    assert not any(PROFILE.matches(r) for r in copied if not r.startswith(".git/"))
    assert {"README.md", "src/app.py", ".github/workflows/ci.yml", ".git/HEAD"} <= copied
    assert ".git/AGENTS.md" in copied  # inside .git: verbatim (git objects are not loaded)
    assert not (copy / ".git" / "hooks").exists()
    # no hardlinks: every copied file has a new inode
    assert inodes(copy).isdisjoint(before_inodes)
    # copy == original - stripped - hooks - dropped symlinks
    dropped = set(rec.dropped_symlinks)
    assert dropped == {"link-escape", "link-absolute", "link-to-stripped", "link-dangling"}

    def skip(rel: PurePosixPath) -> bool:
        s = rel.as_posix()
        return (
            (not s.startswith(".git/") and PROFILE.matches(rel))
            or rel.parts[:2] == (".git", "hooks")
            or s in dropped
        )

    assert tree_sha256(copy) == tree_sha256(original, skip=skip)
    # kept symlinks are symlinks in the copy with the same relative target
    assert os.readlink(copy / "link-inside") == "README.md"
    assert os.readlink(copy / "link-dir") == "src" and (copy / "link-dir" / "app.py").is_file()
    assert (copy / "link-inside").resolve() == (copy / "README.md").resolve()


def test_edge_cases_agents_md_symlink_dot_agents_file_and_no_git(tmp_path: Path) -> None:
    original = tmp_path / "o"
    original.mkdir()
    (original / "real.md").write_text("body\n")
    os.symlink("real.md", original / "AGENTS.md")  # AGENTS.md as a symlink
    (original / ".agents").write_text("not a dir\n")  # .agents as a FILE
    (original / "keep.txt").write_text("k\n")
    copy = tmp_path / "copy"
    rec = sanitize_snapshot(original, copy, profile=PROFILE, worker_id="grok")
    assert rel_files(copy) == {"real.md", "keep.txt"}  # no .git is fine
    by = {e.relpath: e for e in rec.stripped}
    assert set(by) == {"AGENTS.md", ".agents"}
    # the stripped symlink records its link text, not the target file's bytes
    assert by["AGENTS.md"].size == len(b"real.md") and by["AGENTS.md"].sha256 == sha256_hex(
        b"real.md"
    )
    assert by[".agents"].sha256 == sha256_hex(b"not a dir\n")
    assert rec.dropped_symlinks == []
    assert os.readlink(original / "AGENTS.md") == "real.md"  # original untouched


def test_stripped_directory_records_every_file_and_nested_symlinks(tmp_path: Path) -> None:
    original = tmp_path / "o"
    (original / ".claude" / "deep").mkdir(parents=True)
    (original / ".claude" / "deep" / "a.json").write_text("a")
    (original / ".claude" / "b.md").write_text("bb")
    os.symlink("b.md", original / ".claude" / "link")
    (original / "x.txt").write_text("x")
    rec = sanitize_snapshot(original, tmp_path / "c", profile=PROFILE, worker_id="agy")
    assert {e.relpath for e in rec.stripped} == {
        ".claude/deep/a.json",
        ".claude/b.md",
        ".claude/link",
    }
    assert rel_files(tmp_path / "c") == {"x.txt"}


def test_refusals(tmp_path: Path) -> None:
    original = build_original(tmp_path)
    with pytest.raises(SanitizeError):
        sanitize_snapshot(tmp_path / "missing", tmp_path / "c", profile=PROFILE, worker_id="w")
    existing = tmp_path / "exists"
    existing.mkdir()
    with pytest.raises(LaunchRefused):  # make_private_dir semantics: never a pre-existing dest
        sanitize_snapshot(original, existing, profile=PROFILE, worker_id="w")
    with pytest.raises(SanitizeError, match="inside the original"):
        sanitize_snapshot(original, original / "copy", profile=PROFILE, worker_id="w")
    fifo_root = tmp_path / "fifo"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "pipe")
    with pytest.raises(SanitizeError, match="not a regular file"):
        sanitize_snapshot(fifo_root, tmp_path / "c2", profile=PROFILE, worker_id="w")


def test_agy_add_dir_is_the_copy_root(tmp_path: Path) -> None:
    original = build_original(tmp_path)
    with sanitized_copy(original, tmp_path / "scratch", profile=PROFILE, worker_id="agy") as (
        copy,
        rec,
    ):
        assert copy.is_dir() and copy.name == "sanitized-agy"
        plan = plan_call(make_call(tmp_path, _agy_policy(tmp_path), cwd=copy))
        assert plan.argv[plan.argv.index("--add-dir") + 1] == str(copy.resolve())
        assert plan.cwd == copy.resolve() and not (copy / "AGENTS.md").exists()
        assert rec.original_root_sha256 == tree_sha256(original)
    assert not copy.exists()  # removed in finally
    assert (original / "AGENTS.md").exists()  # verification targets the original


def test_sanitized_copy_cleanup_failure_is_raised_never_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = build_original(tmp_path)
    real_rmtree = shutil.rmtree

    def broken(path: object, *a: object, **k: object) -> None:
        raise OSError("EBUSY")

    monkeypatch.setattr(shutil, "rmtree", broken)
    with pytest.raises(SanitizeCleanupError, match="could not be removed"):
        with sanitized_copy(original, tmp_path / "s", profile=PROFILE, worker_id="grok"):
            pass
    monkeypatch.setattr(shutil, "rmtree", real_rmtree)
    # the copy is still there (a worker-visible dir MAY remain: the caller records run.error)
    assert (tmp_path / "s" / "sanitized-grok").is_dir()
    # an exception inside the block still cleans up
    with pytest.raises(RuntimeError, match="inner"):
        with sanitized_copy(original, tmp_path / "s2", profile=PROFILE, worker_id="grok"):
            raise RuntimeError("inner")
    assert not (tmp_path / "s2" / "sanitized-grok").exists()


def test_tree_sha256_is_order_independent_and_sees_symlink_targets(tmp_path: Path) -> None:
    a = tmp_path / "a"
    a.mkdir()
    (a / "f").write_text("1")
    os.symlink("f", a / "l")
    h1 = tree_sha256(a)
    os.remove(a / "l")
    os.symlink("g", a / "l")
    assert tree_sha256(a) != h1  # a changed link target changes the hash
    (a / "f").write_text("2")
    h3 = tree_sha256(a)
    assert h3 != h1 and tree_sha256(a, skip=lambda r: r.name == "l") != h3
