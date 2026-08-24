"""eris.sanitize: strip list (minimum, any depth, case-insensitive), copy
semantics (new inodes, symlink rules, .git without hooks and with
`core.fsmonitor`/`core.untrackedCache` neutralised), the original is
untouched, the copy is what agy gets as --add-dir, cleanup in finally."""

from __future__ import annotations

import os
import shutil
import stat
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
        # a repository that already uses a filesystem monitor: the copy must
        # neutralise it (`neutralise_git_config`), the original must not move
        ".git/config": (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfsmonitor = .git/hooks/fsmonitor-watchman\n"
            "\tuntrackedCache = true\n"
            '[remote "origin"]\n'
            "\turl = https://example.invalid/r.git\n"
        ),
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
            or rel.parts[:2] == (".git", "config")  # rewritten: fsmonitor off
            or s in dropped
        )

    # `.git/config` is skipped on BOTH sides: it is the one file the copy
    # rewrites (see test_the_copy_disables_an_inherited_fsmonitor_and_...)
    assert tree_sha256(copy, skip=skip) == tree_sha256(original, skip=skip)
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


def test_verification_copy_matches_the_original_except_hooks_config_and_escaping_links(
    tmp_path: Path,
) -> None:
    """cond 4: the verification copy is NOT a sanitized copy - it keeps every
    instruction file - and differs from a raw copy only by `.git/hooks`, the
    neutralised `.git/config` (M2c follow-up 3) and dropped escaping/dangling
    symlinks. File set, bytes, modes and the targets of kept symlinks are
    otherwise identical."""
    from eris.sanitize import VERIFICATION_PROFILE

    original = build_original(tmp_path)
    (original / "odd-mode-dir").mkdir()
    (original / "odd-mode-dir" / "inner.txt").write_text("inner\n")
    (original / "odd-mode-dir").chmod(0o701)  # a directory mode a raw copy would keep
    (original / "src").chmod(0o750)
    (original / "secretive.sh").write_text("#!/bin/sh\necho hi\n")
    (original / "secretive.sh").chmod(0o700)
    (original / "src" / "app.py").chmod(0o644)
    (original / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    (original / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\nexit 1\n")
    (original / ".git" / "hooks" / "pre-commit").chmod(0o755)
    before_hash, before_inodes = tree_sha256(original), inodes(original)

    copy = tmp_path / "scratch" / "verify-copy"
    rec = sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")

    assert rec.stripped == []  # nothing is stripped: AGENTS.md & co are still there
    assert (copy / "AGENTS.md").read_bytes() == (original / "AGENTS.md").read_bytes()
    assert (copy / ".git" / "HEAD").is_file() and not (copy / ".git" / "hooks").exists()
    dropped = set(rec.dropped_symlinks)
    assert dropped == {"link-escape", "link-absolute", "link-dangling"}
    assert "link-to-stripped" not in dropped  # nothing is stripped, so this link stays

    def rel_entries(root: Path) -> dict[str, tuple[str, str]]:
        out: dict[str, tuple[str, str]] = {}
        for path in root.rglob("*"):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                out[rel] = ("link", os.readlink(path))
            elif path.is_file():
                out[rel] = ("file", f"{oct(path.stat().st_mode)}:{sha256_hex(path.read_bytes())}")
            else:
                out[rel] = ("dir", oct(path.stat().st_mode))  # cond 4: modes, not just names
        return out

    original_entries = rel_entries(original)
    expected = {
        rel: v
        for rel, v in original_entries.items()
        if not rel.startswith(".git/hooks") and rel != ".git/config" and rel not in dropped
    }
    assert {k: v for k, v in rel_entries(copy).items() if k != ".git/config"} == expected
    # ... and the third exception is the config, whose MODE is still identical
    kind, meta = rel_entries(copy)[".git/config"]
    assert kind == "file" and meta.split(":")[0] == original_entries[".git/config"][1].split(":")[0]
    assert oct((copy / "odd-mode-dir").stat().st_mode) == oct(
        (original / "odd-mode-dir").stat().st_mode
    )
    assert oct((copy / "src").stat().st_mode) == oct((original / "src").stat().st_mode)
    assert oct(copy.stat().st_mode) == oct(original.stat().st_mode)  # the root too
    assert tree_sha256(original) == before_hash and inodes(original) == before_inodes


def _core_values(text: str, key: str) -> list[str]:
    """Every value `git config --get-all core.<key>` would see, in file order:
    a plain textual read of a config file, so the test does not need a git."""
    out: list[str] = []
    in_core = False
    for raw in text.splitlines():
        body = raw.strip()
        if body.startswith("["):
            in_core = body[1:].split("]", 1)[0].strip().lower() == "core"
            continue
        if not in_core or body.startswith(("#", ";")) or not body:
            continue
        name, _, value = body.partition("=")
        if name.strip().lower() == key.lower():
            out.append(value.strip() if _ else "true")
    return out


def test_the_copy_disables_an_inherited_fsmonitor_and_untracked_cache(tmp_path: Path) -> None:
    """M2c follow-up 3, item 2: a snapshot taken from a repository that already
    configures `core.fsmonitor`/`core.untrackedCache` arrives with those
    settings inside `.git/config`. In the COPY they are removed and explicitly
    set to `false`; the ORIGINAL is never written.

    Both directions matter. A live monitor can mark index entries
    fsmonitor-valid DURING a run, which the `-s -v -f` digest would report as a
    violation no verification command caused; and a stale cache lets a command
    answer from data the working tree no longer supports."""
    from eris.sanitize import GIT_CONFIG_NEUTRALISED_BLOCK, VERIFICATION_PROFILE

    original = build_original(tmp_path)
    before_bytes = (original / ".git" / "config").read_bytes()
    before_hash, before_inodes = tree_sha256(original), inodes(original)
    assert _core_values(before_bytes.decode(), "fsmonitor") == [".git/hooks/fsmonitor-watchman"]

    copy = tmp_path / "scratch" / "verify-copy"
    sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")

    text = (copy / ".git" / "config").read_text()
    assert _core_values(text, "fsmonitor") == ["false"]  # the only surviving value
    assert _core_values(text, "untrackedCache") == ["false"]
    assert text.endswith(GIT_CONFIG_NEUTRALISED_BLOCK)
    # everything else in the file is untouched, in order
    assert "\trepositoryformatversion = 0\n" in text
    assert '[remote "origin"]\n\turl = https://example.invalid/r.git\n' in text
    # THE ORIGINAL IS NEVER MODIFIED
    assert (original / ".git" / "config").read_bytes() == before_bytes
    assert tree_sha256(original) == before_hash and inodes(original) == before_inodes


def test_the_config_neutralisation_survives_odd_spellings_includes_and_continuations(
    tmp_path: Path,
) -> None:
    """Item 2, the parsing: git config keys and section names are
    case-insensitive, a bare key means `true`, a value may be continued with a
    trailing backslash, and an `include` can pull the setting in from another
    file. The removal handles the first three; the APPENDED `[core]` block is
    what covers the fourth - a later section wins in git's config order."""
    from eris.sanitize import VERIFICATION_PROFILE, neutralise_git_config

    original = tmp_path / "o"
    (original / ".git").mkdir(parents=True)
    (original / "keep.txt").write_text("k\n")
    (original / ".git" / "config").write_text(
        "[CORE]\n"
        "\tFsMonitor\n"  # bare key = true
        "\tUNTRACKEDCACHE = tr\\\n"
        "ue\n"  # a continued value: both lines must go
        "\t# fsmonitor = a comment, not a setting\n"
        "\tbare = 1\n"
        '[core "sub"]\n'
        "\tfsmonitor = not-core.fsmonitor\n"  # a different section: kept
        "[include]\n"
        "\tpath = extra\n"
    )
    (original / ".git" / "extra").write_text("[core]\n\tfsmonitor = from-the-include\n")

    copy = tmp_path / "scratch" / "verify-copy"
    sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")

    text = (copy / ".git" / "config").read_text()
    assert "FsMonitor\n" not in text and "UNTRACKEDCACHE" not in text and "ue\n" not in text
    assert "\tbare = 1\n" in text  # an unrelated core key survives
    assert "# fsmonitor = a comment, not a setting" in text  # comments are not settings
    assert "fsmonitor = not-core.fsmonitor" in text  # `[core "sub"]` is another section
    assert "\tpath = extra\n" in text  # the include itself is left alone
    # the include still sets it - and the appended block, being LAST, wins
    assert (copy / ".git" / "extra").read_text() == (original / ".git" / "extra").read_text()
    assert text.rstrip().endswith("untrackedCache = false")
    assert _core_values(text, "fsmonitor")[-1] == "false"
    # idempotent: neutralising an already-neutralised copy adds nothing new
    assert neutralise_git_config(copy) is True
    assert _core_values((copy / ".git" / "config").read_text(), "fsmonitor") == ["false"]


@pytest.mark.parametrize("shape", ["no-git", "git-without-config", "config-is-a-symlink"])
def test_a_copy_with_nothing_to_neutralise_is_left_alone(tmp_path: Path, shape: str) -> None:
    """Item 2: no `.git`, a `.git` with no config file (a gitlink, or not a
    repository) or a config that is a SYMLINK - nothing was inherited and
    nothing is written. A symlink is never followed: writing through it could
    leave the copy."""
    from eris.sanitize import VERIFICATION_PROFILE, neutralise_git_config

    original = tmp_path / "o"
    original.mkdir()
    (original / "keep.txt").write_text("k\n")
    if shape != "no-git":
        (original / ".git").mkdir()
        (original / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    if shape == "config-is-a-symlink":
        (original / ".git" / "real").write_text("[core]\n\tfsmonitor = true\n")
        os.symlink("real", original / ".git" / "config")

    copy = tmp_path / "scratch" / "verify-copy"
    sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")

    assert neutralise_git_config(copy) is False
    if shape == "config-is-a-symlink":
        assert (copy / ".git" / "config").is_symlink()
        assert (copy / ".git" / "real").read_text() == "[core]\n\tfsmonitor = true\n"
    else:
        assert not (copy / ".git" / "config").exists()


def test_the_neutralised_config_keeps_a_read_only_file_mode(tmp_path: Path) -> None:
    """Item 2: the rewrite restores the copy's file mode, so a repository that
    ships a read-only `.git/config` still copies faithfully (cond 4 modes) -
    and a config with no trailing newline does not run into the appended
    block."""
    from eris.sanitize import VERIFICATION_PROFILE

    original = tmp_path / "o"
    (original / ".git").mkdir(parents=True)
    (original / ".git" / "config").write_text('[remote "o"]\n\turl = x')  # no final newline
    (original / ".git" / "config").chmod(0o444)

    copy = tmp_path / "scratch" / "verify-copy"
    sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")

    text = (copy / ".git" / "config").read_text()
    assert stat.S_IMODE((copy / ".git" / "config").stat().st_mode) == 0o444
    assert text.startswith('[remote "o"]\n\turl = x\n# eris')  # a newline was supplied
    assert _core_values(text, "fsmonitor") == ["false"]


def test_a_copy_with_read_only_directories_is_still_removable(tmp_path: Path) -> None:
    """cond 4: preserving directory modes must not wedge the cleanup - the
    context manager restores owner write and retries."""
    from eris.sanitize import VERIFICATION_PROFILE

    original = tmp_path / "o"
    (original / "locked").mkdir(parents=True)
    (original / "locked" / "file.txt").write_text("x")
    (original / "locked").chmod(0o500)  # read+execute only: rmtree would fail
    try:
        with sanitized_copy(
            original, tmp_path / "scratch", profile=VERIFICATION_PROFILE, worker_id="verify"
        ) as (copy, _rec):
            assert oct((copy / "locked").stat().st_mode) == oct(
                (original / "locked").stat().st_mode
            )
        assert not (tmp_path / "scratch" / "sanitized-verify").exists()
    finally:
        (original / "locked").chmod(0o700)  # so pytest can clean up


def test_a_symlink_inside_the_copy_is_never_chmodded_when_the_copy_is_removed(
    tmp_path: Path,
) -> None:
    """Final item 6: removing the copy restores owner access on REAL
    directories inside the copy root only. A symlink a worker left behind
    (here inside a read-only directory, so its removal really does hit
    EACCES) is never followed: its target's mode is unchanged, and nothing
    outside the copy root is touched."""
    from eris.sanitize import VERIFICATION_PROFILE

    original = tmp_path / "o"
    original.mkdir()
    (original / "README.md").write_text("x")
    victim = tmp_path / "outside"
    victim.mkdir()
    (victim / "keep").write_text("secret")
    victim.chmod(0o500)  # read+execute only, and it must STAY that way
    scratch = tmp_path / "scratch"
    parent_mode = oct(scratch.stat().st_mode) if scratch.exists() else None
    try:
        with sanitized_copy(
            original, scratch, profile=VERIFICATION_PROFILE, worker_id="verify"
        ) as (copy, _rec):
            locked = copy / "locked"  # what a worker left in its cwd
            locked.mkdir()
            (locked / "escape").symlink_to(victim)
            locked.chmod(0o500)  # unlinking `escape` now raises EACCES
        assert not (scratch / "sanitized-verify").exists()  # the copy IS gone
        assert oct(victim.stat().st_mode) == oct(0o40500)  # never chmod'd through the link
        assert (victim / "keep").read_text() == "secret"
        assert parent_mode is None or oct(scratch.stat().st_mode) == parent_mode
    finally:
        victim.chmod(0o700)


def test_the_removal_handler_re_raises_anything_that_is_not_a_permission_error(
    tmp_path: Path,
) -> None:
    """Final item 6: the handler is not a catch-all. A non-permission error, or
    a permission error on a path outside the copy root, propagates - a removal
    failure is never swallowed - and the handler never calls ``func`` back
    (its signature differs per rmtree primitive: ``os.open`` takes flags)."""
    import errno
    import os as _os

    from eris.sanitize import _force_writable

    root = tmp_path / "copy"
    (root / "sub").mkdir(parents=True)
    handler = _force_writable(root)
    calls: list[str] = []

    def func(path: str) -> None:  # pragma: no cover - must never be called
        calls.append(path)

    with pytest.raises(OSError) as busy:
        handler(func, str(root / "sub"), OSError(errno.EBUSY, "device busy"))
    assert busy.value.errno == errno.EBUSY
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(PermissionError):
        handler(func, str(outside), PermissionError(errno.EACCES, "denied"))
    assert oct(outside.stat().st_mode) == oct(_os.stat(outside).st_mode)  # untouched
    # a permission error on a real directory INSIDE the root is handled: owner
    # access is restored, and func is still never retried
    (root / "sub").chmod(0o500)
    handler(func, str(root / "sub"), PermissionError(errno.EACCES, "denied"))
    assert (root / "sub").stat().st_mode & 0o700 == 0o700
    assert calls == []
