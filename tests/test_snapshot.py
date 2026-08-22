from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from eris.snapshot import (
    SNAPSHOT_BRANCH,
    GitResult,
    SnapshotError,
    build_snapshot,
    default_git_runner,
    git_env,
    read_head_sha,
    verify_snapshot,
)

HEAD = "a" * 40
FUTURE = "b" * 40
FUTURE_BLOB = "c" * 40
FUTURE_TREE = "d" * 40


class FakeGit:
    """Scripted git: answers by (first args) prefix; records every call."""

    def __init__(self, answers: dict[tuple[str, ...], GitResult] | None = None) -> None:
        self.answers = answers or {}
        self.calls: list[tuple[tuple[str, ...], Path | None]] = []

    def __call__(self, args: Sequence[str], cwd: Path | None) -> GitResult:
        key = tuple(args)
        self.calls.append((key, cwd))
        for prefix, result in self.answers.items():
            if key[: len(prefix)] == prefix:
                return result
        return GitResult(0, b"", b"")


def ok(text: str = "") -> GitResult:
    return GitResult(0, text.encode(), b"")


def fail() -> GitResult:
    return GitResult(128, b"", b"fatal: not found")


def clean_answers() -> dict[tuple[str, ...], GitResult]:
    return {
        ("remote",): ok(""),
        ("config", "--local", "--get", "core.hooksPath"): GitResult(1, b"", b""),
        ("for-each-ref",): ok(f"refs/heads/{SNAPSHOT_BRANCH}\n"),
        ("rev-parse", "HEAD"): ok(HEAD),
        ("rev-list", "--count", "HEAD"): ok("3"),
        ("cat-file", "-e", FUTURE): fail(),
        ("cat-file", "-e", FUTURE_BLOB): fail(),
        ("cat-file", "-e", FUTURE_TREE): fail(),
    }


def make_dest(tmp_path: Path) -> Path:
    dest = tmp_path / "snap"
    (dest / ".git" / "objects" / "info").mkdir(parents=True)
    return dest


def test_verify_clean_snapshot(tmp_path: Path) -> None:
    dest = make_dest(tmp_path)
    git = FakeGit(clean_answers())
    v = verify_snapshot(
        dest, head_sha=HEAD, forbidden_shas=[FUTURE, FUTURE_BLOB, FUTURE_TREE], git=git
    )
    assert v.ok and v.problems == [] and v.head_sha == HEAD and v.commit_count == 3
    for obj in (FUTURE, FUTURE_BLOB, FUTURE_TREE):
        assert (("cat-file", "-e", obj), dest) in git.calls  # any object type, not ^{commit}


def test_verify_rejects_injected_future_blob_and_tree(tmp_path: Path) -> None:
    dest = make_dest(tmp_path)
    git = FakeGit({**clean_answers(), ("cat-file", "-e", FUTURE_BLOB): ok("")})
    v = verify_snapshot(dest, head_sha=HEAD, forbidden_shas=[FUTURE, FUTURE_BLOB], git=git)
    assert not v.ok and v.problems == [f"future object {FUTURE_BLOB} is present in the snapshot"]
    git = FakeGit({**clean_answers(), ("cat-file", "-e", FUTURE_TREE): ok("")})
    v = verify_snapshot(dest, head_sha=HEAD, forbidden_shas=[FUTURE_TREE], git=git)
    assert not v.ok and FUTURE_TREE in v.problems[0]


def test_verify_no_git_dir(tmp_path: Path) -> None:
    v = verify_snapshot(tmp_path / "nope", head_sha=None, forbidden_shas=[], git=FakeGit())
    assert not v.ok and v.problems == ["no .git directory"]


@pytest.mark.parametrize(
    ("mutate", "answers", "expected"),
    [
        (
            lambda d: (d / ".git" / "objects" / "info" / "alternates").write_text(
                "/src/.git/objects\n"
            ),
            {},
            "alternates present",
        ),
        (lambda d: (d / ".git" / "FETCH_HEAD").write_text("x"), {}, "FETCH_HEAD present"),
        (lambda d: (d / ".git" / "ORIG_HEAD").write_text("x"), {}, "ORIG_HEAD present"),
        (
            lambda d: (
                (d / ".git" / "hooks").mkdir(),
                (d / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh"),
            ),
            {},
            "hooks present",
        ),
        (lambda d: None, {("remote",): ok("origin\n")}, "remote(s) configured"),
        (
            lambda d: None,
            {("config", "--local", "--get", "core.hooksPath"): ok("/evil")},
            "core.hooksPath set",
        ),
        (
            lambda d: None,
            {
                ("for-each-ref",): ok(
                    f"refs/heads/{SNAPSHOT_BRANCH}\nrefs/heads/main\nrefs/tags/v1\n"
                )
            },
            "unexpected refs",
        ),
        (lambda d: None, {("rev-parse", "HEAD"): ok("c" * 40)}, "HEAD"),
        (lambda d: None, {("cat-file", "-e", FUTURE): ok("")}, "future object"),
        (
            lambda d: None,
            {("remote",): fail(), ("for-each-ref",): fail(), ("rev-parse", "HEAD"): fail()},
            "failed",
        ),
    ],
)
def test_verify_detects_each_problem(
    tmp_path: Path, mutate: object, answers: dict[tuple[str, ...], GitResult], expected: str
) -> None:
    dest = make_dest(tmp_path)
    assert callable(mutate)
    mutate(dest)
    git = FakeGit({**clean_answers(), **answers})
    v = verify_snapshot(dest, head_sha=HEAD, forbidden_shas=[FUTURE], git=git)
    assert not v.ok
    assert any(expected in p for p in v.problems), v.problems


def test_sample_hooks_are_tolerated(tmp_path: Path) -> None:
    dest = make_dest(tmp_path)
    (dest / ".git" / "hooks").mkdir()
    (dest / ".git" / "hooks" / "pre-commit.sample").write_text("#")
    assert verify_snapshot(dest, head_sha=HEAD, forbidden_shas=[], git=FakeGit(clean_answers())).ok


# --------------------------------------------------------------------------- build (faked git)


def test_build_snapshot_argument_validation(tmp_path: Path) -> None:
    with pytest.raises(SnapshotError, match="hex sha"):
        build_snapshot(tmp_path, "not-a-sha", tmp_path / "d", git=FakeGit())
    with pytest.raises(SnapshotError, match="depth"):
        build_snapshot(tmp_path, HEAD, tmp_path / "d", depth=0, git=FakeGit())
    (tmp_path / "exists").mkdir()
    with pytest.raises(SnapshotError, match="already exists"):
        build_snapshot(tmp_path, HEAD, tmp_path / "exists", git=FakeGit())


def test_build_snapshot_sequence_with_fake_git(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    dest = tmp_path / "out" / "snap"

    class BuildingGit(FakeGit):
        def __call__(self, args: Sequence[str], cwd: Path | None) -> GitResult:
            if args[:2] == ("clone", "--mirror") or args[:2] == ["clone", "--mirror"]:
                Path(args[-1]).mkdir(parents=True)
            if args[:2] == ("clone", "--no-local") or args[:2] == ["clone", "--no-local"]:
                (Path(args[-1]) / ".git" / "hooks").mkdir(parents=True)
                (Path(args[-1]) / ".git" / "FETCH_HEAD").write_text("x")
            return super().__call__(args, cwd)

    git = BuildingGit(
        {
            **clean_answers(),
            ("rev-parse", f"{HEAD}^{{commit}}"): ok(HEAD),
            ("rev-list", "--objects", "--all", "--not", HEAD): ok(
                f"{FUTURE}\n{FUTURE_TREE} \n{FUTURE_BLOB} path/to/secret_key.py\n"
            ),
        }
    )
    info = build_snapshot(src, HEAD, dest, depth=7, git=git)
    assert info.head_sha == HEAD and info.depth == 7 and info.commit_count == 3
    assert info.forbidden_shas == (FUTURE, FUTURE_TREE, FUTURE_BLOB)  # commits, trees, blobs
    argv = [c[0] for c in git.calls]
    assert (
        "clone",
        "--mirror",
        "--quiet",
        str(src.resolve()),
        str(dest.parent / ".snap.mirror.git"),
    ) in argv
    assert ("branch", "-f", SNAPSHOT_BRANCH, HEAD) in argv
    assert (
        "clone",
        "--no-local",
        "--depth",
        "7",
        "--single-branch",
        "--branch",
        SNAPSHOT_BRANCH,
        "--quiet",
        str(dest.parent / ".snap.mirror.git"),
        str(dest),
    ) in argv
    assert ("remote", "remove", "origin") in argv
    assert not (dest / ".git" / "FETCH_HEAD").exists()
    assert not (dest / ".git" / "hooks").exists()
    assert not (dest.parent / ".snap.mirror.git").exists()  # mirror removed


def test_build_snapshot_unknown_sha_fails_and_cleans_mirror(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    dest = tmp_path / "out" / "snap"

    class G(FakeGit):
        def __call__(self, args: Sequence[str], cwd: Path | None) -> GitResult:
            if args[:2] == ("clone", "--mirror"):
                Path(args[-1]).mkdir(parents=True)
            return super().__call__(args, cwd)

    git = G({("branch", "-f"): fail()})
    with pytest.raises(SnapshotError, match="branch at pre-fix sha failed"):
        build_snapshot(src, HEAD, dest, git=git)
    assert not (dest.parent / ".snap.mirror.git").exists()


def test_build_snapshot_head_mismatch_is_an_error(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    git = FakeGit({**clean_answers(), ("rev-parse", f"{HEAD}^{{commit}}"): ok("d" * 40)})
    with pytest.raises(SnapshotError, match="!= requested"):
        build_snapshot(src, HEAD, tmp_path / "snap", git=git)


def test_read_head_sha_filesystem_only(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    gitdir = repo / ".git"
    (gitdir / "refs" / "heads").mkdir(parents=True)
    assert read_head_sha(tmp_path / "missing") is None
    (gitdir / "HEAD").write_text(f"{HEAD}\n")  # detached
    assert read_head_sha(repo) == HEAD
    (gitdir / "HEAD").write_text("ref: refs/heads/eris-snapshot\n")
    assert read_head_sha(repo) is None  # ref file missing, no packed-refs
    (gitdir / "packed-refs").write_text(f"# pack-refs\n{FUTURE} refs/heads/eris-snapshot\n")
    assert read_head_sha(repo) == FUTURE
    (gitdir / "refs" / "heads" / "eris-snapshot").write_text(f"{HEAD}\n")
    assert read_head_sha(repo) == HEAD  # loose ref wins
    (gitdir / "HEAD").write_text("ref: ../../etc/passwd\n")
    assert read_head_sha(repo) is None
    (gitdir / "HEAD").write_text("garbage\n")
    assert read_head_sha(repo) is None


def test_git_env_is_hardened(tmp_path: Path) -> None:
    env = git_env(tmp_path)
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["HOME"] == str(tmp_path) and "SSH_AUTH_SOCK" not in env


# --------------------------------------------------------------------------- real git


def run_git(args: list[str], cwd: Path) -> str:
    res = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=git_env(cwd),
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
    )
    return res.stdout.strip()


@pytest.mark.real_subprocess(allow=["git"])
def test_snapshot_has_no_future(tmp_path: Path) -> None:
    src = tmp_path / "source"
    src.mkdir()
    run_git(["init", "-q", "-b", "main"], src)
    ident = ["-c", "user.name=t", "-c", "user.email=t@t"]
    (src / "f.py").write_text("v1\n")
    run_git(["add", "f.py"], src)
    run_git([*ident, "commit", "-q", "-m", "one"], src)
    first = run_git(["rev-parse", "HEAD"], src)
    (src / "f.py").write_text("v2 the fix\n")
    (src / "secret_key.py").write_text("answer = 42\n")
    run_git(["add", "-A"], src)
    run_git([*ident, "commit", "-q", "-m", "two (the fix)"], src)
    second = run_git(["rev-parse", "HEAD"], src)
    fix_blob = run_git(["rev-parse", "HEAD:secret_key.py"], src)
    fix_tree = run_git(["rev-parse", "HEAD^{tree}"], src)
    run_git(["tag", "v-future"], src)

    dest = tmp_path / "snapshots" / "task"
    info = build_snapshot(src, first, dest, depth=10, git=default_git_runner)
    assert info.head_sha == first
    assert {second, fix_tree, fix_blob} <= set(info.forbidden_shas)
    assert read_head_sha(dest) == first
    assert (dest / "f.py").read_text() == "v1\n"
    assert not (dest / "secret_key.py").exists()

    verdict = verify_snapshot(dest, head_sha=first, forbidden_shas=[second], git=default_git_runner)
    assert verdict.ok, verdict.problems
    for obj in (second, fix_tree, fix_blob):
        res = subprocess.run(
            ["git", "cat-file", "-e", obj],
            cwd=dest,
            env=git_env(dest),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        assert res.returncode != 0, f"{obj} is reachable from the snapshot"
    assert run_git(["remote"], dest) == ""
    assert run_git(["for-each-ref", "--format=%(refname)"], dest) == f"refs/heads/{SNAPSHOT_BRANCH}"
    assert not (dest / ".git" / "objects" / "info" / "alternates").exists()
    assert not (dest / ".git" / "FETCH_HEAD").exists()
    assert not (dest.parent / ".task.mirror.git").exists()
    # tampering is caught: a fetchable remote makes the verdict fail
    run_git(["remote", "add", "origin", str(src)], dest)
    assert not verify_snapshot(
        dest, head_sha=first, forbidden_shas=[second], git=default_git_runner
    ).ok
