"""History-truncated corpus snapshots: no future commit is reachable.

Build: ``git clone --mirror`` of the source into a temporary mirror, force a
branch at the pre-fix sha, ``git clone --no-local --depth N --single-branch
--branch`` from the mirror (``--no-local`` so ``--depth`` is honoured and no
hardlinks/alternates point at the source), then remove ``origin``,
``FETCH_HEAD``, ``ORIG_HEAD`` and hooks, and delete the mirror.

:func:`verify_snapshot` is pure over an injectable ``git`` runner (the tests
fake it); one ``real_subprocess`` test exercises real git.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from eris.launch import BASE_ENV, GIT_HARDENING

SNAPSHOT_BRANCH = "eris-snapshot"
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace").strip()


GitRunner = Callable[[Sequence[str], Path | None], GitResult]


def git_env(home: Path) -> dict[str, str]:
    env = dict(BASE_ENV)
    env["PATH"] = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
    env["HOME"] = str(home)
    env.update(GIT_HARDENING)
    return env


def default_git_runner(args: Sequence[str], cwd: Path | None) -> GitResult:
    home = cwd if cwd is not None else Path.cwd()
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd is not None else None,
        env=git_env(home),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=600,
        check=False,
    )
    return GitResult(proc.returncode, proc.stdout, proc.stderr)


@dataclass(frozen=True)
class SnapshotInfo:
    dest: Path
    head_sha: str
    depth: int
    commit_count: int
    forbidden_shas: tuple[str, ...]  # future commits, trees AND blobs


def read_head_sha(repo: Path) -> str | None:
    """HEAD commit of a checkout using the filesystem only (no git process).
    Handles a detached HEAD, a loose ref file and packed-refs; None otherwise."""
    gitdir = Path(repo) / ".git"
    try:
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if _SHA_RE.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    if ".." in ref or ref.startswith("/"):
        return None
    loose = gitdir / ref
    try:
        value = loose.read_text(encoding="utf-8").strip()
        if _SHA_RE.fullmatch(value):
            return value
    except OSError:
        pass
    try:
        for line in (gitdir / "packed-refs").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref and _SHA_RE.fullmatch(parts[0]):
                return parts[0]
    except OSError:
        pass
    return None


@dataclass
class SnapshotVerdict:
    ok: bool
    problems: list[str] = field(default_factory=list)
    head_sha: str | None = None
    commit_count: int | None = None


def _run(git: GitRunner, args: Sequence[str], cwd: Path | None, what: str) -> GitResult:
    res = git(args, cwd)
    if not res.ok:
        raise SnapshotError(
            f"{what} failed ({res.returncode}): {res.stderr.decode(errors='replace')[:400]}"
        )
    return res


def build_snapshot(
    source: Path,
    pre_fix_sha: str,
    dest: Path,
    *,
    depth: int = 50,
    git: GitRunner = default_git_runner,
) -> SnapshotInfo:
    if not _SHA_RE.fullmatch(pre_fix_sha):
        raise SnapshotError(f"pre_fix_sha {pre_fix_sha!r} is not a hex sha")
    if depth < 1:
        raise SnapshotError("depth must be >= 1")
    source = Path(source).resolve()
    dest = Path(dest)
    if dest.exists():
        raise SnapshotError(f"destination {dest} already exists")
    dest.parent.mkdir(parents=True, exist_ok=True)
    mirror = dest.parent / f".{dest.name}.mirror.git"
    if mirror.exists():
        shutil.rmtree(mirror)
    try:
        _run(
            git,
            ["clone", "--mirror", "--quiet", str(source), str(mirror)],
            dest.parent,
            "mirror clone",
        )
        _run(git, ["branch", "-f", SNAPSHOT_BRANCH, pre_fix_sha], mirror, "branch at pre-fix sha")
        full = _run(git, ["rev-parse", f"{pre_fix_sha}^{{commit}}"], mirror, "resolve sha").text
        # Every object (commit, tree, blob) reachable from any ref but NOT from
        # the pre-fix commit is a future object and must be absent from the snapshot.
        future = _run(
            git, ["rev-list", "--objects", "--all", "--not", full], mirror, "list future objects"
        ).text
        forbidden = tuple(line.split()[0] for line in future.splitlines() if line.strip())
        _run(
            git,
            [
                "clone",
                "--no-local",
                "--depth",
                str(depth),
                "--single-branch",
                "--branch",
                SNAPSHOT_BRANCH,
                "--quiet",
                str(mirror),
                str(dest),
            ],
            dest.parent,
            "shallow clone",
        )
        _run(git, ["remote", "remove", "origin"], dest, "remove origin")
        for name in ("FETCH_HEAD", "ORIG_HEAD", "objects/info/alternates"):
            p = dest / ".git" / name
            if p.exists():
                p.unlink()
        hooks = dest / ".git" / "hooks"
        if hooks.exists():
            shutil.rmtree(hooks)
        head = _run(git, ["rev-parse", "HEAD"], dest, "rev-parse HEAD").text
        count = int(_run(git, ["rev-list", "--count", "HEAD"], dest, "count").text or "0")
    finally:
        if mirror.exists():
            shutil.rmtree(mirror, ignore_errors=True)
    if head != full:
        raise SnapshotError(f"snapshot HEAD {head} != requested {full}")
    verdict = verify_snapshot(dest, head_sha=head, forbidden_shas=forbidden, git=git)
    if not verdict.ok:
        raise SnapshotError("snapshot failed verification: " + "; ".join(verdict.problems))
    return SnapshotInfo(dest, head, depth, count, forbidden)


def verify_snapshot(
    dest: Path,
    *,
    head_sha: str | None,
    forbidden_shas: Sequence[str],
    git: GitRunner,
) -> SnapshotVerdict:
    """The checks behind ``test_snapshot_has_no_future``. Pure over ``git``."""
    dest = Path(dest)
    problems: list[str] = []
    gitdir = dest / ".git"
    if not gitdir.is_dir():
        return SnapshotVerdict(False, ["no .git directory"])
    for name in ("objects/info/alternates", "FETCH_HEAD", "ORIG_HEAD"):
        if (gitdir / name).exists():
            problems.append(f".git/{name} present")
    hooks = gitdir / "hooks"
    if hooks.exists() and any(
        p.is_file() and not p.name.endswith(".sample") for p in hooks.iterdir()
    ):
        problems.append("hooks present")
    remotes = git(["remote"], dest)
    if not remotes.ok:
        problems.append("git remote failed")
    elif remotes.text:
        problems.append(f"remote(s) configured: {remotes.text.split()}")
    hooks_path = git(["config", "--local", "--get", "core.hooksPath"], dest)
    if hooks_path.ok and hooks_path.text:
        problems.append(f"core.hooksPath set: {hooks_path.text}")
    refs = git(["for-each-ref", "--format=%(refname)"], dest)
    if not refs.ok:
        problems.append("for-each-ref failed")
    else:
        names = [r for r in refs.text.splitlines() if r]
        extra = [r for r in names if r != f"refs/heads/{SNAPSHOT_BRANCH}"]
        if extra:
            problems.append(f"unexpected refs: {extra}")
    head = git(["rev-parse", "HEAD"], dest)
    head_value = head.text if head.ok else None
    if not head.ok:
        problems.append("rev-parse HEAD failed")
    elif head_sha is not None and head_value != head_sha:
        problems.append(f"HEAD {head_value} != expected {head_sha}")
    count_res = git(["rev-list", "--count", "HEAD"], dest)
    count = int(count_res.text) if count_res.ok and count_res.text.isdigit() else None
    for sha in forbidden_shas:
        # Any object type: commits, trees and blobs of the future must all be absent.
        res = git(["cat-file", "-e", sha], dest)
        if res.ok:
            problems.append(f"future object {sha} is present in the snapshot")
    return SnapshotVerdict(not problems, problems, head_value, count)
