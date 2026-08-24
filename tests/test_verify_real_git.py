"""M2c defect B, against a REAL git: the default evidence battery must run to
completion without tripping the verification tripwire.

The first live run of the harness (2026-08-23) recorded

    snapshot.violated  argv=["/usr/bin/git","status","--porcelain"]
    verify.refused     git ls-files   "an earlier command changed ..."
    verify.refused     git log --oneline -n 20   (same)

because ``git status`` refreshes ``.git/index`` (its stat cache), the copy's
tree hash changed, and every remaining verification command was refused. No
hermetic test could catch that: the fakes never execute a real ``git``.

This is the second and last test allowed to spawn ``git``
(``real_subprocess(allow=["git"])``; the other is
``test_snapshot.py::test_snapshot_has_no_future``). It runs the real code
path - ``build_evidence_pack`` -> ``run_allowlisted`` -> ``spawn`` - against a
real one-commit repository.

It also pins the M2c follow-up: the tripwire excludes ``.git/index`` BY BYTES
(measured here on 2026-08-24: on a fresh copy the first command that reads the
working tree - ``git diff``/``git diff HEAD`` - rewrites it, with or without
``--no-optional-locks``), and covers it SEMANTICALLY with a digest of
``git ls-files -s -v``. Only a real ``git`` can show that the digest is blind
to the stat refresh and sensitive to ``git add`` / ``git rm --cached`` - the
second of which changes NOTHING else in the tree, so without the semantic
digest it is invisible.

Follow-up 2 adds the two halves that stop the whack-a-mole:
``test_every_index_mutation_trips_the_guard`` ENUMERATES every index-mutating
mechanism (a new one is one line in ``INDEX_MUTATIONS``) - it is what caught
``--stage`` being blind to ``--skip-worktree``/``--assume-unchanged`` - and
``test_the_index_digest_does_not_cover_the_index_extensions`` /
``test_the_split_index_is_caught_by_the_tree_hash_not_by_the_digest`` pin, by
measurement, what the digest does NOT cover.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from eris.evidence import (
    PACK_COMMANDS,
    SnapshotGuard,
    TaskSpec,
    VerifyEnv,
    build_evidence_pack,
    git_index_prober,
)
from eris.policy import Policy
from eris.redact import Redactor
from eris.sanitize import VERIFICATION_PROFILE, sanitize_snapshot
from eris.schemas import EvidenceKind
from eris.writer import RunWriter

pytestmark = pytest.mark.real_subprocess(allow=["git"])


def _git_executable() -> Path:
    """Resolved at test time, never from a tracked machine-specific path."""
    found = shutil.which("git")
    if found is None:  # pragma: no cover - git is a hard requirement of the repo
        pytest.skip("git is not on PATH")
    return Path(found).resolve()


def _make_repo(root: Path, git: Path) -> None:
    root.mkdir(parents=True)
    (root / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    (root / "README.md").write_text("# real repo\n")
    common = [
        str(git),
        "-c",
        "user.name=Eris Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "init.defaultBranch=main",
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(root.parent / "git-home"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    for argv in ([*common, "init", "-q"], [*common, "add", "-A"], [*common, "commit", "-qm", "c1"]):
        subprocess.run(argv, cwd=root, env=env, check=True, capture_output=True)


def _policy(tmp_path: Path, git: Path) -> Policy:
    return Policy.model_validate(
        {
            "policy_version": "t",
            "vendors_allowed": ["xai"],
            "workers": {},
            "runs_dir": str(tmp_path / "runs"),
            "path_env": os.environ.get("PATH", "/usr/bin:/bin"),
            "budgets": {"per_run_usd": 1, "per_call_usd": 1},
            "verify": {
                "max_output_bytes": 1_000_000,
                "commands": {
                    "git": {
                        "executable": str(git),
                        "executable_sha256": hashlib.sha256(git.read_bytes()).hexdigest(),
                        "subcommands": ["rev-parse", "status", "ls-files", "log", "diff"],
                        "literal_flags": ["--porcelain", "--oneline", "--no-color"],
                        "value_flags": {"-n": "^[0-9]{1,4}$"},
                        "positional": ["path", "^(HEAD(~[0-9]{1,3})?|[0-9a-f]{7,40})$"],
                        "timeout_s": 60,
                    }
                },
            },
        }
    )


def _verify_env(policy: Policy, repo: Path, scratch_home: Path) -> VerifyEnv:
    """Exactly what ``eval/run.py`` builds, including the semantic index probe."""
    return VerifyEnv(
        policy=policy,
        snapshot_root=repo,
        scratch_home=scratch_home,
        popen=subprocess.Popen,
        killpg=os.killpg,
        guard=SnapshotGuard.over(repo, probe=git_index_prober(policy, scratch_home)),
    )


def _git(
    repo: Path, git: Path, *args: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    """A raw git, NOT through the allowlist: it stands in for a verification
    command that mutates the index (which the allowlist cannot reach today -
    the guard is defence in depth for the day it is wrong or widened)."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo.parent / "git-home"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Eris Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Eris Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    return subprocess.run([str(git), *args], cwd=repo, env=env, check=check, capture_output=True)


def test_the_default_battery_runs_clean_against_a_real_git_repository(tmp_path: Path) -> None:
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    # The battery runs on the pristine COPY, exactly as the harness does. That
    # is load-bearing here: the copied working tree no longer matches the stat
    # data recorded in .git/index, so `git status` WANTS to rewrite the index -
    # which is precisely what tripped the guard in the live run.
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    policy = _policy(tmp_path, git)
    env = _verify_env(policy, repo, tmp_path / "verify-home")
    writer = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    task = TaskSpec.model_validate(
        {
            "task_id": "t_real",
            "question": "Does the battery complete?",
            "category": "control",
            "snapshot": "snapshot",
        }
    )
    build = build_evidence_pack(
        task,
        env=env,
        writer=writer,
        repeat_index=0,
        policy_sha256="0" * 64,
        snapshot_sha=None,
    )
    writer.close()

    events: list[dict[str, Any]] = [
        json.loads(line)
        for line in (tmp_path / "runs" / "r" / "events.jsonl").read_bytes().splitlines()
    ]
    kinds = [e["kind"] for e in events]
    assert "snapshot.violated" not in kinds, [
        e["payload"] for e in events if e["kind"] == "snapshot.violated"
    ]
    assert "verify.refused" not in kinds, [
        e["payload"] for e in events if e["kind"] == "verify.refused"
    ]
    assert build.refused == 0 and env.violated is False
    # the four default commands all produced evidence, in order
    assert len(build.executed_argv) == len(PACK_COMMANDS) == 4
    facts = [i for i in build.items if i.kind is EvidenceKind.REPO_FACT]
    assert len(facts) == 4
    assert [i.label.split(": ", 1)[1] for i in facts] == [" ".join(a) for a in PACK_COMMANDS]
    assert all(i.exit_code == 0 for i in facts)
    # every executed git argv carries the Eris-appended global, before the
    # subcommand - this is what keeps `status` from rewriting .git/index
    for argv in build.executed_argv:
        assert argv[1] == "--no-optional-locks" and not argv[2].startswith("-")
    by_label = {i.label.split(": ", 1)[1]: i for i in facts}
    assert by_label["git rev-parse HEAD"].content.strip().isalnum()
    assert by_label["git status --porcelain"].content == ""  # a clean tree
    assert set(by_label["git ls-files"].content.split()) == {"README.md", "calc.py"}
    assert "c1" in by_label["git log --oneline -n 20"].content


def test_the_battery_plus_a_bare_git_diff_leaves_the_index_guard_quiet(tmp_path: Path) -> None:
    """M2c index guard (a): with the semantic check armed, the whole default
    battery AND a bare ``git diff`` - the command measured to rewrite
    ``.git/index`` on a fresh copy, flag or no flag - run without a
    violation. This is what the byte exclusion buys and must keep buying."""
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    policy = _policy(tmp_path, git)
    env = _verify_env(policy, repo, tmp_path / "verify-home")
    assert env.guard is not None and env.guard.index_check == "semantic"
    baseline_digest = env.guard.index_digest

    index_before = (repo / ".git" / "index").read_bytes()
    for argv in [*(list(a) for a in PACK_COMMANDS), ["git", "diff"], ["git", "diff", "HEAD"]]:
        outcome = env.run(argv)
        assert outcome.violated is False, (argv, outcome.violation_reason)
        assert outcome.exit_code == 0
    assert env.violated is False
    # the stat cache DID churn - which is precisely why it is excluded by bytes
    assert (repo / ".git" / "index").read_bytes() != index_before
    # ... and the staged content did not move an inch
    assert env.guard.index_digest == baseline_digest
    assert env.guard.changed() is None


@pytest.mark.parametrize(
    ("mutation", "tree_also_moves"),
    [
        (("add", "calc.py"), True),  # writes a loose object AND stages it
        (("rm", "--cached", "-q", "README.md"), False),  # NOTHING else in the tree moves
    ],
)
def test_a_real_staging_change_trips_the_guard_with_reason_git_index(
    tmp_path: Path, mutation: tuple[str, ...], tree_also_moves: bool
) -> None:
    """M2c index guard (b)/(c): ``git add`` and ``git rm --cached`` change what
    ``git ls-files``/``git diff``/``git status`` report to LATER evidence. Both
    must trip the tripwire, and both must name the index.

    ``git rm --cached`` is the load-bearing case: it leaves every byte outside
    ``.git/index`` alone, so the byte hash alone cannot see it at all."""
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    # modify BEFORE the baseline: the guard must react to the STAGING, not to
    # the edit (an edit of its own would be a plain `reason: "tree"`)
    (repo / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b  # edited\n")
    policy = _policy(tmp_path, git)
    env = _verify_env(policy, repo, tmp_path / "verify-home")
    assert env.guard is not None and env.guard.index_check == "semantic"
    before = env.guard.index_digest
    assert env.run(["git", "status", "--porcelain"]).violated is False

    _git(repo, git, *mutation)

    outcome = env.run(["git", "status", "--porcelain"])
    assert outcome.violated is True
    assert outcome.violation_reason == "git_index"
    assert outcome.index_digest_after != before
    assert (outcome.tree_after != env.guard.baseline) is tree_also_moves
    assert env.violated is True  # verification is stopped for the run
    with pytest.raises(PermissionError, match="verification is stopped"):
        env.run(["git", "ls-files"])


# --------------------------------------------------------------------- enumeration

# An empty blob: `update-index --cacheinfo` stages it without touching the
# working tree at all.
EMPTY_BLOB = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

#: Every index-mutating mechanism reachable through `git update-index` and
#: friends: ``(files written before the baseline, setup argv, mutating argv)``.
#: A new mechanism is ONE line here.
INDEX_MUTATIONS: list[Any] = [
    pytest.param({}, (), ("update-index", "--skip-worktree", "calc.py"), id="skip-worktree"),
    pytest.param(
        {},
        ("update-index", "--skip-worktree", "calc.py"),
        ("update-index", "--no-skip-worktree", "calc.py"),
        id="no-skip-worktree",
    ),
    pytest.param({}, (), ("update-index", "--assume-unchanged", "calc.py"), id="assume-unchanged"),
    pytest.param(
        {},
        ("update-index", "--assume-unchanged", "calc.py"),
        ("update-index", "--no-assume-unchanged", "calc.py"),
        id="no-assume-unchanged",
    ),
    pytest.param(
        {},
        (),
        ("update-index", "--add", "--cacheinfo", f"100644,{EMPTY_BLOB},ghost.txt"),
        id="cacheinfo",
    ),
    pytest.param({}, (), ("update-index", "--chmod=+x", "calc.py"), id="chmod"),
    pytest.param({"NEW.txt": "new\n"}, (), ("add", "-N", "NEW.txt"), id="intent-to-add"),
    pytest.param(
        {"calc.py": "def add(a: int, b: int) -> int:\n    return a + b  # edited\n"},
        (),
        ("add", "calc.py"),
        id="add-a-modified-file",
    ),
    pytest.param({}, (), ("rm", "--cached", "-q", "README.md"), id="rm-cached"),
]


@pytest.mark.parametrize(("files", "setup", "mutation"), INDEX_MUTATIONS)
def test_every_index_mutation_trips_the_guard(
    tmp_path: Path, files: dict[str, str], setup: tuple[str, ...], mutation: tuple[str, ...]
) -> None:
    """M2c follow-up 2, the ENUMERATION that stops the whack-a-mole: every
    index-mutating mechanism reachable through `git update-index` and friends
    must be `snapshot.violated` with ``reason: "git_index"``.

    The flag cases are why :data:`GIT_INDEX_DIGEST_ARGS` is `ls-files -s -v`
    and no longer `ls-files --stage`: `--skip-worktree` and
    `--assume-unchanged` change what `git status`/`git diff` report about a
    file WITHOUT changing any staged content, so the `--stage` digest stayed
    byte-identical and the tripwire said nothing (measured 2026-08-24, git
    2.50.1). `-v` prints the per-entry status letter (`H` cached, `S`
    skip-worktree, lowercase = assume-unchanged) in the SAME invocation - no
    extra spawn - so the flag bits are in the digest. Reverting to `--stage`
    makes the four flag cases here FAIL."""
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    # anything the mutation needs must exist BEFORE the baseline, so the guard
    # reacts to the INDEX mutation and not to the file that set it up
    for name, content in files.items():
        (repo / name).write_text(content)
    if setup:
        _git(repo, git, *setup)

    policy = _policy(tmp_path, git)
    env = _verify_env(policy, repo, tmp_path / "verify-home")
    assert env.guard is not None and env.guard.index_check == "semantic"
    before = env.guard.index_digest
    assert env.run(["git", "status", "--porcelain"]).violated is False  # quiet beforehand

    _git(repo, git, *mutation)

    outcome = env.run(["git", "status", "--porcelain"])
    assert outcome.violated is True, mutation
    assert outcome.violation_reason == "git_index", mutation
    assert outcome.index_digest_after != before
    assert env.violated is True  # verification is stopped for the run
    with pytest.raises(PermissionError, match="verification is stopped"):
        env.run(["git", "ls-files"])


# --------------------------------------------------------- what it does NOT cover


def _files(root: Path) -> dict[str, str]:
    """relpath -> sha256 for every file EXCEPT `.git/index` itself."""
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and not p.is_symlink() and rel != ".git/index":
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _noop(repo: Path, git: Path) -> None:
    pass


def _invalidate_cache_tree(repo: Path, git: Path) -> None:
    (repo / "new.txt").write_text("new\n")
    _git(repo, git, "update-index", "--add", "new.txt")


def _resolved_merge(repo: Path, git: Path) -> None:
    """Leaves a resolve-undo (REUC) section in the index."""
    _git(repo, git, "checkout", "-q", "-b", "other")
    (repo / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return b + a\n")
    _git(repo, git, "commit", "-qam", "other")
    _git(repo, git, "checkout", "-q", "main")
    (repo / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b + 0\n")
    _git(repo, git, "commit", "-qam", "main2")
    _git(repo, git, "merge", "other", check=False)  # conflict
    (repo / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    _git(repo, git, "add", "calc.py")  # resolving writes REUC
    _git(repo, git, "commit", "-qm", "merged")


@pytest.mark.parametrize(
    ("setup", "mutation", "marker", "present", "reason"),
    [
        pytest.param(
            _noop,
            ("update-index", "--untracked-cache"),
            b"UNTR",
            (False, True),
            None,
            id="untracked-cache",
        ),
        pytest.param(
            _noop, ("update-index", "--fsmonitor"), b"FSMN", (False, True), None, id="fsmonitor"
        ),
        pytest.param(
            _invalidate_cache_tree, ("write-tree",), b"TREE", (True, True), "tree", id="cache-tree"
        ),
        pytest.param(
            _resolved_merge, ("read-tree", "HEAD"), b"REUC", (True, False), None, id="resolve-undo"
        ),
    ],
)
def test_the_index_digest_does_not_cover_the_index_extensions(
    tmp_path: Path,
    setup: Any,
    mutation: tuple[str, ...],
    marker: bytes,
    present: tuple[bool, bool],
    reason: str | None,
) -> None:
    """M2c follow-up 2, the honest half: the index EXTENSIONS are NOT covered.

    `.git/index` carries optional sections beside the cache entries - untracked
    cache (`UNTR`), fsmonitor (`FSMN`), cache-tree (`TREE`), resolve-undo
    (`REUC`). They live in the bytes the tree hash excludes, and `ls-files`
    prints no trace of them at any verbosity, so NEITHER half of the guard sees
    them move. Measured here, 2026-08-24, git 2.50.1: the index bytes change,
    the digest does not.

    The cache-tree case is the one apparent exception, and it is not one: the
    guard trips with ``reason: "tree"`` because `write-tree` also writes a new
    tree OBJECT under `.git/objects`. The cached tree itself stays invisible.

    None of these four changes what a later `git status`/`git diff`/`git
    ls-files` REPORTS - they are caches and undo data - which is why this is
    documented rather than fixed. If that ever stops being true for one of
    them, it needs a digest of its own."""
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    setup(repo, git)

    policy = _policy(tmp_path, git)
    env = _verify_env(policy, repo, tmp_path / "verify-home")
    assert env.guard is not None and env.guard.index_check == "semantic"
    index_before = (repo / ".git" / "index").read_bytes()
    files_before = _files(repo)

    _git(repo, git, *mutation)

    index_after = (repo / ".git" / "index").read_bytes()
    assert index_after != index_before, mutation  # the extension really moved
    # the section this case is about is really the one that appeared/vanished
    assert ((marker in index_before), (marker in index_after)) == present, marker
    change = env.guard.changed()
    assert (change.reason if change is not None else None) == reason
    # whatever the tree hash saw, it was never the extension: the digest is flat
    assert env.guard.probe is not None
    assert env.guard.probe(repo) == env.guard.index_digest
    changed_paths = {rel for rel, sha in _files(repo).items() if files_before.get(rel) != sha} | (
        files_before.keys() - _files(repo).keys()
    )
    assert all(p.startswith(".git/objects/") for p in changed_paths), changed_paths


def test_the_split_index_is_caught_by_the_tree_hash_not_by_the_digest(tmp_path: Path) -> None:
    """M2c follow-up 2: `git update-index --split-index` moves the cache
    entries out into `.git/sharedindex.<sha>` and leaves a delta in
    `.git/index`. Measured 2026-08-24: that shared file is a NEW file in the
    copy, it is not in `GUARD_EXCLUDED_RELPATHS`, and the tree hash therefore
    catches enabling it (``reason: "tree"``). The digest is blind to the split
    - `ls-files -s -v` prints the same entries either way - but it keeps
    working afterwards: with the split enabled, a `--skip-worktree` still moves
    the digest."""
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    policy = _policy(tmp_path, git)
    env = _verify_env(policy, repo, tmp_path / "verify-home")
    assert env.guard is not None and env.guard.index_check == "semantic"
    digest_before = env.guard.index_digest
    assert not list((repo / ".git").glob("sharedindex.*"))

    _git(repo, git, "update-index", "--split-index")

    shared = [p.name for p in (repo / ".git").glob("sharedindex.*")]
    assert len(shared) == 1 and shared[0].startswith("sharedindex.")
    change = env.guard.changed()
    assert change is not None and change.reason == "tree"  # the NEW file is hashed
    assert change.index_digest_after == digest_before  # ... and the digest did not move

    # the semantic half still works against a split index
    env.guard.baseline = change.tree_after
    _git(repo, git, "update-index", "--skip-worktree", "calc.py")
    after = env.guard.changed()
    assert after is not None and after.reason == "git_index"
