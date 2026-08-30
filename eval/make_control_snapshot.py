"""Build a corpus task's ``snapshot/`` git repository from its tracked files.

A corpus snapshot is GENERATED, never committed: a git repository cannot be
committed inside another one (git records a nested ``.git`` as a gitlink, not
as files), and ``.gitignore`` excludes ``eval/corpus/*/snapshot/``. The working
tree lives in ``<task>/files/``; this script copies it into ``<task>/snapshot/``
and makes the single commit.

Python rather than shell so it runs unchanged on Windows: ``shutil`` does the
copy and only ``git`` is spawned, with the identity supplied per-invocation
(``-c user.name=...``) so no global config is read or needed.

    python eval/make_control_snapshot.py eval/corpus/plumbing-control
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath

from eris.sanitize import tree_sha256

Runner = Callable[[Sequence[str], Path], None]

COMMIT_IDENTITY: tuple[str, ...] = (
    "-c",
    "user.name=Eris Corpus",
    "-c",
    "user.email=corpus@eris.invalid",
    "-c",
    "commit.gpgsign=false",
)


def _run(argv: Sequence[str], cwd: Path) -> None:
    subprocess.run(list(argv), cwd=cwd, check=True, capture_output=True)


def git_commands(git: str, message: str) -> list[list[str]]:
    """The three git invocations, in order. Kept separate from execution so a
    hermetic test can assert the argv without spawning anything."""
    return [
        [git, "init", "-q", "-b", "main"],
        [git, "add", "-A"],
        [git, *COMMIT_IDENTITY, "commit", "-qm", message],
    ]


def copy_working_tree(task_dir: Path) -> Path:
    """Replace ``<task>/snapshot/`` with a fresh copy of ``<task>/files/``."""
    files = task_dir / "files"
    if not files.is_dir():
        raise FileNotFoundError(f"{files} does not exist")
    snapshot = task_dir / "snapshot"
    if snapshot.exists():
        shutil.rmtree(snapshot)
    shutil.copytree(files, snapshot)
    return snapshot


def build_snapshot(
    task_dir: Path,
    *,
    git: str = "git",
    message: str = "corpus snapshot",
    runner: Runner | None = None,
) -> Path:
    # Resolved at call time on purpose: a default argument would bind the
    # original function and bypass the test suite's subprocess guard.
    run = runner or _run
    snapshot = copy_working_tree(Path(task_dir))
    for argv in git_commands(git, message):
        run(argv, snapshot)
    return snapshot


def _not_git(rel: PurePosixPath) -> bool:
    return rel.parts[:1] == (".git",)


def snapshot_matches_files(task_dir: Path) -> bool | None:
    """Is ``<task>/snapshot`` still the tree ``<task>/files`` describes?

    None when the question does not apply - no ``files/`` (a snapshot built by
    ``eris.snapshot`` from a real repository at a sha) or no ``snapshot/`` yet.

    This exists because the two trees are versioned differently and cannot drift
    loudly: ``files/`` is committed, ``snapshot/`` is generated and gitignored,
    so editing a corpus file and forgetting to rebuild leaves a campaign
    measuring the OLD tree while the repository shows the new one. The ledger's
    ``snapshot_sha`` would be internally consistent and still describe a tree
    nobody reviewed. Compared modulo ``.git``, which the snapshot has and the
    source does not.
    """
    task_dir = Path(task_dir)
    files, snapshot = task_dir / "files", task_dir / "snapshot"
    if not files.is_dir() or not snapshot.is_dir():
        return None
    return tree_sha256(files) == tree_sha256(snapshot, skip=_not_git)


def corpus_task_dirs(corpus: Path) -> list[Path]:
    """Every corpus task that is built from a committed ``files/`` tree."""
    return sorted(
        p.parent for p in Path(corpus).glob("*/task.json") if (p.parent / "files").is_dir()
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval/make_control_snapshot.py", description=__doc__)
    parser.add_argument(
        "task_dir",
        help="corpus task directory (must contain files/), or a corpus root with --all",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="treat task_dir as a corpus root and build every task under it. Snapshots are "
        "gitignored, so a fresh clone has NONE and a campaign refuses to start; this is the "
        "one command that makes a checkout runnable.",
    )
    parser.add_argument("--git", default="git")
    parser.add_argument("--message", default="corpus snapshot")
    args = parser.parse_args(argv)
    targets = corpus_task_dirs(Path(args.task_dir)) if args.all else [Path(args.task_dir)]
    if not targets:
        raise SystemExit(f"no corpus task with a files/ tree under {args.task_dir}")
    for task_dir in targets:
        snapshot = build_snapshot(task_dir, git=args.git, message=args.message)
        print(f"built {snapshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
