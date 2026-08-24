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
from pathlib import Path

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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval/make_control_snapshot.py", description=__doc__)
    parser.add_argument("task_dir", help="corpus task directory (must contain files/)")
    parser.add_argument("--git", default="git")
    parser.add_argument("--message", default="corpus snapshot")
    args = parser.parse_args(argv)
    snapshot = build_snapshot(Path(args.task_dir), git=args.git, message=args.message)
    print(f"built {snapshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
