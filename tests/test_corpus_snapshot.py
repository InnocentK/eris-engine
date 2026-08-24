"""eval/make_control_snapshot.py: a corpus snapshot is GENERATED, never
committed (a git repository cannot live inside another, and `.gitignore`
excludes `eval/corpus/*/snapshot/`). The generator is Python rather than shell
so it runs unchanged on every target OS; this test drives it with an injected
runner, so it spawns nothing."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from eval.make_control_snapshot import COMMIT_IDENTITY, build_snapshot, git_commands, main

REPO = Path(__file__).resolve().parents[1]
PLUMBING = REPO / "eval" / "corpus" / "plumbing-control"


def _task_dir(tmp_path: Path) -> Path:
    task = tmp_path / "t_01"
    (task / "files").mkdir(parents=True)
    (task / "files" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (task / "files" / "README.md").write_text("# calc\n")
    return task


def test_the_generator_copies_the_files_and_makes_one_commit(tmp_path: Path) -> None:
    task = _task_dir(tmp_path)
    stale = task / "snapshot"
    stale.mkdir()
    (stale / "LEFTOVER").write_text("from a previous build")

    calls: list[tuple[list[str], Path]] = []

    def runner(argv: Sequence[str], cwd: Path) -> None:
        calls.append((list(argv), cwd))

    snapshot = build_snapshot(task, git="/usr/bin/git", message="m", runner=runner)
    assert snapshot == task / "snapshot"
    assert sorted(p.name for p in snapshot.iterdir()) == ["README.md", "calc.py"]
    assert not (snapshot / "LEFTOVER").exists()  # rebuilt, not merged into
    assert [c[0] for c in calls] == git_commands("/usr/bin/git", "m")
    assert all(cwd == snapshot for _argv, cwd in calls)
    # exactly one commit, with the identity supplied per invocation so no
    # global git config is read (or needed) on any machine
    assert [c[0][1] for c in calls] == ["init", "add", "-c"]
    assert calls[2][0][1:7] == list(COMMIT_IDENTITY)
    assert calls[2][0].count("commit") == 1


def test_the_generator_refuses_a_task_without_tracked_files(tmp_path: Path) -> None:
    (tmp_path / "t_02").mkdir()
    with pytest.raises(FileNotFoundError, match="files"):
        build_snapshot(tmp_path / "t_02", runner=lambda _a, _c: None)


def test_the_generator_cli_reports_what_it_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    task = _task_dir(tmp_path)
    import eval.make_control_snapshot as mod

    monkeypatch.setattr(mod, "_run", lambda _argv, _cwd: None)
    assert main([str(task), "--message", "m"]) == 0
    assert str(task / "snapshot") in capsys.readouterr().out


def test_the_plumbing_control_is_generated_not_committed() -> None:
    """The claim in that directory's README, asserted: the working tree is
    tracked in `files/`, and `.gitignore` excludes the generated snapshot."""
    assert (PLUMBING / "files" / "calc.py").is_file()
    assert (PLUMBING / "files" / "README.md").is_file()
    ignore = (REPO / ".gitignore").read_text().splitlines()
    assert "eval/corpus/*/snapshot/" in ignore
    spec = json.loads((PLUMBING / "task.json").read_bytes())
    assert spec["snapshot"] == "snapshot" and spec["scored"] is False
