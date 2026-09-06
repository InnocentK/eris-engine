"""eval/make_control_snapshot.py: a corpus snapshot is GENERATED, never
committed (a git repository cannot live inside another, and `.gitignore`
excludes `eval/corpus/*/snapshot/`). The generator is Python rather than shell
so it runs unchanged on every target OS; this test drives it with an injected
runner, so it spawns nothing."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from eval.make_control_snapshot import (
    COMMIT_IDENTITY,
    IGNORED_NAMES,
    build_snapshot,
    corpus_task_dirs,
    git_commands,
    main,
    snapshot_matches_files,
)

from eris.evidence import TaskSpec

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


def test_a_snapshot_that_drifted_from_its_committed_files_is_detected(tmp_path: Path) -> None:
    """`files/` is committed and `snapshot/` is gitignored, so they are versioned
    differently and drift silently. Edit a corpus file, forget to rebuild, and a
    campaign measures the OLD tree while the repository shows the new one - with
    a `snapshot_sha` that is internally consistent and describes a tree nobody
    reviewed. This is not hypothetical: the plumbing control's snapshot was
    found stale on 2026-08-30, its README and docstrings several edits behind.

    Compared modulo `.git`, which the snapshot has and the source does not - so
    a freshly built snapshot must compare EQUAL, not merely "close".
    """
    task = _task_dir(tmp_path)
    assert snapshot_matches_files(task) is None  # nothing built yet

    build_snapshot(task, runner=lambda argv, cwd: None)
    assert snapshot_matches_files(task) is True

    (task / "files" / "calc.py").write_text("def add(a, b):\n    return a + b  # edited\n")
    assert snapshot_matches_files(task) is False

    build_snapshot(task, runner=lambda argv, cwd: None)
    assert snapshot_matches_files(task) is True


def test_a_stale_snapshot_stops_a_run_before_any_worker_is_spawned(tmp_path: Path) -> None:
    """The check is worthless if it only reports; it must REFUSE, and refuse at
    the point every campaign and every single-cell run passes through, before
    money is spent.
    """
    from eval.run import load_task

    from eris.launch import LaunchRefused

    task = _task_dir(tmp_path)
    build_snapshot(task, runner=lambda argv, cwd: None)
    (task / "task.json").write_text(
        json.dumps(
            {
                "task_id": "t_01",
                "question": "q",
                "category": "control",
                "snapshot": "snapshot",
            }
        )
    )
    assert load_task(task / "task.json")[1] == (task / "snapshot").resolve()

    (task / "files" / "calc.py").write_text("def add(a, b):\n    return a + b  # drifted\n")
    # not `match="stale"`: `tmp_path` is named after the test, so that pattern
    # is satisfied by the temp directory in the message and would hold even
    # with the refusal removed
    with pytest.raises(LaunchRefused, match="does not match the committed"):
        load_task(task / "task.json")


def test_a_stale_snapshot_also_stops_invoke_which_skips_load_task(tmp_path: Path) -> None:
    """`invoke` builds its call in `_build_call`, never touching `load_task` -
    so the refusal above protects only the paths that happen to use it. The
    duplicate check inside `_build_call` is the one standing between a stale
    snapshot and a real spawn on this path, and until this test (panel
    2026-09-06, B3) deleting it broke nothing.
    """
    import argparse

    from eval.run import _build_call

    from eris.launch import LaunchRefused
    from eris.policy import load_policy
    from tests.test_run_harness import world

    w = world(tmp_path)  # a valid policy with CLI workers; its corpus is unused
    task = _task_dir(tmp_path)
    build_snapshot(task, runner=lambda argv, cwd: None)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("q")
    args = argparse.Namespace(
        worker="grok",
        prompt_file=str(prompt),
        snapshot=str(task / "snapshot"),
        task_id="t_01",
        stage="propose",
        repeat_index=0,
    )
    loaded = load_policy(w["policy"])

    # fresh snapshot: the call builds
    _build_call(loaded, args, {}, home=tmp_path, scratch_dir=None)

    # drift the committed files: the SAME invocation must now refuse
    (task / "files" / "calc.py").write_text("def add(a, b):\n    return a + b  # drifted\n")
    with pytest.raises(LaunchRefused, match="does not match the committed"):
        _build_call(loaded, args, {}, home=tmp_path, scratch_dir=None)


def test_the_builder_can_make_every_snapshot_a_clone_is_missing(tmp_path: Path) -> None:
    """Snapshots are gitignored, so a fresh checkout has NONE and every run
    refuses. `--all` is the one command that makes a clone runnable; without it
    the corpus has to be rebuilt task by task, by hand, from memory.
    """
    corpus = tmp_path / "corpus"
    for name in ("t_01", "t_02"):
        d = corpus / name
        (d / "files").mkdir(parents=True)
        (d / "files" / "calc.py").write_text(f"# {name}\n")
        (d / "task.json").write_text("{}")
    # a task with no files/ tree is built by eris.snapshot from a real repo and
    # is not this command's business
    (corpus / "t_03").mkdir()
    (corpus / "t_03" / "task.json").write_text("{}")

    assert corpus_task_dirs(corpus) == [corpus / "t_01", corpus / "t_02"]

    calls: list[Path] = []
    monkey = pytest.MonkeyPatch()
    monkey.setattr("eval.make_control_snapshot._run", lambda argv, cwd: calls.append(cwd))
    try:
        assert main([str(corpus), "--all"]) == 0
    finally:
        monkey.undo()
    assert {c.parent.name for c in calls} == {"t_01", "t_02"}
    assert snapshot_matches_files(corpus / "t_01") is True


def test_the_shipped_corpus_snapshots_are_current() -> None:
    """The real corpus on disk, not a fixture.

    `is not False` alone would pass on a fresh clone for the wrong reason:
    snapshots are gitignored, so `snapshot_matches_files` returns None for every
    task and the assertion holds while nothing has been checked. That is a
    legitimate state - a clone has no snapshots until it builds them - so the
    test SKIPS there and says so, rather than reporting a pass it did not earn.
    """
    tasks = corpus_task_dirs(REPO / "eval" / "corpus")
    assert tasks, "no corpus task with a files/ tree - this test would check nothing"
    results = {t.name: snapshot_matches_files(t) for t in tasks}
    for name, res in results.items():
        assert res is not False, (
            f"{name}: snapshot is stale - rebuild with "
            f"`python eval/make_control_snapshot.py eval/corpus --all`"
        )
    if all(res is None for res in results.values()):
        pytest.skip("no snapshots built in this checkout (gitignored); nothing was verified")


def test_a_symlink_in_the_files_tree_is_refused(tmp_path: Path) -> None:
    """`shutil.copytree` DEREFERENCES symlinks by default, so a link in `files/`
    pointing at the answer key is materialised as the key's PLAINTEXT inside
    `snapshot/` - the worker's own cwd - under whatever name the link had, where
    nothing called `key.json` exists to find (stop review, 2026-08-30).

    A corpus task is a plain tree of source files and has no need of symlinks,
    so they are refused outright rather than resolved carefully.
    """
    task = _task_dir(tmp_path)
    build_snapshot(task, runner=lambda argv, cwd: None)  # clean tree builds

    secret = tmp_path / "keys" / "t_01.json"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text('{"canary": "ERIS-KEY-CANARY-t01-9f3ab27c"}')
    (task / "files" / "notes.txt").symlink_to(secret)
    with pytest.raises(ValueError, match="contains symlink"):
        build_snapshot(task, runner=lambda argv, cwd: None)

    # nested, not only at the top level
    (task / "files" / "notes.txt").unlink()
    (task / "files" / "pkg").mkdir()
    (task / "files" / "pkg" / "x.py").symlink_to(secret)
    with pytest.raises(ValueError, match="contains symlink"):
        build_snapshot(task, runner=lambda argv, cwd: None)


@pytest.mark.real_subprocess
def test_the_documented_cli_entry_points_run_as_scripts() -> None:
    """`eval/run.py` and `eval/score.py` are BOTH modules and scripts.

    `docs/EVAL-PLAN.md` documents `python eval/run.py run|campaign ...`, and the
    test suite imports them as modules - so when `eval/run.py` gained an
    `eval.*` import, the module path kept working and the SCRIPT path died at
    import time with ModuleNotFoundError. Nothing caught it until a campaign was
    run by hand. Run as a script, `sys.path[0]` is `eval/`, not the repository
    root.

    `--help` is enough: the failure was at import, before any argument was read.
    Marked `real_subprocess`, which permits only this interpreter - the point of
    the test is that the SCRIPT path resolves its imports, and nothing but a
    real interpreter can show that.
    """
    for script in ("eval/run.py", "eval/score.py"):
        proc = subprocess.run(
            [sys.executable, script, "--help"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, f"{script} --help failed:\n{proc.stderr[-800:]}"
        assert "usage:" in proc.stdout.lower(), f"{script} printed no usage"


# Phrases that state a task's ANSWER rather than describing its subject. A
# worker's cwd is `<task>/snapshot` and E1 established it reads the parent, so
# everything under a task directory is material the graded model can read.
ANSWER_TELLS: tuple[str, ...] = (
    "no defect",
    "no defects",
    "no bug",
    "nothing to find",
    "nothing wrong",
    "clean control",
    "distractor",
    "planted",
    "look risky",
    "looks risky",
    "the answer is",
    "correct answer",
)


def test_no_scored_task_tells_the_worker_its_answer() -> None:
    """The first draft of this corpus shipped controls whose own files said
    "There is no defect here" and "written to LOOK risky ... so a reviewer under
    pressure has something to reach for". Both were in `files/`, so both were
    copied into `snapshot/` - the worker's cwd. The controls measured nothing.

    The canary machinery could not catch this: it looks for the KEY's content,
    and this is not the key, it is the answer written in prose.

    Unscored plumbing tasks are exempt: they enter no metric, so their payload
    cannot corrupt one, and describing itself is the whole point of a fixture.
    """
    from eval.run import task_is_scored

    offenders: list[str] = []
    for task_dir in sorted(p.parent for p in (REPO / "eval" / "corpus").glob("*/task.json")):
        if not task_is_scored(task_dir / "task.json"):
            continue
        for f in sorted(task_dir.rglob("*")):
            if not f.is_file() or ".git" in f.parts:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue
            for tell in ANSWER_TELLS:
                if tell in text:
                    offenders.append(f"{f.relative_to(REPO)}: {tell!r}")
    assert not offenders, "a scored task tells the worker its answer:\n  " + "\n  ".join(offenders)


def test_a_control_key_and_its_task_agree_that_nothing_is_planted() -> None:
    """A control's whole job is to measure invented findings, which only works
    if there is genuinely nothing to find. `Key` refuses a control that plants
    findings; this asserts the shipped corpus actually has none, and that every
    plan task DOES plant something - a plan key with no findings would measure
    no catch rate at all while looking like a scored task.
    """
    from eval.score import load_key

    corpus = REPO / "eval" / "corpus"
    seen = {"control": 0, "plan": 0}
    for task_dir in sorted(p.parent for p in corpus.glob("*/task.json")):
        spec = json.loads((task_dir / "task.json").read_text())
        if spec.get("scored", True) is False:
            continue
        key = load_key(corpus, task_dir.name)
        cat = key.category.value
        seen[cat] = seen.get(cat, 0) + 1
        if cat == "control":
            assert not key.findings, f"{task_dir.name}: a control must plant nothing"
        elif cat == "plan":
            assert key.findings, f"{task_dir.name}: a plan task with no findings measures nothing"
    assert seen["control"] >= 1 and seen["plan"] >= 1, f"corpus is one-sided: {seen}"


def test_generated_bytecode_does_not_make_a_task_permanently_unrunnable(tmp_path: Path) -> None:
    """The copy excluded `__pycache__` while the freshness check still counted
    it, so a stray one in `files/` - which importing the module once creates -
    made the two trees differ FOREVER: the run was refused, the refusal said
    "rebuild", and rebuilding could not fix it (stop review, 2026-08-30).

    Both sides must exclude exactly the same things, and a real edit must still
    be caught - an exclusion wide enough to hide drift would be worse than the
    bug it fixed.
    """
    task = _task_dir(tmp_path)
    build_snapshot(task, runner=lambda argv, cwd: None)
    assert snapshot_matches_files(task) is True

    pyc = task / "files" / "__pycache__"
    pyc.mkdir()
    (pyc / "calc.cpython-314.pyc").write_bytes(b"\x00stale docstring")
    assert snapshot_matches_files(task) is True, "bytecode must not count as drift"

    # rebuilt WITH the bytecode present, so the copy is what is under test here
    build_snapshot(task, runner=lambda argv, cwd: None)
    assert not (task / "snapshot" / "__pycache__").exists(), "and must not be copied"
    assert snapshot_matches_files(task) is True

    (task / "files" / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    assert snapshot_matches_files(task) is False, "a real edit must still be caught"


def test_every_keyed_finding_is_inside_the_evidence_the_task_declares() -> None:
    """A task's `excerpts` are what the evidence pack puts in front of a worker.
    A planted finding outside them is not a hard finding, it is an unfindable
    one, and the recall it depresses is measuring the corpus rather than the
    model.

    The plan documents were rewritten to space their findings apart and grew
    from 47 to 84 lines; the excerpts still said 1-47, leaving three of five
    planted findings outside the declared evidence. The control excerpts had
    been wrong in the other direction since the first draft, claiming more lines
    than the file has (stop review, 2026-08-30).
    """
    corpus = REPO / "eval" / "corpus"
    checked = 0
    for task_dir in sorted(p.parent for p in corpus.glob("*/task.json")):
        spec = json.loads((task_dir / "task.json").read_text())
        for e in spec.get("excerpts", []):
            n = len((task_dir / "files" / e["path"]).read_text().splitlines())
            assert e["line_end"] <= n, (
                f"{task_dir.name}: excerpt {e['path']} claims line {e['line_end']} of a "
                f"{n}-line file"
            )
            assert e["line_start"] >= 1
        if spec.get("scored", True) is False:
            continue
        from eval.score import load_key

        for f in load_key(corpus, task_dir.name).findings:
            checked += 1
            assert any(
                e["path"] == f.path
                and e["line_start"] <= f.line_start
                and f.line_end <= e["line_end"]
                for e in spec.get("excerpts", [])
            ), (
                f"{task_dir.name}: planted finding {f.id} at {f.path} L{f.line_start}-{f.line_end} "
                "is outside every excerpt the task shows the worker - it cannot be found"
            )
    assert checked, "no scored task plants a finding - this test would check nothing"


def test_every_keyed_finding_survives_into_the_evidence_actually_emitted(tmp_path: Path) -> None:
    """The declaration is not the artifact. `task.json` says which lines to
    show; `eris.evidence` decides what a worker actually receives, capping an
    excerpt at `EXCERPT_MAX_LINES` and eliding an oversized item in `_cap`.
    Asserting that a finding lies inside a DECLARED range proves nothing about
    whether its lines reach the prompt (stop review, 2026-08-30).

    So this builds the REAL pack - `build_evidence_pack`, the function the
    harness calls - over the real snapshot, and looks for each finding's line
    numbers in the item content a worker would be given. The first version
    called the private `_excerpt` helper and asserted a size proxy for `_cap`
    rather than running it: that tested a component, not the emission.

    Builds its own snapshot from the committed `files/` tree rather than
    depending on `<task>/snapshot`. Snapshots are gitignored, so on a clean
    checkout - which is what CI is - a test that skips without one never runs at
    all, and an invariant enforced nowhere is not enforced (stop review,
    2026-08-30). `files/` is committed, so this runs everywhere; that the
    generated snapshot still matches `files/` is a different invariant, checked
    by `test_the_shipped_corpus_snapshots_are_current`, which genuinely cannot
    run without one.
    """
    from eval.score import load_key

    from eris.evidence import build_evidence_pack
    from eris.redact import Redactor
    from eris.writer import RunWriter

    # the established pack-building helpers, rather than a second construction
    # of policy/env that could drift from the one the harness exercises
    from tests.test_evidence import ScriptedPopen, make_env, make_policy

    corpus = REPO / "eval" / "corpus"
    tasks = sorted(p.parent for p in corpus.glob("*/task.json"))

    checked = 0
    for i, task_dir in enumerate(tasks):
        spec_raw = json.loads((task_dir / "task.json").read_text())
        if spec_raw.get("scored", True) is False:
            continue
        # the snapshot a worker would run in, built here from the committed
        # tree, with the same exclusions the real builder applies
        snapshot = tmp_path / f"snap{i}"
        shutil.copytree(task_dir / "files", snapshot, ignore=shutil.ignore_patterns(*IGNORED_NAMES))
        spec = TaskSpec.model_validate(spec_raw)
        (tmp_path / f"env{i}").mkdir(parents=True, exist_ok=True)
        writer = RunWriter(tmp_path / f"run{i}", Redactor(), run_id=f"r{i}").open()
        try:
            build = build_evidence_pack(
                spec,
                env=make_env(
                    tmp_path / f"env{i}",
                    snapshot,
                    ScriptedPopen(),
                    make_policy(tmp_path / f"env{i}"),
                ),
                writer=writer,
                repeat_index=0,
                policy_sha256="0" * 64,
                snapshot_sha=None,
            )
        finally:
            writer.close()
        # Parsed out of `build.rendered` - the bytes that become the prompt -
        # not out of the intermediate item objects. Canonical JSON, so the
        # content is escaped in the raw bytes and has to be decoded rather than
        # substring-searched: the first version looked for a literal newline and
        # failed against the escaped one.
        emitted: dict[str, str] = {}
        for item in json.loads(build.rendered)["items"]:
            label = str(item["label"])
            if not label.startswith("excerpt:"):
                continue
            path = label.split(":", 2)[1]
            assert not item["truncated"], (
                f"{task_dir.name}: the excerpt for {path} is truncated before a worker sees it"
            )
            emitted[path] = emitted.get(path, "") + str(item["content"])
        for f in load_key(corpus, task_dir.name).findings:
            checked += 1
            body = "\n" + emitted.get(f.path, "")
            missing = [n for n in range(f.line_start, f.line_end + 1) if f"\n{n}: " not in body]
            assert not missing, (
                f"{task_dir.name}: finding {f.id} claims {f.path} L{f.line_start}-{f.line_end}, "
                f"but lines {missing[:5]} are not in the evidence the worker receives"
            )
    assert checked, "no scored task plants a finding - this test would check nothing"
