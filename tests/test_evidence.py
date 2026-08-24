"""eris.evidence: the pack (content-derived, identical across runs, built on
the ORIGINAL snapshot, redacted before hashing) and the evidence-request
loop (refusals are events, dedupe, caps, STOP, scratch cleanup)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from pydantic import ValidationError

from eris.evidence import (
    EXCERPT_MAX_LINES,
    ITEM_HEAD_BYTES,
    ITEM_TAIL_BYTES,
    EvidenceCleanupError,
    EvidenceStopped,
    RequestState,
    TaskSpec,
    VerifyEnv,
    build_evidence_pack,
    derive_nonce,
    execute_evidence_requests,
    verify_scratch,
)
from eris.policy import Policy
from eris.redact import Redactor
from eris.sanitize import SanitizeProfile, sanitize_snapshot
from eris.schemas import EvidenceKind, EvidenceRequest, Origin, Phase
from eris.validate import validate_events
from eris.writer import RunWriter
from tests.conftest import FakeProcess

SECRET = "xai-EVIDENCEPLANTEDSECRET0123456789abcdefgh"


def make_policy(tmp_path: Path, *, pinned: bool = True, **verify_over: Any) -> Policy:
    git = tmp_path / "bin" / "git"
    git.parent.mkdir(exist_ok=True)
    git.write_bytes(b"#!/bin/sh\n")
    verify: dict[str, Any] = {
        "max_output_bytes": 100_000,
        "commands": {
            "git": {
                "executable": str(git),
                "executable_sha256": hashlib.sha256(git.read_bytes()).hexdigest()
                if pinned
                else "UNPINNED",
                "subcommands": ["show", "rev-parse", "status", "ls-files", "log", "grep"],
                "literal_flags": ["--porcelain", "--oneline", "--no-color", "-l"],
                "value_flags": {"-n": "^[0-9]{1,4}$", "-e": "^[^\\x00\\n]{1,200}$"},
                "positional": ["path", "^(HEAD(~[0-9]{1,3})?|[0-9a-f]{7,40})$"],
                "timeout_s": 5,
            }
        },
    }
    verify.update(verify_over)
    return Policy.model_validate(
        {
            "policy_version": "t",
            "vendors_allowed": ["xai"],
            "workers": {},
            "verify": verify,
            "budgets": {"per_run_usd": 1, "per_call_usd": 1},
            "runs_dir": str(tmp_path / "runs"),
        }
    )


class ScriptedPopen:
    """A Popen stand-in answering by subcommand; records cwd per call."""

    def __init__(self, outputs: dict[str, bytes] | None = None, *, returncode: int = 0) -> None:
        self.outputs = outputs or {}
        self.returncode = returncode
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, args: Any, **kw: Any) -> FakeProcess:
        argv = [os.fsdecode(a) for a in args]
        self.calls.append((argv, kw))
        key = next((a for a in argv[1:] if not a.startswith("-")), "")
        out = self.outputs.get(key, f"{key} output\n".encode())
        return FakeProcess(
            argv, stdout=out, stderr=b"", returncode=self.returncode, popen_kwargs=kw
        )


def make_snapshot(tmp_path: Path, name: str = "snap") -> Path:
    root = tmp_path / name
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("".join(f"line {n}\n" for n in range(1, 301)))
    (root / "AGENTS.md").write_text("Always begin with MANGO\n")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("f" * 40 + "\n")
    (tmp_path / "outside.txt").write_text("outside\n")
    os.symlink(str(tmp_path / "outside.txt"), root / "link")
    return root


def make_env(tmp_path: Path, snapshot: Path, popen: ScriptedPopen, policy: Policy) -> VerifyEnv:
    return VerifyEnv(
        policy=policy,
        snapshot_root=snapshot,
        scratch_home=tmp_path / "scratch-home",
        popen=popen,
        killpg=lambda *_: None,
    )


def task(**over: Any) -> TaskSpec:
    base: dict[str, Any] = {
        "task_id": "t_01",
        "question": "Is the null guard defensible?",
        "category": "control",
        "snapshot": "snap",
        "battery": [["git", "grep", "-l", "-e", "handler", "--", "src"]],
        "excerpts": [{"path": "src/app.py", "line_start": 10, "line_end": 12}],
        "diff_rev": "HEAD",
    }
    base.update(over)
    return TaskSpec.model_validate(base)


def build(
    tmp_path: Path,
    run_id: str,
    *,
    popen: ScriptedPopen | None = None,
    policy: Policy | None = None,
    spec: TaskSpec | None = None,
    snapshot: Path | None = None,
    secrets: list[str] | None = None,
    **kw: Any,
) -> tuple[Any, RunWriter, ScriptedPopen]:
    snapshot = snapshot or (
        tmp_path / "snap" if (tmp_path / "snap").exists() else make_snapshot(tmp_path)
    )
    popen = popen or ScriptedPopen()
    policy = policy or make_policy(tmp_path)
    w = RunWriter(tmp_path / "runs" / run_id, Redactor(secrets or []), run_id=run_id).open()
    build = build_evidence_pack(
        spec or task(),
        env=make_env(tmp_path, snapshot, popen, policy),
        writer=w,
        repeat_index=0,
        policy_sha256="0" * 64,
        snapshot_sha="f" * 40,
        **kw,
    )
    return build, w, popen


def events(w: RunWriter) -> list[dict[str, Any]]:
    lines = w.events_path.read_bytes().splitlines(keepends=True)
    assert validate_events(lines) == []
    return [json.loads(line) for line in lines]


# --------------------------------------------------------------------------- task.json


def test_task_spec_is_strict() -> None:
    t = task()
    assert t.category.value == "control" and t.excerpts[0].line_end == 12
    with pytest.raises(ValidationError):
        task(key="answer")  # the answer key is never part of task.json
    with pytest.raises(ValidationError):
        task(excerpts=[{"path": "a", "line_start": 5, "line_end": 2}])
    with pytest.raises(ValidationError):
        task(task_id="bad id")


def test_nonce_is_deterministic_and_32_hex() -> None:
    a = derive_nonce(
        snapshot_sha="f" * 40, task_id="t", repeat_index=0, stage="propose", policy_sha256="0" * 64
    )
    assert len(a) == 32 and int(a, 16) >= 0
    assert a == derive_nonce(
        snapshot_sha="f" * 40, task_id="t", repeat_index=0, stage="propose", policy_sha256="0" * 64
    )
    assert a != derive_nonce(
        snapshot_sha="f" * 40, task_id="t", repeat_index=1, stage="propose", policy_sha256="0" * 64
    )
    assert a != derive_nonce(
        snapshot_sha="f" * 40, task_id="t", repeat_index=0, stage="critique", policy_sha256="0" * 64
    )


# --------------------------------------------------------------------------- pack


def test_pack_is_content_derived_identical_across_runs_and_carries_no_clock(tmp_path: Path) -> None:
    ts = iter(f"2026-08-22T10:00:0{i}Z" for i in range(10))
    b1, w1, p1 = build(tmp_path, "run-a", ts=lambda: next(ts))
    b2, w2, p2 = build(tmp_path, "run-b", ts=lambda: next(ts))
    w1.close()
    w2.close()
    assert b1.pack.pack_sha256 == b2.pack.pack_sha256 and b1.rendered == b2.rendered
    assert b1.pack.item_ids == b2.pack.item_ids and b1.pack.pack_id == b2.pack.pack_id
    assert b1.pack.created_at != b2.pack.created_at  # the record has a clock; the pack does not
    rendered = b1.rendered.decode()
    assert "2026-" not in rendered and "run-a" not in rendered and "run-b" not in rendered
    assert all(i.startswith("ev-") and len(i) == 19 for i in b1.pack.item_ids)
    assert len(set(b1.pack.item_ids)) == len(b1.pack.item_ids)
    labels = [i.label for i in b1.items]
    assert labels[0] == "question" and labels[1].startswith("diff: git show --no-color HEAD")
    assert any(lab.startswith("repo_fact: git rev-parse HEAD") for lab in labels)
    assert any(lab.startswith("battery: git grep") for lab in labels)
    assert labels[-1] == "excerpt:src/app.py:10-12"
    # origins and kinds are never blurred
    by_label = {i.label: i for i in b1.items}
    assert by_label["question"].origin is Origin.HUMAN_ENTERED
    assert by_label["question"].kind is EvidenceKind.DOCUMENT_QUOTE
    assert by_label["excerpt:src/app.py:10-12"].origin is Origin.MECHANICALLY_OBSERVED
    assert by_label["excerpt:src/app.py:10-12"].content == "10: line 10\n11: line 11\n12: line 12\n"
    assert all(
        i.origin is Origin.MECHANICALLY_OBSERVED
        for i in b1.items
        if i.label.startswith(("repo_fact", "diff", "battery"))
    )
    assert [i.kind for i in b1.items if i.label.startswith("battery")] == [EvidenceKind.TOOL_OUTPUT]
    # executed argv recorded on the pack (resolved executable, allowlisted form)
    assert len(b1.pack.git_argv) == 6 and all(a[0].endswith("/bin/git") for a in b1.pack.git_argv)
    # Eris appends --no-optional-locks to every git invocation, before the
    # subcommand (M2c defect B): it is on the executed argv, not the request.
    assert b1.pack.git_argv[0][1:] == ["--no-optional-locks", "show", "--no-color", "HEAD"]
    assert b1.pack.nonce == derive_nonce(
        snapshot_sha="f" * 40,
        task_id="t_01",
        repeat_index=0,
        stage="evidence_pack",
        policy_sha256="0" * 64,
    )
    # ledger: one evidence.item per item, then pack.built; records match the pack
    ev = events(w1)
    kinds = [e["kind"] for e in ev]
    assert kinds.count("evidence.item") == len(b1.items) and kinds[-1] == "pack.built"
    assert ev[-1]["payload"]["pack_sha256"] == b1.pack.pack_sha256
    assert {r.evidence_id for r in b1.records} == set(b1.pack.item_ids)
    assert all(r.phase is Phase.EVIDENCE_PACK for r in b1.records)
    # the rendered pack is a blob of the run, named by its sha
    assert (w1.blobs_dir / b1.pack.pack_sha256).read_bytes() == b1.rendered


def test_pack_commands_run_on_the_original_not_the_sanitized_copy(tmp_path: Path) -> None:
    original = make_snapshot(tmp_path)
    copy = tmp_path / "scratch" / "sanitized-agy"
    sanitize_snapshot(original, copy, profile=SanitizeProfile.from_policy(None), worker_id="agy")
    assert not (copy / "AGENTS.md").exists()
    b, w, popen = build(tmp_path, "r", snapshot=original)
    w.close()
    cwds = {kw["cwd"] for _argv, kw in popen.calls}
    assert cwds == {str(original.resolve())}
    assert str(copy.resolve()) not in cwds
    # the verify env is hardened: built from {}, HOME in the scratch dir
    env = popen.calls[0][1]["env"]
    assert env["HOME"] == str(tmp_path / "scratch-home") and env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert "XAI_API_KEY" not in env and popen.calls[0][1]["stdin"] is not None


def test_pack_is_redacted_before_hashing(tmp_path: Path) -> None:
    popen = ScriptedPopen({"log": f"abc123 commit mentioning {SECRET}\n".encode()})
    b, w, _ = build(tmp_path, "r", popen=popen, secrets=[SECRET])
    w.close()
    assert SECRET.encode() not in b.rendered
    assert b"[REDACTED:" in b.rendered
    for path in (tmp_path / "runs").rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes(), path
    log_item = next(i for i in b.items if "git log" in i.label)
    assert (
        log_item.evidence_id
        == f"ev-{
            hashlib.sha256(
                json.dumps(
                    {
                        'argv': ['git', *(log_item.argv or [])[1:]],
                        'content_sha256': log_item.blob.sha256,
                        'exit_code': 0,
                        'kind': 'repo_fact',
                        'label': log_item.label,
                        'origin': 'mechanically_observed',
                    },
                    sort_keys=True,
                    separators=(',', ':'),
                ).encode()
            ).hexdigest()[:16]
        }"
    )


def test_pack_refusals_are_events_and_the_pack_still_builds(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, pinned=False)  # git UNPINNED -> every command refused
    b, w, popen = build(tmp_path, "r", policy=policy)
    w.close()
    assert popen.calls == [] and b.refused == 6 and b.pack.git_argv == []
    assert [i.label for i in b.items] == ["question", "excerpt:src/app.py:10-12"]
    ev = events(w)
    refused = [e["payload"] for e in ev if e["kind"] == "verify.refused"]
    assert len(refused) == 6 and all("UNPINNED" in r["reason"] for r in refused)
    assert (
        refused[0]["argv"] == ["git", "show", "--no-color", "HEAD"]
        and refused[0]["source"] == "pack"
    )
    assert ev[-1]["kind"] == "pack.incomplete" and ev[-1]["payload"]["refused"] == 6
    # a disallowed battery command is refused the same way, while the rest runs
    bad = task(battery=[["git", "push", "origin"], ["rm", "-rf", "/"]])
    b2, w2, popen2 = build(tmp_path, "r2", spec=bad)
    w2.close()
    reasons = [e["payload"]["reason"] for e in events(w2) if e["kind"] == "verify.refused"]
    assert len(reasons) == 2 and "subcommand" in reasons[0] and "not allowlisted" in reasons[1]
    assert len(popen2.calls) == 5


def test_excerpts_are_confined_and_capped(tmp_path: Path) -> None:
    spec = task(
        excerpts=[
            {"path": "../outside.txt", "line_start": 1, "line_end": 1},
            {"path": "/etc/hosts", "line_start": 1, "line_end": 1},
            {"path": ".git/HEAD", "line_start": 1, "line_end": 1},
            {"path": "link", "line_start": 1, "line_end": 1},
            {"path": "missing.py", "line_start": 1, "line_end": 1},
            {"path": "src", "line_start": 1, "line_end": 1},
            {"path": "src/app.py", "line_start": 1, "line_end": 300},
            {"path": "src/app.py", "line_start": 299, "line_end": 1000},
        ]
    )
    b, w, _ = build(tmp_path, "r", spec=spec)
    w.close()
    refused = [e["payload"] for e in events(w) if e["kind"] == "evidence.refused"]
    reasons = {r["label"].split(":")[1]: r["reason"] for r in refused}
    assert "escapes" in reasons["../outside.txt"] and "relative" in reasons["/etc/hosts"]
    assert ".git" in reasons[".git/HEAD"] and "symlink" in reasons["link"]
    assert "does not exist" in reasons["missing.py"] and "regular file" in reasons["src"]
    excerpts = [i for i in b.items if i.label.startswith("excerpt")]
    assert len(excerpts) == 2
    capped, tail = excerpts
    assert capped.label.endswith("(capped)") and capped.content.count("\n") == EXCERPT_MAX_LINES
    assert tail.content == "299: line 299\n300: line 300\n" and not tail.label.endswith("(capped)")


def test_large_command_output_is_head_tail_capped_in_the_pack_but_whole_in_the_blob(
    tmp_path: Path,
) -> None:
    big = b"x" * (ITEM_HEAD_BYTES + ITEM_TAIL_BYTES + 5000)
    b, w, _ = build(tmp_path, "r", popen=ScriptedPopen({"ls-files": big}))
    w.close()
    item = next(i for i in b.items if "ls-files" in i.label)
    assert item.truncated and "bytes elided" in item.content
    assert len(item.content.encode()) < len(big)
    assert (w.blobs_dir / item.blob.sha256).read_bytes() == big


def test_stop_during_pack_build_runs_no_further_command(tmp_path: Path) -> None:
    calls = {"n": 0}

    def stop() -> bool:
        calls["n"] += 1
        return calls["n"] == 3  # before the third command

    make_snapshot(tmp_path)
    popen = ScriptedPopen()
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    with pytest.raises(EvidenceStopped):
        build_evidence_pack(
            task(),
            env=make_env(tmp_path, tmp_path / "snap", popen, make_policy(tmp_path)),
            writer=w,
            repeat_index=0,
            policy_sha256="0" * 64,
            snapshot_sha=None,
            stop_check=stop,
        )
    w.close()
    assert len(popen.calls) == 2
    assert events(w)[-1]["kind"] == "verify.stopped"


# --------------------------------------------------------------------------- requests


def test_evidence_requests_refusals_dedupe_caps_and_expectations(tmp_path: Path) -> None:
    make_snapshot(tmp_path)
    policy = make_policy(tmp_path, max_requests_per_run=2, max_wall_s=100)
    popen = ScriptedPopen({"rev-parse": b"f" * 40 + b"\n"}, returncode=0)
    now = {"t": 0.0}
    env = make_env(tmp_path, tmp_path / "snap", popen, policy)
    env.clock = lambda: now["t"]
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    state = RequestState(started_monotonic=0.0)
    requests = [
        EvidenceRequest(argv=["git", "rev-parse", "HEAD"], expect_exit_code=0),
        EvidenceRequest(argv=["git", "rev-parse", "HEAD"]),  # duplicate (canonical argv)
        EvidenceRequest(argv=["pytest", "-q"], rationale="run the suite"),  # not allowlisted
        EvidenceRequest(argv=["git", "log", "--oneline", "-n", "5"], expect_exit_code=3),
        EvidenceRequest(argv=["git", "status", "--porcelain"]),  # over the per-run cap
    ]
    items = execute_evidence_requests(
        requests,
        source="P1",
        env=env,
        writer=w,
        state=state,
        task_id="t_01",
        stop_check=lambda: False,
    )
    assert len(items) == 2 and state.count == 2 and len(popen.calls) == 2
    assert items[0].kind is EvidenceKind.TOOL_OUTPUT and items[0].phase is Phase.VERIFICATION
    assert items[0].origin is Origin.MECHANICALLY_OBSERVED and items[0].exit_code == 0
    assert items[0].summary == "P1: exit 0"
    assert items[1].summary == "P1: exit 0; expected 3"  # recorded, never overwritten
    assert items[0].argv is not None and items[0].argv[1:] == [
        "--no-optional-locks",
        "rev-parse",
        "HEAD",
    ]
    kinds = [e["kind"] for e in events(w)]
    assert kinds == [
        "evidence.item",
        "verify.duplicate",
        "verify.refused",
        "evidence.item",
        "verify.refused",
    ]
    payloads = [e["payload"] for e in events(w)]
    assert payloads[1]["evidence_id"] == items[0].evidence_id and payloads[1]["source"] == "P1"
    assert "not allowlisted" in payloads[2]["reason"] and payloads[2]["argv"] == ["pytest", "-q"]
    assert "max_requests_per_run (2)" in payloads[4]["reason"]
    # wall budget: a later request after max_wall_s is refused without spawning
    now["t"] = 500.0  # past max_wall_s
    state2 = RequestState(started_monotonic=0.0, count=0)
    more = execute_evidence_requests(
        [EvidenceRequest(argv=["git", "ls-files"])],
        source="C1",
        env=env,
        writer=w,
        state=state2,
        task_id="t_01",
        stop_check=lambda: False,
    )
    assert more == [] and len(popen.calls) == 2
    assert "max_wall_s (100) exceeded" in events(w)[-1]["payload"]["reason"]
    w.close()


def test_evidence_requests_stop_before_a_command(tmp_path: Path) -> None:
    make_snapshot(tmp_path)
    popen = ScriptedPopen()
    env = make_env(tmp_path, tmp_path / "snap", popen, make_policy(tmp_path))
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    flags = iter([False, True])
    with pytest.raises(EvidenceStopped):
        execute_evidence_requests(
            [
                EvidenceRequest(argv=["git", "ls-files"]),
                EvidenceRequest(argv=["git", "status", "--porcelain"]),
            ],
            source="P2",
            env=env,
            writer=w,
            state=RequestState(),
            task_id="t_01",
            stop_check=lambda: next(flags),
        )
    w.close()
    assert len(popen.calls) == 1  # the first ran, the second never spawned
    ev = events(w)
    assert ev[-1]["kind"] == "verify.stopped" and ev[-1]["payload"]["source"] == "P2"


def test_evidence_requests_run_on_the_original_snapshot(tmp_path: Path) -> None:
    original = make_snapshot(tmp_path)
    copy = tmp_path / "scratch" / "sanitized-grok"
    sanitize_snapshot(original, copy, profile=SanitizeProfile.from_policy(None), worker_id="grok")
    popen = ScriptedPopen()
    env = make_env(tmp_path, original, popen, make_policy(tmp_path))
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    execute_evidence_requests(
        [EvidenceRequest(argv=["git", "ls-files"])],
        source="C1",
        env=env,
        writer=w,
        state=RequestState(),
        task_id="t_01",
        stop_check=lambda: False,
    )
    w.close()
    assert popen.calls[0][1]["cwd"] == str(original.resolve())


def test_verification_guard_trips_on_a_changed_copy_and_stops_verification(
    tmp_path: Path,
) -> None:
    """Item 4: a command that changes the verification copy is recorded
    (snapshot.violated, item.violated) and every later command is refused."""
    from eris.evidence import SnapshotGuard
    from eris.sanitize import VERIFICATION_PROFILE, sanitize_snapshot, tree_sha256

    original = make_snapshot(tmp_path)
    before = tree_sha256(original)
    copy = tmp_path / "scratch" / "pristine"
    sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")

    class WritingPopen(ScriptedPopen):
        def __call__(self, args: Any, **kw: Any) -> FakeProcess:
            proc = super().__call__(args, **kw)
            if "ls-files" in [os.fsdecode(a) for a in args]:
                Path(kw["cwd"], "PLANTED").write_text("changed")  # a command that writes
            return proc

    popen = WritingPopen()
    env = make_env(tmp_path, copy, popen, make_policy(tmp_path))
    env.guard = SnapshotGuard.over(copy)
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    items = execute_evidence_requests(
        [
            EvidenceRequest(argv=["git", "status", "--porcelain"]),
            EvidenceRequest(argv=["git", "ls-files"]),
            EvidenceRequest(argv=["git", "rev-parse", "HEAD"]),
        ],
        source="P1",
        env=env,
        writer=w,
        state=RequestState(),
        task_id="t_01",
        stop_check=lambda: False,
    )
    w.close()
    assert [i.violated for i in items] == [False, True]
    assert "VIOLATED" in items[1].summary and env.violated
    ev = events(w)
    kinds = [e["kind"] for e in ev]
    assert "snapshot.violated" in kinds
    violated = next(e["payload"] for e in ev if e["kind"] == "snapshot.violated")
    assert violated["tree_sha256_before"] != violated["tree_sha256_after"]
    refused = [e["payload"] for e in ev if e["kind"] == "verify.refused"]
    assert len(refused) == 1 and "verification is stopped" in refused[0]["reason"]
    assert len(popen.calls) == 2  # the third command never spawned
    assert tree_sha256(original) == before  # the ORIGINAL is untouched
    assert all(kw["cwd"] == str(copy.resolve()) for _a, kw in popen.calls)


def test_the_guard_excluded_set_is_exactly_the_git_index(tmp_path: Path) -> None:
    """M2c defect B: the tripwire ignores git's stat cache and NOTHING else.
    Widening this set is how a verification command gets to rewrite refs,
    objects or config unnoticed - pin it."""
    from eris.evidence import GUARD_EXCLUDED_RELPATHS, _guard_skip

    assert GUARD_EXCLUDED_RELPATHS == {".git/index", ".git/index.lock"}
    assert _guard_skip(PurePosixPath(".git/index"))
    assert _guard_skip(PurePosixPath(".git/index.lock"))
    # near misses are NOT excluded: only the two names, only at the root .git
    for rel in (
        ".git",
        ".git/index2",
        ".git/HEAD",
        ".git/config",
        ".git/refs/heads/main",
        "index",
        "sub/.git/index",
    ):
        assert not _guard_skip(PurePosixPath(rel)), rel


@pytest.mark.parametrize(
    ("written", "trips"),
    [
        ("PLANTED", True),  # a tracked working-tree file
        (".git/refs/heads/main", True),  # history: must still be caught
        (".git/config", True),
        (".git/objects/ab/cdef0123", True),  # a new object
        (".git/HEAD", True),  # the current branch
        (".git/hooks/pre-commit", True),  # code that would run on the next git
        (".git/index", False),  # git's stat cache: the ONLY tolerated write
        (".git/index.lock", False),  # the file it writes the stat cache through
    ],
)
def test_the_guard_still_trips_on_everything_but_the_git_index(
    tmp_path: Path, written: str, trips: bool
) -> None:
    """M2c defect B: narrowing the tripwire must not blind it. `.git` is NOT
    excluded wholesale - a command that rewrites refs or config is a
    violation exactly as before."""
    from eris.evidence import SnapshotGuard

    root = make_snapshot(tmp_path)
    # a WORKING semantic index check: that is what licenses the byte exclusion
    guard = SnapshotGuard.over(root, probe=FakeIndexProbe())
    target = root / written
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("changed by a verification command\n")
    assert (guard.changed() is not None) is trips


class FakeIndexProbe:
    """Stands in for `git ls-files --stage`. The hermetic suite may not spawn
    git, so the STAGED CONTENT is whatever this holder says it is; rewriting
    ``digest`` is a staging change, leaving it alone is a stat refresh."""

    def __init__(self, digest: str | None = "stage-0") -> None:
        self.digest = digest
        self.calls = 0

    def __call__(self, root: Path) -> str | None:
        self.calls += 1
        return self.digest


def test_the_guard_trips_on_a_changed_index_digest_but_not_on_a_stat_refresh(
    tmp_path: Path,
) -> None:
    """M2c item 1: `.git/index` is excluded BY BYTES because a read-only git
    rewrites it, and covered SEMANTICALLY so a staging change is still seen."""
    from eris.evidence import INDEX_CHECK_SEMANTIC, SnapshotGuard

    root = make_snapshot(tmp_path)
    probe = FakeIndexProbe()
    guard = SnapshotGuard.over(root, probe=probe)
    assert guard.index_check == INDEX_CHECK_SEMANTIC and guard.index_digest == "stage-0"

    (root / ".git" / "index").write_bytes(b"a refreshed stat cache")  # legitimate churn
    assert guard.changed() is None

    probe.digest = "stage-1"  # the staged content itself moved (git add / rm --cached)
    change = guard.changed()
    assert change is not None
    assert change.reason == "git_index" and change.index_digest_after == "stage-1"


def test_an_index_change_that_also_moves_the_tree_is_reported_as_git_index(
    tmp_path: Path,
) -> None:
    """`git add` writes a loose object AND stages it, so both halves move.
    The reason must name the index: it is the specific, security-relevant
    half, and `test_verify_real_git.py` asserts exactly that against a real
    `git add`."""
    from eris.evidence import SnapshotGuard

    root = make_snapshot(tmp_path)
    probe = FakeIndexProbe()
    guard = SnapshotGuard.over(root, probe=probe)
    obj = root / ".git" / "objects" / "ab" / "cdef0123"
    obj.parent.mkdir(parents=True)
    obj.write_bytes(b"a new loose object")
    probe.digest = "stage-1"
    change = guard.changed()
    assert change is not None and change.reason == "git_index"


def test_a_guard_without_a_usable_git_falls_back_to_hashing_the_index_bytes(
    tmp_path: Path,
) -> None:
    """M2c item 2: FAIL CLOSED. No semantic digest means the byte exclusion is
    dropped for that run - never a silently skipped check."""
    from eris.evidence import INDEX_CHECK_BYTES_FALLBACK, SnapshotGuard

    root = make_snapshot(tmp_path)
    (root / ".git" / "index").write_bytes(b"stat cache v1")
    for guard in (
        SnapshotGuard.over(root),  # no probe at all
        SnapshotGuard.over(root, probe=FakeIndexProbe(None)),  # git unavailable/failed
    ):
        assert guard.index_check == INDEX_CHECK_BYTES_FALLBACK and guard.index_digest is None
        assert guard.changed() is None
        (root / ".git" / "index").write_bytes(b"stat cache v2")
        change = guard.changed()
        assert change is not None and change.reason == "tree"  # the bytes ARE hashed now
        (root / ".git" / "index").write_bytes(b"stat cache v1")


def test_a_probe_that_stops_working_mid_run_trips_the_guard(tmp_path: Path) -> None:
    """Fail closed the other way too: a digest that can no longer be taken is
    a change, not a pass."""
    from eris.evidence import SnapshotGuard

    root = make_snapshot(tmp_path)
    probe = FakeIndexProbe()
    guard = SnapshotGuard.over(root, probe=probe)
    probe.digest = None
    change = guard.changed()
    assert change is not None and change.reason == "git_index"
    assert change.index_digest_after is None


def test_a_copy_without_a_git_directory_needs_no_index_check(tmp_path: Path) -> None:
    """M2c item 1: the digest is taken only when the copy has a `.git` dir -
    there is no index to guard otherwise, and no fallback to justify."""
    from eris.evidence import INDEX_CHECK_NONE, SnapshotGuard

    root = make_snapshot(tmp_path)
    shutil.rmtree(root / ".git")
    probe = FakeIndexProbe()
    guard = SnapshotGuard.over(root, probe=probe)
    assert guard.index_check == INDEX_CHECK_NONE and guard.probe is None and probe.calls == 0
    assert guard.changed() is None
    (root / "PLANTED").write_text("x")
    change = guard.changed()
    assert change is not None and change.reason == "tree"


def test_the_index_digest_runs_the_pinned_git_and_never_the_model_allowlist(
    tmp_path: Path,
) -> None:
    """M2c item 4: fixed Eris-internal argv on the POLICY-PINNED git with the
    Eris git globals - and deliberately NOT through `check_command`, which
    refuses `--stage` (it is not an allowlisted flag)."""
    from eris.evidence import GIT_ERIS_GLOBALS, GIT_INDEX_DIGEST_ARGS, git_index_prober
    from eris.verify import check_command

    root = make_snapshot(tmp_path)
    policy = make_policy(tmp_path)
    popen = ScriptedPopen({"ls-files": b"100644 abc 0\tcalc.py\n"})
    digest = git_index_prober(policy, tmp_path / "probe-home", popen=popen, killpg=lambda *_: None)(
        root
    )
    assert GIT_INDEX_DIGEST_ARGS == (*GIT_ERIS_GLOBALS, "ls-files", "--stage")
    argv, kw = popen.calls[0]
    assert argv == [
        str(Path(policy.verify.commands["git"].executable).resolve()),
        "--no-optional-locks",
        "ls-files",
        "--stage",
    ]
    assert kw["cwd"] == str(root.resolve())
    assert digest == hashlib.sha256(b"100644 abc 0\tcalc.py\n").hexdigest()
    # the same argv as a MODEL request would be refused - hence "not the allowlist"
    assert not check_command(["git", "ls-files", "--stage"], policy, root).allowed


@pytest.mark.parametrize("why", ["unpinned", "swapped-since-the-pin", "missing"])
def test_the_index_prober_refuses_an_unpinned_or_changed_git(tmp_path: Path, why: str) -> None:
    """M2c item 1: POLICY-PINNED. An unpinned, swapped or missing git yields
    no digest (and is never spawned), which the guard turns into
    `bytes_fallback`."""
    from eris.evidence import INDEX_CHECK_BYTES_FALLBACK, SnapshotGuard, git_index_prober

    root = make_snapshot(tmp_path)
    policy = make_policy(tmp_path, pinned=why != "unpinned")
    if why == "swapped-since-the-pin":
        (tmp_path / "bin" / "git").write_bytes(b"#!/bin/sh\n# swapped\n")
    if why == "missing":
        (tmp_path / "bin" / "git").unlink()
    popen = ScriptedPopen()
    probe = git_index_prober(policy, tmp_path / "probe-home", popen=popen, killpg=lambda *_: None)
    assert probe(root) is None, why
    assert popen.calls == []
    assert SnapshotGuard.over(root, probe=probe).index_check == INDEX_CHECK_BYTES_FALLBACK


@pytest.mark.parametrize("failure", ["exit-code", "truncated-output", "spawn-raises"])
def test_the_index_prober_yields_nothing_when_the_digest_command_fails(
    tmp_path: Path, failure: str
) -> None:
    """A non-zero `ls-files --stage` (not a repository, broken index), output
    the cap truncated, or a spawn that raises, is a failure to CHECK - never a
    digest that would compare equal on the next call."""
    from eris.evidence import git_index_prober

    root = make_snapshot(tmp_path)
    policy = make_policy(tmp_path, max_output_bytes=8)
    popen: Any = ScriptedPopen(returncode=128 if failure == "exit-code" else 0)
    if failure == "truncated-output":
        popen = ScriptedPopen({"ls-files": b"x" * 4096})
    if failure == "spawn-raises":

        def popen(*_a: Any, **_kw: Any) -> Any:
            raise OSError("no such executable")

    probe = git_index_prober(policy, tmp_path / "probe-home", popen=popen, killpg=lambda *_: None)
    assert probe(root) is None


def test_snapshot_violated_names_the_half_that_moved_and_records_both_digests(
    tmp_path: Path,
) -> None:
    """M2c item 1: the event says WHICH tripwire moved (`reason`), how the
    index was checked (`index_check`), and carries both digests."""
    from eris.evidence import SnapshotGuard
    from eris.sanitize import VERIFICATION_PROFILE

    original = make_snapshot(tmp_path)
    copy = tmp_path / "scratch" / "pristine"
    sanitize_snapshot(original, copy, profile=VERIFICATION_PROFILE, worker_id="verify")
    probe = FakeIndexProbe()

    class StagingPopen(ScriptedPopen):
        def __call__(self, args: Any, **kw: Any) -> FakeProcess:
            proc = super().__call__(args, **kw)
            if "ls-files" in [os.fsdecode(a) for a in args]:
                probe.digest = "stage-1"  # the command staged something
            return proc

    popen = StagingPopen()
    env = make_env(tmp_path, copy, popen, make_policy(tmp_path))
    env.guard = SnapshotGuard.over(copy, probe=probe)
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    items = execute_evidence_requests(
        [
            EvidenceRequest(argv=["git", "ls-files"]),
            EvidenceRequest(argv=["git", "rev-parse", "H"]),
        ],
        source="P1",
        env=env,
        writer=w,
        state=RequestState(),
        task_id="t_01",
        stop_check=lambda: False,
    )
    w.close()
    assert [i.violated for i in items] == [True]
    payload = next(e["payload"] for e in events(w) if e["kind"] == "snapshot.violated")
    assert payload["reason"] == "git_index"
    assert payload["index_check"] == "semantic"
    assert payload["git_index_digest_before"] == "stage-0"
    assert payload["git_index_digest_after"] == "stage-1"
    assert payload["tree_sha256_before"] == payload["tree_sha256_after"]  # only the index moved
    assert len(popen.calls) == 1  # the second command never spawned


def test_request_key_ignores_the_options_eris_appends(tmp_path: Path) -> None:
    """M2c defect B: the dedupe key must survive Eris's own git globals, or a
    RESUMED run re-executes every request it already executed (the recorded
    argv carries them, the freshly validated one does too, but a key built
    from either must match)."""
    from eris.evidence import request_key
    from eris.verify import GIT_ERIS_GLOBALS

    validated = ["/usr/bin/git", "ls-files"]
    recorded = ["/opt/homebrew/bin/git", *GIT_ERIS_GLOBALS, "ls-files"]
    assert request_key(recorded) == request_key(validated)
    assert request_key(["git", "log"]) != request_key(["git", "ls-files"])


def test_a_model_supplied_eris_global_is_refused_not_deduped(tmp_path: Path) -> None:
    """M2c follow-up: `request_key` strips the options Eris appends, so keying
    a RAW request would let `git --no-optional-locks ls-files` alias an
    already-executed `git ls-files` and come back as `verify.duplicate` - a
    hard-denied option quietly becoming a no-op. The grammar therefore runs
    BEFORE the key is computed: the request is REFUSED, and the legitimate
    repeat right after it is still deduped."""
    make_snapshot(tmp_path)
    policy = make_policy(tmp_path)
    popen = ScriptedPopen()
    env = make_env(tmp_path, tmp_path / "snap", popen, policy)
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    items = execute_evidence_requests(
        [
            EvidenceRequest(argv=["git", "ls-files"]),
            EvidenceRequest(argv=["git", "--no-optional-locks", "ls-files"]),
            EvidenceRequest(argv=["git", "ls-files", "--no-optional-locks"]),
            EvidenceRequest(argv=["git", "ls-files"]),  # the legitimate repeat
        ],
        source="P1",
        env=env,
        writer=w,
        state=RequestState(),
        task_id="t_01",
        stop_check=lambda: False,
    )
    w.close()
    ev = events(w)
    kinds = [e["kind"] for e in ev]
    assert len(items) == 1 and len(popen.calls) == 1  # only the first request ran
    refused = [e["payload"] for e in ev if e["kind"] == "verify.refused"]
    assert len(refused) == 2, refused
    assert [r["argv"][1:] for r in refused] == [
        ["--no-optional-locks", "ls-files"],
        ["ls-files", "--no-optional-locks"],
    ]
    assert "hard-denied" in refused[1]["reason"]
    # and the honest repeat is still a duplicate, not a re-spawn
    assert kinds.count("verify.duplicate") == 1


def test_pytest_commands_carry_no_cacheprovider(tmp_path: Path) -> None:
    """Item 4: every pytest invocation gets `-p no:cacheprovider` appended
    (and re-checked by the allowlist)."""
    pytest_exe = tmp_path / "bin" / "pytest"
    pytest_exe.parent.mkdir(exist_ok=True)
    pytest_exe.write_bytes(b"#!/bin/sh\n")
    base = make_policy(tmp_path)
    policy = Policy.model_validate(
        {
            **base.model_dump(mode="json"),
            "trusted": True,
            "verify": {
                **base.verify.model_dump(mode="json"),
                "commands": {
                    **{k: v.model_dump(mode="json") for k, v in base.verify.commands.items()},
                    "pytest": {
                        "executable": str(pytest_exe),
                        "executable_sha256": hashlib.sha256(pytest_exe.read_bytes()).hexdigest(),
                        "requires_trusted": True,
                        "literal_flags": ["-q"],
                        "value_flags": {"-p": "^no:[A-Za-z0-9_]+$"},
                        "positional": ["path"],
                        "timeout_s": 5,
                    },
                },
            },
        }
    )
    snapshot = make_snapshot(tmp_path)
    popen = ScriptedPopen()
    env = make_env(tmp_path, snapshot, popen, policy)
    out = env.run(["pytest", "-q"])
    assert out.argv[1:] == ["-q", "-p", "no:cacheprovider"]
    assert popen.calls[0][0][1:] == ["-q", "-p", "no:cacheprovider"]
    out = env.run(["pytest", "-p", "no:cacheprovider", "-q"])
    assert out.argv.count("no:cacheprovider") == 1


def test_verify_scratch_is_private_removed_and_cleanup_failure_is_a_run_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    with verify_scratch(w, tmp_path / "scratch") as home:
        assert home == tmp_path / "scratch" / "verify" and home.is_dir()
        (home / "x").write_text("tmp")
    assert not home.exists()
    # a planted symlink is refused (make_private_dir semantics)
    (tmp_path / "scratch").mkdir(exist_ok=True)
    (tmp_path / "scratch" / "verify").symlink_to(tmp_path / "elsewhere")
    from eris.launch import LaunchRefused

    with pytest.raises(LaunchRefused):
        with verify_scratch(w, tmp_path / "scratch"):
            pass
    (tmp_path / "scratch" / "verify").unlink()
    real = shutil.rmtree

    def broken(path: object, *a: object, **k: object) -> None:
        raise OSError("EBUSY")

    monkeypatch.setattr(shutil, "rmtree", broken)
    with pytest.raises(EvidenceCleanupError):
        with verify_scratch(w, tmp_path / "scratch"):
            pass
    monkeypatch.setattr(shutil, "rmtree", real)
    ev = events(w)
    assert ev[-1]["kind"] == "run.error"
    assert ev[-1]["payload"]["kind"] == "verify_scratch_cleanup_failed"
    w.close()
