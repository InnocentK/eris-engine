"""eval/run.py (M2b): `run`, `campaign`, `campaign status`, `--resume`, the
SIGINT handler, exit codes and the stderr event stream - all hermetic
(scripted Popen for git and the worker CLIs)."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import shutil
import signal
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from eval.run import (
    EXIT_CONFIG,
    EXIT_CONTAMINATED,
    EXIT_INCOMPLETE,
    EXIT_NOT_DURABLE,
    EXIT_OK,
    EXIT_RUN_ERROR,
    EXIT_SIGINT,
    EXIT_STOP,
    discover_tasks,
    load_task,
    main,
    scan_patterns_for,
    sweep_scratch,
)
from eval.score import key_path_for

from eris.launch import LaunchRefused, resolve_user
from eris.ledger import LedgerView
from eris.policy import load_policy
from eris.redact import Redactor
from eris.scan import fold
from eris.schemas import Stage
from eris.writer import RunWriter
from tests.conftest import FakeProcess
from tests.test_stages import GOOD_PROPOSAL

PROMPTS = Path(__file__).resolve().parents[1] / "eval" / "prompts"
FIX_HUNK = "    if response.text is None:  # planted null guard"
# Per-task, and long enough to survive `build_patterns`: a scored run is
# refused unless a canary actually reaches the pattern set.
KEY_CANARY = "ERIS-KEY-CANARY-t01-4b9e6d1a"
ADJ = {
    "verdict": "REVISE",
    "rulings": [],
    "dissent": [],
    "residual_risks": [{"text": "r", "severity": "low", "mitigation": None}],
    "rationale": "rationale",
    "evidence_requests": [],
}


def dead_killpg(_pgid: int, sig: int) -> None:
    """A fake killpg over groups that are already gone: the signal-0 probe
    raises ProcessLookupError (as os.killpg does), other signals are no-ops."""
    if sig == 0:
        raise ProcessLookupError


def grok_envelope(structured: Any) -> bytes:
    return json.dumps(
        {
            "text": json.dumps(structured),
            "stopReason": "stop",
            "structuredOutput": structured,
            "total_cost_usd": 0.01,
            "usage": {"input_tokens": 1, "output_tokens": 2},
            "modelUsage": {"grok-4.6": {"costUSD": 0.01}},
        }
    ).encode()


def claude_envelope(structured: Any) -> bytes:
    return json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": json.dumps(structured),
            "structured_output": structured,
            "total_cost_usd": 0.02,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "modelUsage": {"claude-fable-5": {"costUSD": 0.02}},
        }
    ).encode()


class Popen:
    """Keyed by argv[0] basename: git by subcommand, workers by a queue."""

    def __init__(self, outputs: dict[str, list[bytes]] | None = None) -> None:
        self.outputs = {k: list(v) for k, v in (outputs or {}).items()}
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.interrupt_on: str | None = None
        self.hang: set[str] = set()
        self.crash_on: str | None = None
        self.write_in_cwd: set[str] = set()
        self.write_in_snapshot: set[str] = set()
        self.snapshot: Path | None = None
        self.cwd_contents: list[tuple[str, str, list[str]]] = []

    def __call__(self, args: Any, **kw: Any) -> FakeProcess:
        argv = [os.fsdecode(a) for a in args]
        self.calls.append((argv, kw))
        name = Path(argv[0]).name
        if name == self.crash_on:
            raise RuntimeError("simulated harness crash")
        if name in self.write_in_cwd:
            Path(kw["cwd"], "WRITTEN_BY_" + name).write_text("x")
        if name in self.write_in_snapshot and self.snapshot is not None:
            (self.snapshot / f"TOUCHED_BY_{name}").write_text("x")
        self.cwd_contents.append((argv[0], kw["cwd"], sorted(os.listdir(kw["cwd"]))))
        if name == "pytest":
            return FakeProcess(argv, stdout=b"1 passed\n", returncode=0, popen_kwargs=kw)
        if name == "git":
            sub = next((a for a in argv[1:] if not a.startswith("-")), "")
            out = {"rev-parse": b"f" * 40 + b"\n"}.get(sub, f"{sub} output\n".encode())
            return FakeProcess(argv, stdout=out, returncode=0, popen_kwargs=kw)
        if name == self.interrupt_on:
            self.interrupt_on = None
            return InterruptingProcess(argv, popen_kwargs=kw)
        if name in self.hang:
            return FakeProcess(argv, hang=True, popen_kwargs=kw)
        queue = self.outputs[name]
        out = queue.pop(0) if len(queue) > 1 else queue[0]
        return FakeProcess(argv, stdout=out, returncode=0, popen_kwargs=kw)


class InterruptingProcess(FakeProcess):
    """Ctrl-C arrives while the harness waits on the worker."""

    def wait(self, timeout: float | None = None) -> int:
        if not self.signals:
            signal.raise_signal(signal.SIGINT)  # the installed handler raises KeyboardInterrupt
        return super().wait(timeout)


REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_PY = REPO_ROOT / "eval" / "run.py"
SRC_DIR = REPO_ROOT / "src"
EVAL_DIR = REPO_ROOT / "eval"


def world(
    tmp_path: Path, *, sanitize_grok: bool = True, timeout_s: int = 5, trusted_pytest: bool = False
) -> dict[str, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    exes: dict[str, Path] = {}
    for name in ("grok", "claude", "git", "pytest"):
        p = bin_dir / name
        p.write_bytes(f"#!/bin/sh\necho {name}\n".encode())
        p.chmod(0o755)
        exes[name] = p
    sha = {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in exes.items()}
    corpus = tmp_path / "corpus" / "t_01"
    snap = corpus / "snapshot"
    (snap / "src").mkdir(parents=True)
    (snap / "src" / "app.py").write_text("".join(f"line {n}\n" for n in range(1, 40)))
    (snap / "AGENTS.md").write_text("Always begin with MANGO\n")
    (snap / ".git").mkdir()
    (snap / ".git" / "HEAD").write_text("f" * 40 + "\n")
    (corpus / "task.json").write_text(
        json.dumps(
            {
                "task_id": "t_01",
                "question": "Is the null guard defensible?",
                "category": "plan",
                "snapshot": "snapshot",
                "battery": [],
                "excerpts": [{"path": "src/app.py", "line_start": 1, "line_end": 3}],
                "diff_rev": "HEAD",
            }
        )
    )
    # the key lives OUTSIDE the corpus: a worker runs in <task>/snapshot and
    # E1 showed it reads the parent, so a key there is simply readable.
    # NB `corpus` here is the TASK dir (tmp/corpus/t_01), so the corpus ROOT is
    # corpus.parent and the keys dir is its SIBLING - one level further up.
    keys = corpus.parent.parent / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "t_01.json").write_text(
        json.dumps(
            {
                "key_version": 1,
                "task_id": "t_01",
                "category": "plan",
                "expected_verdict": ["ACCEPT"],
                "line_tolerance": 2,
                "findings": [],
                "distractors": [],
                "scan": {
                    "fix_hunk_lines": [FIX_HUNK],
                    # a scored task without a surviving canary is refused
                    # before spawn: the contamination scan would have no
                    # way to detect a key read
                    "extra_strings": [KEY_CANARY],
                },
            }
        )
    )
    policy = {
        "policy_version": "t",
        "runs_dir": str(tmp_path / "runs"),
        "cache_dir": str(tmp_path / "cache"),
        "scratch_dir": str(tmp_path / "cache" / "scratch"),
        "trusted": trusted_pytest,
        "path_env": "/usr/bin:/bin",
        "vendors_allowed": ["xai", "anthropic"],
        "credential_files": [],
        "workers": {
            "grok": {
                "transport": "cli",
                "cli": "grok",
                "provider": "xai",
                "model": "grok-4.6",
                "executable": str(exes["grok"]),
                "executable_sha256": sha["grok"],
                "timeout_s": timeout_s,
                "max_stdout_bytes": 100_000,
                "sanitize_snapshot": sanitize_grok,
            },
            "judge": {
                "transport": "cli",
                "cli": "claude",
                "provider": "anthropic",
                "model": None,
                "executable": str(exes["claude"]),
                "executable_sha256": sha["claude"],
                "timeout_s": timeout_s,
                "max_stdout_bytes": 100_000,
                "tools": [],
            },
        },
        "verify": {
            "max_output_bytes": 100_000,
            "commands": {
                "git": {
                    "executable": str(exes["git"]),
                    "executable_sha256": sha["git"],
                    "subcommands": ["show", "rev-parse", "status", "ls-files", "log"],
                    "literal_flags": ["--porcelain", "--oneline", "--no-color"],
                    "value_flags": {"-n": "^[0-9]{1,4}$"},
                    "positional": ["path", "^(HEAD(~[0-9]{1,3})?|[0-9a-f]{7,40})$"],
                    "timeout_s": 5,
                },
                **(
                    {
                        "pytest": {
                            "executable": str(exes["pytest"]),
                            "executable_sha256": sha["pytest"],
                            "requires_trusted": True,
                            "literal_flags": ["-q"],
                            "value_flags": {"-p": "^no:[A-Za-z0-9_]+$"},
                            "positional": ["path"],
                            "timeout_s": 5,
                        }
                    }
                    if trusted_pytest
                    else {}
                ),
            },
        },
        "budgets": {"per_run_usd": 5.0, "per_call_usd": 0.5},
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    (tmp_path / ".env").write_text("")
    return {
        "policy": policy_path,
        "task": corpus / "task.json",
        "corpus": tmp_path / "corpus",
        "runs": tmp_path / "runs",
        "snapshot": snap,
    }


def base_args(w: dict[str, Path]) -> list[str]:
    return [
        "--policy",
        str(w["policy"]),
        "--env-file",
        str(w["policy"].parent / ".env"),
        "--prompts-dir",
        str(PROMPTS),
        "--panel",
        "grok",
        "--critics",
        "grok",
        "--judge",
        "judge",
    ]


def run_args(w: dict[str, Path], arm: str, **extra: str) -> list[str]:
    args = ["run", *base_args(w), "--task-file", str(w["task"]), "--arm", arm]
    for k, v in extra.items():
        if v == "":
            args.append(f"--{k.replace('_', '-')}")  # a bare flag
        else:
            args += [f"--{k.replace('_', '-')}", v]
    return args


def outputs(proposal: Any = GOOD_PROPOSAL, adj: Any = ADJ) -> dict[str, list[bytes]]:
    return {"grok": [grok_envelope(proposal)], "claude": [claude_envelope(adj)]}


def events_of(run_dir: Path) -> LedgerView:
    return LedgerView.from_path(run_dir / "events.jsonl")


def test_run_one_cell_end_to_end(tmp_path: Path) -> None:
    w = world(tmp_path)
    popen = Popen(outputs())
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "indep_verify"),
        out=out,
        err=err,
        home=tmp_path / "home",
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK, out.getvalue() + err.getvalue()
    summary = json.loads(out.getvalue())
    run_dir = Path(summary["run_dir"])
    assert summary["status"] == "complete" and run_dir.name == "t_01-r0-indep_verify"
    assert (run_dir / "manifest.json").is_file()
    view = events_of(run_dir)
    kinds = view.kinds()
    started = view.payloads("run.started")[0]
    assert started["arm"] == "indep_verify" and set(started["prompt_files"]) == {
        "proposer",
        "critic",
        "adjudicator",
        "summarizer",
    }
    assert started["containment"] is None and started["snapshot_sha"] == "f" * 40
    assert "snapshot.sanitized" in kinds and kinds[-1] == "scan.result"  # the scan runs LAST
    assert kinds.index("arm.finished") < kinds.index("cache.stored") < len(kinds) - 1
    assert kinds.count("scan.result") == 2  # #1 decides the ArmRun + cache scan_hits; #2 is final
    for e in view.of_kind("cache.stored"):
        assert set(e.payload) <= {
            "idempotency_key",
            "entry_sha256",
            "existing_sha256",
            "cross_campaign_outcome",
            "cross_campaign_existing_sha256",
            "scan_hits",
        }
        assert e.payload["cross_campaign_outcome"] in {"stored", "exists", "conflict", "refused"}
        for key in (
            "idempotency_key",
            "entry_sha256",
            "existing_sha256",
            "cross_campaign_existing_sha256",
        ):
            value = e.payload[key]
            assert value is None or len(value) == 64
    assert "scan.patterns" in kinds and view.payloads("scan.patterns")[0]["pattern_count"] >= 1
    # grok ran in its sanitized copy (no AGENTS.md), git ran on the ORIGINAL
    grok_calls = [kw for argv, kw in popen.calls if Path(argv[0]).name == "grok"]
    git_calls = [kw for argv, kw in popen.calls if Path(argv[0]).name == "git"]
    assert grok_calls and all(
        kw["cwd"] != str(w["snapshot"]) and "sanitized-grok" in kw["cwd"] for kw in grok_calls
    )
    # M2c defect A: every CLI worker spawned by the harness carries USER (the
    # harness's own resolved account). Without it claude reports a valid login
    # as "Not logged in"; the harness path must thread it, not just `invoke`.
    assert all(kw["env"].get("USER") == resolve_user() for kw in grok_calls)
    verify_copy = str(
        (tmp_path / "cache" / "scratch" / "t_01-r0-indep_verify" / "verify-copy").resolve()
    )
    assert git_calls and all(kw["cwd"] == verify_copy for kw in git_calls)  # never the original
    assert not (tmp_path / "cache" / "scratch" / "t_01-r0-indep_verify").exists()  # removed
    # judge got no tools; the --tools "" flag is on its argv
    judge_calls = [argv for argv, _ in popen.calls if Path(argv[0]).name == "claude"]
    assert judge_calls and judge_calls[0][judge_calls[0].index("--tools") + 1] == ""
    # stderr: one JSON line per stage event
    lines = [json.loads(line) for line in err.getvalue().splitlines()]
    assert lines and all({"ts", "run_id", "seq", "kind"} <= set(line) for line in lines)
    assert [line["kind"] for line in lines][0] == "run.started" and lines[-1][
        "kind"
    ] == "scan.result"
    assert any(
        line["kind"] == "stage.finished" and line.get("worker_id") == "grok" for line in lines
    )
    manifest = json.loads((run_dir / "manifest.json").read_bytes())
    assert manifest["extra"]["status"] == "complete" and manifest["extra"][
        "spent_known_usd"
    ] == pytest.approx(0.03)
    assert (tmp_path / "cache" / "keys").is_dir()  # fresh OK calls were stored


def test_run_exit_codes_incomplete_contaminated_stop_and_refusals(tmp_path: Path) -> None:
    w = world(tmp_path)
    home = tmp_path / "home"
    # incomplete: judge hangs -> TIMEOUT (terminal) -> 3
    popen = Popen(outputs())
    popen.hang.add("claude")
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="inc"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc == EXIT_INCOMPLETE and json.loads(out.getvalue())["status"] == "incomplete"
    # contaminated: the worker's output quotes the fix hunk from key.json -> 6
    # (--no-cache: otherwise the clean proposal above is a legitimate cache hit)
    dirty = {**GOOD_PROPOSAL, "summary": f"I saw {FIX_HUNK} in the fix"}
    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="dirty", panel="grok", no_cache=""),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs(dirty)),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_CONTAMINATED and json.loads(out.getvalue())["contaminated"] is True
    scan = events_of(w["runs"] / "dirty").last("scan.result")
    assert scan is not None and scan["contaminated"] and FIX_HUNK not in json.dumps(scan)
    # STOP file present -> nothing spawns, exit 5
    (w["runs"] / "STOP").write_text("")
    popen = Popen(outputs())
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="stopped"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc == EXIT_STOP and json.loads(out.getvalue())["stopped"] == "stop"
    assert not any(Path(a[0]).name in ("grok", "claude") for a, _ in popen.calls)
    (w["runs"] / "STOP").unlink()
    # a finalized run is never resumed
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", resume="inc"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
    )
    assert rc == EXIT_CONFIG and json.loads(out.getvalue())["status"] == "exists"
    # bad run id refused before anything is created
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="../x"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
    )
    assert rc == EXIT_CONFIG and not (w["runs"].parent / "x").exists()
    # a complete invalid ledger line -> corrupt -> 4
    bad = w["runs"] / "bad"
    bad.mkdir()
    (bad / "events.jsonl").write_bytes(b"{garbage\n")
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", resume="bad"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
    )
    assert rc == EXIT_RUN_ERROR and json.loads(out.getvalue())["status"] == "corrupt"
    # unknown worker in --panel -> 2
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="nope", panel="nobody"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
    )
    assert rc == EXIT_CONFIG


def test_sigint_kills_records_and_resume_completes(tmp_path: Path) -> None:
    w = world(tmp_path)
    home = tmp_path / "home"
    popen = Popen(outputs())
    popen.interrupt_on = "claude"  # Ctrl-C while the judge runs
    killed: list[tuple[int, int]] = []
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="sig"),
        out=out,
        err=err,
        home=home,
        popen=popen,
        killpg=lambda pg, sig: killed.append((pg, sig)),
    )
    assert rc == EXIT_SIGINT and json.loads(out.getvalue())["status"] == "interrupted"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler  # restored
    assert killed and killed[0][1] == signal.SIGTERM  # the group was killed on the existing path
    run_dir = w["runs"] / "sig"
    assert not (run_dir / "manifest.json").exists()
    view = events_of(run_dir)
    kinds = view.kinds()
    assert kinds[-1] == "run.interrupted"
    interrupted = [i for i in view.payloads("invocation.finished") if i["error"] == "interrupted"]
    assert (
        len(interrupted) == 1
        and interrupted[0]["status"] == "failed"
        and interrupted[0]["worker_id"] == "judge"
    )
    cost = [
        c for c in view.payloads("cost") if c["invocation_id"] == interrupted[0]["invocation_id"]
    ][0]
    assert cost["cost_known"] is False and cost["estimated"] is True
    attempts = [
        a
        for a in view.payloads("retry.attempt")
        if a["invocation_id"] == interrupted[0]["invocation_id"]
    ]
    assert attempts and attempts[0]["decision"] == "stop" and "interrupted" in attempts[0]["reason"]
    assert attempts[0]["error_class"] == "interrupted"  # its own class, never `unknown`
    assert "stage.interrupted" in view.kinds()  # the attempt is CLOSED, not left open
    assert any(k == "invocation.spawned" for k in kinds)
    assert any(line for line in err.getvalue().splitlines() if '"run.interrupted"' in line)
    # resume: proposals replayed, judge re-run, cell completes
    popen2 = Popen(outputs())
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", resume="sig"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=popen2,
        killpg=dead_killpg,
    )
    assert rc == EXIT_OK, out.getvalue()
    assert [Path(a[0]).name for a, _ in popen2.calls if Path(a[0]).name in ("grok", "claude")] == [
        "claude"
    ]
    view = events_of(run_dir)
    assert "run.resumed" in view.kinds()
    # the SIGINT path already closed and costed that attempt: resume must NOT
    # synthesize an abandoned attempt for it (that was a double count)
    assert "invocation.abandoned" not in view.kinds()
    resumed = view.payloads("run.resumed")[0]
    assert resumed["abandoned"] == 0
    interrupted_costs = [
        c
        for c in view.payloads("cost")
        if c["cost_known"] is False and c["invocation_id"].endswith("-a1")
    ]
    assert len(interrupted_costs) == 1  # costed exactly once, by the interrupt
    assert (run_dir / "manifest.json").is_file()
    assert [p["stage"] for p in view.payloads("stage.resumed")] == ["pack", "propose"]


def test_campaign_dry_run_run_status_and_resume(tmp_path: Path) -> None:
    w = world(tmp_path)
    home = tmp_path / "home"
    camp = [
        "campaign",
        *base_args(w),
        "--campaign-id",
        "c1",
        "--corpus",
        str(w["corpus"]),
        "--repeats",
        "2",
        "--arms",
        "indep_verify,single,consensus",
    ]
    out = io.StringIO()
    rc = main([*camp, "--dry-run"], out=out, err=io.StringIO(), home=home, popen=Popen(outputs()))
    assert rc == EXIT_OK
    order = json.loads(out.getvalue())["cells"]
    assert [c["run_id"] for c in order] == [
        "t_01-r0-single-grok",
        "t_01-r0-consensus",
        "t_01-r0-indep_verify",
        "t_01-r1-single-grok",
        "t_01-r1-consensus",
        "t_01-r1-indep_verify",
    ]
    assert all(c["state"] == "pending" for c in order)
    assert not (w["runs"] / "c1").exists()  # dry-run writes nothing
    popen = Popen(outputs())
    out, err = io.StringIO(), io.StringIO()
    rc = main(camp, out=out, err=err, home=home, popen=popen, killpg=lambda *_: None)
    assert rc == EXIT_OK, out.getvalue()
    summary = json.loads(out.getvalue())
    assert [c["run_id"] for c in summary["cells"]] == [c["run_id"] for c in order]
    assert all(c["exit_code"] == 0 for c in summary["cells"])
    # proposals were spawned once per repeat (single -> consensus -> indep_verify share them)
    grok_spawns = [a for a, _ in popen.calls if Path(a[0]).name == "grok"]
    assert len(grok_spawns) == 2
    assert (w["runs"] / "c1" / "manifest.json").is_file() and (
        w["runs"] / "c1" / "events.jsonl"
    ).is_file()
    cview = events_of(w["runs"] / "c1")
    assert cview.kinds().count("cell.finished") == 6 and cview.kinds()[-1] == "campaign.finished"
    # status: read-only, no lock taken
    out = io.StringIO()
    rc = main(["campaign", "status", "--runs-dir", str(w["runs"]), "--campaign-id", "c1"], out=out)
    assert rc == EXIT_OK
    status = json.loads(out.getvalue())
    assert status["state"] == "finalized" and len(status["cells"]) == 6
    assert all(c["state"] == "finalized" and c["status"] == "complete" for c in status["cells"])
    # a second campaign run refuses (finalized) unless --resume, which skips every cell
    out = io.StringIO()
    rc = main(camp, out=out, err=io.StringIO(), home=home, popen=Popen(outputs()))
    assert rc == EXIT_CONFIG
    # STOP inside the campaign dir stops before the next cell
    w2 = world(tmp_path / "two")
    (w2["runs"] / "c2").mkdir(parents=True)
    (w2["runs"] / "c2" / "STOP").write_text("")
    out = io.StringIO()
    rc = main(
        [
            "campaign",
            *base_args(w2),
            "--campaign-id",
            "c2",
            "--corpus",
            str(w2["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single",
        ],
        out=out,
        err=io.StringIO(),
        home=tmp_path / "two" / "home",
        popen=Popen(outputs()),
    )
    assert rc == EXIT_STOP
    assert events_of(w2["runs"] / "c2").payloads("cell.skipped")[0]["reason"] == "stop"


def test_campaign_resume_skips_finalized_cells_and_resumes_unfinished(tmp_path: Path) -> None:
    w = world(tmp_path)
    home = tmp_path / "home"
    camp = [
        "campaign",
        *base_args(w),
        "--campaign-id",
        "c1",
        "--corpus",
        str(w["corpus"]),
        "--repeats",
        "1",
        "--arms",
        "single,indep_verify",
    ]
    popen = Popen(outputs())
    popen.interrupt_on = "claude"  # the judge of the second cell is interrupted
    out = io.StringIO()
    rc = main(camp, out=out, err=io.StringIO(), home=home, popen=popen, killpg=lambda *_: None)
    assert rc == EXIT_SIGINT
    cview = events_of(w["runs"] / "c1")
    assert cview.kinds()[-1] == "campaign.finished" and "cell.interrupted" in cview.kinds()
    assert not (w["runs"] / "c1" / "manifest.json").exists()
    out = io.StringIO()
    rc = main(["campaign", "status", "--runs-dir", str(w["runs"]), "--campaign-id", "c1"], out=out)
    states = {c["run_id"]: c["state"] for c in json.loads(out.getvalue())["cells"]}
    assert states == {"t_01-r0-single-grok": "finalized", "t_01-r0-indep_verify": "unfinished"}
    popen2 = Popen(outputs())
    out = io.StringIO()
    rc = main(
        [*camp, "--resume"],
        out=out,
        err=io.StringIO(),
        home=home,
        popen=popen2,
        killpg=dead_killpg,
    )
    assert rc == EXIT_OK, out.getvalue()
    cview = events_of(w["runs"] / "c1")
    assert [p["run_id"] for p in cview.payloads("cell.skipped")] == ["t_01-r0-single-grok"]
    assert [Path(a[0]).name for a, _ in popen2.calls if Path(a[0]).name in ("grok", "claude")] == [
        "claude"
    ]
    assert (w["runs"] / "c1" / "manifest.json").is_file()


WRITER_FILES = {".lock", "events.jsonl", "manifest.json"}


def writer_files_only(run_dir: Path) -> list[str]:
    """Every path under a run dir that RunWriter did not write."""
    bad: list[str] = []
    for path in run_dir.rglob("*"):
        rel = path.relative_to(run_dir)
        if (
            rel.parts[0] in WRITER_FILES
            or rel.parts[:2] == ("blobs", "sha256")
            or rel.parts == ("blobs",)
        ):
            continue
        bad.append(rel.as_posix())
    return bad


def test_runs_dir_holds_only_writer_files_and_scratch_is_swept(tmp_path: Path) -> None:
    """Item 5: after success, a STOP refusal and a crash, nothing but
    RunWriter-written files exists under runs/<id>/; every ephemeral file
    lives under scratch_dir/<id> and is removed; orphans are swept at
    startup and logged; the judge ran in an EMPTY dir under scratch; the
    original snapshot's tree hash is unchanged."""
    from eris.sanitize import tree_sha256

    w = world(tmp_path)
    home = tmp_path / "home"
    scratch_dir = tmp_path / "cache" / "scratch"
    (scratch_dir / "orphan-run").mkdir(parents=True)
    (scratch_dir / "orphan-run" / "leftover").write_text("x")
    old = time.time() - 86_400  # a day old: provably orphaned, not a concurrent run
    os.utime(scratch_dir / "orphan-run", (old, old))
    before = tree_sha256(w["snapshot"])
    popen = Popen(outputs())
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="ok"),
        out=out,
        err=err,
        home=home,
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK, out.getvalue()
    assert not (scratch_dir / "orphan-run").exists()
    swept = [json.loads(line) for line in err.getvalue().splitlines() if "scratch_swept" in line]
    assert swept and swept[0]["removed"] == ["orphan-run"]
    assert writer_files_only(w["runs"] / "ok") == []
    assert not (scratch_dir / "ok").exists()
    judge_cwd = [kw["cwd"] for a, kw in popen.calls if Path(a[0]).name == "claude"][0]
    assert judge_cwd == str((scratch_dir / "ok" / "judge-adjudicator-0").resolve())
    git_cwd = {kw["cwd"] for a, kw in popen.calls if Path(a[0]).name == "git"}
    assert git_cwd == {
        str((scratch_dir / "ok" / "verify-copy").resolve())
    }  # verification on the copy
    assert str(w["snapshot"].resolve()) not in git_cwd
    assert tree_sha256(w["snapshot"]) == before
    started = events_of(w["runs"] / "ok").payloads("run.started")[0]
    assert (
        started["snapshot_tree_sha256"] == before
        and "snapshot.verification_copy" in events_of(w["runs"] / "ok").kinds()
    )
    # STOP refusal
    (w["runs"] / "STOP").write_text("")
    rc = main(
        run_args(w, "indep_verify", run_id="stopped"),
        out=io.StringIO(),
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    (w["runs"] / "STOP").unlink()
    assert (
        rc == EXIT_STOP
        and writer_files_only(w["runs"] / "stopped") == []
        and not (scratch_dir / "stopped").exists()
    )
    # crash: an injected exception from the worker spawn propagates, scratch still removed
    crashing = Popen(outputs())
    crashing.crash_on = "grok"
    with pytest.raises(RuntimeError, match="simulated"):
        main(
            run_args(w, "indep_verify", run_id="crashed", no_cache=""),
            out=io.StringIO(),
            err=io.StringIO(),
            home=home,
            popen=crashing,
            killpg=lambda *_: None,
        )
    assert (
        writer_files_only(w["runs"] / "crashed") == []
        and not (w["runs"] / "crashed" / "manifest.json").exists()
    )
    assert not (scratch_dir / "crashed").exists()
    assert tree_sha256(w["snapshot"]) == before


def test_verification_violation_is_recorded_and_stops_verification(tmp_path: Path) -> None:
    """Item 4 end to end: a trusted pytest battery command writes into its
    cwd (the pristine copy) -> snapshot.violated, the item violated, the
    next command refused, the original untouched, pytest carried
    -p no:cacheprovider."""
    from eris.sanitize import tree_sha256

    w = world(tmp_path, trusted_pytest=True)
    task = json.loads(w["task"].read_text())
    w["task"].write_text(json.dumps({**task, "battery": [["pytest", "-q"], ["git", "ls-files"]]}))
    before = tree_sha256(w["snapshot"])
    popen = Popen(outputs())
    popen.write_in_cwd.add("pytest")
    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="viol", panel="grok"),
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc in (EXIT_OK, EXIT_INCOMPLETE), out.getvalue()
    view = events_of(w["runs"] / "viol")
    assert "snapshot.violated" in view.kinds()
    pytest_call = [a for a, _ in popen.calls if Path(a[0]).name == "pytest"][0]
    assert pytest_call[1:] == ["-q", "-p", "no:cacheprovider"]
    items = view.payloads("evidence.item")
    assert any(i["violated"] for i in items) and all(
        not i["violated"] for i in items if i["argv"] and i["argv"][-1] != "no:cacheprovider"
    )
    refused = [
        p for p in view.payloads("verify.refused") if "verification is stopped" in p["reason"]
    ]
    assert refused and refused[0]["argv"] == ["git", "ls-files"]
    assert tree_sha256(w["snapshot"]) == before
    assert not (w["snapshot"] / "WRITTEN_BY_pytest").exists()


def test_killpg_absence_is_a_documented_refusal_at_call_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 14: os.killpg is looked up when the command runs, not at import;
    without it every spawning/resuming command is refused (exit 2) with the
    documented message, while a dry-run still works."""
    w = world(tmp_path)
    monkeypatch.delattr(os, "killpg")
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify", run_id="nokill"),
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=Popen(outputs()),
    )
    assert rc == EXIT_CONFIG and "os.killpg is unavailable" in json.loads(out.getvalue())["error"]
    assert not (w["runs"] / "nokill").exists()
    out = io.StringIO()
    rc = main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single",
            "--dry-run",
        ],
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=Popen(outputs()),
    )
    assert rc == EXIT_OK  # dry-run spawns nothing


def test_writer_errors_on_the_error_path_are_never_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 15: a writer failure while recording a refusal propagates (the
    ledger contract); it is never hidden behind the original error."""
    import eval.run as run_mod

    from eris.writer import RunWriter as RealWriter
    from eris.writer import WriterError

    class BrokenWriter(RealWriter):
        def append(self, kind: str, payload: Any) -> Any:
            if kind == "run.error":
                raise WriterError("disk full while recording the error")
            return super().append(kind, payload)

    monkeypatch.setattr(run_mod, "RunWriter", BrokenWriter)
    w = world(tmp_path)
    import shutil

    def broken_rmtree(path: Any, *a: Any, **k: Any) -> None:
        raise OSError("EBUSY")  # a cleanup failure is recorded as run.error

    monkeypatch.setattr(shutil, "rmtree", broken_rmtree)
    with pytest.raises(WriterError, match="disk full"):
        main(
            run_args(w, "indep_verify", run_id="loud", no_cache=""),
            out=io.StringIO(),
            err=io.StringIO(),
            home=tmp_path / "home",
            popen=Popen(outputs()),
            killpg=lambda *_: None,
        )


def test_campaign_budget_counts_corrupt_cells_pessimistically_and_not_the_current_cell(
    tmp_path: Path,
) -> None:
    """Item 12: a corrupt cell ledger reserves per_call x planned calls and
    is reported; the cell being resumed is excluded from the campaign base
    (its own ledger seeds its run budget, never counted twice)."""
    w = world(tmp_path)
    home = tmp_path / "home"
    camp = [
        "campaign",
        *base_args(w),
        "--campaign-id",
        "c1",
        "--corpus",
        str(w["corpus"]),
        "--repeats",
        "1",
        "--arms",
        "single,indep_verify",
    ]
    popen = Popen(outputs())
    popen.interrupt_on = "claude"
    rc = main(
        camp, out=io.StringIO(), err=io.StringIO(), home=home, popen=popen, killpg=lambda *_: None
    )
    assert rc == EXIT_SIGINT
    single = w["runs"] / "c1" / "t_01-r0-single-grok"
    lines = (single / "events.jsonl").read_bytes().splitlines(keepends=True)
    lines[1] = b"{not json}\n"
    (single / "events.jsonl").write_bytes(b"".join(lines))
    out = io.StringIO()
    rc = main(
        [*camp, "--resume"],
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=dead_killpg,
    )
    assert rc == EXIT_OK, out.getvalue()
    cview = events_of(w["runs"] / "c1")
    started = [p for p in cview.payloads("cell.started") if p["run_id"] == "t_01-r0-indep_verify"][
        -1
    ]
    budget = started["campaign_budget"]
    assert budget["corrupt_cells"] == ["t_01-r0-single-grok"]
    # one planned call, reserved at the worst case the driver can reach (retries included)
    from eris.retry import worst_case_call_reservation

    assert budget["reserved_usd"] == pytest.approx(worst_case_call_reservation(0.5))
    assert budget["reserved_usd"] == pytest.approx(2.5)  # 5 x per_call (the mixed chain)
    assert budget["known_usd"] == 0.0  # the resumed cell's own spend is NOT in the base
    assert "t_01-r0-indep_verify" not in budget["counted_cells"]


def test_judge_workspace_is_fresh_per_iteration_and_checked_at_spawn(tmp_path: Path) -> None:
    """cond 2 end to end: the iterating judge arm gets a DIFFERENT empty dir
    per iteration (each verified empty at spawn time); a workspace that is not
    empty when the spawn is about to happen refuses the call."""
    w = world(tmp_path)
    asking = {
        **ADJ,
        "evidence_requests": [
            {"argv": ["git", "status", "--porcelain"], "rationale": "", "expect_exit_code": None}
        ],
    }
    popen = Popen(
        {
            "grok": [grok_envelope(GOOD_PROPOSAL)],
            "claude": [claude_envelope(asking), claude_envelope(ADJ)],
        }
    )
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify_iter", run_id="iter"),
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK, out.getvalue()
    judge = [
        (cwd, contents) for exe, cwd, contents in popen.cwd_contents if Path(exe).name == "claude"
    ]
    assert len(judge) == 2 and judge[0][0] != judge[1][0]
    assert judge[0][1] == [] and judge[1][1] == []  # each was EMPTY at spawn time
    assert judge[0][0].endswith("judge-adjudicator-0") and judge[1][0].endswith(
        "judge-adjudicator-1"
    )
    assert not Path(judge[0][0]).exists()  # both removed with the scratch root
    # the emptiness guard is enforced at spawn time, not only at planning
    from eval.run import assert_judge_workspace_empty

    from eris.launch import LaunchRefused, WorkerCall
    from eris.policy import WorkerPolicy

    dirty = tmp_path / "dirty-judge"
    dirty.mkdir()
    (dirty / "leftover").write_text("x")
    policy = WorkerPolicy.model_validate(
        {
            "transport": "cli",
            "cli": "claude",
            "provider": "anthropic",
            "executable_sha256": "a" * 64,
            "timeout_s": 60,
            "max_stdout_bytes": 1000,
        }
    )
    call = WorkerCall(
        worker_id="judge",
        policy=policy,
        prompt="p",
        cwd=dirty,
        task_id="t",
        stage=Stage.ADJUDICATE,
        repeat_index=0,
        policy_sha256="0" * 64,
        user="testuser",
    )
    with pytest.raises(LaunchRefused, match="not empty"):
        assert_judge_workspace_empty(call)
    (dirty / "leftover").unlink()
    assert_judge_workspace_empty(call)  # empty again: fine
    assert_judge_workspace_empty(call.__class__(**{**call.__dict__, "stage": Stage.PROPOSE}))


def test_sweep_never_removes_a_live_scratch_dir(tmp_path: Path) -> None:
    """cond 5: only provably orphaned entries are swept - not the current
    run's, not one whose run still holds its writer lock, not a recent one."""
    from eval.run import sweep_scratch

    from eris.redact import Redactor
    from eris.writer import RunWriter

    scratch = tmp_path / "scratch"
    runs = tmp_path / "runs"
    scratch.mkdir()
    runs.mkdir()
    for name in ("live-run", "stale-run", "recent-run", "current-run"):
        (scratch / name).mkdir()
        (scratch / name / "marker").write_text("x")
    old = 10_000.0
    now = 100_000.0
    for name in ("live-run", "stale-run", "current-run"):
        os.utime(scratch / name, (old, old))
    os.utime(scratch / "recent-run", (now - 5, now - 5))
    live = RunWriter(runs / "live-run", Redactor(), run_id="live-run").open()  # holds the lock
    try:
        removed = sweep_scratch(
            scratch,
            io.StringIO(),
            runs_dir=runs,
            exclude=["current-run"],
            now=lambda: now,
        )
    finally:
        live.close()
    assert removed == ["stale-run"]
    assert (scratch / "live-run").is_dir() and (scratch / "current-run").is_dir()
    assert (scratch / "recent-run").is_dir() and not (scratch / "stale-run").exists()
    # once the lock is free and the entry is old, it is swept
    removed = sweep_scratch(
        scratch, io.StringIO(), runs_dir=runs, exclude=["current-run"], now=lambda: now
    )
    assert removed == ["live-run"]  # the lock is free now, and it is old


def test_scan_result_is_the_last_event_even_when_an_error_is_recorded(tmp_path: Path) -> None:
    """cond 10: a run.error raised late (the ORIGINAL snapshot changed under
    us) is appended BEFORE the final scan, so scan.result stays last."""
    w = world(tmp_path)
    popen = Popen(outputs())
    popen.snapshot = w["snapshot"]
    popen.write_in_snapshot.add("grok")  # the worker touches the original
    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="modified", panel="grok", no_cache=""),
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=popen,
        killpg=lambda *_: None,
    )
    assert rc == EXIT_RUN_ERROR, out.getvalue()
    view = events_of(w["runs"] / "modified")
    kinds = view.kinds()
    assert kinds[-1] == "scan.result"  # genuinely last
    assert "run.error" in kinds and kinds.index("run.error") < len(kinds) - 1
    errors = view.payloads("run.error")
    assert any(e["kind"] == "snapshot_modified" for e in errors)
    assert (w["snapshot"] / "TOUCHED_BY_grok").exists()  # the test's own tampering


def test_sweep_excludes_the_current_run_on_the_run_and_campaign_paths(tmp_path: Path) -> None:
    """cond 5a: whichever command creates runs, the sweep is told their ids,
    so a scratch dir belonging to THIS command is never removed - even when it
    looks old and its lock is free."""
    w = world(tmp_path)
    home = tmp_path / "home"
    scratch_dir = tmp_path / "cache" / "scratch"
    old = time.time() - 86_400

    scratch_dir.mkdir(parents=True)
    mine = scratch_dir / "t_01-r0-indep_verify"
    mine.mkdir()
    (mine / "leftover").write_text("x")
    os.utime(mine, (old, old))
    out = io.StringIO()
    rc = main(
        run_args(w, "indep_verify"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_CONFIG and mine.is_dir() and (mine / "leftover").exists()
    assert "already exists" in json.loads(out.getvalue())["error"]
    shutil.rmtree(mine)

    for name in ("t_01-r0-single-grok", "t_01-r0-indep_verify", "c1"):
        d = scratch_dir / name
        d.mkdir(exist_ok=True)
        os.utime(d, (old, old))
    unrelated = scratch_dir / "someone-elses-old-run"
    unrelated.mkdir()
    os.utime(unrelated, (old, old))
    err = io.StringIO()
    main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c1",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single,indep_verify",
        ],
        out=io.StringIO(),
        err=err,
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    swept = [json.loads(line) for line in err.getvalue().splitlines() if "scratch_swept" in line]
    assert swept and swept[0]["removed"] == ["someone-elses-old-run"]
    assert set(swept[0]["kept"]) >= {"c1", "t_01-r0-single-grok", "t_01-r0-indep_verify"}
    assert all(v == "current run" for v in swept[0]["kept"].values())


def test_a_refused_scratch_entry_is_never_deleted_and_the_run_id_stays_reusable(
    tmp_path: Path,
) -> None:
    """cond 5b + consequence 1: the scratch path is validated BEFORE the writer
    opens - a planted entry survives untouched, no run dir is created, and the
    run id works again once the entry is removed."""
    w = world(tmp_path)
    home = tmp_path / "home"
    scratch_dir = tmp_path / "cache" / "scratch"
    scratch_dir.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep").write_text("x")
    planted = scratch_dir / "reuse"
    planted.symlink_to(elsewhere)
    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="reuse", panel="grok"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_CONFIG
    summary = json.loads(out.getvalue())
    assert summary["status"] == "refused" and str(planted) in summary["error"]
    assert planted.is_symlink()
    assert sorted(q.name for q in elsewhere.iterdir()) == ["keep"]
    assert not (w["runs"] / "reuse").exists()
    planted.unlink()
    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="reuse", panel="grok"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK, out.getvalue()
    assert (w["runs"] / "reuse" / "manifest.json").is_file()


def test_a_post_scan_failure_never_appends_behind_the_final_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cond 10: after the final scan the ledger is SEALED - a failure in the
    post-scan path is reported on stderr and the exit code, and an append
    would raise rather than slip in behind scan.result."""
    from eris.redact import Redactor
    from eris.writer import RunWriter as RealWriter
    from eris.writer import WriterClosed

    real_finalize = RealWriter.finalize
    calls = {"n": 0}

    def broken_finalize(self: RealWriter, extra: Any = None) -> Path:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("simulated manifest failure after the scan")
        return real_finalize(self, extra)

    monkeypatch.setattr(RealWriter, "finalize", broken_finalize)
    w = world(tmp_path)
    err, out = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "single", run_id="sealed", panel="grok", no_cache=""),
        out=out,
        err=err,
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_RUN_ERROR
    view = events_of(w["runs"] / "sealed")
    assert view.kinds()[-1] == "scan.result"
    reported = [json.loads(line) for line in err.getvalue().splitlines() if '"after_scan"' in line]
    assert reported and "simulated manifest failure" in reported[0]["error"]
    writer = RealWriter(tmp_path / "runs" / "sealcheck", Redactor(), run_id="sealcheck").open()
    writer.append("run.started", {})
    writer.seal()
    with pytest.raises(WriterClosed, match="sealed"):
        writer.append("run.error", {"kind": "late"})
    writer.finalize({"ok": True})


def test_scratch_over_the_retention_bound_is_swept_even_when_liveness_is_unprovable(
    tmp_path: Path,
) -> None:
    """New consequence 2: unprovable liveness must not let scratch accumulate
    forever - past `scratch_retention_s` an entry goes anyway, and is logged."""
    from eval.run import sweep_scratch

    from eris.redact import Redactor
    from eris.writer import RunWriter

    scratch = tmp_path / "scratch"
    runs = tmp_path / "runs"
    scratch.mkdir()
    runs.mkdir()
    now = 1_000_000.0
    week = 604_800.0
    for name in ("just-under", "just-over"):
        (scratch / name).mkdir()
    os.utime(scratch / "just-under", (now - week + 60, now - week + 60))
    os.utime(scratch / "just-over", (now - week - 60, now - week - 60))
    held = [RunWriter(runs / n, Redactor(), run_id=n).open() for n in ("just-under", "just-over")]
    try:
        err = io.StringIO()
        removed = sweep_scratch(
            scratch, err, runs_dir=runs, min_age_s=3600.0, max_age_s=week, now=lambda: now
        )
    finally:
        for writer in held:
            writer.close()
    assert removed == ["just-over"]
    assert (scratch / "just-under").is_dir() and not (scratch / "just-over").exists()
    line = [json.loads(x) for x in err.getvalue().splitlines() if "scratch_swept" in x][0]
    assert line["forced_over_retention"] == ["just-over"]
    assert line["kept"]["just-under"].startswith("run is live")


def test_exclusion_outranks_the_retention_bound_in_the_sweep(tmp_path: Path) -> None:
    """Final item 1: the retention bound sweeps ORPHANS only. An entry whose
    run id belongs to this command is never removed, at any age - deleting a
    live run's scratch is worse than leaking a stale directory."""
    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir()
    ancient = time.time() - 30 * 86_400  # far beyond the 7-day bound
    mine, theirs = scratch_dir / "current-run", scratch_dir / "someone-else"
    for d in (mine, theirs):
        d.mkdir()
        (d / "payload").write_text("x")
        os.utime(d, (ancient, ancient))
    err = io.StringIO()
    removed = sweep_scratch(
        scratch_dir,
        err,
        runs_dir=tmp_path / "runs",
        exclude=["current-run"],
        max_age_s=7 * 86_400.0,
    )
    assert removed == ["someone-else"] and not theirs.exists()
    assert mine.is_dir() and (mine / "payload").read_text() == "x"  # untouched, whatever its age
    line = [json.loads(x) for x in err.getvalue().splitlines() if "scratch_swept" in x][0]
    assert line["forced_over_retention"] == ["someone-else"]
    assert line["kept"] == {"current-run": "current run"}


def test_a_scratch_entry_appearing_after_the_precheck_refuses_before_any_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final item 2: the mkdir(exist_ok=False) IS the reservation and it runs
    BEFORE the writer opens, so an entry that appears between the precheck and
    it refuses with no ledger created, no run dir, and nothing deleted."""
    import eval.run as run_module

    w = world(tmp_path)
    scratch_dir = tmp_path / "cache" / "scratch"
    scratch_dir.mkdir(parents=True)
    real = run_module.make_private_dir
    planted: list[Path] = []

    def racing_make_private_dir(path: Path) -> None:
        if not planted:  # a concurrent placement, exactly between check and mkdir
            Path(path).mkdir(parents=True)
            (Path(path) / "not-ours").write_text("planted")
            planted.append(Path(path))
        real(path)

    monkeypatch.setattr(run_module, "make_private_dir", racing_make_private_dir)
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "single", run_id="raced", panel="grok"),
        out=out,
        err=err,
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_CONFIG, out.getvalue()
    assert "refusing" in json.loads(out.getvalue())["error"]
    assert not (w["runs"] / "raced").exists()  # NO ledger, no run dir
    entry = planted[0]
    assert entry.is_dir() and (entry / "not-ours").read_text() == "planted"  # untouched


def test_a_writer_open_failure_reports_a_scratch_it_could_not_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer refuses (the run already has a ledger) and the reservation is
    handed back - but the removal FAILS. No ledger is open, so there is no
    ``run.error`` to carry it: the failure must appear in BOTH remaining
    channels, the structured stderr line naming the scratch AND the returned
    outcome, which stops being a clean refusal (worker-visible files remain)."""
    import eval.run as run_module

    w = world(tmp_path)
    (w["runs"] / "taken").mkdir(parents=True)
    (w["runs"] / "taken" / "events.jsonl").write_bytes(b"")  # RunExists without --resume

    def broken_rmtree(path: Any, *a: Any, **k: Any) -> None:
        raise OSError(f"EBUSY {path}")

    monkeypatch.setattr(run_module.shutil, "rmtree", broken_rmtree)
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "single", run_id="taken", panel="grok"),
        out=out,
        err=err,
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    scratch = tmp_path / "cache" / "scratch" / "taken"
    summary = json.loads(out.getvalue())
    # channel 1: the outcome. The writer's own reason is still named, and the
    # exit code is the run error, not the clean EXIT_CONFIG refusal it was.
    assert rc == EXIT_RUN_ERROR, summary
    assert summary["status"] == "exists"
    assert "exists; pass resume=True" in summary["error"]
    assert "scratch cleanup failed" in summary["error"] and "EBUSY" in summary["error"]
    # channel 2: the structured stderr line, naming the path of the leftover
    lines = [json.loads(x) for x in err.getvalue().splitlines() if "scratch_cleanup_failed" in x]
    assert lines == [
        {
            "status": "error",
            "kind": "scratch_cleanup_failed",
            "run_id": "taken",
            "scratch": str(scratch),
            "error": f"{scratch}: EBUSY {scratch}",
        }
    ]
    assert scratch.is_dir()  # the leftover is real, and both channels say so


def test_a_scratch_root_cleanup_failure_never_replaces_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_scratch_root`` removes the scratch in a ``finally``. Raising there
    would DISCARD the exception already propagating - the refusal, the writer
    error, the interrupt - and report a leftover directory in its place. With
    something in flight the cleanup failure goes to stderr and the ORIGINAL
    propagates; with nothing in flight it is raised, exactly as before."""
    import eval.run as run_module

    from eris.writer import RunExists

    def broken_rmtree(path: Any, *a: Any, **k: Any) -> None:
        raise OSError(f"EBUSY {path}")

    monkeypatch.setattr(run_module.shutil, "rmtree", broken_rmtree)
    (tmp_path / "scratch").mkdir()
    in_flight, err = tmp_path / "scratch" / "r1", io.StringIO()
    with pytest.raises(RunExists, match="the writer refused"):  # the REASON, not the cleanup
        with run_module._scratch_root(in_flight, err):
            raise RunExists("the writer refused")
    assert [json.loads(x) for x in err.getvalue().splitlines()] == [
        {
            "status": "error",
            "kind": "scratch_cleanup_failed",
            "run_id": "r1",
            "scratch": str(in_flight),
            "error": f"EBUSY {in_flight}",
        }
    ]
    assert in_flight.is_dir()  # named, not silently leaked
    # nothing in flight: the cleanup failure IS the failure, and still raises
    clean, err2 = tmp_path / "scratch" / "r2", io.StringIO()
    with pytest.raises(OSError, match="EBUSY"), run_module._scratch_root(clean, err2):
        pass
    assert err2.getvalue() == ""


def test_a_post_scan_failure_is_durable_in_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final item 7: a failure after the seal cannot be an event, so it is
    recorded in manifest.json - which is written after the scan - instead of
    living only on stderr."""
    from eris.writer import RunWriter as RealWriter

    real_finalize = RealWriter.finalize
    calls = {"n": 0}

    def broken_once(self: RealWriter, extra: Any = None) -> Path:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("simulated manifest failure after the scan")
        return real_finalize(self, extra)

    monkeypatch.setattr(RealWriter, "finalize", broken_once)
    w = world(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "single", run_id="durable", panel="grok", no_cache=""),
        out=out,
        err=err,
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_RUN_ERROR
    view = events_of(w["runs"] / "durable")
    assert view.kinds()[-1] == "scan.result"  # still nothing behind the scan
    manifest = json.loads((w["runs"] / "durable" / "manifest.json").read_bytes())
    errors = manifest["post_scan_errors"]
    assert [e["kind"] for e in errors] == ["OSError"]
    assert "simulated manifest failure" in errors[0]["error"]
    assert [json.loads(x) for x in err.getvalue().splitlines() if '"after_scan"' in x]


def test_a_finalized_but_unfsynced_manifest_gets_its_own_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final item 7: the manifest rename succeeded, so every future open sees a
    FINALIZED run; only its durability is unproven. That is its own exit code
    and its own log line, never a finalize failure."""
    from eris.writer import RunWriter as RealWriter

    real_fsync_dir = RealWriter._fsync_dir

    def flaky(self: RealWriter, path: Path) -> None:
        # only the post-rename fsync of the run dir (the manifest is in place)
        if Path(path) == self.run_dir and self.manifest_path.is_file():
            raise OSError("simulated directory fsync failure after the rename")
        real_fsync_dir(self, path)

    monkeypatch.setattr(RealWriter, "_fsync_dir", flaky)
    w = world(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    rc = main(
        run_args(w, "single", run_id="unsynced", panel="grok", no_cache=""),
        out=out,
        err=err,
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_NOT_DURABLE and EXIT_NOT_DURABLE not in (EXIT_RUN_ERROR, EXIT_CONFIG)
    summary = json.loads(out.getvalue())
    assert summary["status"] == "not_durable" and "fsynced" in summary["error"]
    logged = [json.loads(x) for x in err.getvalue().splitlines() if '"not_durable"' in x]
    assert logged and "run_id" in logged[0]
    manifest_path = w["runs"] / "unsynced" / "manifest.json"
    assert manifest_path.is_file()  # the run IS finalized
    assert json.loads(manifest_path.read_bytes())["extra"]["status"] == "complete"
    assert events_of(w["runs"] / "unsynced").kinds()[-1] == "scan.result"


def test_campaign_discovery_skips_an_unscored_plumbing_task(tmp_path: Path) -> None:
    """M2c: `"scored": false` in task.json is ENFORCED, not just documented -
    a campaign never sweeps a plumbing task up. An explicit --task-file still
    runs it, which is the whole point of having one."""
    w = world(tmp_path)
    plumbing = w["corpus"] / "t_plumb"
    (plumbing / "snapshot" / ".git").mkdir(parents=True)
    (plumbing / "snapshot" / ".git" / "HEAD").write_text("f" * 40 + "\n")
    (plumbing / "snapshot" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    spec = json.loads((w["corpus"] / "t_01" / "task.json").read_text())
    spec.update({"task_id": "t_plumb", "scored": False, "diff_rev": None, "excerpts": []})
    (plumbing / "task.json").write_text(json.dumps(spec))
    _keys = w["corpus"].parent / "keys"
    (_keys / "t_plumb.json").write_text((_keys / "t_01.json").read_text())

    assert [p.parent.name for p in discover_tasks(w["corpus"])] == ["t_01"]

    out = io.StringIO()
    rc = main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c1",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single",
            "--dry-run",
        ],
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=Popen(outputs()),
    )
    assert rc == EXIT_OK
    cells = json.loads(out.getvalue())["cells"]
    assert cells and all(c["task_id"] == "t_01" for c in cells)
    # ... but naming it explicitly still runs it
    assert [p.name for p in [plumbing / "task.json"]] == ["task.json"]
    out2 = io.StringIO()
    rc = main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c2",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single",
            "--task-file",
            str(plumbing / "task.json"),
            "--dry-run",
        ],
        out=out2,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=Popen(outputs()),
    )
    assert rc == EXIT_OK
    assert {c["task_id"] for c in json.loads(out2.getvalue())["cells"]} == {"t_plumb"}


def test_a_snapshot_eris_refuses_is_a_clean_refusal_not_a_traceback(tmp_path: Path) -> None:
    """M2c follow-up 5, advisor round, item 4. `SanitizeError` was not caught
    by `run_cell`: every deliberate refusal added by this milestone - a nested
    repository, an unsupported `extensions.*`, a `.git` shape Eris cannot
    reason about - would have surfaced as an unhandled traceback with no
    ledger entry and no documented exit code.

    A refusal is a refusal: EXIT_CONFIG, status `refused`, the reason in the
    summary, and a `run.error` event on the ledger."""
    w = world(tmp_path)
    snap = w["task"].parent / "snapshot"
    (snap / "vendor").mkdir()
    (snap / "vendor" / ".git").write_text("gitdir: ../../elsewhere/.git\n")

    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="nested", panel="grok"),
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_CONFIG
    summary = json.loads(out.getvalue())
    assert summary["status"] == "refused"
    assert "vendor/.git" in summary["error"] and "NESTED repository" in summary["error"]
    kinds = [e.kind for e in events_of(w["runs"] / "nested").events]
    assert "run.error" in kinds
    # ... and no half-built copy is left in the scratch dir
    leftovers = list((tmp_path / "cache" / "scratch").rglob("*verify*"))
    assert leftovers == [], leftovers


# --------------------------------------------------------------------------- cleanup reporting


class _ClosedStream:
    """A stderr whose every write fails, like a closed pipe."""

    def write(self, _data: str) -> int:
        raise ValueError("I/O operation on closed file")

    def flush(self) -> None:
        raise ValueError("I/O operation on closed file")


def test_the_cleanup_report_never_replaces_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report that cannot be delivered is dropped: the reason survives.

    The reporting channel exists so a cleanup failure is not lost. If writing
    it could itself raise, it would destroy the very exception it was called
    to preserve - the defect one level deeper than the one it fixed.
    """
    import eval.run as run_module

    scratch = tmp_path / "scratch" / "r1"
    scratch.parent.mkdir(parents=True)

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("EBUSY: device or resource busy")

    monkeypatch.setattr(run_module.shutil, "rmtree", boom)
    with pytest.raises(RuntimeError, match="the real reason"):
        with run_module._scratch_root(scratch, _ClosedStream()):  # type: ignore[arg-type]
            raise RuntimeError("the real reason")


def test_a_cleanup_that_raises_something_other_than_oserror_is_still_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``rmtree`` is not contractually limited to OSError - a handler of ours
    can raise anything. Whatever it raises, the reason still wins."""
    import eval.run as run_module

    scratch = tmp_path / "scratch" / "r2"
    scratch.parent.mkdir(parents=True)

    def boom(*_a: object, **_k: object) -> None:
        raise RecursionError("a handler blew the stack")

    monkeypatch.setattr(run_module.shutil, "rmtree", boom)
    err = io.StringIO()
    with pytest.raises(RuntimeError, match="the real reason"):
        with run_module._scratch_root(scratch, err):
            raise RuntimeError("the real reason")
    line = json.loads(err.getvalue().strip())
    assert line["kind"] == "scratch_cleanup_failed"
    assert "blew the stack" in line["error"]


def test_the_reporter_itself_never_raises(tmp_path: Path) -> None:
    import eval.run as run_module

    run_module._print_scratch_cleanup_failure(
        _ClosedStream(),  # type: ignore[arg-type]
        "r3",
        tmp_path / "scratch" / "r3",
        "EBUSY",
    )


class _Unprintable(OSError):
    """An exception whose ``__str__`` raises, as a C-extension error can."""

    def __str__(self) -> str:
        raise RuntimeError("this exception cannot be printed")


def test_an_unprintable_cleanup_error_never_replaces_the_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Formatting the cleanup failure happens where the arguments are built,
    OUTSIDE the reporter's own guard - so a pathological ``__str__`` there
    would replace the reason just as surely as an unguarded write."""
    import eval.run as run_module

    scratch = tmp_path / "scratch" / "r4"
    scratch.parent.mkdir(parents=True)

    def boom(*_a: object, **_k: object) -> None:
        raise _Unprintable("never seen")

    monkeypatch.setattr(run_module.shutil, "rmtree", boom)
    err = io.StringIO()
    with pytest.raises(RuntimeError, match="the real reason"):
        with run_module._scratch_root(scratch, err):
            raise RuntimeError("the real reason")
    line = json.loads(err.getvalue().strip())
    assert line["error"] == "<unprintable error>"


def test_remove_scratch_never_raises_on_an_unprintable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_remove_scratch` documents that it never raises; its own error
    formatting must therefore be defensive too."""
    import eval.run as run_module

    scratch = tmp_path / "scratch" / "r5"
    scratch.mkdir(parents=True)

    def boom(*_a: object, **_k: object) -> None:
        raise _Unprintable("never seen")

    monkeypatch.setattr(run_module.shutil, "rmtree", boom)
    assert run_module._remove_scratch(scratch) == f"{scratch}: <unprintable error>"


class _UnprintablePath(type(Path())):  # type: ignore[misc]
    """A path whose ``__str__`` raises - stands in for anything in the report
    that could explode while being formatted."""

    def __str__(self) -> str:
        raise RuntimeError("this path cannot be printed")


def test_the_whole_report_is_guarded_not_just_its_last_step(tmp_path: Path) -> None:
    """The reporter must be unable to raise ANYWHERE in its body.

    This was fixed three times one step at a time (the write, the caller's
    formatting, the dict construction) because each fix guarded only the step
    the previous finding named. The guard now wraps the whole body; this test
    explodes a DIFFERENT step than any of those findings did.
    """
    import eval.run as run_module

    run_module._print_scratch_cleanup_failure(
        io.StringIO(), "r6", _UnprintablePath(tmp_path / "s"), "EBUSY"
    )


def test_a_scored_run_is_refused_unless_a_canary_survives_into_the_patterns(
    tmp_path: Path,
) -> None:
    """The canary is a detector only if it reaches the pattern set.

    `build_patterns` drops candidates that are too short, already in
    `known_texts`, or present in the pre-fix tree - quietly, as counts. A canary
    that also appears in the snapshot (copied into `files/`, say) is therefore
    removed, and the detection the key promises does not exist for that run,
    while the run still reports `contaminated: false` (panel, 2026-08-30).
    Checked against the SURVIVING patterns, because the key file is not what
    does the detecting.
    """
    w = world(tmp_path)
    loaded = load_policy(w["policy"])
    args = (w["task"], w["snapshot"], tmp_path / "home", tmp_path / "run", loaded.policy)
    assert any(p.folded == fold(KEY_CANARY) for p in scan_patterns_for(*args).patterns)

    # the same canary, now also sitting in the snapshot the worker starts from
    (w["snapshot"] / "leaked.txt").write_text(f"{KEY_CANARY}\n")
    with pytest.raises(LaunchRefused, match="survived into the scan patterns"):
        scan_patterns_for(*args)
    (w["snapshot"] / "leaked.txt").unlink()

    # a scored task with no key at all is refused too: patterns would be empty
    # and the money would be spent on a cell whose scan could not fire
    key_file = key_path_for(w["corpus"] / "t_01")
    body = key_file.read_text()
    key_file.unlink()
    with pytest.raises(LaunchRefused, match="answer key"):
        scan_patterns_for(*args)
    key_file.write_text(body)
    assert scan_patterns_for(*args).count > 0


def test_a_leaked_key_stops_the_run_before_any_worker_spawns(tmp_path: Path) -> None:
    """The scorer's refusal fires after the cells have run and the money is
    spent, and deleting the stray file then produces metrics with no record that
    it was present while workers ran. `load_task` is on every campaign and
    single-run path, before spawn.
    """
    w = world(tmp_path)
    assert load_task(w["task"])[0].task_id == "t_01"

    planted = w["corpus"] / "t_01" / "snapshot" / "key.json"
    planted.write_text("{}")
    with pytest.raises(LaunchRefused, match="readable by the worker"):
        load_task(w["task"])
    planted.unlink()
    assert load_task(w["task"])[0].task_id == "t_01"


def test_key_content_anywhere_in_the_task_stops_the_run(tmp_path: Path) -> None:
    """A filename check cannot see a key that arrived under another name.

    `shutil.copytree` dereferences symlinks, so a link in `files/` pointing at
    the key lands in `snapshot/` as plaintext under the link's name; and
    `Path.rglob` does not walk symlinked directories, so a directory link to the
    keys folder is invisible to a name walk entirely. The question is asked
    directly instead: does the token that exists ONLY in the answer key appear
    anywhere inside this task (stop review, 2026-08-30)?
    """
    w = world(tmp_path)
    assert load_task(w["task"])[0].task_id == "t_01"

    # the key's plaintext, in the worker's own cwd, under an innocuous name
    planted = w["corpus"] / "t_01" / "snapshot" / "notes.txt"
    planted.write_text(f"reference: {KEY_CANARY}\n")
    with pytest.raises(LaunchRefused, match="canary appears inside the corpus task"):
        load_task(w["task"])
    planted.unlink()

    # a directory symlink exposing the whole keys folder
    peek = w["corpus"] / "t_01" / "peek"
    peek.symlink_to(key_path_for(w["corpus"] / "t_01").parent, target_is_directory=True)
    with pytest.raises(LaunchRefused, match="canary appears inside the corpus task"):
        load_task(w["task"])
    peek.unlink()

    assert load_task(w["task"])[0].task_id == "t_01"


def test_campaign_and_run_ledgers_are_distinguishable_by_their_start_marker(
    tmp_path: Path,
) -> None:
    """The two start markers are mutually exclusive, per directory.

    `eval/live_preconditions.sh` classifies a COLLIDED run id by reading the
    directory's own ledger: `campaign.started` means campaign (resume with a
    bare `--resume`), `run.started` means standalone (resume with
    `--resume <RUN_ID>`), and anything else - missing, empty, chain-corrupt, or
    carrying BOTH - refuses to print a resume form at all.

    That classifier is only sound while the markers stay mutually exclusive,
    and nothing enforced it: its rationale asserted the invariant from a grep of
    `cmd_campaign` taken at one moment (stop review, 2026-08-31). Appending
    `run.started` to the campaign writer would make the gate print the
    standalone flag for a real campaign directory - `--resume c2`, which
    argparse rejects as `invalid choice: 'c2' (choose from 'status')` - and no
    test would have noticed.
    """
    w = world(tmp_path)
    home = tmp_path / "home"
    rc = main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c2",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single",
        ],
        out=io.StringIO(),
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK

    campaign_kinds = set(events_of(w["runs"] / "c2").kinds())
    assert "campaign.started" in campaign_kinds
    assert "run.started" not in campaign_kinds, (
        "a campaign directory's own ledger gained `run.started`: the live-run "
        "gate would now print the standalone resume flag for a campaign"
    )

    cell_dirs = [p for p in (w["runs"] / "c2").iterdir() if p.is_dir() and p.name != "blobs"]
    assert cell_dirs, "campaign wrote no cell directories"

    out = io.StringIO()
    rc = main(
        run_args(w, "single", run_id="solo"),
        out=out,
        err=io.StringIO(),
        home=home,
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK, out.getvalue()
    solo_dir = Path(json.loads(out.getvalue())["run_dir"])

    # Every directory the gate could classify, found the way the gate finds
    # them - by walking for a ledger - rather than by listing the ones this
    # test remembered to create.
    ledgers = sorted(p.parent for p in w["runs"].rglob("events.jsonl"))
    assert {w["runs"] / "c2", solo_dir} <= set(ledgers)
    assert set(cell_dirs) <= set(ledgers)
    for d in ledgers:
        kinds = set(events_of(d).kinds())
        markers = kinds & {"run.started", "campaign.started"}
        assert len(markers) == 1, (
            f"{d.relative_to(w['runs'])} carries {sorted(markers) or 'no'} start marker(s); "
            "the live-run gate classifies a collided id by exactly one of them "
            "and refuses to advise on zero or two"
        )
        expected = "campaign.started" if d == w["runs"] / "c2" else "run.started"
        assert markers == {expected}, (
            f"{d.relative_to(w['runs'])} carries {markers}, want {expected}"
        )


_INDIRECT_LOOKUP = frozenset({"__getattribute__", "__getattr__"})


def _hides_arity(node: ast.Call) -> bool:
    """A splat: how many arguments this passes cannot be read."""
    return any(isinstance(a, ast.Starred) for a in node.args) or any(
        k.arg is None for k in node.keywords
    )


def _passes_two(node: ast.Call) -> bool:
    """Called the way `RunWriter.append(kind, payload)` is called.

    A splat counts, because `f(*pair)` may well be passing two. Both callers
    below use THIS function rather than their own arity test: the splat check
    lived inside the `.append` branch and the unreadable-callee branch was
    written later with a fresh `len(args) + len(keywords) >= 2`, so
    `getattr(w, n)(*pair)` walked past it (stop review, 2026-08-31). Two copies
    of a rule are two rules, and only one of them gets fixed.
    """
    return _hides_arity(node) or len(node.args) + len(node.keywords) >= 2


def _event_append_sites(
    roots: tuple[Path, ...],
) -> tuple[dict[str, set[str]], list[tuple[str, str, str | None]]]:
    """Every ``<writer>.append(kind, payload)`` under ``roots``.

    Returns (literal kinds -> {"module.function"}, dynamic sites). An event
    append takes two arguments; ``list.append`` takes one, which is what
    separates them. The enclosing function is the INNERMOST one, so a helper
    nested inside a command is reported under its own name rather than the
    command's.
    """
    markers = {"run.started", "campaign.started"}
    literal: dict[str, set[str]] = {}
    # (where, rendered, provable_prefix). `provable_prefix` is None when the
    # kind cannot be read at all - a splat, a `getattr`, a detached bound
    # method - and those can never be proven safe. It is computed HERE,
    # while the node is in hand, because an earlier version stored
    # `ast.unparse(node)` and re-parsed it in `mode="eval"`; an alias
    # assignment unparses to a STATEMENT, so that raised SyntaxError inside
    # the test instead of failing it (found by running case F).
    dynamic: list[tuple[str, str, str | None]] = []

    def literal_prefix(node: ast.expr) -> str | None:
        """The literal text a computed kind must start with, if any."""
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    class V(ast.NodeVisitor):
        def __init__(self, module: str, called: set[int]) -> None:
            self.module = module
            self.called = called  # id() of every Attribute that IS a call target
            self.stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        @property
        def _where(self) -> str:
            return f"{self.module}.{self.stack[-1] if self.stack else '<module>'}"

        def visit_Attribute(self, node: ast.Attribute) -> None:
            # A REFERENCE to `.append` that is not immediately called detaches
            # the method from every later call site, which this scan then
            # cannot see. Enumerating the ways to write one is what failed
            # before: the previous version matched `emit = w.append`
            # (`ast.Assign`) alone, so an annotated assignment, a tuple target,
            # a walrus, a default argument, a `return`, a dict literal and
            # `partial(w.append, ...)` all walked past it (stop review,
            # 2026-08-31). The structural question - is this reference called
            # right here? - has no shapes to enumerate, so it has none to miss.
            if node.attr == "append" and id(node) not in self.called:
                dynamic.append((f"{self._where}:{node.lineno}", ast.unparse(node), None))
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            passes_two = _passes_two(node)
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "append":
                    self._maybe_event(node, self._where)
                elif node.func.attr in _INDIRECT_LOOKUP and passes_two:
                    # `w.__getattribute__("append")(kind, payload)`.
                    dynamic.append((f"{self._where}:{node.lineno}", ast.unparse(node), None))
            elif isinstance(node.func, ast.Name):
                # Only a LITERAL name can be read. `getattr(w, "append")` is the
                # method; `getattr(w, name)` might be, and the difference is not
                # visible here - so the readable one is judged on its name and
                # the unreadable one is refused if it is called like an event
                # append. Refusing every dynamic `getattr` outright would fail
                # the four that exist (`score.py`, `validate.py`), none of which
                # touches a writer; a check that cries wolf gets ignored, which
                # is the reasoning already applied to the openai-api WARN.
                if node.func.id == "getattr":
                    name = node.args[1] if len(node.args) >= 2 else None
                    if isinstance(name, ast.Constant) and name.value == "append":
                        dynamic.append((f"{self._where}:{node.lineno}", ast.unparse(node), None))
                # Any other plain name is a readable local or imported callable,
                # not an indirect lookup. Letting these fall through to the
                # refusal below flagged every ordinary two-argument call in the
                # repository - `note(...)`, `_abandoned_payload(...)` - which is
                # how this branch was found to be miswritten, by running it.
            elif passes_two:
                # The callee is neither a name nor an attribute - `getattr(w,
                # n)(k, p)`, `table["append"](k, p)`, `(lambda ...)(k, p)`. The
                # scan cannot tell what method it reaches, and it is called the
                # way an event append is called, so it is refused.
                dynamic.append((f"{self._where}:{node.lineno}", ast.unparse(node), None))
            self.generic_visit(node)

        def _maybe_event(self, node: ast.Call, where: str) -> None:
            """Is this `RunWriter.append(kind, payload)`, and what kind?

            `append(self, kind, payload)` takes BOTH parameters positionally OR
            by keyword (`src/eris/writer.py:344`), so arity alone cannot find
            these calls: `w.append("campaign.started", payload={})` has one
            positional argument and `w.append(kind=...)` has none. An earlier
            version required two positionals, which a `list.append` never has -
            true, but it also excluded every keyword form of the call it was
            looking for (stop review, 2026-08-31). What separates an event
            append from `list.append` is that it passes TWO things, however
            they are spelled.
            """
            if _hides_arity(node):
                # A splat hides the kind. BOTH forms are checked here, before
                # the arity gate below, because neither passes it: `append(*p)`
                # presents one argument and `append(**d)` one keyword with no
                # `kind=`, so the gate meant to catch them would skip them.
                # `**d` was handled first and `*p` was not, which is the same
                # oversight one shape over (stop review, 2026-08-31).
                dynamic.append((f"{where}:{node.lineno}", ast.unparse(node), None))
                return
            kwargs = {k.arg for k in node.keywords}
            if not (_passes_two(node) or "kind" in kwargs):
                return  # list.append(x)
            arg: ast.expr | None = node.args[0] if node.args else None
            if arg is None:
                arg = next((k.value for k in node.keywords if k.arg == "kind"), None)
            if arg is None:
                dynamic.append((f"{where}:{node.lineno}", ast.unparse(node), None))
                return
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value in markers:
                    literal.setdefault(arg.value, set()).add(where)
            else:
                dynamic.append((f"{where}:{node.lineno}", ast.unparse(arg), literal_prefix(arg)))

    for root in roots:
        for f in sorted(root.rglob("*.py")):
            rel = f.relative_to(REPO_ROOT).as_posix()
            tree = ast.parse(f.read_text(encoding="utf-8"))
            called = {
                id(n.func)
                for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            }
            V(rel, called).visit(tree)
    return literal, dynamic


def test_no_module_writes_the_other_kinds_start_marker() -> None:
    """The start markers are mutually exclusive across the WHOLE codebase.

    `eval/live_preconditions.sh` classifies a collided run id by these markers:
    `campaign.started` means campaign (bare `--resume`), `run.started` means
    standalone (`--resume <RUN_ID>`), and zero or two means it refuses to
    advise. That is a claim about every directory in `runs_dir`, so it is a
    claim about every place an event can be appended - not about the two
    commands a behavioural test happens to drive.

    Two earlier versions were narrower than the claim. The first asserted only
    over directories a campaign and a run produced, so `campaign.started` added
    to `cmd_invoke` passed. The second scanned `eval/run.py` alone and matched
    only literal kinds, so a marker written from another module, or from a
    computed string, was invisible to it (stop review, 2026-08-31).

    Dynamic kinds are real here - `stages.py` appends ``f"cache.{outcome}"`` -
    so this cannot simply ignore them. A computed kind is accepted only when it
    starts with a literal prefix that NO marker starts with, which is a proof
    that it cannot produce one. Anything else fails: the test cannot see the
    kind, so it refuses, exactly as the gate refuses a ledger it cannot read.

    WHAT THIS DOES NOT COVER, measured rather than assumed. The scan reads
    static call structure. A method resolved dynamically and parked in a local
    escapes it::

        _f = getattr(w, name)   # name is not a literal
        _f("campaign.started", {})   # callee is a plain Name

    Refusing every non-literal `getattr` would close that, and would also fail
    the four in `score.py` and `validate.py` that touch no writer - a check that
    cries wolf gets ignored, which is the reasoning already applied to the
    openai-api WARN in `eval/live_preconditions.sh`. So the boundary is drawn
    here and stated instead of papered over: that mutation was run, this test
    PASSED, and
    `test_campaign_and_run_ledgers_are_distinguishable_by_their_start_marker`
    FAILED on it, because a marker written by any means at all lands in a ledger
    it walks. The two tests are complementary and neither is sufficient: static
    structure for every call site that can be read, real ledgers for the paths
    actually exercised.
    """
    literal, dynamic = _event_append_sites((SRC_DIR, EVAL_DIR))

    assert literal == {
        "campaign.started": {"eval/run.py.cmd_campaign"},
        "run.started": {"eval/run.py.cmd_invoke", "eval/run.py.run_cell"},
    }, (
        "the start-marker site map changed. `eval/live_preconditions.sh` "
        "classifies a collided run id by these markers being mutually exclusive "
        "per directory; if one command now writes both, or writes the other "
        "kind's marker, the gate prints the wrong --resume form for a real run."
    )

    unprovable = [
        (where, rendered)
        for where, rendered, prefix in dynamic
        if not prefix or any(m.startswith(prefix) for m in ("run.started", "campaign.started"))
    ]
    assert not unprovable, (
        f"event kind(s) built from an expression this test cannot rule out: {unprovable}. "
        "A computed kind is only safe here if it begins with a literal prefix that "
        "neither `run.started` nor `campaign.started` begins with. Give it such a "
        "prefix, or make the kind literal."
    )


def test_campaign_status_reports_committed_cost_and_names_what_it_cannot_read(
    tmp_path: Path,
) -> None:
    """`campaign status` must report the figure the stop condition reads.

    The operator stop condition is "committed cost over $X", and it named
    `spent_known_usd + reserved` "from campaign status". That command reported
    no reserved figure and no campaign-level total at all, so the reading it
    asked for could not be taken from the command it named (stop review,
    2026-08-31). Committed is known PLUS reserved, because `reserved_usd` holds
    counted costs whose value is unknown - a missing-cost worker's call, or one
    killed before it could report - and leaving it out understates the spend by
    exactly the part nobody can see.
    """
    w = world(tmp_path)
    rc = main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c3",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single",
        ],
        out=io.StringIO(),
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=Popen(outputs()),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK

    def status() -> dict[str, Any]:
        out = io.StringIO()
        assert (
            main(
                ["campaign", "status", "--runs-dir", str(w["runs"]), "--campaign-id", "c3"],
                out=out,
            )
            == EXIT_OK
        )
        return json.loads(out.getvalue())

    first = status()
    known_before = first["cost"]["spent_known_usd"]
    assert first["cost"]["committed_usd"] == pytest.approx(
        known_before + first["cost"]["reserved_usd"]
    )
    assert first["cost"]["unreadable_ledgers"] == []
    # The per-cell figures the command already reported add up to the campaign
    # total it now reports, or the two disagree in front of the operator. Only
    # finalized cells carry a per-cell figure (it comes from the manifest, while
    # the campaign total comes from the ledgers), so this holds while every cell
    # is finalized - which it is, the campaign having completed.
    assert known_before == pytest.approx(
        sum(c["spent_known_usd"] for c in first["cells"] if c.get("spent_known_usd"))
    )

    # A RESERVED cost - a call whose value is not known, which is what a
    # missing-cost worker or an interrupted call produces - must land in
    # `committed_usd` and NOT in `spent_known_usd`. Written directly, because
    # every worker in this hermetic world reports its cost, so a campaign run
    # here leaves `reserved_usd` at zero and an assertion about it cannot fail
    # (found by mutating `committed_usd` and watching the test pass).
    extra = w["runs"] / "c3" / "t_01-r0-single-reserved"
    with RunWriter(extra, Redactor(), run_id="t_01-r0-single-reserved") as ew:
        ew.append("run.started", {"eris_version": "0.0.0"})
        ew.append(
            "cost",
            {"invocation_id": "inv-known-1", "attempt": 1, "cost_usd": 1.25, "cost_known": True},
        )
        ew.append(
            "cost",
            {
                "invocation_id": "inv-unknown-1",
                "attempt": 1,
                "cost_usd": 2.0,
                "cost_known": False,
                "estimated": True,
            },
        )
    cost = status()["cost"]
    assert cost["spent_known_usd"] == pytest.approx(known_before + 1.25)
    assert cost["reserved_usd"] == pytest.approx(2.0)
    assert cost["committed_usd"] == pytest.approx(known_before + 1.25 + 2.0)
    assert cost["committed_is_complete"] is True
    assert cost["counted_records_without_cost"] == 0

    # A cache REPLAY writes `cost_usd=origin.cost_usd, counted=False`
    # (`cache.py`), so replaying a missing-cost worker's result leaves a
    # valueless record that cost NOTHING - the origin's estimate was booked in
    # the cell that ran it. It must NOT break completeness. Keying the flag on
    # `cost_totals.unknown_count`, which counts every valueless record, made
    # exactly this look like unaccounted spend.
    replay = w["runs"] / "c3" / "t_01-r0-single-replay"
    with RunWriter(replay, Redactor(), run_id="t_01-r0-single-replay") as rw:
        rw.append("run.started", {"eris_version": "0.0.0"})
        rw.append(
            "cost",
            {
                "invocation_id": "inv-replay-1",
                "attempt": 1,
                "cost_usd": None,
                "counted": False,
                "cost_known": False,
            },
        )
    after_replay = status()["cost"]
    assert after_replay["counted_records_without_cost"] == 0
    assert after_replay["committed_is_complete"] is True
    assert after_replay["committed_usd"] == pytest.approx(cost["committed_usd"])

    # A cost record with NO cost at all - `cost_usd: None`, which a cache replay
    # can produce - is counted by `cost_totals` and added to neither bucket. It
    # is spend that exists and cannot be valued, so it breaks completeness the
    # same way an unreadable ledger does. The flag consulted only `unreadable`
    # and reported true while these were present.
    valueless = w["runs"] / "c3" / "t_01-r0-single-valueless"
    with RunWriter(valueless, Redactor(), run_id="t_01-r0-single-valueless") as vw:
        vw.append("run.started", {"eris_version": "0.0.0"})
        vw.append("cost", {"invocation_id": "inv-none-1", "attempt": 1, "cost_usd": None})
    valued = status()["cost"]
    assert valued["counted_records_without_cost"] == 1
    assert valued["committed_is_complete"] is False
    assert valued["unreadable_ledgers"] == []  # readable, just unvaluable
    assert valued["committed_usd"] == pytest.approx(cost["committed_usd"])

    # Isolation (panel 2026-09-06, B4): with the valueless cell still present,
    # `unknown_records == 1` already held the flag False, so the assertion after
    # the corruption below could not see the `unreadable` half - dropping
    # `not unreadable` from the flag left this whole test green. Remove the cell
    # and prove the flag RECOVERED, so the next False is unreadable's alone.
    shutil.rmtree(valueless)
    recovered = status()["cost"]
    assert recovered["counted_records_without_cost"] == 0
    assert recovered["committed_is_complete"] is True

    # A cell whose ledger will not parse is NAMED rather than skipped: dropping
    # it silently would lower the committed figure the operator is watching.
    lines = (extra / "events.jsonl").read_bytes().splitlines(keepends=True)
    d = json.loads(lines[1])
    d["prev_sha256"] = ("b" if d["prev_sha256"][0] == "a" else "a") + d["prev_sha256"][1:]
    (extra / "events.jsonl").write_bytes(
        b"".join(
            lines[:1]
            + [json.dumps(d, separators=(",", ":"), sort_keys=True).encode() + b"\n"]
            + lines[2:]
        )
    )
    after = status()["cost"]
    assert after["unreadable_ledgers"] == [extra.name]
    # Its $3.25 is gone from the total, so the total is a FLOOR. The flag is
    # what makes that legible: without it an operator reads $0.01 committed and
    # concludes the campaign is nowhere near the ceiling, when the truth is
    # unknown and strictly larger. Understating is the dangerous direction for
    # a budget stop.
    assert after["committed_usd"] == pytest.approx(known_before)
    assert after["committed_is_complete"] is False
    assert first["cost"]["committed_is_complete"] is True
