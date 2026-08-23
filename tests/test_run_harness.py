"""eval/run.py (M2b): `run`, `campaign`, `campaign status`, `--resume`, the
SIGINT handler, exit codes and the stderr event stream - all hermetic
(scripted Popen for git and the worker CLIs)."""

from __future__ import annotations

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
    EXIT_OK,
    EXIT_RUN_ERROR,
    EXIT_SIGINT,
    EXIT_STOP,
    main,
)

from eris.ledger import LedgerView
from eris.schemas import Stage
from tests.conftest import FakeProcess
from tests.test_stages import GOOD_PROPOSAL

PROMPTS = Path(__file__).resolve().parents[1] / "eval" / "prompts"
FIX_HUNK = "    if response.text is None:  # planted null guard"
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
            sub = argv[1] if len(argv) > 1 else ""
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
                "category": "control",
                "snapshot": "snapshot",
                "battery": [],
                "excerpts": [{"path": "src/app.py", "line_start": 1, "line_end": 3}],
                "diff_rev": "HEAD",
            }
        )
    )
    (corpus / "key.json").write_text(
        json.dumps(
            {
                "key_version": 1,
                "task_id": "t_01",
                "category": "control",
                "expected_verdict": ["ACCEPT"],
                "line_tolerance": 2,
                "findings": [],
                "distractors": [],
                "scan": {"fix_hunk_lines": [FIX_HUNK], "extra_strings": []},
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
        assert set(e.payload) <= {"idempotency_key", "entry_sha256", "existing_sha256", "scan_hits"}
        assert all(v is None or isinstance(v, int) or len(str(v)) == 64 for v in e.payload.values())
    assert "scan.patterns" in kinds and view.payloads("scan.patterns")[0]["pattern_count"] >= 1
    # grok ran in its sanitized copy (no AGENTS.md), git ran on the ORIGINAL
    grok_calls = [kw for argv, kw in popen.calls if Path(argv[0]).name == "grok"]
    git_calls = [kw for argv, kw in popen.calls if Path(argv[0]).name == "git"]
    assert grok_calls and all(
        kw["cwd"] != str(w["snapshot"]) and "sanitized-grok" in kw["cwd"] for kw in grok_calls
    )
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
