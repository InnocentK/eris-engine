"""Phase 0 harness - thin CLI over ``eris``.

* ``preflight``  - the doctor checks (names, never values).
* ``dry-run``    - argv / env NAMES / cwd / idempotency key for one worker.
                   Zero subprocesses.
* ``invoke``     - ONE worker, propose stage (Milestone 1).
* ``run``        - ONE cell: one task, one repeat, one arm (Milestone 2b).
                   ``--resume <run_id>`` continues an unfinished cell.
* ``campaign``   - every cell of a corpus under ``runs/<campaign_id>/``,
                   task-major -> repeat -> arms in the fixed order;
                   ``--dry-run`` prints the order; ``campaign status`` is
                   read-only (no writer, no lock).

Exit codes: 0 ok; 2 config/policy; 3 incomplete panel; 4 run-level error;
5 STOP/budget; 6 contaminated; 7 score gate (``eval/score.py``); 130 SIGINT.
Stderr carries one JSON line per stage event; stdout the machine summary.

The SIGINT handler lives HERE and only here (never under ``src/``): the first
Ctrl-C kills the worker group through the launcher's existing path, records
``invocation.finished`` (status failed, error ``interrupted``, cost not
known), ``run.interrupted`` and the campaign's ``cell.interrupted``, and
exits 130. The run dir is left unfinalized so ``--resume`` can continue it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from eris.arms import (
    ARM_ORDER,
    CellSpec,
    Prior,
    ResumeRefused,
    finish_arm,
    kill_stale_groups,
    load_prior,
    remove_stale_scratch,
    run_arm,
    stop_file_paths,
)
from eris.cache import Cache, CacheUnsupported
from eris.doctor import run_doctor
from eris.evidence import SnapshotGuard, TaskSpec, VerifyEnv, verify_scratch
from eris.launch import (
    KillPg,
    LaunchRefused,
    PopenFactory,
    WorkerCall,
    WorkerResult,
    idempotency_key,
    invocation_id_for,
    make_private_dir,
    plan_call,
    run_worker,
)
from eris.ledger import LedgerCorrupt, LedgerView, cost_totals
from eris.policy import LoadedPolicy, PolicyError, load_policy
from eris.redact import CredentialFileError, Redactor, load_credential_values, parse_dotenv
from eris.retry import BudgetLedger, stop_requested
from eris.sanitize import (
    PRISTINE_PROFILE,
    SanitizeCleanupError,
    SanitizeProfile,
    sanitized_copy,
    tree_sha256,
)
from eris.scan import PatternSet, build_patterns, scan_and_record
from eris.schemas import (
    Arm,
    ArmStatus,
    CostRecord,
    Event,
    Invocation,
    Stage,
    Transport,
    WorkerStatus,
    now_ts,
    sha256_hex,
)
from eris.snapshot import read_head_sha
from eris.stages import StageContext, load_prompt_files, store_pending_cache
from eris.version import __version__
from eris.writer import LedgerInvalid, RunExists, RunWriter, WriterError, WriterLocked

DEFAULT_POLICY = "policies/default.yaml"
DEFAULT_PROMPTS = "eval/prompts"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_INCOMPLETE = 3
EXIT_RUN_ERROR = 4
EXIT_STOP = 5
EXIT_CONTAMINATED = 6
EXIT_GATE = 7
EXIT_SIGINT = 130

# Stage events streamed to stderr (one JSON line each, reliability R18 fields).
STREAMED_PREFIXES = (
    "run.",
    "arm.",
    "step.",
    "stage.",
    "cell.",
    "budget.",
    "retry.scheduled",
    "worker.absent",
    "scan.result",
    "invocation.reused",
    "invocation.abandoned",
    "campaign.",
    "pack.",
    "verify.refused",
    "verify.stopped",
)
STREAM_FIELDS = (
    "stage",
    "step",
    "worker_id",
    "role",
    "reason",
    "status",
    "arm",
    "where",
    "contaminated",
    "scan_incomplete",
)


def validate_run_id(run_id: str) -> str:
    """A run id is a single path component: validated BEFORE any path is built."""
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError(f"run id {run_id!r} must match {RUN_ID_RE.pattern}")
    return run_id


def default_run_id(task_id: str, worker: str, repeat_index: int) -> str:
    stamp = now_ts()[:19].replace(":", "").replace("-", "")
    raw = f"{task_id}-{worker}-r{repeat_index}-{stamp}"
    return validate_run_id(re.sub(r"[^A-Za-z0-9_-]", "_", raw)[:64])


def run_dir_for(runs_dir: Path, run_id: str) -> Path:
    """``runs_dir/run_id`` with the id validated and containment re-checked."""
    validate_run_id(run_id)
    root = Path(runs_dir).resolve()
    run_dir = (root / run_id).resolve()
    if run_dir.parent != root:
        raise ValueError(f"run dir {run_dir} is not directly under {root}")
    return run_dir


def _read_env_values(env_file: Path) -> dict[str, str]:
    if not env_file.exists():
        return {}
    return parse_dotenv(env_file.read_text(encoding="utf-8"))


def _credential_paths(loaded: LoadedPolicy, home: Path) -> list[Path]:
    out: list[Path] = []
    for raw in loaded.policy.credential_files:
        out.append(Path(raw.replace("~", str(home), 1)) if raw.startswith("~") else Path(raw))
    return out


def _build_call(
    loaded: LoadedPolicy,
    args: argparse.Namespace,
    secrets: dict[str, str],
    home: Path,
    scratch_dir: Path | None,
) -> WorkerCall:
    worker = loaded.policy.workers.get(args.worker)
    if worker is None:
        raise LaunchRefused(f"worker {args.worker!r} is not declared in the policy")
    if worker.transport is not Transport.CLI:
        raise LaunchRefused("api workers are Milestone 2")
    prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    snapshot = Path(args.snapshot).resolve()
    if not snapshot.is_dir():
        raise LaunchRefused(f"snapshot {snapshot} is not a directory")
    return WorkerCall(
        worker_id=args.worker,
        policy=worker,
        prompt=prompt,
        cwd=snapshot,
        task_id=args.task_id,
        stage=Stage(args.stage),
        repeat_index=args.repeat_index,
        policy_sha256=loaded.sha256,
        scratch_dir=scratch_dir,
        home=str(home),
        tmpdir=str(scratch_dir / "tmp") if scratch_dir else "/tmp",
        path_env=loaded.policy.path_env,
        secrets={k: v for k, v in secrets.items() if k in worker.env_allow},
        snapshot_sha=read_head_sha(snapshot),  # filesystem-observed, never user-supplied
    )


def cmd_preflight(args: argparse.Namespace, out: IO[str], home: Path) -> int:
    report = run_doctor(
        policy_path=Path(args.policy),
        env_file=Path(args.env_file),
        probe=bool(args.probe),
        home=home,
    )
    print(report.render(), file=out)
    return 0 if report.ok else 1


def cmd_dry_run(args: argparse.Namespace, out: IO[str], home: Path) -> int:
    loaded = load_policy(Path(args.policy))
    secrets = _read_env_values(Path(args.env_file))
    call = _build_call(loaded, args, secrets, home, None)
    try:
        plan = plan_call(call)
    except LaunchRefused as exc:
        print(json.dumps({"worker": args.worker, "status": "refused", "error": str(exc)}), file=out)
        return 2
    worker = call.policy
    summary: dict[str, Any] = {
        "worker": args.worker,
        "provider": worker.provider,
        "model_requested": worker.model,
        "executable": plan.executable,
        "pinned": worker.pinned,
        "argv": plan.argv,
        "env_names": sorted(plan.env),
        "cwd": str(plan.cwd),
        "idempotency_key": plan.idempotency_key,
        "snapshot_sha": call.snapshot_sha,
        "timeout_s": worker.timeout_s,
        "max_stdout_bytes": worker.max_stdout_bytes,
        "policy_sha256": loaded.sha256,
    }
    print(json.dumps(summary, indent=2, sort_keys=True), file=out)
    return 0


def cmd_invoke(
    args: argparse.Namespace, out: IO[str], home: Path, popen: PopenFactory, killpg: KillPg
) -> int:
    run_id = (
        args.run_id
        if args.run_id is not None
        else default_run_id(args.task_id, args.worker, args.repeat_index)
    )
    run_dir = run_dir_for(Path(args.runs_dir), run_id)  # validated before anything is created
    loaded = load_policy(Path(args.policy))
    env_values = _read_env_values(Path(args.env_file))
    creds = load_credential_values(_credential_paths(loaded, home))  # raises if unparsable
    redactor = Redactor(list(env_values.values()) + creds.values)
    scratch_root = Path(loaded.policy.scratch_dir)
    if _is_under(scratch_root, Path(args.runs_dir)):
        raise LaunchRefused(f"scratch_dir {scratch_root} must not be under the runs dir")
    sweep_scratch(scratch_root, sys.stderr)
    scratch = scratch_root / run_id  # path only; created AFTER the writer holds the lock
    call = _build_call(loaded, args, env_values, home, scratch)
    plan_key = plan_call(call).idempotency_key if call.policy.executable else None
    with RunWriter(run_dir, redactor, run_id=run_id) as writer, _scratch_root(scratch):
        (scratch / "tmp").mkdir()
        started = now_ts()
        writer.append(
            "run.started",
            {
                "eris_version": __version__,
                "policy_path": str(loaded.path),
                "policy_sha256": loaded.sha256,
                "pins_sha256": loaded.pins_sha256,
                "worker_id": args.worker,
                "task_id": args.task_id,
                "stage": args.stage,
                "repeat_index": args.repeat_index,
                "snapshot": str(call.cwd),
                "snapshot_sha": call.snapshot_sha,
                "idempotency_key": plan_key,
                "credential_warnings": creds.warnings,
            },
        )
        result = run_worker(call, popen=popen, killpg=killpg)
        stdout_ref = writer.put_blob(result.stdout) if result.stdout else None
        stderr_ref = writer.put_blob(result.stderr) if result.stderr else None
        output_ref = writer.put_blob(result.output_file) if result.output_file else None
        invocation = Invocation(
            invocation_id=invocation_id_for(result.idempotency_key, 1),
            task_id=args.task_id,
            worker_id=args.worker,
            provider=result.provider,
            transport=Transport.CLI,
            model_requested=result.model_requested,
            model_executed=result.model_executed,
            stage=Stage(args.stage),
            repeat_index=args.repeat_index,
            attempt=1,
            idempotency_key=result.idempotency_key,
            argv=result.argv,
            env_names=result.env_names,
            cwd=result.cwd,
            executable_sha256=result.executable_sha256,
            cli_version=None,
            started_at=started,
            finished_at=now_ts(),
            duration_ms=result.duration_ms,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            status=result.status,
            error=result.error,
            usage=result.usage,
            cost_usd=result.cost_usd,
            stdout_sha256=stdout_ref.sha256 if stdout_ref else None,
            stderr_sha256=stderr_ref.sha256 if stderr_ref else None,
            output_file_sha256=output_ref.sha256 if output_ref else None,
            output_file_truncated=result.output_file_truncated,
            output_file_size=result.output_file_size,
            cleanup_error=result.cleanup_error,
            conversation_id=result.conversation_id,
            worker_reported_duration_ms=result.worker_reported_duration_ms,
            prompt_sha256=sha256_hex(call.prompt.encode("utf-8")),
            warning=result.warning,
            pgid=result.pgid,
        )
        writer.append("invocation.finished", invocation)
        if result.cleanup_error:
            # A raw worker file MAY remain under the run's scratch dir: run-level error, never silent.
            writer.append(
                "run.error",
                {"kind": "scratch_cleanup_failed", "error": result.cleanup_error},
            )
        writer.append(
            "cost",
            CostRecord(
                invocation_id=invocation.invocation_id,
                attempt=1,
                cost_usd=result.cost_usd,
                usage=result.usage,
                counted=True,
            ),
        )
        if result.status is WorkerStatus.OK:
            writer.append(
                "proposal.raw",
                {
                    "worker_id": args.worker,
                    "model_executed": result.model_executed,
                    "parse_mode": result.parse_mode,
                    "text": result.text,
                    "structured": result.structured,
                    "output_file_sha256": output_ref.sha256 if output_ref else None,
                    "output_file_truncated": result.output_file_truncated,
                    "output_file_size": result.output_file_size,
                },
            )
        else:
            writer.append(
                "worker.absent",
                {"worker_id": args.worker, "status": result.status.value, "error": result.error},
            )
        manifest = writer.finalize(
            {
                "worker_id": args.worker,
                "status": result.status.value,
                "cleanup_error": result.cleanup_error,
            }
        )
    summary = {
        "run_dir": str(run_dir),
        "manifest": str(manifest),
        "worker": args.worker,
        "status": result.status.value,
        "error": result.error,
        "model_executed": result.model_executed,
        "cost_usd": result.cost_usd,
        "duration_ms": result.duration_ms,
        "cleanup_error": result.cleanup_error,
        "redactions": {
            k: v
            for ref in (stdout_ref, stderr_ref, output_ref)
            if ref
            for k, v in ref.redaction_counts.items()
        },
    }
    print(json.dumps(summary, indent=2, sort_keys=True), file=out)
    if result.cleanup_error:
        return 4  # run-level error even when the worker itself succeeded
    return 0 if result.status is WorkerStatus.OK else 3


# --------------------------------------------------------------------------- M2b: cells


class Interrupted(Exception):
    """Raised by the SIGINT handler (installed only by ``run``/``campaign``)."""


@dataclass
class Harness:
    """Everything a cell needs, loaded once per command."""

    loaded: LoadedPolicy
    redactor: Redactor
    secrets: dict[str, str]
    home: Path
    prompts_dir: Path
    runs_dir: Path
    popen: PopenFactory
    killpg: KillPg
    err: IO[str]
    cache: Cache | None
    credential_warnings: list[str] = field(default_factory=list)
    interrupted: bool = False
    sleep: Callable[[float], None] = time.sleep
    current_call: WorkerCall | None = None
    swept: list[str] = field(default_factory=list)

    @property
    def policy(self) -> Any:
        return self.loaded.policy

    @property
    def scratch_dir(self) -> Path:
        return Path(self.policy.scratch_dir)

    def scratch_for(self, run_id: str) -> Path:
        """``scratch_dir/<run_id>``: every ephemeral file of a run, never under runs/."""
        root = self.scratch_dir
        if _is_under(root, self.runs_dir):
            raise LaunchRefused(f"scratch_dir {root} must not be under the runs dir")
        return root / validate_run_id(run_id)


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def sweep_scratch(scratch_dir: Path, err: IO[str]) -> list[str]:
    """At startup: remove every orphaned entry under ``scratch_dir`` (a
    previous crash left it); log what was removed. Symlinks are unlinked,
    never followed."""
    removed: list[str] = []
    if not scratch_dir.is_dir() or scratch_dir.is_symlink():
        return removed
    for entry in sorted(scratch_dir.iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            shutil.rmtree(entry)
        removed.append(entry.name)
    if removed:
        line = {"status": "scratch_swept", "scratch_dir": str(scratch_dir), "removed": removed}
        print(json.dumps(line), file=err, flush=True)
    return removed


def load_harness(
    args: argparse.Namespace, home: Path, popen: PopenFactory, killpg: KillPg, err: IO[str]
) -> Harness:
    loaded = load_policy(Path(args.policy))
    env_values = _read_env_values(Path(args.env_file))
    creds = load_credential_values(_credential_paths(loaded, home))  # raises if unparsable
    runs_dir = Path(getattr(args, "runs_dir", None) or loaded.policy.runs_dir)
    cache: Cache | None = None
    if not getattr(args, "no_cache", False):
        cache_dir = Path(getattr(args, "cache_dir", None) or loaded.policy.cache_dir)
        try:
            cache = Cache(
                cache_dir,
                runs_dir=runs_dir,
                reuse_across_campaigns=bool(getattr(args, "reuse_across_campaigns", False)),
                fresh=bool(getattr(args, "fresh", False)),
            )
        except CacheUnsupported as exc:
            print(json.dumps({"status": "warning", "cache": str(exc)}), file=err)
    h = Harness(
        loaded=loaded,
        redactor=Redactor(list(env_values.values()) + creds.values),
        secrets=env_values,
        home=home,
        prompts_dir=Path(getattr(args, "prompts_dir", None) or DEFAULT_PROMPTS),
        runs_dir=runs_dir,
        popen=popen,
        killpg=killpg,
        err=err,
        cache=cache,
        credential_warnings=list(creds.warnings),
    )
    if _is_under(h.scratch_dir, runs_dir):
        raise PolicyError(f"scratch_dir {h.scratch_dir} must not be under the runs dir")
    h.swept = sweep_scratch(h.scratch_dir, err)
    return h


def load_task(task_file: Path) -> tuple[TaskSpec, Path]:
    """``task.json`` + the snapshot directory it names (relative to the file)."""
    task = TaskSpec.model_validate_json(Path(task_file).read_bytes())
    snapshot = Path(task.snapshot)
    if not snapshot.is_absolute():
        snapshot = Path(task_file).resolve().parent / snapshot
    snapshot = snapshot.resolve()
    if not snapshot.is_dir():
        raise LaunchRefused(f"snapshot {snapshot} is not a directory")
    return task, snapshot


def scan_patterns_for(
    task_file: Path, snapshot: Path, home: Path, run_dir: Path, policy: Any
) -> PatternSet:
    """Patterns from the sibling ``key.json`` (fix hunks, extra strings,
    source repo) + the fixed markers. The key is opened for THIS ONLY."""
    key_path = Path(task_file).resolve().parent / "key.json"
    fix_hunks: list[str] = []
    extra: list[str] = []
    source_repo: str | None = None
    if key_path.is_file():
        key = json.loads(key_path.read_bytes())
        scan = key.get("scan", {}) if isinstance(key, dict) else {}
        fix_hunks = [str(x) for x in scan.get("fix_hunk_lines", [])]
        extra = [str(x) for x in scan.get("extra_strings", [])]
        src = key.get("source_repo") if isinstance(key, dict) else None
        source_repo = str(src) if src else None
    return build_patterns(
        snapshot_root=snapshot,
        home=home,
        source_repo=source_repo,
        fix_hunk_lines=fix_hunks,
        extra_strings=extra,
        policy_patterns=list(policy.scan.patterns_from_policy),
        known_texts=[str(snapshot), str(run_dir), str(run_dir.parent)],
    )


def _stream(err: IO[str], run_id: str) -> Callable[[Event], None]:
    def on_event(event: Event) -> None:
        if not event.kind.startswith(STREAMED_PREFIXES):
            return
        line: dict[str, Any] = {
            "ts": event.ts,
            "run_id": run_id,
            "seq": event.seq,
            "kind": event.kind,
        }
        for key in STREAM_FIELDS:
            if key in event.payload:
                line[key] = event.payload[key]
        print(json.dumps(line, sort_keys=True), file=err, flush=True)

    return on_event


@contextmanager
def sigint_handler(h: Harness) -> Iterator[None]:
    """Installed ONLY by ``run``/``campaign``; restored afterwards."""

    def handler(signum: int, frame: Any) -> None:
        h.interrupted = True
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGINT, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def cell_spec_from_args(h: Harness, task: TaskSpec, args: argparse.Namespace, arm: Arm) -> CellSpec:
    workers = h.policy.workers
    panel = (
        tuple(args.panel.split(","))
        if getattr(args, "panel", None)
        else tuple(
            w for w, p in workers.items() if p.transport is Transport.CLI and w != args.judge
        )
    )
    critics = tuple(args.critics.split(",")) if getattr(args, "critics", None) else panel
    judge = args.judge if arm is not Arm.SINGLE else None
    for w in (*panel, *critics, *((judge,) if judge else ())):
        if w not in workers:
            raise LaunchRefused(f"worker {w!r} is not declared in the policy")
    return CellSpec(
        arm=arm,
        task=task,
        repeat_index=args.repeat_index,
        panel=panel,
        critics=critics,
        judge=judge,
    )


@dataclass
class CellOutcome:
    run_id: str
    exit_code: int
    status: str
    contaminated: bool = False
    stopped: str | None = None
    error: str | None = None


def run_cell(
    h: Harness,
    spec: CellSpec,
    task_file: Path,
    snapshot: Path,
    *,
    run_dir: Path,
    campaign_id: str | None,
    resume: bool,
    campaign_budget: tuple[float, float] = (0.0, 0.0),
) -> CellOutcome:
    """One cell, start to finalize. Never raises on worker behaviour; writer
    errors, refusals and interrupts are turned into exit codes."""
    run_id = run_dir.name
    policy = h.policy
    stop_paths = stop_file_paths(h.runs_dir, campaign_id)
    try:
        writer = RunWriter(
            run_dir, h.redactor, run_id=run_id, resume=resume, on_event=_stream(h.err, run_id)
        ).open()
    except RunExists as exc:
        return CellOutcome(run_id, EXIT_CONFIG, "exists", error=str(exc))
    except LedgerInvalid as exc:
        return CellOutcome(run_id, EXIT_RUN_ERROR, "corrupt", error=str(exc))
    except WriterLocked as exc:
        return CellOutcome(run_id, EXIT_RUN_ERROR, "locked", error=str(exc))
    prompts = load_prompt_files(h.prompts_dir)
    snapshot_sha = read_head_sha(snapshot)
    original_tree = tree_sha256(snapshot)
    outcome = CellOutcome(run_id, EXIT_OK, "running")
    scratch = h.scratch_for(run_id)
    try:
        prior: Prior | None = None
        if resume:
            view = LedgerView.from_path(writer.events_path)
            prior = load_prior(view, writer, per_call_usd=policy.budgets.per_call_usd)
            killed = kill_stale_groups(prior.stale_pgids, killpg=h.killpg)
            removed = remove_stale_scratch(scratch)
            writer.append(
                "run.resumed",
                {
                    "abandoned": len(prior.abandoned),
                    "killed_pgids": killed,
                    "stale_scratch": removed,
                    "corrupt_blobs": list(writer.corrupt_blobs),
                },
            )
            base_known, base_reserved = _spent_from_view(view)
        else:
            base_known, base_reserved = 0.0, 0.0
        make_private_dir(scratch)  # after the lock; refuses a planted entry; never under runs/
        (scratch / "tmp").mkdir()
        judge_dir = scratch / "judge-empty"  # the judge's cwd/workspace: EMPTY, never the snapshot
        judge_dir.mkdir()
        budget = BudgetLedger(
            per_call_usd=policy.budgets.per_call_usd,
            run_ceiling_usd=policy.budgets.per_run_usd,
            campaign_ceiling_usd=policy.budgets.per_campaign_usd,
            spent_known_usd=base_known,
            reserved_usd=base_reserved,
            campaign_spent_known_base_usd=campaign_budget[0],
            campaign_reserved_base_usd=campaign_budget[1],
        )
        writer.append(
            "run.started",
            {
                "eris_version": __version__,
                "policy_path": str(h.loaded.path),
                "policy_sha256": h.loaded.sha256,
                "pins_sha256": h.loaded.pins_sha256,
                "task_file": str(task_file),
                "task_id": spec.task.task_id,
                "category": spec.task.category.value,
                "arm": spec.arm.value,
                "repeat_index": spec.repeat_index,
                "panel": list(spec.panel),
                "critics": list(spec.critics),
                "judge": spec.judge,
                "snapshot": str(snapshot),
                "snapshot_sha": snapshot_sha,
                "snapshot_tree_sha256": original_tree,
                "scratch_dir": str(scratch),
                "prompt_files": {role: p.sha256 for role, p in sorted(prompts.items())},
                "containment": policy.containment,
                "campaign_id": campaign_id,
                "resume": resume,
                "credential_warnings": h.credential_warnings,
            },
        )
        patterns = scan_patterns_for(task_file, snapshot, h.home, run_dir, policy)
        writer.append(
            "scan.patterns",
            {
                "patterns_sha256": patterns.patterns_sha256,
                "pattern_count": patterns.count,
                "dropped": dict(patterns.dropped_reasons),
            },
        )
        profile = SanitizeProfile.from_policy(policy)
        sanitized: dict[str, Path] = {}

        def runner(call: WorkerCall) -> WorkerResult:
            h.current_call = call

            def spawned(pgid: int) -> None:
                writer.append(
                    "invocation.spawned",
                    {
                        "idempotency_key": idempotency_key(call),
                        "worker_id": call.worker_id,
                        "stage": call.stage.value,
                        "pgid": pgid,
                    },
                )

            # current_call stays set if the call is interrupted: the SIGINT
            # recorder needs it after the exception has unwound to run_cell
            result = run_worker(call, popen=h.popen, killpg=h.killpg, on_spawn=spawned)
            h.current_call = None
            return result

        def stop_check() -> bool:
            return h.interrupted or stop_requested(*stop_paths)

        with (
            verify_scratch(writer, scratch) as scratch_home,
            sanitized_copy(
                snapshot, scratch, profile=PRISTINE_PROFILE, worker_id="verify", name="pristine"
            ) as (pristine, pristine_record),
            _sanitized_copies(writer, spec, policy, snapshot, scratch, profile, sanitized),
        ):
            writer.append("snapshot.pristine", pristine_record)
            env = VerifyEnv(
                policy=policy,
                snapshot_root=pristine,  # verification on a PRISTINE copy, never the original
                scratch_home=scratch_home,
                popen=h.popen,
                killpg=h.killpg,
                guard=SnapshotGuard.over(pristine),
            )
            ctx = StageContext(
                writer=writer,
                policy=policy,
                policy_sha256=h.loaded.sha256,
                task=spec.task,
                repeat_index=spec.repeat_index,
                snapshot_sha=snapshot_sha,
                prompts=prompts,
                budget=budget,
                stop_check=stop_check,
                sleep=h.sleep,
                cwd_for=lambda w, role: (
                    judge_dir
                    if role in ("adjudicator", "summarizer")
                    else sanitized.get(w, snapshot)
                ),
                scratch_dir=scratch,
                home=str(h.home),
                path_env=policy.path_env,
                secrets=h.secrets,
                runner=runner,
                cache=h.cache,
                campaign_id=campaign_id,
            )
            try:
                draft = run_arm(spec, ctx, env, prior=prior)
            except KeyboardInterrupt:
                _record_interrupt(h, writer, ctx)
                raise
            scan = scan_and_record(writer, patterns)
            hits: dict[str, int] = {}
            for hit in scan.hits:
                if hit.where.startswith("blob:"):
                    hits[hit.where[5:]] = hits.get(hit.where[5:], 0) + hit.count
            store_pending_cache(ctx, hits)
            view = LedgerView.from_path(writer.events_path)
            record = finish_arm(
                draft, ctx, view, contaminated=scan.contaminated, containment=policy.containment
            )
        if tree_sha256(snapshot) != original_tree:
            writer.append(
                "run.error",
                {
                    "kind": "snapshot_modified",
                    "error": "the ORIGINAL snapshot changed during the run",
                },
            )
        totals = cost_totals(LedgerView.from_path(writer.events_path))
        run_errors = [e for e in LedgerView.from_path(writer.events_path).payloads("run.error")]
        writer.finalize(
            {
                "arm": spec.arm.value,
                "status": record.status.value,
                "contaminated": record.contaminated,
                "scan_incomplete": scan.scan_incomplete,
                "stopped": draft.stopped,
                "spent_known_usd": budget.spent_known_usd,
                "spent_reserved_usd": budget.reserved_usd,
                "cost_attributed_usd": totals.attributed_usd,
                "run_errors": len(run_errors),
            }
        )
        outcome.contaminated = record.contaminated
        outcome.stopped = draft.stopped
        outcome.status = record.status.value
        if run_errors:
            outcome.exit_code, outcome.status = EXIT_RUN_ERROR, "run_error"
        elif draft.stopped is not None:
            outcome.exit_code = EXIT_STOP
        elif record.contaminated or scan.scan_incomplete:
            outcome.exit_code = EXIT_CONTAMINATED
        elif record.status is not ArmStatus.COMPLETE:
            outcome.exit_code = EXIT_INCOMPLETE
        return outcome
    except KeyboardInterrupt:
        outcome.exit_code, outcome.status = EXIT_SIGINT, "interrupted"
        return outcome
    except (LaunchRefused, ResumeRefused, LedgerCorrupt, PolicyError) as exc:
        _safe_append(writer, "run.error", {"kind": type(exc).__name__, "error": str(exc)})
        outcome.exit_code, outcome.status, outcome.error = EXIT_CONFIG, "refused", str(exc)
        return outcome
    except (SanitizeCleanupError, OSError, WriterError) as exc:
        _safe_append(writer, "run.error", {"kind": type(exc).__name__, "error": str(exc)})
        outcome.exit_code, outcome.status, outcome.error = EXIT_RUN_ERROR, "run_error", str(exc)
        return outcome
    finally:
        if scratch.exists() or scratch.is_symlink():
            try:
                shutil.rmtree(scratch)
            except OSError as exc:
                _safe_append(
                    writer, "run.error", {"kind": "scratch_cleanup_failed", "error": str(exc)}
                )
                outcome.exit_code, outcome.status = EXIT_RUN_ERROR, "run_error"
        writer.close()


@contextmanager
def _scratch_root(scratch: Path) -> Iterator[Path]:
    """Create the run's private scratch root (refusing a planted entry or
    symlink) and remove it in ``finally`` whatever happens."""
    make_private_dir(scratch)
    try:
        yield scratch
    finally:
        shutil.rmtree(scratch, ignore_errors=False)


def _safe_append(writer: RunWriter, kind: str, payload: dict[str, Any]) -> None:
    try:
        writer.append(kind, payload)
    except WriterError:
        pass  # the original error is what the caller reports


def _spent_from_view(view: LedgerView) -> tuple[float, float]:
    totals = cost_totals(view)
    return totals.known_usd, totals.reserved_usd


@contextmanager
def _sanitized_copies(
    writer: RunWriter,
    spec: CellSpec,
    policy: Any,
    snapshot: Path,
    scratch: Path,
    profile: SanitizeProfile,
    out: dict[str, Path],
) -> Iterator[None]:
    """A private sanitized copy per worker with ``sanitize_snapshot`` (nested
    context managers; every copy is removed in finally)."""
    from contextlib import ExitStack

    workers = sorted({*spec.panel, *spec.critics})
    with ExitStack() as stack:
        for worker_id in workers:
            if not policy.workers[worker_id].sanitize_snapshot:
                continue
            copy_root, record = stack.enter_context(
                sanitized_copy(snapshot, scratch, profile=profile, worker_id=worker_id)
            )
            writer.append("snapshot.sanitized", record)
            out[worker_id] = copy_root
        yield


def _record_interrupt(h: Harness, writer: RunWriter, ctx: StageContext) -> None:
    """First SIGINT: the launcher already killed the group; record the
    in-flight attempt as failed/interrupted with an unknown cost."""
    call = h.current_call
    if call is not None:
        key = idempotency_key(call)
        prior = [
            p
            for p in LedgerView.from_path(writer.events_path).payloads("invocation.finished")
            if p.get("idempotency_key") == key
        ]
        attempt = len(prior) + 1
        ts = now_ts()
        inv = Invocation(
            invocation_id=invocation_id_for(key, attempt),
            task_id=call.task_id,
            worker_id=call.worker_id,
            provider=call.policy.provider,
            transport=Transport.CLI,
            model_requested=call.policy.model,
            model_executed=None,
            stage=call.stage,
            repeat_index=call.repeat_index,
            attempt=attempt,
            idempotency_key=key,
            argv=[],
            env_names=[],
            cwd=str(call.cwd),
            executable_sha256=None,
            cli_version=None,
            started_at=ts,
            finished_at=ts,
            duration_ms=None,
            exit_code=None,
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
            status=WorkerStatus.FAILED,
            error="interrupted",
            usage=None,
            cost_usd=None,
            stdout_sha256=None,
            stderr_sha256=None,
            prompt_sha256=sha256_hex(call.prompt.encode("utf-8")),
        )
        writer.append("invocation.finished", inv)
        writer.append(
            "cost",
            CostRecord(
                invocation_id=inv.invocation_id,
                attempt=attempt,
                cost_usd=ctx.budget.per_call_usd,
                counted=True,
                estimated=True,
                cost_known=False,
            ),
        )
    writer.append(
        "run.interrupted", {"signal": "SIGINT", "worker_id": call.worker_id if call else None}
    )


def cmd_run(
    args: argparse.Namespace,
    out: IO[str],
    err: IO[str],
    home: Path,
    popen: PopenFactory,
    killpg: KillPg,
) -> int:
    h = load_harness(args, home, popen, killpg, err)
    task, snapshot = load_task(Path(args.task_file))
    arm = Arm(args.arm)
    spec = cell_spec_from_args(h, task, args, arm)
    run_id = validate_run_id(args.resume or args.run_id or spec.run_id)
    run_dir = run_dir_for(h.runs_dir, run_id)
    with sigint_handler(h):
        outcome = run_cell(
            h,
            spec,
            Path(args.task_file),
            snapshot,
            run_dir=run_dir,
            campaign_id=None,
            resume=args.resume is not None,
        )
    print(json.dumps(_outcome_summary(outcome, run_dir), indent=2, sort_keys=True), file=out)
    return outcome.exit_code


def _outcome_summary(o: CellOutcome, run_dir: Path) -> dict[str, Any]:
    return {
        "run_dir": str(run_dir),
        "run_id": o.run_id,
        "status": o.status,
        "exit_code": o.exit_code,
        "contaminated": o.contaminated,
        "stopped": o.stopped,
        "error": o.error,
    }


# --------------------------------------------------------------------------- campaign


def campaign_cells(
    h: Harness,
    task_files: Sequence[Path],
    repeats: int,
    arms: Sequence[Arm],
    args: argparse.Namespace,
) -> list[tuple[CellSpec, Path, Path]]:
    """Task-major -> repeat -> arms in the fixed order; ``single`` expands to
    one cell per panel worker."""
    cells: list[tuple[CellSpec, Path, Path]] = []
    ordered = [a for a in ARM_ORDER if a in arms]
    for task_file in task_files:
        task, snapshot = load_task(task_file)
        for repeat in range(repeats):
            ns = argparse.Namespace(**{**vars(args), "repeat_index": repeat})
            for arm in ordered:
                base = cell_spec_from_args(
                    h, task, ns, arm if arm is not Arm.SINGLE else Arm.INDEP_VERIFY
                )
                if arm is Arm.SINGLE:
                    for worker in base.panel:
                        cells.append(
                            (
                                CellSpec(Arm.SINGLE, task, repeat, (worker,), (), None),
                                task_file,
                                snapshot,
                            )
                        )
                else:
                    cells.append(
                        (
                            CellSpec(arm, task, repeat, base.panel, base.critics, base.judge),
                            task_file,
                            snapshot,
                        )
                    )
    return cells


def discover_tasks(corpus: Path) -> list[Path]:
    return sorted(p for p in Path(corpus).glob("*/task.json") if p.is_file())


def _cell_state(cell_dir: Path) -> str:
    if (cell_dir / "manifest.json").is_file():
        return "finalized"
    if (cell_dir / "events.jsonl").is_file():
        return "unfinished"
    return "pending"


def cmd_campaign(
    args: argparse.Namespace,
    out: IO[str],
    err: IO[str],
    home: Path,
    popen: PopenFactory,
    killpg: KillPg,
) -> int:
    h = load_harness(args, home, popen, killpg, err)
    campaign_id = validate_run_id(args.campaign_id)
    campaign_dir = run_dir_for(h.runs_dir, campaign_id)
    task_files = (
        [Path(t) for t in args.task_file] if args.task_file else discover_tasks(Path(args.corpus))
    )
    if not task_files:
        raise LaunchRefused("no task.json found")
    arms = [Arm(a) for a in args.arms.split(",")] if args.arms else list(ARM_ORDER)
    cells = campaign_cells(h, task_files, args.repeats, arms, args)
    order = [
        {
            "run_id": s.run_id,
            "task_id": s.task.task_id,
            "repeat_index": s.repeat_index,
            "arm": s.arm.value,
            "panel": list(s.panel),
            "state": _cell_state(campaign_dir / s.run_id),
        }
        for s, _t, _s in cells
    ]
    if args.dry_run:
        print(
            json.dumps({"campaign_id": campaign_id, "cells": order}, indent=2, sort_keys=True),
            file=out,
        )
        return EXIT_OK
    stop_paths = stop_file_paths(h.runs_dir, campaign_id)
    results: list[dict[str, Any]] = []
    exit_code = EXIT_OK
    with sigint_handler(h):
        try:
            writer = RunWriter(
                campaign_dir,
                h.redactor,
                run_id=campaign_id,
                resume=bool(args.resume),
                on_event=_stream(h.err, campaign_id),
            ).open()
        except (RunExists, LedgerInvalid, WriterLocked) as exc:
            print(json.dumps({"status": "error", "error": str(exc)}), file=out)
            return EXIT_CONFIG if isinstance(exc, RunExists) else EXIT_RUN_ERROR
        try:
            writer.append(
                "campaign.started",
                {
                    "campaign_id": campaign_id,
                    "cells": order,
                    "resume": bool(args.resume),
                    "policy_sha256": h.loaded.sha256,
                    "eris_version": __version__,
                },
            )
            for spec, task_file, snapshot in cells:
                cell_dir = campaign_dir / spec.run_id
                state = _cell_state(cell_dir)
                if state == "finalized":
                    writer.append("cell.skipped", {"run_id": spec.run_id, "reason": "finalized"})
                    continue
                if stop_requested(*stop_paths) or h.interrupted:
                    writer.append("cell.skipped", {"run_id": spec.run_id, "reason": "stop"})
                    exit_code = EXIT_STOP
                    continue
                known, reserved = _campaign_spent(campaign_dir, cells)
                writer.append(
                    "cell.started",
                    {
                        "run_id": spec.run_id,
                        "arm": spec.arm.value,
                        "task_id": spec.task.task_id,
                        "repeat_index": spec.repeat_index,
                        "resume": state == "unfinished",
                    },
                )
                try:
                    outcome = run_cell(
                        h,
                        spec,
                        task_file,
                        snapshot,
                        run_dir=cell_dir,
                        campaign_id=campaign_id,
                        resume=state == "unfinished",
                        campaign_budget=(known, reserved),
                    )
                except KeyboardInterrupt:
                    writer.append("cell.interrupted", {"run_id": spec.run_id})
                    exit_code = EXIT_SIGINT
                    break
                results.append({"run_id": spec.run_id, **_outcome_summary(outcome, cell_dir)})
                writer.append(
                    "cell.finished",
                    {
                        "run_id": spec.run_id,
                        "status": outcome.status,
                        "exit_code": outcome.exit_code,
                        "contaminated": outcome.contaminated,
                        "stopped": outcome.stopped,
                    },
                )
                if outcome.exit_code == EXIT_SIGINT:
                    writer.append("cell.interrupted", {"run_id": spec.run_id})
                    exit_code = EXIT_SIGINT
                    break
                if outcome.exit_code == EXIT_STOP and outcome.stopped == "stop":
                    exit_code = EXIT_STOP
                    break
                if outcome.exit_code != EXIT_OK and exit_code == EXIT_OK:
                    exit_code = outcome.exit_code
            writer.append("campaign.finished", {"exit_code": exit_code, "cells": len(results)})
            if exit_code != EXIT_SIGINT:
                writer.finalize({"exit_code": exit_code, "cells": results})
        finally:
            writer.close()
    print(
        json.dumps(
            {"campaign_id": campaign_id, "exit_code": exit_code, "cells": results},
            indent=2,
            sort_keys=True,
        ),
        file=out,
    )
    return exit_code


def _campaign_spent(
    campaign_dir: Path, cells: Sequence[tuple[CellSpec, Path, Path]]
) -> tuple[float, float]:
    """Known + reserved spend of every cell ledger already on disk (resume-safe)."""
    known = reserved = 0.0
    for spec, _t, _s in cells:
        events = campaign_dir / spec.run_id / "events.jsonl"
        if not events.is_file():
            continue
        try:
            totals = cost_totals(LedgerView.from_path(events))
        except LedgerCorrupt:
            continue
        known += totals.known_usd
        reserved += totals.reserved_usd
    return known, reserved


def cmd_campaign_status(args: argparse.Namespace, out: IO[str]) -> int:
    """Read-only: no writer, no lock. Reports every cell dir's state."""
    campaign_dir = run_dir_for(Path(args.runs_dir), validate_run_id(args.campaign_id))
    if not campaign_dir.is_dir():
        print(json.dumps({"status": "error", "error": f"{campaign_dir} does not exist"}), file=out)
        return EXIT_CONFIG
    cells: list[dict[str, Any]] = []
    for cell_dir in sorted(p for p in campaign_dir.iterdir() if p.is_dir()):
        if _cell_state(cell_dir) == "pending":
            continue  # the campaign's own blobs/ and scratch/ dirs, not cells
        entry: dict[str, Any] = {"run_id": cell_dir.name, "state": _cell_state(cell_dir)}
        manifest = cell_dir / "manifest.json"
        if manifest.is_file():
            extra = json.loads(manifest.read_bytes()).get("extra", {})
            entry.update(
                {
                    k: extra.get(k)
                    for k in ("arm", "status", "contaminated", "stopped", "spent_known_usd")
                }
            )
        elif (cell_dir / "events.jsonl").is_file():
            try:
                view = LedgerView.from_path(cell_dir / "events.jsonl")
                entry["events"] = len(view.events)
                entry["last_kind"] = view.events[-1].kind if view.events else None
            except LedgerCorrupt as exc:
                entry["state"] = "corrupt"
                entry["error"] = str(exc)[:200]
        cells.append(entry)
    campaign_state = _cell_state(campaign_dir)
    print(
        json.dumps(
            {"campaign_id": campaign_dir.name, "state": campaign_state, "cells": cells},
            indent=2,
            sort_keys=True,
        ),
        file=out,
    )
    return EXIT_OK


# --------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eval/run.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser("preflight")
    pre.add_argument("--policy", default=DEFAULT_POLICY)
    pre.add_argument("--env-file", default=".env")
    pre.add_argument("--probe", action="store_true")

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--policy", default=DEFAULT_POLICY)
        p.add_argument("--env-file", default=".env")
        p.add_argument("--worker", required=True)
        p.add_argument("--prompt-file", required=True)
        p.add_argument("--snapshot", required=True)
        p.add_argument("--task-id", default="adhoc")
        p.add_argument("--stage", default="propose", choices=[s.value for s in Stage])
        p.add_argument("--repeat-index", type=int, default=0)

    dry = sub.add_parser("dry-run")
    common(dry)
    inv = sub.add_parser("invoke")
    common(inv)
    inv.add_argument("--runs-dir", default="runs")
    inv.add_argument("--run-id", default=None)

    def cell_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--policy", default=DEFAULT_POLICY)
        p.add_argument("--env-file", default=".env")
        p.add_argument("--prompts-dir", default=DEFAULT_PROMPTS)
        p.add_argument("--runs-dir", default=None, help="default: policy runs_dir")
        p.add_argument("--cache-dir", default=None, help="default: policy cache_dir")
        p.add_argument("--no-cache", action="store_true")
        p.add_argument("--fresh", action="store_true", help="no cache lookup; store if absent")
        p.add_argument("--reuse-across-campaigns", action="store_true")
        p.add_argument("--panel", default=None, help="comma-separated worker ids")
        p.add_argument("--critics", default=None, help="comma-separated worker ids")
        p.add_argument("--judge", default="judge")

    run = sub.add_parser("run", help="one cell: task x repeat x arm")
    cell_common(run)
    run.add_argument("--task-file", required=True)
    run.add_argument("--arm", required=True, choices=[a.value for a in Arm])
    run.add_argument("--repeat-index", type=int, default=0)
    run.add_argument("--run-id", default=None)
    run.add_argument("--resume", default=None, metavar="RUN_ID")

    camp = sub.add_parser("campaign", help="every cell of a corpus under runs/<campaign_id>/")
    camp_sub = camp.add_subparsers(dest="campaign_command")
    status = camp_sub.add_parser("status", help="read-only state of a campaign (no lock)")
    status.add_argument("--runs-dir", default="runs")
    status.add_argument("--campaign-id", required=True)
    cell_common(camp)
    camp.add_argument("--campaign-id", default=None)
    camp.add_argument("--corpus", default="eval/corpus")
    camp.add_argument("--task-file", action="append", default=None)
    camp.add_argument("--repeats", type=int, default=2)
    camp.add_argument("--arms", default=None, help="comma-separated subset, run in the fixed order")
    camp.add_argument("--dry-run", action="store_true")
    camp.add_argument("--resume", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    out: IO[str] | None = None,
    err: IO[str] | None = None,
    home: Path | None = None,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    home = home or Path.home()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "preflight":
            return cmd_preflight(args, out, home)
        if args.command == "dry-run":
            return cmd_dry_run(args, out, home)
        if args.command == "invoke":
            return cmd_invoke(args, out, home, popen, killpg)
        if args.command == "run":
            return cmd_run(args, out, err, home, popen, killpg)
        if getattr(args, "campaign_command", None) == "status":
            return cmd_campaign_status(args, out)
        if not args.campaign_id:
            raise ValueError("campaign needs --campaign-id")
        return cmd_campaign(args, out, err, home, popen, killpg)
    except (PolicyError, LaunchRefused, CredentialFileError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=out)
        return EXIT_CONFIG


if __name__ == "__main__":
    raise SystemExit(main())
