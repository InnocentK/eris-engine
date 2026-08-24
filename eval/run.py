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
import fcntl
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

from pydantic import ValidationError

from eris.arms import (
    ARM_ORDER,
    CellSpec,
    Prior,
    ResumeRefused,
    finish_arm,
    kill_stale_groups,
    load_prior,
    planned_worker_calls,
    remove_stale_scratch,
    run_arm,
    stop_file_paths,
)
from eris.cache import Cache, CacheUnsupported
from eris.doctor import run_doctor
from eris.evidence import (
    NestedRepositoryRefused,
    SnapshotGuard,
    TaskSpec,
    VerifyEnv,
    git_index_prober,
    verify_scratch,
)
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
    resolve_user,
    run_worker,
)
from eris.ledger import LedgerCorrupt, LedgerView, cost_totals
from eris.policy import LoadedPolicy, PolicyError, load_policy
from eris.redact import CredentialFileError, Redactor, load_credential_values, parse_dotenv
from eris.retry import BudgetLedger, stop_requested, worst_case_call_reservation
from eris.sanitize import (
    VERIFICATION_PROFILE,
    SanitizeCleanupError,
    SanitizeError,
    SanitizeProfile,
    sanitized_copy,
    tree_sha256,
)
from eris.scan import PatternSet, build_patterns, scan_and_record
from eris.schemas import (
    Arm,
    ArmStatus,
    CostRecord,
    ErrorClass,
    Event,
    Invocation,
    RetryAttempt,
    RetryDecision,
    Stage,
    Transport,
    WorkerStatus,
    now_ts,
    sha256_hex,
)
from eris.snapshot import read_head_sha
from eris.stages import StageContext, load_prompt_files, store_pending_cache
from eris.version import __version__
from eris.writer import (
    LedgerInvalid,
    ManifestNotDurable,
    RunExists,
    RunWriter,
    WriterError,
    WriterLocked,
)

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
EXIT_NOT_DURABLE = 8  # manifest renamed into place, directory fsync failed
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
        user=resolve_user(),
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
    sweep_scratch(
        scratch_root,
        sys.stderr,
        runs_dir=Path(args.runs_dir),
        exclude=[run_id],
        max_age_s=float(loaded.policy.scratch_retention_s),
    )
    scratch = scratch_root / run_id
    # cond 5b: refuse BEFORE anything is written, and leave the entry alone
    if scratch.exists() or scratch.is_symlink():
        raise LaunchRefused(
            f"scratch path {scratch} already exists (or is a symlink); refusing before any "
            "ledger is created. It was left untouched: remove it or use another run id."
        )
    call = _build_call(loaded, args, env_values, home, scratch)
    plan_key = plan_call(call).idempotency_key if call.policy.executable else None
    # The RESERVATION is the mkdir(exist_ok=False) inside _scratch_root, and it
    # happens BEFORE the writer opens: an entry that appears between the check
    # above and the mkdir refuses with no ledger created and nothing deleted.
    with _scratch_root(scratch), RunWriter(run_dir, redactor, run_id=run_id) as writer:
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
    # The account name CLI workers run as; resolved once per command from the
    # OS, never from a filtered os.environ (eris.launch.resolve_user).
    user: str | None
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

    def sweep(self, exclude: Sequence[str]) -> list[str]:
        """Sweep orphaned scratch, always naming the run ids of THIS command so
        their paths are never touched (cond 5a)."""
        self.swept = sweep_scratch(
            self.scratch_dir,
            self.err,
            runs_dir=self.runs_dir,
            exclude=exclude,
            max_age_s=float(self.policy.scratch_retention_s),
        )
        return self.swept

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


SWEEP_MIN_AGE_S = 3600.0
"""A scratch entry younger than this is never swept: it may belong to a run
that is starting concurrently but has not taken its lock yet."""


def _find_run_dir(runs_dir: Path, name: str) -> Path | None:
    """``runs/<name>`` or ``runs/<campaign>/<name>`` (cells live one level in)."""
    direct = runs_dir / name
    if (direct / "events.jsonl").is_file() or (direct / "manifest.json").is_file():
        return direct
    if not runs_dir.is_dir():
        return None
    for campaign in sorted(p for p in runs_dir.iterdir() if p.is_dir() and not p.is_symlink()):
        cell = campaign / name
        if (cell / "events.jsonl").is_file() or (cell / "manifest.json").is_file():
            return cell
    return None


def _lock_is_held(lock_path: Path) -> bool:
    """True when another process holds the run's writer lock. Fail SAFE: any
    situation in which liveness cannot be disproved (no ``fcntl.flock`` on this
    platform, an unreadable lock file) counts as HELD, so the scratch of a
    possibly live run is never swept. M2c adds a portable liveness probe."""
    if not lock_path.is_file():
        return False
    if not hasattr(fcntl, "flock"):  # documented: cannot disprove liveness here
        return True
    try:
        fh = open(lock_path, "ab")
    except OSError:
        return True
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        fh.close()


def sweep_scratch(
    scratch_dir: Path,
    err: IO[str],
    *,
    runs_dir: Path,
    exclude: Sequence[str] = (),
    min_age_s: float = SWEEP_MIN_AGE_S,
    max_age_s: float | None = None,
    now: Callable[[], float] = time.time,
) -> list[str]:
    """Remove ORPHANED entries under ``scratch_dir`` and log what went. An
    entry is swept only when it is provably not in use: it is not this run's,
    its run directory (if any) is finalized or its writer lock is free, and it
    has not been touched within ``min_age_s``. Symlinks are unlinked, never
    followed. A concurrent run's scratch is left alone.

    ``max_age_s`` (the policy's ``scratch_retention_s``) is a hard bound on
    ORPHANS: an entry older than it is swept even when liveness cannot be
    disproved, so a platform without a working lock probe cannot accumulate
    scratch forever. Those sweeps are logged separately as ``forced``.
    EXCLUSION OUTRANKS RETENTION: a path whose run id is in ``exclude``
    belongs to this command and is never swept, at any age - deleting a live
    run's scratch is worse than leaking a stale directory."""
    removed: list[str] = []
    forced: list[str] = []
    skipped: dict[str, str] = {}
    if not scratch_dir.is_dir() or scratch_dir.is_symlink():
        return removed
    excluded = set(exclude)
    for entry in sorted(scratch_dir.iterdir()):
        reason: str | None = None
        try:
            age = now() - entry.lstat().st_mtime
        except OSError:
            age = 0.0
        over_retention = max_age_s is not None and age >= max_age_s
        if entry.name in excluded:
            reason = "current run"  # outranks the retention bound, at any age
        elif over_retention:
            forced.append(entry.name)  # hard bound: swept whatever the lock says
        else:
            run_dir = _find_run_dir(runs_dir, entry.name)
            if (
                run_dir is not None
                and not (run_dir / "manifest.json").is_file()
                and _lock_is_held(run_dir / ".lock")
            ):
                reason = "run is live (writer lock held)"
            elif age < min_age_s:
                reason = f"modified {age:.0f}s ago (< {min_age_s:.0f}s)"
        if reason is not None:
            skipped[entry.name] = reason
            continue
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            shutil.rmtree(entry)
        removed.append(entry.name)
    if removed or skipped:
        line = {
            "status": "scratch_swept",
            "scratch_dir": str(scratch_dir),
            "removed": removed,
            "forced_over_retention": forced,
            "kept": skipped,
        }
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
        user=resolve_user(),
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
    # NB: no sweep here - the run ids are not known yet, and a sweep that cannot
    # name the current run could delete a live scratch dir. Each command calls
    # `h.sweep(...)` once it knows them (cond 5a).
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
    scratch = h.scratch_for(run_id)
    if scratch.exists() or scratch.is_symlink():
        # cond 5b: nothing is created and NOTHING is deleted. The entry (a crash
        # leftover, or something planted) is left exactly as it was found.
        return CellOutcome(
            run_id,
            EXIT_CONFIG,
            "refused",
            error=(
                f"scratch path {scratch} already exists (or is a symlink); refusing before any "
                "ledger is created. It was left untouched: remove it or use another run id."
            ),
        )
    # RESERVE the scratch before anything else: the mkdir(exist_ok=False) IS the
    # reservation, so an entry that appears between the check above and it can
    # never end up with a ledger created behind it. The refusal deletes nothing.
    try:
        make_private_dir(scratch)
    except LaunchRefused as exc:
        return CellOutcome(run_id, EXIT_CONFIG, "refused", error=str(exc))
    scratch_created = True
    try:
        writer = RunWriter(
            run_dir, h.redactor, run_id=run_id, resume=resume, on_event=_stream(h.err, run_id)
        ).open()
    except (RunExists, LedgerInvalid, WriterLocked) as exc:
        # the reservation is ours and no ledger opened: give it back
        _remove_scratch(scratch)
        if isinstance(exc, RunExists):
            return CellOutcome(run_id, EXIT_CONFIG, "exists", error=str(exc))
        status = "corrupt" if isinstance(exc, LedgerInvalid) else "locked"
        return CellOutcome(run_id, EXIT_RUN_ERROR, status, error=str(exc))
    prompts = load_prompt_files(h.prompts_dir)
    snapshot_sha = read_head_sha(snapshot)
    original_tree = tree_sha256(snapshot)
    outcome = CellOutcome(run_id, EXIT_OK, "running")
    manifest_extra: dict[str, Any] = {"arm": spec.arm.value, "status": "post_scan_failure"}
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
        (scratch / "tmp").mkdir()

        def judge_workspace(role: str, iteration: int) -> Path:
            # a FRESH empty dir per judge CALL: iteration N+1 never sees what
            # iteration N left behind (and never the snapshot)
            path = scratch / f"judge-{role}-{iteration}"
            if not path.exists():
                make_private_dir(path)
            return path

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

            assert_judge_workspace_empty(call)  # checked HERE, not only at planning
            # current_call stays set if the call is interrupted: the SIGINT
            # recorder needs it after the exception has unwound to run_cell
            result = run_worker(call, popen=h.popen, killpg=h.killpg, on_spawn=spawned)
            h.current_call = None
            return result

        def cwd_for(worker_id: str, role: str, iteration: int) -> Path:
            if role in JUDGE_ROLES:
                return judge_workspace(role, iteration)
            return sanitized.get(worker_id, snapshot)

        def stop_check() -> bool:
            return h.interrupted or stop_requested(*stop_paths)

        with (
            verify_scratch(writer, scratch) as scratch_home,
            sanitized_copy(
                snapshot,
                scratch,
                profile=VERIFICATION_PROFILE,
                worker_id="verify",
                name="verify-copy",
            ) as (verify_copy, verify_copy_record),
            _sanitized_copies(writer, spec, policy, snapshot, scratch, profile, sanitized),
        ):
            writer.append("snapshot.verification_copy", verify_copy_record)
            env = VerifyEnv(
                policy=policy,
                snapshot_root=verify_copy,  # a private copy, never the original
                scratch_home=scratch_home,
                popen=h.popen,
                killpg=h.killpg,
                guard=SnapshotGuard.over(
                    verify_copy,
                    # semantic cover for `.git/index`, which the tree hash
                    # excludes by bytes; no usable git falls back to bytes
                    probe=git_index_prober(policy, scratch_home, popen=h.popen, killpg=h.killpg),
                ),
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
                cwd_for=cwd_for,
                scratch_dir=scratch,
                home=str(h.home),
                user=h.user,
                path_env=policy.path_env,
                secrets=h.secrets,
                runner=runner,
                cache=h.cache,
                campaign_id=campaign_id,
                prior_attempts=dict(prior.attempts) if prior is not None else {},
            )
            try:
                draft = run_arm(spec, ctx, env, prior=prior)
            except KeyboardInterrupt:
                _record_interrupt(h, writer, ctx)
                raise
            # scan #1 decides the ArmRun's contamination and the cache entries' scan_hits
            first = scan_and_record(writer, patterns)
            hits: dict[str, int] = {}
            for hit in first.hits:
                if hit.where.startswith("blob:"):
                    hits[hit.where[5:]] = hits.get(hit.where[5:], 0) + hit.count
            view = LedgerView.from_path(writer.events_path)
            record = finish_arm(
                draft, ctx, view, contaminated=first.contaminated, containment=policy.containment
            )
            store_pending_cache(ctx, hits)  # cache.* events carry hashes and keys only
        # EVERYTHING that can still append goes before the final scan, so that
        # scan.result is genuinely the last line of the ledger: the snapshot
        # check and the scratch removal are done here, not in the finally.
        if tree_sha256(snapshot) != original_tree:
            writer.append(
                "run.error",
                {
                    "kind": "snapshot_modified",
                    "error": "the ORIGINAL snapshot changed during the run",
                },
            )
        cleanup_error = _remove_scratch(scratch)
        if cleanup_error is not None:
            writer.append("run.error", {"kind": "scratch_cleanup_failed", "error": cleanup_error})
        # the FINAL scan is the LAST event: it covers arm.finished, the
        # cache-store events and any run.error above; the scorer reads it
        scan = scan_and_record(writer, patterns)
        writer.seal()  # structural: any later append raises instead of slipping in
        scan_contaminated = first.contaminated or scan.contaminated
        scan_incomplete = first.scan_incomplete or scan.scan_incomplete
        totals = cost_totals(LedgerView.from_path(writer.events_path))
        run_errors = [e for e in LedgerView.from_path(writer.events_path).payloads("run.error")]
        manifest_extra = {
            "arm": spec.arm.value,
            "status": record.status.value,
            "contaminated": scan_contaminated,
            "scan_incomplete": scan_incomplete,
            "stopped": draft.stopped,
            "spent_known_usd": budget.spent_known_usd,
            "spent_reserved_usd": budget.reserved_usd,
            "cost_attributed_usd": totals.attributed_usd,
            "run_errors": len(run_errors),
        }
        not_durable: str | None = None
        try:
            writer.finalize(manifest_extra)
        except ManifestNotDurable as exc:
            # the run IS finalized (the manifest is in place); only its
            # durability across a power loss is unproven -> its OWN exit code
            not_durable = str(exc)
            print(
                json.dumps({"status": "not_durable", "run_id": run_id, "error": not_durable}),
                file=h.err,
                flush=True,
            )
        outcome.contaminated = scan_contaminated
        outcome.stopped = draft.stopped
        outcome.status = record.status.value
        if not_durable is not None:
            outcome.exit_code, outcome.status, outcome.error = (
                EXIT_NOT_DURABLE,
                "not_durable",
                not_durable,
            )
        elif run_errors:
            outcome.exit_code, outcome.status = EXIT_RUN_ERROR, "run_error"
        elif draft.stopped is not None:
            outcome.exit_code = EXIT_STOP
        elif scan_contaminated or scan_incomplete:
            outcome.exit_code = EXIT_CONTAMINATED
        elif record.status is not ArmStatus.COMPLETE:
            outcome.exit_code = EXIT_INCOMPLETE
        return outcome
    except KeyboardInterrupt:
        outcome.exit_code, outcome.status = EXIT_SIGINT, "interrupted"
        return outcome
    except SanitizeCleanupError as exc:
        # a SUBCLASS of SanitizeError, and it must NOT be read as a refusal:
        # worker-visible files may remain, which is a run error
        _record_run_error(writer, h, type(exc).__name__, str(exc))
        outcome.exit_code, outcome.status, outcome.error = EXIT_RUN_ERROR, "run_error", str(exc)
        return outcome
    except (
        LaunchRefused,
        ResumeRefused,
        LedgerCorrupt,
        PolicyError,
        SanitizeError,
        NestedRepositoryRefused,
    ) as exc:
        # `SanitizeError` and `NestedRepositoryRefused` are DELIBERATE refusals
        # of a snapshot Eris will not verify (a nested repository, an
        # unsupported `extensions.*`, a `.git` shape it cannot reason about).
        # They used to escape `run_cell` as an unhandled traceback; they are
        # refusals like any other, and exit EXIT_CONFIG with status "refused".
        _record_run_error(writer, h, type(exc).__name__, str(exc))
        outcome.exit_code, outcome.status, outcome.error = EXIT_CONFIG, "refused", str(exc)
        return outcome
    except (OSError, WriterError) as exc:
        _record_run_error(writer, h, type(exc).__name__, str(exc))
        outcome.exit_code, outcome.status, outcome.error = EXIT_RUN_ERROR, "run_error", str(exc)
        return outcome
    finally:
        try:
            # exceptional paths only (the happy path removed it above), and only
            # ever OUR directory: a refused pre-existing entry is never deleted
            error = _remove_scratch(scratch) if scratch_created else None
            if error is not None:
                outcome.exit_code, outcome.status = EXIT_RUN_ERROR, "run_error"
                _record_run_error(writer, h, "scratch_cleanup_failed", error)
            _finalize_after_post_scan_failure(writer, h, manifest_extra, outcome)
        finally:
            writer.close()  # always: no fd outlives the cell, whatever propagated


JUDGE_ROLES: frozenset[str] = frozenset({"adjudicator", "summarizer"})
JUDGE_STAGES: frozenset[Stage] = frozenset({Stage.ADJUDICATE, Stage.SUMMARIZE})


def assert_judge_workspace_empty(call: WorkerCall) -> None:
    """Immediately before a judge spawn: its cwd must still be an EMPTY
    directory. A non-empty workspace means containment failed (a previous
    iteration's files, or something planted); refuse loudly."""
    if call.stage not in JUDGE_STAGES:
        return
    cwd = Path(call.cwd)
    if cwd.is_symlink() or not cwd.is_dir():
        raise LaunchRefused(f"judge workspace {cwd} is not a directory; refusing to spawn")
    entries = sorted(p.name for p in cwd.iterdir())
    if entries:
        raise LaunchRefused(
            f"judge workspace {cwd} is not empty ({entries[:5]}); refusing to spawn"
        )


def _record_run_error(writer: RunWriter, h: Harness, kind: str, error: str) -> None:
    """A run-level failure becomes a ``run.error`` EVENT while the ledger still
    accepts events. Once the ledger is sealed (after the final scan) or closed
    it goes to stderr and the exit code instead: nothing may appear behind
    ``scan.result`` (cond 10), and nothing is silently dropped either."""
    if writer.closed or writer.sealed:
        # durable too: the manifest is written AFTER the scan, so a post-scan
        # failure is recorded there and not only on stderr (it is stderr-only
        # when the manifest is already written, i.e. the writer is closed)
        writer.record_post_scan_error(kind, error)
        print(
            json.dumps({"status": "error", "kind": kind, "error": error, "after_scan": True}),
            file=h.err,
            flush=True,
        )
        return
    writer.append("run.error", {"kind": kind, "error": error})


def _finalize_after_post_scan_failure(
    writer: RunWriter, h: Harness, extra: dict[str, Any], outcome: CellOutcome
) -> None:
    """A failure between the seal and the manifest leaves a sealed, UNfinalized
    run: finalize it here so the failure itself (``post_scan_errors``) reaches
    disk. Never raises - the cell's exit code already reports the failure."""
    if not writer.sealed or writer.closed:
        return  # not sealed yet (nothing durable to add), or already finalized
    try:
        writer.finalize(extra)
    except ManifestNotDurable as exc:
        outcome.exit_code, outcome.status, outcome.error = EXIT_NOT_DURABLE, "not_durable", str(exc)
        print(
            json.dumps({"status": "not_durable", "run_id": writer.run_id, "error": str(exc)}),
            file=h.err,
            flush=True,
        )
    except (OSError, WriterError) as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "kind": "post_scan_finalize_failed",
                    "error": str(exc),
                    "after_scan": True,
                }
            ),
            file=h.err,
            flush=True,
        )


def _remove_scratch(scratch: Path) -> str | None:
    """Remove the run's scratch root. Returns the failure text, never raises."""
    try:
        if scratch.is_symlink():
            scratch.unlink()
        elif scratch.exists():
            shutil.rmtree(scratch)
    except OSError as exc:
        return f"{scratch}: {exc}"
    return None


@contextmanager
def _scratch_root(scratch: Path) -> Iterator[Path]:
    """Create the run's private scratch root (refusing a planted entry or
    symlink) and remove it in ``finally`` whatever happens."""
    make_private_dir(scratch)
    try:
        yield scratch
    finally:
        shutil.rmtree(scratch, ignore_errors=False)


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
            "retry.attempt",
            RetryAttempt(
                invocation_id=inv.invocation_id,
                attempt=attempt,
                status=WorkerStatus.FAILED,
                error_class=ErrorClass.INTERRUPTED,
                reason="interrupted (SIGINT): the group was killed; no retry",
                weight=1,
                budget_used_after=0,
                backoff_s=0.0,
                decision=RetryDecision.STOP,
            ),
        )
        # The attempt is CLOSED here (invocation.finished + cost + retry.attempt).
        # `load_prior` reads this marker and does NOT synthesize an abandoned
        # attempt for it on resume: the cost would otherwise be counted twice.
        writer.append(
            "stage.interrupted",
            {
                "stage": call.stage.value,
                "worker_id": call.worker_id,
                "idempotency_key": key,
                "attempt": attempt,
            },
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
    h.sweep(exclude=[run_id])  # never this run's own scratch (cond 5a)
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


def task_is_scored(task_file: Path) -> bool:
    """``task.json``'s ``scored`` flag (default True). An unparsable task file
    is left to the caller to fail on - never silently skipped."""
    try:
        return bool(TaskSpec.model_validate_json(Path(task_file).read_bytes()).scored)
    except (OSError, ValidationError):
        return True


def discover_tasks(corpus: Path) -> list[Path]:
    """Every scored ``task.json`` under the corpus. A task with
    ``"scored": false`` is a PLUMBING task: it is skipped here so a campaign
    never sweeps it up, while an explicit ``--task-file`` still runs it."""
    return sorted(p for p in Path(corpus).glob("*/task.json") if p.is_file() and task_is_scored(p))


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
    # every cell of this campaign is "current": none of their scratch may be
    # swept, whatever their age or lock state (cond 5a)
    h.sweep(exclude=[campaign_id, *(cell.run_id for cell, _t, _s in cells)])
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
                spend = _campaign_spent(
                    campaign_dir,
                    cells,
                    per_call_usd=h.policy.budgets.per_call_usd,
                    exclude_run_id=spec.run_id,
                )
                writer.append(
                    "cell.started",
                    {
                        "run_id": spec.run_id,
                        "arm": spec.arm.value,
                        "task_id": spec.task.task_id,
                        "repeat_index": spec.repeat_index,
                        "resume": state == "unfinished",
                        "campaign_budget": {
                            "known_usd": spend.known_usd,
                            "reserved_usd": spend.reserved_usd,
                            "corrupt_cells": spend.corrupt_cells,
                            "counted_cells": spend.counted_cells,
                        },
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
                        campaign_budget=(spend.known_usd, spend.reserved_usd),
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


@dataclass
class CampaignSpend:
    known_usd: float
    reserved_usd: float
    corrupt_cells: list[str]
    counted_cells: list[str]


def planned_calls(spec: CellSpec) -> int:
    """Logical worker calls a cell makes, from the ARM's steps (the iterating
    judge counts once per iteration). Each may RETRY, so a reservation
    multiplies this by :func:`~eris.retry.worst_case_call_reservation`."""
    return planned_worker_calls(spec)


def _campaign_spent(
    campaign_dir: Path,
    cells: Sequence[tuple[CellSpec, Path, Path]],
    *,
    per_call_usd: float,
    exclude_run_id: str | None = None,
) -> CampaignSpend:
    """Known + reserved spend of every OTHER cell ledger on disk. A corrupt
    ledger is never ignored: it reserves per_call x planned calls and is
    reported. The cell being run/resumed is excluded (its own ledger seeds
    its run-level budget; it must not be counted twice)."""
    known = reserved = 0.0
    corrupt: list[str] = []
    counted: list[str] = []
    for spec, _t, _s in cells:
        if spec.run_id == exclude_run_id:
            continue
        events = campaign_dir / spec.run_id / "events.jsonl"
        if not events.is_file():
            continue
        try:
            totals = cost_totals(LedgerView.from_path(events))
        except LedgerCorrupt:
            # unreadable: reserve the worst case - every planned call retrying
            # to exhaustion (timeouts reserve 2x per attempt)
            corrupt.append(spec.run_id)
            reserved += planned_calls(spec) * worst_case_call_reservation(per_call_usd)
            continue
        counted.append(spec.run_id)
        known += totals.known_usd
        reserved += totals.reserved_usd
    return CampaignSpend(round(known, 6), round(reserved, 6), corrupt, counted)


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
    killpg: KillPg | None = None,
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    home = home or Path.home()
    args = build_parser().parse_args(argv)
    if killpg is None:
        # resolved at CALL time, never as an import-time default: on a platform
        # without os.killpg (Windows) every command that may spawn or resume a
        # worker is refused with a documented message (M2c adds the fallback)
        resolved = getattr(os, "killpg", None)
        if (
            resolved is None
            and args.command in ("invoke", "run", "campaign")
            and not (
                getattr(args, "campaign_command", None) == "status"
                or getattr(args, "dry_run", False)
            )
        ):
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": "os.killpg is unavailable on this platform: Eris cannot kill "
                        "a worker process group on timeout or resume; refusing to spawn "
                        "(documented refusal; M2c adds a portable fallback)",
                    }
                ),
                file=out,
            )
            return EXIT_CONFIG
        killpg = resolved if resolved is not None else _no_killpg
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
    except ManifestNotDurable as exc:
        # finalized but not proven durable: never a config error, never a
        # finalize failure (docs/SECURITY.md "Durability of the record")
        print(json.dumps({"status": "not_durable", "error": str(exc)}), file=out)
        return EXIT_NOT_DURABLE
    except (PolicyError, LaunchRefused, CredentialFileError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=out)
        return EXIT_CONFIG


def _no_killpg(pgid: int, sig: int) -> None:  # pragma: no cover - never reached (refused above)
    raise OSError("os.killpg is unavailable on this platform")


if __name__ == "__main__":
    raise SystemExit(main())
