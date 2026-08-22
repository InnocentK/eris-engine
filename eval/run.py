"""Phase 0 harness - thin CLI over ``eris``. Milestone 1 scope ONLY:

* ``preflight``  - the doctor checks (names, never values).
* ``dry-run``    - argv / env NAMES / cwd / idempotency key for one worker.
                   Zero subprocesses.
* ``invoke``     - ONE worker, propose stage: launch -> parse -> redact ->
                   write through RunWriter. No arms, critique, adjudication
                   or scoring (Milestone 2).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Any

from eris.doctor import run_doctor
from eris.launch import KillPg, LaunchRefused, PopenFactory, WorkerCall, plan_call, run_worker
from eris.policy import LoadedPolicy, PolicyError, load_policy
from eris.redact import CredentialFileError, Redactor, load_credential_values, parse_dotenv
from eris.schemas import CostRecord, Invocation, Stage, Transport, WorkerStatus, now_ts
from eris.snapshot import read_head_sha
from eris.version import __version__
from eris.writer import RunWriter

DEFAULT_POLICY = "policies/default.yaml"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


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
        snapshot_sha=args.snapshot_sha or read_head_sha(snapshot),
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
    scratch = run_dir / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "tmp").mkdir(exist_ok=True)
    call = _build_call(loaded, args, env_values, home, scratch)
    plan_key = plan_call(call).idempotency_key if call.policy.executable else None
    with RunWriter(run_dir, redactor, run_id=run_id) as writer:
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
            invocation_id=f"inv-{result.idempotency_key[:16]}",
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
        )
        writer.append("invocation.finished", invocation)
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
                },
            )
        else:
            writer.append(
                "worker.absent",
                {"worker_id": args.worker, "status": result.status.value, "error": result.error},
            )
        manifest = writer.finalize({"worker_id": args.worker, "status": result.status.value})
    summary = {
        "run_dir": str(run_dir),
        "manifest": str(manifest),
        "worker": args.worker,
        "status": result.status.value,
        "error": result.error,
        "model_executed": result.model_executed,
        "cost_usd": result.cost_usd,
        "duration_ms": result.duration_ms,
        "redactions": {
            k: v
            for ref in (stdout_ref, stderr_ref, output_ref)
            if ref
            for k, v in ref.redaction_counts.items()
        },
    }
    print(json.dumps(summary, indent=2, sort_keys=True), file=out)
    return 0 if result.status is WorkerStatus.OK else 3


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
        p.add_argument("--snapshot-sha", default=None, help="base commit (default: read .git/HEAD)")
        p.add_argument("--stage", default="propose", choices=[s.value for s in Stage])
        p.add_argument("--repeat-index", type=int, default=0)

    dry = sub.add_parser("dry-run")
    common(dry)
    inv = sub.add_parser("invoke")
    common(inv)
    inv.add_argument("--runs-dir", default="runs")
    inv.add_argument("--run-id", default=None)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    out: IO[str] | None = None,
    home: Path | None = None,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
) -> int:
    out = out or sys.stdout
    home = home or Path.home()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "preflight":
            return cmd_preflight(args, out, home)
        if args.command == "dry-run":
            return cmd_dry_run(args, out, home)
        return cmd_invoke(args, out, home, popen, killpg)
    except (PolicyError, LaunchRefused, CredentialFileError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=out)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
