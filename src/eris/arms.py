"""Experimental arms: pure data + ONE sequential runner.

::

    P=pack  PR=propose(panel)  V1=verify(pack battery + proposals' requests)
    CR=critique(critics, framing)  V2=verify(challenges' requests)
    AD=adjudicate(judge)  ADi=AD with max_iterations=3 (the judge's own
    requests are executed and the judge re-run; NO new proposals/critiques)
    SM=summarize(judge)
    single:(P,PR)  consensus:(P,PR,SM)  indep_verify:(P,PR,V1,AD)
    indep_verify_iter:(P,PR,V1,ADi)  indep_verify_critique:(P,PR,V1,CR,V2,AD)

Paired ablation: the propose call is built only from (worker, pack, repeat,
prompt file, schema, policy) so its idempotency key is shared across
arms 3/3b/4 (and ``single``); ``ArmRun.propose_keys`` records the keys and
the scorer pairs only identical key sets. The arm is NOT on any
``Invocation``. Arm 3's judge never sees critiques; arm 4's does.

Boundaries: STOP is checked before every step and before every worker
call (the attempt in flight always completes); a budget trip marks the
cell missing and skips the remaining stages (``stage.skipped{reason:
budget}``). Resume (``load_prior``) replays finished stages whose blobs
re-hash, writes ``invocation.abandoned`` (+ a pessimistic cost record) for
a ``stage.started`` without ``stage.finished``, and hands back the pgids
recorded by ``invocation.spawned`` so the caller can kill survivors
through the existing group-kill path.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from eris.evidence import (
    EvidenceStopped,
    PackBuild,
    RequestState,
    TaskSpec,
    VerifyEnv,
    build_evidence_pack,
    execute_evidence_requests,
    rebuild_pack,
    request_key,
)
from eris.launch import KillPg, LaunchRefused, _kill_group
from eris.ledger import LedgerView, cost_totals
from eris.schemas import (
    Adjudication,
    Arm,
    ArmRun,
    ArmStatus,
    CostRecord,
    Critique,
    ErrorClass,
    EvidenceItem,
    EvidencePack,
    MissingCell,
    Phase,
    Proposal,
    Stage,
    now_ts,
)
from eris.stages import (
    AdjudicationResult,
    StageContext,
    evidence_index,
    labels_for,
    run_adjudicate,
    run_critique,
    run_propose,
)
from eris.writer import RunWriter

MAX_ITERATIONS = 3
ARM_STEPS: dict[Arm, tuple[str, ...]] = {
    Arm.SINGLE: ("pack", "propose"),
    Arm.CONSENSUS: ("pack", "propose", "summarize"),
    Arm.INDEP_VERIFY: ("pack", "propose", "verify", "adjudicate"),
    Arm.INDEP_VERIFY_ITER: ("pack", "propose", "verify", "adjudicate_iter"),
    Arm.INDEP_VERIFY_CRITIQUE: ("pack", "propose", "verify", "critique", "verify2", "adjudicate"),
}
ARM_ORDER: tuple[Arm, ...] = (
    Arm.SINGLE,
    Arm.CONSENSUS,
    Arm.INDEP_VERIFY,
    Arm.INDEP_VERIFY_ITER,
    Arm.INDEP_VERIFY_CRITIQUE,
)
JUDGED_ARMS: frozenset[Arm] = frozenset(
    {Arm.CONSENSUS, Arm.INDEP_VERIFY, Arm.INDEP_VERIFY_ITER, Arm.INDEP_VERIFY_CRITIQUE}
)


class ArmStopped(Exception):
    """STOP or budget ended the arm; the in-flight attempt completed first."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ResumeRefused(RuntimeError):
    """Resume cannot proceed safely on this platform or ledger (documented)."""


@dataclass(frozen=True)
class CellSpec:
    arm: Arm
    task: TaskSpec
    repeat_index: int
    panel: tuple[str, ...]
    critics: tuple[str, ...] = ()
    judge: str | None = None

    def __post_init__(self) -> None:
        if not self.panel:
            raise ValueError("a cell needs at least one panel worker")
        if self.arm in JUDGED_ARMS and not self.judge:
            raise ValueError(f"arm {self.arm.value} needs a judge")
        if self.arm is Arm.INDEP_VERIFY_CRITIQUE and not self.critics:
            raise ValueError("indep_verify_critique needs critics")
        if self.arm is Arm.SINGLE and len(self.panel) != 1:
            raise ValueError("single runs one worker per cell")

    @property
    def run_id(self) -> str:
        base = f"{self.task.task_id}-r{self.repeat_index}-{self.arm.value}"
        if self.arm is Arm.SINGLE:
            base += f"-{self.panel[0]}"
        return "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in base)[:64]


# --------------------------------------------------------------------------- prior (resume)


@dataclass
class Prior:
    """What an unfinished ledger already holds (blobs verified)."""

    pack: PackBuild | None = None
    proposals: dict[str, Proposal] = field(default_factory=dict)
    critiques: dict[str, Critique] = field(default_factory=dict)
    finished: dict[tuple[str, str, int], dict[str, Any]] = field(default_factory=dict)
    verification: list[tuple[EvidenceItem, bytes]] = field(default_factory=list)
    adjudications: dict[tuple[str, int], tuple[Adjudication, Adjudication]] = field(
        default_factory=dict
    )
    abandoned: list[dict[str, Any]] = field(default_factory=list)
    stale_pgids: list[int] = field(default_factory=list)
    requests_executed: dict[str, str] = field(default_factory=dict)  # request_key -> evidence_id


def load_prior(view: LedgerView, writer: RunWriter, *, per_call_usd: float) -> Prior:
    """Rebuild the prior state of a run being resumed. Writes
    ``invocation.abandoned`` + a pessimistic ``cost`` for every attempt that
    started and never finished. Never trusts a blob that does not re-hash."""
    prior = Prior()
    intact = writer.blob_intact
    # stage.started / stage.finished pairing by (stage, worker, key)
    open_stages: dict[tuple[str, str, str], dict[str, Any]] = {}
    spawned: dict[str, int] = {}
    closed_by_sigint: set[tuple[str, str, str]] = set()
    for ev in view.events:
        p = ev.payload
        if ev.kind == "stage.interrupted":
            # SIGINT already recorded that attempt (invocation.finished + cost):
            # the stage stays OPEN (it re-runs) but no abandoned attempt is invented
            closed_by_sigint.add((str(p["stage"]), str(p["worker_id"]), str(p["idempotency_key"])))
        elif ev.kind == "stage.started":
            open_stages[(str(p["stage"]), str(p["worker_id"]), str(p["idempotency_key"]))] = p
        elif ev.kind == "invocation.spawned":
            spawned[str(p.get("idempotency_key"))] = int(p["pgid"])
        elif ev.kind == "stage.finished":
            key = (str(p["stage"]), str(p["worker_id"]), str(p["idempotency_key"]))
            open_stages.pop(key, None)
            blobs = [str(b) for b in p.get("blobs", [])]
            if all(intact(b) for b in blobs):
                prior.finished[(key[0], key[1], int(p.get("iteration", 0)))] = p
    attempts: dict[str, int] = {}
    for inv in view.payloads("invocation.finished"):
        k = str(inv.get("idempotency_key"))
        attempts[k] = max(attempts.get(k, 0), int(inv.get("attempt", 0)))
    already = {
        (str(a.get("idempotency_key")), int(a.get("attempt", 0)))
        for a in view.payloads("invocation.abandoned")
    }
    for (stage, worker_id, idem), started in open_stages.items():
        pgid = spawned.get(idem)
        attempt = attempts.get(idem, 0) + 1
        payload = {
            "stage": stage,
            "worker_id": worker_id,
            "idempotency_key": idem,
            "attempt": attempt,
            "pgid": pgid,
            "role": started.get("role"),
        }
        if pgid is not None:
            prior.stale_pgids.append(pgid)
        if (stage, worker_id, idem) in closed_by_sigint:
            continue  # closed by the SIGINT path; its cost is already on the ledger
        if (idem, attempt) in already:
            prior.abandoned.append(payload)  # a repeated resume: recorded once, never twice
            continue
        writer.append("invocation.abandoned", payload)
        writer.append(
            "cost",
            CostRecord(
                invocation_id=f"inv-{idem[:16]}-a{attempt}",
                attempt=attempt,
                cost_usd=per_call_usd,
                usage=None,
                counted=True,
                estimated=True,
                cost_known=False,
            ),
        )
        prior.abandoned.append(payload)
    # the pack
    packs = view.records("pack.built", EvidencePack)
    items = view.records("evidence.item", EvidenceItem)
    if packs:
        pack = packs[-1]
        pack_items = [
            r for r in items if r.phase is Phase.EVIDENCE_PACK and r.evidence_id in pack.item_ids
        ]
        if (
            intact(pack.pack_sha256)
            and all(intact(r.content_sha256) for r in pack_items)
            and len(pack_items) == len(pack.item_ids)
        ):
            prior.pack = rebuild_pack(
                pack,
                pack_items,
                blob_bytes=lambda sha: (writer.blobs_dir / sha).read_bytes(),
                blobs_dir=writer.blobs_dir,
            )
    # records behind intact stage.finished entries
    for prop in view.records("proposal.recorded", Proposal):
        if ("propose", prop.worker_id, 0) in prior.finished:
            prior.proposals[prop.worker_id] = prop
    for crit in view.records("critique.recorded", Critique):
        if ("critique", crit.worker_id, 0) in prior.finished:
            prior.critiques[crit.worker_id] = crit
    for r in items:
        if r.phase is Phase.VERIFICATION and intact(r.content_sha256):
            prior.verification.append((r, (writer.blobs_dir / r.content_sha256).read_bytes()))
            if r.argv:
                prior.requests_executed[request_key(r.argv)] = r.evidence_id
    raws = {a.adjudication_id: a for a in view.records("adjudication.raw", Adjudication)}
    for enforced in view.records("adjudication.enforced", Adjudication):
        raw = raws.get(enforced.adjudication_id)
        if raw is None:
            continue
        for (stage, _worker, iteration), fin in prior.finished.items():
            if fin.get("record_id") == enforced.adjudication_id and stage in (
                "adjudicate",
                "summarize",
            ):
                prior.adjudications[(stage, iteration)] = (raw, enforced)
    return prior


class _GroupHandle:
    """A PopenLike over a bare pgid so the existing ``_kill_group`` path
    (SIGTERM, WAIT, SIGKILL sweep) can be reused on resume."""

    def __init__(self, pgid: int, alive: Callable[[int], bool], clock: Callable[[], float]) -> None:
        self.pid = pgid
        self._alive = alive
        self._clock = clock
        self.returncode: int | None = None
        self.stdout: IO[bytes] | None = None
        self.stderr: IO[bytes] | None = None

    def poll(self) -> int | None:
        if self._alive(self.pid):
            return None
        self.returncode = 0
        return 0

    def wait(self, timeout: float | None = None) -> int:
        deadline = self._clock() + (timeout if timeout is not None else 0.0)
        while self._alive(self.pid):
            if timeout is None or self._clock() >= deadline:
                raise subprocess.TimeoutExpired(f"pgid {self.pid}", timeout or 0.0)
            time.sleep(0.01)
        self.returncode = 0
        return 0


def kill_stale_groups(
    pgids: Sequence[int],
    *,
    killpg: KillPg | None = None,
    alive: Callable[[int], bool] | None = None,
    grace_s: float = 2.0,
    clock: Callable[[], float] = time.monotonic,
) -> list[int]:
    """Kill every recorded process group that is still alive through the
    launcher's ``_kill_group`` (SIGTERM, wait up to ``grace_s``, SIGKILL
    sweep, wait again). A group that survives refuses the resume. Where
    ``os.killpg`` does not exist (Windows) resume is REFUSED with a
    documented message - M2c adds the portable fallback."""
    if not pgids:
        return []
    if killpg is None:
        if not hasattr(os, "killpg"):
            raise ResumeRefused(
                "resume needs os.killpg to reap a possibly surviving worker process group; "
                "it is unavailable on this platform (documented refusal; M2c adds a portable "
                "fallback). Make sure no worker is running, then start a fresh run."
            )
        killpg = os.killpg
    if alive is None:

        def alive(pgid: int) -> bool:
            assert killpg is not None
            try:
                killpg(pgid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            return True

    killed: list[int] = []
    for pgid in sorted(set(pgids)):
        if not alive(pgid):
            continue
        handle = _GroupHandle(pgid, alive, clock)
        try:
            _kill_group(handle, killpg, grace_s)
        except LaunchRefused as exc:
            raise ResumeRefused(
                f"process group {pgid} from the interrupted run survived SIGKILL ({exc}); "
                "refusing to resume while it may still write"
            ) from exc
        if alive(pgid):
            raise ResumeRefused(
                f"process group {pgid} from the interrupted run is still alive; refusing to resume"
            )
        killed.append(pgid)
    return killed


def remove_stale_scratch(scratch_root: Path) -> list[str]:
    """Remove ``call-*`` dirs left under the run's scratch root by a crashed
    call (after the pgid check)."""
    scratch = Path(scratch_root)
    removed: list[str] = []
    if not scratch.is_dir() or scratch.is_symlink():
        return removed
    for entry in sorted(scratch.iterdir()):
        if entry.name.startswith("call-") and entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
            removed.append(entry.name)
    return removed


# --------------------------------------------------------------------------- runner


@dataclass
class ArmDraft:
    spec: CellSpec
    steps_done: list[str] = field(default_factory=list)
    propose_keys: list[str] = field(default_factory=list)
    missing: list[MissingCell] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)
    critiques: list[Critique] = field(default_factory=list)
    adjudications: list[AdjudicationResult | tuple[Adjudication, Adjudication]] = field(
        default_factory=list
    )
    iterations: int = 0
    stopped: str | None = None
    final_adjudication: Adjudication | None = None

    @property
    def status(self) -> ArmStatus:
        return (
            ArmStatus.COMPLETE
            if not self.missing and self.stopped is None
            else ArmStatus.INCOMPLETE
        )

    @property
    def raw_final(self) -> Adjudication | None:
        if not self.adjudications:
            return None
        last = self.adjudications[-1]
        return last.raw if isinstance(last, AdjudicationResult) else last[0]


def _check_stop(ctx: StageContext, where: str) -> None:
    if ctx.stop_check():
        ctx.writer.append("run.stopped", {"where": where, "reason": "STOP file present"})
        raise ArmStopped("stop")


def run_arm(
    spec: CellSpec, ctx: StageContext, env: VerifyEnv, *, prior: Prior | None = None
) -> ArmDraft:
    """Run one cell sequentially. Never raises on worker behaviour; writer
    errors propagate. Returns the draft the caller finishes after the scan."""
    w = ctx.writer
    steps = ARM_STEPS[spec.arm]
    draft = ArmDraft(spec)
    prior = prior or Prior()
    w.append(
        "arm.started",
        {
            "arm": spec.arm.value,
            "task_id": spec.task.task_id,
            "repeat_index": spec.repeat_index,
            "panel": list(spec.panel),
            "critics": list(spec.critics),
            "judge": spec.judge,
            "steps": list(steps),
            "resumed": bool(prior.proposals or prior.pack is not None),
        },
    )
    pack: PackBuild | None = prior.pack
    verification: list[tuple[EvidenceItem, bytes]] = list(prior.verification)
    requests = RequestState(executed=dict(prior.requests_executed), count=len(verification))
    for step in steps:
        if draft.stopped is not None:
            w.append("stage.skipped", {"step": step, "reason": draft.stopped})
            continue
        try:
            _check_stop(ctx, f"step:{step}")
            w.append("step.started", {"step": step})
            if step == "pack":
                pack = _step_pack(spec, ctx, env, pack)
            else:
                assert pack is not None
                if step == "propose":
                    _step_propose(spec, ctx, pack, draft, prior)
                elif step in ("verify", "verify2"):
                    _step_verify(step, spec, ctx, env, draft, verification, requests)
                elif step == "critique":
                    _step_critique(spec, ctx, pack, draft, prior)
                elif step in ("adjudicate", "adjudicate_iter", "summarize"):
                    _step_judge(step, spec, ctx, env, pack, draft, verification, requests, prior)
                else:  # pragma: no cover - the table is closed
                    raise AssertionError(step)
            w.append("step.finished", {"step": step})
            draft.steps_done.append(step)
        except ArmStopped as exc:
            draft.stopped = exc.reason
            w.append("step.aborted", {"step": step, "reason": exc.reason})
    _fill_missing(spec, draft)
    return draft


def _fill_missing(spec: CellSpec, draft: ArmDraft) -> None:
    """After a stop, every cell that never ran is recorded as missing."""
    if draft.stopped is None:
        return
    have = {(m.worker_id, m.stage) for m in draft.missing}
    proposed = {p.worker_id for p in draft.proposals}
    for worker_id in spec.panel:
        if worker_id not in proposed and (worker_id, Stage.PROPOSE) not in have:
            draft.missing.append(
                MissingCell(worker_id=worker_id, stage=Stage.PROPOSE, reason=draft.stopped)
            )
    if spec.arm is Arm.INDEP_VERIFY_CRITIQUE:
        critiqued = {c.worker_id for c in draft.critiques}
        for critic in spec.critics:
            if critic not in critiqued and (critic, Stage.CRITIQUE) not in have:
                draft.missing.append(
                    MissingCell(worker_id=critic, stage=Stage.CRITIQUE, reason=draft.stopped)
                )
    if spec.judge and draft.final_adjudication is None:
        stage = Stage.SUMMARIZE if spec.arm is Arm.CONSENSUS else Stage.ADJUDICATE
        if (spec.judge, stage) not in have:
            draft.missing.append(
                MissingCell(worker_id=spec.judge, stage=stage, reason=draft.stopped)
            )


def _step_pack(
    spec: CellSpec, ctx: StageContext, env: VerifyEnv, pack: PackBuild | None
) -> PackBuild:
    if pack is not None:
        ctx.writer.append("stage.resumed", {"stage": "pack", "pack_id": pack.pack.pack_id})
        ctx.pack_items = list(pack.items)
        return pack
    try:
        built = build_evidence_pack(
            spec.task,
            env=env,
            writer=ctx.writer,
            repeat_index=spec.repeat_index,
            policy_sha256=ctx.policy_sha256,
            snapshot_sha=ctx.snapshot_sha,
            stop_check=ctx.stop_check,
            ts=ctx.ts,
        )
    except EvidenceStopped:
        raise ArmStopped("stop") from None
    ctx.pack_items = list(built.items)
    return built


def _step_propose(
    spec: CellSpec, ctx: StageContext, pack: PackBuild, draft: ArmDraft, prior: Prior
) -> None:
    for i, worker_id in enumerate(spec.panel):
        fin = prior.finished.get(("propose", worker_id, 0))
        if fin is not None:
            ctx.writer.append("stage.resumed", {"stage": "propose", "worker_id": worker_id})
            draft.propose_keys.append(str(fin["idempotency_key"]))
            prop = prior.proposals.get(worker_id)
            if prop is not None:
                draft.proposals.append(prop)
            else:
                draft.missing.append(
                    MissingCell(
                        worker_id=worker_id, stage=Stage.PROPOSE, reason="absent (recorded)"
                    )
                )
            continue
        _check_stop(ctx, f"cell:propose:{worker_id}")
        out, prop = run_propose(ctx, worker_id, pack)
        draft.propose_keys.append(out.key)
        if prop is not None:
            draft.proposals.append(prop)
            continue
        reason = f"{out.error_class.value}: {out.reason}"[:200]
        draft.missing.append(MissingCell(worker_id=worker_id, stage=Stage.PROPOSE, reason=reason))
        ctx.writer.append(
            "cell.missing", {"worker_id": worker_id, "stage": "propose", "reason": reason}
        )
        if out.error_class is ErrorClass.BUDGET_TRIPPED:
            for rest in spec.panel[i + 1 :]:
                draft.missing.append(
                    MissingCell(worker_id=rest, stage=Stage.PROPOSE, reason="budget")
                )
                ctx.writer.append(
                    "stage.skipped", {"stage": "propose", "worker_id": rest, "reason": "budget"}
                )
            raise ArmStopped("budget")


def _step_verify(
    step: str,
    spec: CellSpec,
    ctx: StageContext,
    env: VerifyEnv,
    draft: ArmDraft,
    verification: list[tuple[EvidenceItem, bytes]],
    requests: RequestState,
) -> None:
    labels = labels_for(draft.proposals)
    sources: list[tuple[str, list[Any]]] = []
    if step == "verify":
        sources = [(labels[p.proposal_id], list(p.evidence_requests)) for p in draft.proposals]
    else:
        n = 0
        for crit in draft.critiques:
            for ch in crit.challenges:
                n += 1
                if ch.evidence_request is not None:
                    sources.append((f"C{n}", [ch.evidence_request]))
    for source, reqs in sources:
        if not reqs:
            continue
        try:
            items = execute_evidence_requests(
                reqs,
                source=source,
                env=env,
                writer=ctx.writer,
                state=requests,
                task_id=spec.task.task_id,
                stop_check=ctx.stop_check,
                ts=ctx.ts,
            )
        except EvidenceStopped:
            raise ArmStopped("stop") from None
        for item in items:
            verification.append((item, (ctx.writer.blobs_dir / item.content_sha256).read_bytes()))
    ctx.verification = list(verification)


def _step_critique(
    spec: CellSpec, ctx: StageContext, pack: PackBuild, draft: ArmDraft, prior: Prior
) -> None:
    if not draft.proposals:
        ctx.writer.append("stage.skipped", {"stage": "critique", "reason": "no proposals"})
        return
    for critic in spec.critics:
        if ("critique", critic, 0) in prior.finished:
            ctx.writer.append("stage.resumed", {"stage": "critique", "worker_id": critic})
            crit = prior.critiques.get(critic)
            if crit is not None:
                draft.critiques.append(crit)
            else:
                draft.missing.append(
                    MissingCell(worker_id=critic, stage=Stage.CRITIQUE, reason="absent (recorded)")
                )
            continue
        _check_stop(ctx, f"cell:critique:{critic}")
        out, crit = run_critique(ctx, critic, pack, draft.proposals)
        if crit is not None:
            draft.critiques.append(crit)
            continue
        reason = f"{out.error_class.value}: {out.reason}"[:200]
        draft.missing.append(MissingCell(worker_id=critic, stage=Stage.CRITIQUE, reason=reason))
        ctx.writer.append(
            "cell.missing", {"worker_id": critic, "stage": "critique", "reason": reason}
        )
        if out.error_class is ErrorClass.BUDGET_TRIPPED:
            raise ArmStopped("budget")


def _step_judge(
    step: str,
    spec: CellSpec,
    ctx: StageContext,
    env: VerifyEnv,
    pack: PackBuild,
    draft: ArmDraft,
    verification: list[tuple[EvidenceItem, bytes]],
    requests: RequestState,
    prior: Prior,
) -> None:
    assert spec.judge is not None
    judge = spec.judge
    role = "summarizer" if step == "summarize" else "adjudicator"
    stage = Stage.SUMMARIZE if step == "summarize" else Stage.ADJUDICATE
    if not draft.proposals:
        ctx.writer.append("stage.skipped", {"stage": stage.value, "reason": "no proposals"})
        draft.missing.append(MissingCell(worker_id=judge, stage=stage, reason="no proposals"))
        return
    critiques = draft.critiques if spec.arm is Arm.INDEP_VERIFY_CRITIQUE else []
    iteration = 0
    while True:
        prior_adj = prior.adjudications.get((stage.value, iteration))
        if prior_adj is not None:
            ctx.writer.append(
                "stage.resumed", {"stage": stage.value, "worker_id": judge, "iteration": iteration}
            )
            draft.adjudications.append(prior_adj)
            raw, enforced = prior_adj
            draft.final_adjudication = enforced
            pending = list(raw.evidence_requests)
        else:
            _check_stop(ctx, f"cell:{stage.value}:{judge}:{iteration}")
            res = run_adjudicate(
                ctx,
                judge,
                pack,
                draft.proposals,
                critiques,
                verification,
                evidence_index(pack, verification),
                role=role,
                iteration=iteration,
            )
            draft.adjudications.append(res)
            if res.enforced is None:
                reason = f"{res.outcome.error_class.value}: {res.outcome.reason}"[:200]
                draft.missing.append(MissingCell(worker_id=judge, stage=stage, reason=reason))
                ctx.writer.append(
                    "cell.missing", {"worker_id": judge, "stage": stage.value, "reason": reason}
                )
                if res.outcome.error_class is ErrorClass.BUDGET_TRIPPED:
                    raise ArmStopped("budget")
                return
            draft.final_adjudication = res.enforced
            pending = res.requests
        if step != "adjudicate_iter" or not pending or iteration + 1 >= MAX_ITERATIONS:
            break
        try:
            items = execute_evidence_requests(
                pending,
                source="judge",
                env=env,
                writer=ctx.writer,
                state=requests,
                task_id=spec.task.task_id,
                stop_check=ctx.stop_check,
                ts=ctx.ts,
            )
        except EvidenceStopped:
            raise ArmStopped("stop") from None
        if not items:
            ctx.writer.append(
                "adjudication.iteration_stopped",
                {"iteration": iteration, "reason": "no new evidence from the judge's requests"},
            )
            break
        for item in items:
            verification.append((item, (ctx.writer.blobs_dir / item.content_sha256).read_bytes()))
        ctx.verification = list(verification)
        iteration += 1
        draft.iterations = iteration
        ctx.writer.append(
            "adjudication.iteration", {"iteration": iteration, "new_items": len(items)}
        )


# --------------------------------------------------------------------------- finish


def finish_arm(
    draft: ArmDraft,
    ctx: StageContext,
    view: LedgerView,
    *,
    contaminated: bool,
    containment: str | None,
) -> ArmRun:
    """Build and append the ``ArmRun`` (``arm.finished``) from the draft,
    the ledger's cost totals and the scan verdict."""
    totals = cost_totals(view)
    record = ArmRun(
        arm=draft.spec.arm,
        task_id=draft.spec.task.task_id,
        repeat_index=draft.spec.repeat_index,
        category=draft.spec.task.category,
        panel=list(draft.spec.panel),
        # only an arm WITH a critique step has critics (arm 3 never ran them)
        critics=list(draft.spec.critics) if "critique" in ARM_STEPS[draft.spec.arm] else [],
        judge=draft.spec.judge,
        steps=list(draft.steps_done),
        propose_keys=sorted(set(draft.propose_keys)),
        status=draft.status,
        missing_cells=list(draft.missing),
        iterations=draft.iterations,
        contaminated=contaminated,
        containment=containment,
        cost_spent_usd=totals.spent_usd,
        cost_attributed_usd=totals.attributed_usd,
        final_adjudication_id=draft.final_adjudication.adjudication_id
        if draft.final_adjudication
        else None,
    )
    ctx.writer.append("arm.finished", record)
    return record


def stop_file_paths(runs_dir: Path, campaign_id: str | None) -> list[Path]:
    paths = [Path(runs_dir) / "STOP"]
    if campaign_id:
        paths.append(Path(runs_dir) / campaign_id / "STOP")
    return paths


def utc_now() -> str:
    return now_ts()
