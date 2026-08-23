"""eris.arms: the arm table, the paired-ablation proof, STOP at stage/cell
boundaries, budget skips, judge iterations, consensus raw+enforced, resume
(prior replay, abandoned attempts, stale groups, stale scratch)."""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from typing import Any

import pytest

from eris.arms import (
    ARM_ORDER,
    ARM_STEPS,
    MAX_ITERATIONS,
    ArmStopped,
    CellSpec,
    ResumeRefused,
    finish_arm,
    kill_stale_groups,
    load_prior,
    remove_stale_scratch,
    run_arm,
)
from eris.cache import Cache
from eris.evidence import TaskSpec
from eris.launch import WorkerCall, WorkerResult
from eris.ledger import LedgerView, cost_totals
from eris.redact import Redactor
from eris.retry import BudgetLedger
from eris.scan import build_patterns, scan_and_record
from eris.schemas import Arm, ArmRun, ArmStatus, Invocation, Stage, Verdict
from eris.stages import StageContext, load_prompt_files, store_pending_cache
from eris.writer import RunWriter
from tests.test_evidence import ScriptedPopen, make_env, make_snapshot, task
from tests.test_stages import (
    GOOD_CRITIQUE,
    GOOD_PROPOSAL,
    PROMPTS,
    Spy,
    full_policy,
    good_adjudication,
)

ADJ_ANY = {
    "verdict": "REVISE",
    "rulings": [],
    "dissent": [],
    "residual_risks": [{"text": "r", "severity": "low", "mitigation": None}],
    "rationale": "rationale",
    "evidence_requests": [],
}


class Fleet:
    """One fake world (snapshot, policy, cache) hosting several cells."""

    def __init__(
        self, tmp_path: Path, answers: dict[tuple[str, str], list[Any]], *, cache: bool = True
    ) -> None:
        self.tmp = tmp_path
        self.snapshot = make_snapshot(tmp_path)
        self.policy = full_policy(tmp_path)
        self.spy = Spy(answers)
        self.cache = Cache(tmp_path / "cache", runs_dir=tmp_path / "runs") if cache else None
        self.stop = False
        self.stop_after_calls: int | None = None
        self.ceiling = 50.0
        self.popens: list[ScriptedPopen] = []
        self.writers: dict[str, RunWriter] = {}

    def stop_check(self) -> bool:
        if self.stop_after_calls is not None and len(self.spy.calls) >= self.stop_after_calls:
            return True
        return self.stop

    def open(self, spec: CellSpec, *, resume: bool = False) -> tuple[StageContext, Any]:
        run_dir = self.tmp / "runs" / spec.run_id
        writer = RunWriter(run_dir, Redactor(), run_id=spec.run_id, resume=resume).open()
        self.writers[spec.run_id] = writer
        popen = ScriptedPopen({"rev-parse": b"f" * 40 + b"\n"})
        self.popens.append(popen)
        env = make_env(self.tmp, self.snapshot, popen, self.policy)
        ctx = StageContext(
            writer=writer,
            policy=self.policy,
            policy_sha256="0" * 64,
            task=spec.task,
            repeat_index=spec.repeat_index,
            snapshot_sha="f" * 40,
            prompts=load_prompt_files(PROMPTS),
            budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=self.ceiling),
            stop_check=self.stop_check,
            sleep=lambda _s: None,
            cwd_for=lambda _w, _r: self.snapshot,
            scratch_dir=run_dir / "scratch",
            home=str(self.tmp / "home"),
            path_env="/usr/bin:/bin",
            runner=self.spy,
            cache=self.cache,
            campaign_id="camp",
        )
        return ctx, env

    def run(
        self, spec: CellSpec, *, resume: bool = False, prior_loader: bool = False
    ) -> tuple[ArmRun, LedgerView, StageContext]:
        ctx, env = self.open(spec, resume=resume)
        prior = None
        if prior_loader:
            view0 = LedgerView.from_path(ctx.writer.events_path)
            prior = load_prior(view0, ctx.writer, per_call_usd=0.5)
            kill_stale_groups(prior.stale_pgids, killpg=lambda *_: None, alive=lambda _p: False)
            remove_stale_scratch(self.tmp / "scratch-root")
        draft = run_arm(spec, ctx, env, prior=prior)
        patterns = build_patterns(snapshot_root=None, home=self.tmp / "home")
        scan = scan_and_record(ctx.writer, patterns)
        hits: dict[str, int] = {}
        for h in scan.hits:
            if h.where.startswith("blob:"):
                hits[h.where[5:]] = hits.get(h.where[5:], 0) + h.count
        store_pending_cache(ctx, hits)
        view = LedgerView.from_path(ctx.writer.events_path)
        record = finish_arm(draft, ctx, view, contaminated=scan.contaminated, containment=None)
        ctx.writer.finalize({"arm": spec.arm.value})
        return record, LedgerView.from_path(ctx.writer.events_path), ctx


def spec(arm: Arm, **kw: Any) -> CellSpec:
    base: dict[str, Any] = {
        "arm": arm,
        "task": task(),
        "repeat_index": 0,
        "panel": ("grok", "codex"),
        "critics": ("codex",),
        "judge": "judge",
    }
    base.update(kw)
    return CellSpec(**base)


def answers(
    over: dict[tuple[str, str], list[Any]] | None = None,
) -> dict[tuple[str, str], list[Any]]:
    base: dict[tuple[str, str], list[Any]] = {
        ("grok", "propose"): [GOOD_PROPOSAL],
        ("codex", "propose"): [{**GOOD_PROPOSAL, "summary": "codex view", "findings": []}],
        ("codex", "critique"): [GOOD_CRITIQUE],
        ("judge", "adjudicate"): [ADJ_ANY],
        ("judge", "summarize"): [ADJ_ANY],
    }
    base.update(over or {})
    return base


# --------------------------------------------------------------------------- table


def test_arm_table_is_data_in_the_fixed_order() -> None:
    assert ARM_ORDER == (
        Arm.SINGLE,
        Arm.CONSENSUS,
        Arm.INDEP_VERIFY,
        Arm.INDEP_VERIFY_ITER,
        Arm.INDEP_VERIFY_CRITIQUE,
    )
    assert ARM_STEPS[Arm.SINGLE] == ("pack", "propose")
    assert ARM_STEPS[Arm.CONSENSUS] == ("pack", "propose", "summarize")
    assert ARM_STEPS[Arm.INDEP_VERIFY] == ("pack", "propose", "verify", "adjudicate")
    assert ARM_STEPS[Arm.INDEP_VERIFY_ITER] == ("pack", "propose", "verify", "adjudicate_iter")
    assert ARM_STEPS[Arm.INDEP_VERIFY_CRITIQUE] == (
        "pack",
        "propose",
        "verify",
        "critique",
        "verify2",
        "adjudicate",
    )
    assert set(ARM_STEPS) == set(Arm) and MAX_ITERATIONS == 3
    with pytest.raises(ValueError, match="judge"):
        spec(Arm.INDEP_VERIFY, judge=None)
    with pytest.raises(ValueError, match="critics"):
        spec(Arm.INDEP_VERIFY_CRITIQUE, critics=())
    with pytest.raises(ValueError, match="single"):
        spec(Arm.SINGLE)
    assert spec(Arm.SINGLE, panel=("grok",), judge=None).run_id == "t_01-r0-single-grok"
    assert spec(Arm.INDEP_VERIFY_ITER).run_id == "t_01-r0-indep_verify_iter"


# --------------------------------------------------------------------------- paired ablation


def test_paired_ablation_one_set_of_propose_spawns_across_arms_3_3b_4(tmp_path: Path) -> None:
    """Item 2: one world, task+repeat fixed; arms 3, 3b, 4 -> ONE set of
    PROPOSE spawns; 3b/4 carry invocation.reused; propose blob hashes are
    equal across run dirs; adjudicator prompt hashes differ; arm 3's judge
    prompt contains no critique text; Invocation carries no arm."""
    fleet = Fleet(tmp_path, answers())
    r3, v3, _ = fleet.run(spec(Arm.INDEP_VERIFY))
    r3b, v3b, _ = fleet.run(spec(Arm.INDEP_VERIFY_ITER))
    r4, v4, _ = fleet.run(spec(Arm.INDEP_VERIFY_CRITIQUE))
    propose_calls = [c for c in fleet.spy.calls if c.stage is Stage.PROPOSE]
    assert len(propose_calls) == 2 and {c.worker_id for c in propose_calls} == {"grok", "codex"}
    assert "invocation.reused" not in v3.kinds()

    def reused_propose(v: LedgerView) -> int:
        return len(
            [
                i
                for i in v.payloads("invocation.finished")
                if i["stage"] == "propose" and i["reused_from"] is not None
            ]
        )

    assert reused_propose(v3) == 0 and reused_propose(v3b) == 2 and reused_propose(v4) == 2
    assert (
        r3.status is ArmStatus.COMPLETE
        and r3b.status is ArmStatus.COMPLETE
        and r4.status is ArmStatus.COMPLETE
    )
    assert r3.propose_keys == r3b.propose_keys == r4.propose_keys and len(r3.propose_keys) == 2

    # propose blobs: identical hashes in every run dir, and present on disk in each
    def propose_blobs(v: LedgerView) -> set[str]:
        return {
            str(i["stdout_sha256"])
            for i in v.payloads("invocation.finished")
            if i["stage"] == "propose"
        }

    blobs = propose_blobs(v3)
    assert blobs == propose_blobs(v3b) == propose_blobs(v4) and len(blobs) == 2
    for run_id in (
        r.run_id
        for r in (
            spec(Arm.INDEP_VERIFY),
            spec(Arm.INDEP_VERIFY_ITER),
            spec(Arm.INDEP_VERIFY_CRITIQUE),
        )
    ):
        for sha in blobs:
            assert (tmp_path / "runs" / run_id / "blobs" / "sha256" / sha).is_file()
    # the reused invocations name their origin and cost nothing new
    reused = v4.payloads("invocation.reused")
    origin_ids = {
        i["invocation_id"] for i in v3.payloads("invocation.finished") if i["stage"] == "propose"
    }
    assert {r["reused_from"] for r in reused} == origin_ids
    assert all(
        c["counted"] is False for c in v4.payloads("cost") if c["invocation_id"] in origin_ids
    )
    # adjudicator prompts differ: arm 4 carries critiques, arm 3 none
    # arm 3b's judge prompt is byte-identical to arm 3's (same evidence, no
    # critiques), so that judge call is itself a cache hit: two judge spawns (arms 3, 4)
    judge_calls = [c for c in fleet.spy.calls if c.stage is Stage.ADJUDICATE]
    p3, p4 = [c.prompt for c in judge_calls]
    assert p3 != p4
    assert "tests exist under tests/" not in p3 and "tests exist under tests/" in p4
    inv3 = [i for i in v3.payloads("invocation.finished") if i["stage"] == "adjudicate"][0]
    inv3b = [i for i in v3b.payloads("invocation.finished") if i["stage"] == "adjudicate"][0]
    inv4 = [i for i in v4.payloads("invocation.finished") if i["stage"] == "adjudicate"][0]
    assert inv3["prompt_sha256"] == inv3b["prompt_sha256"] != inv4["prompt_sha256"]
    assert inv3b["reused_from"] == inv3["invocation_id"] and inv4["reused_from"] is None
    # no Invocation carries an arm
    for v in (v3, v3b, v4):
        for inv in v.records("invocation.finished", Invocation):
            assert "arm" not in inv.model_dump() and not hasattr(inv, "arm")
    assert (
        r4.critics == ["codex"]
        and r3.critics == []
        and r4.steps == list(ARM_STEPS[Arm.INDEP_VERIFY_CRITIQUE])
    )
    # costs: arm 3 paid for proposals; arm 4 attributes them without spending
    assert r3.cost_spent_usd > r4.cost_spent_usd and r4.cost_attributed_usd > r4.cost_spent_usd
    # verification items were produced from the proposals' requests on the original
    assert any(
        e["kind"] == "evidence.item" and e["payload"]["phase"] == "verification"
        for e in [e.model_dump() for e in v3.events]
    )
    assert all(
        kw["cwd"] == str(fleet.snapshot.resolve()) for p in fleet.popens for _a, kw in p.calls
    )


def test_single_arm_reuses_the_panel_proposal_via_cache(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers())
    r1, v1, _ = fleet.run(spec(Arm.SINGLE, panel=("grok",), judge=None, critics=()))
    assert r1.status is ArmStatus.COMPLETE and r1.judge is None and r1.final_adjudication_id is None
    r3, v3, _ = fleet.run(spec(Arm.INDEP_VERIFY))
    assert (
        len([c for c in fleet.spy.calls if c.stage is Stage.PROPOSE]) == 2
    )  # grok once, codex once
    assert v3.kinds().count("invocation.reused") == 1
    assert r1.propose_keys[0] in r3.propose_keys


# --------------------------------------------------------------------------- STOP / budget


def test_stop_at_a_cell_boundary_prevents_the_next_first_attempt(tmp_path: Path) -> None:
    """Item 6: STOP appears after the first panel worker finished; the second
    worker's FIRST attempt never spawns; the remaining stages are skipped;
    the cell is incomplete with the missing cells recorded."""
    fleet = Fleet(tmp_path, answers(), cache=False)
    fleet.stop_after_calls = 1
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY_CRITIQUE))
    assert len(fleet.spy.calls) == 1 and fleet.spy.calls[0].worker_id == "grok"
    assert record.status is ArmStatus.INCOMPLETE
    missing = {(m.worker_id, m.stage.value): m.reason for m in record.missing_cells}
    assert missing == {
        ("codex", "propose"): "stop",
        ("codex", "critique"): "stop",
        ("judge", "adjudicate"): "stop",
    }
    kinds = view.kinds()
    assert "run.stopped" in kinds and kinds.count("step.aborted") == 1
    skipped = [e.payload for e in view.of_kind("stage.skipped")]
    assert [s["step"] for s in skipped] == ["verify", "critique", "verify2", "adjudicate"]
    assert all(s["reason"] == "stop" for s in skipped)
    assert record.steps == ["pack"]
    stopped = view.last("run.stopped")
    assert stopped is not None and stopped["where"] == "cell:propose:codex"


def test_stop_at_a_step_boundary(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers(), cache=False)
    fleet.stop_after_calls = 2  # after both proposals: before the verify step
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY))
    assert len(fleet.spy.calls) == 2 and record.steps == ["pack", "propose"]
    assert view.last("run.stopped") == {"where": "step:verify", "reason": "STOP file present"}
    assert [m.worker_id for m in record.missing_cells] == ["judge"]


def test_budget_trip_marks_the_cell_missing_and_skips_the_remaining_stages(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers(), cache=False)
    fleet.ceiling = 0.51  # the first pre-check (0.5) fits; after $0.02 known the second trips
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY))
    assert len(fleet.spy.calls) == 1
    assert record.status is ArmStatus.INCOMPLETE
    reasons = {m.worker_id: m.reason for m in record.missing_cells}
    assert reasons["codex"].startswith("budget_tripped") and reasons["judge"] == "budget"
    kinds = view.kinds()
    assert "budget.tripped" in kinds and "cell.missing" in kinds
    tripped = [i for i in view.payloads("invocation.finished") if i["status"] == "budget_tripped"]
    assert len(tripped) == 1 and tripped[0]["worker_id"] == "codex"
    assert [s["step"] for s in view.payloads("stage.skipped") if "step" in s] == [
        "verify",
        "adjudicate",
    ]
    assert all(s["reason"] == "budget" for s in view.payloads("stage.skipped"))


# --------------------------------------------------------------------------- judge variants


def test_adjudicate_iter_executes_the_judges_requests_and_reruns(tmp_path: Path) -> None:
    first = {
        **ADJ_ANY,
        "evidence_requests": [
            {"argv": ["git", "status", "--porcelain"], "rationale": "", "expect_exit_code": None}
        ],
    }
    fleet = Fleet(
        tmp_path, answers({("judge", "adjudicate"): [first, first, ADJ_ANY]}), cache=False
    )
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY_ITER))
    judge_calls = [c for c in fleet.spy.calls if c.stage is Stage.ADJUDICATE]
    # iteration 0 requests -> executed -> iteration 1 requests the same command -> duplicate,
    # nothing new -> iteration stops; judge ran twice, proposals/critics never re-ran
    assert len(judge_calls) == 2 and record.iterations == 1
    assert len([c for c in fleet.spy.calls if c.stage is Stage.PROPOSE]) == 2
    assert (
        "status --porcelain" not in judge_calls[0].prompt or "git status" in judge_calls[1].prompt
    )
    assert judge_calls[0].prompt != judge_calls[1].prompt
    kinds = view.kinds()
    assert "adjudication.iteration" in kinds and "adjudication.iteration_stopped" in kinds
    assert "verify.duplicate" in kinds
    assert record.status is ArmStatus.COMPLETE and record.final_adjudication_id is not None


def test_adjudicate_iter_caps_at_max_iterations(tmp_path: Path) -> None:
    reqs = [
        [{"argv": ["git", "status", "--porcelain"], "rationale": "", "expect_exit_code": None}],
        [
            {
                "argv": ["git", "grep", "-l", "-e", "x", "--", "src"],
                "rationale": "",
                "expect_exit_code": None,
            }
        ],
        [{"argv": ["git", "rev-parse", "HEAD"], "rationale": "", "expect_exit_code": None}],
        [
            {
                "argv": ["git", "log", "--oneline", "-n", "3"],
                "rationale": "",
                "expect_exit_code": None,
            }
        ],
    ]
    adjs = [{**ADJ_ANY, "evidence_requests": r} for r in reqs]
    fleet = Fleet(tmp_path, answers({("judge", "adjudicate"): adjs}), cache=False)
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY_ITER))
    assert len([c for c in fleet.spy.calls if c.stage is Stage.ADJUDICATE]) == MAX_ITERATIONS
    assert record.iterations == MAX_ITERATIONS - 1


def test_consensus_records_raw_and_enforced_and_summarizer_role(tmp_path: Path) -> None:
    adj = {**good_adjudication(["clm-x-0"], []), "verdict": "ACCEPT"}
    fleet = Fleet(tmp_path, answers({("judge", "summarize"): [adj]}), cache=False)
    record, view, _ = fleet.run(spec(Arm.CONSENSUS))
    assert record.status is ArmStatus.COMPLETE and record.steps == ["pack", "propose", "summarize"]
    raw = view.last("adjudication.raw")
    enforced = view.last("adjudication.enforced")
    assert raw is not None and enforced is not None
    assert raw["verdict"] == "ACCEPT" == enforced["verdict"]  # 1 downgrade: no escalation
    assert enforced["downgrades"] == 1 and raw["downgrades"] == 0
    assert record.final_adjudication_id == enforced["adjudication_id"]
    call = [c for c in fleet.spy.calls if c.stage is Stage.SUMMARIZE][0]
    assert "SUMMARIZER" in call.prompt and call.policy.tools == []
    assert "verify" not in record.steps and "critique" not in record.steps


def test_judge_absent_is_a_missing_cell(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers({("judge", "adjudicate"): ["TIMEOUT"]}), cache=False)
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY))
    assert record.status is ArmStatus.INCOMPLETE and record.final_adjudication_id is None
    assert [m.worker_id for m in record.missing_cells] == ["judge"]
    assert record.missing_cells[0].reason.startswith("timeout")
    assert len([c for c in fleet.spy.calls if c.stage is Stage.ADJUDICATE]) == 1  # terminal


def test_no_proposals_skips_critique_and_judge(tmp_path: Path) -> None:
    fleet = Fleet(
        tmp_path,
        answers({("grok", "propose"): ["TIMEOUT"], ("codex", "propose"): ["TIMEOUT"]}),
        cache=False,
    )
    record, view, _ = fleet.run(spec(Arm.INDEP_VERIFY_CRITIQUE))
    assert record.status is ArmStatus.INCOMPLETE
    assert {m.worker_id for m in record.missing_cells} == {"grok", "codex", "judge"}
    skipped = [s for s in view.payloads("stage.skipped") if s.get("reason") == "no proposals"]
    assert [s["stage"] for s in skipped] == ["critique", "adjudicate"]
    assert len([c for c in fleet.spy.calls if c.stage is Stage.CRITIQUE]) == 0


# --------------------------------------------------------------------------- resume


class CrashingSpy(Spy):
    def __init__(self, answers: dict[tuple[str, str], list[Any]], crash_on: str) -> None:
        super().__init__(answers)
        self.crash_on = crash_on

    def __call__(self, call: WorkerCall) -> WorkerResult:
        if call.stage.value == self.crash_on:
            self.calls.append(call)
            raise RuntimeError("simulated harness crash mid-call")
        return super().__call__(call)


def test_resume_replays_finished_stages_and_abandons_the_open_attempt(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers(), cache=False)
    fleet.spy = CrashingSpy(answers(), crash_on="adjudicate")
    s = spec(Arm.INDEP_VERIFY_CRITIQUE)
    ctx, env = fleet.open(s)
    ctx.writer.append(
        "invocation.spawned", {"idempotency_key": "x", "pgid": 1}
    )  # unrelated, earlier
    with pytest.raises(RuntimeError, match="simulated"):
        run_arm(s, ctx, env)
    # mimic what the harness does at spawn: the judge's pgid was recorded
    judge_key = [
        p
        for p in LedgerView.from_path(ctx.writer.events_path).payloads("stage.started")
        if p["stage"] == "adjudicate"
    ][0]["idempotency_key"]
    ctx.writer.append("invocation.spawned", {"idempotency_key": judge_key, "pgid": 4242})
    scratch_root = tmp_path / "scratch-root"
    (scratch_root / "call-deadbeef").mkdir(parents=True)
    (scratch_root / "call-deadbeef" / "last_message.json").write_text("{}")
    ctx.writer.close()
    before = LedgerView.from_path(ctx.writer.events_path)
    assert len([c for c in fleet.spy.calls if c.stage is Stage.PROPOSE]) == 2
    # resume
    fleet.spy = Spy(answers())
    ctx2, env2 = fleet.open(s, resume=True)
    view = LedgerView.from_path(ctx2.writer.events_path)
    prior = load_prior(view, ctx2.writer, per_call_usd=0.5)
    assert (
        prior.pack is not None
        and set(prior.proposals) == {"grok", "codex"}
        and set(prior.critiques) == {"codex"}
    )
    assert len(prior.verification) >= 1 and prior.adjudications == {}
    assert [a["stage"] for a in prior.abandoned] == ["adjudicate"] and prior.stale_pgids == [4242]
    killed_with: list[tuple[int, int]] = []
    live = {"alive": True}

    def fake_killpg(pg: int, sig: int) -> None:
        killed_with.append((pg, sig))
        if sig == signal.SIGTERM:
            live["alive"] = False

    killed = kill_stale_groups(
        prior.stale_pgids, killpg=fake_killpg, alive=lambda _p: live["alive"], grace_s=0.5
    )
    assert killed == [4242] and [k[0] for k in killed_with] == [4242, 4242]
    assert remove_stale_scratch(scratch_root) == ["call-deadbeef"]
    assert not (scratch_root / "call-deadbeef").exists()
    after = LedgerView.from_path(ctx2.writer.events_path)
    assert after.kinds()[len(before.events) :] == ["invocation.abandoned", "cost"]
    abandoned = after.last("invocation.abandoned")
    assert abandoned is not None and abandoned["pgid"] == 4242 and abandoned["attempt"] == 1
    cost = after.records("cost", __import__("eris.schemas", fromlist=["CostRecord"]).CostRecord)[-1]
    assert cost.cost_usd == 0.5 and not cost.cost_known and cost.estimated and cost.counted
    draft = run_arm(s, ctx2, env2, prior=prior)
    assert draft.status is ArmStatus.COMPLETE
    assert [c.stage for c in fleet.spy.calls] == [Stage.ADJUDICATE]  # only the judge ran
    final = LedgerView.from_path(ctx2.writer.events_path)
    resumed = [p["stage"] for p in final.payloads("stage.resumed")]
    assert resumed == ["pack", "propose", "propose", "critique"]
    assert (
        final.last(
            "arm.started",
        )["resumed"]
        is True
        if final.last("arm.started")
        else False
    )
    ctx2.writer.close()


def test_resume_does_not_trust_a_tampered_blob(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers(), cache=False)
    fleet.spy = CrashingSpy(answers(), crash_on="adjudicate")
    s = spec(Arm.INDEP_VERIFY)
    ctx, env = fleet.open(s)
    with pytest.raises(RuntimeError):
        run_arm(s, ctx, env)
    grok_inv = [
        i
        for i in LedgerView.from_path(ctx.writer.events_path).payloads("invocation.finished")
        if i["worker_id"] == "grok"
    ][0]
    (ctx.writer.blobs_dir / grok_inv["stdout_sha256"]).write_bytes(b"tampered")
    ctx.writer.close()
    fleet.spy = Spy(answers())
    ctx2, env2 = fleet.open(s, resume=True)
    assert grok_inv["stdout_sha256"] in ctx2.writer.corrupt_blobs
    prior = load_prior(LedgerView.from_path(ctx2.writer.events_path), ctx2.writer, per_call_usd=0.5)
    assert "grok" not in prior.proposals and "codex" in prior.proposals
    draft = run_arm(s, ctx2, env2, prior=prior)
    assert draft.status is ArmStatus.COMPLETE
    assert [c.worker_id for c in fleet.spy.calls] == [
        "grok",
        "judge",
    ]  # grok re-ran, codex replayed
    ctx2.writer.close()


def test_kill_stale_groups_refuses_without_killpg_and_skips_dead_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert kill_stale_groups([]) == []
    assert kill_stale_groups([1, 2], killpg=lambda *_: None, alive=lambda _p: False) == []
    monkeypatch.delattr(os, "killpg")
    with pytest.raises(ResumeRefused, match="documented refusal"):
        kill_stale_groups([4242])


def test_cost_totals_distinguish_spent_attributed_and_unknown(tmp_path: Path) -> None:
    fleet = Fleet(tmp_path, answers())
    r3, v3, _ = fleet.run(spec(Arm.INDEP_VERIFY))
    r4, v4, _ = fleet.run(spec(Arm.INDEP_VERIFY_CRITIQUE))
    t3, t4 = cost_totals(v3), cost_totals(v4)
    assert t3.spent_usd == t3.attributed_usd and t3.known_usd == t3.spent_usd
    assert t4.attributed_usd > t4.spent_usd and "propose" in t4.by_stage_attributed
    assert t4.by_stage_spent.get("propose", 0.0) == 0.0 and t4.by_stage_spent["critique"] > 0
    assert t3.attempts == 3 and t4.attempts == 4
    assert r3.cost_spent_usd == t3.spent_usd and r4.cost_attributed_usd == t4.attributed_usd


def test_arm_stopped_is_an_exception_with_a_reason() -> None:
    exc = ArmStopped("budget")
    assert exc.reason == "budget" and str(exc) == "budget"
    assert Verdict.ABSTAIN.value == "ABSTAIN"  # the vocabulary the scorer reads
    assert TaskSpec.model_validate(task().model_dump()) == task()
    assert json.loads(json.dumps({"x": 1})) == {"x": 1}


def test_resume_is_idempotent_and_restores_the_request_dedupe_set(tmp_path: Path) -> None:
    """Items 7 + 8: a second resume does not re-append invocation.abandoned
    (deduped by key + attempt); an already-executed request is a
    verify.duplicate on resume, never re-executed."""
    fleet = Fleet(tmp_path, answers(), cache=False)
    fleet.spy = CrashingSpy(answers(), crash_on="adjudicate")
    s = spec(Arm.INDEP_VERIFY)
    ctx, env = fleet.open(s)
    with pytest.raises(RuntimeError):
        run_arm(s, ctx, env)
    ctx.writer.close()
    git_calls_before = sum(1 for p in fleet.popens for a, _ in p.calls if "ls-files" in a)
    assert git_calls_before >= 1  # V1 executed the proposals' `git ls-files` request
    # first resume: one abandoned record
    ctx2, env2 = fleet.open(s, resume=True)
    prior = load_prior(LedgerView.from_path(ctx2.writer.events_path), ctx2.writer, per_call_usd=0.5)
    assert len(prior.abandoned) == 1 and prior.requests_executed
    ctx2.writer.close()
    # second resume (e.g. after another interruption before any progress): still one
    ctx3, env3 = fleet.open(s, resume=True)
    prior3 = load_prior(
        LedgerView.from_path(ctx3.writer.events_path), ctx3.writer, per_call_usd=0.5
    )
    view = LedgerView.from_path(ctx3.writer.events_path)
    assert view.kinds().count("invocation.abandoned") == 1 and len(prior3.abandoned) == 1
    assert len([c for c in view.payloads("cost") if c["cost_known"] is False]) == 1
    # the dedupe set: the proposals' request is a duplicate now, not a new spawn
    ctx3.runner = fleet.spy = Spy(answers())
    draft = run_arm(s, ctx3, env3, prior=prior3)
    assert draft.status is ArmStatus.COMPLETE
    after = LedgerView.from_path(ctx3.writer.events_path)
    assert "verify.duplicate" in after.kinds()[len(view.events) :]
    ls_files_spawns = sum(1 for a, _ in fleet.popens[-1].calls if "ls-files" in a)
    assert ls_files_spawns == 0
    ctx3.writer.close()


def test_kill_stale_groups_waits_and_refuses_a_survivor() -> None:
    """Item 7: a live pgid is killed through the launcher's path (SIGTERM,
    wait, SIGKILL sweep) and the resume proceeds only once it is gone; a
    survivor refuses the resume."""
    signals: list[int] = []
    state = {"alive": True, "polls": 0}

    def alive(_pgid: int) -> bool:
        state["polls"] += 1
        return state["alive"]

    def killpg(_pgid: int, sig: int) -> None:
        signals.append(sig)
        if sig == signal.SIGTERM:
            state["alive"] = False  # dies on TERM, after a wait

    killed = kill_stale_groups([4242], killpg=killpg, alive=alive, grace_s=0.5)
    assert killed == [4242] and signals == [signal.SIGTERM, signal.SIGKILL]
    assert state["polls"] >= 2  # it waited (polled) before the sweep and before proceeding
    state["alive"] = True
    with pytest.raises(ResumeRefused, match="survived"):
        kill_stale_groups([4242], killpg=lambda *_: signals.append(0), alive=alive, grace_s=0.05)
