"""eris.retry: the pattern table against the captured fixtures, the pure
classification/backoff/weight rules, and the driver (every attempt =
Invocation + CostRecord + RetryAttempt; STOP and the money pre-check
between attempts; writer errors propagate)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from eris.launch import WorkerCall, WorkerResult, run_worker
from eris.redact import Redactor
from eris.retry import (
    MALFORMED_OUTPUT_CAP,
    PATTERNS,
    RETRY_WEIGHT_MAX,
    BudgetLedger,
    Classification,
    RetryState,
    backoff_s,
    classify,
    run_with_retry,
    stop_requested,
)
from eris.schemas import ErrorClass, RetryDecision, Stage, WorkerStatus
from eris.validate import validate_events
from eris.writer import RunWriter, WriterClosed
from tests.conftest import FakeProcessFactory
from tests.test_launch import _agy_policy, fixture, grok_ok, make_call, make_policy


def _result(
    tmp_path: Path,
    fake_process: Callable[..., FakeProcessFactory],
    cli: str,
    stdout: bytes,
    **kw: Any,
) -> WorkerResult:
    if cli == "agy":
        policy = _agy_policy(tmp_path)
    elif cli == "claude":
        policy = make_policy(tmp_path, "claude", provider="anthropic", model=None)
    elif cli == "codex":
        policy = make_policy(tmp_path, "codex", provider="openai", model="gpt-5.4")
    else:
        policy = make_policy(tmp_path)
    return run_worker(
        make_call(tmp_path, policy, **kw),
        popen=fake_process(stdout=stdout, returncode=1 if cli == "codex" else 0),
        killpg=lambda *_: None,
    )


def _absent_like(status: WorkerStatus, error: str | None, **kw: Any) -> WorkerResult:
    base: dict[str, Any] = dict(
        worker_id="w",
        provider="xai",
        model_requested="m",
        model_executed=None,
        status=status,
        error=error,
        text=None,
        structured=None,
        usage=None,
        cost_usd=None,
        duration_ms=0,
        exit_code=None,
        argv=["/x/grok"],
        env_names=[],
        cwd="/s",
        idempotency_key="0" * 64,
        executable_sha256=None,
        stdout=b"",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=status is WorkerStatus.TIMEOUT,
        parse_mode="none",
    )
    base.update(kw)
    return WorkerResult(**base)


# --------------------------------------------------------------------------- pattern table


@pytest.mark.parametrize(
    ("cli", "name", "expected"),
    [
        ("claude", "budget_tripped.json", ErrorClass.BUDGET_TRIPPED),  # T2
        ("claude", "bare_not_logged_in.json", ErrorClass.AUTH_TERMINAL),  # T3
        # v1 capture: the vendor session ceiling (HTTP 429, "resets 5:30pm").
        # Fell through to UNKNOWN in the live campaign; terminal by design -
        # an in-chain retry cannot outlive a ceiling that resets on the
        # vendor's clock, and it is NOT the harness's own BUDGET_TRIPPED.
        ("claude", "session_limit_429.json", ErrorClass.POLICY_TERMINAL),  # v1
        ("codex", "auth_401.jsonl", ErrorClass.AUTH_TERMINAL),  # E2
        ("agy", "print_timeout.json", ErrorClass.TIMEOUT),  # A7
        ("agy", "read_denied.json", ErrorClass.POLICY_TERMINAL),  # A5
        ("agy", "read_denied_outside_with_add_dir.json", ErrorClass.POLICY_TERMINAL),  # A16
        ("agy", "auth_failed.json", ErrorClass.AUTH_TERMINAL),  # A8
        ("grok", "api_error_403.json", ErrorClass.POLICY_TERMINAL),  # E17
        ("grok", "plan.json", ErrorClass.OK_WITH_WARNING),  # T7 cancelled
        ("grok", "schema.json", ErrorClass.OK),
        ("agy", "plain.json", ErrorClass.OK),
    ],
)
def test_pattern_table_against_captured_fixtures(
    tmp_path: Path,
    fake_process: Callable[..., FakeProcessFactory],
    cli: str,
    name: str,
    expected: ErrorClass,
) -> None:
    version = {"claude": "2.1.239", "codex": "0.147.0", "agy": "1.1.18", "grok": "1.0.5"}[cli]
    # captures added after the flag experiments live under the CLI version
    # that actually emitted them
    version = {"session_limit_429.json": "2.1.252"}.get(name, version)
    res = _result(tmp_path, fake_process, cli, fixture(cli, version, name))
    cls = classify(res, schema_requested=False)
    assert cls.error_class is expected, (cls, res.error)
    assert cls.retryable is (expected in (ErrorClass.TIMEOUT,))
    assert cls.weight == (2 if expected is ErrorClass.TIMEOUT else 1)


def test_pattern_table_is_data_and_every_entry_names_a_class() -> None:
    assert all(isinstance(p.regex, str) and p.regex for p in PATTERNS)
    assert {p.error_class for p in PATTERNS} == {
        ErrorClass.BUDGET_TRIPPED,
        ErrorClass.AUTH_TERMINAL,
        ErrorClass.POLICY_TERMINAL,
        ErrorClass.TIMEOUT,
        ErrorClass.TRANSIENT_IO,
    }
    # a pattern scoped to one CLI never fires for another worker's error
    res = _absent_like(WorkerStatus.FAILED, "codex: 401 Unauthorized", argv=["/x/grok"])
    assert classify(res, schema_requested=False).error_class is ErrorClass.AUTH_TERMINAL
    res = _absent_like(WorkerStatus.FAILED, "something 401 Unauthorized", argv=["/x/grok"])
    assert classify(res, schema_requested=False).error_class is ErrorClass.UNKNOWN


# --------------------------------------------------------------------------- status rules


def test_classify_status_rules() -> None:
    c = classify(_absent_like(WorkerStatus.TIMEOUT, "timed out"), schema_requested=False)
    assert c.error_class is ErrorClass.TIMEOUT and c.retryable and c.weight == 2
    judge = classify(
        _absent_like(WorkerStatus.TIMEOUT, "timed out"),
        schema_requested=False,
        stage=Stage.ADJUDICATE,
    )
    assert judge.error_class is ErrorClass.TIMEOUT and judge.terminal and "E8" in judge.reason
    summ = classify(
        _absent_like(WorkerStatus.TIMEOUT, "t"), schema_requested=False, stage=Stage.SUMMARIZE
    )
    assert summ.terminal
    # the agy worker-reported timeout is a timeout too, and terminal for the judge
    agy = _absent_like(WorkerStatus.FAILED, "agy: timeout waiting for response", argv=["/x/agy"])
    assert classify(agy, schema_requested=False).retryable
    assert classify(agy, schema_requested=False, stage=Stage.ADJUDICATE).terminal
    for status in (WorkerStatus.REFUSED, WorkerStatus.MISSING):
        c = classify(_absent_like(status, "x"), schema_requested=False)
        assert c.error_class is ErrorClass.POLICY_TERMINAL and c.terminal
    c = classify(_absent_like(WorkerStatus.BUDGET_TRIPPED, "budget"), schema_requested=False)
    assert c.error_class is ErrorClass.BUDGET_TRIPPED and c.terminal
    for msg in ("spawn failed: denied", "cannot write schema: disk"):
        c = classify(_absent_like(WorkerStatus.FAILED, msg), schema_requested=False)
        assert c.error_class is ErrorClass.TRANSIENT_IO and c.retryable and c.weight == 1
    c = classify(_absent_like(WorkerStatus.FAILED, "survived SIGKILL"), schema_requested=False)
    assert c.error_class is ErrorClass.POLICY_TERMINAL
    c = classify(_absent_like(WorkerStatus.FAILED, "exit code 3"), schema_requested=False)
    assert c.error_class is ErrorClass.UNKNOWN and c.terminal


def test_classify_codex_empty_stdout_is_transient_only_with_nonzero_exit() -> None:
    dead = _absent_like(
        WorkerStatus.FAILED,
        "codex: no JSONL events on stdout",
        argv=["/x/codex"],
        exit_code=137,
        stdout=b"",
    )
    assert classify(dead, schema_requested=False).error_class is ErrorClass.TRANSIENT_IO
    garbage = _absent_like(
        WorkerStatus.FAILED,
        "codex: no JSONL events on stdout",
        argv=["/x/codex"],
        exit_code=1,
        stdout=b"garbage",
    )
    assert classify(garbage, schema_requested=False).error_class is ErrorClass.UNKNOWN
    clean_exit = _absent_like(
        WorkerStatus.FAILED, "codex: no turn.completed event", argv=["/x/codex"], exit_code=0
    )
    assert classify(clean_exit, schema_requested=False).error_class is ErrorClass.UNKNOWN


def test_classify_ok_with_schema_but_no_structured_is_malformed_output() -> None:
    ok = _absent_like(WorkerStatus.OK, None, text="prose", structured=None)
    c = classify(ok, schema_requested=True)
    assert c.error_class is ErrorClass.MALFORMED_OUTPUT and c.retryable and c.weight == 1
    assert classify(ok, schema_requested=False).error_class is ErrorClass.OK
    good = _absent_like(WorkerStatus.OK, None, structured={"a": 1})
    assert classify(good, schema_requested=True).error_class is ErrorClass.OK
    warned = _absent_like(WorkerStatus.OK, None, structured={"a": 1}, warning="w")
    assert classify(warned, schema_requested=True).error_class is ErrorClass.OK_WITH_WARNING
    # malformed wins over the warning: the output is unusable either way
    both = _absent_like(WorkerStatus.OK, None, structured=None, warning="w")
    assert classify(both, schema_requested=True).error_class is ErrorClass.MALFORMED_OUTPUT


def test_backoff_schedule() -> None:
    assert [backoff_s(ErrorClass.TIMEOUT, n) for n in (1, 2, 3)] == [30.0, 60.0, 90.0]
    assert [backoff_s(ErrorClass.TRANSIENT_IO, n) for n in (1, 2, 3)] == [10.0, 20.0, 40.0]
    assert backoff_s(ErrorClass.MALFORMED_OUTPUT, 1) == 0.0
    assert backoff_s(ErrorClass.UNKNOWN, 1) == 0.0
    with pytest.raises(ValueError):
        backoff_s(ErrorClass.TIMEOUT, 0)


def test_retry_weight_budget_and_malformed_cap() -> None:
    timeout = Classification(ErrorClass.TIMEOUT, "t", True, 2)
    transient = Classification(ErrorClass.TRANSIENT_IO, "t", True, 1)
    malformed = Classification(ErrorClass.MALFORMED_OUTPUT, "m", True, 1)
    terminal = Classification(ErrorClass.AUTH_TERMINAL, "a", False, 1)
    s = RetryState()
    assert s.may_retry(timeout) is None
    s.charge(timeout)
    assert s.weight_used == 2 and "exhausted" in str(s.may_retry(timeout))  # 2 + 2 > 3
    assert s.may_retry(transient) is None  # 2 + 1 == 3 is allowed
    s.charge(transient)
    assert s.may_retry(transient) is not None and s.weight_used == RETRY_WEIGHT_MAX
    s = RetryState()
    for _ in range(3):
        assert s.may_retry(transient) is None
        s.charge(transient)
    assert "exhausted" in str(s.may_retry(transient))
    s = RetryState()
    for _ in range(MALFORMED_OUTPUT_CAP):
        assert s.may_retry(malformed) is None
        s.charge(malformed)
    assert "capped" in str(s.may_retry(malformed))
    assert "terminal" in str(RetryState().may_retry(terminal))


# --------------------------------------------------------------------------- budget ledger


def test_budget_ledger_precheck_and_reservations() -> None:
    b = BudgetLedger(per_call_usd=1.0, run_ceiling_usd=3.0)
    assert b.precheck() is None
    facts = b.record(0.5, timed_out=False)
    assert facts.cost_known and not facts.estimated and b.spent_known_usd == 0.5
    facts = b.record(None, timed_out=False)
    assert not facts.cost_known and facts.estimated and facts.cost_usd == 1.0
    assert b.reserved_usd == 1.0 and b.precheck() is None  # 0.5 + 1 + 1 = 2.5 <= 3
    facts = b.record(None, timed_out=True)
    assert facts.cost_usd == 2.0 and b.reserved_usd == 3.0  # timeouts reserve 2x
    assert b.precheck() is not None and "run budget" in str(b.precheck())
    # ceiling exactly equal to what is committed still trips (per_call > 0)
    exact = BudgetLedger(per_call_usd=0.25, run_ceiling_usd=2.0)
    exact.record(2.0, timed_out=False)
    assert exact.spent_known_usd == exact.run_ceiling_usd and exact.precheck() is not None
    under = BudgetLedger(per_call_usd=0.25, run_ceiling_usd=2.0)
    under.record(1.75, timed_out=False)
    assert under.precheck() is None  # 1.75 + 0.25 == 2.0 is NOT > ceiling
    with pytest.raises(ValueError):
        BudgetLedger(per_call_usd=0, run_ceiling_usd=1)
    with pytest.raises(ValueError):
        BudgetLedger(per_call_usd=1, run_ceiling_usd=1, campaign_ceiling_usd=0)


def test_budget_ledger_campaign_ceiling() -> None:
    b = BudgetLedger(
        per_call_usd=1.0,
        run_ceiling_usd=100.0,
        campaign_ceiling_usd=10.0,
        campaign_spent_known_base_usd=7.0,
        campaign_reserved_base_usd=2.0,
    )
    assert b.precheck() is None  # 9 + 1 == 10 is allowed
    b.record(0.5, timed_out=False)
    assert b.campaign_committed_usd == 9.5 and "campaign budget" in str(b.precheck())


# --------------------------------------------------------------------------- driver


def _writer(tmp_path: Path, run_id: str = "r1") -> RunWriter:
    return RunWriter(tmp_path / "runs" / run_id, Redactor(), run_id=run_id).open()


def _events(w: RunWriter) -> list[dict[str, Any]]:
    lines = w.events_path.read_bytes().splitlines(keepends=True)
    assert validate_events(lines) == []
    return [json.loads(line) for line in lines]


def _runner(tmp_path: Path, outcomes: list[bytes | None]) -> tuple[WorkerRunnerSpy, WorkerCall]:
    """A runner that answers successive calls from ``outcomes``: bytes =
    grok stdout for the fake process; None = a hanging process (TIMEOUT)."""
    policy = make_policy(tmp_path, timeout_s=1)
    call = make_call(tmp_path, policy)
    return WorkerRunnerSpy(outcomes), call


class WorkerRunnerSpy:
    def __init__(self, outcomes: list[bytes | None]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[WorkerCall] = []

    def __call__(self, call: WorkerCall) -> WorkerResult:
        self.calls.append(call)
        outcome = self.outcomes.pop(0)
        if outcome is None:
            return _absent_like(
                WorkerStatus.TIMEOUT,
                "timed out after 1s (killed with signal 15)",
                idempotency_key="c" * 64,
                argv=["/x/grok", "-p", "prompt"],
                stdout=b"",
                stderr=b"partial stderr",
                pgid=4242,
            )
        from eris.launch import parse_grok

        env = parse_grok(outcome)
        return _absent_like(
            WorkerStatus.OK if not env.is_error else WorkerStatus.FAILED,
            env.error if env.is_error else None,
            idempotency_key="c" * 64,
            argv=["/x/grok", "-p", "prompt"],
            text=env.text,
            structured=env.structured,
            cost_usd=env.cost_usd,
            usage=env.usage,
            model_executed=env.model_executed,
            stdout=outcome,
            exit_code=0,
            warning=None if env.is_error else env.error,
            pgid=4242,
        )


def test_driver_retries_a_timeout_once_then_succeeds(tmp_path: Path) -> None:
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [None, grok_ok('{"ok": true}')])
    slept: list[float] = []
    stops: list[int] = []

    def stop_check() -> bool:
        stops.append(1)
        return False

    budget = BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0)
    out = run_with_retry(
        call, writer=w, budget=budget, stop_check=stop_check, sleep=slept.append, runner=runner
    )
    assert out.ok and not out.stopped and len(out.attempts) == 2 and len(runner.calls) == 2
    assert runner.calls[0] == runner.calls[1] == call  # identical call, fresh process
    assert slept == [30.0] and stops == [1, 1]  # between attempts AND after the backoff
    a1, a2 = out.attempts
    assert a1.invocation.invocation_id.endswith("-a1") and a2.invocation.invocation_id.endswith(
        "-a2"
    )
    assert a1.invocation.idempotency_key == a2.invocation.idempotency_key
    assert a1.invocation.status is WorkerStatus.TIMEOUT and a1.invocation.pgid == 4242
    assert a1.retry.decision is RetryDecision.RETRY and a1.retry.weight == 2
    assert a1.retry.backoff_s == 30.0 and a1.retry.budget_used_after == 2
    # a timed-out call with no cost is reserved at 2x per_call, cost_known False
    assert a1.cost.cost_usd == 1.0 and a1.cost.estimated and not a1.cost.cost_known
    assert a1.cost.counted is True
    assert a2.cost.cost_usd == 0.01 and a2.cost.cost_known and not a2.cost.estimated
    assert a2.retry.decision is RetryDecision.STOP and a2.retry.error_class is ErrorClass.OK
    assert budget.spent_known_usd == 0.01 and budget.reserved_usd == 1.0
    kinds = [e["kind"] for e in _events(w)]
    assert kinds == [
        "invocation.finished",
        "cost",
        "retry.attempt",
        "retry.scheduled",
        "invocation.finished",
        "cost",
        "retry.attempt",
    ]
    scheduled = _events(w)[3]["payload"]
    assert scheduled["attempt"] == 2 and scheduled["error_class"] == "timeout"
    assert scheduled["delay_s"] == 30.0
    assert _events(w)[0]["payload"]["prompt_sha256"] == a2.invocation.prompt_sha256
    assert a1.blobs["stderr"].sha256 == a1.invocation.stderr_sha256
    w.close()


def test_driver_stop_between_attempts_lets_the_attempt_finish_and_does_not_retry(
    tmp_path: Path,
) -> None:
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [None, grok_ok()])
    slept: list[float] = []
    out = run_with_retry(
        call,
        writer=w,
        budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
        stop_check=lambda: True,
        sleep=slept.append,
        runner=runner,
    )
    assert out.stopped and len(out.attempts) == 1 and len(runner.calls) == 1 and slept == []
    assert out.result.status is WorkerStatus.TIMEOUT  # the in-flight attempt completed
    assert out.final.retry.decision is RetryDecision.STOP and "STOP" in out.final.retry.reason
    assert out.final.retry.backoff_s == 0.0 and out.final.retry.budget_used_after == 0
    assert [e["kind"] for e in _events(w)] == ["invocation.finished", "cost", "retry.attempt"]
    w.close()


def test_driver_budget_precheck_trips_before_the_first_spawn(tmp_path: Path) -> None:
    """F4: a ceiling exactly equal to the known spend -> BUDGET_TRIPPED
    invocation, budget.tripped event, the runner is never called."""
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [grok_ok()])
    budget = BudgetLedger(per_call_usd=0.5, run_ceiling_usd=2.0)
    budget.record(2.0, timed_out=False)
    out = run_with_retry(
        call,
        writer=w,
        budget=budget,
        stop_check=lambda: False,
        sleep=lambda _s: None,
        runner=runner,
    )
    assert runner.calls == [] and len(out.attempts) == 1 and not out.ok
    inv = out.invocation
    assert inv.status is WorkerStatus.BUDGET_TRIPPED and inv.argv == [] and inv.pgid is None
    assert inv.error is not None and "run budget" in inv.error
    assert out.error_class is ErrorClass.BUDGET_TRIPPED
    assert out.final.cost.cost_usd == 0.0 and out.final.cost.cost_known
    events = _events(w)
    assert [e["kind"] for e in events] == [
        "budget.tripped",
        "invocation.finished",
        "cost",
        "retry.attempt",
    ]
    assert events[0]["payload"]["spent_known_usd"] == 2.0
    assert events[3]["payload"]["decision"] == "stop"
    w.close()


def test_driver_budget_precheck_trips_between_attempts(tmp_path: Path) -> None:
    """A timeout reserves 2x per_call; the pre-check before the retry trips."""
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [None, grok_ok()])
    slept: list[float] = []
    out = run_with_retry(
        call,
        writer=w,
        budget=BudgetLedger(per_call_usd=1.0, run_ceiling_usd=2.5),
        stop_check=lambda: False,
        sleep=slept.append,
        runner=runner,
    )
    assert len(runner.calls) == 1 and slept == [30.0]  # the retry was scheduled and slept
    assert len(out.attempts) == 2
    assert out.attempts[0].invocation.status is WorkerStatus.TIMEOUT
    assert out.attempts[1].invocation.status is WorkerStatus.BUDGET_TRIPPED
    assert out.attempts[1].invocation.attempt == 2
    assert out.attempts[1].invocation.invocation_id.endswith("-a2")
    kinds = [e["kind"] for e in _events(w)]
    assert kinds[3] == "retry.scheduled" and kinds[4] == "budget.tripped"
    w.close()


def test_driver_claude_budget_envelope_becomes_budget_tripped_status(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """F4 from the worker's side: the T2 envelope (FAILED at the launcher)
    is recorded as status BUDGET_TRIPPED with its real cost (0.129044)."""
    w = _writer(tmp_path)
    policy = make_policy(tmp_path, "claude", provider="anthropic", model=None)
    call = make_call(tmp_path, policy)
    factory = fake_process(stdout=fixture("claude", "2.1.239", "budget_tripped.json"))

    def runner(c: WorkerCall) -> WorkerResult:
        return run_worker(c, popen=factory, killpg=lambda *_: None)

    budget = BudgetLedger(per_call_usd=0.5, run_ceiling_usd=5.0)
    out = run_with_retry(
        call,
        writer=w,
        budget=budget,
        stop_check=lambda: False,
        sleep=lambda _s: None,
        runner=runner,
    )
    assert len(out.attempts) == 1 and len(factory.instances) == 1
    inv = out.invocation
    assert inv.status is WorkerStatus.BUDGET_TRIPPED and inv.cost_usd == 0.129044
    assert inv.error is not None and "error_max_budget_usd" in inv.error
    assert out.final.cost.cost_usd == 0.129044 and out.final.cost.cost_known
    assert budget.spent_known_usd == 0.129044
    assert out.final.retry.error_class is ErrorClass.BUDGET_TRIPPED
    assert out.final.retry.decision is RetryDecision.STOP
    w.close()


def test_driver_malformed_output_retries_identical_prompt_up_to_cap(tmp_path: Path) -> None:
    w = _writer(tmp_path)
    prose = grok_ok("not json at all")
    policy = make_policy(tmp_path)
    call = make_call(tmp_path, policy, schema={"type": "object"})
    runner = WorkerRunnerSpy([prose, prose, prose, prose])
    slept: list[float] = []
    out = run_with_retry(
        call,
        writer=w,
        budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
        stop_check=lambda: False,
        sleep=slept.append,
        runner=runner,
    )
    assert len(out.attempts) == 1 + MALFORMED_OUTPUT_CAP and slept == []  # backoff 0: no sleep
    assert all(c.prompt == call.prompt for c in runner.calls)  # no "fix your JSON" turn
    assert out.error_class is ErrorClass.MALFORMED_OUTPUT and not out.ok
    assert out.final.retry.decision is RetryDecision.STOP and "capped" in out.final.retry.reason
    assert [a.retry.budget_used_after for a in out.attempts] == [1, 2, 2]
    kinds = [e["kind"] for e in _events(w)]
    assert kinds.count("retry.scheduled") == MALFORMED_OUTPUT_CAP
    assert all(e["payload"]["delay_s"] == 0.0 for e in _events(w) if e["kind"] == "retry.scheduled")
    w.close()


def test_driver_terminal_failure_is_not_retried(tmp_path: Path) -> None:
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [fixture("grok", "1.0.5", "api_error_403.json"), grok_ok()])
    out = run_with_retry(
        call,
        writer=w,
        budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
        stop_check=lambda: False,
        sleep=lambda _s: None,
        runner=runner,
    )
    assert len(runner.calls) == 1 and out.error_class is ErrorClass.POLICY_TERMINAL
    assert out.final.retry.decision is RetryDecision.STOP and "terminal" in out.final.retry.reason
    # the failed attempt with no reported cost is reserved at 1x per_call
    assert out.final.cost.cost_usd == 0.5 and not out.final.cost.cost_known
    w.close()


def test_driver_judge_timeout_is_terminal(tmp_path: Path) -> None:
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [None, grok_ok()])
    judge_call = WorkerCall(**{**call.__dict__, "stage": Stage.ADJUDICATE})
    out = run_with_retry(
        judge_call,
        writer=w,
        budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
        stop_check=lambda: False,
        sleep=lambda _s: None,
        runner=runner,
    )
    assert len(runner.calls) == 1 and out.error_class is ErrorClass.TIMEOUT
    assert out.final.retry.decision is RetryDecision.STOP and "E8" in out.final.retry.reason
    w.close()


def test_driver_writer_errors_propagate_and_are_never_classified(tmp_path: Path) -> None:
    w = _writer(tmp_path)
    w.close()
    runner, call = _runner(tmp_path, [grok_ok()])
    with pytest.raises(WriterClosed):
        run_with_retry(
            call,
            writer=w,
            budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
            stop_check=lambda: False,
            sleep=lambda _s: None,
            runner=runner,
        )


def test_stop_requested_checks_every_path(tmp_path: Path) -> None:
    assert not stop_requested(tmp_path / "STOP", tmp_path / "c" / "STOP")
    (tmp_path / "STOP").write_text("")
    assert stop_requested(tmp_path / "c" / "STOP", tmp_path / "STOP")


def test_stop_during_the_backoff_sleep_cancels_the_retry_spawn(tmp_path: Path) -> None:
    """Item 6: STOP appears while the driver sleeps; the retry never spawns
    (retry.cancelled), the outcome is stopped."""
    w = _writer(tmp_path)
    runner, call = _runner(tmp_path, [None, grok_ok()])
    flag = {"stop": False}

    def sleep(_s: float) -> None:
        flag["stop"] = True  # the file appears during the backoff

    out = run_with_retry(
        call,
        writer=w,
        budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
        stop_check=lambda: flag["stop"],
        sleep=sleep,
        runner=runner,
    )
    assert len(runner.calls) == 1 and out.stopped and len(out.attempts) == 1
    assert out.attempts[0].retry.decision is RetryDecision.RETRY  # it WAS scheduled
    kinds = [e["kind"] for e in _events(w)]
    assert kinds[-2:] == ["retry.scheduled", "retry.cancelled"]
    assert "STOP" in _events(w)[-1]["payload"]["reason"]
    w.close()


def test_worst_case_call_reservation_equals_the_brute_forced_maximum(tmp_path: Path) -> None:
    """cond 12 + final item 5: the pessimistic per-call reservation used for a
    corrupt cell ledger is the maximum over EVERY class sequence the driver can
    actually produce - brute-forced here, not a hand-picked chain. A pure
    timeout chain (2 x 2) and a pure transient chain (4 x 1) both reserve 4x,
    but the attainable MIXED chain timeout -> transient -> timeout reserves 5x,
    and the helper must not be below it."""
    import itertools

    from eris.retry import worst_case_call_reservation

    per_call = 0.5
    classes = {
        "malformed": lambda: _absent_like(WorkerStatus.OK, None, idempotency_key="c" * 64),
        "timeout": lambda: _absent_like(
            WorkerStatus.TIMEOUT, "timed out after 1s", idempotency_key="c" * 64
        ),
        "transient": lambda: _absent_like(
            WorkerStatus.FAILED, "spawn failed: denied", idempotency_key="c" * 64
        ),
    }

    class ScriptedRunner:
        def __init__(self, names: tuple[str, ...]) -> None:
            self.names = names
            self.i = 0

        def __call__(self, call: WorkerCall) -> WorkerResult:
            name = self.names[min(self.i, len(self.names) - 1)]
            self.i += 1
            return classes[name]()

    _spy, call = _runner(tmp_path, [])
    observed: dict[tuple[str, ...], float] = {}
    # 5 = more attempts than the weight budget can ever allow, so no sequence is
    # cut short by the script running out
    for n, names in enumerate(itertools.product(sorted(classes), repeat=5)):
        w = RunWriter(
            tmp_path / "runs" / f"brute-{n}", Redactor(), run_id="brute", fsync=lambda _fd: None
        ).open()
        budget = BudgetLedger(per_call_usd=per_call, run_ceiling_usd=1_000_000.0)
        out = run_with_retry(
            call,
            writer=w,
            budget=budget,
            stop_check=lambda: False,
            sleep=lambda _s: None,
            runner=ScriptedRunner(names),
            output_check=lambda r: "malformed" if r.status is WorkerStatus.OK else None,
        )
        w.close()
        assert budget.spent_known_usd == 0.0  # no cost is ever reported
        observed[names[: len(out.attempts)]] = budget.reserved_usd

    worst = max(observed.values())
    assert worst_case_call_reservation(per_call) == pytest.approx(worst)
    assert worst == pytest.approx(5 * per_call)  # the mixed chain, not 4x
    assert observed[("timeout", "transient", "timeout")] == pytest.approx(worst)
    assert observed[("timeout", "timeout")] == pytest.approx(4 * per_call)  # pure timeout chain
    assert observed[("transient",) * 4] == pytest.approx(4 * per_call)  # pure transient chain
    # and it IS an upper bound: no producible sequence reserves more
    assert all(v <= worst_case_call_reservation(per_call) + 1e-9 for v in observed.values())


def test_the_driver_continues_attempt_numbering_from_the_ledger(tmp_path: Path) -> None:
    """Final item 3: on a resume the driver starts at the ledger's next attempt
    number, so invocation ids stay unique and attempts stay monotonic. The
    backoff schedule still counts tries within THIS driver run."""
    w = _writer(tmp_path, "resumed")
    runner, call = _runner(tmp_path, [None, grok_ok('{"ok": true}')])
    slept: list[float] = []
    out = run_with_retry(
        call,
        writer=w,
        budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
        stop_check=lambda: False,
        sleep=slept.append,
        runner=runner,
        first_attempt=3,
    )
    w.close()
    assert [a.invocation.attempt for a in out.attempts] == [3, 4]
    assert [a.retry.attempt for a in out.attempts] == [3, 4]
    assert out.attempts[0].invocation.invocation_id.endswith("-a3")
    assert out.attempts[1].invocation.invocation_id.endswith("-a4")
    assert slept == [30.0] and out.attempts[0].retry.backoff_s == 30.0  # tries, not 3 x 30
    scheduled = [e for e in _events(w) if e["kind"] == "retry.scheduled"]
    assert [e["payload"]["attempt"] for e in scheduled] == [4]
    bad = _writer(tmp_path, "bad")
    with pytest.raises(ValueError, match="first_attempt"):
        run_with_retry(
            call,
            writer=bad,
            budget=BudgetLedger(per_call_usd=0.5, run_ceiling_usd=10.0),
            stop_check=lambda: False,
            sleep=slept.append,
            runner=runner,
            first_attempt=0,
        )
    bad.close()
