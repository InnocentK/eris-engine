"""Retry policy (pure) and the attempt driver. UNKNOWN IS TERMINAL.

Classification (:func:`classify`) maps a :class:`~eris.launch.WorkerResult`
to an :class:`~eris.schemas.ErrorClass`:

=================  ==========================================  =====  ======  ==============
class              trigger                                     retry  weight  backoff
=================  ==========================================  =====  ======  ==============
timeout            status TIMEOUT; agy "timeout waiting for    yes    2 of 3  30 s x attempt
                   response"
transient_io       "spawn failed", "cannot write schema",      yes    1 of 3  10 * 2^(n-1)
                   codex no JSONL / no turn.completed with
                   rc != 0 AND empty stdout
malformed_output   schema requested and ``structured`` None    yes    1, cap 2  0
                   (status OK)
budget_tripped     claude subtype error_max_budget_usd /       no     -       status
                   terminal_reason budget_exhausted; the              BUDGET_TRIPPED,
                   Eris pre-check                                     cost recorded
auth_terminal      claude "Not logged in"; codex "401          no
                   Unauthorized"; agy "authentication failed"
policy_terminal    agy "permission check failed"; grok 403     no
                   content refusal; status REFUSED/MISSING;
                   group survived SIGKILL
ok_with_warning    status OK with a warning                    no             Invocation.warning
unknown            anything else                               no
=================  ==========================================  =====  ======  ==============

A retry costs its class weight out of a budget of 3 per call; a timeout of
the judge (ADJUDICATE / SUMMARIZE) is TERMINAL (the E8 hang is
deterministic). The pattern table is DATA (:data:`PATTERNS`) and is tested
against the captured fixtures.

The driver (:func:`run_with_retry`) runs attempts of ONE call: every
attempt writes an ``Invocation`` (id unique per attempt), a ``CostRecord``
(``counted=True``; a missing cost becomes the pessimistic ``per_call_usd``
reservation with ``cost_known=False``) and a ``RetryAttempt`` (the
decision). Before EVERY spawn the money pre-check runs
(``spent_known + reserved + per_call_usd > ceiling`` per run and per
campaign -> a BUDGET_TRIPPED invocation, nothing spawned, F4). Between
attempts the STOP check runs; the attempt in flight always completes. A
``retry.scheduled`` event is written before the injected ``sleep``.
Writer failures propagate; they are never classified.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from eris.launch import (
    WorkerCall,
    WorkerResult,
    budget_tripped_result,
    invocation_id_for,
    run_worker,
)
from eris.schemas import (
    CostRecord,
    ErrorClass,
    Invocation,
    RetryAttempt,
    RetryDecision,
    Stage,
    Transport,
    WorkerStatus,
    now_ts,
    sha256_hex,
)
from eris.writer import BlobRef, RunWriter

RETRY_WEIGHT_MAX = 3
MALFORMED_OUTPUT_CAP = 2
TIMEOUT_BACKOFF_S = 30.0
TRANSIENT_BACKOFF_S = 10.0
TIMEOUT_RESERVATION_FACTOR = 2  # a timed-out call with no reported cost reserves 2x per_call
JUDGE_STAGES: frozenset[Stage] = frozenset({Stage.ADJUDICATE, Stage.SUMMARIZE})


# --------------------------------------------------------------------------- pattern table


@dataclass(frozen=True)
class ErrorPattern:
    """``cli`` None = any worker; ``regex`` is searched in the error text."""

    cli: str | None
    regex: str
    error_class: ErrorClass
    note: str = ""


PATTERNS: tuple[ErrorPattern, ...] = (
    # budget (claude T2 capture: subtype error_max_budget_usd / terminal_reason budget_exhausted)
    ErrorPattern("claude", r"error_max_budget_usd|budget_exhausted", ErrorClass.BUDGET_TRIPPED),
    # auth
    ErrorPattern("claude", r"Not logged in", ErrorClass.AUTH_TERMINAL, "T3/E2 capture"),
    ErrorPattern("codex", r"401 Unauthorized", ErrorClass.AUTH_TERMINAL, "E2 capture"),
    ErrorPattern("agy", r"authentication failed", ErrorClass.AUTH_TERMINAL, "A8 capture"),
    # policy
    ErrorPattern("agy", r"permission check failed", ErrorClass.POLICY_TERMINAL, "A5/A16"),
    ErrorPattern("grok", r"403 Forbidden|permission-denied", ErrorClass.POLICY_TERMINAL, "E17"),
    ErrorPattern(None, r"survived SIGKILL", ErrorClass.POLICY_TERMINAL, "group kill failed"),
    # timeout reported by the worker itself (agy --print-timeout, A7)
    ErrorPattern("agy", r"timeout waiting for response", ErrorClass.TIMEOUT, "A7 capture"),
    # transient I/O on our side
    ErrorPattern(None, r"^spawn failed", ErrorClass.TRANSIENT_IO),
    ErrorPattern(None, r"^cannot write schema", ErrorClass.TRANSIENT_IO),
)
_CODEX_EMPTY_RE = re.compile(r"no JSONL events|no turn\.completed")
_COMPILED: tuple[tuple[ErrorPattern, re.Pattern[str]], ...] = tuple(
    (p, re.compile(p.regex)) for p in PATTERNS
)

RETRYABLE: frozenset[ErrorClass] = frozenset(
    {ErrorClass.TIMEOUT, ErrorClass.TRANSIENT_IO, ErrorClass.MALFORMED_OUTPUT}
)
WEIGHT: dict[ErrorClass, int] = {ErrorClass.TIMEOUT: 2}


@dataclass(frozen=True)
class Classification:
    error_class: ErrorClass
    reason: str
    retryable: bool
    weight: int  # 1 or 2

    @property
    def terminal(self) -> bool:
        return not self.retryable


def _cls(error_class: ErrorClass, reason: str, *, retryable: bool | None = None) -> Classification:
    if retryable is None:
        retryable = error_class in RETRYABLE
    return Classification(error_class, reason, retryable, WEIGHT.get(error_class, 1))


def classify(
    result: WorkerResult, *, schema_requested: bool, stage: Stage = Stage.PROPOSE
) -> Classification:
    """Pure. Order: status first, then the pattern table, then UNKNOWN."""
    cli = result.argv[0].rsplit("/", 1)[-1] if result.argv else None
    error = result.error or ""
    if result.status is WorkerStatus.OK:
        if schema_requested and result.structured is None:
            return _cls(ErrorClass.MALFORMED_OUTPUT, "schema requested but no structured output")
        if result.warning:
            return _cls(ErrorClass.OK_WITH_WARNING, result.warning)
        return _cls(ErrorClass.OK, "ok")
    if result.status is WorkerStatus.BUDGET_TRIPPED:
        return _cls(ErrorClass.BUDGET_TRIPPED, error or "budget pre-check")
    if result.status is WorkerStatus.TIMEOUT:
        if stage in JUDGE_STAGES:
            return _cls(ErrorClass.TIMEOUT, "judge timeout is terminal (E8 hang)", retryable=False)
        return _cls(ErrorClass.TIMEOUT, error or "status TIMEOUT")
    if result.status in (WorkerStatus.REFUSED, WorkerStatus.MISSING):
        return _cls(ErrorClass.POLICY_TERMINAL, f"status {result.status.value}: {error}")
    # status FAILED: the table decides; first match wins
    worker_cli = _cli_of(result, cli)
    for pattern, rx in _COMPILED:
        if pattern.cli is not None and pattern.cli != worker_cli:
            continue
        if rx.search(error):
            if pattern.error_class is ErrorClass.TIMEOUT and stage in JUDGE_STAGES:
                return _cls(
                    ErrorClass.TIMEOUT, "judge timeout is terminal (E8 hang)", retryable=False
                )
            return _cls(pattern.error_class, f"{pattern.regex!r} matched: {error[:200]}")
    if worker_cli == "codex" and _CODEX_EMPTY_RE.search(error):
        if result.exit_code not in (0, None) and not result.stdout:
            return _cls(
                ErrorClass.TRANSIENT_IO, f"codex died before any event (rc {result.exit_code})"
            )
        return _cls(ErrorClass.UNKNOWN, f"codex produced no usable events: {error[:200]}")
    return _cls(ErrorClass.UNKNOWN, f"unclassified failure: {error[:200]}")


def _cli_of(result: WorkerResult, argv0_name: str | None) -> str | None:
    """The worker CLI name: from the error prefix (``claude: …``) when the
    parser set one, else from argv[0]'s basename."""
    error = result.error or ""
    for name in ("claude", "codex", "agy", "grok"):
        if error.startswith(name + ":"):
            return name
    return argv0_name


def backoff_s(error_class: ErrorClass, attempt: int) -> float:
    """Delay BEFORE attempt ``attempt + 1`` after a failure of class
    ``error_class`` on attempt ``attempt`` (1-based)."""
    if attempt < 1:
        raise ValueError("attempt must be >= 1")
    if error_class is ErrorClass.TIMEOUT:
        return TIMEOUT_BACKOFF_S * attempt
    if error_class is ErrorClass.TRANSIENT_IO:
        return TRANSIENT_BACKOFF_S * float(1 << (attempt - 1))
    return 0.0


# --------------------------------------------------------------------------- budgets


@dataclass(frozen=True)
class CostFacts:
    cost_usd: float
    estimated: bool
    cost_known: bool


@dataclass
class BudgetLedger:
    """Money. Known spend and pessimistic reservations are tracked apart and
    never blended. ``campaign_*_base`` carry what earlier runs of the
    campaign spent (from their ledgers); this run's figures are added."""

    per_call_usd: float
    run_ceiling_usd: float
    campaign_ceiling_usd: float | None = None
    spent_known_usd: float = 0.0
    reserved_usd: float = 0.0
    campaign_spent_known_base_usd: float = 0.0
    campaign_reserved_base_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.per_call_usd <= 0 or self.run_ceiling_usd <= 0:
            raise ValueError("per_call_usd and run_ceiling_usd must be > 0")
        if self.campaign_ceiling_usd is not None and self.campaign_ceiling_usd <= 0:
            raise ValueError("campaign_ceiling_usd must be > 0")

    @property
    def committed_usd(self) -> float:
        return self.spent_known_usd + self.reserved_usd

    @property
    def campaign_committed_usd(self) -> float:
        return (
            self.campaign_spent_known_base_usd
            + self.campaign_reserved_base_usd
            + self.committed_usd
        )

    def precheck(self) -> str | None:
        """None when a call may be spawned, else the reason it may not.
        ``spent_known + reserved + per_call_usd > ceiling`` trips; a ceiling
        exactly equal to what is committed trips too (per_call_usd > 0)."""
        if self.committed_usd + self.per_call_usd > self.run_ceiling_usd:
            return (
                f"run budget: known {self.spent_known_usd:.4f} + reserved {self.reserved_usd:.4f} "
                f"+ per_call {self.per_call_usd:.4f} > ceiling {self.run_ceiling_usd:.4f}"
            )
        if (
            self.campaign_ceiling_usd is not None
            and self.campaign_committed_usd + self.per_call_usd > self.campaign_ceiling_usd
        ):
            return (
                f"campaign budget: committed {self.campaign_committed_usd:.4f} + per_call "
                f"{self.per_call_usd:.4f} > ceiling {self.campaign_ceiling_usd:.4f}"
            )
        return None

    def record(self, cost_usd: float | None, *, timed_out: bool) -> CostFacts:
        """Account one finished attempt. A reported cost is KNOWN; a missing
        one is RESERVED at ``per_call_usd`` (x2 for a timeout)."""
        if cost_usd is not None:
            self.spent_known_usd += cost_usd
            return CostFacts(cost_usd, estimated=False, cost_known=True)
        reserve = self.per_call_usd * (TIMEOUT_RESERVATION_FACTOR if timed_out else 1)
        self.reserved_usd += reserve
        return CostFacts(reserve, estimated=True, cost_known=False)


# --------------------------------------------------------------------------- retry weight budget


@dataclass
class RetryState:
    weight_used: int = 0
    malformed_retries: int = 0

    def may_retry(self, cls: Classification) -> str | None:
        """None when another attempt is allowed, else why not."""
        if not cls.retryable:
            return f"{cls.error_class.value} is terminal"
        if self.weight_used + cls.weight > RETRY_WEIGHT_MAX:
            return (
                f"retry weight exhausted ({self.weight_used} used + {cls.weight} > "
                f"{RETRY_WEIGHT_MAX})"
            )
        if (
            cls.error_class is ErrorClass.MALFORMED_OUTPUT
            and self.malformed_retries >= MALFORMED_OUTPUT_CAP
        ):
            return f"malformed_output retries capped at {MALFORMED_OUTPUT_CAP}"
        return None

    def charge(self, cls: Classification) -> None:
        self.weight_used += cls.weight
        if cls.error_class is ErrorClass.MALFORMED_OUTPUT:
            self.malformed_retries += 1


# --------------------------------------------------------------------------- driver


@dataclass
class AttemptRecord:
    result: WorkerResult
    invocation: Invocation
    cost: CostRecord
    retry: RetryAttempt
    classification: Classification
    blobs: dict[str, BlobRef] = field(default_factory=dict)


@dataclass
class RetryOutcome:
    attempts: list[AttemptRecord]
    stopped: bool = False

    @property
    def final(self) -> AttemptRecord:
        return self.attempts[-1]

    @property
    def result(self) -> WorkerResult:
        return self.final.result

    @property
    def invocation(self) -> Invocation:
        return self.final.invocation

    @property
    def error_class(self) -> ErrorClass:
        return self.final.classification.error_class

    @property
    def ok(self) -> bool:
        return self.error_class in (ErrorClass.OK, ErrorClass.OK_WITH_WARNING)


WorkerRunner = Callable[[WorkerCall], WorkerResult]


def run_with_retry(
    call: WorkerCall,
    *,
    writer: RunWriter,
    budget: BudgetLedger,
    stop_check: Callable[[], bool],
    sleep: Callable[[float], None],
    runner: WorkerRunner = run_worker,
    clock: Callable[[], str] = now_ts,
    output_check: Callable[[WorkerResult], str | None] | None = None,
) -> RetryOutcome:
    """Drive attempts of ONE call until success, a terminal class, the retry
    weight budget, STOP, or the money pre-check ends it. Never raises on
    worker behaviour; writer errors propagate. ``output_check`` (the stage's
    wire-model parse) turns an OK result into ``malformed_output`` when it
    returns a rejection reason: retried with the IDENTICAL prompt, cap 2."""
    state = RetryState()
    attempts: list[AttemptRecord] = []
    schema_requested = call.schema is not None
    prompt_sha = sha256_hex(call.prompt.encode("utf-8"))
    attempt = 0
    while True:
        attempt += 1
        # money pre-check before EVERY spawn (F4): nothing is spawned on a trip
        reason = budget.precheck()
        if reason is not None:
            result = budget_tripped_result(call, reason)
            writer.append(
                "budget.tripped",
                {
                    "idempotency_key": result.idempotency_key,
                    "attempt": attempt,
                    "reason": reason,
                    "spent_known_usd": budget.spent_known_usd,
                    "spent_reserved_usd": budget.reserved_usd,
                },
            )
            cls = _cls(ErrorClass.BUDGET_TRIPPED, reason)
            rec = _record_attempt(
                writer,
                call,
                result,
                cls,
                attempt,
                clock(),
                clock(),
                prompt_sha,
                CostFacts(0.0, estimated=False, cost_known=True),
                state,
                RetryDecision.STOP,
                reason,
            )
            attempts.append(rec)
            return RetryOutcome(attempts)
        started = clock()
        result = runner(call)
        finished = clock()
        cls = classify(result, schema_requested=schema_requested, stage=call.stage)
        if output_check is not None and cls.error_class in (
            ErrorClass.OK,
            ErrorClass.OK_WITH_WARNING,
        ):
            rejection = output_check(result)
            if rejection is not None:
                cls = _cls(ErrorClass.MALFORMED_OUTPUT, rejection)
        facts = budget.record(result.cost_usd, timed_out=result.timed_out)
        why_not = state.may_retry(cls)
        stopped = False
        if why_not is None and stop_check():
            why_not = "STOP requested between attempts"
            stopped = True
        decision = RetryDecision.STOP if why_not else RetryDecision.RETRY
        if decision is RetryDecision.RETRY:
            state.charge(cls)
            reason = f"retry {cls.error_class.value}: {cls.reason}"
        else:
            reason = f"{why_not} ({cls.reason})"
        rec = _record_attempt(
            writer,
            call,
            result,
            cls,
            attempt,
            started,
            finished,
            prompt_sha,
            facts,
            state,
            decision,
            reason,
        )
        attempts.append(rec)
        if decision is RetryDecision.STOP:
            return RetryOutcome(attempts, stopped=stopped)
        delay = backoff_s(cls.error_class, attempt)
        writer.append(
            "retry.scheduled",
            {
                "idempotency_key": result.idempotency_key,
                "attempt": attempt + 1,
                "error_class": cls.error_class.value,
                "delay_s": delay,
            },
        )
        if delay > 0:
            sleep(delay)


def _record_attempt(
    writer: RunWriter,
    call: WorkerCall,
    result: WorkerResult,
    cls: Classification,
    attempt: int,
    started: str,
    finished: str,
    prompt_sha: str,
    facts: CostFacts,
    state: RetryState,
    decision: RetryDecision,
    reason: str,
) -> AttemptRecord:
    blobs: dict[str, BlobRef] = {}
    if result.stdout:
        blobs["stdout"] = writer.put_blob(result.stdout)
    if result.stderr:
        blobs["stderr"] = writer.put_blob(result.stderr)
    if result.output_file:
        blobs["output_file"] = writer.put_blob(result.output_file)
    status = result.status
    if cls.error_class is ErrorClass.BUDGET_TRIPPED:
        status = WorkerStatus.BUDGET_TRIPPED  # F4: the claude cap trip IS a budget trip
    invocation = Invocation(
        invocation_id=invocation_id_for(result.idempotency_key, attempt),
        task_id=call.task_id,
        worker_id=call.worker_id,
        provider=result.provider,
        transport=Transport.CLI,
        model_requested=result.model_requested,
        model_executed=result.model_executed,
        stage=call.stage,
        repeat_index=call.repeat_index,
        attempt=attempt,
        idempotency_key=result.idempotency_key,
        argv=list(result.argv),
        env_names=list(result.env_names),
        cwd=result.cwd,
        executable_sha256=result.executable_sha256,
        cli_version=None,
        started_at=started,
        finished_at=finished,
        duration_ms=result.duration_ms,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        stdout_truncated=result.stdout_truncated,
        stderr_truncated=result.stderr_truncated,
        status=status,
        error=result.error,
        usage=result.usage,
        cost_usd=result.cost_usd,
        stdout_sha256=blobs["stdout"].sha256 if "stdout" in blobs else None,
        stderr_sha256=blobs["stderr"].sha256 if "stderr" in blobs else None,
        output_file_sha256=blobs["output_file"].sha256 if "output_file" in blobs else None,
        output_file_truncated=result.output_file_truncated,
        output_file_size=result.output_file_size,
        cleanup_error=result.cleanup_error,
        conversation_id=result.conversation_id,
        worker_reported_duration_ms=result.worker_reported_duration_ms,
        prompt_sha256=prompt_sha,
        reused_from=None,
        pgid=result.pgid,
        warning=result.warning,
    )
    writer.append("invocation.finished", invocation)
    if result.cleanup_error:
        writer.append(
            "run.error", {"kind": "scratch_cleanup_failed", "error": result.cleanup_error}
        )
    cost = CostRecord(
        invocation_id=invocation.invocation_id,
        attempt=attempt,
        cost_usd=facts.cost_usd,
        usage=result.usage,
        counted=True,
        estimated=facts.estimated,
        cost_known=facts.cost_known,
    )
    writer.append("cost", cost)
    retry = RetryAttempt(
        invocation_id=invocation.invocation_id,
        attempt=attempt,
        status=status,
        error_class=cls.error_class,
        reason=reason,
        weight=cls.weight,
        budget_used_after=state.weight_used,
        backoff_s=backoff_s(cls.error_class, attempt) if decision is RetryDecision.RETRY else 0.0,
        decision=decision,
    )
    writer.append("retry.attempt", retry)
    return AttemptRecord(result, invocation, cost, retry, cls, blobs)


def stop_requested(*paths: Path) -> bool:
    """True when any STOP file exists (``runs/STOP`` global, ``runs/<campaign>/STOP``)."""
    return any(Path(p).exists() for p in paths)
