"""Every Eris record, its ``origin``, and the canonical byte form.

Rules (see docs/PROTOCOL.md and docs/INVARIANTS.md):

* Every record is a Pydantic v2 model with ``extra="forbid"`` and carries
  ``schema_version`` and ``origin``.
* ``origin`` is never blurred: evidence produced by running a tool is
  ``mechanically_observed``; anything a model said is ``model_asserted``;
  approvals are ``human_entered``.
* :func:`canonical_bytes` is THE serialization: sorted keys, compact
  separators, UTF-8, no NaN/Infinity, RFC 3339 ``Z`` timestamps as strings.
  The golden fixtures under ``tests/fixtures/records/<SCHEMA_VERSION>/`` pin
  these bytes; changing them is a schema change.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "0.1.2"

TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"

Timestamp = Annotated[str, Field(pattern=TS_PATTERN)]
Sha256 = Annotated[str, Field(pattern=SHA256_PATTERN)]
RecordId = Annotated[str, Field(pattern=ID_PATTERN)]
_TS_RE = re.compile(TS_PATTERN)


def now_ts() -> Timestamp:
    """Current UTC time as RFC 3339 with microseconds and a literal ``Z``."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value: str) -> datetime:
    """Parse a :data:`Timestamp`; raises ``ValueError`` for anything else."""
    if not _TS_RE.fullmatch(value):
        raise ValueError(f"not an RFC 3339 Z timestamp: {value!r}")
    return datetime.strptime(
        value, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=UTC)


# --------------------------------------------------------------------------- enums


class Origin(StrEnum):
    MODEL_ASSERTED = "model_asserted"
    MECHANICALLY_OBSERVED = "mechanically_observed"
    HUMAN_ENTERED = "human_entered"


class Verdict(StrEnum):
    ACCEPT = "ACCEPT"
    REVISE = "REVISE"
    ESCALATE = "ESCALATE"
    ABSTAIN = "ABSTAIN"
    REJECT = "REJECT"


class ClaimStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    CONTESTED = "CONTESTED"
    UNSUPPORTED = "UNSUPPORTED"


class ChallengeStatus(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"


class EvidenceKind(StrEnum):
    TEST_OUTPUT = "test_output"
    TOOL_OUTPUT = "tool_output"
    REPO_FACT = "repo_fact"
    DOCUMENT_QUOTE = "document_quote"
    DRY_RUN = "dry_run"
    HUMAN_ATTESTATION = "human_attestation"
    MODEL_ASSERTION = "model_assertion"


class Phase(StrEnum):
    EVIDENCE_PACK = "evidence_pack"
    PROPOSAL = "proposal"
    CRITIQUE = "critique"
    VERIFICATION = "verification"
    ADJUDICATION = "adjudication"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Lens(StrEnum):
    SECURITY = "security"
    RELIABILITY = "reliability"
    DATA_INTEGRITY = "data_integrity"
    OPS = "ops"
    TESTABILITY = "testability"
    FRAMING = "framing"


class Transport(StrEnum):
    CLI = "cli"
    API = "api"


class Stage(StrEnum):
    PROPOSE = "propose"
    CRITIQUE = "critique"
    VERIFY = "verify"  # F6: mechanical verification of evidence requests
    ADJUDICATE = "adjudicate"
    SUMMARIZE = "summarize"  # F6: the consensus arm's summarizer (judge worker, no tools)


class WorkerStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    MISSING = "missing"
    REFUSED = "refused"
    BUDGET_TRIPPED = "budget_tripped"


class TaskCategory(StrEnum):
    REVERT = "revert"
    PLANTED = "planted"
    PLAN = "plan"
    CONTROL = "control"
    INSUFFICIENT = "insufficient"


class ApprovalAction(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"


class VerificationVerdict(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


# --------------------------------------------------------------------------- base


class Record(BaseModel):
    """Base for every persisted record."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)

    schema_version: str = SCHEMA_VERSION
    origin: Origin

    @field_validator("schema_version")
    @classmethod
    def _schema_version_is_current(cls, value: str) -> str:
        """No migrations in 0.x: a record from any other schema version is
        refused at parse time rather than silently reinterpreted. Old
        goldens stay committed (immutable, see MANIFEST.json) as history."""
        if value != SCHEMA_VERSION:
            raise ValueError(
                f"schema_version {value!r} is not the current {SCHEMA_VERSION!r}; "
                "no migration exists"
            )
        return value


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)


class Usage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None
    reasoning_tokens: int | None = None


# --------------------------------------------------------------------------- records


class Task(Record):
    origin: Origin = Origin.HUMAN_ENTERED
    task_id: RecordId
    question: str = Field(min_length=1)
    category: TaskCategory
    snapshot_sha: str = Field(pattern=r"^[0-9a-f]{7,64}$")
    policy_sha256: Sha256
    created_at: Timestamp


class Invocation(Record):
    """One attempt to run one worker. Always mechanically observed."""

    origin: Origin = Origin.MECHANICALLY_OBSERVED
    invocation_id: RecordId
    task_id: RecordId
    worker_id: RecordId
    provider: str = Field(min_length=1)
    transport: Transport
    model_requested: str | None
    model_executed: str | None
    stage: Stage
    repeat_index: int = Field(ge=0)
    attempt: int = Field(ge=1)
    idempotency_key: Sha256
    argv: list[str]
    env_names: list[str]
    cwd: str
    executable_sha256: Sha256 | None
    cli_version: str | None
    started_at: Timestamp
    finished_at: Timestamp | None
    duration_ms: int | None = Field(default=None, ge=0)
    exit_code: int | None
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    status: WorkerStatus
    error: str | None
    usage: Usage | None
    cost_usd: float | None = Field(default=None, ge=0)
    stdout_sha256: Sha256 | None
    stderr_sha256: Sha256 | None
    output_file_sha256: Sha256 | None = None
    output_file_truncated: bool = False
    output_file_size: int | None = Field(default=None, ge=0)
    cleanup_error: str | None = None
    # 0.1.2: the worker's own session handle (agy ``conversation_id``; lets
    # ``~/.gemini/antigravity-cli/brain/<id>/`` be derived at read time for
    # cross-run contamination audits) and the duration the worker itself
    # reported (agy ``duration_seconds``). ``duration_ms`` stays clock-derived
    # by Eris and is never overwritten by the worker's figure.
    conversation_id: str | None = None
    worker_reported_duration_ms: int | None = Field(default=None, ge=0)


class Claim(Record):
    origin: Origin = Origin.MODEL_ASSERTED
    claim_id: RecordId
    text: str = Field(min_length=1)
    location: Location | None = None
    evidence_refs: list[RecordId] = Field(default_factory=list)
    revision: int = Field(default=1, ge=1)
    revised_at: Timestamp


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: RecordId
    severity: Severity
    location: Location | None = None
    description: str = Field(min_length=1)
    claim_ids: list[RecordId] = Field(default_factory=list)


class Proposal(Record):
    origin: Origin = Origin.MODEL_ASSERTED
    proposal_id: RecordId
    task_id: RecordId
    invocation_id: RecordId
    worker_id: RecordId
    summary: str
    claims: list[Claim] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    rationale_sha256: Sha256 | None = None


class EvidenceRequest(BaseModel):
    """A model-proposed command. It is a REQUEST: refused unless allowlisted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    argv: list[str] = Field(min_length=1)
    rationale: str = ""


class Challenge(Record):
    origin: Origin = Origin.MODEL_ASSERTED
    challenge_id: RecordId
    target_proposal_id: RecordId
    target_claim_id: RecordId | None = None
    text: str = Field(min_length=1)
    severity: Severity
    evidence_refs: list[RecordId] = Field(default_factory=list)
    evidence_request: EvidenceRequest | None = None
    status: ChallengeStatus = ChallengeStatus.UNVERIFIED


class Critique(Record):
    origin: Origin = Origin.MODEL_ASSERTED
    critique_id: RecordId
    task_id: RecordId
    invocation_id: RecordId
    worker_id: RecordId
    lens: Lens
    target_proposal_ids: list[RecordId]
    challenges: list[Challenge] = Field(default_factory=list)


class EvidenceItem(Record):
    evidence_id: RecordId
    task_id: RecordId
    kind: EvidenceKind
    phase: Phase
    content_sha256: Sha256
    size_bytes: int = Field(ge=0)
    created_at: Timestamp
    argv: list[str] | None = None
    exit_code: int | None = None
    summary: str = ""
    redaction_counts: dict[str, int] = Field(default_factory=dict)


class VerificationResult(Record):
    origin: Origin = Origin.MECHANICALLY_OBSERVED
    verification_id: RecordId
    task_id: RecordId
    claim_id: RecordId
    evidence_id: RecordId
    verdict: VerificationVerdict
    method: str = Field(min_length=1)
    checker_version: str | None = None


class Ruling(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: RecordId
    status: ClaimStatus
    evidence_refs: list[RecordId] = Field(default_factory=list)
    note: str = ""


class Dissent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dissent_id: RecordId
    worker_id: RecordId | None = None
    position: str = Field(min_length=1)
    contested_claim_ids: list[RecordId] = Field(default_factory=list)
    evidence_refs: list[RecordId] = Field(default_factory=list)


class ResidualRisk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1)
    severity: Severity
    mitigation: str | None = None


class Adjudication(Record):
    """The adjudicator's answer. ``dissent`` and ``residual_risks`` are
    REQUIRED keys but may be empty (an honest ABSTAIN must be expressible);
    ``eris.validate`` decides when empty is an error."""

    origin: Origin = Origin.MODEL_ASSERTED
    adjudication_id: RecordId
    task_id: RecordId
    invocation_id: RecordId | None
    verdict: Verdict
    rulings: list[Ruling]
    dissent: list[Dissent]
    residual_risks: list[ResidualRisk]
    rationale: str = ""
    downgrades: int = Field(default=0, ge=0)
    escalated_by_engine: bool = False


class Approval(Record):
    origin: Origin = Origin.HUMAN_ENTERED
    approval_id: RecordId
    task_id: RecordId
    adjudication_id: RecordId
    adjudication_sha256: Sha256
    actor: str = Field(min_length=1)
    action: ApprovalAction
    scope: list[str] = Field(default_factory=list)
    note: str | None = None
    ts: Timestamp


class CostRecord(Record):
    origin: Origin = Origin.MECHANICALLY_OBSERVED
    invocation_id: RecordId
    attempt: int = Field(ge=1)
    cost_usd: float | None = Field(default=None, ge=0)
    usage: Usage | None = None
    counted: bool = True


class Event(Record):
    """One line of ``events.jsonl``. ``prev_sha256`` is the sha256 of the
    previous LINE's bytes (without the newline); ``payload_sha256`` is the
    sha256 of ``canonical_bytes(payload)``. Written only by ``RunWriter``."""

    origin: Origin = Origin.MECHANICALLY_OBSERVED
    seq: int = Field(ge=0)
    ts: Timestamp
    run_id: RecordId
    kind: str = Field(pattern=r"^[a-z][a-z0-9_.]{0,63}$")
    prev_sha256: Sha256 | None
    payload_sha256: Sha256
    payload: dict[str, Any]


RECORD_TYPES: tuple[type[Record], ...] = (
    Task,
    Invocation,
    Claim,
    Proposal,
    Challenge,
    Critique,
    EvidenceItem,
    VerificationResult,
    Adjudication,
    Approval,
    CostRecord,
    Event,
)


# --------------------------------------------------------------------------- canonical


def to_jsonable(obj: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return dict(obj)


def canonical_bytes(obj: BaseModel | Mapping[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no whitespace, no NaN."""
    return json.dumps(
        to_jsonable(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_sha256(obj: BaseModel | Mapping[str, Any]) -> str:
    return sha256_hex(canonical_bytes(obj))
