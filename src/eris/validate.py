"""Engine-enforced adjudication rules. Pure: returns Findings, never raises,
never does I/O.

Codes (severity):

* ``REF_MISSING`` (error) - a cited evidence id does not exist.
* ``REF_MODEL_ASSERTED`` (error) - cited evidence is model_asserted.
* ``REF_PREDATES_CLAIM`` (error) - ``phase=verification`` evidence created
  before the claim's current revision. Applies ONLY to verification evidence;
  evidence-pack items legitimately predate every proposal.
* ``SUPPORTED_WITHOUT_REFS`` (error) - SUPPORTED (or VERIFIED) with no refs.
* ``REFUTED_WITHOUT_REFS`` (error) - REFUTED ruling with no refs.
* ``CLAIM_MISSING`` (error) - a ruling names a claim that does not exist.
* ``DISSENT_EMPTY_WITH_CONTEST`` (error) - contest exists but ``dissent`` is
  empty. (Empty is schema-valid; this is the validator's job.)
* ``RESIDUAL_RISKS_EMPTY_ON_ACCEPT`` (error) - ACCEPT with no residual risks.
* ``ORIGIN_MISMATCH`` (error) - a record's origin contradicts what it is.
* ``UNVERIFIED_CHALLENGE`` (warning) - a challenge without evidence; it is
  RETAINED, never dropped.
* ``SEQ_GAP``, ``HASH_MISMATCH``, ``SCHEMA_VERSION``, ``MALFORMED_LINE``
  (error) - ledger chain problems found by :func:`validate_events`.
* ``ESCALATED`` (info) - :func:`enforce_rulings` forced ESCALATE because the
  downgrade count reached :data:`ESCALATE_AT`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

from pydantic import ValidationError

from eris.schemas import (
    SCHEMA_VERSION,
    Adjudication,
    Approval,
    Challenge,
    ChallengeStatus,
    Claim,
    ClaimStatus,
    CostRecord,
    Critique,
    Event,
    EvidenceItem,
    EvidenceKind,
    Invocation,
    Origin,
    Proposal,
    Record,
    Ruling,
    Task,
    Verdict,
    VerificationResult,
    canonical_bytes,
    parse_ts,
    sha256_hex,
)

ESCALATE_AT = 3

# M1: the codes the engine DETECTS but does not ACT on. Every other error code
# already changes an outcome - the REF_*/`*_WITHOUT_REFS` family downgrades its
# ruling (and is measured by `unsupported_claim_rate`), and VERDICT_* forces
# ACCEPT to ESCALATE. Those are the engine working, not a broken record, and a
# cell carrying them is still evidence.
#
# These are different: the adjudication asserts something incoherent - a ruling
# on a claim nobody made, one claim ruled twice, a contest with no dissent
# recorded, an ACCEPT with no residual risks - and NOTHING happens. `eval/score.py`
# treats a cell whose final adjudication carries one of these as not-evidence.
# DECIDED 2026-08-30 (user): they keep NO verdict powers. Giving them any is a
# protocol change of the same kind as H3, and `DISSENT_EMPTY_WITH_CONTEST` would
# fire on nearly every arm-4 cell today because `_contest_exists` counts any
# non-REFUTED challenge and nothing ever refutes one. Reasons and the concrete
# triggers for revisiting are in
# `docs/decisions/2026-08-30-deferred-validator-decisions.md` - read it before
# proposing a change here.
UNHANDLED_CODES: frozenset[str] = frozenset(
    {
        "CLAIM_MISSING",
        "DUPLICATE_RULING",
        "DISSENT_EMPTY_WITH_CONTEST",
        "RESIDUAL_RISKS_EMPTY_ON_ACCEPT",
        "ORIGIN_MISMATCH",
        "UNVERIFIED_CHALLENGE",
    }
)

Severity = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    message: str
    record_id: str | None = None
    ref: str | None = None
    # Did the engine CHANGE something because of this finding? Set by the
    # producer, which is the only place that knows. Classifying by CODE is
    # wrong: `REF_MISSING` downgrades a SUPPORTED/REFUTED ruling but is inert on
    # a CONTESTED or UNSUPPORTED one, because only those two statuses are
    # downgraded. `eval/score.py` treats an unacted error as evidence that the
    # record is incoherent and nothing was done - which is M1.
    acted: bool = False


CODES: frozenset[str] = frozenset(
    {
        "REF_MISSING",
        "REF_MODEL_ASSERTED",
        "REF_NOT_MECHANICAL",  # H3 (2026-08-27)
        "REF_PREDATES_CLAIM",
        "SUPPORTED_WITHOUT_REFS",
        "REFUTED_WITHOUT_REFS",
        "CLAIM_MISSING",
        "DISSENT_EMPTY_WITH_CONTEST",
        "RESIDUAL_RISKS_EMPTY_ON_ACCEPT",
        "ORIGIN_MISMATCH",
        "UNVERIFIED_CHALLENGE",
        "SEQ_GAP",
        "HASH_MISMATCH",
        "SCHEMA_VERSION",
        "MALFORMED_LINE",
        "ESCALATED",
        "VERDICT_UNSUPPORTED",  # H3 (2026-08-27)
        "VERDICT_UNRESOLVED_CLAIMS",  # H3 (2026-08-29)
        "DUPLICATE_RULING",  # H3 (2026-08-29)
    }
)


def _err(code: str, message: str, record_id: str | None = None, ref: str | None = None) -> Finding:
    return Finding(code, "error", message, record_id, ref)


# --------------------------------------------------------------------------- refs


def _check_refs(
    refs: Sequence[str],
    owner_id: str,
    claim: Claim | None,
    evidence: Mapping[str, EvidenceItem],
) -> tuple[list[Finding], bool]:
    """Return (findings, any_bad). Never raises."""
    findings: list[Finding] = []
    bad = False
    for ref in refs:
        item = evidence.get(ref)
        if item is None:
            findings.append(_err("REF_MISSING", f"evidence {ref!r} does not exist", owner_id, ref))
            bad = True
            continue
        if item.origin is Origin.MODEL_ASSERTED or item.kind is EvidenceKind.MODEL_ASSERTION:
            findings.append(
                _err("REF_MODEL_ASSERTED", f"evidence {ref!r} is model_asserted", owner_id, ref)
            )
            bad = True
            continue
        # H3 (user decision 2026-08-27, STRICT): a ruling may rest ONLY on
        # `mechanically_observed` evidence. Rejecting `model_asserted` alone was
        # weaker than AGENTS.md's stated rule and let a claim be SUPPORTED by
        # HUMAN_ENTERED text - including the task question that asked about it.
        if item.origin is not Origin.MECHANICALLY_OBSERVED:
            findings.append(
                _err(
                    "REF_NOT_MECHANICAL",
                    f"evidence {ref!r} is {item.origin.value}, not mechanically_observed",
                    owner_id,
                    ref,
                )
            )
            bad = True
            continue
        if claim is not None and item.phase.value == "verification":
            try:
                predates = parse_ts(item.created_at) < parse_ts(claim.revised_at)
            except ValueError:
                predates = True
            if predates:
                findings.append(
                    _err(
                        "REF_PREDATES_CLAIM",
                        f"verification evidence {ref!r} predates revision "
                        f"{claim.revision} of claim {claim.claim_id!r}",
                        owner_id,
                        ref,
                    )
                )
                bad = True
    return findings, bad


# --------------------------------------------------------------------------- adjudication


def _contest_exists(rulings: Sequence[Ruling], challenges: Iterable[Challenge]) -> bool:
    if any(r.status is ClaimStatus.CONTESTED for r in rulings):
        return True
    return any(c.status is not ChallengeStatus.REFUTED for c in challenges)


def enforce_rulings(
    adj: Adjudication,
    claims: Mapping[str, Claim],
    evidence: Mapping[str, EvidenceItem],
    challenges: Iterable[Challenge] = (),
) -> tuple[Adjudication, list[Finding]]:
    """Apply the engine rule to a model's adjudication.

    Every ruling's refs are checked; a SUPPORTED/REFUTED ruling with any bad
    ref, or with no refs at all, is downgraded to UNSUPPORTED. When the
    cumulative downgrade count reaches :data:`ESCALATE_AT` the verdict becomes
    ESCALATE. Idempotent on the returned record. Never raises.
    """
    findings: list[Finding] = []
    new_rulings: list[Ruling] = []
    downgrades = 0
    challenges = tuple(challenges)
    for ruling in adj.rulings:
        claim = claims.get(ruling.claim_id)
        if claim is None:
            findings.append(
                _err(
                    "CLAIM_MISSING",
                    f"claim {ruling.claim_id!r} does not exist",
                    adj.adjudication_id,
                )
            )
        ref_findings, bad = _check_refs(ruling.evidence_refs, ruling.claim_id, claim, evidence)
        # Held, not appended: whether these were ACTED ON is only known after the
        # downgrade decision below, and only a downgraded SUPPORTED/REFUTED
        # ruling acts on them. A `REF_MISSING` on a CONTESTED or UNSUPPORTED
        # ruling is flagged and then ignored - that is M1, and classifying by
        # CODE would call it handled.
        per_ruling: list[Finding] = list(ref_findings)
        status = ruling.status
        reasons = [f.code for f in ref_findings]
        if status in (ClaimStatus.SUPPORTED, ClaimStatus.REFUTED):
            if not ruling.evidence_refs:
                code = (
                    "SUPPORTED_WITHOUT_REFS"
                    if status is ClaimStatus.SUPPORTED
                    else "REFUTED_WITHOUT_REFS"
                )
                per_ruling.append(
                    _err(
                        code,
                        f"{status.value} ruling on {ruling.claim_id!r} cites no evidence",
                        ruling.claim_id,
                    )
                )
                reasons.append(code)
                bad = True
            if bad:
                downgrades += 1
                per_ruling = [replace(f, acted=True) for f in per_ruling]
                note = ruling.note
                suffix = f"engine: downgraded {status.value}->UNSUPPORTED ({', '.join(reasons)})"
                note = f"{note}; {suffix}" if note else suffix
                ruling = ruling.model_copy(update={"status": ClaimStatus.UNSUPPORTED, "note": note})
        findings.extend(per_ruling)
        new_rulings.append(ruling)

    # A claim may carry exactly ONE ruling (`PROTOCOL.md`: "each claim gets one
    # of SUPPORTED | REFUTED | CONTESTED | UNSUPPORTED"). Two rulings on one
    # claim make the record self-contradictory - and they defeated the ACCEPT
    # gate, because coverage was a SET membership test: a judge could pair a
    # real UNSUPPORTED with a bogus SUPPORTED duplicate and satisfy both
    # "every claim is ruled" and "some ruling is evidenced" at once.
    seen_claims: set[str] = set()
    duplicate_rulings: set[str] = set()
    for r in new_rulings:
        if r.claim_id in seen_claims:
            duplicate_rulings.add(r.claim_id)
        seen_claims.add(r.claim_id)
    for cid in sorted(duplicate_rulings):
        statuses = sorted({r.status.value for r in new_rulings if r.claim_id == cid})
        findings.append(
            _err(
                "DUPLICATE_RULING",
                f"claim {cid!r} carries {len([r for r in new_rulings if r.claim_id == cid])} "
                f"rulings ({', '.join(statuses)}); a claim may be ruled exactly once",
                adj.adjudication_id,
                cid,
            )
        )

    total = adj.downgrades + downgrades
    verdict = adj.verdict
    escalated = adj.escalated_by_engine
    if total >= ESCALATE_AT and not escalated:
        verdict = Verdict.ESCALATE
        escalated = True
        findings.append(
            Finding(
                "ESCALATED",
                "info",
                f"{total} downgrades >= {ESCALATE_AT}; verdict forced to ESCALATE",
                adj.adjudication_id,
            )
        )
    # H3 (user decision 2026-08-27, STRICT): bind the VERDICT to evidence, not
    # just the individual rulings. Before this, `{"verdict": "ACCEPT",
    # "rulings": []}` passed through untouched - an ACCEPT with zero evidence
    # citations - and a judge that self-declared every ruling UNSUPPORTED also
    # reached ACCEPT, because a self-declared UNSUPPORTED is not a *downgrade*
    # and never armed the escalation guard.
    # ---- ACCEPT preconditions (H3). ACCEPT asserts the proposed answer is
    # defensible GIVEN the panel's claims and the available evidence, so it must
    # rest on evidence AND leave nothing the panel raised unresolved.
    if verdict is Verdict.ACCEPT:
        accept_errors: list[str] = []
        # (a) it must rest on something. A REFUTED ruling counts: if every
        # adverse claim was mechanically refuted the answer IS defensible.
        # Only rulings that SURVIVED enforcement qualify - anything downgraded
        # is now UNSUPPORTED. `r.claim_id in claims` is load-bearing: a ruling
        # naming a claim NOBODY MADE is flagged CLAIM_MISSING but deliberately
        # not downgraded (its refs were fine), so without it a judge could
        # satisfy the rule by inventing a claim id and citing real evidence.
        if not any(
            r.status in (ClaimStatus.SUPPORTED, ClaimStatus.REFUTED)
            and r.claim_id in claims
            and r.claim_id not in duplicate_rulings
            for r in new_rulings
        ):
            findings.append(
                _err(
                    "VERDICT_UNSUPPORTED",
                    "ACCEPT with no evidenced SUPPORTED/REFUTED ruling; forced to ESCALATE",
                    adj.adjudication_id,
                )
            )
            findings[-1] = replace(findings[-1], acted=True)
            accept_errors.append("unsupported")
        # (b) it must leave nothing UNRESOLVED. A claim the judge never ruled on
        # was not adjudicated at all - silently ignoring "there is a null deref
        # at line 42" and returning ACCEPT is precisely the failure this engine
        # exists to prevent. A CONTESTED ruling is an open dispute, not a
        # resolution. UNSUPPORTED IS a resolution ("that claim was not backed"),
        # so it does not block ACCEPT.
        # a claim ruled twice is NOT resolved: the record says two things about it
        ruled = {r.claim_id for r in new_rulings} - duplicate_rulings
        unruled = sorted(set(claims) - ruled)
        contested = sorted(r.claim_id for r in new_rulings if r.status is ClaimStatus.CONTESTED)
        if unruled or contested:
            detail = []
            if unruled:
                detail.append(f"{len(unruled)} claim(s) never ruled on: {unruled[:5]}")
            if contested:
                detail.append(f"{len(contested)} CONTESTED: {contested[:5]}")
            findings.append(
                _err(
                    "VERDICT_UNRESOLVED_CLAIMS",
                    "ACCEPT leaves claims unresolved (" + "; ".join(detail) + ")",
                    adj.adjudication_id,
                )
            )
            findings[-1] = replace(findings[-1], acted=True)
            accept_errors.append("unresolved")
        if accept_errors:
            verdict = Verdict.ESCALATE
            escalated = True
    enforced = adj.model_copy(
        update={
            "rulings": new_rulings,
            "downgrades": total,
            "verdict": verdict,
            "escalated_by_engine": escalated,
        }
    )
    findings.extend(_adjudication_shape_findings(adj, enforced, challenges))
    return enforced, findings


def _adjudication_shape_findings(
    original: Adjudication, enforced: Adjudication, challenges: Sequence[Challenge]
) -> list[Finding]:
    findings: list[Finding] = []
    if _contest_exists(enforced.rulings, challenges) and not enforced.dissent:
        findings.append(
            _err(
                "DISSENT_EMPTY_WITH_CONTEST",
                "a contest exists but dissent is empty",
                original.adjudication_id,
            )
        )
    if original.verdict is Verdict.ACCEPT and not original.residual_risks:
        findings.append(
            _err(
                "RESIDUAL_RISKS_EMPTY_ON_ACCEPT",
                "ACCEPT with no residual risks recorded",
                original.adjudication_id,
            )
        )
    return findings


def validate_adjudication(
    adj: Adjudication,
    claims: Mapping[str, Claim],
    evidence: Mapping[str, EvidenceItem],
    challenges: Iterable[Challenge] = (),
) -> list[Finding]:
    """Findings only (no enforcement). Never raises.

    UNCALLED, DELIBERATELY (decided 2026-08-30). The engine calls
    `enforce_rulings` directly, which both enforces AND returns the findings, so
    a findings-only wrapper has no caller because it has no purpose. It is also
    the only path that would reach `validate_origin`. Reach for it if something
    ever needs findings WITHOUT enforcement.
    See `docs/decisions/2026-08-30-deferred-validator-decisions.md`.
    """
    _, findings = enforce_rulings(adj, claims, evidence, challenges)
    findings.extend(validate_origin(adj))
    return findings


# --------------------------------------------------------------------------- critique


def validate_critique(critique: Critique) -> list[Finding]:
    """Unevidenced challenges are retained and flagged; VERIFIED without refs is an error.

    DELIBERATELY NOT INVOKED (decided 2026-08-30). `ChallengeStatus` is written
    in one place only and always as UNVERIFIED, so calling this today would emit
    `UNVERIFIED_CHALLENGE` for every challenge ever created, permanently, and
    the `VERIFIED`-without-refs branch below is unreachable. That is the M2 hole
    (`VerificationResult` has no producer), not a wiring gap: invoke this in the
    SAME change that builds challenge verification.
    See `docs/decisions/2026-08-30-deferred-validator-decisions.md`.
    """
    findings: list[Finding] = list(validate_origin(critique))
    for ch in critique.challenges:
        findings.extend(validate_origin(ch))
        evidenced = bool(ch.evidence_refs) or ch.evidence_request is not None
        if ch.status is ChallengeStatus.UNVERIFIED:
            findings.append(
                Finding(
                    "UNVERIFIED_CHALLENGE",
                    "warning",
                    "challenge is unverified"
                    + ("" if evidenced else " and carries no evidence_refs or evidence_request")
                    + "; retained",
                    ch.challenge_id,
                )
            )
        elif not ch.evidence_refs:
            findings.append(
                _err(
                    "SUPPORTED_WITHOUT_REFS",
                    f"challenge marked {ch.status.value} cites no evidence",
                    ch.challenge_id,
                )
            )
    return findings


# --------------------------------------------------------------------------- origin

_MECH = frozenset({Origin.MECHANICALLY_OBSERVED})
_MODEL = frozenset({Origin.MODEL_ASSERTED})
_HUMAN = frozenset({Origin.HUMAN_ENTERED})

ORIGIN_RULES: dict[type[Record], frozenset[Origin]] = {
    Invocation: _MECH,
    VerificationResult: _MECH,
    CostRecord: _MECH,
    Event: _MECH,
    Proposal: _MODEL,
    Critique: _MODEL,
    Challenge: _MODEL,
    Claim: _MODEL,
    Approval: _HUMAN,
    Task: _HUMAN,
    Adjudication: frozenset({Origin.MODEL_ASSERTED, Origin.HUMAN_ENTERED}),
}

EVIDENCE_ORIGIN_RULES: dict[EvidenceKind, frozenset[Origin]] = {
    EvidenceKind.TEST_OUTPUT: _MECH,
    EvidenceKind.TOOL_OUTPUT: _MECH,
    EvidenceKind.REPO_FACT: _MECH,
    EvidenceKind.DRY_RUN: _MECH,
    EvidenceKind.DOCUMENT_QUOTE: frozenset({Origin.MECHANICALLY_OBSERVED, Origin.HUMAN_ENTERED}),
    EvidenceKind.HUMAN_ATTESTATION: _HUMAN,
    EvidenceKind.MODEL_ASSERTION: _MODEL,
}


def _record_id(record: Record) -> str | None:
    for name in (
        "evidence_id",
        "adjudication_id",
        "critique_id",
        "challenge_id",
        "claim_id",
        "proposal_id",
        "invocation_id",
        "approval_id",
        "task_id",
        "verification_id",
    ):
        value = getattr(record, name, None)
        if isinstance(value, str):
            return value
    if isinstance(record, Event):
        return f"seq:{record.seq}"
    return None


def validate_origin(record: Record) -> list[Finding]:
    """ORIGIN_MISMATCH when a record's origin contradicts what it is.

    UNREACHABLE AT RUNTIME (decided 2026-08-30). It HAS callers -
    `validate_adjudication` and `validate_critique` - but both of those are
    themselves uncalled, so nothing reaches it. Wire models use
    `extra="forbid"` and have no `origin` field, so a model cannot set one -
    Eris does, in its own constructors. This guards Eris against itself, which
    is a unit-test concern. Make it reachable if a wire model ever gains
    `origin`.
    See `docs/decisions/2026-08-30-deferred-validator-decisions.md`.
    """
    if isinstance(record, EvidenceItem):
        allowed = EVIDENCE_ORIGIN_RULES[record.kind]
        what = f"evidence kind {record.kind.value}"
    else:
        rule = ORIGIN_RULES.get(type(record))
        if rule is None:
            return []
        allowed = rule
        what = type(record).__name__
    if record.origin in allowed:
        return []
    return [
        _err(
            "ORIGIN_MISMATCH",
            f"{what} must have origin in {sorted(o.value for o in allowed)}, "
            f"got {record.origin.value}",
            _record_id(record),
        )
    ]


# --------------------------------------------------------------------------- ledger


def validate_events(lines: Iterable[bytes]) -> list[Finding]:
    """Check an ``events.jsonl`` chain. Pure over bytes; never raises.

    Each line: seq == previous + 1 (first is 0), prev_sha256 == sha256 of the
    previous line's bytes (None for the first), payload_sha256 ==
    sha256(canonical_bytes(payload)), schema_version == SCHEMA_VERSION.
    """
    findings: list[Finding] = []
    prev_sha: str | None = None
    expected_seq = 0
    for index, raw in enumerate(lines):
        line = raw[:-1] if raw.endswith(b"\n") else raw
        where = f"line:{index}"
        try:
            data: Any = json.loads(line)
            if isinstance(data, dict) and data.get("schema_version") != SCHEMA_VERSION:
                # Record parsing refuses foreign versions outright; the ledger
                # validator reports the precise code instead, then checks the
                # rest of the chain with the version substituted (the line's
                # own bytes still feed the hash chain unchanged).
                findings.append(
                    _err(
                        "SCHEMA_VERSION",
                        f"event schema_version {data.get('schema_version')!r} != "
                        f"{SCHEMA_VERSION!r}",
                        f"seq:{data.get('seq')}" if "seq" in data else where,
                    )
                )
                data = {**data, "schema_version": SCHEMA_VERSION}
            event = Event.model_validate(data)
        except (ValueError, ValidationError, TypeError) as exc:
            findings.append(_err("MALFORMED_LINE", f"unparsable event line: {exc!s:.120}", where))
            prev_sha = sha256_hex(line)
            expected_seq += 1
            continue
        where = f"seq:{event.seq}"
        if event.seq != expected_seq:
            findings.append(_err("SEQ_GAP", f"expected seq {expected_seq}, got {event.seq}", where))
            expected_seq = event.seq
        if event.prev_sha256 != prev_sha:
            findings.append(
                _err(
                    "HASH_MISMATCH",
                    f"prev_sha256 {event.prev_sha256!r} != sha256 of previous line {prev_sha!r}",
                    where,
                )
            )
        try:
            payload_sha = sha256_hex(canonical_bytes(event.payload))
        except (TypeError, ValueError):
            payload_sha = ""
        if payload_sha != event.payload_sha256:
            findings.append(
                _err("HASH_MISMATCH", "payload_sha256 does not match canonical payload", where)
            )
        prev_sha = sha256_hex(line)
        expected_seq += 1
    return findings


def has_errors(findings: Iterable[Finding]) -> bool:
    return any(f.severity == "error" for f in findings)
