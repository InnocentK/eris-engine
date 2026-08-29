from __future__ import annotations

import json
import random
from collections.abc import Sequence

import pytest

from eris.schemas import (
    SCHEMA_VERSION,
    Adjudication,
    Challenge,
    ChallengeStatus,
    Claim,
    ClaimStatus,
    Critique,
    Dissent,
    Event,
    EvidenceItem,
    EvidenceKind,
    EvidenceRequest,
    Origin,
    Phase,
    ResidualRisk,
    Ruling,
    Severity,
    Verdict,
    canonical_bytes,
    sha256_hex,
)
from eris.validate import (
    CODES,
    ESCALATE_AT,
    Finding,
    enforce_rulings,
    has_errors,
    validate_adjudication,
    validate_critique,
    validate_events,
    validate_origin,
)
from tests.examples import SHA_A, T0, T1, T2, example_records

# --------------------------------------------------------------------------- helpers


def codes(findings: Sequence[Finding]) -> list[str]:
    return [f.code for f in findings]


def claim(claim_id: str = "c_01", revised_at: str = T1, revision: int = 1) -> Claim:
    return Claim(claim_id=claim_id, text="x", revised_at=revised_at, revision=revision)


def evidence(
    evidence_id: str = "e_01",
    *,
    origin: Origin = Origin.MECHANICALLY_OBSERVED,
    kind: EvidenceKind = EvidenceKind.TEST_OUTPUT,
    phase: Phase = Phase.VERIFICATION,
    created_at: str = T2,
) -> EvidenceItem:
    return EvidenceItem(
        origin=origin,
        evidence_id=evidence_id,
        task_id="t",
        kind=kind,
        phase=phase,
        content_sha256=SHA_A,
        size_bytes=1,
        created_at=created_at,
    )


def adjudication(
    rulings: list[Ruling],
    *,
    verdict: Verdict = Verdict.REVISE,
    dissent: list[Dissent] | None = None,
    residual_risks: list[ResidualRisk] | None = None,
    downgrades: int = 0,
) -> Adjudication:
    return Adjudication(
        adjudication_id="adj",
        task_id="t",
        invocation_id=None,
        verdict=verdict,
        rulings=rulings,
        dissent=dissent or [],
        residual_risks=residual_risks
        if residual_risks is not None
        else [ResidualRisk(text="r", severity=Severity.LOW)],
        downgrades=downgrades,
    )


def supported(claim_id: str = "c_01", refs: list[str] | None = None) -> Ruling:
    return Ruling(
        claim_id=claim_id,
        status=ClaimStatus.SUPPORTED,
        evidence_refs=["e_01"] if refs is None else refs,
    )


CLAIMS = {"c_01": claim()}
EVIDENCE = {"e_01": evidence()}


# --------------------------------------------------------------------------- positive


def test_clean_adjudication_has_no_findings() -> None:
    adj = adjudication([supported()])
    enforced, findings = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert findings == []
    assert enforced == adj
    assert validate_adjudication(adj, CLAIMS, EVIDENCE) == []


def test_evidence_pack_item_may_predate_claim() -> None:
    """REF_PREDATES_CLAIM applies ONLY to phase=verification evidence."""
    old_pack = evidence(phase=Phase.EVIDENCE_PACK, created_at=T0)
    adj = adjudication([supported()])
    enforced, findings = enforce_rulings(adj, CLAIMS, {"e_01": old_pack})
    assert findings == []
    assert enforced.rulings[0].status is ClaimStatus.SUPPORTED


# --------------------------------------------------------------------------- each code negative


def test_ref_missing_downgrades() -> None:
    adj = adjudication([supported(refs=["nope"])])
    enforced, findings = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert codes(findings) == ["REF_MISSING"]
    assert findings[0].ref == "nope"
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED
    assert "engine: downgraded SUPPORTED->UNSUPPORTED (REF_MISSING)" in enforced.rulings[0].note
    assert enforced.downgrades == 1


def test_ref_model_asserted_downgrades() -> None:
    ev = {"e_01": evidence(origin=Origin.MODEL_ASSERTED, kind=EvidenceKind.MODEL_ASSERTION)}
    enforced, findings = enforce_rulings(adjudication([supported()]), CLAIMS, ev)
    assert codes(findings) == ["REF_MODEL_ASSERTED"]
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED


def test_ref_predates_claim_only_for_verification_phase() -> None:
    stale = {"e_01": evidence(phase=Phase.VERIFICATION, created_at=T0)}
    enforced, findings = enforce_rulings(adjudication([supported()]), CLAIMS, stale)
    assert codes(findings) == ["REF_PREDATES_CLAIM"]
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED


def test_ref_equal_timestamp_does_not_predate() -> None:
    same = {"e_01": evidence(created_at=T1)}
    _, findings = enforce_rulings(adjudication([supported()]), CLAIMS, same)
    assert findings == []


def test_supported_without_refs() -> None:
    enforced, findings = enforce_rulings(adjudication([supported(refs=[])]), CLAIMS, EVIDENCE)
    assert codes(findings) == ["SUPPORTED_WITHOUT_REFS"]
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED


def test_refuted_without_refs() -> None:
    r = Ruling(claim_id="c_01", status=ClaimStatus.REFUTED)
    enforced, findings = enforce_rulings(adjudication([r]), CLAIMS, EVIDENCE)
    assert codes(findings) == ["REFUTED_WITHOUT_REFS"]
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED


def test_unsupported_or_contested_with_bad_refs_is_flagged_not_downgraded() -> None:
    r = Ruling(claim_id="c_01", status=ClaimStatus.CONTESTED, evidence_refs=["nope"])
    adj = adjudication([r], dissent=[Dissent(dissent_id="d", position="p")])
    enforced, findings = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert codes(findings) == ["REF_MISSING"]
    assert enforced.downgrades == 0
    assert enforced.rulings[0].status is ClaimStatus.CONTESTED


def test_claim_missing() -> None:
    enforced, findings = enforce_rulings(adjudication([supported("ghost")]), CLAIMS, EVIDENCE)
    assert codes(findings) == ["CLAIM_MISSING"]
    # refs were fine, so no downgrade; but the claim is unknown
    assert enforced.rulings[0].status is ClaimStatus.SUPPORTED


def test_dissent_empty_with_contest_from_ruling() -> None:
    r = Ruling(claim_id="c_01", status=ClaimStatus.CONTESTED, evidence_refs=["e_01"])
    _, findings = enforce_rulings(adjudication([r]), CLAIMS, EVIDENCE)
    assert codes(findings) == ["DISSENT_EMPTY_WITH_CONTEST"]


def test_dissent_empty_with_contest_from_challenge() -> None:
    ch = Challenge(challenge_id="ch", target_proposal_id="p", text="t", severity=Severity.LOW)
    _, findings = enforce_rulings(adjudication([supported()]), CLAIMS, EVIDENCE, [ch])
    assert codes(findings) == ["DISSENT_EMPTY_WITH_CONTEST"]
    refuted = ch.model_copy(update={"status": ChallengeStatus.REFUTED})
    _, findings = enforce_rulings(adjudication([supported()]), CLAIMS, EVIDENCE, [refuted])
    assert findings == []


def test_dissent_present_with_contest_is_fine() -> None:
    r = Ruling(claim_id="c_01", status=ClaimStatus.CONTESTED, evidence_refs=["e_01"])
    adj = adjudication([r], dissent=[Dissent(dissent_id="d", position="disagree")])
    _, findings = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert findings == []


def test_residual_risks_empty_on_accept() -> None:
    adj = adjudication([supported()], verdict=Verdict.ACCEPT, residual_risks=[])
    _, findings = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert codes(findings) == ["RESIDUAL_RISKS_EMPTY_ON_ACCEPT"]


def test_abstain_with_empty_lists_is_honest_and_clean() -> None:
    adj = adjudication([], verdict=Verdict.ABSTAIN, residual_risks=[])
    _, findings = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert findings == []


def test_origin_mismatch_cases() -> None:
    assert codes(validate_origin(evidence(origin=Origin.MODEL_ASSERTED))) == ["ORIGIN_MISMATCH"]
    assert (
        validate_origin(evidence(origin=Origin.HUMAN_ENTERED, kind=EvidenceKind.HUMAN_ATTESTATION))
        == []
    )
    assert codes(validate_origin(evidence(kind=EvidenceKind.HUMAN_ATTESTATION))) == [
        "ORIGIN_MISMATCH"
    ]
    proposal = example_records()["proposal"]
    assert validate_origin(proposal) == []
    blurred = proposal.model_copy(update={"origin": Origin.MECHANICALLY_OBSERVED})
    f = validate_origin(blurred)
    assert codes(f) == ["ORIGIN_MISMATCH"] and f[0].record_id == "p_01"
    inv = example_records()["invocation"]
    assert codes(validate_origin(inv.model_copy(update={"origin": Origin.MODEL_ASSERTED}))) == [
        "ORIGIN_MISMATCH"
    ]
    ap = example_records()["approval"]
    assert codes(validate_origin(ap.model_copy(update={"origin": Origin.MODEL_ASSERTED}))) == [
        "ORIGIN_MISMATCH"
    ]
    ev = example_records()["event"]
    assert validate_origin(ev) == []
    assert (
        validate_origin(ev.model_copy(update={"origin": Origin.HUMAN_ENTERED}))[0].record_id
        == "seq:1"
    )
    human_adj = adjudication([]).model_copy(update={"origin": Origin.HUMAN_ENTERED})
    assert validate_origin(human_adj) == []


def test_validate_adjudication_includes_origin() -> None:
    adj = adjudication([supported()]).model_copy(update={"origin": Origin.MECHANICALLY_OBSERVED})
    assert codes(validate_adjudication(adj, CLAIMS, EVIDENCE)) == ["ORIGIN_MISMATCH"]


def test_unverified_challenge_is_warning_and_retained() -> None:
    critique = example_records()["critique"]
    assert isinstance(critique, Critique)
    findings = validate_critique(critique)
    assert codes(findings) == ["UNVERIFIED_CHALLENGE"]
    assert findings[0].severity == "warning"
    assert not has_errors(findings)
    bare = Challenge(challenge_id="b", target_proposal_id="p", text="t", severity=Severity.LOW)
    f = validate_critique(critique.model_copy(update={"challenges": [bare]}))
    assert "carries no evidence_refs" in f[0].message
    verified_no_refs = bare.model_copy(update={"status": ChallengeStatus.VERIFIED})
    f = validate_critique(critique.model_copy(update={"challenges": [verified_no_refs]}))
    assert codes(f) == ["SUPPORTED_WITHOUT_REFS"] and has_errors(f)
    with_req = bare.model_copy(update={"evidence_request": EvidenceRequest(argv=["git", "log"])})
    assert (
        "retained"
        in validate_critique(critique.model_copy(update={"challenges": [with_req]}))[0].message
    )


# --------------------------------------------------------------------------- escalation


def test_escalates_at_three_downgrades() -> None:
    rulings = [supported(f"c_{i}", refs=[]) for i in range(ESCALATE_AT)]
    claims = {f"c_{i}": claim(f"c_{i}") for i in range(ESCALATE_AT)}
    adj = adjudication(rulings, verdict=Verdict.ACCEPT)
    enforced, findings = enforce_rulings(adj, claims, EVIDENCE)
    assert enforced.verdict is Verdict.ESCALATE
    assert enforced.escalated_by_engine is True
    assert enforced.downgrades == ESCALATE_AT
    assert "ESCALATED" in codes(findings)
    assert codes(findings).count("SUPPORTED_WITHOUT_REFS") == ESCALATE_AT


def test_two_downgrades_do_not_escalate() -> None:
    rulings = [supported(f"c_{i}", refs=[]) for i in range(2)]
    claims = {f"c_{i}": claim(f"c_{i}") for i in range(2)}
    enforced, findings = enforce_rulings(adjudication(rulings), claims, EVIDENCE)
    assert enforced.verdict is Verdict.REVISE
    assert "ESCALATED" not in codes(findings)


def test_downgrades_accumulate_across_passes() -> None:
    rulings = [supported("c_01", refs=[])]
    adj = adjudication(rulings, downgrades=ESCALATE_AT - 1)
    enforced, _ = enforce_rulings(adj, CLAIMS, EVIDENCE)
    assert enforced.downgrades == ESCALATE_AT
    assert enforced.verdict is Verdict.ESCALATE


def test_enforce_is_idempotent() -> None:
    rulings = [supported(f"c_{i}", refs=["nope"]) for i in range(4)]
    claims = {f"c_{i}": claim(f"c_{i}") for i in range(4)}
    once, _ = enforce_rulings(adjudication(rulings), claims, EVIDENCE)
    twice, _ = enforce_rulings(once, claims, EVIDENCE)
    assert once == twice


# --------------------------------------------------------------------------- ledger


def make_chain(payloads: list[dict[str, object]]) -> list[bytes]:
    lines: list[bytes] = []
    prev: str | None = None
    for seq, payload in enumerate(payloads):
        ev = Event(
            seq=seq,
            ts=T1,
            run_id="r",
            kind="k",
            prev_sha256=prev,
            payload_sha256=sha256_hex(canonical_bytes(payload)),
            payload=payload,
        )
        line = canonical_bytes(ev)
        lines.append(line + b"\n")
        prev = sha256_hex(line)
    return lines


def test_events_clean_chain() -> None:
    assert validate_events(make_chain([{"a": 1}, {"b": 2}, {"c": 3}])) == []
    assert validate_events([]) == []


def test_events_seq_gap() -> None:
    lines = make_chain([{"a": 1}, {"b": 2}, {"c": 3}])
    del lines[1]
    f = validate_events(lines)
    assert "SEQ_GAP" in codes(f) and "HASH_MISMATCH" in codes(f)


def test_events_hash_mismatch_on_tampered_payload() -> None:
    lines = make_chain([{"a": 1}, {"b": 2}])
    data = json.loads(lines[0])
    data["payload"]["a"] = 2
    lines[0] = canonical_bytes(data) + b"\n"
    f = validate_events(lines)
    assert codes(f).count("HASH_MISMATCH") == 2  # payload hash + next line's prev
    assert f[0].record_id == "seq:0"


def test_events_schema_version() -> None:
    lines = make_chain([{"a": 1}])
    data = json.loads(lines[0])
    data["schema_version"] = "9.9.9"
    lines[0] = canonical_bytes(data) + b"\n"
    assert codes(validate_events(lines)) == ["SCHEMA_VERSION"]
    assert SCHEMA_VERSION != "9.9.9"


def test_events_malformed_line_never_raises() -> None:
    lines = make_chain([{"a": 1}, {"b": 2}, {"c": 3}])
    lines[1] = b"{not json\n"
    f = validate_events(lines)
    assert f[0].code == "MALFORMED_LINE" and f[0].record_id == "line:1"
    assert "HASH_MISMATCH" in codes(f)  # line 2's prev no longer matches
    lines[1] = b'{"seq": 1}\n'
    assert "MALFORMED_LINE" in codes(validate_events(lines))
    assert validate_events([b"", b"\n", b"\xff\xfe", b"[]", b"null"])


def test_all_codes_are_declared() -> None:
    assert {
        "REF_MISSING",
        "REF_MODEL_ASSERTED",
        "REF_PREDATES_CLAIM",
        "SUPPORTED_WITHOUT_REFS",
        "DISSENT_EMPTY_WITH_CONTEST",
        "RESIDUAL_RISKS_EMPTY_ON_ACCEPT",
        "ORIGIN_MISMATCH",
        "UNVERIFIED_CHALLENGE",
        "SEQ_GAP",
        "HASH_MISMATCH",
        "SCHEMA_VERSION",
    } <= CODES


# --------------------------------------------------------------------------- property


def _random_world(
    rng: random.Random,
) -> tuple[Adjudication, dict[str, Claim], dict[str, EvidenceItem], list[Challenge]]:
    times = [T0, T1, T2]
    claim_ids = [f"c_{i}" for i in range(rng.randint(0, 6))]
    claims = {cid: claim(cid, revised_at=rng.choice(times)) for cid in claim_ids}
    ev_ids = [f"e_{i}" for i in range(rng.randint(0, 6))]
    evidence_map = {
        eid: evidence(
            eid,
            origin=rng.choice(list(Origin)),
            kind=rng.choice(list(EvidenceKind)),
            phase=rng.choice(list(Phase)),
            created_at=rng.choice(times),
        )
        for eid in ev_ids
    }
    pool = ev_ids + ["missing_1", "missing_2"]
    rulings = [
        Ruling(
            claim_id=rng.choice(claim_ids + ["ghost"]),
            status=rng.choice(list(ClaimStatus)),
            evidence_refs=rng.sample(pool, k=rng.randint(0, min(3, len(pool)))),
        )
        for _ in range(rng.randint(0, 8))
    ]
    challenges = [
        Challenge(
            challenge_id=f"ch_{i}",
            target_proposal_id="p",
            text="t",
            severity=rng.choice(list(Severity)),
            status=rng.choice(list(ChallengeStatus)),
        )
        for i in range(rng.randint(0, 3))
    ]
    adj = adjudication(
        rulings,
        verdict=rng.choice(list(Verdict)),
        dissent=[Dissent(dissent_id="d", position="p")] if rng.random() < 0.5 else [],
        residual_risks=[] if rng.random() < 0.5 else None,
        downgrades=rng.randint(0, 4),
    )
    return adj, claims, evidence_map, challenges


@pytest.mark.parametrize("seed", range(40))
def test_property_enforce_never_raises_and_is_idempotent(seed: int) -> None:
    rng = random.Random(seed)
    adj, claims, ev, challenges = _random_world(rng)
    once, findings = enforce_rulings(adj, claims, ev, challenges)
    assert all(f.code in CODES for f in findings)
    twice, _ = enforce_rulings(once, claims, ev, challenges)
    assert once == twice
    assert once.downgrades >= adj.downgrades
    if once.downgrades >= ESCALATE_AT:
        assert once.verdict is Verdict.ESCALATE
    for r in once.rulings:
        if r.status in (ClaimStatus.SUPPORTED, ClaimStatus.REFUTED):
            assert r.evidence_refs
            for ref in r.evidence_refs:
                # H3 (strict): the surviving rule is mechanically_observed,
                # not merely "not model_asserted"
                assert ref in ev and ev[ref].origin is Origin.MECHANICALLY_OBSERVED
    if once.verdict is Verdict.ACCEPT:
        assert any(r.status is ClaimStatus.SUPPORTED for r in once.rulings)


@pytest.mark.parametrize("seed", range(20))
def test_property_validate_events_never_raises(seed: int) -> None:
    rng = random.Random(seed)
    lines = make_chain([{"i": i, "r": rng.random()} for i in range(rng.randint(0, 6))])
    for _ in range(rng.randint(0, 4)):
        if not lines:
            break
        i = rng.randrange(len(lines))
        op = rng.choice(["flip", "drop", "dup", "garbage", "truncate"])
        if op == "flip":
            b = bytearray(lines[i])
            j = rng.randrange(len(b) - 1)
            b[j] = (b[j] + 1) % 256
            lines[i] = bytes(b)
        elif op == "drop":
            del lines[i]
        elif op == "dup":
            lines.insert(i, lines[i])
        elif op == "garbage":
            lines[i] = bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
        else:
            lines[i] = lines[i][: rng.randrange(len(lines[i]))]
    findings = validate_events(lines)
    assert all(f.code in CODES and f.severity == "error" for f in findings)


# --------------------------------------------------------------- H3 (strict, 2026-08-27)


def test_supported_ruling_needs_mechanically_observed_evidence() -> None:
    """H3a: rejecting only `model_asserted` was weaker than AGENTS.md's rule.

    A HUMAN_ENTERED document quote - the task question itself is one, via
    `build_evidence_pack` - could support a claim, so "the null guard is missing
    at line 42" could be SUPPORTED by the question that asked about it.
    """
    human = {"e_h": evidence("e_h", origin=Origin.HUMAN_ENTERED, kind=EvidenceKind.DOCUMENT_QUOTE)}
    enforced, findings = enforce_rulings(adjudication([supported(refs=["e_h"])]), CLAIMS, human)
    assert codes(findings) == ["REF_NOT_MECHANICAL"]
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED
    assert enforced.downgrades == 1
    # mechanically observed evidence is unaffected
    enforced, findings = enforce_rulings(adjudication([supported(refs=["e_01"])]), CLAIMS, EVIDENCE)
    assert codes(findings) == []
    assert enforced.rulings[0].status is ClaimStatus.SUPPORTED


def test_accept_without_a_supported_ruling_is_escalated() -> None:
    """H3b: bind the VERDICT to evidence, not only the individual rulings.

    `{"verdict": "ACCEPT", "rulings": []}` used to pass through untouched, and a
    judge that self-declared every ruling UNSUPPORTED also reached ACCEPT - a
    self-declared UNSUPPORTED is not a *downgrade*, so the escalation guard at
    ESCALATE_AT never armed.
    """
    enforced, findings = enforce_rulings(
        adjudication(
            [],
            verdict=Verdict.ACCEPT,
            residual_risks=[ResidualRisk(text="r", severity=Severity.LOW)],
        ),
        CLAIMS,
        EVIDENCE,
    )
    assert "VERDICT_UNSUPPORTED" in codes(findings)
    assert enforced.verdict is Verdict.ESCALATE
    assert enforced.escalated_by_engine is True

    # self-declared UNSUPPORTED rulings: still no support, still escalated
    r = Ruling(claim_id="c_01", status=ClaimStatus.UNSUPPORTED, evidence_refs=["e_01"])
    enforced, findings = enforce_rulings(
        adjudication(
            [r],
            verdict=Verdict.ACCEPT,
            residual_risks=[ResidualRisk(text="r", severity=Severity.LOW)],
        ),
        CLAIMS,
        EVIDENCE,
    )
    assert enforced.verdict is Verdict.ESCALATE
    assert enforced.downgrades == 0  # not a downgrade - that was the hole

    # an ACCEPT that IS supported stands
    enforced, findings = enforce_rulings(
        adjudication(
            [supported(refs=["e_01"])],
            verdict=Verdict.ACCEPT,
            residual_risks=[ResidualRisk(text="r", severity=Severity.LOW)],
        ),
        CLAIMS,
        EVIDENCE,
    )
    assert enforced.verdict is Verdict.ACCEPT and codes(findings) == []


def test_a_fabricated_claim_id_cannot_satisfy_the_accept_rule() -> None:
    """H3, stop-gate finding: the ACCEPT rule must rest on a REAL claim.

    A ruling naming a claim nobody made is flagged CLAIM_MISSING but is
    deliberately NOT downgraded (see `test_claim_missing`: its refs were fine).
    So a judge could invent a claim id, cite genuine mechanically_observed
    evidence at it, and that ruling would satisfy "ACCEPT needs a surviving
    evidenced ruling" - an ACCEPT resting on a claim that does not exist.
    """
    ghost = Ruling(claim_id="clm-deadbeef-9", status=ClaimStatus.SUPPORTED, evidence_refs=["e_01"])
    enforced, findings = enforce_rulings(
        adjudication([ghost], verdict=Verdict.ACCEPT), CLAIMS, EVIDENCE
    )
    assert "CLAIM_MISSING" in codes(findings)
    assert "VERDICT_UNSUPPORTED" in codes(findings)
    assert enforced.verdict is Verdict.ESCALATE
    # the ruling itself is still not downgraded - that is the documented
    # behaviour of test_claim_missing; it simply cannot prop up a verdict
    assert enforced.rulings[0].status is ClaimStatus.SUPPORTED

    # one real evidenced ruling alongside the ghost is enough for ACCEPT
    enforced, _ = enforce_rulings(
        adjudication([ghost, supported(refs=["e_01"])], verdict=Verdict.ACCEPT),
        CLAIMS,
        EVIDENCE,
    )
    assert enforced.verdict is Verdict.ACCEPT


def test_accept_may_rest_on_a_mechanically_refuted_ruling_alone() -> None:
    """H3, advisor finding: `REFUTED` satisfies the ACCEPT rule.

    If every adverse claim is mechanically REFUTED the proposed answer IS
    defensible, so demanding a SUPPORTED ruling would escalate a legitimate
    ACCEPT. This is the half of the verdict rule that the other H3 tests, which
    only exercise SUPPORTED, do not cover.
    """
    refuted = Ruling(claim_id="c_01", status=ClaimStatus.REFUTED, evidence_refs=["e_01"])
    enforced, findings = enforce_rulings(
        adjudication([refuted], verdict=Verdict.ACCEPT), CLAIMS, EVIDENCE
    )
    assert enforced.rulings[0].status is ClaimStatus.REFUTED  # survived enforcement
    assert "VERDICT_UNSUPPORTED" not in codes(findings)
    assert enforced.verdict is Verdict.ACCEPT

    # but a REFUTED ruling that was DOWNGRADED cannot prop up ACCEPT
    enforced, findings = enforce_rulings(
        adjudication(
            [Ruling(claim_id="c_01", status=ClaimStatus.REFUTED, evidence_refs=["ghost"])],
            verdict=Verdict.ACCEPT,
        ),
        CLAIMS,
        EVIDENCE,
    )
    assert enforced.rulings[0].status is ClaimStatus.UNSUPPORTED
    assert "VERDICT_UNSUPPORTED" in codes(findings)
    assert enforced.verdict is Verdict.ESCALATE


def test_accept_cannot_leave_a_claim_unresolved() -> None:
    """H3, stop-gate finding: ACCEPT must RESOLVE the panel's claims, not merely
    rest on one of them.

    `claims` is every claim from every proposal (`stages.py`: `{c.claim_id: c
    for p in proposals for c in p.claims}`), so a claim with no ruling was never
    adjudicated at all. Silently ignoring "there is a null deref at line 42" and
    returning ACCEPT is exactly the failure this engine exists to prevent. A
    CONTESTED ruling is an open dispute, not a resolution. UNSUPPORTED IS a
    resolution - "that claim was not backed" - so it does not block ACCEPT.
    """
    claims = {cid: claim(cid) for cid in ("c_01", "c_02", "c_03")}

    def supported_on(cid: str) -> Ruling:
        return Ruling(claim_id=cid, status=ClaimStatus.SUPPORTED, evidence_refs=["e_01"])

    # ruled on one of three: the other two were ignored
    enforced, findings = enforce_rulings(
        adjudication([supported_on("c_01")], verdict=Verdict.ACCEPT), claims, EVIDENCE
    )
    assert "VERDICT_UNRESOLVED_CLAIMS" in codes(findings)
    assert enforced.verdict is Verdict.ESCALATE and enforced.escalated_by_engine
    assert "c_02" in findings[0].message and "c_03" in findings[0].message

    # a CONTESTED claim is an open dispute
    enforced, findings = enforce_rulings(
        adjudication(
            [
                supported_on("c_01"),
                supported_on("c_02"),
                Ruling(claim_id="c_03", status=ClaimStatus.CONTESTED, evidence_refs=["e_01"]),
            ],
            verdict=Verdict.ACCEPT,
            dissent=[Dissent(dissent_id="d", position="p")],
        ),
        claims,
        EVIDENCE,
    )
    assert "VERDICT_UNRESOLVED_CLAIMS" in codes(findings)
    assert enforced.verdict is Verdict.ESCALATE

    # UNSUPPORTED is a resolution, not an open question
    enforced, findings = enforce_rulings(
        adjudication(
            [
                supported_on("c_01"),
                supported_on("c_02"),
                Ruling(claim_id="c_03", status=ClaimStatus.UNSUPPORTED),
            ],
            verdict=Verdict.ACCEPT,
        ),
        claims,
        EVIDENCE,
    )
    assert "VERDICT_UNRESOLVED_CLAIMS" not in codes(findings)
    assert enforced.verdict is Verdict.ACCEPT

    # every claim resolved: ACCEPT stands
    enforced, findings = enforce_rulings(
        adjudication([supported_on(c) for c in claims], verdict=Verdict.ACCEPT),
        claims,
        EVIDENCE,
    )
    assert enforced.verdict is Verdict.ACCEPT and codes(findings) == []

    # a non-ACCEPT verdict is untouched by this rule
    enforced, findings = enforce_rulings(
        adjudication([supported_on("c_01")], verdict=Verdict.REVISE), claims, EVIDENCE
    )
    assert "VERDICT_UNRESOLVED_CLAIMS" not in codes(findings)
    assert enforced.verdict is Verdict.REVISE


def test_a_claim_ruled_twice_cannot_satisfy_the_accept_guard() -> None:
    """H3, stop-gate finding: contradictory duplicate rulings bypassed ACCEPT.

    Coverage was a SET membership test, so a judge could pair a real
    `UNSUPPORTED` with a bogus `SUPPORTED` duplicate on the SAME claim and
    satisfy both halves at once - "every claim is ruled" and "some ruling is
    evidenced" - while the record said two contradictory things about that
    claim. `PROTOCOL.md` gives each claim exactly one of SUPPORTED | REFUTED |
    CONTESTED | UNSUPPORTED, so a second ruling is a validity error and the
    claim counts as unresolved.
    """
    claims = {cid: claim(cid) for cid in ("c_01", "c_02")}
    sup = Ruling(claim_id="c_01", status=ClaimStatus.SUPPORTED, evidence_refs=["e_01"])
    uns = Ruling(claim_id="c_01", status=ClaimStatus.UNSUPPORTED)
    other = Ruling(claim_id="c_02", status=ClaimStatus.SUPPORTED, evidence_refs=["e_01"])

    enforced, findings = enforce_rulings(
        adjudication([sup, uns, other], verdict=Verdict.ACCEPT), claims, EVIDENCE
    )
    assert "DUPLICATE_RULING" in codes(findings)
    assert "VERDICT_UNRESOLVED_CLAIMS" in codes(findings)
    assert enforced.verdict is Verdict.ESCALATE
    dup = next(f for f in findings if f.code == "DUPLICATE_RULING")
    assert dup.ref == "c_01" and "SUPPORTED" in dup.message and "UNSUPPORTED" in dup.message

    # even a redundant identical duplicate is a validity error
    enforced, findings = enforce_rulings(
        adjudication([sup, sup, other], verdict=Verdict.ACCEPT), claims, EVIDENCE
    )
    assert "DUPLICATE_RULING" in codes(findings) and enforced.verdict is Verdict.ESCALATE

    # a duplicated claim cannot be the thing ACCEPT rests on either
    enforced, findings = enforce_rulings(
        adjudication(
            [sup, uns, Ruling(claim_id="c_02", status=ClaimStatus.UNSUPPORTED)],
            verdict=Verdict.ACCEPT,
        ),
        claims,
        EVIDENCE,
    )
    assert "VERDICT_UNSUPPORTED" in codes(findings)

    # one ruling per claim is untouched
    enforced, findings = enforce_rulings(
        adjudication([sup, other], verdict=Verdict.ACCEPT), claims, EVIDENCE
    )
    assert codes(findings) == [] and enforced.verdict is Verdict.ACCEPT
