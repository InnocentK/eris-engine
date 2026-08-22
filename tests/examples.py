"""Deterministic example records shared by the golden-bytes tests and the
validator tests. Changing any value here changes the golden fixtures."""

from __future__ import annotations

from eris.schemas import (
    Adjudication,
    Approval,
    ApprovalAction,
    Challenge,
    ChallengeStatus,
    Claim,
    ClaimStatus,
    CostRecord,
    Critique,
    Dissent,
    Event,
    EvidenceItem,
    EvidenceKind,
    EvidenceRequest,
    Finding,
    Invocation,
    Lens,
    Location,
    Origin,
    Phase,
    Proposal,
    Record,
    ResidualRisk,
    Ruling,
    Severity,
    Stage,
    Task,
    Transport,
    Usage,
    Verdict,
    VerificationResult,
    VerificationVerdict,
    WorkerStatus,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
T0 = "2026-08-21T10:00:00Z"
T1 = "2026-08-21T10:05:00.250000Z"
T2 = "2026-08-21T10:10:00.000001Z"


def example_records() -> dict[str, Record]:
    claim = Claim(
        claim_id="c_01",
        text="Tests pass on the snapshot",
        location=Location(path="providers/claude.py", line_start=148, line_end=171),
        evidence_refs=["e_01"],
        revision=2,
        revised_at=T1,
    )
    return {
        "task": Task(
            task_id="t_01",
            question="Is the change to providers/claude.py defensible?",
            category="revert",
            snapshot_sha="0123abcd",
            policy_sha256=SHA_A,
            created_at=T0,
        ),
        "invocation": Invocation(
            invocation_id="inv_01",
            task_id="t_01",
            worker_id="claude",
            provider="anthropic",
            transport=Transport.CLI,
            model_requested="claude-fable-5",
            model_executed="claude-fable-5",
            stage=Stage.PROPOSE,
            repeat_index=0,
            attempt=1,
            idempotency_key=SHA_B,
            argv=["/opt/homebrew/bin/claude", "-p", "…", "--safe-mode"],
            env_names=["HOME", "PATH"],
            cwd="/tmp/snapshot",
            executable_sha256=SHA_C,
            cli_version="2.1.239",
            started_at=T0,
            finished_at=T1,
            duration_ms=300250,
            exit_code=0,
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
            status=WorkerStatus.OK,
            error=None,
            usage=Usage(input_tokens=2, output_tokens=13, cached_input_tokens=22968),
            cost_usd=0.011819,
            stdout_sha256=SHA_D,
            stderr_sha256=None,
            conversation_id="ed889929-a04c-457f-91d1-194be848aa04",
            worker_reported_duration_ms=2646,
        ),
        "claim": claim,
        "proposal": Proposal(
            proposal_id="p_01",
            task_id="t_01",
            invocation_id="inv_01",
            worker_id="claude",
            summary="Null guard missing in claude.py",
            claims=[claim],
            findings=[
                Finding(
                    finding_id="f_01",
                    severity=Severity.HIGH,
                    location=Location(path="providers/claude.py", line_start=150),
                    description="response.text may be None",
                    claim_ids=["c_01"],
                )
            ],
            assumptions=["CI config unchanged"],
            rationale_sha256=SHA_A,
        ),
        "challenge": Challenge(
            challenge_id="ch_01",
            target_proposal_id="p_01",
            target_claim_id="c_01",
            text="The suite skips integration tests",
            severity=Severity.MEDIUM,
            evidence_request=EvidenceRequest(argv=["pytest", "-q", "-m", "integration"]),
            status=ChallengeStatus.UNVERIFIED,
        ),
        "critique": Critique(
            critique_id="k_01",
            task_id="t_01",
            invocation_id="inv_02",
            worker_id="codex",
            lens=Lens.FRAMING,
            target_proposal_ids=["p_01"],
            challenges=[
                Challenge(
                    challenge_id="ch_01",
                    target_proposal_id="p_01",
                    target_claim_id="c_01",
                    text="The suite skips integration tests",
                    severity=Severity.MEDIUM,
                    evidence_request=EvidenceRequest(argv=["pytest", "-q", "-m", "integration"]),
                )
            ],
        ),
        "evidence": EvidenceItem(
            origin=Origin.MECHANICALLY_OBSERVED,
            evidence_id="e_01",
            task_id="t_01",
            kind=EvidenceKind.TEST_OUTPUT,
            phase=Phase.VERIFICATION,
            content_sha256=SHA_C,
            size_bytes=8123,
            created_at=T2,
            argv=["pytest", "-q"],
            exit_code=0,
            summary="412 passed",
            redaction_counts={"openai_key": 1},
        ),
        "verification": VerificationResult(
            verification_id="v_01",
            task_id="t_01",
            claim_id="c_01",
            evidence_id="e_01",
            verdict=VerificationVerdict.SUPPORTED,
            method="exit_code==0",
            checker_version="eris-verify 0.1.0",
        ),
        "adjudication": Adjudication(
            adjudication_id="adj_01",
            task_id="t_01",
            invocation_id="inv_03",
            verdict=Verdict.ACCEPT,
            rulings=[Ruling(claim_id="c_01", status=ClaimStatus.SUPPORTED, evidence_refs=["e_01"])],
            dissent=[
                Dissent(
                    dissent_id="x_01",
                    worker_id="codex",
                    position="Failure may be a flaky test",
                    contested_claim_ids=["c_01"],
                )
            ],
            residual_risks=[
                ResidualRisk(text="integration tests not run", severity=Severity.MEDIUM)
            ],
            rationale="model-provided rationale (not a trace of internal reasoning)",
        ),
        "approval": Approval(
            approval_id="ap_01",
            task_id="t_01",
            adjudication_id="adj_01",
            adjudication_sha256=SHA_B,
            actor="InnocentK@users.noreply.github.com",
            action=ApprovalAction.APPROVE,
            scope=["apply"],
            note=None,
            ts=T2,
        ),
        "cost": CostRecord(
            invocation_id="inv_01", attempt=1, cost_usd=0.011819, usage=Usage(output_tokens=13)
        ),
        "event": Event(
            seq=1,
            ts=T1,
            run_id="run_01",
            kind="invocation.finished",
            prev_sha256=SHA_A,
            payload_sha256=SHA_B,
            payload={"invocation_id": "inv_01", "status": "ok", "n": 1, "f": 0.5, "z": None},
        ),
    }
