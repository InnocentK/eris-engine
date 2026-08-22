# Eris protocol (Phase 0 harness)

This document states the protocol the Phase 0 harness is built to evaluate and
the rules the code already enforces. Nothing here is an orchestrator; the
pipeline stages beyond "propose" are Milestone 2 and are marked as such.

## The question Eris answers

"Is this proposed answer, plan, patch, or action defensible given competing
proposals, adversarial criticism, and available evidence?"

Athena and Hermes decide what work to pursue. Eris decides whether a proposed
answer or action is defensible.

## Pipeline (hypothesis under test)

1. **Independent proposals** - each declared worker runs in a fresh process,
   read-only, in a history-truncated snapshot, with a byte-identical prompt.
   Workers never see each other. *(Milestone 1: `eval/run.py invoke` runs ONE
   worker for this stage.)*
2. **One critique round** - critics see proposals, never each other, with a
   mandatory `framing` lens ("assume the leading proposal is wrong"). Exactly
   one round; no rebuttal chat. *(Milestone 2.)*
3. **Mechanical verification** - Eris executes only allowlisted commands
   (`src/eris/verify.py`) inside the snapshot. Model-proposed commands are
   requests and are refused unless allowlisted. *(Grammar: Milestone 1;
   stage wiring: Milestone 2.)*
4. **Evidence-bound adjudication** - a model answers; the ENGINE then applies
   the rules in `src/eris/validate.py` to its answer. *(Validator: Milestone
   1; stage wiring: Milestone 2.)*
5. **Human gate** - any action leaving the sandbox requires an `Approval`
   record bound to the sha256 of the adjudication it approves. *(Schema only.)*

Two separate limits: critique ROUNDS (one) and evidence ITERATIONS (re-verify
while allowlisted evidence requests remain; no model prose is regenerated).

## Origin: never blurred

Every record carries `origin`:

| origin | meaning | examples |
|---|---|---|
| `mechanically_observed` | produced by running a tool, hashed by the writer | `Invocation`, `EvidenceItem(kind=test_output)`, `VerificationResult`, `Event` |
| `model_asserted` | a model said it | `Proposal`, `Claim`, `Critique`, `Challenge`, `Adjudication`, `EvidenceItem(kind=model_assertion)` |
| `human_entered` | a person typed it | `Task`, `Approval`, `EvidenceItem(kind=human_attestation)` |

`validate_origin` emits `ORIGIN_MISMATCH` when a record's origin contradicts
what it is (`tests/test_validate.py::test_origin_mismatch_cases`).

Model rationale is rendered as "model-provided rationale (not a trace of
internal reasoning)". Eris never claims to reveal hidden chain-of-thought.

## The evidence rule (engine-enforced)

Applied by `enforce_rulings` to every adjudication, after the model answers:

* Each claim gets one of `SUPPORTED | REFUTED | CONTESTED | UNSUPPORTED`.
* A `SUPPORTED` or `REFUTED` ruling is **downgraded to `UNSUPPORTED`** when it
  cites no evidence, or when any cited evidence is missing, is
  `model_asserted`, or (for `phase=verification` evidence only) was created
  before the claim's current revision. Evidence-pack items legitimately
  predate every proposal and are never "stale".
* Three or more cumulative downgrades force the verdict to `ESCALATE`.
  (Swapping the adjudicator lineage once before escalating is Milestone 2.)
* "All models agree" with no evidence is `UNSUPPORTED`. Agreement is weak
  evidence; tool output, tests, repository facts and upstream documentation
  outrank it. Never claim consensus from a vote.
* Unevidenced challenges are **retained** as `UNVERIFIED` (warning), never
  dropped - suppressing them would suppress valid uncertainty.

## Verdict vocabulary

`ACCEPT | REVISE | ESCALATE | ABSTAIN | REJECT`

* `dissent` and `residual_risks` are REQUIRED keys on every adjudication but
  may be empty: an honest `ABSTAIN` must be expressible.
* The validator, not the schema, decides when empty is wrong:
  `DISSENT_EMPTY_WITH_CONTEST` when a contest exists (a `CONTESTED` ruling or
  a non-refuted challenge) and `RESIDUAL_RISKS_EMPTY_ON_ACCEPT`.
* "Insufficient evidence" (`ABSTAIN`) and "human review required"
  (`ESCALATE`) are valid, successful outcomes.

## Independence

Independence is recorded from the executed provider + model per run
(`Invocation.provider`, `Invocation.model_executed`), not the CLI brand. Codex
emits no model id in its JSONL, so `model_executed` is `None` for codex runs
and is recorded as unknown, never guessed. Hermes, as configured on this
machine, is OpenAI-backed and has no read-only mode: a caller, not a worker.

## Absence, never substitution

A worker that is missing, unpinned, refused, failed, timed out, or over
budget is recorded (`WorkerStatus`, `worker.absent` event). No fallback inside
a panel - it would collapse lineage diversity. In the evaluation a
budget-tripped cell is MISSING, not ABSTAIN.

## Idempotency

The worker-call key (`launch.idempotency_key`) hashes worker id, provider,
model, stage, task id, prompt sha256, schema sha256, repeat index and policy
sha256. It deliberately EXCLUDES the experimental arm so arms 3/3b/4 share
proposals (paired ablation) and INCLUDES `repeat_index` so repeats are
distinct. Every retry attempt is its own event; failed attempts' cost counts.

## The ledger

`runs/<run_id>/events.jsonl` is an append-only hash chain written only by
`eris.writer.RunWriter`: `seq` contiguous from 0, `prev_sha256` = sha256 of the
previous line's bytes, `payload_sha256` = sha256 of the canonical payload.
Blobs are content-addressed under `blobs/sha256/` and are redacted BEFORE
hashing. `manifest.json` is written last. `validate_events` verifies a chain
from bytes alone.
