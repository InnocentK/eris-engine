# Eris protocol (Phase 0 harness)

This document states the protocol the Phase 0 harness is built to evaluate and
the rules the code already enforces. Nothing here is an orchestrator: the
stages are wired by `eval/run.py` (Milestone 2b) for the pre-registered
experiment only; the engine is built only if Phase 0 clears its rule.

## The question Eris answers

"Is this proposed answer, plan, patch, or action defensible given competing
proposals, adversarial criticism, and available evidence?"

Athena and Hermes decide what work to pursue. Eris decides whether a proposed
answer or action is defensible.

## Pipeline (hypothesis under test)

1. **Independent proposals** - each declared worker runs in a fresh process,
   read-only, in a history-truncated snapshot, with a byte-identical prompt.
   Workers never see each other. *(`eval/run.py run --arm …`, M2b.)*
2. **One critique round** - critics see proposals, never each other, with a
   mandatory `framing` lens ("assume the leading proposal is wrong"). Exactly
   one round; no rebuttal chat. *(M2b: `indep_verify_critique` only.)*
3. **Mechanical verification** - Eris executes only allowlisted commands
   (`src/eris/verify.py`) inside the snapshot. Model-proposed commands are
   requests and are refused unless allowlisted. *(Grammar: M1; stage wiring
   `eris.evidence`, M2b.)*
4. **Evidence-bound adjudication** - a model answers; the ENGINE then applies
   the rules in `src/eris/validate.py` to its answer. *(Validator: M1; stage
   wiring `eris.stages.run_adjudicate`, M2b.)*
5. **Human gate** - any action leaving the sandbox requires an `Approval`
   record bound to the sha256 of the adjudication it approves. *(Schema only.)*

Two separate limits: critique ROUNDS (one) and evidence ITERATIONS (re-verify
while allowlisted evidence requests remain; no model prose is regenerated).

## Stage contracts (Milestone 2b, `src/eris/stages.py`)

Every worker call is built from a FROZEN prompt file
(`eval/prompts/{proposer,critic,adjudicator,summarizer}.md`, ROLE + RULES;
sha256 recorded in `run.started.prompt_files`) plus two sections Eris
appends:

* **DATA** - ONE canonical-JSON document `{"evidence": [...], "proposals":
  [...], "challenges": [...]}` between the delimiters `-----BEGIN ERIS DATA
  <nonce>-----` / `-----END ERIS DATA <nonce>-----`, where
  `nonce = sha256("eris-envelope"|snapshot_sha|task_id|repeat_index|stage|
  policy_sha256)[:32]`. Repository text appears only inside JSON strings. An
  occurrence of the nonce inside the data becomes `[NONCE]` and is recorded
  as `envelope.nonce_collision`. A prompt over 256 KiB is refused (never
  spilled to a file).
* **OUTPUT SCHEMA** - the wire model's JSON Schema with `$defs` inlined,
  `additionalProperties: false` and every key required.

**Wire models** (`ProposalOut`, `CritiqueOut`, `AdjudicationOut`;
`extra="forbid"`, NO defaults, strict JSON validation) are the ONLY way
model output enters Eris. A model-supplied
id, `origin`, `schema_version` or engine field is `malformed_output`: the
call is retried with the IDENTICAL prompt in a fresh process (cap 2), then
recorded as `worker.absent`; a semantic violation (unknown label, claim
index out of range, invalid ref) is treated the same way. Every record a
later stage consumes is re-parsed from the redacted payload the writer
persisted. `Record.model_validate(model_json)` is never
called. Eris assigns every id: claims `clm-<propose_key[:12]>-<i>`, findings
`fnd-…`, proposals `prop-…`, challenges `<critique_key[:12]>-p<k>-c<n>`,
dissent `dis-…`.

**Evidence pack** (`eris.evidence`): built once per (task, repeat) from the
ORIGINAL snapshot before any proposal - the question (`document_quote`,
`human_entered`), the plan text and/or `git show` diff, repo facts (`git
rev-parse HEAD`, `status --porcelain`, `ls-files`, `log --oneline -n 20`),
the task battery and confined file excerpts. Every byte passes
`RunWriter.put_blob` before it is hashed; item ids are content-derived
(`ev-<sha[:16]>`), so the pack - and the proposer call key - is identical
across arms. The rendered pack carries no timestamp or run id.

**Proposers** see the pack only. **Critics** see the pack + proposals
`P1..Pn` and never each other (all critic prompts share one hash); every
critic carries the `framing` lens. **Adjudicator / summarizer** (the
dedicated `judge` worker: text only, `tools: []`, timeout 300 s, a TIMEOUT is
terminal; cwd and workspace = an EMPTY private dir per call, never the
snapshot) see
evidence blocks (16 KiB head+tail cap), `P1..Pn` (label → worker in
`proposal.labels`), `C1..` (arm 4 only) and verification items -
never raw repository files, rationale blobs, another stage's instruction
text or a host absolute path (executables are rendered by basename). After
the judge: `adjudication.raw` → `enforce_rulings` → `adjudication.enforced`
→ `validate.findings`.

**Evidence requests** come only from structured output. Each is re-checked
by `check_command` inside `run_allowlisted` in a private VERIFICATION copy
of the original snapshot (a command that changes the copy is
`snapshot.violated` and stops verification);
refusals are `verify.refused` events (the challenge stays UNVERIFIED);
duplicates by canonical argv are `verify.duplicate`; `verify.max_requests_per_run`
(12) and `verify.max_wall_s` cap a run; STOP is checked before every command.

**Arms** (`eris.arms`, fixed order): `single` (pack, propose one worker),
`consensus` (+ summarize), `indep_verify` (+ verify + adjudicate),
`indep_verify_iter` (adjudicate iterates ≤ 3 times over the judge's own
requests; no new proposals or critiques), `indep_verify_critique` (+ critique
+ verify + adjudicate). Arms 3/3b/4 (and `single`) share the propose call
(paired ablation); `ArmRun.propose_keys` records it and the scorer pairs only
identical key sets. Retries, budgets, STOP, resume, the contamination scan,
the cache and the scorer are specified in `docs/SECURITY.md` and
`docs/EVAL-PLAN.md`; every rule has a test in `docs/INVARIANTS.md`.

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
  cites no evidence, or when any cited evidence is missing, is **not
  `mechanically_observed`**, or (for `phase=verification` evidence only) was
  created before the claim's current revision. Evidence-pack items legitimately
  predate every proposal and are never "stale".
  Since 0.4.0 the origin rule is `mechanically_observed` ONLY, not merely "not
  `model_asserted`": the pack carries the task question and any plan text as
  `human_entered` `document_quote`s, so the weaker rule let a claim be
  SUPPORTED by the question that asked about it (`REF_NOT_MECHANICAL`).
* Three or more cumulative downgrades force the verdict to `ESCALATE`.
* **The verdict itself must rest on evidence, and must resolve the claims.**
  An `ACCEPT` is forced to `ESCALATE` unless BOTH hold:
  1. at least one ruling **survives enforcement as `SUPPORTED` or `REFUTED` AND
     names a claim that exists** (`VERDICT_UNSUPPORTED`, 0.4.0); and
  2. **every claim carries a ruling and none is `CONTESTED`**
     (`VERDICT_UNRESOLVED_CLAIMS`, 0.4.0). `claims` is every claim from every
     proposal, so a claim with no ruling was never adjudicated - silently
     ignoring "there is a null deref at line 42" and answering ACCEPT is the
     failure this engine exists to prevent. `CONTESTED` is an open dispute, not
     a resolution; `UNSUPPORTED` IS one ("that claim was not backed") and does
     not block ACCEPT.

  For (1), each half is load-bearing:
  - `REFUTED` counts because if every adverse claim is mechanically refuted the
    proposed answer IS defensible; demanding `SUPPORTED` would escalate a
    legitimate ACCEPT.
  - the claim must exist because a ruling naming a claim nobody made is flagged
    `CLAIM_MISSING` but deliberately NOT downgraded (its refs were fine), so
    otherwise a judge could satisfy this whole rule by inventing a claim id and
    citing real evidence at it.

  Before 0.4.0, `{"verdict": "ACCEPT", "rulings": []}` was recorded verbatim,
  and a judge that self-declared every ruling `UNSUPPORTED` also reached
  ACCEPT - a self-declared `UNSUPPORTED` is not a *downgrade*, so the
  escalation guard never armed. The downgrade rule is applied FIRST, so when
  both apply the record keeps its `ESCALATED` finding.
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
model, the pinned executable's sha256, stage, task id, prompt sha256, schema
sha256, repeat index and policy sha256. It deliberately EXCLUDES the experimental arm so arms 3/3b/4 share
proposals (paired ablation) and INCLUDES `repeat_index` so repeats are
distinct. Every retry attempt is its own `Invocation` (`inv-<key[:16]>-a<n>`),
`CostRecord` and `RetryAttempt`; failed attempts' cost counts; a cache hit
re-appends the origin `Invocation` with `reused_from` and a
`CostRecord(counted=False)`.

## The ledger

`runs/<run_id>/events.jsonl` is an append-only hash chain written only by
`eris.writer.RunWriter`: `seq` contiguous from 0, `prev_sha256` = sha256 of the
previous line's bytes, `payload_sha256` = sha256 of the canonical payload.
Blobs are content-addressed under `blobs/sha256/` and are redacted BEFORE
hashing. `manifest.json` is written last. `validate_events` verifies a chain
from bytes alone.
