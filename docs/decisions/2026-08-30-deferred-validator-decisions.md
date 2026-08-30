# Deferred: validator findings without verdict powers, and two uninvoked validators

**Decided 2026-08-30 by the user: leave both as they are.** Recorded so the
choice is visible and revisitable, not re-litigated by the next agent.

Both items came out of the multi-family pre-live review
(`2026-08-26-multi-family-prelive-review.md`, finding M1) and survived the M1
fix (v0.4.1/0.4.2) deliberately.

---

## 1. `CLAIM_MISSING` and `DISSENT_EMPTY_WITH_CONTEST` do not change a verdict

### What they detect

| code | meaning |
|---|---|
| `CLAIM_MISSING` | a ruling names a claim no proposer made (`validate.py`, the `claims.get` branch) |
| `DISSENT_EMPTY_WITH_CONTEST` | a live contest exists and `dissent` is empty (`_contest_exists`) |

Both are `severity: "error"`. Both describe an adjudication that contradicts
itself.

### What happens today

* the finding is recorded in `validate.findings` with `acted: false`;
* since M1 the cell is EXCLUDED from quality metrics and from paired deltas
  (`exclusion: validator_errors`) and counted in the per-arm `validator` block;
* **the verdict is untouched** - an operator still reads a clean `REVISE` or
  `ACCEPT`.

### Decision: leave it. No verdict powers.

Reasons, in the order that decided it:

1. It changes **what a verdict means**, which is a protocol decision of the same
   kind as H3 - and H3 was decided explicitly rather than assumed.
2. `CLAIM_MISSING` is usually a sloppy id on an otherwise sound adjudication.
   Escalating on it makes the engine noisy without making it more correct.
3. **`DISSENT_EMPTY_WITH_CONTEST` would fire far too broadly today.**
   `_contest_exists` counts any non-`REFUTED` challenge as a contest, and
   nothing in the engine ever sets a challenge to `REFUTED` or `VERIFIED`
   (see item 2). So essentially every arm-4 cell with a challenge would
   escalate. Fixing the verdict rule before fixing that would be backwards.

### Revisit when — concrete triggers

* **After the first scored campaign**, read
  `summary.per_arm[*].validator.codes`. If `DISSENT_EMPTY_WITH_CONTEST`
  appears on a large share of arm-4 cells, the current M1 exclusion is
  quietly gutting arm 4's denominator, and the question is not "should it
  escalate" but "is `_contest_exists` too broad".
* If `CLAIM_MISSING` turns out to be common in live runs rather than rare.
* If challenge verification is ever built (item 2) - the third reason above
  evaporates and the decision should be taken again on its merits.

---

## 2. Three validators are unreachable at runtime

Corrected 2026-08-30 after the first version of this record got it wrong: the
claim was "`validate_critique` and `validate_origin` are never invoked", which
is false for one of them and omits a third validator entirely. The verification
grep excluded `validate.py` itself - the one file where a caller was.

| validator | runtime callers | callers inside `validate.py` | status |
|---|---|---|---|
| `validate_origin` | 0 | **3** | **IS invoked** - by the two below, which are themselves dead. Transitively unreachable |
| `validate_critique` | 0 | 0 | dead |
| `validate_adjudication` | 0 | 0 | dead |

`validate_events` and `enforce_rulings` ARE live and are not part of this.

### Decision: leave all three unreachable. Do NOT "wire them up".

**`validate_adjudication`** is a findings-only wrapper: it calls
`enforce_rulings` and discards the enforced record. The engine already calls
`enforce_rulings` directly, which both enforces AND returns the findings, so the
wrapper has no caller because it has no purpose. It is also the only path that
would reach `validate_origin`, which is why "invoke `validate_origin`" is not
even the right framing - the question is whether a findings-only variant should
exist at all.

**`validate_origin`** checks that a record's `origin` matches what the record is
(an `EvidenceItem` from a git command must be `mechanically_observed`, and so
on). It is near-redundant: the wire models (`ProposalOut`, `ChallengeOut`, ...)
use `extra="forbid"` and have no `origin` field, so **a model cannot set an
origin**. Eris sets it in its own constructors. The validator therefore guards
Eris against itself - a unit-test concern, not a runtime one.

**`validate_critique`** emits `UNVERIFIED_CHALLENGE` for a challenge that has
not been verified. `ChallengeStatus` is written in exactly ONE place
(`stages.py`, at challenge construction) and only ever to `UNVERIFIED`; nothing
sets `VERIFIED` or `REFUTED`. So invoking it today would emit a warning for
**every challenge ever created**, permanently, and its other branch (a
`VERIFIED` challenge citing no evidence) is unreachable.

That is not a wiring gap. It is the same hole as **M2** in the pre-live review:
`VerificationResult` - the record that would carry "this challenge was checked
against evidence" - has no producer anywhere in `src/` or `eval/`. Challenge
verification is not built.

### Revisit when — concrete triggers

* **When challenge verification (M2) is built.** At that point
  `validate_critique` becomes meaningful and should be invoked in the same
  change; `UNVERIFIED_CHALLENGE` stops being universal and starts carrying
  information.
* If a wire model ever gains an `origin` field - i.e. if a model becomes able
  to assert its own origin - `validate_origin` stops being redundant and MUST
  be reachable from a live path on model-derived records.
* If anything ever needs findings WITHOUT enforcement, `validate_adjudication`
  is the function to reach for; today nothing does.

---

## Status

Neither item is a defect to be fixed on a schedule. Both are decisions with a
stated reason and a stated trigger. An agent that finds `UNHANDLED_CODES`, the
uninvoked validators, or these two finding codes should read this file before
proposing a change to them.
