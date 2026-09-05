# Deferred: validator findings without verdict powers, and two uninvoked validators

**Decided 2026-08-30 by the user: leave both as they are.** Recorded so the
choice is visible and revisitable, not re-litigated by the next agent.

> **PARTLY SUPERSEDED, 2026-09-04.** The decision below - that these findings
> get NO VERDICT POWERS - still stands. What changed is the separate M1
> behaviour it describes under "What happens today": a validator error no
> longer EXCLUDES the cell from quality metrics or from paired deltas. It is
> reported instead. See
> [`2026-09-04-validator-errors-stop-excluding-cells.md`](2026-09-04-validator-errors-stop-excluding-cells.md).
>
> Two of this document's stated premises did not survive the campaigns. Reason
> 3 below says `DISSENT_EMPTY_WITH_CONTEST` "would fire far too broadly today"
> and that "essentially every arm-4 cell with a challenge would escalate": it
> has fired ONCE in 32 cells, on an ARM 3 cell, through the CONTESTED-ruling
> branch rather than the challenge branch the reason blames. And the revisit
> trigger below - watch `summary.per_arm[*].validator.codes` after the first
> scored campaign - fired on a DIFFERENT code, `REF_NOT_MECHANICAL`, which this
> document never covered.

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

## 2. Five functions in `eris.validate` are unreachable at runtime

This section was wrong TWICE before it was right, which is why it is now
computed rather than asserted:

* v1: "`validate_critique` and `validate_origin` are never invoked" - false;
  `validate_origin` has three callers. The verification grep excluded
  `validate.py` itself, the one file where a caller was.
* v2: "three validators are unreachable" with a caller table - still incomplete;
  it counted only direct callers, so it missed `_record_id` and `has_errors`,
  and its test would have passed if a LIVE function started calling a dead one.

**Reachability is TRANSITIVE from the real entry points** - what `src/` and
`eval/` actually use. Computed:

| | functions |
|---|---|
| entry points | `enforce_rulings`, `validate_events` |
| reachable | those two plus `_adjudication_shape_findings`, `_check_refs`, `_contest_exists`, `_err` |
| **unreachable** | `validate_adjudication`, `validate_critique`, `validate_origin`, `_record_id`, `has_errors` |

### What the check actually proves

A static reachability claim is only as good as its assumptions, so the gate
CHECKS them and fails if any stops holding, rather than relying on them
silently:

1. every definition is a module-level `def` - an `async def` or a class method
   would be invisible to the scan and its reachability never examined;
2. everything that RUNS at import is a caller, which is more than bare
   module-level statements: a decorator, a default argument value, a class base
   expression and every statement in a class body all execute at import. An
   earlier version skipped `FunctionDef`/`ClassDef` wholesale and so missed all
   four - a dead function referenced in any of them would have run at import
   while the gate still called it unreachable;
3. the module is never bound as an object (`import eris.validate`,
   `from eris import validate`, `importlib`) - that binding is what would make
   `getattr(mod, <computed>)` possible and defeat the analysis. A `getattr`
   with a matching string literal is counted as a use.

4. `from __future__ import annotations` is present, so annotations are strings
   and do NOT evaluate at import. Without it every annotation becomes an
   import-time reference this scan does not follow.

Each is mutation-verified, including all five import-time forms (class body,
class decorator, class base, module-level default argument, and a method
default - the last correctly trips assumption 1 instead, because a method is
outside the model and the gate refuses to claim rather than guess). Tests are
excluded from the entry points deliberately: they are not a runtime path.

`has_errors(findings) -> bool` is the error-severity predicate; `eval/score.py`
reimplements it inline as `f.get("severity") == "error"` because it reads
findings from a ledger payload, not from `Finding` objects. `_record_id` is a
private helper used only by `validate_origin`.

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
