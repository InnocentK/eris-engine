# plan-restore-drill: the first ACCEPT-expected plan task

Date: 2026-09-07 · User decisions: amend the draft rule to bound both verdict
directions; rebalance the plan side now; ONE task with a second on demand;
multi-family cleanliness review; author before the next campaign.

## Why it is load-bearing, not decorative

`wrong_reject` fires only where the key expects ACCEPT. With the old geometry
(controls ACCEPT, plans REVISE) a judge that accepts all code and revises all
plans scored ZERO on BOTH verdict-error metrics, and the rule bound added the
same day would never fire against it - raised by the xai seat in the sizing
consult and verified against `wrong_reject`'s definition before deciding
anything. One ACCEPT-expected plan cell makes that judge visible.

## Sizing: the consult and the decision

Three families asked ONE vs TWO. openai: TWO (n=1 cannot separate judge bias
from a borderline document). google: TWO, with a "sound-but-tempting" twin.
xai: ONE, and a refutation of the tempting twin that survived verification:
an ACCEPT-keyed bait document converts a judge's calibrated caution into
`wrong_reject`, which now feeds the rule's comparative bound - punishing the
more careful arm, the inversion of the bound's purpose. (b-s3b's arm 4
revised BOTH controls, so the existing clean/tempting pair never separated
disposition from document either.)

User decision: ONE boring clean plan now; the SECOND clean plan is authored
only if this one produces the ambiguous result (a judge revises it and no
agreement that the document was at fault). No tempting twin.

## The document and its review

`DRILL.md` (91 lines): a quarterly restore drill for the review archive, in
the corpus's existing fictional world. Round 1 of the cleanliness review
(openai, xai, google - hunt for a defect a fair reviewer would BLOCK on):
one REAL (the goal claimed the drill proves the 4-hour target while the
residual-risk section called drill timing an approximation - internal
tension) and two ARGUABLE (unstated backup-store access boundary; a stale
backup auto-failing the drill conflates a recovery-point breach with a
restore-path failure). All three fixed: the criterion now holds a stated 2x
margin on drill hardware, the access boundary is explicit, freshness and
restore are judged separately.

Round 2 on the revised document: openai CLEAN (verified), xai CLEAN - both
re-probed the round-1 areas. **google unavailable for round 2, stated per
the protocol**: `google/gemini-3.1-pro-preview` and the antigravity route
both 403 (license), `agy` reports individual quota exhausted resetting in
~110h - measured 2026-09-07, so the family returns on or after
**2026-09-12** - and the family that raised two of the round-1 findings could
not confirm their fixes, so the round-2 CLEAN is two-family, best-effort.
FOLLOW-UP: on or after 2026-09-12, run the round-2 cleanliness prompt past a
google-family model and append its verdict here. Its round-1
concerns are the ones the fixes address and the other two seats re-checked.

## Mechanical changes

* `eval/corpus/plan-restore-drill/` + `eval/keys/plan-restore-drill.json`
  (empty findings, `expected_verdict: ["ACCEPT"]`, canary); snapshot built.
* `Key` validator: a plan that plants nothing must expect exactly ACCEPT -
  the mirror of the control-plants-nothing rule, same failure mode (a task
  that measures nothing while looking scored).
* The corpus agreement test is verdict-aware instead of blanket: a
  REVISE-expecting plan with an empty key still fails; at least one plan
  must still plant; at least one ACCEPT-expected plan must now exist.
  Mutation-checked: flipping the new key to REVISE is caught twice (model
  and test); deleting the task trips the floor.
* Scoring epoch note: this key is NEW, so no historical campaign is
  affected; the epoch guard does not fire.

## What the next campaign should watch

If any judged arm REVISEs `plan-restore-drill`, the per-cell record is the
second-plan trigger: human-adjudicate whether the stated reason names a real
defect (then the document, not the judge, is at fault - fix or replace it)
or not (`wrong_reject` and the rule's new bound are doing their job).
