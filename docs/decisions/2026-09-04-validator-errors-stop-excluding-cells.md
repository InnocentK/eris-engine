# A validator error stops excluding a cell

Date: 2026-09-04 · Decided by: the user
· Recommended by: a three-family panel (codex/OpenAI, grok/xAI, agy/Google),
unanimous after two members changed position
· Supersedes part of [`2026-08-30-deferred-validator-decisions.md`](2026-08-30-deferred-validator-decisions.md)
· Status: **settled and implemented**

## What changed

A cell whose final adjudication carries an error-severity validator finding the
engine did not act on is no longer excluded from quality metrics, and no longer
refuses a paired delta. The finding is reported instead - per arm as
`validator.malformed_rate`, per cell as `validator_codes`.

`validator_unknown` is untouched. An ABSENT validator record is not an arm
outcome; nothing has been shown to be clean.

## Why the old rule was wrong, in two ways

**1. It inverted the decision it was built beside.** The exclusion triggers on
`Finding.acted == False` - the engine DECLINING to change anything. The
2026-08-30 decision was that these findings get NO verdict powers. So the rule
gave a finding the power to delete a whole cell in exactly the case where the
protocol denied it the power to alter one verdict. grok put it best: "Exclusion,
if it exists at all, must be a declared code set, not the negation of `acted`."

**2. It was post-treatment selection.** Whether an arm's judge emits a malformed
adjudication is an OUTCOME of that arm. Excluding on it drops the arm's own
failures and measures it on a cleaner subsample than its comparator. All three
panel members reached this independently in round 1, having been given the
hypothesis WITH its counter-argument and told not to simply agree.

The counter-argument - that a self-contradicting record is a confound, so the
delta would measure malformation rather than treatment - is what the previous
rule asserted. It does not hold: a confound is upstream of assignment; this is
downstream of it. The distinction is exactly the one that separates this from
the C1 guard (arms did not share proposals) which legitimately still refuses.

## What the evidence showed

Replaying b-s3b with the exclusion disabled, measured rather than argued:

| | exclusion ON | exclusion OFF |
|---|---|---|
| `comparison.blocked` | True | **False** |
| common support | 3 cells | **4 cells** |
| arm 4 `wrong_reject_rate` | 0.333 | **0.5** |
| arm 4 `wrong_accept_rate` | 0.0 | 0.0 |

**The excluded cell was itself one of arm 4's failures** - REVISE on an
ACCEPT-expected control. The exclusion hid a failure of the arm under test and
flattered it. That is the bias, with its direction measured.

Note what did NOT move: `wrong_accept_rate`, the pre-registered decision input.
Do not read that as reassurance. Arm 4 never accepts, so `wrong_accept_rate` is
blind to this failure BY CONSTRUCTION - which is why `wrong_reject_rate` exists.
An unblocked comparison is not a licence to apply the build rule: 4 cells, 1
repeat.

## What was NOT changed, and why

**The primary estimand stays the pre-registered keyed outcome.** agy proposed
promoting a composite (valid adjudication AND correct verdict) to primary;
codex and grok both argued that swapping the estimand after two blocked
campaigns is itself the post-hoc change, and agy conceded. The composite may be
reported as a companion and can become primary only in a prospectively amended
experiment.

**`DISSENT_EMPTY_WITH_CONTEST` and `REF_NOT_MECHANICAL` keep no verdict powers.**
The 2026-08-30 decision on that stands untouched.

**`_contest_exists` is not narrowed.** Option C would not have prevented the one
observed case: b-s3's finding came from the CONTESTED-ruling branch, not the
"any non-REFUTED challenge" branch the deferral blames.

## Three stale statements corrected

1. `M1_PRE_REGISTRATION` - published in every summary and required verbatim in
   `docs/EVAL-PLAN.md` - asserted "only arm 4 passes critiques to the validator
   and so only it can emit `DISSENT_EMPTY_WITH_CONTEST`". FALSE: the only
   occurrence in this repository is on an arm 3 cell.
2. `validate.py` predicted the code "would fire on nearly every arm-4 cell
   today". Observed: once in 32 cells, on zero arm-4 cells.
3. `_validator_errors`' docstring said only `UNHANDLED_CODES` count and named
   REF_NOT_MECHANICAL as one that must never exclude. That described the LEGACY
   fallback; any unacted error excluded, whatever its code.

## One finding retracted

I reported a fourth defect: that `DISSENT_EMPTY_WITH_CONTEST` is "verdict-blind
while its sibling check is verdict-aware", firing on an already-escalated
adjudication. On inspection that is not a defect. The two checks differ because
their RULES differ - `RESIDUAL_RISKS_EMPTY_ON_ACCEPT` is by definition about
ACCEPT and must read the verdict; a contest with no dissent is a property of the
record's shape and holds whatever the verdict. Recorded rather than dropped,
because it was reported to the decision-maker before it was checked.

## How much to trust the panel

Round 1 was independent: 2 for B, 1 for E. Rounds 2 and 3 included a
verified-facts block from the reconciler which resolved several of the members'
open questions in B's favour, and the third member then moved. So this is "two
independent, one persuaded by evidence", not three witnesses. The strongest
argument is structural rather than statistical and does not depend on n: only
2 cells have ever been excluded, out of 32.

grok's round-3 caution is worth keeping: an unblocked pooled comparison is not
the same as a usable one, and `common_support: 4` is the pooled set - a paired
delta is a different question.
