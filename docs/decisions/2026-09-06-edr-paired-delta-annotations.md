# EDR: paired-delta annotations and the cost basis

Date: 2026-09-06 · Contract §11 record.

**Decision.** A paired row whose treatment attempted no calls of its own is
ANNOTATED (`treatment_executed_no_calls`, reading ATTEMPTED spawns), never
dropped - refusing it is post-treatment selection that keeps exactly the
subset most likely to show an effect. `delta_cost_spent_is_order_dependent`
marks every row where a replay makes the spent delta an artifact of campaign
order; `delta_cost_attributed_usd` is the comparable figure and its VALUE is
now test-pinned. Unshared proposals (C1) and mixed validator bases (M1) still
REFUSE pairs: those are confounds, upstream of the treatment.

**Evidence.** b-s3b: arm 3b replayed everything (the judge made zero evidence
requests, so `adjudicate_iter` correctly broke on the first pass - the earlier
diagnosis blaming the cache key is DISPROVED and recorded); its spent deltas
read -$1.02..-$1.56 in favour of an arm that made no calls, while attributed
read 0.0. The §9.9 panel (B1) showed the guarding test pinned only the KEY's
presence - aliasing attributed to spent passed - and the raiser verified the
fixture's spent (-0.02) and attributed (+0.01) differ by construction before
accepting the fix.

**Results.** Named tests PASS including failed-calls-not-a-no-op and the B1
value pin; every mutation executed and caught. CI 1258 PASS at `0aee4ea`.

**Review.** §9.9 AvA~ panel + final reviewer
([`2026-09-06-diff-panel-adjudication.md`](2026-09-06-diff-panel-adjudication.md)).
B1 confirmed by all reviewers; counter round ACCEPT.

**Risks.** Annotations can be ignored; zero-by-construction rows sit in means
as measurements (documented INVARIANTS row). The 3b-3 comparison remains
undefined until a judge actually iterates.

**Rollback.** Revert; summaries regenerate deterministically.

**Recommendation: SHIP.**
