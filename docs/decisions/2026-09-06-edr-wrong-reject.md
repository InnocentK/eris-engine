# EDR: `wrong_reject` beside `wrong_accept`

Date: 2026-09-06 · Contract §11 record.

**Decision.** Count a REVISE/ESCALATE/REJECT verdict against a key expecting
ACCEPT as `wrong_reject`, per cell and as a per-arm rate over cells WITH a
verdict (None when none has one). The pre-registered decision rule still reads
`wrong_accept_rate` alone; whether it should also read `wrong_reject_rate` is
the user's decision and is NOT made here.

**Scope.** `eval/score.py`, tests, record amendments. Not the rule text.

**Evidence.** S1-D predicted the blind spot in prose. Measured: b-s1
`indep_verify` 0.5 (the two control cells S1-D named); b-s3
`indep_verify_critique` 1.0 with `wrong_accept_rate` 0.0 - the best figure on
the pre-registered metric, produced by a judge that rejected everything; b-s3b
arm 4 at 0.0/0.5 against arms 3 and 3b at 0.5/0.0 - the same fact from two
sides. The §9.9 panel (A3 + a round-2 addition) forced the verdict-cell
denominator: sixteen verdictless single-arm cells had read 0.0,
indistinguishable from a judge that never erred; they now read None.

**Results.** `test_an_arm_that_never_accepts_is_caught_by_wrong_reject`,
forced-ESCALATE, correct-REVISE and verdictless-None tests PASS, each with an
executed mutation that fails it. CI 1258 PASS at `0aee4ea`.

**Review.** §9.9 AvA~ panel + final reviewer as above (composition, dissent,
deviations: [`2026-09-06-diff-panel-adjudication.md`](2026-09-06-diff-panel-adjudication.md)).
Panel finding E4, held open deliberately: the corpus is 2 ACCEPT + 2 REVISE,
so a constant-REVISE judge still perfects the metric the rule reads -
`wrong_reject` mitigates only if read.

**Risks.** E4 above (tracked for the next corpus revision). Rates over few
verdict cells are noisy; `verdict_cells` is reported beside them.

**Rollback.** Revert; the field is additive, no consumer depends on it.

**Recommendation: SHIP**, with the open question - should the build rule read
`wrong_reject_rate` too? - explicitly left for the user.
