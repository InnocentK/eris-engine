# EDR: validator errors stop excluding cells

Date: 2026-09-06 · Contract §11 record for the change decided 2026-09-04,
hardened by the 2026-09-06 §9.9 review.

**Decision.** A validator FINDING no longer excludes a cell from quality
metrics or paired deltas; it is REPORTED - `validator.malformed_rate` (over
assessed cells), `validator_codes` per cell, and inside the comparison block.
An ABSENT record (`validator_unknown`) still excludes. Rationale: the trigger
was `Finding.acted == False` - the engine DECLINING to act - so the exclusion
gave a finding power exactly where the recorded protocol decision denies it
any; and whether a judge emits a malformed adjudication is an OUTCOME of the
arm under test, so dropping those cells scored each arm on a cleaner subsample
of its own work.

**Scope.** `eval/score.py` exclusion paths, comparison-block reasons,
`M1_PRE_REGISTRATION` (synced verbatim to EVAL-PLAN, test-enforced),
INVARIANTS rows (including repairing the row that still asserted the exclusion
- found by the §9.9 panel), amendments to the three results records.
Deliberately unchanged: validator findings still have NO verdict powers
(2026-08-30 decision); `validator_unknown` still excludes; ledger-invalid
cells still block the matrix.

**Evidence.** Measured on b-s3b: the one excluded cell was arm 4's REVISE on
an ACCEPT-expected control - the exclusion was deleting evidence AGAINST the
arm it excluded for; restoring it moved arm 4 `wrong_reject_rate` 0.333 -> 0.5
and turned `comparison.blocked` false with common support 4/4. Exclusions were
rare and asymmetric: 2 cells in 44 across b-s1/b-s3/b-s3b (this figure was
misstated as "of 32" and corrected - §9.9 finding C3).

**Results.** `test_cells_are_scored_with_verdict_basis_costs_and_paired_deltas`
PASS, and re-adding the exclusion fails it (mutation executed). Post-change
rates re-derived from unchanged ledgers; full CI 1258 PASS / coverage 95.55% /
audit clean at `0aee4ea`.

**Review.** Decision panel 2026-09-04: three families (claude, grok, gemini),
three rounds, unanimous after a verified-facts round - "two independent, one
persuaded by evidence" (recorded in
[`2026-09-04-validator-errors-stop-excluding-cells.md`](2026-09-04-validator-errors-stop-excluding-cells.md)).
Implementation then faced the §9.9 AvA~ diff panel (five lenses, three
families, implementer excluded - full composition, dissent and deviations in
[`2026-09-06-diff-panel-adjudication.md`](2026-09-06-diff-panel-adjudication.md)),
which returned REVISE 5/5 and hardened this change with A1-A4 (population
blocking, in-block markers, verdict-cell and assessed-cell denominators), all
fixed and mutation-checked. Final reviewer openai/gpt-5.4: REVISE then SHIP
after fixes. Standing dissent: one reviewer holds per-arm rates should be
WITHHELD when blocked; adjudicated against and recorded in code.

**Risks.** Malformed cells now sit in denominators by design; the mitigation
is reporting, and a reader who quotes a rate past the `pooled_comparison`
marker defeats it. Residual: no automated consumer of the decision rule exists
yet, so enforcement is textual.

**Rollback.** Revert the score.py hunks; summaries regenerate byte-identically
from unchanged ledgers (determinism verified). No run data is touched.

**Recommendation: SHIP** (as part of this branch; both mandated reviews
complete, final disposition SHIP).
