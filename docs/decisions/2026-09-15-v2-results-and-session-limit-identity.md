# v2 results, and the session-limit identity fix

Date: 2026-09-15 · Status: v2 SCORED (frozen); classifier fix implemented,
pending independent review (kanban t_b4c81cba) · Campaign artifacts:
`runs/v2/` and `summaries/v2.json`
(sha256 `69412d2b38c25425229ec7399a7a97d6f954c2766d0cd0dfba59266033cbfca4`),
both IMMUTABLE - this record changes no run, no summary, no key, no metric,
no prediction.

v2 ran 2026-09-15 at exact revision `acbdfce225ecdf19f887bf8968144b5da1de5520`
(branch `fix/corpus-key-leak`, clean tree), per the pre-registered runbook in
[`2026-09-13-v2-campaign.md`](2026-09-13-v2-campaign.md). Gate exit 0; dry-run
matrix 10/10 with `plan-restore-drill` present; campaign finalized;
committed cost $10.673464; independent score regeneration reproduced
`summaries/v2.json` byte-identically (audit t_d2d45570).

## W1-W5, scored against the pre-registration

| # | Prediction (abbreviated) | Outcome |
|---|---|---|
| W1 | matrix 10/10, nothing missing/unexpected, `comparison.blocked: false` | **Falsified as a conjunction.** `matrix`: declared 10, scored 10, missing `[]`, unexpected `[]` - that half held. `comparison.blocked` is `true`: common support covers 3 of 5 (task, repeat) cells (`plan-restore-drill#0`, `plan-rollout#0` outside it), so the pooled rates are over the surviving subset and the decision rule may not be applied |
| W2 | any vendor ceiling classifies POLICY_TERMINAL, not "unknown: unclassified failure" | **Falsified.** The ceiling fired 8 times (every firing in the four incomplete cells) and every one classified `unknown: unclassified failure: You've hit your session limit · resets 3:10am (America/New_York)`. Root cause below |
| W3 | the flip test: drill ACCEPT closes the tripwire; REVISE/ESCALATE fires the second-plan trigger | **Indeterminate - trigger not reached.** Both drill cells lost their judge to the misclassified ceiling; no verdict exists in either arm, so the flip test measured nothing |
| W4 | arm 4's plan-rollout verdict (v1's hole) is recovered; the 4-3 pair computes on all five tasks | **Falsified.** plan-rollout produced no verdict in EITHER arm (v1 lost one); the pair computes on 3 of 5 tasks |
| W5 | old-task proposals replay from cache; cost between v1's $15.25 and roughly half of it | **Falsified as a conjunction.** Cost held: $10.673464 sits inside ($7.63, $15.25). Replay-from-v1 did not happen: `indep_verify` cells show `replayed_invocations: 0` everywhere - the claude and grok re-pins between v1 and v2 (2026-09-13/-14) changed `executable_sha256`, which is PART of the idempotency key since M2b, so no v1 entry could hit BY DESIGN. The critique arm's replays (2,2,2,2,1) are within-v2 arm-sharing, not the predicted cross-campaign reuse. The prediction failed to account for a mechanism this repository built deliberately |

Four predictions in five failed wholly or as conjunctions. That is the
pre-registration working as intended: the misses are recorded, not
renegotiated. The dominant cause is ONE defect, below. No W-interpretation,
key, metric or prediction is edited by this record.

## The defect: worker identity guessed from argv[0]

`eris.retry.classify` scopes `hit your session limit` to cli `claude`
(added from the v1 capture, commit 4b91cb2). Identity came from `_cli_of`:
the error's `claude:` prefix when the parser set one, else argv[0]'s
basename. Both fallbacks failed live in v2:

- the claude 2.1.272 re-pin (d0b6c2f) resolves to the VERSIONED executable
  `~/.local/share/claude/versions/2.1.272` - `preflight_executable`
  deliberately hashes and executes the realpath - so the basename is
  `2.1.272`, not `claude`;
- the session-limit envelope's `result` is verbatim vendor text
  ("You've hit your session limit · resets …"), and
  `_claude_error_message` returns `result` verbatim when present, so there
  is no `claude:` prefix.

The claude-scoped pattern never fired; the ceiling fell through to UNKNOWN
("unclassified failure"), and 4 of 10 cells (both drill cells, both rollout
cells) were lost unnamed. The existing fixture harness masked this: its fake
executable is a file literally named `claude` (`tests/test_launch.py
make_policy`), so argv[0]'s basename accidentally supplied the identity that
the live path does not.

Note the class boundary: UNKNOWN and POLICY_TERMINAL are both terminal, so
no retry behaviour differed and no money was misspent - the defect is that a
KNOWN, named ceiling was recorded as an unclassified failure, which broke
W2 verbatim and denied the W3/W4 cells an honest cause of death.

## The fix (contained; one writer; this worktree)

Selected design: **canonical configured identity carried on the result.**
`WorkerResult` gains `cli: str | None` - the configured `policy.cli` that
selected the parser producing the result - stamped at both construction
sites in `eris.launch` (`run_worker`, `_absent`). `_cli_of` returns it
first; the error-prefix and basename fallbacks survive only for results
that predate the field (hand-built fixtures; cache replays are status OK
and never reach the pattern table, and `CacheHit.result` leaves the field
None). The pattern table itself is UNCHANGED - no regex loosened, no scope
dropped.

Rejected alternatives:

- *Match the versioned basename* (`2.1.272`, or a `claude/versions/*` path
  regex): brittle against every future re-pin and against vendors whose
  install layout differs per OS; portability is a requirement.
- *Widen the pattern to `cli=None`*: destroys pattern isolation - the whole
  point of CLI scoping is that one vendor's error text never classifies
  another's failure.
- *Prefix every parser error with the cli name*: rewrites recorded error
  text (the ledger keeps verbatim vendor messages today) and still leaves
  argv-based guessing in place for unprefixed shapes.

Regression coverage
(`test_retry.py::test_versioned_executable_no_prefix_error_classifies_by_policy_cli`):
reproduces the live shape end-to-end through `run_worker` - versioned
executable basename `2.1.272`, the captured 2.1.252 session-limit envelope,
no `claude:` prefix - for BOTH the worker `claude` (propose) and the
configured `judge` (adjudicate) using the same binary, asserting
POLICY_TERMINAL and terminal. Isolation is asserted both ways: the same
error text on a grok-configured worker stays UNKNOWN whatever its argv
basename says, including a basename that lies by being literally `claude`.
Verified failing at base `acbdfce` with exactly the live misclassification
(`ErrorClass.UNKNOWN`, "unclassified failure: You've hit your session
limit …") before the fix was applied, and passing after.

Commands actually run (this workspace, 2026-09-15):

- `.venv/bin/python -m pytest tests/test_retry.py -q` -> 34 passed
- base-revision check (fix stashed): the new test FAILED with
  `ErrorClass.UNKNOWN` on the claude propose path; fix restored: passed
- `.venv/bin/python -m pytest tests/test_launch.py tests/test_cache.py
  tests/test_stages.py -q` -> 200 passed
- `task ci` -> lint, mypy strict, coverage (1266 passed, 95.55% ≥ 90%
  floor), pip-audit clean; exit 0
- `shasum -a 256 summaries/v2.json` unchanged before and after:
  `69412d2b…3cbfca4`; `git status` clean outside the five changed files

## Unresolved risks and rollback

- The wire schema is untouched (`Invocation` records argv as before;
  `WorkerResult` is in-process, not a ledger record). No golden changed.
- Cache replays carry `cli=None`; if a cached result ever reaches the
  pattern table (today impossible: replays are status OK), identity falls
  back to the old guessing. Accepted and documented in the field's comment.
- The fix is unverified LIVE. Whether a real 2.1.272 ceiling classifies
  POLICY_TERMINAL end-to-end is exactly what the authorized replacement
  campaign (kanban t_8f1e823c) must demonstrate if the ceiling fires; the
  hermetic regression is the strongest pre-live evidence available.
- Standing dissents (OpenAI model-identity; user-ratified unmonitorable
  residual) are unaffected and not relitigated.
- Rollback: revert the single fix commit (`git revert <sha>`); no data,
  schema or policy migration in either direction.

Recommendation: REVISE -> independent review (t_b4c81cba, different
reviewer), then the human-authorized replacement campaign. 0.5.0
preparation stays blocked until W3/W4 are measured and live W2 behaviour is
verified, per the v2 audit.
