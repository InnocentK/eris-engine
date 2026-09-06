# §9.9 diff panel: five lenses, unanimous REVISE, twenty-four findings adjudicated

Date: 2026-09-06 · Subject: the full branch diff `main...fix/corpus-key-leak`
(55 files, ~8.1k insertions) · Format: **AvA~** (round 1 → cross-critique →
per-finding rebuttal → raiser counter → adjudication) · Disposition: **REVISE,
5 of 5 reviewers**, executed the same day - every adjudicated fix below is in
the diff the final reviewer sees.

## Panel

The implementer (an anthropic model) is excluded from the panel per §9.9.
Three families covered five lenses; §8 caps a family at two lenses when fewer
than four are available, and the shortfall is stated: openai and xai hold two
each, google one.

| lens | subject | family / model | via |
|---|---|---|---|
| A | scorer statistics | openai / codex CLI | `codex exec` |
| B | tests as proof | xai / grok-4.6 | `opencode run` |
| C | claims vs code | google / gemini-3.1-pro | `opencode run` |
| D | engine + gate safety | openai / gpt-5 | `opencode run` |
| E | corpus + answer keys | xai / grok-4.5 | `opencode run` |

**Deviations, stated:** (1) The round-1 briefing omitted two elements §8
mandates in every reviewer prompt - the blunt-not-deferential framing and
explicit authority to recommend REVISE / HUMAN REVIEW REQUIRED. Caught by
re-reading §8 mid-flight; both were in the round-2 briefing, which every
reviewer passed through before any disposition was recorded. (2) gemini's
round-2 first attempt died on a denied shell execution and returned nothing;
retried with explicit read-only constraints and completed. (3) Several of
gemini's round-2 "VERIFIED" labels were doc-reading only - its C1 "destructive
overwrites" is disproved by `RunWriter.open`, and its C2 self-confirmation
never touched a ledger. Weighted accordingly; in the counter round it conceded
all three of its own findings cleanly, including C2 against the ledger.
(4) One reviewer left five untracked scratch files in the repository root -
two of them scripts that would MUTATE `eval/score.py` in place - despite a
read-only instruction. Verified before deleting them that no tracked file
carried either mutation (grep for both target strings, plus the two tests that
would fail under them, all clean); the files were removed. Reviewer sandboxes
are not enforcement: the harness relies on instructions plus after-the-fact
verification, and this is the first observed breach.

## What survived, in one table

21 round-1 findings + 3 round-2 additions. 20 confirmed against the artifact
(every mutation-shaped claim RUN, not read), 1 refuted, 3 adjudicated as
judgment calls. Fixes landed the same day unless marked.

| id | outcome | one line |
|---|---|---|
| A1 high | fixed | symmetric exclusions left `blocked: False` while pooled rates described the survivor subset; blocked now fires when common support falls short of the scored population |
| A2 med | fixed, dissent kept | the block is stamped inside every per-arm block (`pooled_comparison`); codex maintains rates should be WITHHELD - adjudicated against, no per-arm field is itself a comparison |
| A3 med (+R2) | fixed | verdict-error rates over cells WITH a verdict, None otherwise; b-s1's sixteen verdictless single cells had read 0.0, a judge that never erred |
| A4 med | fixed | `malformed_rate` over assessed cells; 1 malformed + 9 unknown had read 0.1, all-unknown a reassuring 0.0 |
| B1 high | fixed | the paired-delta test pinned only the KEY's presence; now the value, from cells whose spent and attributed figures differ by construction |
| B2 low | fixed | the named test's fixtures both carried `wrong_accept=True`, so the OR-merge it exists to catch passed it (a sibling caught it at suite level); the distinguishing cell is now in the named test |
| B3 med | fixed | the stale-snapshot refusal was tested only through `load_task`; `_build_call` (the `invoke` spend path) now has its own refusal test - deleting the check broke nothing before it |
| B4 med | fixed | `committed_is_complete`'s unreadable-branch assert was pre-satisfied by leftover state; the scenario now proves recovery first |
| B5 low | fixed | the corpus inventory test checked one filename at the task root; it now calls `find_leaked_keys` itself |
| C1 med (regraded) | fixed | the runbook gated `$SLUG` and ran `$SLUG-001`; one `RUN_ID` now. No overwrite was ever possible (`RunExists`), which is why high was wrong |
| C2 med | **refuted** | the cost note's 46 = 27 claude/judge + 19 grok is reproduced from the ledgers by three independent counts; the "56" summed results-doc prose that counts replays. Raiser conceded |
| C3 low | corrected | "2 exclusions out of 32" mixed populations; 2 of 44, correction note on the 2026-09-04 record |
| D1 low (regraded) | fixed | empty `USED` made the WARN grep implementation-defined - BSD grep false-FAILs, ugrep silently fail-opens; skipped outright now |
| D2 low | fixed | ids regex-escaped and anchored `[.:]` - covers dotted ids, `worker.<id>.<subfield>:` lines, and the raiser's trailing-non-word-char counter, all verified |
| D3 low | fixed | the renderer called every `document_quote` "question"; a plan adds a second. Counts by kind now, honestly labelled |
| D4 low (regraded) | fixed | `XAI_API_KEY=` (empty) passed the name-only grep; `=..*` now. Launch keeps empties and checks names only, so this line was the last honest guard |
| E1/E2/E5 high | fixed | `must_mention` single tokens scored correct paraphrases as misses (verified with the live matcher, with matching-wording controls); entries are now concept groups - bare string, or any-of synonyms. Twelve paraphrase cases pinned in tests |
| E3 high | fixed | m2 keyed a true workspace fact as a planted defect; the raiser, asked to name a migration step it predicts will fail, conceded there is none. Dropped - and NOT made a distractor, which would punish quoting a true statement |
| E4 med | tracked, not fixed here | 2 ACCEPT + 2 REVISE keys let a constant-REVISE judge perfect `wrong_accept`; standing geometry, already tested and recorded. Corpus rebalance goes to the next corpus revision. Whether the pre-registered rule should also read `wrong_reject` is the user's call, flagged in the EDR |
| E6 med | fixed | r2 stays keyed - the raiser's counter stands (the plan names config lint as its only preflight, no deliberately-not-doing frame) - with tokens tightened so bare "lint"+"config" no longer scores |
| R2 gpt-5 | folded into A3 | `wrong_reject` had the same verdictless-zero |
| R2 codex ×2 | fixed / noted | gate temp files now `mktemp` under a private dir (fixed names were shared and raceable); `USED` = declared CLI workers, not the spawned subset - equal today, commented in the gate |
| R2 grok-4.6 | fixed | `docs/INVARIANTS.md` asserted the validator-error EXCLUSION in one row and its removal in another, same do-not-break table, and a test named `..._excludes_the_cell...` now tests counting. Row superseded in place, test renamed |

## The one refusal worth recording

Re-scoring the historical campaigns under the revised keys was REFUSED by the
scorer itself: it verifies the key hash recorded at run time and exits 7 -
"an edit between running and scoring silently rewrites what the run is
measured against." That guard predates this panel and fired correctly at the
first attempt. So: **a key revision is a scoring-epoch boundary.** b-s1 / b-s3
/ b-s3b remain scored under the pre-revision keys (with the A-fixes applied -
regenerated before the keys changed); their `runs/*-summary.json` say what the
old keys measured, and no number in any results record moves because of
E1/E2/E5. The revised keys apply to campaigns that have not run yet.

## Standing environment fact surfaced by the gate

While verifying the gate fixes, the gate itself FAILED its preflight and pin
checks: the `agy` binary on this machine has drifted from its pin since
2026-08-31. That is the gate doing its job. Re-pinning
(`eris policy pin`) authorises the new binary and is a deliberate human act -
not performed here.

## The §9.9 final independent review

**openai/gpt-5.4**, a fresh invocation holding no panel seat, family distinct
from the implementer. Inputs: the branch diff at `08a5920`, repo read access,
the CI evidence (1257 passed / 95.54% / audit clean), this record, acceptance
criteria, risks and rollback.

**First pass: REVISE**, three findings, none raised by the panel - all three
survived my verification and were fixed in `0aee4ea`:
1. (medium) a declared `scored: false` plumbing cell was simultaneously
   `skipped` and `missing`, blocking a valid mixed campaign - reproduced by the
   reviewer end-to-end;
2. (medium) the gate's `XAI_API_KEY` grep refused `.env` syntax the runtime's
   `parse_dotenv` accepts (export keyword, quotes) - the gate now calls the
   runtime's own parser;
3. (low) two INVARIANTS rows lagged the code (pairing evidence is kept-blob
   equality; the scorer's allowed roots are three).

**Second pass, same seat, fresh invocation: SHIP** - per-fix VERIFIED,
including a deliberate hostile check that the skipped-vs-invalid asymmetry in
fix 1 is correct (an invalid ledger keeps blocking; it is a real hole).

One wart the reviewer examined and tolerated as an internal name mismatch was
fixed after the disposition, at the trivial rung (§6): `matrix.scored` had
come to include skipped-but-declared cells; it now counts only scored cells,
with `skipped_declared` reported beside it, pinned by the mixed-campaign test.
A field named "scored" that counts unscored cells is the shape of lie this
branch exists to remove; the change is one field and one test and is stated
here rather than re-convening a panel for it.

## Stop-time review: two regressions introduced by the fixes themselves

A stop-time reviewer (openai, via the session's stop gate) found two defects
that did not exist before this review's own fixes - the failure mode every
fix invites, and worth naming as such:

1. The mixed-campaign matrix fix let declared skipped cells satisfy `missing`
   but left `unexpected` reading scored directories only, so an UNDECLARED
   plumbing directory vanished from matrix accounting - counted for nothing,
   refused by nothing. Both populations now face the same gate, and the rogue
   directory raises `GateRefused` (end-to-end test; revert caught).
2. The `must_mention` group schema admitted an empty group, which `any([])`
   makes unmatchable - a correct, precisely-located prediction scored as an FP
   and an FN at once. Its mirror, an empty string, always matches. Both refuse
   at key load now (revert of each branch caught).

## Where the raw record lives

Round-by-round outputs, prompts, rebuttals, counters and the adjudication
ledger are session artifacts (not committed): the durable substance is this
record, the fixes, and their named tests. Every "verified" above means a
command was run and its output read - by me, not taken from a reviewer's word,
per the standing directive that evidence outranks agreement.
