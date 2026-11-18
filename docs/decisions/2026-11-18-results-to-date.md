# Results to date: no answer yet, and what the harness found about itself

Date: 2026-11-18 · Status: SUMMARY of existing records. This record changes no
run, summary, key, metric, prediction, or decision rule, and adds no new
measurement. Every number below is copied from the dated record it links to;
where this summary and a dated record disagree, the dated record governs.

## The short version

Eris exists to test one question: does *independent proposals → adversarial
critique → mechanical verification → evidence-bound adjudication* beat a
single strong model and naive multi-model consensus?

**That question is not answered.** The draft build rule in
[`../EVAL-PLAN.md`](../EVAL-PLAN.md) has not cleared, and no campaign so far is
Phase 0 evidence. What exists is the six pilot and validation campaigns listed below, on
a subset of four or five tasks, run to find out whether the harness measures what it claims
to. It mostly did not at first, and the campaigns show how that was found and
fixed.

## What was run

All campaigns used `control` and `plan` tasks only. Containment is still null
(E1 in [`../SECURITY.md`](../SECURITY.md)), so `revert`, `planted` and
`insufficient` tasks cannot be scored, and those are the categories the build
rule is written over.

| Campaign | Date | Cells | Known cost | Record |
|---|---|---|---|---|
| `b-s1` | 2026-08-31 | 20 of 20 complete | not fully observable | [`2026-08-31-s1-results.md`](2026-08-31-s1-results.md) |
| `b-s3` | 2026-08-31 | ran, not comparable | see record | [`2026-08-31-s3-results.md`](2026-08-31-s3-results.md) |
| `b-s3b` | 2026-08-31 | 12 of 12 complete | $12.69 | [`2026-08-31-s3b-results.md`](2026-08-31-s3b-results.md) |
| `v1` | 2026-09-07 | 10 declared, 9 complete | $15.25 | [`2026-09-07-v1-results.md`](2026-09-07-v1-results.md) |
| `v2` | 2026-09-15 | 10 scored, 6 operationally complete | $10.67 | [`2026-09-15-v2-results-and-session-limit-identity.md`](2026-09-15-v2-results-and-session-limit-identity.md) |
| `v3` | 2026-09-15 | 10 of 10 complete | $17.36 | [`2026-09-15-v3-results-and-0.5-cache-epoch.md`](2026-09-15-v3-results-and-0.5-cache-epoch.md) |

Arm 3 is independent proposals with mechanical verification and a judge, with
no critique. Arm 4 is arm 3 plus one critique round. The two are meant to be a
paired ablation over byte-identical proposals.

## What the measurements say so far

These are descriptive readings over four or five tasks. None supports a claim
about which arm is better.

- **The judged arm is wrong in both directions.** In `b-s1`, arm 3 had a
  wrong-accept rate of 0.25 and a wrong-reject rate of 0.5 over its four
  verdict cells.
- **The critique round has so far made the reviewer reject more, not judge
  better.** In `b-s3b`, arm 4 returned REVISE on every cell, including both
  clean controls. In `v1`, over cells with a verdict, arm 3 read wrong-accept
  0.4 and wrong-reject 0.2; arm 4 read wrong-accept 0.0 and wrong-reject
  0.75, and accepted nothing. In `v3`, the clean
  `plan-restore-drill` task was ACCEPT in arm 3 and REVISE in arm 4.
- **Recall is high and precision is low.** In `v1`, arm 3 covered every
  planted finding on both defect plans; arm 4 covered one of two on
  `plan-migration`. Plan precision stayed near 0.1: the reviewers flag almost
  everything.
- **No paired arm effect can be read.** In `v3` the byte-paired support for
  arm 4 against arm 3 was 0 of 5, so the comparison is descriptive only.

## What the harness found about itself

These are the durable results of the work so far. Each was caught by a
pre-registered prediction failing or by a campaign reading that did not add
up, and each has a dated record.

1. **A metric that rewards refusing everything.** Wrong-accept rate alone made
   an arm that never accepts look perfect. `wrong_reject_rate` was added, the
   rates are now computed only over cells that carry a verdict, and the draft
   build rule gained a comparative wrong-reject bound on 2026-09-07.
2. **Answer keys that punished correct paraphrases.** Single-token keys scored
   provably correct findings as misses. Concept-group keys replaced them and
   were validated on live output in `v1`.
3. **A task that could not be answered from its own evidence.** In `v1` both
   arms escalated an ACCEPT-expected plan because everything it relied on lay
   outside the snapshot. The fault was the task's evidence packaging; the
   evidence was added.
4. **Worker identity guessed from the executable's name.** A vendor session
   limit was recorded as an unclassified failure because the pinned executable
   resolved to a versioned path. `v2` lost four of ten cells to it. The
   configured identity is now carried on the result.
5. **A cache pointer namespace that broke pairing.** One global write-once
   pointer per key meant `v3`'s sibling arms could not share proposals, which
   is why paired support was 0 of 5. Pointers are campaign-scoped from 0.5.0.

Pre-registration did its job. In `v1`, five of seven predictions survived. In
`v2`, four of five were falsified wholly or as conjunctions. In `v3`, one was
confirmed, one was not triggered, one split, and two were falsified. The
misses are recorded as misses.

## What this does and does not support

- It does **not** support "adversarial multi-model review beats a single
  strong model". It does not support the opposite either.
- It does **not** support a comparison with the incumbents. The single-model
  arms in `b-s1` are unjudged and produce no verdict rates.
- It **does** support a narrower claim: on this harness, an honest comparison
  needed two error directions, verdict-only denominators, evidence-complete
  tasks, explicit worker identity and campaign-scoped pairing, and none of
  those was right on the first attempt.

## What is still open

- Containment (E1), without which the task categories the build rule is
  written over cannot be scored.
- The corpus: five scored tasks are a validation subset, not the planned
  Phase 0 corpus.
- A campaign on 0.5.0 that actually produces paired arm-4 against arm-3 cells.
- Live classification of a vendor session ceiling on the current pin, which
  `v3` did not trigger.
- The standing dissents recorded in the `v3` record.
