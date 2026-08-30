# `confident_wrong` is split; the decision rule reads the mechanical half

Date: 2026-08-30 · Branch: `fix/corpus-key-leak` · Decided by: the user
· Raised by: Codex (OpenAI) in the Phase A multi-family panel, finding 3 of 5
· Status: **settled**, listed in `AGENTS.md` standing decisions

## What was wrong

`eval/score.py` computed one flag:

```python
confident_wrong = exclusion is None and (
    (verdict is Verdict.ACCEPT and Verdict.ACCEPT not in key.expected_verdict)
    or any(s in ("high", "critical") for s in matching.fp_severities)
)
```

Two unlike things in one number:

* the engine returned **ACCEPT** where the key's `expected_verdict` says it must
  not — a mechanical comparison against the key;
* a false positive carried **`high` or `critical`** — the model's own severity
  label, written by the model, on the model's own claim.

There is no confidence field anywhere in `src/eris/schemas.py` (verified by
grep, 2026-08-30). Severity is the only thing in the neighbourhood, and it is a
self-report.

## Why it mattered

`docs/EVAL-PLAN.md` pre-registers the build/don't-build rule:

> build the orchestrator only if arm 4 beats arm 3 by >= 10 points catch rate or
> **halves confident-wrong** at <= 2x cost, AND arm 3 beats the incumbents.

So one of the **two branches that authorise building the orchestrator** could be
satisfied by an arm grading its own claims more mildly: the same findings, the
same misses, `critical` written as `low`. A tone change, buying a build
decision. That is the single most consequential decision this experiment exists
to make.

Codex's finding was verified before being acted on: an unmatched `critical`
prediction sets the flag, the identical prediction labelled `low` does not.

## Options considered

| # | Option | Why not |
|---|---|---|
| 1 | Leave as is, keep the caveat in the output | The caveat is real and was already published, but a documented gameable branch is still a gameable branch |
| 2 | Rename to `severe_false_positive_or_wrong_accept_rate` | Honest labelling, no change to the arithmetic — the branch stays gameable |
| 3 | **Split; the rule reads the mechanical half** | **Chosen** |
| 4 | Decide after the corpus exists | Deciding a metric definition after seeing which arm it favours is what pre-registration exists to prevent |

## The decision

Split into two fields, two per-arm rates and two paired deltas:

* **`wrong_accept`** — the verdict against the key's `expected_verdict`.
  Mechanical. Nothing a model writes about itself can move it.
* **`severe_false_positive`** — a `high`/`critical` false positive. The model's
  own label on its own claim.

`docs/EVAL-PLAN.md`'s rule now reads **`wrong_accept_rate`**.
`severe_false_positive_rate` is reported beside it and is **an input to no
rule**. No `confident_wrong_rate` survives anywhere, so no reader can quote "the
confident-wrong rate" and mean either one.

## What is enforced, and how

`docs/INVARIANTS.md` (Scorer) names three tests. The one that matters goes
through the **real scoring path**:

`test_score.py::test_a_severe_false_positive_alone_is_not_a_wrong_accept` runs a
campaign whose single-arm proposal reports a `high` finding matching nothing in
the key, with no verdict at all: `severe_false_positive: true`,
`wrong_accept: false`. Re-merging the severity clause into `wrong_accept` makes
it fail.

The first version of that test built a `CellScore` by hand. The mutation run
showed it did not constrain `score_cell` at all — the severity clause could be
put back and the test still passed. Recorded here because the lesson is the
general one: a test over a constructed value does not test the code that
constructs it.

## Known consequence, load-bearing on corpus design

`wrong_accept` is **narrower** than the flag it replaces. Arm 1 (`single`) has
no judge, so it has no verdict and can never be `wrong_accept`. That is correct
— there is no ACCEPT to be wrong about — but it means the metric discriminates
only among the judged arms (2, 3, 3b, 4).

The pre-registered rule compares arm 4 against arm 3, so that is exactly where
it is needed. But it constrains Phase B: **the corpus must contain enough tasks
whose correct verdict is not ACCEPT for this metric to have anything to
measure.** A corpus of clean controls and plan reviews would leave
`wrong_accept_rate` near zero for every arm and the branch unable to
discriminate.

## Revisit when

* a confidence signal is added to the wire schema (then a real confident-wrong
  metric becomes possible, and this split can be reconsidered on its merits); or
* a scored campaign shows `wrong_accept` is too sparse to discriminate arms —
  in which case the answer is more ACCEPT-negative corpus tasks before it is a
  change to the metric.

Do not reopen this to "simplify by re-merging the fields". The merge is the
defect.
