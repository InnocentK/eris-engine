# Plan: make a live SCORED campaign possible (Option 2, prep phase)

## The blocker, established not assumed
`eval/corpus/` holds one entry, `plumbing-control`, `scored: false`.
`campaign --corpus eval/corpus --dry-run` -> `{"error": "no task.json found"}`.
`discover_tasks` filters on the scored flag, so a campaign sees ZERO tasks.

## What is scorable at all today
Measured, not recalled (`eval/score.py::GATED_CATEGORIES`):

| category | gated on containment? |
|---|---|
| `revert`, `planted`, `insufficient` | YES - and `containment: container` is REFUSED at policy load (H2), so these can NEVER be scored today |
| `control`, `plan` | no |

## What each scorable category can actually measure

This decided the shape of the plan. From `Matching.precision/recall`:

* a **control** task has `findings: []`, so `tp+fn == 0` and **recall is
  `None`** - it contributes NOTHING to catch rate. If an arm invents a finding,
  `precision` becomes 0.0. So a control measures FALSE-POSITIVE discipline,
  `confident_wrong`, abstention, cost and wall-clock - and cannot measure catch
  rate at all.
* a **plan** task has real key findings, so it measures BOTH precision and
  recall.

**Therefore a corpus of controls alone would produce a campaign whose headline
metric is undefined.** Plan tasks carry the only catch-rate signal available
before containment exists.

## What I propose to author

Four tasks, enough for a real multi-cell campaign without pretending to be the
~27-task Phase 0 corpus:

| task | category | purpose |
|---|---|---|
| `control-clean-io` | control | a small module with no defect; measures invented findings |
| `control-guarded` | control | correct code that LOOKS risky (bounds already checked); measures false positives under temptation |
| `plan-migration` | plan | a migration plan with 3 known pitfalls in `key.findings` |
| `plan-rollout` | plan | a rollout plan with 2 known pitfalls and 2 `distractors` |

Each is `task.json` + `files/` + a GENERATED `snapshot/`
(`eval/make_control_snapshot.py --all`). The answer key is **NOT** in the task
directory: it goes in `eval/keys/<task_id>.json`, outside the corpus, because a
worker's cwd is `<task>/snapshot` and E1 proved claude/codex/grok read the
snapshot's parent. `load_task` refuses to run a task with any `key.json` under
it and `load_key` refuses to score one, so authoring it in place fails closed
rather than silently leaking. Each key needs a per-task `ERIS-KEY-CANARY-*`
token in `scan.extra_strings`, and a scored run is refused unless that token
survives into the scan pattern set.

## What this can and cannot conclude

CAN: that `campaign`, `--resume`, budget aggregation, `campaign status` and
`eval/score.py`'s campaign path work on real multi-cell data; per-arm cost and
wall-clock; false-positive rate on controls; catch rate on plan tasks; whether
`summary.comparison.blocked` fires.

CANNOT: the pre-registered Phase 0 decision (arm 4 beats arm 3 by >= 10 points
catch rate). That needs the defect categories, which are gated. **This campaign
must not be reported as a Phase 0 result**, and the report will say so.

## The validity problem I want the panel to attack

**I am authoring the answer key for a system I built.** For `control` tasks the
risk is low - "there is nothing to find" is not a judgement call. For `plan`
tasks it is real: I choose which pitfalls count, so I am defining correctness
for the thing I wrote, and I could unconsciously choose pitfalls that favour the
arms with more machinery (3b/4). Mitigations I am considering:
1. derive plan pitfalls from THIS repo's own decision records - defects that
   were actually found by review here, not invented by me now;
2. write `key.findings` BEFORE looking at any model output, and never adjust the
   key after seeing a run (record the key's git sha in the report);
3. state in the EDR that the key is author-generated and therefore weaker
   evidence than a corpus drawn from external history.

## Risks
* **E1 contamination**: workers read outside the snapshot; `plan`/`control` are
  scored anyway by prior user decision, and `eris.scan` marks contamination.
  Any contaminated cell is excluded and reported.
* **Cost**: 4 tasks x 5 arms x 2 repeats = 40 cells. At ~4 worker calls per
  judged cell this is materially more than the single-cell runs so far. I will
  propose a repeat count and a budget ceiling in the live-test plan, not here.
* the four tasks are small; small snapshots may make every arm trivially
  correct, producing no discrimination. That is a real possible outcome and the
  report will say so rather than dressing it up.

## Questions for the panel
1. Is the control/plan split right, given controls cannot measure recall?
2. Is mitigation 1 (pitfalls from this repo's own decision records) genuinely
   better than inventing them, or does it just move the conflict?
3. What would make this campaign's result WORTHLESS that I have not listed?
4. Should `insufficient` be attempted? It is gated - but is there a way to get
   an abstention signal without it?
