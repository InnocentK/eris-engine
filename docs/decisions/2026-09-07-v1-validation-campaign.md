# v1: validation campaign for the new key epoch

Date: 2026-09-07 · Campaign id: `v1` · Status: PLANNED - this document is the
runbook; results will be recorded separately when it has run.

**Not Phase 0 evidence.** Same standing caveats as every B-phase record: no
containment, plan/control categories only, nothing here may be quoted against
the build rule. This campaign exists to validate the instrument changes since
b-s3b before anything heavier relies on them.

## What it validates, specifically

1. **The concept-group keys** (E1/E2/E5 fix): do correctly-phrased findings
   on `plan-migration` / `plan-rollout` get credited under the new
   `must_mention` groups, live rather than in fixtures?
2. **`plan-restore-drill`**, the first ACCEPT-expected plan task, live for
   the first time. The pre-registered tripwire from
   [`2026-09-07-accept-plan-task.md`](2026-09-07-accept-plan-task.md): if any
   judged arm REVISEs it, human-adjudicate the stated reason - a real defect
   means the document is at fault; no real defect means `wrong_reject` and
   the rule's bound are doing their job. That adjudication, either way, is
   the trigger decision for the second clean plan.
3. **The amended rule's inputs**: `wrong_reject_rate` is now computable over
   THREE ACCEPT-expected tasks (two controls + the new plan), and the
   arm-4-vs-arm-3 bound can be read against real cells for the first time.
4. **The scorer fixes under load**: population blocking, per-arm
   `pooled_comparison` markers, verdict-cell denominators, the matrix's
   skipped-vs-missing accounting, and the DECISION_RULE note in
   `pre_registration_notes` - all appear in a real summary.
5. **M1-1** (open question): `summary.per_arm[*].validator.codes` from a
   fresh scored campaign.

## Design

* Arms `indep_verify,indep_verify_critique` (3 and 4) - the pair the rule
  compares. Arm 3b is omitted: until a judge requests evidence it reduces to
  arm 3 (b-s3b), and this campaign is not the place to spend on proving that
  again.
* Panel `claude,grok`, judge `judge` - the paired-design panel decided after
  S1 (these two cache cleanly, holding proposals constant across arms;
  `--critics` defaults to the panel).
* 5 tasks x 1 repeat x 2 arms = **10 cells**, confirmed by dry-run before
  this document was committed: 2 cells per task, `plan-restore-drill`
  present, no directory created.

## Cost expectation, honestly bounded

Proposals and adjudications for the four pre-existing tasks may replay from
the B-phase cache (claude and grok replayed cleanly there); every
`plan-restore-drill` call is necessarily fresh. Bounds: **$5-25 expected**;
the hard ceilings are unchanged (`per_call_usd` 4.0, `per_run_usd` 20,
`per_campaign_usd` 200). A budget abort at these caps was last seen at the
old 1.0 worker cap and would itself be a finding.

## Predictions (each falsifiable in the summary)

| # | Prediction |
|---|---|
| V1 | `matrix`: 10 declared, 10 scored, `missing: []`, `unexpected: []`, `skipped_declared: 0` |
| V2 | no `budget_tripped` invocation anywhere in the campaign |
| V3 | `comparison.blocked: false` - both arms score all 5 tasks (an exclusion falsifies this and must be named, not argued around) |
| V4 | every summary's `pre_registration_notes[0]` carries the DECISION_RULE string |
| V5 | `plan-restore-drill` produces a real verdict (not None) in both judged arms |
| V6 | `wrong_reject_rate` is computable (not None) for both arms |
| V7 | at least one `REF_NOT_MECHANICAL` appears in `validator.codes` and NO cell is excluded for it (4 of 6 earlier live judged runs carried one; exclusion was removed 2026-09-04) |

## The runbook (operator: run these in order)

```bash
cd /path/to/eris-engine

# 1. Gate (free; must exit 0)
CAMPAIGN_IDS='v1' SINGLE_RUN_IDS='' bash eval/live_preconditions.sh
echo "gate exit=$?"

# 2. Matrix check (free; expect 10 cells, plan-restore-drill present)
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id v1 \
    --arms indep_verify,indep_verify_critique --repeats 1 \
    --panel claude,grok --dry-run

# 3. Launch (SPENDS MONEY)
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id v1 \
    --arms indep_verify,indep_verify_critique --repeats 1 \
    --panel claude,grok
echo "exit=$?"

# 4. Status + committed cost
.venv/bin/python eval/run.py campaign status --campaign-id v1

# 5. Score (read-only) and keep the summary - OUTSIDE runs/: everything under
#    runs/ belongs to RunWriter (redacted, hashed, append-only), and the gate's
#    collision check treats any entry there as a run id (stop-time review,
#    2026-09-07; the B-phase summaries were relocated for the same reason)
mkdir -p summaries
.venv/bin/python eval/score.py --campaign-dir runs/v1 --corpus eval/corpus \
    > summaries/v1.json
echo "score exit=$?"
```

To halt mid-flight: the gate prints the exact per-campaign STOP command when
it passes - use that one, not the global `runs/STOP`, which stops everything.
To resume after an interrupt: re-run step 3 with the SAME `--arms`,
`--repeats` and `--panel` plus `--resume` (`--arms` defaults to ALL FIVE arms
and `--repeats` to 2 if omitted - omitting them redeclares a different
matrix).

## After it runs

Bring the summary back here: results get their own dated record scoring the
V-predictions, the restore-drill tripwire gets its adjudication, and M1-1
gets its first real data point. The scoring epoch note stands: v1 is the
FIRST campaign scoreable under the revised keys, and no cross-epoch number
may be compared against b-s1/b-s3/b-s3b quality metrics - different keys
measure different things.
