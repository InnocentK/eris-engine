# Live-test plan (Phase B) — what will be run, and what would falsify it

Date: 2026-08-30 · Branch: `fix/corpus-key-leak` · Status: **draft, for panel review (B3)**
· Runs only after the panel has reviewed it

## What this campaign is for

Operability evidence on real multi-cell data, and the first quality signals the
corpus can produce. It is **not** Phase 0 evidence and the report will say so in
its first paragraph: the pre-registered decision rule compares arm 4 with arm 3
on catch rate over `revert`/`planted` tasks, and those categories are gated on a
containment that does not exist (`docs/SECURITY.md`, E1). Only `control` and
`plan` are scorable at all.

## What is being measured

| Question | Where the answer comes from |
|---|---|
| Does `campaign` complete a real multi-cell matrix? | exit code, `campaign status`, `summary.matrix` |
| Does `--resume` restart only unfinished cells? | a deliberate interrupt, then resume; `cell.skipped` events |
| Does budget aggregation behave as the code says? | `cost_spent_usd` vs `cost_attributed_usd`, `unknown_cost_records` |
| Do the new refusals fire on a real run, not just in tests? | any `LaunchRefused` in the ledger; zero expected |
| What is the control false-positive rate? | `per_arm[*].control.fpr` |
| What is the plan catch rate? | `per_arm[*].recall.micro`, **upper bound only** — see EVAL-PLAN |
| Is any comparison blocked, and why? | `summary.comparison.blocked` + `reason` |

## The constraint that shapes everything: what is committed, not what is spent

`codex` and `agy` return `cost_usd=None`, so each of their calls RESERVES
`per_call_usd` ($2). `claude` and `grok` report a cost, charged at its actual
value (`src/eris/retry.py::BudgetLedger.record`). The ceiling trips on
`known + reserved + per_call > ceiling`: a campaign is bounded by what it
COMMITS, and reservations are the part computable in advance.

An earlier draft asserted that EVERY call reserves $2 and put the full matrix at
$480. That was wrong - it ignored that half the panel reports cost - and the
panel caught it. Recomputed from `planned_worker_calls`, `ARM_STEPS` and the
per-worker parsers:

| arms | rpt | cells | reserving calls | reserved | known-cost calls |
|---|---|---|---|---|---|
| `single` | 1 | 16 | 8 | $16 | 8 |
| `single,indep_verify` | 1 | 20 | 16 | $32 | 20 |
| `indep_verify,indep_verify_iter,indep_verify_critique` | 1 | 12 | 32 | $64 | 52 |
| all five | 1 | 32 | 48 | $96 | 72 |
| all five | 2 | 64 | 96 | **$192** | 144 |

The full matrix reserves $192 of a $200 ceiling before one reported cost is
added, leaving $8 for 144 claude/grok calls. Whether it trips depends on figures
nobody can predict in advance, and if it trips it truncates in fixed arm order -
arm 4 first, the arm the experiment exists to judge. **So the full matrix will
not be run.** The runs below leave real headroom on reservations alone.

## Preconditions — none of the runs below may start until these pass

The plan as first written went straight to spending. It named no preflight, no
pin check, no `.env`, and no dry run, while this session's ORIGINAL blocker was
exactly that: `claude` and `agy` auto-updated, their pinned hashes stopped
matching, and every launch refused. A runbook that spends money without
checking its preconditions is not a runbook (stop review, 2026-08-30).

```
bash eval/live_preconditions.sh        # exits non-zero if ANY check fails
```

It is a script, not a list of snippets to eyeball, because the snippets this
plan first carried failed silently: the `.env` check printed nothing when it
failed, the id-collision check reported "ids free" when the runs directory did
not exist, and every command said `python` where this repo needs
`.venv/bin/python`. It checks:

1. **preflight** - the doctor (names, never values).
2. **no CLI worker is UNPINNED.** A stale pin does NOT raise: `load_policy`
   downgrades that worker to `UNPINNED`, and `launch.py` refuses it at spawn -
   mid-campaign, after money has been spent on earlier cells. An earlier version
   of this check compared the hashes in `policies/pins.yaml` against the
   binaries and passed a deliberately corrupted pin, because the loader had
   already discarded the mismatched value.
3. **`.env` carries `XAI_API_KEY`** - without it grok is refused at launch by
   policy, and under the stop conditions below that refusal would be recorded as
   a finding about the engine.
4. **the run ids are free** - `RunExists` refuses a collision (exit 2).
5. **`runs_dir` resolved FROM THE POLICY**, and echoed, because the STOP path
   below depends on it and `--runs-dir` can override it.

Then, costing nothing, confirm the matrix is the intended one - the only step
that catches the `--arms` defaulting trap before it declares 64 cells:

```
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id b-s1 \
    --arms single,indep_verify --repeats 1 --dry-run
```

If the script exits non-zero, fix what it names and run it again. Do not start S0 with a
failing precondition on the theory that one cell is cheap: the point of S0 is to
learn something about the corpus, and a launch refusal teaches nothing about it.

## The runs

**S0 — one cell, live.** Prove the corpus runs at all before spending on a
matrix.

```
python eval/run.py run --task-file eval/corpus/control-clean-io/task.json \
    --arm single --panel claude --run-id b-s0

# what S0 is FOR - read these before spending on a matrix:
#   exit 0 = ok, 6 = CONTAMINATED (stop the whole plan), 3 = incomplete
echo "exit=$?"
python - <<'PY'
import json
from pathlib import Path
ev = [json.loads(l) for l in (Path("runs/b-s0/events.jsonl")).read_bytes().splitlines()]
scan = [e["payload"] for e in ev if e["kind"] == "scan.result"]
print("scan:", scan[-1] if scan else "NO SCAN RESULT - the run did not finish")
print("errors:", [e["payload"] for e in ev if e["kind"] == "run.error"] or "none")
PY
```

A contaminated S0 stops the plan: the worker reached something outside its
snapshot, and no quality number from any later run would mean anything. An
`ok` S0 does NOT prove the reverse - the canary detects a verbatim emission
only - it just means the one thing we can detect did not happen.

**S1 — operability matrix, with the interrupt inside it.** The widest
configuration that leaves real headroom ($32 reserved of $200). The resume test
is not a separate run: a campaign cannot be both completed and interrupted, so
the interrupt happens DURING S1 and the resume finishes it.

```
# start it; send SIGINT (Ctrl-C) once some cells have finished
python eval/run.py campaign --corpus eval/corpus --campaign-id b-s1 \
    --arms single,indep_verify --repeats 1
python eval/run.py campaign status --campaign-id b-s1

# resume: the SAME --arms and --repeats must be given again. `--arms` defaults
# to ALL FIVE and `--repeats` to 2, so omitting them redeclares a 64-cell
# matrix into this campaign. `--resume` is a bare flag and takes no value.
python eval/run.py campaign --corpus eval/corpus --campaign-id b-s1 \
    --arms single,indep_verify --repeats 1 --resume
python eval/run.py campaign status --campaign-id b-s1
python eval/score.py --campaign-dir runs/b-s1 --corpus eval/corpus > runs/b-s1/summary.json
```

**S3 — the judged arms, only if S1 is clean.** A separate campaign so its
ceiling is its own ($64 reserved). `indep_verify` is included as the BASELINE,
so the 3b-3 and 4-3 paired deltas are computed WITHIN one campaign.

```
python eval/run.py campaign --corpus eval/corpus --campaign-id b-s3 \
    --arms indep_verify,indep_verify_iter,indep_verify_critique --repeats 1
python eval/run.py campaign status --campaign-id b-s3
python eval/score.py --campaign-dir runs/b-s3 --corpus eval/corpus > runs/b-s3/summary.json
```

**Cross-campaign comparison is forbidden.** `eval/score.py` takes ONE
`--campaign-dir`, and putting two campaigns' cells in one directory raises
`GateRefused` - each `campaign.started` declares only its own. No per-arm rate
from S1 may be set beside one from S3: different populations, one repeat, and no
shared proposals (cross-campaign cache reuse is off), so any difference is
confounded with proposal variance. Only S3's within-campaign paired deltas are
comparable at all.

## Predictions, each with what would falsify it

Written before the run. A prediction that survives is weak evidence; one that
fails is the point of writing them down.

| # | Prediction | Falsified by |
|---|---|---|
| P1 | S1 completes with `matrix.missing == []` | any missing cell |
| P2 | No cell is excluded as `run_error` | any `run.error` in a ledger |
| P3 | Both controls draw zero false positives: `control.flagged_cells == 0` of 2 | either control flagged. Reported as the raw count, never as a rate: with 2 controls an FPR can only be 0, 0.5 or 1, so "fpr <= 0.5" survived one control being wholly invented |
| P4 | S3's best arm covers >= 3 of the 5 planted findings | fewer. Reported as `covered/5` per arm, never as a rate: there are 5 findings in the whole corpus, so a micro recall is one of {0, .2, .4, .6, .8, 1} and "> 0" survived on a single match |
| P5 | *(deleted)* — `eval/score.py` takes one campaign directory, so "S1+S3 compared together" is not a thing that can be computed. Cross-campaign comparison is forbidden above rather than predicted about |
| P6 | Codex/agy execution records carry `cost_known == false`, grouped by worker | none do — which would contradict the premise of the sizing above. NOT `unknown_cost_records`, which counts records with no cost at all: an executed missing-cost call is recorded at $2 with `cost_known=false` and never reaches that counter, while a cache replay can raise it |
| P7 | No cell is `contaminated` | any hit — the canary or a builtin marker fired, and every quality number is then suspect |
| P8 | `spent_known_usd` (claude+grok, actual) is under $10 across S1+S3 | more. Stated on `spent_known_usd` because ACTUAL total spend is not observable here: a missing-cost call is recorded as a $2 estimate with `cost_known=false` and summed into `cost_spent_usd`, so that field is known-plus-estimate, not spend. Real codex/agy spend is UNKNOWN and no number in this report may claim otherwise |

## Stop conditions — and who enforces them

**The harness does not enforce these.** `cmd_campaign` breaks its loop only on
SIGINT and on a STOP file; a `LaunchRefused` or a contaminated cell sets the
campaign exit code and the loop CONTINUES to the next cell
(`eval/run.py`, the cell loop). So these are operator conditions, and the
operator has to be watching. Each is listed with how it is actually seen:

| Condition | How it is detected | Action |
|---|---|---|
| a cell refuses (`LaunchRefused`) | non-zero campaign exit code; `status` shows the cell `refused` | stop, do not re-run: a gate fired on real data and that is the finding |
| a cell is `contaminated` | exit 6, or `contaminated: true` in the summary | stop; the key may have been read and every quality number is suspect |
| the ceiling trips | a cell `stopped` for budget; `missing_cells` with a `budget` reason | stop; the sizing above was wrong, re-derive before re-running |
| committed cost over $50 | `spent_known_usd + reserved` from `campaign status` | stop |

To halt a campaign mid-flight, write the CAMPAIGN-SCOPED stop file:

```
touch "$RUNS_DIR/$CAMPAIGN_ID/STOP"    # halts THAT campaign only
```

`$RUNS_DIR` is the value the precondition script echoed, not a hardcoded
`runs/` - `--runs-dir` can override the policy. `$CAMPAIGN_ID` is the campaign
actually in flight: an earlier draft showed only the `b-s1` path, which an
operator running S3 could have copied, stopping nothing while S3 kept
spending.

**Not `runs/STOP`.** That path is the global stop file (`arms.stop_file_paths`
returns both) and it halts every run using this runs directory, including
anything else in flight. An earlier draft of this plan named the global one.

## What will be recorded

Per run: campaign id, exit code, `summary.json`, and — because `run.started`
records `eris_version` ("0.4.3"), not a commit —

* `git rev-parse HEAD` of the engine, and `git status --short` to show whether
  the tree was clean;
* the sha256 of every `eval/keys/*.json` and every `task.json` (the ledger binds
  these per cell, but the report should carry them once);
* `policies/pins.yaml` contents — the resolved worker executables and their
  hashes — and the version string each worker CLI reports;
* every prediction marked survived/falsified, with the observation that decided
  it.

## Known limits, stated before the numbers exist

1. **Not Phase 0.** The decision rule cannot be evaluated; no result here may be
   quoted against it.
2. **Plan scoring is an upper bound.** A mechanical match says a finding is in
   the right place and names the right things, not that it is correct. Blind
   human adjudication is the arbiter (EVAL-PLAN).
3. **I authored the keys for a system I built.** The plan pitfalls are drawn
   from defects actually found in this repository, which reduces but does not
   remove the conflict.
4. **The canary detects a verbatim read only.** A worker that reads the key and
   paraphrases it is reported clean. Absence of a hit is not evidence of a clean
   run.
5. **`--repeats 1` is BELOW the pre-registered floor.** `docs/EVAL-PLAN.md`
   says ">= 2 repeats per cell". One repeat gives no variance estimate at all,
   so no difference between arms here can be distinguished from run-to-run
   noise. The floor is broken deliberately to stay under the ceiling, and that
   trade is the reason this campaign cannot answer a quality question.
6. **`wrong_accept_rate` cannot discriminate on this corpus.** It is the
   decision rule's input, and it can only fire where the expected verdict is
   not ACCEPT: 2 of the 4 tasks. Diluted by the two control zeros, the per-arm
   rate can only be 0, 0.25 or 0.5, and "halves the wrong-ACCEPT rate" is 2/4
   versus 1/4 - a single cell. Arm 1 will show a structural 0.0 because it has
   no judge and therefore no verdict to be wrong. The rate will be reported per
   REVISE task with n=2 stated beside it, or not at all. This is the corpus
   constraint recorded in
   `docs/decisions/2026-08-30-confident-wrong-split.md`, arriving exactly where
   that record predicted it would.
7. **Four tasks is a small corpus.** Small snapshots may make every arm
   trivially correct, producing no discrimination. That is a real possible
   outcome and the report will say so rather than dressing it up.

## Panel review (B3) — done, 2026-08-30

Three families, each a different lens, each given this plan and the repository:
**codex** (OpenAI, arithmetic and design), **grok** (xAI, what it could be
misread as proving), **agy** (Google, whether the commands actually work). Every
finding below was reproduced here before the plan was changed.

| # | Family | Finding | Verified | Applied |
|---|---|---|---|---|
| 1 | agy + codex | P5 was unevaluable: `eval/score.py` takes ONE `--campaign-dir`, and merging two campaigns' cells raises `GateRefused` | `eval/score.py:1758`; `_matrix_block` refuses undeclared cells | P5 deleted; cross-campaign comparison forbidden outright |
| 2 | agy | The S2 resume command was literally unrunnable (`--resume ...`), and omitting `--arms`/`--repeats` on a resume redeclares ALL FIVE arms at 2 repeats into the campaign | `--repeats` default 2, `--arms` default None, `--resume` is `store_true` | S2 folded into S1 with the exact flags, and the trap written next to the command |
| 3 | agy + codex | S1 as written could not be both completed and interrupted | reading the sequence | one lifecycle: start, SIGINT, status, resume, score |
| 4 | codex | **The reservation arithmetic was wrong.** Only missing-cost calls reserve; claude and grok report cost and are charged actual. The full matrix reserves $192, not $480 | `retry.py::BudgetLedger.record`; `parse_codex`/`parse_agy` return `cost_usd=None` | table recomputed per worker; the wrong figure is left in the document with its correction |
| 5 | codex + grok | P3/P4 were satisfiable by trivial outcomes: with 2 controls an FPR is one of {0, .5, 1}, and with 5 findings a micro recall is one of {0, .2, .4, .6, .8, 1} | counted the keys | both restated as raw counts with explicit denominators |
| 6 | codex | P6 measured the wrong field: an executed missing-cost call is recorded at $2 with `cost_known=false` and never reaches `unknown_cost_records`, which a cache replay CAN raise | `retry.py`, `ledger.py`, `cache.py` | P6 now reads `cost_known` on execution records, per worker |
| 7 | codex | P8 and the "$50 actual" stop condition are not observable: `cost_spent_usd` is known-plus-estimate, not spend | `ledger.py::cost_totals` | P8 restated on `spent_known_usd`; the stop condition is committed cost |
| 8 | agy | The stop conditions are not enforced by the harness - the campaign loop breaks only on SIGINT and STOP | `eval/run.py` cell loop | rewritten as operator conditions with how each is detected, and `runs/STOP` named as the mechanism |
| 9 | agy | Nothing recorded the engine commit, worker CLI versions, or pins; `run.started` carries `eris_version`, not a sha | `run.started` payload | recording section expanded |
| 10 | grok | `wrong_accept_rate` cannot discriminate here: it fires only on the 2 REVISE tasks and is diluted by the control zeros | expected verdicts in the four keys | Known limits 6 |
| 11 | grok | `--repeats 1` is below EVAL-PLAN's pre-registered floor of 2 | `docs/EVAL-PLAN.md:84` | Known limits 5 |

Not applied, with the reason: none. Every finding above was reproduced and acted
on.

**What the panel did not settle.** grok noted it could not verify whether a live
worker actually walks out of these snapshots, because that needs a real spawn -
which is what S0 is for. If S0 shows contamination, the plan stops there.
