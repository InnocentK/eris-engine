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

1. **preflight, parsed - not just its exit code.** `preflight` EXITS 0 while
   reporting problems: a missing env-file and a grok worker with no
   `XAI_API_KEY` come back as `WARN` with status 0. Checking the exit code alone
   passed a doctor that was saying the run would fail. The gate fails on any
   `FAIL`/`ERROR`, and on a `WARN` for any worker THIS run spawns - scoped that
   way because `openai-api` has no key configured and warns every time, and
   failing on a worker that is never called trains an operator to ignore the
   gate.
2. **every CLI worker passes the LAUNCH-TIME pin check.** The gate calls
   `launch.preflight_executable` itself, once per CLI worker: resolve the pinned
   path, hash the realpath, compare with the pin. That is the code that refuses
   a cell at spawn - mid-campaign, after money has been spent on earlier cells -
   so calling it is the only way to know in advance. Two earlier versions of
   this check were wrong in opposite directions, and the second was wrong on
   this machine while claiming to be right: it asserted that a stale pin makes
   `load_policy` downgrade the worker to `UNPINNED` and tested only for that.
   It does not. `policy._merge_pins` copies `pins.yaml`'s `sha256` verbatim into
   `executable_sha256` and nothing hashes the binary at load time, so a stale
   pin loads as `pinned=True`. On 2026-08-31 that check printed **PASS - no CLI
   worker is UNPINNED** while `claude`, `judge` and `grok` had all auto-updated
   out from under their pins and would each have been refused at spawn; five
   deliberately corrupted pins also loaded as `pinned=True`. Only `preflight`
   (check 1) caught it, and a gate whose checks disagree is a gate with one
   check.
3. **`.env` carries `XAI_API_KEY`** - without it grok is refused at launch by
   policy, and under the stop conditions below that refusal would be recorded as
   a finding about the engine.
4. **the run ids are free** - `RunExists` refuses a collision (exit 2).
5. **`runs_dir` resolved FROM THE POLICY**, and echoed, because the STOP path
   below depends on it and `--runs-dir` can override it.
6. **every corpus snapshot is built and matches its `files/`.** Snapshots are
   generated and gitignored, so a clean checkout has NONE and every run refuses
   with "snapshot ... is not a directory" - after the campaign has started.
   Build them first:
   `.venv/bin/python eval/make_control_snapshot.py eval/corpus --all`

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
.venv/bin/python eval/run.py run --task-file eval/corpus/control-clean-io/task.json \
    --arm single --panel claude --run-id b-s0

# what S0 is FOR - read these before spending on a matrix:
#   exit 0 = ok, 6 = CONTAMINATED (stop the whole plan), 3 = incomplete
echo "exit=$?"
.venv/bin/python - <<'PY'
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
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id b-s1 \
    --arms single,indep_verify --repeats 1
.venv/bin/python eval/run.py campaign status --campaign-id b-s1

# resume: the SAME --arms and --repeats must be given again. `--arms` defaults
# to ALL FIVE and `--repeats` to 2, so omitting them redeclares a 64-cell
# matrix into this campaign. `--resume` is a bare flag and takes no value.
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id b-s1 \
    --arms single,indep_verify --repeats 1 --resume
.venv/bin/python eval/run.py campaign status --campaign-id b-s1
.venv/bin/python eval/score.py --campaign-dir runs/b-s1 --corpus eval/corpus > runs/b-s1/summary.json
```

**S3 — the judged arms, on a claude+grok panel.** Decided by the user
2026-08-31, after S1; supersedes the four-family panel this section first
carried. A separate campaign so its ceiling is its own.

S3 exists to compute the 3b-3 and 4-3 **paired** deltas within one campaign, and
S1 showed that pairing was broken for half the panel: `cache.refused: entry has
no model_executed` means codex and agy re-execute in every cell, so their
proposals differ between arms. An arm delta would then carry codex/agy proposal
variance, which 4 tasks at 1 repeat cannot separate from the arm. claude and
grok cache cleanly - reused in all four S1 `indep_verify` cells - so a panel of
those two holds the proposals CONSTANT across the three arms, which is what a
paired design requires.

Two consequences worth stating rather than discovering later:

* **Every COMPLETED call reports its cost - and the interrupt is the
  exception, deliberately.** Neither missing-cost worker is on the panel, so no
  finished call is booked as a $2 placeholder. But this section also instructs
  the operator to SIGINT the campaign, and a killed call never returns a cost,
  so `BudgetLedger` books `per_call_usd` for it with `cost_known: false` -
  whatever worker it was. Verified on `runs/b-s0`: the interrupted invocation is
  **claude**, `status: failed`, `error: "interrupted"`, `cost_known: false`,
  `$2.00`.

  So S3 should carry **exactly one** unobservable call, plus one more for each
  timeout retry (S1 had one, on agy). An earlier draft of this section claimed
  "every dollar becomes observable" and told the operator to interrupt the run
  four paragraphs later; the two were written in the same edit and neither was
  read against the other, which is the defect class this document keeps
  recording.

  `spent_known_usd` is unaffected either way - it sums only `cost_known: true`
  records, so P8 does read what it claims - but it is NOT the whole cost while
  an interrupt is folded in, and the report must not present it as such. The
  interrupted invocation is identifiable by `error: "interrupted"`, so it can be
  named and excluded rather than quietly averaged in.
* **This is not a retreat from multi-family review.** The panel is two families
  for a MEASUREMENT whose subject is the arm, not the panel. Eris's standing
  rule - never review with one family, never let a family review itself - is
  about producing a review. Holding the proposal fixed is how you measure what
  the adjudication step adds. A four-family panel is what the engine runs in
  use; it is the wrong instrument for this particular difference.

`--critics` defaults to the panel (`eval/run.py:895`, verified by parsing the
argv), so `--panel claude,grok` carries the critics with it and
`indep_verify_critique` will not reach for codex or agy.

**The interrupt lives here now.** S1 ran to completion before one was sent, so
live campaign resume is still untested (S0 covered run-level resume; cell
skipping is covered hermetically only). Interrupt S3 once a few cells have
finished and resume it - the same lifecycle S1 was supposed to exercise.

```
# start it; send SIGINT (Ctrl-C) ONCE after a few cell.finished events
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id b-s3 \
    --arms indep_verify,indep_verify_iter,indep_verify_critique --repeats 1 \
    --panel claude,grok
.venv/bin/python eval/run.py campaign status --campaign-id b-s3

# resume: SAME --arms, --repeats and --panel again. `--resume` takes no value.
.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id b-s3 \
    --arms indep_verify,indep_verify_iter,indep_verify_critique --repeats 1 \
    --panel claude,grok --resume
.venv/bin/python eval/run.py campaign status --campaign-id b-s3
.venv/bin/python eval/score.py --campaign-dir runs/b-s3 --corpus eval/corpus \
    > /tmp/b-s3-summary.json
```

`score.py` prints its REFUSAL to stdout as well, so it writes to `/tmp` and the
exit code is checked before the file is treated as results.

**Sized from S1's measurements, not from the per-call table.** 12 cells, panel
of 2. Cached after the first arm per task, so the executed calls per task are 2
proposals, 2 critique calls and up to 5 judge calls (1 + up to `MAX_ITERATIONS`
+ 1). At S1's observed rates - claude propose $0.56, grok propose $0.077, judge
$0.80 - that is about **$5.3 per task, ~$21 for S3** of real spend, plus the
**$2 placeholder the deliberate interrupt books** (and $2 more per timeout
retry). Committed lands near $23 - read it as `cost.committed_usd` from `campaign
status` - well under the $50 stop condition. The `$50` committed-cost stop condition therefore stands unchanged
and is no longer in contradiction with the sizing.

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
| P6 | Codex/agy execution records carry `cost_known == false`, grouped by worker. **A claude/grok record carrying it is NOT a falsification** — see the interrupt note below | none of codex/agy do — which would contradict the premise of the sizing above. NOT `unknown_cost_records`, which counts records with no cost at all: an executed missing-cost call is recorded at $2 with `cost_known=false` and never reaches that counter, while a cache replay can raise it |
| P7 | No cell is `contaminated` | any hit — the canary or a builtin marker fired, and every quality number is then suspect |
| P8 | `spent_known_usd` (claude+grok, actual) is under $10 across S1+S3 | more. Stated on `spent_known_usd` because ACTUAL total spend is not observable here: a missing-cost call is recorded as a $2 estimate with `cost_known=false` and summed into `cost_spent_usd`, so that field is known-plus-estimate, not spend. Real codex/agy spend is UNKNOWN and no number in this report may claim otherwise |

### An interrupted call books the full $2 estimate, whatever worker it was

Observed on the first S0 attempt (2026-08-31, `runs/b-s0`, SIGINT at 26 s).
The killed invocation records `status: failed`, `error: "interrupted"`,
`cost_usd: null` — the CLI never returned, so it never reported a cost — and
`BudgetLedger` then books the conservative `per_call_usd` **$2.00** with
`cost_known: false, estimated: true, counted: true`. The worker was `claude`,
which normally reports its actual cost.

Three consequences, all of which bear on S1 because S1 interrupts on purpose:

* **The reservation arithmetic above counts no interrupts.** Every in-flight
  call killed by the S1 SIGINT books $2 estimated on top of the $32. One
  interrupt is noise against a $200 ceiling; it is written down because the
  table claims to be what the campaign commits, and it is not, once a signal
  arrives.
* **P6 must not be read as "only codex/agy carry `cost_known == false`."** A
  claude or grok record carries it too, after an interrupt. The report groups
  by worker AND by `status`, or a reader concludes claude does not report cost.
* **`spent_known_usd` is unaffected** — an estimate is not known spend — so P8
  still reads what it claims to read. That is the field behaving correctly.

The attempt is CLOSED at interrupt (`invocation.finished` + `cost` +
`retry.attempt` with `decision: stop`), and `load_prior` reads
`stage.interrupted` and does not synthesize an abandoned attempt on resume, so
the $2 is carried forward once, not twice. A resumed run therefore shows the
phantom estimate in its ledger and the report should name it rather than
explain it away.

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
| committed cost over $50, **or `cost.committed_is_complete` false** | `campaign status` | stop |


**The reading this stop condition asks for did not exist.** It said
`spent_known_usd + reserved` "from `campaign status`", and that command reported
neither a reserved figure nor any campaign-level total - only a per-cell
`spent_known_usd`. An operator following it could sum 20 per-cell numbers by
hand and still see only the KNOWN half, missing every estimated call: in S1 that
is $5.80 of a $39.80 commitment, so the condition would have read 15% of the
spend it exists to bound. `campaign status` now reports
`cost: {spent_known_usd, reserved_usd, committed_usd, committed_is_complete,
counted_records_without_cost, unreadable_ledgers}`, summed from the same `cost_totals`
the scorer uses.

A cell whose ledger will not parse is named - and its spend is still **missing
from the total**, because it cannot be read. `campaign_spend` meets that case by
reserving `planned_calls x worst_case_call`, which needs the cell specs and
`per_call_usd`; `campaign status` takes neither a policy nor a corpus, so it
cannot compute that bound. It therefore reports `committed_is_complete: false`
and the total is a FLOOR. An earlier version called the corrupt cell "never
silently dropped from the total", which was half true: it was named, and it was
dropped. Understating is the dangerous direction for a condition whose whole
question is "am I under $50", so an incomplete total is a stop in its own right.

**A second way the total can be short.** A cost record that COUNTS but carries
no figure is spend that exists and cannot be valued, and `cost_totals` adds it
to neither bucket. The completeness flag consulted only `unreadable_ledgers`, so
it reported **true** while such records were present. It now requires
`counted_records_without_cost == 0` as well.

**And a way that reads short when nothing is wrong.** The obvious signal for the
above is `cost_totals.unknown_count`, and it is the wrong one: it counts EVERY
valueless record, and the common valueless record is a cache **replay**.
`cache.py` writes a replay as `cost_usd=origin.cost_usd, counted=False`, so
replaying a missing-cost worker's result leaves a record with no figure that
cost nothing - the origin's estimate was already booked in the cell that ran it.
Keying completeness on `unknown_count` would flag every such replay as
unaccounted spend and tell the operator to stop a campaign that was fine, which
is the cry-wolf failure this gate is built to avoid. `counted` is the field that
separates a replay from unvaluable spend, and both cases are pinned by tests.

An unreadable ledger and an unvaluable record are different failures with the
same consequence - a floor presented as a total - and the flag answers for both
without answering for replays. Checked against S1:
$5.800906 known + $34.00 reserved = $39.800906 committed, which reproduces the
figure previously derived by hand from the summary JSON.

**The $50 stop condition once contradicted the S3 sizing; the panel decision
resolved it.** As first written, the table planned S3 at **$64 reserved** on
reservations alone while the stop condition said halt at **$50** committed. S3
would have tripped its own stop condition by construction, at roughly 25 of its
32 reserving calls - near the end, after most of the money was spent, leaving an
incomplete matrix and no usable paired deltas.

It is recorded rather than quietly deleted because the resolution was not a
number. Raising the threshold to fit the sizing was the obvious move and the
wrong one: it would have bought a campaign whose paired deltas were already
known to be half-confounded. Dropping the two uncacheable workers made S3 both
valid and cheap (~$21, all real), and the $50 threshold then needed no change at
all. A contradiction between a budget and a plan is sometimes telling you the
plan is wrong, not the budget.

S1 ran at $39.80 committed and stayed under it.

To halt a campaign mid-flight, write the CAMPAIGN-SCOPED stop file:

The precondition script PRINTS one ready-to-run command per campaign id, with
the path resolved ABSOLUTE and shell-QUOTED:

```
    touch '/…/eris-engine/runs/b-s1/STOP'
```

Absolute, so it works from any directory. Quoted, because a `runs_dir`
containing a space is perfectly valid - and with `runs_dir: "my runs"` the
earlier unquoted, relative form printed

```
    touch my runs/b-s1/STOP
```

which creates a file called `my` in the current directory, fails on the rest,
and **leaves the campaign running while the operator believes it is halted**.
That is the worst failure available to a stop mechanism, so the script now emits
the exact string to paste and it was tested against a spaced `runs_dir`: the
STOP file lands in the campaign directory and no stray file is created.

**S0 is stopped differently, and the script says so.** A standalone `run`
passes `campaign_id=None`, so `arms.stop_file_paths` gives it ONLY the global
`<runs_dir>/STOP`; a per-run `<runs_dir>/b-s0/STOP` is never read. An earlier
version printed exactly that command as the way to halt S0 - a file nothing
looks at, while the only thing that would have worked was the global file the
same script labelled "do not use". S0 is now documented as: Ctrl-C (it is one
cell, and the in-flight call finishes first), or the global stop file.

The global `<runs_dir>/STOP` is printed for that purpose and labelled as the one
NOT to use for a campaign: it halts every run using that runs directory.

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

## S0 result — 2026-08-31, `runs/b-s0`

Exit **0**, `contaminated: false`, `scan_incomplete: false`, **0 hits** over 9
blobs and 43 events, 7 canary patterns (1 dropped as non-distinctive: it
occurred in a known text). The worker's `cwd` was the snapshot directory and
`cache.refused: missing` — a real call, no replay. Engine at `677c1e8`,
`claude` binary `625869b0…` (2.1.251).

The first attempt was SIGINT'd at 26 s; the resume re-ran `propose` as attempt
2 and `stage.resumed` reused the pack. Cost: **$2.406317** total =
**$2.00** interrupt estimate (`cost_known: false`) + **$0.406317** actual
(`cost_known: true`, 54.4 s, 82 input / 17 117 cached / 5 312 output / 2 025
reasoning tokens). The phantom carried forward exactly once, as the code says.

S0 did what it was for: the corpus runs, containment held, and three things
came back that no amount of reading the code would have produced.

### S0-1. `control.fpr` measures whether the arm SPOKE, not whether it invented

The proposal returned **3 findings on a clean control**: `low` (no tests exist
in the repo, no location), `low` (`textblock.py:17` — bare `str.split()`
collapses newlines and paragraph breaks), `info` (`textblock.py:38` — `if line`
is a truthiness test, so a whitespace-only line gets padded).

**All three are true.** Line 17 is `for word in text.split():`; line 38 is
`return [pad + line if line else line for line in lines]`; `git ls-files`
returns exactly `README.md` and `textblock.py`. The summary's verdict was
"defensible as it stands" and labelled all three non-blocking.

`control-clean-io.json` has 0 key findings (enforced by
`Key._control_has_nothing_to_find`), `predicted_findings` applies **no severity
floor**, and `_control_block` counts `flagged = len([s for s in ctl if s.fp >
0])`. So this cell scores **fp = 3, flagged**. Any accurate, self-labelled
non-blocking remark is a false positive by construction, and every competent
reviewer has something true to say about any file.

**P3 is therefore expected to fail, and the metric is NOT being changed.**
Rewriting a pre-registered metric after one result disfavours it is option 4 of
`docs/decisions/2026-08-30-confident-wrong-split.md`, rejected there for this
exact reason. P3 stands as written and will be reported falsified with this
cell as the cause. What the report must NOT do is call the number an invention
rate: on this corpus `control.fpr` is a **flag rate**, and a high one is
consistent with an arm that invented nothing at all. Whether a severity floor,
an adjudicated definition, or `wrong_accept` is the right invention signal is a
question for after the campaign, on the evidence, not a patch applied now.

### S0-2. The binary is pinned; the MODEL is not

`invocation.finished` records `model_requested: null`, `model_executed:
**claude-fable-5**`. `policies/default.yaml` sets `model: null` for both
`claude` (line 46) and `judge` (line 60) — "null = CLI default; set to pin a
model". So the arm ran whatever the CLI defaults to, and a CLI update can change
the model under a binary whose hash still matches its pin. That is the same
drift class that failed the gate this morning, in a place the pin check cannot
see.

The asymmetry is explicit in the source: `policy.py` enforces a lineage guard on
`agy` ("an unpinned default would break the Google lineage", line 112-114) and
none on the Anthropic workers, whose comment at line 57 names the identical
failure — "could silently collapse into another vendor's".

Mitigation that already exists: every invocation records `model_executed`, so
the campaign is auditable after the fact. What is missing is control, not
observability. Setting `model: claude-fable-5` would pass `--model
claude-fable-5` (`launch.py:152`) and change nothing about today's behaviour
while stopping the drift — but the flag has never been executed here, and an
untested flag that refuses every claude cell would do so mid-campaign, after
money is spent. **It must be verified by one real spawn before S1, not assumed.**

### S0-3. `evidence_refs` is not an exhaustive account of what informed a claim

Assumption 1 of the proposal: "README.md content is not in the DATA evidence
set; **I read it directly (read-only)** and it matches the docstrings". The
worker was spawned with `--tools Read,Grep,Glob` and `cwd` = the snapshot, and
`README.md` is one of the snapshot's two tracked files — so this is E1
containment working as designed, **not** contamination, and the scan agrees.

It is still worth stating plainly: a claim can rest on a file the worker opened
itself, outside the evidence pack. Here the model said so, marked the claim
assumption-backed, and filed an `evidence_request` to bring README into the
record — the honest path, and evidence the prompt's rules land. The report must
not describe `evidence_refs` as a complete provenance record.

### S0-4. Pinning the model, and the two things verifying it exposed

`model: claude-fable-5` is now set for `claude` and `judge` (S0-2). It was
**executed before being pinned**, not assumed: `build_argv_claude` produced the
argv, and the real CLI ran it — `modelUsage` names `claude-fable-5`. All four
families now carry an explicit model, so the panel's lineage is declared rather
than inherited from whatever each CLI defaults to.

The verification call cost **$0.098324** and returned two facts worth keeping:

* **A pinned model is not the only model in the call.** `modelUsage` listed
  `claude-fable-5` AND `claude-haiku-4-5-20251001` (899 input / 9 output
  tokens). The CLI does some of its own work on a second model. Eris records a
  single `model_executed`, so the ledger names the pinned model and is silent
  about the auxiliary one. The report may say the arm's *reviewer* model was
  pinned; it may not say the arm ran one model.
* **`max_budget_usd` is not a pre-spend cap.** The call was given
  `--max-budget-usd 0.05` and finished at `total_cost_usd: 0.098324` with
  `terminal_reason: "budget_exhausted"` — nearly double the cap, because the
  cap is observed after the fact and cache creation ($0.097 of it) lands in one
  go. The policy's `max_budget_usd: 1.0` therefore bounds a claude call at
  roughly-a-dollar, not at a dollar, and the S1 sizing should be read that way.

### S0-5. The gate printed a scoped re-check that could not work

With `b-s0` finalized, the id check FAILs forever, which trains an operator to
ignore the gate - the failure the openai-api scoping exists to prevent. The
check now reports whether a collided id is FINALIZED or resumable and prints
the scoped re-check for the ids actually about to start.

The first version of that printed
`CAMPAIGN_IDS='b-s1 b-s3' SINGLE_RUN_IDS='' bash eval/live_preconditions.sh`
and it **did not work**: the script read `${SINGLE_RUN_IDS:-"b-s0"}`, and the
colon form substitutes the default for an EMPTY value too, so the override was
discarded and `b-s0` was checked anyway. Fixed to `${SINGLE_RUN_IDS-"b-s0"}`.

Found by running the printed command instead of trusting it. That is the same
defect class as every stop-command failure in this document - an instruction
whose EFFECT was never executed - and it survived being written by someone who
had just written that lesson down two sections earlier.

### S0-6. The collision remediation printed the wrong resume syntax for a campaign

Caught by the Codex stop review, not by me. The block added in S0-5 told the
operator to resume ANY collided id with `--resume <id>`. That is the
**standalone** form. For a campaign, `--resume` is declared `store_true`, so the
bare id lands where the `campaign_command` positional is expected:

```
campaign --campaign-id b-s1 --arms single,indep_verify --repeats 1 --resume b-s1
  -> exit 2: argument campaign_command: invalid choice: 'b-s1' (choose from 'status')
```

Verified at the parser, not guessed: `parse_args` refuses that form, accepts a
bare `--resume` for `campaign`, and accepts `--resume b-s0` for `run`.

This is **B3 panel finding 2 reintroduced** - the finding that the S2 resume
command "was literally unrunnable (`--resume ...`)" - and it was written ten
lines after the STOP commands in the same script were split by exactly the
distinction it ignores. Knowing a distinction and applying it are different
things, and the only reliable difference is executing the output.

The remediation now tracks collided ids in two lists and prints the form that
matches the run kind, including the `--arms`/`--repeats` trap on a campaign
resume. All four branches (campaign/standalone x finalized/unfinalized) were
exercised against fixture directories before this was written down.

### S0-7. The kind was inferred from the request, not from the run that collided

Caught by the Codex stop review, on the fix for S0-6. Splitting the ids into two
lists fixed the syntax but classified each collided id by **which variable it
was requested in**, which is not evidence about anything on disk. Scoping an id
into the other variable - `CAMPAIGN_IDS='b-s0'` - produced confident campaign
remediation for a standalone run. The id that collided is whatever exists in
`runs/`, so that is what has to be classified.

The discriminator is the directory's own ledger: `cmd_campaign` appends
`campaign.started` to the campaign dir's `events.jsonl` (its cells live in
subdirectories); a standalone `run` never does. The block now reads that, and
when the id was requested as one kind but is the other it says so and states
that the advice follows the disk.

**It fails closed.** A directory with no `events.jsonl`, or one whose ledger
does not parse, is reported `unknown` and **no resume form is printed at all** -
a gate that cannot tell which command applies must say so rather than guess one,
because a guessed command is what the last two findings were.

Six cases were exercised against fixture directories before this was written:
campaign/standalone x finalized/unfinalized, a dir with no ledger, and a dir
with an unparseable one. The fixtures were removed afterwards.

Two review rounds on one twenty-line block, each finding a real defect in the
fix for the previous one. Worth stating plainly: the shape of my error here was
stable across both. I reached for the fact that was cheap to hand - first the
list I had just written, then the list again - instead of the fact that was
authoritative, which was on disk the whole time and cost one file read.

### S0-8. Absence is not evidence: empty and chain-corrupt ledgers got advice anyway

Caught by the Codex stop review, on the fix for S0-7. Reading the kind from disk
was right; the reading was not. It set `kind = "standalone"` and flipped to
`campaign` only on seeing `campaign.started`, so **standalone was the answer
whenever no marker was found** - an empty `events.jsonl`, a ledger torn or
corrupt before that event, a directory that is not a run at all. Confident
advice from no evidence, which is the failure this whole document is about.

Both kinds leave POSITIVE evidence, so absence never has to be interpreted:
`cmd_campaign` appends `campaign.started` to the campaign dir and never
`run.started`; a standalone `run` appends `run.started` and never
`campaign.started` (`eval/run.py:351`, `:1060`, `:1751`). The classifier now
requires one of them and reports `unknown` otherwise.

Reading is done by **the engine's own `LedgerView.from_path`**, so a ledger
whose hash chain does not validate is refused here exactly as `eval/score.py`
refuses it, rather than being parsed line by line and believed. A torn
unterminated tail is tolerated as everywhere else in Eris, and cannot affect the
answer because both markers are written at the head of the file.

Seven cases exercised against fixtures built with the real `RunWriter`, so their
chains are genuine: campaign, standalone, valid-chain-with-neither-marker, empty
ledger, **chain-corrupt**, no ledger at all, and the real finalized `b-s0`. The
chain-corrupt fixture carries an intact `run.started` on line 1 and is still
reported `unknown` - corruption outranks the marker. Fixtures removed afterwards.

**The first chain-corrupt fixture was itself broken** and silently proved
nothing: it replaced `"prev_sha256":"` in a one-event ledger, where that field
is `null`, so the mutation never landed and the "corrupt" file was byte-identical
to the good one. The gate called it standalone and that was CORRECT. Had that
been read as a pass, this section would claim a chain check that had never once
been exercised. A negative result from a fixture is worth nothing until the
fixture is shown to bite.

### S0-9. Conflicting markers were resolved by precedence, which is a guess

Caught by the Codex stop review, on the fix for S0-8. That fix required positive
evidence and reported `unknown` when there was none - but when there was
evidence for BOTH kinds it silently preferred `campaign`, because
`campaign.started` was tested first. A precedence rule is not a finding; it is
the same error as defaulting to `standalone` on no evidence, moved one branch
over.

No code path writes both. `cmd_campaign` appends `campaign.started` to the
campaign dir and never `run.started`; `run_cell` and `cmd_invoke` append
`run.started` to their own dirs. A directory carrying both is not what either
command would have made, so nothing in this gate knows which resume form
applies, and it now says so.

That mutual exclusion is load-bearing for the whole classifier, and when this
section was first written it rested on a grep of `cmd_campaign` taken once - an
invariant asserted, not enforced (S0-10).

Three cases exercised with real `RunWriter` fixtures: both markers -> `unknown`
with the reason named; `campaign.started` alone -> campaign; `run.started` alone
-> standalone. Fixtures removed afterwards.

**Four review rounds on one block, each finding a real defect in the fix for the
previous one.** The defects were not variations - they were the same defect
migrating: pick an answer where the evidence does not determine one. First from
the list I had just written, then from the list again, then from absence, then
from precedence. Each fix closed the instance in front of me and left the
disposition intact. What finally covers it is a rule about the code rather than
about the cases: **the classifier may only speak when the evidence is
unambiguous, and every other input - missing, empty, corrupt, contradictory -
takes the same silent branch.** That is now one `unknown` path with five
reasons, not five branches with four answers.

### S0-10. The rationale asserted an invariant the code did not enforce

Caught by the Codex stop review, on the fix for S0-9. The classifier's whole
fail-closed structure rests on one fact: a campaign directory's ledger carries
`campaign.started` and never `run.started`, and a standalone run's carries the
reverse. The comment stated that as though the code guaranteed it. Nothing did.
It was a grep of `cmd_campaign` taken at one moment, and a later edit that
appended `run.started` to the campaign writer would have made the gate print
`--resume c2` for a real campaign - which argparse rejects with
`invalid choice: 'c2' (choose from 'status')` - with no test failing anywhere.

An unenforced invariant in a rationale is worse than no rationale: it reads as a
guarantee, so the next reader stops checking.

Now enforced by
`tests/test_run_harness.py::test_campaign_and_run_ledgers_are_distinguishable_by_their_start_marker`,
which runs a real campaign and a real standalone run through the harness and
asserts the exclusion in three places: the campaign directory's own ledger, each
cell directory's ledger, and the standalone run's ledger.

**Mutation-checked in both directions**, because a test that has never failed
has not been shown to test anything:

* appending `run.started` to `cmd_campaign`'s writer -> fails with "a campaign
  directory's own ledger gained `run.started`: the live-run gate would now print
  the standalone resume flag for a campaign";
* appending `campaign.started` in `run_cell` -> fails with
  "t_01-r0-single-grok gained `campaign.started`".

Both mutations were reverted and `git diff` confirmed clean.

A second overclaim in the same comment: torn-tail tolerance was justified by
"both markers are written at the head of the file", which is also unenforced.
Rewritten to the reason that actually holds regardless of position - if a tear
removes a marker there is no positive evidence left, so the classifier reports
`unknown`, the silent branch. Tolerance cannot manufacture an answer.

**Five rounds.** The first four were the same defect migrating between branches
(S0-9). This one is that defect moved out of the code and into the prose about
the code: having made the branch structure fail closed, I explained why it was
safe using a fact I had checked once by hand and then described as a property of
the system. The check that closes it is the same one that closes the others -
make the claim fail before believing it.

### S0-11. The test enforced the invariant only where it happened to look

Caught by the Codex stop review, on the fix for S0-10. The test added there ran
a campaign and a standalone run and asserted mutual exclusion on the directories
those produced. The claim it was written to enforce is universal over paths:
**for any directory in `runs_dir`, exactly one start marker is present.**

`eval/run.py` builds a `RunWriter` at three sites - `cmd_invoke` (:347),
`run_cell` (:974) and `cmd_campaign` (:1739). The test exercised the last two.
Adding `campaign.started` to `cmd_invoke` therefore misclassifies an invoke
directory as a campaign, and the gate prints a bare `--resume` for a run that
needs `--resume <RUN_ID>` - **with every behavioural test still green**. That was
verified, not argued: the mutation was applied and the behavioural test passed.

Two changes, because the two failure modes are different:

1. The behavioural test now finds directories the way the gate does - walking
   `runs_dir` for `events.jsonl` - instead of asserting over the ones the test
   remembered to create. It asserts exactly one marker per ledger, and which.
2. A structural test pins the site map itself: every literal
   `.append("run.started"|"campaign.started", ...)` in `eval/run.py`, by
   enclosing function, compared for exact equality against
   `{"campaign.started": {"cmd_campaign"}, "run.started": {"cmd_invoke",
   "run_cell"}}`. Adding, moving or removing a site fails it; so does renaming
   one of those functions, which is intended - the gate's rationale names them.

Mutation-checked, and this is the result that matters:

| mutation | behavioural | structural |
|---|---|---|
| `run.started` into `cmd_campaign` | FAILS | FAILS |
| `campaign.started` into `run_cell` | FAILS | FAILS |
| **`campaign.started` into `cmd_invoke`** | **PASSES** | **FAILS** |

The third row is the finding. All mutations reverted, `git diff` clean.

**Six rounds.** The through-line has not changed once: an answer that outruns its
evidence. It has only moved further out - from the branch, to the reason for the
branch, to the test for the reason. A behavioural test can only speak for the
paths it runs; when the claim quantifies over all paths, something has to check
all paths, and "I exercised the important ones" is the same guess in a new
costume.

### S0-12. The structural test could not see the kinds it claimed to rule out

Caught by the Codex stop review, on the fix for S0-11. That fix pinned the
marker site map and closed the `cmd_invoke` gap, but the scan behind it was
narrower than the sentence above it in two ways:

* **It parsed `eval/run.py` only.** `src/eris/arms.py` and `src/eris/stages.py`
  both hold a writer and append events. A marker written from either was
  invisible to a test asserting a property of the whole system.
* **It matched only literal kinds.** `stages.py:1137` appends
  ``f"cache.{res.outcome}"``, so computed kinds are not hypothetical here. A
  marker built from an expression was invisible by construction.

The scan now covers every `.py` under `src/` and `eval/`, keys sites by
`path.function` using the INNERMOST enclosing function, and separates an event
append from a `list.append` by arity - an event append takes `(kind, payload)`.

For computed kinds it does the thing the gate does with a ledger it cannot
read: **it refuses.** A dynamic kind passes only when it starts with a literal
prefix that neither marker starts with, which is a proof it cannot produce one.
``f"cache.{outcome}"`` passes on that reasoning rather than by being named in an
exception list, so a future `cache.*` kind needs no edit here - and a kind with
no literal prefix fails, whatever it happens to evaluate to today.

Mutation-checked; the second row is the finding:

| mutation | behavioural | structural |
|---|---|---|
| `campaign.started` appended in `src/eris/arms.py` | FAILS | FAILS (names `src/eris/arms.py.run_arm`) |
| **computed kind `f"{spec.arm.value}.started"` in `arms.py`** | **PASSES** | **FAILS** ("cannot rule out") |

Both reverted, `git diff` clean.

**Seven rounds, and the shape is now explicit enough to state as a rule.** Every
round I produced an artifact that answered more than it had checked, and every
fix moved the unchecked part one level outward: branch, then rationale, then
test, then the test's own field of view. A test does not enforce a universal
claim by being about the right subject - it enforces it by being unable to pass
while the claim is false. The operative question is not "does this check the
thing?" but "what is this blind to, and would the claim survive there?" Where
the answer is "I cannot see", the only honest output is a refusal, in a test
exactly as in a gate.

### S0-13. The scan matched a calling convention, not the call

Caught by the Codex stop review, on the fix for S0-12. That scan found event
appends by requiring **two positional arguments** - chosen because a
`list.append` takes one, so arity separated them cleanly. It does, and it also
excludes most of the ways the call it is hunting for can legally be written.

`RunWriter.append(self, kind, payload)` (`src/eris/writer.py:344`) takes both
parameters positionally or by keyword. So

```python
w.append("campaign.started", payload={...})   # one positional -> missed
w.append(kind="campaign.started", ...)        # no positional  -> missed
w.append(**{"kind": "campaign.started", ...}) # invisible      -> missed
```

were each a legal way to break the invariant that the test enforcing it could
not see. None exists today - the survey found 0 keyword-form and 0 splat appends
against 86 positional ones - which is exactly why it survived: the scan matched
the codebase's current habit rather than the callable's signature.

What separates an event append from a `list.append` is that it passes TWO
things, however they are spelled. The scan now takes the kind from `args[0]` or
from a `kind=` keyword, and refuses any call whose keywords include a `**`
splat, since the kind is then not visible at all. That splat check runs BEFORE
the arity gate, because a splat call presents one keyword and no `kind=` and
would otherwise be skipped by the very gate meant to catch it - a bug written
and then found in the same round, by running case C instead of reasoning about
it.

Mutation-checked, all three shapes:

| mutation in `src/eris/arms.py` | structural |
|---|---|
| `append("campaign.started", payload={...})` | FAILS - site map changed |
| `append(kind="campaign.started", ...)` | FAILS - site map changed |
| `append(**{"kind": "campaign.started", ...})` | FAILS - "cannot rule out" |

All reverted, `git diff` clean. The baseline map is unchanged, so positional
detection is intact and the new rule is strictly wider than the old one.

**Eight rounds.** S0-12 named the question as "what is this blind to?" and this
round answers it for the previous answer: it was blind to the calling
convention, because I derived the detector from the code in front of me instead
of from the signature being called. Reading the definition of what you are
looking for costs one line - `src/eris/writer.py:344` - and it is the difference
between a scan that finds every such call and one that finds every such call
*written the way the current authors happen to write them*.

### S0-14. A positional splat walked past the widened scan, and two neighbours with it

Caught by the Codex stop review, on the fix for S0-13. That round widened the
scan to keyword forms and added a refusal for `append(**d)`, checked before the
arity gate. It did not add the same refusal for `append(*pair)`: one positional
argument, no `kind=`, so the arity gate returned early and the call was never
looked at. The `**` twin was handled in the same function, three lines above.

Fixing only the reported shape would have left the next two, so the question was
asked properly this time - what else can reach `RunWriter.append` without
presenting an `ast.Attribute` named `append` with a readable first argument?
Three things, all currently zero in `src/` and `eval/`, all now refused:

* `w.append(*pair)` and `w.append(*a, payload=b)` - splatted positionals;
* `getattr(w, "append")(kind, payload)` - no Attribute node to match;
* `emit = w.append` then `emit(...)` - the call site is detached from the name.

A `list.append(*x)` would now fail this test too. That is the intended trade: it
is zero-occurrence today, and the failure message says to make the call explicit.

**The fix contained its own defect, and running case F is what found it.**
`visit_Assign` recorded `ast.unparse(node)` for an alias, and the prefix check
re-parsed every dynamic entry with `ast.parse(expr, mode="eval")`. An assignment
unparses to a STATEMENT, so the test raised `SyntaxError` from inside itself
rather than failing with its message - and the mutation table I had already
written down said "FAILS", because a crash exits non-zero and I had matched on
exit code. Two bugs, one masking the other, both invisible to the check I was
running. `dynamic` entries now carry a prefix resolved while the node is in
hand; nothing is re-parsed.

Mutation table, six shapes, all with the assertion actually firing and no crash:

| mutation in `src/eris/arms.py` | result |
|---|---|
| `append(*pair)` | FAILS - cannot rule out |
| `append(*a, payload={})` | FAILS - cannot rule out |
| `getattr(w, "append")(...)` | FAILS - cannot rule out |
| `emit = w.append` | FAILS - cannot rule out |
| `append(f"{spec.arm.value}.started", ...)` | FAILS - cannot rule out |
| `append("campaign.started", {})` | FAILS - site map changed |

Baseline passes. All reverted, `git diff` clean.

**Nine rounds.** The lesson S0-13 drew - read the signature, not the habit - was
right and insufficient, because I applied it to the parameter list and not to
the call syntax. The durable form is narrower and duller: **when a check works
by recognising a shape, enumerate the shapes that reach the same behaviour, and
refuse the ones you cannot read.** And check the checker's own failure mode: an
exit code cannot distinguish a test that failed from a test that broke.

### S0-15. Enumerating detachment shapes, instead of asking whether the reference is called

Caught by the Codex stop review, on the fix for S0-14. That round added a
refusal for a detached bound method and implemented it as `ast.Assign` whose
value is an `Attribute` named `append` - which catches `emit = w.append` and
nothing else. Measured against the old predicate, five other ways to write the
same detachment walked straight past it:

| shape | old rule | now |
|---|---|---|
| `_e: object = w.append` (annotated) | MISSED | CAUGHT |
| `_e, _z = w.append, 1` (tuple target) | MISSED | CAUGHT |
| `_z = (_e := w.append)` (walrus) | MISSED | CAUGHT |
| `_h = {"x": w.append}` (dict literal) | MISSED | CAUGHT |
| `map(w.append, [])` (passed as argument) | MISSED | CAUGHT |
| `_e = w.append` (plain assign) | CAUGHT | CAUGHT |

S0-14 said the rule was "enumerate the shapes that reach the same behaviour",
and that is what produced this: an enumeration is a list, and a list of syntax
has no reason to be complete. The replacement asks a structural question with no
shapes in it - **is this reference to `.append` called right here?** Every way of
detaching a method, including ones nobody has written yet, is a reference that is
not a call. There is nothing left to enumerate, so there is nothing left to miss.

It also subsumes what it replaced: the `ast.Assign` special case is gone, not
supplemented. Zero uncalled `.append` references exist in `src/` and `eval/`
today, so the rule costs nothing and any future one - including a plain
`list.append` passed to `map` - fails with a message saying to call it
explicitly.

Nine shapes mutation-checked with the assertion actually firing and no crash
(the five above, plus plain assign, `getattr`, positional splat, and a literal
marker for the site-map half). Baseline passes; all reverted, `git diff` clean.

**Ten rounds.** The through-line finally has a name: I keep answering "which
cases?" when the question is "what makes a case?". Every round I produced a
correct list and the next round found the item that was not on it - shapes of
argument, shapes of call, shapes of reference. A list of cases is a guess about
the future written in the syntax of the present. The two rules that have
actually held are structural and dull: **refuse what you cannot read**, and
**ask what makes something an instance rather than which instances exist.**

### S0-16. Indirect lookup, and the first boundary drawn on purpose

Caught by the Codex stop review, on the fix for S0-15. The `getattr` branch
required a LITERAL `"append"`, so `getattr(w, name)` reached the same method
unread. Neighbouring shapes were unread for the same reason: a subscript
dispatch table, `__getattribute__`, a lambda callee.

The rule added is the structural one again - **a call passing two things whose
callee cannot be read as a plain name or attribute is refused** - plus the
dunder lookups. Zero such calls exist in `src/` and `eval/`, so it costs nothing
today. Six shapes mutation-checked, assertion firing, no crash: non-literal
`getattr`, subscript table, `__getattribute__`, lambda callee, literal `getattr`,
and a literal marker for the site-map half. Baseline passes.

**The first draft of that rule failed loudly and correctly.** Written as a
fall-through, it refused every ordinary two-argument call to a plain name -
`note(...)`, `_abandoned_payload(...)` - because a `Name` callee that was not
`getattr` fell into the refusal branch. A `Name` IS readable. Found by running
it, in the first second, which is the only reason it is not in this document as
next round's finding.

**And this round drew a boundary instead of extending the fix.** One shape is
still invisible to the static scan:

```python
_f = getattr(w, name)        # name not a literal
_f("campaign.started", {})   # callee is a plain Name
```

Refusing every non-literal `getattr` would close it, and would also fail the
four in `score.py` and `validate.py` that touch no writer. A check that cries
wolf gets ignored - the reasoning already written into this gate for the
openai-api WARN - so closing it that way would trade a real hole for a worse
one.

The boundary is therefore stated in the test, with the measurement that
establishes it: **that mutation was run.** The structural test PASSED (exit 0)
and the behavioural test FAILED (exit 1), because a marker written by any means
lands in a ledger it walks. The two tests are complementary and neither is
sufficient - static structure for every call site that can be read, real ledgers
for the paths actually exercised.

**Eleven rounds.** S0-10's lesson was "do not assert an invariant the code does
not enforce". Ten rounds later the thing needing that treatment was my own claim
of completeness. A scan cannot promise to see everything; it can promise to
refuse what it cannot see, and to say where its sight ends. Writing the limit
down is what stops the next reader - me - from trusting a green test further
than it reaches.

### S0-17. The same splat oversight, in the branch added to fix the last one

Caught by the Codex stop review, on the fix for S0-16. The unreadable-callee
branch guarded on `len(node.args) + len(node.keywords) >= 2`, so a splat walked
past it:

| call | arity read as | refused before |
|---|---|---|
| `getattr(w, n)(*pair)` | 1 | no |
| `getattr(w, n)(**d)` | 1 | no |
| `t["append"](*pair)` | 1 | no |
| `getattr(w, n)(k, p)` | 2 | yes |

S0-14 is the same finding. It was fixed there by adding a splat check inside
`_maybe_event`, on the `.append` path - and S0-16 then wrote a NEW arity test in
a NEW branch, from scratch, without it. The defect was not that I forgot the
lesson; it is that the lesson was applied to one copy of a rule that now had two.

So the fix is not a third splat check. Arity now lives in two functions,
`_hides_arity` and `_passes_two`, used by both branches and by nothing else -
verified by grep, three call sites, no other place computing an argument count
for this purpose. `_passes_two` treats a splat as passing two, because `f(*pair)`
may well be. Two copies of a rule are two rules, and only one of them gets fixed.

Six mutations, assertion firing, no crash - the four splat evasions above, plus
`w.append(*pair)` and a literal marker as regressions on the paths S0-14 and
S0-12 covered, to show the shared predicate did not loosen them. Baseline passes.

`getattr(*a)` parked in a local remains outside the static scan. That is the
residue documented in S0-16, not a new hole: the boundary named there is "a
method resolved dynamically and parked in a local", and this is an instance of
it, covered by the behavioural test rather than by this one.

**Twelve rounds.** The finding here is about repair, not detection: I fixed
S0-14 at the site that failed instead of at the rule, so the rule stayed
single-copy in my head and double-copy in the file. A fix that leaves the
duplication intact schedules its own recurrence, and the recurrence arrives
wearing the next feature's clothes.

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
