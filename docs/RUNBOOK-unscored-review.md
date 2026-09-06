# Runbook: review a real plan or document with Eris (unscored)

Status: **first real-work path.** Every command below was executed while writing
this, except the two that spend money, which are marked. Scoped to **plans and
documents** on purpose - see "Why not code, yet".

## What this gives you, and what it does not

You get a multi-family panel of models reading your document, a judge that
adjudicates their claims against the evidence pack, an enforced verdict, dissent
and residual risks, and a hash-chained ledger of the whole thing.

You do **not** get verification. Eris's evidence allowlist refused *every*
command the models proposed across all four campaigns run so far - `python3`,
`ls`, `grep`, most `git` subcommands. So the output is an **adjudicated opinion
with zero mechanically-observed evidence**. `AGENTS.md` says agreement between
models is weak evidence; this path produces exactly that, better organised.
Weigh it as a strong second opinion, not as a check.

That limitation is the panel's main objection to using this at all (agy, testing
lens: it "institutionalizes unverified model consensus as a functional
product"). It is recorded rather than argued away. The counter is that the
alternative - a scored campaign - needs container containment that does not
exist, so it cannot measure real work either.

## Before anything

**Put the review task OUTSIDE this repository.** A worker's cwd is
`<task>/snapshot`, and E1 established that claude, codex and grok read the
snapshot's parent and siblings. A task inside `eris-engine/` puts
`eval/keys/*.json` - the answer keys for the scored corpus - inside the tree a
worker can walk to. Verified: from `reviews/x/snapshot` the repo root is three
parents up.

Use somewhere like `~/eris-reviews/<slug>/`.

## 1. Build the review task

```bash
SLUG=my-design-doc                    # becomes task_id; must equal the dir name
DEST=~/eris-reviews/$SLUG
SRC=/path/to/YOUR-DOC.md              # the document under review
DOC=$(basename "$SRC")
mkdir -p "$DEST/snapshot"
cp "$SRC" "$DEST/snapshot/"

cd "$DEST/snapshot"
git init -q -b main
git add -A
git -c user.name=eris -c user.email=eris@localhost commit -qm "review subject"
cd -
```

The snapshot must be a git repository: the evidence pack runs `git rev-parse`,
`ls-files`, `log` and `status` to establish what the worker is looking at.

Then the task file. **The document only reaches the reviewers if you declare it
as an excerpt** - `TaskSpec.excerpts` defaults to an empty list, and the pack
builder iterates only what is declared. Omit it and the panel receives your
question plus four git facts and never sees a line of the document, while
producing a confident review of it.

Each excerpt is capped at `EXCERPT_MAX_LINES = 200` counted from `line_start`,
so a longer document needs several. `reviews/make_task.py` writes them for you:

```bash
cd /path/to/eris-engine
.venv/bin/python reviews/make_task.py "$DEST" "$DOC" \
    "Is this defensible? State a verdict and support every claim with evidence."
```

Six things it sets are load-bearing, each verified:

* **`excerpts` naming the document.** Above. `show_review.py` warns loudly after
  the fact if the pack held no excerpt, but that is a consolation prize - the
  spend has already happened.

* **`"scored": false`** - `TaskSpec.scored` defaults to **true**
  (`Field(default=True, strict=True)`), and a scored task with no answer key is
  refused before any worker spawns. Omit this line and the run dies.
* **`task_id` equals the directory name** - `load_task` refuses a mismatch,
  because the key is addressed by directory when scanning and by `task_id` when
  scoring.
* **`category: "plan"`** - the only honest label available. See below.
* **`snapshot` is relative to `task.json`.**
* **Excerpts cap at 200 lines each**, counted from `line_start`. An excerpt
  that asks for more is cut and its label marked `(capped)` - visible in the
  pack, not silent - which is what the splitting above avoids. Separately, a
  rendered prompt over 256 KiB is *refused* (`MAX_PROMPT_BYTES` raises
  `LaunchRefused`): a very large document fails the run rather than being
  quietly shortened.

Check it loads before spending anything:

```bash
cd /path/to/eris-engine
.venv/bin/python -c "
import sys; sys.path.insert(0,'.')
from pathlib import Path
from eval.run import load_task
t, s = load_task(Path('$DEST/task.json'))
print('OK', t.task_id, '| scored:', t.scored, '| snapshot:', s)
print('excerpts:', [(e.path, e.line_start, e.line_end) for e in t.excerpts] or
      'NONE - the reviewers will not see the document')"
```

## 2. Gate (free, and it has caught a real failure twice)

```bash
cd /path/to/eris-engine
CAMPAIGN_IDS='' SINGLE_RUN_IDS="$SLUG" bash eval/live_preconditions.sh
echo "gate exit=$?"
```

Must exit 0. It checks the worker pins against the binaries on disk, which is
not the same as `preflight`'s exit code - `preflight` exits 0 while reporting
`FAIL` lines. `claude` auto-updated out from under its pin twice in one day
during this project's campaigns. If it fails on a pin:

```bash
.venv/bin/python -m eris.cli policy pin --policy policies/default.yaml
```

Re-pinning authorises new binaries. Look at what changed first.

## 3. Run it (SPENDS MONEY)

```bash
.venv/bin/python eval/run.py run \
    --task-file "$DEST/task.json" \
    --arm indep_verify \
    --panel claude,codex,grok,agy \
    --judge judge \
    --run-id "$SLUG-001" \
    --fresh
echo "exit=$?"
```

* **`--arm indep_verify`, never `single`.** `ARM_STEPS[SINGLE]` is
  `("pack", "propose")` with no judge, so `single` produces **no verdict at
  all** - just unadjudicated proposals.
* **`--panel` with four families** is the point of the tool. Note `codex` and
  `agy` report no cost, so part of your spend is unobservable and is booked at
  the `per_call_usd` estimate.
* **`--fresh`** skips the cache lookup. Without it a re-run can replay a
  previous answer wholesale: in campaign b-s3b one arm spawned **zero** calls
  and replayed everything, spending $0 and looking like a result.
* Expect long silences. A proposer call can take up to 600s and the judge up to
  300s with no output at all. Silence is not a hang - S0 was interrupted at 26
  seconds on the assumption that it was.

## 4. Read the review

`eval/run.py` prints a machine summary, not a review. This renders the
adjudication:

```bash
.venv/bin/python reviews/show_review.py runs/$SLUG-001
```

It prints the verdict (and whether the ENGINE forced it rather than the judge
choosing it), the rationale, dissent, residual risks, how many rulings the
engine downgraded, every finding per worker, and - last, deliberately - how many
mechanical checks were refused, with the caveat that nothing is verified.

## Exit codes

`0` ok · `2` config/collision · `3` incomplete (a worker was absent) · `4` run
error · `5` stopped · **`6` contaminated** · `7` gate refused · `130` interrupted

**Exit 6 on a real repository is the one to expect that a synthetic corpus never
produced.** It means a scan marker reached the output. Do not use the review.

To resume an interrupted run: `--resume "$SLUG-001"` (it takes the run id as its
value; drop `--run-id`).

## Stopping

A standalone run is **not** stopped by `runs/<id>/STOP` - it passes
`campaign_id=None` and reads only the global file:

```bash
touch /path/to/eris-engine/runs/STOP     # halts every run using this runs dir
```

Or Ctrl-C once; the in-flight call finishes first.

## Why not code, yet

There is no honest task category for an arbitrary patch. `TaskCategory` is
`revert | planted | plan | control | insufficient`. `control` asserts nothing is
wrong; `revert` and `planted` say a known defect was introduced and are refused
without container containment. Only `plan` is truthful about a document you are
asking to be judged. Reviewing code would mean labelling it something it is not,
in a ledger whose whole purpose is that its labels are true.

## Known limits, stated rather than discovered later

1. **No mechanical verification.** Above. This is the big one.
2. **The verify battery is macOS-and-Python specific**: `policies/default.yaml`
   pins `/opt/homebrew/bin/{ruff,mypy,pytest}`. On Linux, or for a non-Python
   project, those are a dead battery until repinned.
3. **`max_budget_usd: 4.0` was sized on synthetic documents** whose largest
   observed call was $0.931. A larger real document is a larger context; if a
   call aborts with `error_max_budget_usd`, that cap is why.
4. **Excerpts cap at 200 lines** and a prompt over 256 KiB is refused. A long
   document is truncated, not rejected - check what actually reached the pack.
5. **The engine's human gate is schema-only.** Nothing here is a human review.
