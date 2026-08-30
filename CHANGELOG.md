# Changelog

## 0.4.3 - the scorer is bound to what it scored (2026-08-30)

Two multi-family review rounds against Phase A - a three-family panel (OpenAI /
xAI / Google) and a stop-time Codex review - found that the answer key could
still be read by the graded worker, and that several numbers the scorer printed
could be wrong in ways no reader would notice. Every finding below was
reproduced here before being acted on; two of them were in code written earlier
in the same session, and one was in a test that passed for the wrong reason.

### The answer key

* Keys move OUT of the corpus to `eval/keys/<task_id>.json`. A worker runs with
  cwd `<task>/snapshot` and E1 established that claude, codex and grok read the
  snapshot's PARENT, so `key.json` beside `task.json` was readable by the thing
  being graded - and `scan.build_patterns` deliberately does not match
  `must_mention`, so a worker that read the key and paraphrased it scored
  perfectly and was never flagged.
* `find_leaked_keys` refuses a key ANYWHERE in the task subtree (`files/`,
  `snapshot/` - the worker's own cwd - nested, or `KEY.json`), in `load_task`
  BEFORE any spawn as well as at scoring time. Checking one exact path refused
  the file that had been there and nothing else.
* `shutil.copytree` DEREFERENCES symlinks, so a link in `files/` pointing at the
  key was materialised as the key's plaintext inside `snapshot/` under the
  link's name, where no filename check looks; `Path.rglob` does not walk
  symlinked directories at all. Symlinks in `files/` are refused at build, and
  `load_task` refuses any file inside the task whose CONTENTS carry the key's
  canary - following symlinks, skipping already-visited real directories so a
  cycle cannot hang it, and treating an unreadably large file as a hit.
* The key file may not itself be a symlink: `eval/keys/t.json ->
  ../corpus/t/ground-truth.json` loaded perfectly while the bytes stayed where
  the worker reads. Moving the key means moving the bytes, not the path.
* Every scored key carries a per-task `ERIS-KEY-CANARY-<suffix>`, and a scored
  run is REFUSED unless that canary SURVIVES into the scan pattern set -
  `build_patterns` silently drops candidates that are too short, already known,
  or present in the pre-fix tree, and a dropped canary detects nothing.
  `BUILTIN_MARKERS` gained `eval/keys/`: relocating the key had taken it out of
  marker coverage, trading a leak for a blind spot.
* The canary detects a VERBATIM emission and nothing else. Stated in the code,
  in `docs/EVAL-PLAN.md` and in the scorer's own output: absence of a hit is NOT
  evidence of a clean run.

### What the scorer counts

* Recall is a COVERAGE of key findings and precision counts DISTINCT true
  claims. Credit was a maximum matching, one prediction to one key finding, so a
  prediction naming BOTH planted bugs scored recall 0.5 while emitting that same
  prediction TWICE scored 1.0 - a run was rewarded for repeating itself.
  Repeating a true finding can no longer dilute a false positive either. The
  augmenting-path search is gone, and with it a `RecursionError` on a key of
  >1000 findings.
* `run.started` records `task_sha256` and `key_sha256`, compared before anything
  else - before the `scored` flag is read, because flipping that flag is one of
  the edits this guards against. The scorer rereads both files, so the answer
  could previously be edited after the answering.
* Scored cells are checked against the matrix `campaign.started` declared, keyed
  on `run_id`. Cells were discovered by listing directories: one that never
  finished vanished, an extra was scored as if it belonged, duplicates were all
  aggregated.
* The `single` arm is aggregated per WORKER (`single:<worker>`): it expands to
  one cell per panel worker, so pooling by arm merged separate model lineages
  into one number and gave `single` several times the weight of other arms.
* A cell that recorded a failure about itself (`run.error`,
  `manifest.post_scan_errors`) is excluded as `run_error`, and the manifest must
  describe the ledger that is there (`event_count`, `last_sha256`, no torn tail
  on a finalized run) - all four were previously unread.
* Rates are published pooled AND per-cell, each named, with their denominators:
  precision, recall and `unsupported_claim_rate`. The bare number was a per-CELL
  mean answering a per-FINDING question, and silently dropped cells whose rate
  was None. Clean controls get a false-positive rate of their own, every rate is
  stratified `by_category`, and `comparison` is BLOCKED when arms did not score
  the same cells.
* A prediction with no `line_start` matches nothing (it defaulted to line 1, so
  a bare path hit anything near the top of a file); key finding ids must be
  unique; a `control` key may plant nothing; `paired_deltas` emits an explicit
  unpaired row rather than skipping a coordinate.

### The decision rule

* `confident_wrong` is SPLIT into `wrong_accept` (mechanical: the verdict
  against the key's `expected_verdict`) and `severe_false_positive` (the model's
  OWN severity label on its OWN claim). `docs/EVAL-PLAN.md`'s build/don't-build
  rule now reads `wrong_accept_rate`; the severity rate is reported beside it
  and is an input to no rule. Combined, one of the two branches authorising a
  whole orchestrator could be satisfied by an arm relabelling `critical` as
  `low` - a tone change, with no change in what it found, and there is no
  confidence field anywhere in the wire schema. User decision, recorded in
  `docs/decisions/2026-08-30-confident-wrong-split.md`.

### Documentation, and two rules that make its failures fail closed

* `CHANGELOG.md`'s newest entry must name `eris.__version__` and have a body.
  This entry exists because the version had been bumped across three commits
  with no record at all and nothing failed.
* Live documents may not name a repo path that does not exist. An
  `eval/README.md` was cited in four places - including AGENTS.md's gate
  condition and its map of where the pre-registration lives - as the home of the
  Phase 0 decision rule, and had never been written. `docs/EVAL-PLAN.md` says
  plainly that it carries the pre-registration, and states the rule once.
* Backticked, bare and markdown-link forms are all checked; a directory counts
  as well as a file, with or without a trailing slash; and links are checked in
  every document including `docs/history/` and `docs/decisions/`. A reference
  can be written four ways and three of them evaded an earlier version of the
  rule, which demanded a file extension everywhere except in the
  backticked-with-slash case. Sixty forms are probed - each target bare,
  backticked, as a link, in a list item, in a table cell and in a heading. The first version looked only inside
  backticks, and the two references that survived it survived because their
  backticks had been removed to make it pass: an invariant a formatting change
  defeats is not one.
* Scope is a DENYLIST. Every document is checked unless it matches
  `UNCHECKED_DOCS`, which carries a reason per entry and is asserted
  non-vacuous. The version before this named the two directories it DID check -
  root and `docs/` - so `eval/corpus/*/README.md` and anything else written
  elsewhere was exempt by having been overlooked. An allowlist of what is
  checked fails open by construction.
* Paths named because they do NOT exist are listed in `DELIBERATELY_ABSENT` with
  a reason, and a second test fails if one later starts existing. Other tools'
  filenames are in `EXTERNAL_CONVENTIONS`. Links are exempt only for content
  that is not ours to fix: a fixture repository may legitimately contain a
  broken link.
* `docs/history/*.md` carry a banner naming the live documents. The body of each
  is untouched; the banner says so, and says when it was added, rather than
  claiming the file is never edited while being an edit.

### Corpus and harness

* Snapshots are generated, never committed, and drift silently from the
  committed `files/` tree. `load_task` refuses a stale snapshot before any
  worker is spawned - on every spawn path, including `invoke` - and
  `make_control_snapshot.py <corpus> --all` builds a whole corpus, which a fresh
  clone needs before anything will run. The plumbing control's snapshot WAS
  stale, several edits behind its own README.
* `TaskSpec.scored` is `strict=True`: `eval/run.py` and `eval/score.py` read the
  flag through different code, and under lax coercion `"scored": "false"` made
  discovery skip a task the scorer still expected.
* A task whose directory name disagrees with its `task_id` is refused rather
  than scanned against one key and graded against another.

## 0.4.2 - the legacy fallback is stated and gated, not hidden (2026-08-29)

0.4.1's binding rule said whether a finding was acted on is "recorded per
finding as `Finding.acted`, NOT inferred from its code" - while the scorer still
inferred from the code for ledgers that carry no `acted`. The coupling test
added in 0.4.1 asserts the plan ECHOES the scorer's string; it cannot assert the
string is TRUE. Six ledgers in `runs/` are of that vintage, so this was live.

* Classification is per FINDING, so `_validator_basis` is conservative: a cell
  counts as coarsely scored when ANY of its findings lacks `acted`, not only
  when all do. Asking "does any finding carry `acted`" reported a mixed cell as
  exact and hid the coarsely-classified ones, bypassing the gate. Both functions
  now read one shared `_matched_findings` extractor so they cannot disagree
  about which findings they describe.
* The gate's EXPLANATION is true for both causes. It said the arm "has cells
  from ledgers with no `Finding.acted`" - false twice over for a mixed cell,
  whose ledger does have `acted` and only some of whose findings were scored
  coarsely; a reader would hunt for a pre-0.4.2 ledger, find none, and conclude
  the gate was wrong. The basis value is `coarse_codes` (not `legacy_codes`) and
  the per-arm key is `coarsely_scored_cells`, because both cover a mixed cell.
* `_validator_basis` reports how each cell was classified: `"acted"` (exact) or
  `"coarse_codes"` (at least one finding lacked `acted`, so the code fallback
  ran - it calls every `REF_*` handled and therefore UNDER-REPORTS malformation).
* `summary.comparison` is BLOCKED while any arm has coarsely-scored cells: an
  arm scored by code and an arm scored by `acted` are measured against two
  different definitions of malformed, so their rates are not comparable.
* `M1_PRE_REGISTRATION` now states the exception rather than asserting an
  absolute the code does not honour, and `docs/EVAL-PLAN.md` carries the
  corrected text.

## 0.4.1 - engine validator findings are consequential (M1) (2026-08-29)

`enforce_rulings` emitted findings about malformed adjudications and **nothing
read them** - not the exit code, not the scorer, not the verdict. A campaign
could be full of incoherent adjudications and every metric would look clean.

* **The scorer reads them, joined to the FINAL adjudication.** `_validator_errors`
  matches `adjudication_id == ArmRun.final_adjudication_id`, never "the last
  findings event": `adjudicate_iter` writes one per judge call, and resume
  replays a stored adjudication rather than re-deriving it, so reading the last
  event would count an ATTEMPT rather than the outcome the cell ended on.
* **Only findings the engine does NOT act on exclude a cell.**
  `validate.UNHANDLED_CODES` is that set (`CLAIM_MISSING`, `DUPLICATE_RULING`,
  `DISSENT_EMPTY_WITH_CONTEST`, `RESIDUAL_RISKS_EMPTY_ON_ACCEPT`, and the two
  validators that are never invoked). Codes the engine already handles - the
  `REF_*` family downgrades its ruling, `VERDICT_*` forces ACCEPT to ESCALATE -
  do NOT exclude. Running the change against the real ledgers is what caught
  this: 4 of the 6 live runs carry `REF_NOT_MECHANICAL`, and excluding them
  would have deleted the denominator for corrected behaviour and gutted
  `unsupported_claim_rate`, the metric whose whole job is to report it.
* A cell with an unhandled finding is excluded (`exclusion: validator_errors`)
  and **can never pair**: a delta against a malformed adjudication is confounded
  with the malformation, exactly as C1 was confounded with proposal variance.
* Findings are counted as a **multiset**; `None` (no adjudication to judge) is
  never reported as "clean".
* `per_arm[*].validator` and a campaign-level `validator` block report the
  malformed rate, unknown count and per-code totals. `docs/EVAL-PLAN.md` makes
  it binding: **an arm with a higher malformed rate has not earned a better
  score.**
* `test_unhandled_codes_is_exactly_the_set_that_changes_nothing` pins the set
  against measured behaviour, so it cannot drift from the code.

**Findings carry `acted`, and the scorer uses it instead of the code.** A
stop-gate found the code-keyed rule wrong in principle: only a SUPPORTED/REFUTED
ruling is downgraded, so `REF_MISSING` is acted on for those and completely
INERT on a CONTESTED or UNSUPPORTED ruling - the same code is handled in one
ruling and ignored in the next. `Finding.acted` is set by `enforce_rulings`,
which is the only place that knows, and written per finding into
`validate.findings`. `UNHANDLED_CODES` remains only as the coarse fallback for
ledgers <= 0.4.1 that carry no `acted` (it under-reports there, and says so).

**The binding pre-registration is now the scorer's own text.** A stop-gate found
`docs/EVAL-PLAN.md` still stating the code-keyed rule under its BINDING heading -
that cells are excluded by `UNHANDLED_CODES`, and that `REF_*` never excludes -
both false once the rule moved to `Finding.acted`. A stale rule in the document
the decision rule is read from is worse than no rule. `eval/score.py` now holds
the canonical `M1_PRE_REGISTRATION`, the plan carries it verbatim, and
`test_the_binding_pre_registration_matches_the_scorer` fails if either drifts or
if the rule is pushed outside the binding bullet.

Post-change panel (OpenAI + xAI, both BLOCK) added, all verified and fixed:

* `None` had a value but no CONSEQUENCE - a cell with an adjudication and no
  findings event was still scored. Unknown is not clean: it is now excluded
  (`validator_unknown`) and cannot pair.
* The LAST findings event per adjudication id wins. Ids are deterministic
  (`adj-{prefix}`), so a crash after `validate.findings` and before
  `stage.finished` leaves a stale event the clean re-run reproduces under the
  SAME id; summing every match let the abandoned attempt exclude the outcome
  that replaced it - the attempt-vs-outcome error, inside the fix for M1.
* **Excluding malformed cells creates a NEW bias.** Only arm 4 passes critiques
  to the validator, so only it can emit `DISSENT_EMPTY_WITH_CONTEST`; an arm
  that drops its malformed cells is left with a cleaner SUBSAMPLE and can win on
  catch rate. `summary.comparison.blocked` is now set MECHANICALLY whenever any
  arm dropped cells, and `docs/EVAL-PLAN.md` says under its BINDING heading that
  the decision rule may not be applied while it is set - a gate, not advice.
* The partition test is exhaustive over `CODES`: every code must have a case
  (which MEASURES whether it is handled) or a stated reason it cannot come from
  `enforce_rulings`. It immediately caught `REF_MODEL_ASSERTED` unclassified.

Not done, deliberately: giving `CLAIM_MISSING` / `DISSENT_EMPTY_WITH_CONTEST`
verdict powers is a protocol change of the same kind as H3 and belongs to the
user. `validate_critique` and `validate_origin` are never invoked at all - a
separate gap, recorded not fixed.

## 0.4.0 - evidence actually binds the verdict; four pre-live findings closed (2026-08-27)

A four-family review before live testing, plus the first live runs of the full
arm, produced one Critical and three Highs. All four are closed here. Behaviour
changes: adjudication verdicts and scorer pairing are both STRICTER, so runs
recorded before this version may score differently.

* **H3 (user decision: STRICT) - evidence now binds the verdict.**
  `enforce_rulings` accepts only `mechanically_observed` evidence in support of
  a ruling (`REF_NOT_MECHANICAL`); rejecting `model_asserted` alone let
  HUMAN_ENTERED text support a claim - including the task question that asked
  about it. An `ACCEPT` with no surviving `SUPPORTED` ruling is forced to
  `ESCALATE` (`VERDICT_UNSUPPORTED`): previously `{"verdict": "ACCEPT",
  "rulings": []}` passed through untouched, and a judge that self-declared every
  ruling UNSUPPORTED also reached ACCEPT, because a self-declared UNSUPPORTED is
  not a *downgrade* and never armed the escalation guard. The downgrade rule
  runs FIRST so it keeps its own `ESCALATED` finding when both apply.
  Fired on its first live run: 4x `REF_NOT_MECHANICAL`, the judge having cited
  the question to support four claims.
  A claim may be ruled EXACTLY ONCE (`DUPLICATE_RULING`); a second ruling is a
  validity error and leaves the claim unresolved, because coverage was a set
  membership test and a bogus `SUPPORTED` duplicate paired with a real
  `UNSUPPORTED` satisfied both ACCEPT conditions at once.
  An ACCEPT must also RESOLVE the panel's claims: every claim needs a ruling and
  none may be `CONTESTED` (`VERDICT_UNRESOLVED_CLAIMS`). A judge could otherwise
  rule on one claim, ignore the rest, and answer ACCEPT with no complaint at
  all - `claims` is every claim from every proposal, so an unruled claim was
  never adjudicated. `UNSUPPORTED` is a resolution and does not block.
  The ACCEPT rule counts a ruling only when its claim EXISTS: a ruling naming a
  claim nobody made is flagged `CLAIM_MISSING` but deliberately not downgraded
  (its refs were fine), so without that test a judge could satisfy the whole
  rule by inventing a claim id and citing real evidence at it.
* **C1 (Critical) - the paired ablation no longer claims pairings it does not
  have.** Sharing across arms 3/3b/4 happens ONLY through the call cache, and
  `Cache.lookup` refuses any entry without `model_executed`, which
  `parse_codex`/`parse_agy` never populate - so with the default panel those two
  workers are re-spawned by every arm with different text while the idempotency
  keys stay identical. `paired_deltas` now requires positive evidence of sharing
  (`invocation.reused`) and reports `paired: false` with the unshared keys
  otherwise. `docs/INVARIANTS.md`'s PAIRED ABLATION row was FALSE in production
  and is corrected.
* **Defect C (High, found by the live run) - paths handed to a worker must be
  absolute.** `scratch_dir` defaults to the relative `cache/scratch`, but a
  worker's cwd is the SNAPSHOT, so codex got a relative `--output-schema`, could
  not read it, and exited 1 before emitting a single JSONL event - three retries
  and no diagnosis. Resolved at the point of use, plus a `LaunchRefused` in
  `plan_call` so the class cannot recur silently. `TMPDIR` was broken the same
  way for every worker. No hermetic test could catch this: the fakes never
  resolve a path against a real subprocess cwd.
* **H2 (High) - `containment: container` is refused at policy load** until a
  container exists. Nothing in the tree implements one, so the declaration was
  always false, and it is the only gate protecting scored defect/ABSTAIN
  results. Delete the validator in the same change that builds the mechanism.
* `env_allow` documentation corrected: declaring a name makes it REQUIRED (the
  worker is refused at launch if it is absent), which the header previously
  described as "may be passed".

## 0.3.14 - the whole reporter body is guarded, not its last step (2026-08-24)

Twelfth stop-time finding, and the third in a row on the same helper. Each
previous fix guarded exactly the step the previous finding named - the write
(0.3.12), then the caller's formatting (0.3.13) - leaving the next step
exposed. This one stops chasing steps.

* `_print_scratch_cleanup_failure`'s ENTIRE body is inside one guard,
  including the dict construction where `str(scratch)` lived. `_safe_text` is
  kept inside it as belt-and-braces, not as the mechanism.
* Test explodes a DIFFERENT step than any previous finding did (a path whose
  `__str__` raises) and fails against the 0.3.13 shape.

The rule, and the reason it took three rounds: a handler already dealing with
a failure must be unable to raise ANYWHERE, so the guard belongs around the
whole body and must stay there as the body changes - guarding "the line that
broke" is what produced three findings instead of one.

## 0.3.13 - formatting a cleanup failure cannot replace the reason (2026-08-24)

Eleventh stop-time finding, and a fair correction to 0.3.12's claim that it
"closed the class": it guarded the reporter's WRITE, but the arguments are
built at the call site, outside that guard.

* `_safe_text(value, fallback)` - `str()` that cannot raise. `_scratch_root`
  formats the cleanup exception through it, and `_remove_scratch` formats its
  own return text through it (that function's contract is that it NEVER
  raises, and callers rely on the return value being the only signal).
* An exception whose `__str__` raises - a real shape for C-extension errors -
  no longer replaces the reason with a `RuntimeError` from the reporting path.
* Two tests, each verified to fail without the fix.

The general rule, now stated in INVARIANTS: in a handler that is already
dealing with a failure, EVERY step - formatting, serialising, writing - must
be unable to raise, not just the last one.

## 0.3.12 - the cleanup report cannot replace the reason (2026-08-24)

Tenth stop-time finding, one level deeper than 0.3.11's: the reporting channel
that exists so a cleanup failure is never lost could itself raise, destroying
the very exception it was called to preserve.

* `_print_scratch_cleanup_failure` NEVER raises. Every caller is already
  handling a failure; a closed stream or broken pipe must not become the
  reported outcome. An undeliverable report is dropped deliberately - there is
  nowhere left to say so, and the docstring says exactly that.
* `_scratch_root` catches `BaseException` from `shutil.rmtree`, not just
  `OSError`: rmtree is not contractually limited to it (an `onexc` handler can
  raise anything), and anything escaping that inner block would replace the
  reason.
* Three tests, each verified to fail without the fix: the reason survives an
  undeliverable report; a non-OSError cleanup is still reported and still
  loses to the reason; the reporter is called directly against a closed stream.

## 0.3.11 - a scratch removal failure is reported, and never instead of the reason (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; the goldens are untouched).
Two cleanup-reporting defects in `eval/run.py`, both found by reading the
contract `sanitize._remove_copy` states - "never swallowed, because
worker-visible files may remain" - against what the harness actually does.

Fixed
* **A run-scratch removal failure on the writer-open path was reported
  NOWHERE.** `run_cell` catches `RunExists` / `LedgerInvalid` / `WriterLocked`,
  hands the reservation back with `_remove_scratch(scratch)` and DISCARDED its
  return value. `_remove_scratch` returns the failure text and never raises, so
  on that one path a failed removal changed nothing: no ledger is open to take
  a `run.error`, no stderr line was printed, the exit code was the clean
  refusal it would have been anyway - and the verification copy stayed on disk
  with nothing pointing at it. The return value is now used on both channels
  that exist there: the harness's structured stderr line
  (`{"status": "error", "kind": "scratch_cleanup_failed", "run_id", "scratch",
  "error"}`, naming the path of the leftover) AND the returned `CellOutcome` -
  the text is appended to `error`, and the exit code becomes the run error (4),
  because a refusal that left worker-visible files behind is not a clean
  refusal. `status` still names why the writer refused (`exists` / `corrupt` /
  `locked`); no new exit code was invented.
* **`_scratch_root` raised from a `finally`, replacing the reason the run
  failed.** `shutil.rmtree(scratch, ignore_errors=False)` in a `finally`
  propagates out of the context manager and DISCARDS whatever was already in
  flight - the refusal, the writer error, the `KeyboardInterrupt` - so the
  operator would have been told the scratch directory was busy and never why
  the run stopped. A cleanup failure is still never silent, but it no longer
  costs the reason: with an exception in flight it goes to the structured
  stderr line and the original propagates; with nothing in flight it is raised,
  exactly as before. `cmd_invoke` takes `err` for this (it also stops writing
  the sweep line to `sys.stderr` directly, so `main`'s stream is honoured).
* `_remove_scratch`'s docstring now says why the return value is not optional,
  and `docs/INVARIANTS.md` carries both rules with their tests.

Audited, unchanged: the other two `_remove_scratch` call sites already use the
return value - the happy path appends `run.error` before the final scan (so
`scan.result` stays last and the run exits 4), and the `finally` records it
through `_record_run_error`, which routes to the ledger, or to the manifest and
stderr once the ledger is sealed.

## 0.3.10 - nested repositories are refused (advisor round) (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; the goldens are untouched).
The cross-family advisor BLOCKED 0.3.9 with a finding the coordinator then
reproduced independently, and so did I before writing any of this.

**The config allowlist rewrites exactly ONE file: the copy's own
`.git/config`. A NESTED repository has its own, and Eris never sees it.**
Measured 2026-08-24, git 2.50.1: an outer repository whose `sub/.git` is a
FILE reading `gitdir: <outside the snapshot>`, with that external config
carrying `diff.external`:

| state of `sub` | `status --porcelain` | `diff HEAD` | `status --porcelain=v2` |
|---|---|---|---|
| not in the index | no execution | no execution | no execution |
| registered as a gitlink (mode 160000) | **EXECUTED** | **EXECUTED** | **EXECUTED** |

No `.gitmodules` was involved, and `GIT_MODULES` only covered top-level
`.git/modules`. Nothing Eris rewrites, deletes or hashes could have helped:
the config that executes belongs to a repository outside the copy.

Fixed
* **`sanitize.assert_no_nested_repositories` refuses any `.git` below the copy
  root** - whatever its shape (directory, gitlink file, symlink) and at
  whatever depth. The root's own `.git` is skipped; a file merely named like
  one (`.gitignore`, `.gitmodules`) is not a repository. Recursive
  sanitisation is NOT attempted: it would mean rewriting a config tree of
  unbounded depth, some of it outside the snapshot, and getting that wrong is
  this bug again. Refusing is the honest scope.
* **A gitlink in the INDEX refuses the verification run**, taken on the
  guard's baseline from the `ls-files -s -v -f` output the tripwire already
  spawns (`-s` prints the mode, so the signal is free - no new command, and
  `GIT_INDEX_DIGEST_ARGS` is unchanged). This is the half the copier cannot
  see: a submodule that is registered but NOT checked out leaves nothing on
  disk, which is exactly what a non-recursive clone produces - and
  `eris.snapshot` clones non-recursively, so a superproject would otherwise
  arrive looking like an ordinary repository. Nothing can execute in that
  state, so it is a SCOPE refusal, not a containment one, and it says so.
* `git_index_prober` now returns `IndexProbeResult(digest, gitlinks)` instead
  of a bare digest string. The digest, the argv and the `bytes_fallback`
  behaviour are unchanged.

Fixed - `extensions.*` is a known-key allowlist with validated values
* 0.3.9 kept the WHOLE `extensions` section on the claim that no value there
  names anything dangerous. That was an assertion about a key set git is free
  to grow, with no evidence behind it. Now only
  `extensions.objectformat` / `extensions.compatobjectformat` survive, and only
  with a value in `{sha1, sha256}`; `extensions.worktreeConfig` is DROPPED
  (Eris deletes the `.git/config.worktree` it enables, so its absence changes
  nothing, and refusing it would be a false refusal on any checkout where
  someone has run `git config --worktree`); **anything else REFUSES the copy,
  naming the key**.
* Refusing rather than dropping is the point. An extension declares how the
  repository is STORED, so a copy with one silently dropped is a repository git
  OPENS and then misreads. Measured 2026-08-24 on git 2.50.1: `git init
  --ref-format=reftable` really does write `extensions.refstorage = reftable`
  with `repositoryformatversion = 1`, and a copy without it has no `refs/`
  files to fall back on. Loud beats quietly wrong.
* Known false refusal, measured and stated: at `repositoryformatversion = 0`
  git IGNORES `extensions.*` entirely (`exit 0`, no warning), so a v0
  repository carrying a stray extension is refused although git would open it
  happily. `git init` never writes extensions at v0, so this is not expected in
  practice; the refusal is unconditional because a version-dependent rule is
  harder to audit than a flat one.

Fixed - the parser claim is now measured rather than asserted
* `parse_git_config` accepted `[]`, which real git REFUSES: git builds
  `section[.subsection]` into one buffer and rejects the line when it is empty
  (`config.c`, `var->len < 1`). Measured 2026-08-24 on git 2.50.1: `[]` is
  `fatal: bad config line`, while `[ "x"]` - an empty section with a NON-empty
  subsection - is accepted. Eris now refuses exactly the first.
* The grammar table is a shared constant (`GRAMMAR_ROWS`) and is now replayed
  through a REAL git, row by row, comparing Eris's entries with
  `git config --list -z` record for record (NUL-separated `key\nvalue`, which
  is unambiguous where `--list` is not because a value may contain a newline).
  The hand-written expectations pinned what I believed git does; this pins what
  git does.
* The refusal table (`UNPARSEABLE_ROWS`) gets the same treatment, and the
  measurement corrected a guess in the process: git refuses EVERY row in it
  except "a key outside any section". So Eris refuses a superset of what git
  refuses - stricter in exactly one place, identical everywhere else. That
  direction costs a copy and never an escape; the reverse cannot occur, because
  refusal is the only outcome for that table.
* The module comment no longer claims equivalence with git's parser. It states
  what is verified - a correspondence pinned by two tables - and says plainly
  that a construction in neither table is unverified.

Fixed - a refusal now behaves like one, end to end
* `sanitized_copy` called `sanitize_snapshot` BEFORE entering its
  `try`/`finally`, so any failure while the copy was being built left a
  half-built copy in the scratch dir for the orphan sweep to find hours later.
  This milestone added a lot of refusals, so that mattered a lot more than it
  used to. The copy is now removed on the build path too - but only when THIS
  call created it: a `dest` that already existed is refused by
  `make_private_dir` and left exactly as found, the rule the run-scratch
  reservation already follows. If the removal ALSO fails, the cleanup error is
  raised (worker-visible files may remain, which is a run error, not a
  refusal) with the original refusal as its `__cause__` - neither fact is lost.
* `SanitizeError` was not caught by `run_cell`, so every deliberate refusal
  would have surfaced as an unhandled traceback with no ledger entry and no
  documented exit code. `SanitizeError` and `NestedRepositoryRefused` now exit
  `EXIT_CONFIG` with status `refused`, the reason in the summary and a
  `run.error` event on the ledger - like every other refusal.
  `SanitizeCleanupError`, a SUBCLASS, is caught first and stays
  `EXIT_RUN_ERROR`: it is a failure, not a refusal.

Fixed - docs that had drifted from the code
* `docs/INVARIANTS.md` cited five tests that this milestone renamed
  (`test_neutralise_refuses_every_config_shape_it_cannot_reason_about`,
  `test_a_copy_with_nothing_to_neutralise_is_left_alone`,
  `test_the_copy_disables_an_inherited_fsmonitor_and_untracked_cache`,
  `test_the_config_neutralisation_survives_odd_spellings_includes_and_continuations`,
  `test_the_neutralised_config_keeps_a_read_only_file_mode`). All corrected.
  Found mechanically, by collecting the suite and checking every `::test_`
  citation in the docs; the only remaining "misses" are two `*` globs and the
  historical 0.3.8 entry, which is left alone on purpose - a changelog records
  what was true then.
* `docs/INVARIANTS.md` still said "verification commands run on the ORIGINAL",
  and `sanitize.py`'s module docstring said "mechanical verification ALWAYS
  runs on the ORIGINAL". Both are wrong and have been since the verification
  copy was introduced: verification runs in a private VERIFICATION copy -
  never in a stripped worker copy, and never in the original. (The unit test
  named `test_pack_commands_run_on_the_original_not_the_sanitized_copy` passes
  the original directly as `snapshot_root`; that is what its name refers to,
  and the row now says so.)
* `docs/INVARIANTS.md` still described the old neutraliser (`removes
  core.fsmonitor/core.untrackedCache and appends [core] fsmonitor=false`) and
  a "regular neutralised file". Both now describe the allowlist rewrite.
* `docs/SECURITY.md` said `extensions.worktreeConfig` is dropped while also
  saying the whole `extensions` section is retained - contradictory even
  before item 2. Both statements are now the same one.
* New `docs/INVARIANTS.md` rows for all five items of this round, and a
  `docs/SECURITY.md` section for nested repositories with the measurement
  table.

Fixed (final round) - `.GIT` evaded the nested-repo walk
* The "ANY `.git`, any shape, any depth" promise was FALSE as written.
  Measured 2026-08-24 on macOS/APFS: a directory created as `sub/.GIT` is
  reported by `os.walk` under that literal name, while `Path("sub/.git")
  .exists()` is True and git resolves it - so the exact `name == ".git"` test
  missed a nested repository the kernel hands straight to git.
* Names are now compared FOLDED (`_fold`: NFC then casefold), and the same
  fold guards the copier's `.git/hooks` skip and its in-git test. That second
  one was a hole in its own right, found by the fix: **`.GIT/HOOKS` was being
  COPIED into the verification copy**, where our allowlisted git would have
  run a repository hook on the first invocation.
* Honest limits, both measured. NFC is a **no-op** for `.git`: it is pure
  ASCII, so NFC/NFD/NFKC/NFKD all return it unchanged and there is no
  decomposed spelling to defend against - the step is kept only so the helper
  survives a future non-ASCII marker name, not because `.git` needs it, and
  the "NFD-composed variant" the round asked for a test for does not exist.
  Compatibility lookalikes are deliberately NOT folded: a fullwidth `.gｉt` is
  a genuinely different file (creating it leaves `.git` non-existent), so
  matching it would be a false refusal.
* On a case-SENSITIVE filesystem `.GIT` is a distinct directory git never
  reads, so folding costs a refused copy there and never an escape.

Fixed (final round) - a repository config is not only a git problem
* Measured 2026-08-24 against the other two allowlisted tools, and both were
  already true before any of the M2c config work - nothing in it introduced
  these, and nothing in it would have caught them either:

  | tool | what a repository config did | Eris's flag |
  |---|---|---|
  | `mypy` | `mypy.ini` with `plugins = ./evil_plugin.py` **EXECUTED the plugin** - arbitrary code execution, the same class as `[diff] external` | `--config-file <os.devnull>` |
  | `ruff` | `ruff.toml` with `[lint] select = []` made `ruff check` report "All checks passed!" on a file with an unused import - **evidence manipulation**, not execution | `--isolated` |

* Eris appends these itself (`verify.ERIS_ISOLATION_FLAGS`) on exactly the
  contract `--no-optional-locks` already had: FIRST in argv, before any
  subcommand or positional. Every one of them is also HARD-DENIED to a model,
  so a proposal can neither double the flag nor point it somewhere else, and a
  test asserts the two halves cannot drift apart. `--isolated` was removed from
  the default policy's ruff `literal_flags`, since Eris now supplies it.
* The ruff case is not execution, but for an engine whose one job is deciding
  whether an answer is defensible *given the evidence*, a repository that gets
  to choose which findings exist is its own kind of serious.
* `os.devnull` rather than a literal `/dev/null`: Windows spells it `nul`, and
  whether mypy accepts `--config-file nul` there is UNKNOWN and untested. mypy
  also prints `<devnull>: No [mypy] section in config file` on stderr, which
  lands in the recorded evidence; that noise is accepted for the isolation.
* **`pytest` gets no isolation flag because none exists**, and that is now
  stated in `docs/SECURITY.md` rather than implied: `conftest.py` IS repository
  code that pytest imports and executes by design, which is exactly why pytest
  carries `requires_trusted`.
* The end-to-end tests live in a new `tests/test_verify_isolation.py`. It needs
  no addition to the hermeticity allow-list: every command runs as
  `sys.executable -m <tool>`, and the argv is the one `check_command` actually
  produced with only argv[0] swapped, so what is proved is the flag Eris really
  emits.

Fixed (final round) - two fail-closed corrections
* **No semantic index digest now REFUSES the run, it does not degrade.** The
  guard used to fall back to byte-hashing `.git/index` when git was unusable
  (`index_check: "bytes_fallback"`). That was a hole rather than a fallback:
  without the digest the GITLINK scan never runs, so a superproject sailed
  straight through exactly when the tripwire was weakest. `IndexScopeUnknown`
  now refuses and names the reason, and `INDEX_CHECK_BYTES_FALLBACK` is gone.
  Nothing real is lost - every command in the default battery IS git, so a
  copy whose pinned git cannot be run has no verification to produce. A copy
  with NO `.git` still needs no digest (`index_check: "none"`) and is not
  refused. `VerificationRefused` is the new common base that `eval/run.py`
  catches, so a future refusal cannot forget to be one.
* **Cleanup ownership is the successful `mkdir`, never a prior existence
  check.** `sanitized_copy` checked `dest.exists()` BEFORE calling
  `make_private_dir`, so a directory appearing in that window would be refused
  by the reservation (correctly) and then DELETED by the cleanup
  (catastrophically) - "it did not exist when I looked" was being used as "I
  created it". The reservation now happens in `sanitized_copy` itself and
  nothing is removed unless that `mkdir(exist_ok=False)` returned normally;
  `sanitize_snapshot` takes `dest_reserved=True` so it does not reserve twice.
  Confirmed by reverting: the planted directory was deleted.

Behaviour change an operator will notice
* **A repository that uses submodules can no longer be verified at all** -
  checked out or not. This is the largest scope reduction in the M2c
  follow-ups and the one most likely to be felt: it shows up as a clean
  refusal naming the path, never as a quiet half-verification.

## 0.3.9 - the verification copy's `.git` is contained: config by allowlist (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; the goldens are untouched). The
cross-family stop-time review of `b271b87` found the SIXTH consecutive hole in
this control, and the first that is ARBITRARY CODE EXECUTION rather than an
observation gap: "the new fail-closed control still permits Git to escape the
verification copy."

Measured on this machine, git 2.50.1, 2026-08-24, against the ALLOWLISTED
verification command `git --no-optional-locks diff HEAD`:

| vector | observed before this change |
|---|---|
| `[diff] external = <path>` in the copy's `.git/config` | the named program **EXECUTED** |
| `[diff "evil"] textconv = <path>` + `f.txt diff=evil` in a TRACKED `.gitattributes` | **EXECUTED** |
| `.git/objects/info/alternates` -> another object store, in a history-truncated snapshot | a commit `eris.snapshot` removed went from `cat-file -e` FAILING to SUCCEEDING; its blob read out in full |

The repository chose the program, not the model, so the executable pin, the
subcommand lists and the `--ext-diff`/`--textconv` hard-denies were all
irrelevant. The previous control neutralised the two keys we happened to know
about (`core.fsmonitor`, `core.untrackedCache`) and left everything else. That
was the wrong SHAPE, so this replaces the denylist with an allowlist rather
than adding a seventh patch.

Fixed
* **The copy's `.git/config` is rewritten from an ALLOWLIST**
  (`sanitize.rewrite_git_config`, replacing `neutralise_git_config`). Only
  `core.repositoryformatversion`, `core.filemode`, `core.bare`, `core.symlinks`,
  `core.ignorecase`, `core.precomposeunicode`, `core.logallrefupdates` and the
  whole un-subsectioned `extensions` section survive - the repository FORMAT
  and the filesystem capability flags. Every `diff.*`, `filter.*`, `merge.*`,
  `gpg.*`, `credential.*`, `url.*`, `http.*`, `uploadpack.*`, `include.*`,
  `includeIf.*`, `alias.*`, `remote.*`, `branch.*`, `user.*` and every other
  `core.*` is dropped. `core.fsmonitor`/`core.untrackedCache` are no longer set
  to `false`; they are simply absent, which is stronger. With no driver
  DEFINED, a `.gitattributes` naming `diff=evil` is inert - verified end to end
  against a real git, not assumed.
* **The rewrite is a re-serialisation, not a line filter.**
  `sanitize.parse_git_config` is a port of git's `config.c`; the output is
  generated from the parsed `(section, key, value)` triples with every value
  re-quoted. Every previous version of this control scanned LINES, and git's
  grammar is not line-oriented: measured the same day, `[core] filemode = true`
  is a header AND a variable on one line, and `[core][diff] external = x` puts
  the variable in `diff` - which a line filter looking for `[core]` would have
  kept. A config Eris cannot parse REFUSES the copy; git refuses to open such a
  repository too. One divergence found by re-measuring rather than by reading:
  git's `get_next_char` reports EOF AS a newline, so a config whose last value
  ends in a trailing backslash with no final newline ENDS the value
  (`core.filemode=tru`) instead of being a bad escape - refusing it would have
  been a false refusal, and the parser and a test row now match git.
* **The repository-level escapes are removed or refused.** The copy deletes
  `.git/objects/info/alternates`, `.git/objects/info/http-alternates` and
  `.git/config.worktree` (`drop_git_repo_escapes`), and REFUSES a copy that is
  not ONE self-contained repository (`assert_no_repo_escapes` +
  `assert_git_layout_sane`): `.git` present as a gitlink FILE,
  `.git/commondir`, `.git/worktrees/`, `.git/modules/`. Each refusal names the
  path and why.
* `GIT_REQUIRED_KINDS` gained the six paths this change names and a third
  column (WHY, appended to the refusal message); `.git` tightened from
  "file or dir" to "dir". `GIT_REFUSED_IF_PRESENT` and `GIT_DROPPED_RELPATHS`
  are new tables beside it, and `LAYOUT_ROWS` still has to match
  `GIT_REQUIRED_KINDS` exactly.
* `neutralise_git_config` -> `rewrite_git_config`; `ConfigNeutralisation` ->
  `ConfigRewrite`, which now also reports the entry names kept and dropped.

Behaviour changes an operator will notice
* **A snapshot with submodules (`.git/modules/`), one that hosts linked
  worktrees (`.git/worktrees/`), one that IS a linked worktree
  (`.git/commondir`), or one whose `.git` is a gitlink FILE is now REFUSED.**
  That is a deliberate scope reduction: those repositories keep config and
  objects in a `.git` Eris has not copied, has not rewritten and does not
  guard. It shows up as a refusal, never as a quiet half-verification.
* The copy's `.git/config` no longer resembles the original's. Anything reading
  it for the repository's remotes, user or aliases will find none.

Not a regression
* The ORIGINAL is still never opened for writing, in every path including the
  refusals, and that is now pinned across the refusing cases too.
* The race guards (`lstat`, `O_NOFOLLOW`, `O_EXCL`, the dev+inode re-check
  before the `unlink`), `GUARD_EXCLUDED_RELPATHS`, `GIT_INDEX_DIGEST_ARGS`, the
  model-facing allowlist and the `bytes_fallback` are untouched.
* An ordinary checkout - two remotes, a user, aliases, tracking config, several
  branches - still runs the WHOLE default battery clean. That test exists
  because a guard that rejects ordinary repositories gets deleted by the next
  person.

Honest limits (not fixed, stated)
* The working TREE is still the repository's, `.gitattributes` included. It is
  inert only for as long as nothing DEFINES the driver it names, so widening
  the allowlist is the thing to watch.
* Objects, refs, commit messages, tags and notes are copied verbatim and remain
  in-band instruction channels.
* The allowlist is applied ONCE, during sanitisation. Nothing re-applies it
  between verification commands; a command that rewrote `.git/config` mid-run
  would be caught by the guard's tree hash, not by the rewriter.
* This contains git's reading of the copy. It is not a container, and it does
  not stop a worker or a trusted `pytest` from reading outside the snapshot.

Tests
* `test_verify_real_git.py::test_a_repository_diff_external_cannot_execute_in_the_verification_copy`,
  `::test_a_repository_textconv_driver_cannot_execute_in_the_verification_copy`,
  `::test_a_planted_alternates_cannot_reach_a_truncated_away_object` - the three
  measured vectors, end to end through `sanitize_snapshot` and a real
  verification command. Each also proves the vector is REAL by running the same
  thing in the untouched original.
* `::test_a_git_info_attributes_driver_cannot_execute_in_the_verification_copy` -
  the same vector one level down, through `.git/info/attributes` (the
  repository-LOCAL attributes file, not tracked, copied with the rest of
  `.git`). Measured on git 2.50.1: with the driver defined it EXECUTES, with
  the driver unset it is inert. The docs called this inert BY REASONING; it is
  now pinned, and it is the test that fails first if the allowlist ever gains
  a driver-defining key.
* `::test_an_ordinary_repository_still_runs_the_whole_battery_after_the_rewrite`
  (no false refusal), `::test_the_config_rewrite_keeps_exactly_the_allowlisted_keys_git_reports`
  (the round trip, judged by `git config --list` rather than by Eris's own
  parser), `::test_the_object_format_extension_survives_the_rewrite` (a real
  sha256 repository still opens).
* `test_sanitize.py::test_the_copy_config_keeps_only_the_allowlisted_keys`,
  `::test_the_config_parser_reads_gits_real_grammar`,
  `::test_a_config_eris_cannot_parse_refuses_the_copy`,
  `::test_an_allowlisted_value_is_requoted_and_a_control_byte_refuses`,
  `::test_a_bare_allowlisted_key_stays_bare`,
  `::test_a_subsectioned_core_or_extensions_entry_is_dropped`,
  `::test_the_alternates_and_worktree_config_are_dropped_from_the_copy`,
  `::test_a_copy_that_is_not_one_self_contained_repository_is_refused`,
  `::test_the_repo_escape_checks_fail_closed_on_an_unreadable_path`,
  `::test_the_original_is_byte_identical_whatever_the_copy_does`.

## 0.3.8 - the `.git/config` control fails closed, and a general layout guard (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; the goldens are untouched). The
cross-family stop-time review of `731ee2f` found the FIFTH consecutive hole in
the same control (the verification tripwire and its copy): "symlinked
`.git/config` bypasses the new neutralisation." Correct, and the pattern is the
finding. The four before it were an excluded `.git/index` path, a missing
semantic index check, missing index flag bits, and the fsmonitor-valid bit -
four different KINDS of hole in one control. Each was patched individually.

The common shape: **a path Eris reasons about is not the thing git actually
reads.** `neutralise_git_config` did `if cfg.is_symlink() or not cfg.is_file():
return False` - it failed OPEN. Eris `lstat`ed and gave up; git followed the
link and honoured `core.fsmonitor` from its target.

Fixed
* **The `.git/config` control fails CLOSED.** A config that is a symlink
  resolving INSIDE the copy to a regular file is read, unlinked and REPLACED by
  a regular file holding the neutralised bytes, recorded in `dropped_symlinks`.
  Every other shape - a link escaping the copy root, a dangling link, a link to
  a directory or a fifo, a fifo, a directory - RAISES `SanitizeError` naming the
  path and the reason. A link that escapes or dangles in the ORIGINAL is dropped
  by the copier first, which legitimately leaves nothing to inherit; that case
  still proceeds with no config.
* **The target is never written through** (the docstring's promise, now
  enforced): containment is decided on the REALPATH, the read carries
  `O_NOFOLLOW | O_NONBLOCK` (a link to a fifo fails the type check instead of
  blocking the run forever), the link is re-`lstat`ed and must still be the same
  dev+inode immediately before the `unlink`, and the replacement is created
  `O_CREAT | O_EXCL | O_NOFOLLOW`. No pre-existing path, anywhere, is opened for
  writing.
* **A general post-sanitisation assertion, which is the point of this change.**
  `assert_git_layout_sane` checks every path in `GIT_REQUIRED_KINDS` - `.git`
  (directory or the gitlink FILE), `.git/config` (file), `.git/index` (file),
  `.git/hooks` (directory) - by `lstat`, never following a link. ABSENT is
  always allowed. Anything else refuses the copy. A path Eris comes to depend on
  is ONE line there plus one row in `LAYOUT_ROWS`, and the test asserts the two
  sets are EQUAL, so a new path with no test row fails the suite.
* `neutralise_git_config` now returns `ConfigNeutralisation(rewritten,
  replaced_symlink)` instead of a bare `bool`; `_neutralised_bytes` is factored
  out so the symlink-replacement path and the ordinary path share exactly one
  parser.

Honest limits (not fixed, stated)
* The assertion is a TYPE check on a FIXED list. It says nothing about the
  CONTENT of those files, nothing about `.git` paths not on the list (`HEAD`,
  `refs/`, `objects/`, `info/`, `commondir`, `objects/info/alternates`,
  `modules/`), and nothing outside `.git`. In-tree symlinks elsewhere in the
  snapshot are still kept by design.
* It runs ONCE, at the end of sanitisation. Nothing re-checks the layout between
  verification commands; a command that replaced `.git/config` with a symlink
  mid-run would be caught by the guard's tree hash (which records link targets),
  not by this.
* An in-copy `.git/config` symlink is REPAIRED rather than refused, because the
  copier legitimately preserves in-tree links. If that repair is ever wrong, it
  is wrong in the direction of a working, neutralised copy.

Tests
* `test_sanitize.py::test_a_symlinked_git_config_inside_the_copy_is_replaced_never_followed`,
  `::test_a_git_config_symlink_escaping_the_copy_is_dropped_and_never_read`
  (parametrized over `/etc/passwd`, an absolute path outside the tree, and a
  relative escape; the target's size, mtime and mode are asserted unchanged),
  `::test_neutralise_refuses_every_config_shape_it_cannot_reason_about`
  (6 shapes), `::test_the_git_layout_assertion_refuses_every_non_regular_shape`
  and `::test_the_git_layout_assertion_accepts_the_shapes_git_really_has` (the
  table, both directions), `::test_a_planted_git_shape_refuses_the_whole_
  sanitize_run` (reached end to end through `sanitize_snapshot`).
* `::test_the_config_replacement_refuses_a_link_that_changed_under_it` swaps the
  link between the read and the unlink (the TOCTOU the realpath check alone
  would not close) and
  `::test_a_git_path_that_cannot_be_read_or_stat_ed_refuses_the_copy` covers the
  errno branches: an errno that is not "absent" is never treated as absent.
* `test_verify_real_git.py::test_a_symlinked_config_cannot_smuggle_an_fsmonitor_into_the_verification_copy`:
  a real repository whose `.git/config` is an in-tree symlink setting
  `core.fsmonitor` to a tracked hook. git resolves the monitor through the link
  in the SOURCE; in the copy the config is a regular file reading `false`, the
  battery runs clean, and two `git status` refreshes leave every entry `H` -
  nothing is ever marked fsmonitor valid. The original keeps its link and its
  setting, tree hash unchanged.

## 0.3.7 - the fsmonitor chain: `-f` in the digest, fsmonitor off in the copy (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; the goldens are untouched). The
cross-family stop-time review of `0f121d8` found what 0.3.6 left: the
enumeration omitted git's behaviour-changing FSMONITOR-VALID entry bit.
`git update-index --fsmonitor-valid <path>` sets a documented per-entry bit that
makes git treat the file as unchanged, and `ls-files -v` does NOT show it - only
`-f` does (git-ls-files(1): "-f  Similar to -t, but use lowercase letters for
files that are marked as fsmonitor valid").

Measured (this machine, git 2.50.1, 2026-08-24; the suite re-measures it). The
bit only persists with an ACTIVE monitor returning a real update token, which is
why the first attempt to reproduce it looked like a dead end:

| state | `update-index --fsmonitor-valid` | `ls-files -s -v` | `ls-files -s -v -f` |
|---|---|---|---|
| no `core.fsmonitor` | exits 0, stores NOTHING | unchanged | unchanged |
| hook printing nothing | `warning: Empty last update token`, all bits cleared | unchanged | unchanged |
| hook emitting a v2 token | the bit PERSISTS | **unchanged (SILENT)** | moves |
| the same, then `--no-fsmonitor-valid` | the bit is cleared | **unchanged (SILENT)** | moves |
| second refresh of a fresh copy, monitor on | git marks every entry valid ITSELF | unchanged | moves |

Fixed
* **`GIT_INDEX_DIGEST_ARGS` is now `ls-files -s -v -f`.** Same single spawn, no
  schema change, strictly more coverage: without an active monitor `-f` prints
  exactly what `-v` prints, so it costs no false positive and the quiet battery
  stays quiet (re-measured). `check_command` refuses `-f` exactly as it refuses
  `-s`/`-v`/`--stage`, so the digest stays off the model-facing allowlist.
* **The enumeration grew two REAL cases, not two comments.**
  `test_verify_real_git.py::test_every_index_mutation_trips_the_guard` now
  installs a `core.fsmonitor` hook that emits a v2 update token, primes it
  (two refreshes on a fresh copy: the first writes the token, the second marks
  entries valid), and asserts that `--fsmonitor-valid` and
  `--no-fsmonitor-valid` both trip the guard with `reason: "git_index"`.
  Dropping `-f` makes both cases fail.
* **The verification copy no longer inherits a filesystem monitor.**
  `sanitize.neutralise_git_config` removes `core.fsmonitor` and
  `core.untrackedCache` from the COPY's `.git/config` and appends an explicit
  `[core]` block setting both to `false`. Removing `.git/hooks` was not enough:
  `core.fsmonitor` may name any path in the repository. The removal handles
  case, bare keys and backslash-continued values; the appended block, being the
  last section, also covers a value pulled in by an `include`. **The ORIGINAL is
  never opened for writing**, and the edit happens while the copy is being
  built - before the guard takes its baseline and before any verification
  command runs. This is a behaviour change to a security-relevant control and it
  earns its keep in both directions: left on, a monitor marks index entries
  fsmonitor-valid BY ITSELF on the second refresh of a fresh copy, which the new
  digest reports as a `snapshot.violated` that no verification command caused
  (verification would halt for the run); and a stale cache lets a command answer
  from data the working tree no longer supports.

Documented (`docs/SECURITY.md`): fsmonitor is out of the flat "nothing catches
these" row and into an honest chain - ENABLING it is caught by the tree hash
(`.git/config` is hashed and is not in `GUARD_EXCLUDED_RELPATHS`), the per-entry
valid bit is caught by the digest via `-f`, the `FSMN` section and its token are
caught by nothing, and the copy now starts with the setting off. The
verification copy's "differs from a raw `cp -a` in exactly two documented ways"
becomes THREE, in `docs/SECURITY.md`, `docs/INVARIANTS.md` (two rows) and the
`VERIFICATION_PROFILE` docstring; the untracked cache stays uncaught but is now
neutralised the same way.

## 0.3.6 - the index digest now sees the index FLAG BITS (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; the goldens are untouched). The
cross-family stop-time review of `bc33722` found the gap 0.3.5 left: `git
ls-files --stage` prints mode, blob sha, stage and path - and NOT the index flag
bits. `--skip-worktree` and `--assume-unchanged` change what `git status` and
`git diff` report about a file without changing any staged content, so setting
or clearing either left the digest byte-identical and the tripwire silent.

Measured (this machine, git 2.50.1, 2026-08-24; the suite re-measures it):

| index state | `ls-files --stage` | `ls-files -s -v` |
|---|---|---|
| baseline / both flags cleared | unchanged | unchanged |
| `--skip-worktree` set | **unchanged (SILENT)** | moves |
| `--assume-unchanged` set | **unchanged (SILENT)** | moves |
| stat refresh (`touch` + `diff HEAD`) | unchanged | unchanged (no false positive) |
| unstaged working-tree edit | unchanged | unchanged (the letter stays `H`) |

Fixed
* **`GIT_INDEX_DIGEST_ARGS` is now `ls-files -s -v`.** `-v` prepends the
  per-entry status letter (`H` cached, `S` skip-worktree, lowercase =
  assume-unchanged) in the SAME invocation: no extra spawn, no schema change,
  strictly more coverage. The probe itself still leaves `.git/index`
  byte-identical (re-measured). `check_command` refuses `-s`/`-v` exactly as it
  refused `--stage`, so the digest stays off the model-facing allowlist.
* **The mechanisms are ENUMERATED, not chased one at a time.** This was the
  third finding against the same control, so
  `test_verify_real_git.py::test_every_index_mutation_trips_the_guard` walks
  `--skip-worktree`, `--no-skip-worktree`, `--assume-unchanged`,
  `--no-assume-unchanged`, `--cacheinfo`, `--chmod=+x`, `-N`, `git add` of a
  modified file and `git rm --cached`, and asserts `reason: "git_index"` for
  each. A new mechanism is one line in `INDEX_MUTATIONS`. Reverted to
  `--stage`, the four flag cases fail.

Documented, having CHECKED each rather than assuming (`docs/SECURITY.md`, "What
the digest does NOT cover"; two named tests):
* The index EXTENSIONS - untracked cache (`UNTR`), fsmonitor (`FSMN`),
  cache-tree (`TREE`), resolve-undo (`REUC`) - live inside `.git/index`, which
  the byte hash excludes, and `ls-files` prints no trace of them at any
  verbosity. **Neither half of the guard catches any of the four.** Stated
  plainly rather than implied away: they are caches and undo data and none of
  them changes what a later `status`/`diff`/`ls-files` reports, which is the
  property the tripwire protects. The cache-tree case looks caught and is not -
  the guard trips there only on the object `write-tree` writes.
* The SPLIT index IS caught, and by the tree hash: `git update-index
  --split-index` writes a new `.git/sharedindex.<sha>`, which is not in
  `GUARD_EXCLUDED_RELPATHS`, so enabling it is `reason: "tree"`. The digest is
  blind to the split itself but keeps working over it - a `--skip-worktree`
  applied afterwards still moves it. `--no-split-index` leaves the shared file
  behind, so the tree stays changed.

## 0.3.5 - the verification tripwire now sees git index mutations (2026-08-24)

No schema change (`SCHEMA_VERSION` stays 0.1.5; `snapshot.violated` is an
EVENT, and `Event.payload` is a free-form `dict[str, Any]` - no golden is
touched). A cross-family review of `920262d` found the gap the 0.3.4 fix left
behind: `evidence.GUARD_EXCLUDED_RELPATHS` keeps `.git/index` out of the
tripwire's hash, but the index is not inert. `git ls-files` reads it directly
and `git diff`/`git status` compare against it, so a command that mutates it
changes what LATER evidence reports - and the guard would not notice. The
current allowlist cannot reach `git add`/`git rm`; the guard is defence in
depth for the day it is wrong or is widened.

Measured (this machine, git 2.50.1, 2026-08-24; `tests/test_verify_real_git.py`
re-measures it in CI) - the exclusion cannot simply be removed. With
`--no-optional-locks` on every invocation, `status --porcelain`, `ls-files`,
`ls-files --stage`, `log --oneline`, `grep`, `blame`, `show` and `rev-parse`
leave `.git/index` byte-identical, but the first command that reads the working
tree against the index (`diff`, and `diff HEAD` too - the spec had this as bare
`diff` only) refreshes it, flag or no flag. Hashing those bytes would trip the
guard on a legitimate allowlisted command on every run. Meanwhile the digest of
`git ls-files --stage` is stable across all of that and moves on `git add` and
`git rm --cached` - and `git rm --cached` changes nothing else in the tree, so
the byte hash alone cannot see it at all.

Fixed
* **`SnapshotGuard` gains a semantic git-index digest.** Whenever the
  verification copy has a `.git` DIRECTORY, the guard digests
  `git --no-optional-locks ls-files --stage` (`evidence.GIT_INDEX_DIGEST_ARGS`)
  alongside the tree hash and compares it after every command. Either half
  moving is `snapshot.violated` and stops verification. The event payload now
  carries `reason` (`"tree"` or `"git_index"`; the index wins when both moved,
  as it does for `git add`, which writes a loose object AND stages it),
  `index_check`, and `git_index_digest_before` / `_after` next to the tree
  hashes.
* **The digest is an Eris-internal invocation.** Fixed argv, the POLICY-PINNED
  `git` (hash re-checked at call time; unpinned, missing or since-changed
  yields no digest and is never spawned), the hardened verify env. It does NOT
  go through `check_command`: it is neither proposed nor influenced by a model,
  and the allowlist would refuse `--stage` anyway.
* **Fail closed.** A copy with a `.git` directory and no usable digest (git
  unavailable, non-zero exit, timeout, truncated output, or a probe that stops
  working part way through the run) drops the byte exclusion for that run,
  hashes `.git/index` like any other file, and records
  `index_check: "bytes_fallback"`. A copy with no `.git` directory records
  `index_check: "none"`. The check is never silently skipped.
* `GUARD_EXCLUDED_RELPATHS` is UNCHANGED - still exactly `.git/index` and
  `.git/index.lock`, still pinned by
  `test_evidence.py::test_the_guard_excluded_set_is_exactly_the_git_index`, and
  now commented with both the reason it exists and the digest that covers it.

`tests/test_verify_real_git.py` grows the real-git half: the default battery
plus a bare `git diff` and `git diff HEAD` run clean with the semantic check
armed, and a real `git add` of a modified file and a real `git rm --cached`
both trip the guard with `reason: "git_index"`. Removing the semantic check
makes both staging tests fail (the `rm --cached` case does not trip at all).

## 0.3.4 - first live plumbing run: two defects fixed (2026-08-23)

No schema change (`SCHEMA_VERSION` stays 0.1.5; every committed golden is
untouched). The harness was pointed at a real worker CLI for the first time
(`eval/run.py run --task-file eval/corpus/plumbing-control/task.json --arm
single --panel claude`). The harness behaved - pack built, absences recorded,
scan ran twice, exit 3, no crash - and surfaced two defects that no hermetic
test could have caught, because the fakes never execute a real CLI or a real
`git`. Full bisection tables in `docs/EVAL-PLAN.md` ("First live plumbing
run"); every rule below has a row in `docs/INVARIANTS.md`.

Fixed (each with a test that would have caught it)
* **A - `USER` is required in the worker environment.** `claude` reported
  `Not logged in - Please run /login` while `claude auth status` said
  `loggedIn: true`. `HOME` + `PATH` + `TMPDIR` + every var the harness adds
  still failed; `USER` alone fixed it; `LOGNAME` alone and `SHELL` alone did
  not. `launch.build_env` now takes a required `user` keyword and sets
  `USER`; `launch.resolve_user()` reads the OS (passwd database first,
  `getpass.getuser` as the portable Windows fallback), never a filtered
  `os.environ`, and discards an implausible name. `WorkerCall.user` and
  `StageContext.user` have NO default so no call site can omit it silently.
  `eris doctor` gains a `user` check that WARNs, naming the bogus auth
  symptom, when the account cannot be resolved. API workers are unaffected
  (no subprocess); verification commands do not get `USER` either.
* **B - a read-only `git` command tripped the verification tripwire.**
  `git status --porcelain` refreshed `.git/index` on the freshly copied
  verification tree, the tree hash changed, `snapshot.violated` was recorded
  and every remaining verification command in the run was refused. Both
  halves: (1) `verify.GIT_ERIS_GLOBALS` - Eris appends `--no-optional-locks`
  to every `git` invocation, before the subcommand; it is hard-denied from a
  model like every other git global; (2) `evidence.GUARD_EXCLUDED_RELPATHS` -
  the tripwire hash excludes `.git/index` and `.git/index.lock` and NOTHING
  else, so a write to refs, objects, HEAD, config or hooks is still a
  violation. `evidence.request_key` also drops the Eris-appended globals, or
  a resumed run would re-execute requests it had already executed.
  `tests/test_verify_real_git.py` runs the real battery against a real git
  repository (`real_subprocess(allow=["git"])` now has two call sites, not
  one); reverting both halves reproduces the live ledger exactly.

Advisor round (one review round; findings folded into the same milestone)
* `USER` is not attacker-, policy- or secret-controllable: a policy `env` or
  an `env_allow` secret naming `USER` is REFUSED, the OS value is written LAST
  in `build_env`, and `getpass.getuser` is consulted only when none of
  `LOGNAME`/`USER`/`LNAME`/`USERNAME` is set (it reads them before passwd), so
  an environment-derived answer counts as UNRESOLVED. Windows therefore runs
  without `USER` - a deliberate, documented refusal that `eris doctor` reports.
* `eris doctor` no longer prints the account NAME: `USER: resolved` /
  `USER: could not be resolved (...)`. The doctor reports names, not values.
* `TaskSpec.scored` (default True). `"scored": false` is now ENFORCED rather
  than documented: campaign discovery skips the task and `eval/score.py`
  reports its cells as `skipped: not a scored corpus task`, entering them in
  no metric. An explicit `--task-file` still runs it. The scorer reads the
  flag as JSON, deliberately NOT through `eris.evidence.TaskSpec`, which would
  drag `eris.verify` and `subprocess` into the scorer (its import guard caught
  this).
* `request_key` is keyed only on a VALIDATED argv: `execute_evidence_requests`
  applies the grammar BEFORE computing the key, so a model-supplied
  `--no-optional-locks` is refused instead of aliasing an already-executed
  request into `verify.duplicate`. `run_allowlisted` still re-validates
  immediately before spawn.
* The corpus snapshot generator is Python (`eval/make_control_snapshot.py`),
  not POSIX shell: `shutil` copies and only `git` is spawned, with the commit
  identity passed per invocation. The README no longer overclaims portability.
* Guard coverage extended: writes to `.git/objects/...`, `.git/HEAD` and
  `.git/hooks/pre-commit` trip the tripwire; `.git/index` and
  `.git/index.lock` do not.

Also
* `policies/default.yaml`: `~/.grok/auth.json` removed from
  `credential_files` (doctor: absent; the Grok CLI no longer creates it). The
  reason is in the policy comment.
* `eval/corpus/plumbing-control/` - the first corpus entry, a **plumbing
  control, not a scored task**: two functions, no defect. Its `snapshot/` is
  GENERATED, never committed (a git repository cannot live inside another,
  and `.gitignore` excludes `eval/corpus/*/snapshot/`); the working tree is
  tracked in `files/` and `eval/make_control_snapshot.py` (portable Python)
  rebuilds it.
* `docs/EVAL-PLAN.md`: the live-run result rows, and **M2c-2** recorded as an
  OPEN portability item - the tracked policy holds machine-specific ABSOLUTE
  verify executables while the hashes live in the gitignored `pins.yaml`,
  with the two candidate designs. Not fixed here: it changes the policy schema
  and the pin command.
* `pack.incomplete` on that run was a CONSEQUENCE of defect B and is recorded
  as M2c-C, to be re-checked on the next live run.

---

## 0.3.3 - final advisor fix round (2026-08-23)

No schema change (`SCHEMA_VERSION` stays 0.1.5; every committed golden is
untouched). Seven blocking items from the cross-family advisor's confirmation
pass on `c30f3f4`, each with a named test (`docs/INVARIANTS.md` "Final fix
round"):

1. **Exclusion outranks retention** in the scratch sweep: a path whose run id
   belongs to the current command is never swept, at any age. The 7-day
   `scratch_retention_s` bound applies to orphans only.
2. **The scratch reservation is the `mkdir(exist_ok=False)`**, taken BEFORE
   the writer opens (`run` and `invoke`). An entry appearing between the
   precheck and the mkdir refuses with no ledger, no run directory and
   nothing deleted; a writer-open failure gives the reservation back.
3. **Monotonic attempt numbering across resumes**: the next attempt number is
   derived from every recorded attempt (finished, abandoned, interrupted) and
   `run_with_retry(first_attempt=...)` continues from the ledger instead of
   restarting at 1, so no two attempts share a number or an invocation id.
   Abandoning stays idempotent, and the backoff still counts tries within the
   driver run.
4. **Durable sealing**: a ledger whose last event is `scan.result` reopens
   SEALED, so a resume after a failed finalize cannot append behind the final
   scan.
5. **True worst-case reservation**: `worst_case_call_reservation` walks the
   real retry budget and per-attempt reservation factors instead of guessing
   a closed form. The attainable mixed chain (timeout -> transient ->
   timeout) reserves **5x** `per_call_usd`, not 4x; the test brute-forces
   every class sequence the driver can produce.
6. **`_force_writable` scoped**: removing a sanitized copy restores owner rwx
   on real directories inside the copy root only - never a symlink, never a
   parent - re-raises anything that is not a permission error, and no longer
   calls the rmtree primitive back (invalid for `os.open`).
7. **Durable post-scan failure + fsync-after-rename**: a failure after the
   seal is recorded in `manifest.json` (`post_scan_errors`), not stderr-only;
   a manifest renamed into place whose directory fsync fails is "finalized but
   not fsynced" - `ManifestNotDurable`, a `not_durable` log line and its own
   exit code **8**, never a run error. Both documented in `docs/SECURITY.md`.

## 0.3.2 - schema 0.1.5 + advisor re-check fixes (2026-08-23)

Schema `SCHEMA_VERSION` 0.1.4 → **0.1.5** (new golden dir
`tests/fixtures/records/0.1.5/`, MANIFEST block + pinned constant;
0.1.0–0.1.4 untouched): `ErrorClass.INTERRUPTED` - the harness's own SIGINT
class, terminal and never produced by the retry classifier (it used to be
recorded as `unknown`).

Advisor re-check (Codex at `871c7da`; conditions 1, 3, 6, 8, 11, 14 lifted).
Fixed, each with a test (`docs/INVARIANTS.md` "Advisor re-check"):
* (cond 2) a FRESH empty judge workspace per call (`judge-<role>-<iteration>`),
  emptiness re-checked immediately before every spawn;
* (cond 4) `PRISTINE_PROFILE` → `VERIFICATION_PROFILE`: it strips nothing and
  differs from a raw copy only by `.git/hooks` and dropped
  absolute/dangling/escaping symlinks, both documented and asserted (file set,
  bytes, modes, kept symlink targets); the event is `snapshot.verification_copy`;
* (cond 5) the scratch sweep removes only provably orphaned entries (not the
  current run's, no held writer lock, older than an hour) and logs removed AND
  kept with reasons;
* (cond 7) SIGINT closes its attempt (`stage.interrupted`): resume no longer
  synthesizes an abandoned attempt for it, so the cost is counted once;
* (cond 9) a key/entry/blob that IS a symlink is refused whatever it points at
  (lstat before resolve; the path is returned unresolved);
* (cond 10) the final `scan.result` is genuinely last: the snapshot check and
  the scratch removal append before it, and a sealed ledger reports a late
  failure on stderr rather than swallowing it;
* (cond 12) a corrupt cell ledger reserves `planned_calls x
  worst_case_call_reservation(per_call)` - retries included, derived from the
  retry constants;
* (cond 13) lstat-first cell discovery (symlinked cell dir or manifest
  skipped) and a TRANSITIVE AST guard over the scorer's first-party imports.

`Claim.revised_at` = the Invocation's `finished_at` is deliberate: it is what
makes a fresh record and a cache-replayed one byte-identical (tested).

Final re-check (Codex at `47c9254`; conditions 2, 9, 13, 15 lifted). Fixed:
* (cond 4) directory modes are preserved on the copy (root included), and a
  read-only directory still gets removed;
* (cond 5a) every command passes its own run ids to the sweep - `run`,
  `campaign` (all planned cells) and `invoke`;
* (cond 5b + consequence 1) the scratch path is validated BEFORE the writer
  opens: a refusal creates no ledger, deletes nothing, names the path, and
  leaves the run id reusable;
* (cond 7) `stage.interrupted` closes exactly its own attempt, so a later
  crashed attempt with the same key still yields an abandoned record;
* (cond 10) `RunWriter.seal()` makes it structurally impossible to append
  behind the final scan; post-scan failures go to stderr + the exit code;
* (cond 12) planned calls come from the arm's steps, counting every judge
  iteration;
* (consequence 2) `Policy.scratch_retention_s` (7 days) is a hard sweep
  bound, so unprovable liveness cannot let scratch accumulate.

Documented, not changed (Codex's third note): a corrupt cell ledger reserves
the worst case and can halt later cells on the campaign budget - intended
fail-closed behaviour, operator-resolvable (`docs/SECURITY.md`,
`docs/EVAL-PLAN.md`).

## 0.3.1 - schema 0.1.4 + advisor-round fixes (2026-08-23)

Schema `SCHEMA_VERSION` 0.1.3 → **0.1.4** (new golden dir
`tests/fixtures/records/0.1.4/`, MANIFEST block pinned; 0.1.0–0.1.3 untouched)
* `EvidenceItem.violated` — set when the post-command tree hash of the
  pristine verification copy differs from its pre-command hash, i.e. a
  verification command modified the tree it ran in.

Advisor-round fixes (Codex, block conditions 1-15; each with a test)
* Downstream stages consume the REDACTED persisted records, so a fresh call
  and a cache replay hand the next model byte-identical bytes.
* Judge/summarizer run in an empty private directory, never the snapshot.
* Verification runs on a pristine COPY; the original's tree hash is asserted
  unchanged; `pytest` commands carry `-p no:cacheprovider`.
* Nothing but `RunWriter` output lives under `runs/`; scratch, sanitized and
  verification copies live under the policy `scratch_dir`, swept at startup.
* STOP is re-checked after the retry backoff; resume is idempotent and waits
  for a killed group; the executed-request dedupe set survives resume.
* Cache paths are realpath-contained; the scan runs last; corrupt cell
  ledgers are charged pessimistically; `key.json` spans must be ordered;
  the scorer follows no symlinked cell directories.
* `os.killpg` absence is resolved at call time; SIGINT records a
  `RetryAttempt`; writer errors are never swallowed.

The version bump rides with the schema bump per the INVARIANTS rule (a
serialization change bumps `eris.version` in the same change).

## 0.3.0 - Milestone 2b: end-to-end harness (2026-08-23)

Schema `SCHEMA_VERSION` 0.1.2 → **0.1.3** (new golden dir
`tests/fixtures/records/0.1.3/`, MANIFEST block pinned; 0.1.0–0.1.2 untouched)
* New records (all `mechanically_observed`): `EvidencePack`, `RetryAttempt`
  (the retry DECISION), `ScanResult` (pattern hashes + counts only),
  `SnapshotSanitization`, `ArmRun`. New enums `ErrorClass`, `RetryDecision`,
  `Arm`, `ArmStatus`; `Stage` gains `verify` and `summarize` (F6).
* Field additions: `Invocation.{prompt_sha256, reused_from, pgid, warning}`,
  `CostRecord.{estimated, cost_known}`, `Proposal.evidence_requests`,
  `Adjudication.evidence_requests`, `EvidenceRequest.expect_exit_code`.
* Policy: `WorkerPolicy.{sanitize_snapshot, role_tools}`, `Policy.cache_dir`
  (never under `runs/`), `Budgets.per_campaign_usd`,
  `verify.{max_requests_per_run=12, max_wall_s=1800}`, `sanitize.{strip_names,
  strip_dirs}` (additions to the enforced R3.1 minimum), `scan.patterns_from_policy`.
  `default.yaml`: agy and grok get `sanitize_snapshot: true`.
* Coverage floor 80 → 90.

New modules (Phase 1; each requirement has a named test)
* `eris.retry`: pure classification (`classify`, pattern table as data,
  tested against the captured fixtures: T2 budget, E2 401, A7/A5/A8 agy,
  E17 grok, grok `cancelled`), backoff schedule (timeout 30 s × attempt,
  transient 10·2^(n-1), malformed 0), retry weight budget (3; timeout
  weight 2; malformed_output cap 2), judge TIMEOUT terminal; `BudgetLedger`
  (known vs reserved spend, per-run and per-campaign pre-check, timeouts
  reserve 2× `per_call_usd`); `run_with_retry` driver: every attempt =
  `Invocation` + `CostRecord` + `RetryAttempt`, `retry.scheduled` before the
  injected sleep, STOP between attempts, money pre-check before every spawn
  (F4: `BUDGET_TRIPPED` is produced; the claude cap-trip envelope is recorded
  with status `BUDGET_TRIPPED` and its real cost), writer errors propagate.
  `WorkerResult.pgid` / `SpawnResult.pgid` record the process group.
* `eris.cache`: worker-call cache under `cache_dir` (never under `runs/`;
  refused). Entry file = sha256 of its redacted bytes (they come out of
  `RunWriter.put_blob`), `keys/<idempotency_key>` pointer, blob copies.
  HIT requires hash == name, key/prompt/`executable_sha256` (current pin)
  match, current `schema_version`, status ok, `scan_hits == 0`, model known,
  same campaign unless `reuse_across_campaigns`; lstat + `O_NOFOLLOW`
  reads; any failure is a reasoned miss. Write-once (`O_EXCL`); a differing
  entry under the same key is a `conflict`, never an overwrite; `fresh`
  skips the lookup. `replay_hit`: blobs re-enter the run through
  `put_blob` (hash must survive re-redaction), the cached `Invocation` is
  re-appended with `reused_from`, `CostRecord(counted=False)`,
  `invocation.reused`. No `O_NOFOLLOW` (Windows) → `CacheUnsupported`
  (documented refusal). `executable_sha256` joined the idempotency key
  material (`idempotency_material`).
* `eris.sanitize`: per-worker snapshot copy with instruction files
  stripped (agy A15 / grok E1). Strip list = policy `sanitize` on top of
  the enforced minimum, matched by name at any depth, case-insensitively,
  slash entries as path suffixes; a match strips a file, a directory (every
  file recorded) or a symlink (`AGENTS.md` as a symlink, `.agents` as a
  file). Files get new inodes (no hardlinks); symlinks are kept only when
  relative, inside the tree and not into a stripped entry, else dropped and
  recorded; `.git` copied without `hooks`; no `.git` is fine; fifos refused.
  `SnapshotSanitization` records profile / original / copy tree hashes.
  `sanitized_copy()` context manager: private dir under the run scratch,
  removed in `finally`, cleanup failure raised (`SanitizeCleanupError`).
  Tests pin the original's tree hash + inodes and agy's `--add-dir` == copy.
* `eris.scan`: contamination tripwire (detect only). Patterns derived at
  run time (source-repo path, `athena-assistant`, `eval/corpus/`,
  `key.json`, `~/.claude/projects`, `~/.codex/sessions`,
  `~/.gemini/antigravity-cli/brain`, key.json fix-hunk lines + extra
  strings, policy strings; never `must_mention`), whitespace-folded;
  dropped (counted, never listed) when shorter than 12 chars (the fixed
  markers are exempt), present in the pre-fix tree, or contained in the
  harness's own recorded paths (`known_texts`: the snapshot/run dirs Eris
  writes into `run.started` / `Invocation.cwd` — a spec gap, see report).
  Scans every blob, every event payload, the pack and reused cache
  entries; `scan_incomplete` on truncated stdout or empty-stdout TIMEOUT;
  `scan.result` carries `ScanResult` (pattern hashes + counts only);
  re-scanning over the scan event adds no hits.
* `eris.evidence`: `TaskSpec` (task.json, strict), the evidence pack built
  once per (task, repeat) on the ORIGINAL snapshot — question
  (`document_quote`/`human_entered`), plan text, `git show` diff, repo
  facts (`git rev-parse HEAD`, `status --porcelain`, `ls-files`, `log
  --oneline -n 20`), the task battery and confined, capped file excerpts —
  every byte through `put_blob` before it is hashed; content-derived ids
  `ev-<sha[:16]>` identical across runs; the rendered pack carries no
  timestamp or run id; `pack_sha256` = the pack blob; refusals are
  `verify.refused`/`evidence.refused` events and the pack still builds
  (`pack.incomplete`). `execute_evidence_requests`: `run_allowlisted` on the
  original, refusals as events (challenge stays UNVERIFIED), dedupe by
  canonical argv (`verify.duplicate`), `max_requests_per_run` /
  `max_wall_s` caps, STOP before every command (`EvidenceStopped`),
  `expect_exit_code` recorded next to the observed code. `verify_scratch`:
  private HOME under the run dir, removed in `finally`, cleanup failure =
  `run.error` + `EvidenceCleanupError`. `derive_nonce` per plan §C.

* `eris.stages` (Phase 2, step C): frozen prompt files
  `eval/prompts/{proposer,critic,adjudicator,summarizer}.md` (ROLE/RULES;
  sha256 recorded per run); Eris appends a DATA section — ONE canonical JSON
  document between deterministic nonce delimiters (`derive_nonce`; a nonce
  inside the data → `[NONCE]` + `envelope.nonce_collision`) — and an OUTPUT
  SCHEMA section (`wire_schema`: `$defs` inlined, `additionalProperties`
  false, all keys required). Prompt > 256 KiB → `LaunchRefused` (never
  spilled). Wire models `ProposalOut` / `CritiqueOut` / `AdjudicationOut`
  (`extra=forbid`): model-supplied ids / `origin` / engine fields are
  `malformed_output` (retried with the identical prompt, cap 2, then
  `worker.absent`); `Record.model_validate(model_json)` is never called; Eris
  assigns ids (`clm-<key[:12]>-<i>`, `fnd-…`, `<key[:12]>-p<k>-c<n>`,
  `dis-…`). Critics see proposals + evidence only (one prompt hash across
  critics, lens `framing`); judge/summarizer are text-only (`role_tools`,
  `tools: []`) and receive evidence blocks (16 KiB head+tail), `P1..Pn`
  (`proposal.labels`), `C1..`, verification items — executable basenames
  only, never host paths or other stages' instructions. After the judge:
  `enforce_rulings` → `adjudication.raw`, `adjudication.enforced`,
  `validate.findings`. Cache hits replay through `replay_hit`; fresh OK
  calls are stored after the run's scan with their `scan_hits`.
  `run_with_retry` gained `output_check` (the wire-model parse).
  `default.yaml`: dedicated `judge` worker (claude, `tools: []`, timeout
  300; judge TIMEOUT terminal) and `containment: null` (declared, gated by
  the scorer). Evidence-id material now uses the executable basename.

* `eris.arms` (step E): the arm table as data (`single`, `consensus`,
  `indep_verify`, `indep_verify_iter`, `indep_verify_critique`; fixed
  order) and ONE sequential runner. Propose calls are shared across arms
  (paired ablation: one set of propose spawns for 3/3b/4, `invocation.reused`
  in 3b/4, equal blob hashes, different adjudicator prompt hashes, arm 3's
  judge never sees critiques; no `Invocation` carries an arm; `single`
  reuses the panel proposal). STOP is checked before every step and before
  every worker call (the first attempt of the next cell never spawns); a
  budget trip marks the cell missing and skips the remaining stages
  (`stage.skipped{reason: budget}`). `adjudicate_iter`: the judge's own
  requests are executed and the judge re-run (cap 3; no new proposals or
  critiques). Consensus records `adjudication.raw` and `.enforced` from the
  summarizer. Resume: `load_prior` replays finished stages whose blobs
  re-hash (a tampered blob re-runs that worker), writes
  `invocation.abandoned` + a pessimistic cost for an open attempt, returns
  the pgids from `invocation.spawned` (new launcher `on_spawn` hook);
  `kill_stale_groups` (SIGTERM then SIGKILL; refused with a documented
  message without `os.killpg`), `remove_stale_scratch`. `eris.ledger`:
  read-only validated ledger view + cost totals (spent vs attributed, by
  stage), shared with the scorer.

* `eval/run.py` (step G): `run` (one cell: task × repeat × arm;
  `--resume <run_id>`), `campaign` (every cell of a corpus under
  `runs/<campaign_id>/`, task-major → repeat → arms in the fixed order,
  `single` expanded per panel worker, its own writer/lock, `--dry-run`
  prints the order, `--resume` skips finalized cells and resumes unfinished
  ones, per-campaign budget base from the cell ledgers), `campaign status`
  (read-only, no writer, no lock). Per cell: `run.started` (prompt file
  hashes, containment, snapshot sha), sanitized copies for
  `sanitize_snapshot` workers (removed in `finally`), verify scratch,
  scan patterns from the sibling `key.json` (opened for this only),
  `scan.result` before finalize, cache stores after the scan, `ArmRun`,
  manifest extras (status, contaminated, scan_incomplete, stopped, spent
  known/reserved). STOP files `runs/STOP` / `runs/<campaign>/STOP`. SIGINT
  handler installed ONLY by `run`/`campaign`: the launcher kills the worker
  group on the existing path, `invocation.finished` (failed, `interrupted`,
  cost not known), `run.interrupted`, `cell.interrupted`, exit 130, run dir
  left resumable (`invocation.spawned` carries the pgid). Exit codes
  0/2/3/4/5/6/7/130. Stderr: one JSON line per stage event
  (`RunWriter(on_event=…)` observer). `launch.spawn` kills the group on
  `KeyboardInterrupt` before re-raising (cleanup, not a handler).

* `eval/score.py` (step K): read-only scorer over `runs/<campaign>/` +
  `eval/corpus/` (AST guard: no subprocess/socket/httpx/os/`eris.launch`/
  `eris.verify`; a read-path audit test proves it opens nothing outside the
  runs dir and the corpus). `key.json` v1 format (strict): `task_id`,
  `category`, `expected_verdict[]`, `line_tolerance`, `findings[{id, path,
  line_start, line_end, severity, must_mention[]}]`, `distractors[]`,
  `scan{fix_hunk_lines, extra_strings}`, `injection_canary?`,
  `source_repo?`. Per cell: ledger validated (invalid → listed, not
  scored), re-scan with the current key, contaminated / `scan_incomplete`
  → excluded from quality metrics but costed, BUDGET_TRIPPED → `missing`,
  incomplete panel or judge → `incomplete`. **E1 gate**: `revert` /
  `planted` / `insufficient` require `ArmRun.containment == "container"`
  (exit 7, no metrics, no CLI override); `control` / `plan` score normally.
  Metrics: precision/recall (path + line overlap within tolerance +
  `must_mention`; 0/0 → None), distractor hits (FP), unsupported-claim rate
  from `adjudication.enforced.downgrades`, confident-wrong (ACCEPT off-key
  or a high/critical FP), abstention 2×2, cost spent AND attributed by
  stage (+ unknown-cost count), wall, attempts. Arm 1 findings come from
  the proposal; arm 2 is scored on the RAW summarizer verdict; paired
  deltas 3b−3 and 4−3 per (task, repeat) only with identical `propose_keys`.

Advisor round (Codex review, 15 items; each with a test - `docs/INVARIANTS.md`
"Advisor round"):
* (1) downstream records are the REDACTED ones the writer persisted (fresh
  == cache-hit bytes); (2) the judge/summarizer runs in an EMPTY private dir;
  (3) the scorer cross-checks `key.json` `task_id`/`category` against the
  ArmRun and states that `containment` is a declaration; (4) verification
  runs in a PRISTINE copy with a tree-hash guard (`snapshot.violated`,
  `EvidenceItem.violated` - schema 0.1.3 → **0.1.4**, new golden dir +
  pinned block), pytest `-p no:cacheprovider`; (5) every ephemeral file
  lives under `Policy.scratch_dir` (default `cache/scratch/<run_id>/`),
  never under `runs/`, swept at startup; (6) STOP re-checked after the
  backoff sleep; (7) idempotent resume + waited group kill; (8) the request
  dedupe set survives resume; (9) cache realpath containment; (10) the final
  scan is the last event before finalize, stderr/output-file truncation →
  `scan_incomplete`, no ScanResult → refused when gated; (11) wire models
  without defaults, strict, semantic violations retryable; (12) corrupt cell
  ledgers reserved pessimistically, the resumed cell never counted twice;
  (13) key span order, symlinked cell dirs ignored, real AST allowlist;
  (14) `os.killpg` resolved at call time; (15) SIGINT `RetryAttempt`, writer
  errors never swallowed.

Flakiness root cause (item 9 of the Phase 2 instructions): `launch.spawn` let a `PermissionError`
(macOS `killpg` EPERM while a dead group member is an unreaped zombie)
escape with the worker's pipes open; the leaked fds' `ResourceWarning`
finalizers then failed whichever unrelated test was running under
`filterwarnings = error` (`test_repo_default_policy…`, the 50 MB redaction
test). Fix: the SIGKILL sweep retries EPERM briefly and refuses loudly only
if it persists; `spawn` closes the pipes on every exit path. Two tests.

Docs: INVARIANTS rows for every M2b rule; PROTOCOL stage contracts;
SECURITY (sanitization + residuals, scan + false-negative limits, cache,
prompt envelope, retry/budget/STOP/resume/SIGINT, A17, E17); EVAL-PLAN
(runnable now, arm-2 raw-scoring note, plan-category caveat, A17/E17 rows,
E16 built); README/AGENTS/ARCHITECTURE mention `run`/`campaign`/`score`.

Defect fixes (step A; each with a test)
* F1 `parse_claude` keeps usage/cost/model names on `is_error` and composes
  the message from subtype/terminal_reason/errors (T2 capture: the
  `--max-budget-usd 0.10` cap tripped at $0.129 — the cap overshoots).
* F2 `invocation_id` is unique per attempt: `inv-<key[:16]>-a<n>`.
* F3 "OK with error" → status OK + `warning` (`WorkerResult.warning`,
  `Invocation.warning`); `error` is None on OK.
* F5 `RunWriter` re-hashes every blob on resume; a blob that does not hash
  to its name (or is a symlink) is reported in `corrupt_blobs`, not indexed.
* `parse_codex` unwraps the `turn.failed` error object (E2 401 capture);
  `parse_grok` surfaces `{type: error, message}` (E17 403 refusal).
* Fixtures: `claude/2.1.239/budget_tripped.json`, `codex/0.147.0/auth_401.jsonl`,
  `grok/1.0.5/api_error_403.json` with provenance sidecars.

## 0.2.0 - Milestone 2a: Antigravity `agy` worker, E-experiment results (2026-08-22)

Added
* `agy` (Antigravity CLI 1.1.18) replaces the uninstalled `gemini` CLI as the
  Google lineage. `build_argv_agy`: `-p <prompt> --model <m> --mode plan
  --sandbox --add-dir <snapshot realpath> --output-format json
  --disable-slash-commands --print-timeout <N>s [--json-schema <inline>]`
  (canonical order) with `N = timeout_s - 30` above 60 s else
  `max(1, timeout_s // 2)`, always strictly below `timeout_s` (`timeout_s`
  < 2 refused for agy); `parse_agy` (status ERROR → FAILED with the worker's
  message, usage retained, `structured_output` preferred, no model id / cost;
  `duration_seconds` accepted only when finite in `[0, 1e7]`). Nine captured
  agy envelopes are fixtures (A7/A8/A10b/A14/A15/A16 sidecars carry
  reconstructed, labelled argv).
* Advisor fixes (Codex, MERGE-AFTER-FIXES): parser exceptions are contained
  in `_execute` (`run_worker` never raises); `timeout_s`/`max_*_bytes` are
  strict ints (`timeout_s` in `[1, 86400]`); the 0.1.2 manifest block is
  pinned by hash like 0.1.0/0.1.1 (committed = immutable); the lineage guard
  is `^gemini-\S+$` and documented as syntactic; the fixture username guard
  is a portable path-pattern scan.
* `--add-dir` is REQUIRED for agy (A14: without a declared workspace agy
  cannot read even its own cwd; A16: with it, reads outside are denied — the
  valid E1 pass). Exactly one, equal to the spawn cwd, re-checked element by
  element in `plan_call` (`assert_agy_workspace`).
* `eris.policy`: `CliName` is `claude|codex|agy|grok`; lineage guard - an agy
  worker must declare a `gemini-*` model. `policies/default.yaml`: agy entry
  (google, `gemini-3.1-pro-high`, `AGY_CLI_DISABLE_AUTO_UPDATE=1`),
  `~/.gemini/antigravity-cli/settings.json` among the credential files.
* `FORBIDDEN_ARGV_TOKENS` += `accept-edits`, `--continue`, `--conversation`,
  `--prompt-interactive`, `--input-format`, `--new-project`, `--project`,
  `--agent`, `--log-file`; an exact-element test proves the agy builder never
  emits `-c`. NEVER env += `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_GEMINI_BASE_URL`, `AGY_ADC_AUTH`,
  prefix `ANTIGRAVITY_`.
* `parse_grok` reads `structuredOutput` (E9 capture); claude E9/E8b captures
  added as fixtures.
* `SCHEMA_VERSION` 0.1.1 → **0.1.2**: `Invocation.conversation_id` and
  `Invocation.worker_reported_duration_ms` (optional). New goldens under
  `tests/fixtures/records/0.1.2/` + manifest entry; 0.1.0/0.1.1 untouched and
  their manifest blocks are now pinned by hash in the test.
* `eris doctor`: `worker.<id>.state` reports the size of agy's
  brain/conversations directories (WARN ≥ 256 MiB); never deletes them.
* Suite-wide fixture guards (`tests/test_fixtures.py`): no redaction literal
  (home dir / username, derived from the environment) under `tests/fixtures`;
  every capture has a `.meta.json` with its argv. `tests/test_no_gemini.py`:
  no gemini builder/parser/literal in `src/eris`.
* Docs: EVAL-PLAN results for E1/E1b/E2/E7/E8/E8b/E9 and A1–A11; SECURITY
  E1 consequence + containment options (USER DECISION, option 1 recommended)
  and the agy section; INVARIANTS rows for every new test.

Removed
* `build_argv_gemini`, `parse_gemini`, `first_balanced_json` (its only
  caller), the `gemini` worker and `PER_CLI_ENV["gemini"]`.

Known caveats (documented, not resolved)
* **agy injects the declared workspace's `AGENTS.md`/`GEMINI.md` rules**
  (A15 replied `MANGO KIWI`); no opt-out flag. A9/A11's "no injection" was
  vacuous (no workspace declared). Mitigation — per-worker snapshot
  sanitization (strip `AGENTS.md`/`GEMINI.md`/`CLAUDE.md`/`.agents/` from the
  agy worktree copy, recorded in the manifest) — is Milestone 2b
  (`TODO(m2b)` at `build_argv_agy`). Until then agy output is exposed to
  repo-authored instructions, same class as grok.
* agy prints `warning: --mode plan has no effect while slash command
  expansion is disabled.` under the required argv; the observed denials come
  from its non-interactive permission check. Re-verify on version change.
* `AGY_CLI_DISABLE_AUTO_UPDATE` name from binary strings; effect ASSUMPTION.
* Which model agy executed is unobservable (`model_executed=None`).

## 0.1.1 - schema versioning discipline (2026-08-22)

* `SCHEMA_VERSION` 0.1.0 -> 0.1.1. The `Invocation` record gained four optional
  fields (`output_file_sha256`, `output_file_size`, `output_file_truncated`,
  `cleanup_error`) during the M1 advisor rounds; the 0.1.0 golden had been
  regenerated in place, which is exactly the habit this entry ends. The
  original 0.1.0 goldens are restored (immutable history) and 0.1.1 goldens
  are generated from `tests/examples.py`.
* `tests/fixtures/records/MANIFEST.json` pins the sha256 of every golden of
  every committed version; `test_committed_goldens_are_immutable` fails on
  any edit to a committed version directory.
* `Record.schema_version` is validated against the current `SCHEMA_VERSION`
  at parse time: no migrations exist in 0.x, so an old record is refused
  rather than silently reinterpreted (`test_old_schema_versions_are_rejected_on_parse`).
* Package version 0.1.0 -> 0.1.1 (`src/eris/version.py`).

## Unreleased - advisor review fixes (2026-08-22)

Round 2 (remaining BLOCK conditions)
* Codex scratch: per-call dir created with `exist_ok=False` (existing entry
  or symlink refused, symlinked parent refused) under the run's scratch,
  which the harness creates only after the writer holds the lock; `-o` is
  `lstat`-checked and opened `O_NOFOLLOW`; `rmtree` failures are reported
  (`cleanup_error` on the result and Invocation, `run.error` event, exit 4).
* `output_file_truncated` / `output_file_size` on `WorkerResult` and
  `Invocation` (golden `invocation.json` regenerated: four optional fields).
* `--snapshot-sha` flag dropped; the base commit is read from `.git` only.
* Doctor skips every probe after a credential-file parse failure.
* Full `git <sub> -h` + man captures for all declared subcommands added to
  `tests/fixtures/help/`; the policy test requires each git flag to appear
  in at least one declared subcommand's help; `--no-pager` (a global
  option) dropped from the policy.
* Docs/docstrings aligned with the code (forbidden tokens exempt the
  prompt; mypy `--plugins` gone; snapshot checks cover every object; only a
  partial final line is a torn write).

Fixed (each with a test that would have caught it; see docs/INVARIANTS.md)
* `verify.run_allowlisted` takes raw argv and re-validates immediately
  before spawn; a forged `Decision` can no longer execute.
* Timeout kill path always sweeps the process group with SIGKILL after the
  leader exits (members that ignore SIGTERM are now killed).
* Codex `-o` output is read into memory and deleted; nothing unredacted
  stays on disk; the per-call scratch dir is removed in `finally`.
* `eval/run.py` validates run ids (`^[A-Za-z0-9_-]{1,64}$`) before building
  any path and checks containment under the runs dir.
* Executable preflight resolves and hashes the realpath and executes it.
* Hard deny lists reconciled against captured `--help` of the pinned tools
  (`tests/fixtures/help/`); `--plugins` (not a mypy flag) removed; ruff
  `--line-length` and pytest `-rN` removed from the policy allowlist
  (`-r` is now a value flag).
* Writer: a complete but unparsable last line is INVALID, not a torn tail;
  directories are fsynced at creation.
* Snapshot builder records future commits, trees AND blobs; the verifier
  checks every object id.
* Doctor never probes an unpinned/mismatched binary; probe output is
  redacted.
* `model_executed` is None unless `modelUsage` names exactly one model;
  forbidden-token scan exempts the prompt element.
* `credential_files` corrected to the four files that exist on this machine;
  a missing file is a warning, an unparsable one fails closed.
* Idempotency key includes the snapshot base commit (`snapshot_sha`).

## 0.1.0 - 2026-08-22 - Phase 0, Milestone 1 (harness, no engine)

Added
* Tooling: `pyproject.toml` (src layout, ruff E4/E7/E9/F/B/I + format, mypy
  strict with the pydantic plugin, coverage floor 80 on `src`+`eval`),
  exact pins in `requirements.txt` (all install on Python 3.14.2),
  `Taskfile.yml`, pre-commit, CI matrix 3.12/3.14 with blocking pip-audit.
* `tests/conftest.py`: three autouse hermeticity guards (`shutil.which` for
  worker binaries, every subprocess entry point, sockets), `real_subprocess`
  marker, `FakeProcess` fixture.
* `eris.schemas`: all records with `origin`, canonical bytes, golden
  fixtures under `tests/fixtures/records/0.1.0/`.
* `eris.validate`: engine rules as findings; `enforce_rulings` with
  escalation at 3 downgrades; ledger chain validation.
* `eris.policy` + `policies/default.yaml` + `eris policy pin`.
* `eris.redact`: pattern set, fold view, base64 rematch, exact values.
* `eris.writer.RunWriter`: the single redacting, fsync'd, flock'd path to
  `runs/`.
* `eris.launch`: per-CLI argv builders, env from `{}`, hardened spawn,
  envelope parsers pinned to captured claude 2.1.239 / codex 0.147.0 /
  grok 1.0.5 envelopes (`tests/fixtures/envelopes/`).
* `eris.verify`: allowlist grammar with hard deny lists.
* `eris.snapshot`: history-truncated snapshots with a pure verifier.
* `eris.doctor` / `eris doctor`: names-only preflight with flock probe.
* `eval/run.py`: `preflight`, `dry-run`, single-worker `invoke`.
* Docs: PROTOCOL, ARCHITECTURE, SECURITY, INVARIANTS, EVAL-PLAN.

Deviations from the plan (see the M1 report)
* Extra validator codes beyond the plan's list: `REFUTED_WITHOUT_REFS`,
  `CLAIM_MISSING`, `MALFORMED_LINE`, `ESCALATED` (info).
* Executable pins live in a gitignored `policies/pins.yaml` sidecar merged at
  load, instead of being rewritten into `default.yaml`.
* The `real_subprocess` marker accepts `allow=["git"]` for the single
  snapshot integration test.
* `types-PyYAML` pinned at 6.0.12.20250915 (the plan gave no version).

Not built (Milestone 2): arms, critique/adjudicate stages, `eval/score.py`,
API workers, corpus keys, `eval/README.md` pre-registration.
