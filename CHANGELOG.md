# Changelog

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
