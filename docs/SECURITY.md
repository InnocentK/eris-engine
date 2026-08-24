# Security model (Milestone 1 + 2a + 2b)

Single-user, self-hosted. The threat model is accidental: a worker CLI that
reads or writes where it should not, a secret that reaches the ledger, a
repository that injects instructions, a model-proposed command that executes.
Adversarial repositories are OUT of scope until containers (Phase 3).

## E1: every worker except agy reads outside the snapshot — USER DECISION

Measured 2026-08-22 (`docs/EVAL-PLAN.md`, E1/E1b/A10b): claude (plan mode,
`--tools Read,Grep,Glob`), codex (`-s read-only`) and grok (plan mode, also
with `--sandbox strict`) all read and printed canary files in the snapshot's
parent and sibling directories. Read-only modes confine WRITES, not reads.
Only agy refused: with `--add-dir <snapshot>` declared it read inside the
workspace (A15) and denied `read_file` of absolute paths outside it (A16) —
its in-process permission check, policy, not the kernel. (A10b's earlier
"pass" was vacuous: without `--add-dir` agy cannot read even its own cwd,
A14.)

**Consequence.** On this host a worker can read the Athena working tree
(which contains every fix the corpus hides), the answer keys under
`eval/corpus/`, and the vendors' memory/session stores. Any defect-detection
or ABSTAIN result obtained before containment is not evidence.

**Options** (security critic, 2026-08-22; none is built in M2a):

1. **A dedicated low-privilege macOS user runs the workers** — uniform and
   kernel-enforced (file permissions), keeps each CLI's own sandbox working,
   no nested seatbelt. Cost ≈ half a day plus re-login of all four CLIs as
   that user. **RECOMMENDED.**
2. **Docker with only the snapshot mounted** — strongest isolation; Linux
   builds and OAuth for agy are UNKNOWN; 1–2 days.
3. **Move Athena + keys off-disk during runs** — still leaks the vendors'
   memory stores; rejected as the primary control.
4. **Accept + scan envelopes for the Athena path / fix hunks** — detects, does
   not prevent; valid for plumbing and clean-control runs only.
5. **Per-worker read confinement on the host** — heterogeneous and partly
   disproven: grok's documented strict sandbox FAILED (E1b); codex's
   restricted-read profile path set is unknown; claude's is policy-only;
   agy's is policy-only.

**DECISION (user, 2026-08-22): option 4 — accept and scan, plumbing and
clean-control runs only.** Rationale: Eris is to be deployed across Debian
LXC, macOS (Apple silicon and older Intel), CachyOS and Windows 11, so a
per-host privileged-user recipe (option 1) is the wrong shape, and Docker
(option 2) is a large lift for what E1 needs now. Consequences that code and
docs must keep honoring:

* `eval/score.py` refuses to score defect-detection or ABSTAIN categories
  (`revert`, `planted`, `insufficient`) unless `ArmRun.containment ==
  "container"` (exit 7, no metrics, no CLI override); `control` and `plan`
  score normally. `containment` is a policy DECLARATION (`containment: null`
  in `default.yaml`), not a verification, until M2c builds the container.
  BUILT (M2b): `tests/test_score.py::test_e1_gate_refuses_defect_categories_without_containment`.
* The envelope/ledger scan for the Athena path, `athena-assistant`, answer-key
  strings and fix-hunk lines is BUILT (`eris.scan`, M2b; see "Contamination
  scan" below); a hit marks the run `contaminated` (detects, never prevents).
* The eventual portable containment is container-based (Docker/Podman on
  Linux, macOS, Windows; a Debian LXC is itself a container but does not
  confine the workers' reads *within* it). Per-OS user tricks are out.

## Boundaries that code enforces

### Worker processes (`launch.py`)
* Read-only flags per CLI, verified by experiment on 2026-08-21/22
  (`tests/fixtures/envelopes/*/*.meta.json`): claude `--safe-mode
  --permission-mode plan --tools <list>`; codex `exec -s read-only --ephemeral
  --ignore-user-config --ignore-rules -c project_doc_max_bytes=0`; grok
  `--permission-mode plan --disable-web-search`; agy `--mode plan --sandbox
  --add-dir <snapshot realpath> --output-format json
  --disable-slash-commands --print-timeout <N>s` (see the agy section below
  for what each part actually enforces).
* `--bare`, `bypassPermissions`, `workspace-write`, `danger-full-access`,
  `yolo`, `--dangerously-skip-permissions`, `--full-auto`, `acceptEdits`,
  `--skip-trust`, `--allow-all`, and (agy) `accept-edits`, `--continue`,
  `--conversation`, `--prompt-interactive`, `--input-format`,
  `--new-project`, `--project`, `--agent`, `--log-file` are refused,
  case-insensitive, as substrings of every argv element EXCEPT the prompt (a
  reviewer may legitimately quote them); the prompt itself may not start with
  `-`. agy's short `-c` (continue a conversation) is NOT a substring token —
  it would hit codex `-c project_doc_max_bytes=0` and git `--cached` — so an
  exact-element test proves the agy builder never emits it.
* Env built from `{}`. NEVER list: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`,
  `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PYTEST_ADDOPTS`,
  `PYTEST_PLUGINS`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `NODE_OPTIONS`,
  `NODE_PATH`, `PERL5OPT`, `BASH_ENV`, `ENV`, `ZDOTDIR`,
  `GEMINI_CLI_TRUST_WORKSPACE`, `EDITOR`, `VISUAL`, `GEMINI_API_KEY`,
  `GOOGLE_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`,
  `GOOGLE_GEMINI_BASE_URL`, `AGY_ADC_AUTH`, and prefixes `LD_`, `DYLD_`,
  `GIT_`, `AWS_`, `PYTEST_`, `CODEX_SANDBOX`, `ANTIGRAVITY_`. `AGY_` is not
  blanket-banned (the policy sets `AGY_CLI_DISABLE_AUTO_UPDATE`). The only
  `GIT_*` allowed are Eris's own four hardening values.
* The allowlist is exact and is pinned by a test
  (`test_launch.py::test_env_key_set_is_exact_for_every_cli`): locale/pager
  hygiene, `PATH`, `HOME`, `TMPDIR`, `USER`, the git hardening values and the
  per-CLI knobs, plus whatever the policy's `env`/`env_allow` names add.
  `USER` is there deliberately (M2c, 2026-08-23). Without it `claude` reports
  `Not logged in · Please run /login` while `claude auth status` says
  `loggedIn: true` — bisected on this machine: `HOME` + `PATH` + `TMPDIR`
  fails, adding `USER` fixes it, `LOGNAME` alone and `SHELL` alone do not. It
  is an account name, not a credential, and is on no NEVER list; it is
  resolved from the OS (`launch.resolve_user`: the passwd database first,
  `getpass.getuser` as the portable fallback), never read out of a filtered
  `os.environ`, and it is omitted rather than invented when the account cannot
  be determined (`eris doctor` warns). API workers do not get this environment
  at all — they are HTTP calls with no subprocess. Mechanical VERIFICATION
  commands (`build_verify_env`) also do not get `USER`: git, ruff, mypy and
  pytest do not authenticate.
* `USER` is not attacker- or policy-controllable. A policy `env` or an
  `env_allow` secret that names `USER` is REFUSED, and the OS-derived value is
  written LAST so nothing already in the dict can override it. `getpass` is a
  fallback only where it cannot be answering out of the environment (it reads
  `LOGNAME`/`USER`/`LNAME`/`USERNAME` before the passwd database); an
  environment-derived answer counts as unresolved and `USER` is omitted, so a
  stray `export USER=` cannot choose the account a worker CLI is told it is
  running as. On Windows that means no `USER` at all — a deliberate,
  documented refusal, reported by `eris doctor`. The doctor prints
  `USER: resolved`, never the account name.
* Pinned executable path + sha256 checked immediately before spawn; a changed
  binary is refused. Pins are machine-specific (`policies/pins.yaml`).
* `stdin=DEVNULL`, `shell=False`, `start_new_session=True`, stdout and stderr
  byte caps drained concurrently. On timeout: SIGTERM to the process group,
  wait for the leader, then ALWAYS a SIGKILL sweep of the whole group (a
  member that ignores SIGTERM or outlives the leader is still killed).
* The pinned path is resolved to its realpath; the realpath is hashed and is
  what is executed (argv[0]), so a retargeted symlink cannot swap the binary
  between check and exec.
* Codex's `-o` last-message file is read into memory (without following
  symlinks; a non-regular file is refused unread) and deleted inside
  `run_worker`; the per-call scratch directory is created fresh (existing
  entry or symlink refused) under the run's tmp after the writer holds the
  lock, and removed in `finally`. A cleanup failure is reported as
  `cleanup_error` and becomes a `run.error` event (exit code 4), never
  silent. Oversize files are capped and flagged `output_file_truncated`.
* `model_executed` is taken from the envelope only when it names exactly one
  model; otherwise it is `None` (never guessed). agy and codex emit no model
  id at all: `model_executed` is always `None` for them.
* A worker's prompt may not start with `-`.

### Antigravity `agy` 1.1.18 (Google lineage, M2a)
What each part of the required argv enforces, and what it does not:
* `--mode plan` is agy's IN-PROCESS policy (no repo write, shell denied —
  A2/A5). It is not an OS boundary. **Caveat (A6/A10/A10b/A11/A14–A16
  stderr):** `warning: --mode plan has no effect while slash command
  expansion is disabled.` With `--disable-slash-commands` present, the
  denials actually observed (write A6, shell A5/A6, read outside the declared
  workspace A16) come from agy's
  non-interactive permission check, which refuses every tool call it cannot
  prompt for. The set is kept as specified because it denied everything it
  was asked to deny on 1.1.18; it must be re-verified on any version change
  (`EVAL-PLAN.md` E11/E15).
* `--sandbox` is agy's OS seatbelt for TERMINAL commands only (per the
  profile strings embedded in the binary); it was indistinguishable from plan
  alone in A4. It must be DROPPED if Eris ever wraps agy in its own
  `sandbox-exec` (nested seatbelt fails; reproduced 4×).
* `--add-dir <snapshot realpath>` is REQUIRED and declares the workspace: agy
  reads only inside declared workspaces. Without it, `read_file` of
  `README.md` INSIDE the cwd is denied (A14, with and without
  `--disable-slash-commands`; A12 even tried `~/workspace`), so the earlier
  A10b "E1 pass" was vacuous. With `--add-dir $cwd` the inside read succeeds
  (A15) and absolute paths OUTSIDE the workspace are denied (A16, no canary
  leaked) — **E1 PASS for agy on a valid basis**, by its in-process
  permission check, not the kernel. The launcher emits exactly one
  `--add-dir` equal to the spawn cwd and `plan_call` re-checks it element by
  element (a second, missing or different workspace is refused).
* **Rules injection from the declared workspace is CONFIRMED** (A15: the
  reply began `MANGO KIWI`, the markers planted in the workspace's
  `AGENTS.md` and `GEMINI.md`). A9/A11 saw no injection only because no
  workspace was declared (vacuous). No opt-out flag exists. Mitigation =
  per-worker snapshot sanitization (`eris.sanitize`, BUILT in M2b; see
  "Snapshot sanitization" below): agy's proposer/critic roles run on a
  private copy with the instruction files stripped and `--add-dir` pointing
  at that copy (`test_sanitize.py::test_agy_add_dir_is_the_copy_root`).
  **A17 (2026-08-22):** with `--add-dir`, agy resolved an in-workspace
  symlink `LINK_TO_OUTSIDE.txt -> ../outside` to its real path and DENIED
  the read - agy's confinement resolves symlinks; the sanitizer's symlink
  drop is defence in depth, not the only control.
* Canonical argv order (the code is the reference; docs and sidecars follow
  it): `-p <prompt> --model <m> --mode plan --sandbox --add-dir <snapshot
  realpath> --output-format json --disable-slash-commands --print-timeout
  <N>s [--json-schema <inline>]`.
* `--print-timeout <N>s` with `N = timeout_s - 30` above 60 s, else
  `max(1, timeout_s // 2)` — ALWAYS strictly less than Eris's `timeout_s`,
  so agy's own timer fires first and emits a parseable `status ERROR`
  envelope (A7); Eris's `timeout_s` and the process-group SIGKILL sweep
  remain the backstop. A policy `timeout_s` below 2 s is refused for agy
  (no positive whole second is strictly smaller than 1). `timeout_s` itself
  is a strict int in `[1, 86400]` (no `"60"`/`60.0`/`true` coercion).
* Lineage guard (`eris.policy`): an `agy` worker must declare a model
  matching `^gemini-\S+$` because `agy models` also serves Claude and
  GPT-OSS ids. The guard is SYNTACTIC only: the envelope carries no model
  id, so which model actually executed is UNKNOWN (`model_executed=None`),
  and agy may silently default — the agy log for A9 said the requested id
  was "not in local config, defaulting".
* Parser containment: a parser exception (e.g. a malformed
  `duration_seconds`) never escapes `run_worker`; the result is FAILED with
  `<cli>: parser failure: …`, and `worker_reported_duration_ms` accepts only
  finite values in `[0, 1e7]` s.
* Residual, not enforced: every run writes a transcript and SQLite state under
  `~/.gemini/antigravity-cli/{brain,conversations}/` (≈1 MB/run; plan mode
  writes its implementation plan there too). Eris never deletes vendor state
  (lock races, not ours); `Invocation.conversation_id` lets
  `brain/<id>/` be located for audits, and `eris doctor` reports the
  directory sizes (WARN ≥ 256 MiB) — clean up manually.
* Residual, not enforced: agy spawns a background auto-updater that can change
  the binary under its sha256 pin. `AGY_CLI_DISABLE_AUTO_UPDATE=1` is set
  (name from the binary's strings; effect ASSUMPTION); the doctor reports a
  changed hash as FAIL ("re-pin deliberately").
* Auth is HOME-rooted (A8); the exact file is UNKNOWN.
  `~/.gemini/antigravity-cli/settings.json` is declared as a credential file
  for redaction even though, when inspected, it held only
  `enableTelemetry`/`trustedWorkspaces`.
* Hooks: no `.agents/hooks.json` SessionStart hook fired in A9/A11, but those
  runs had no declared workspace; whether hooks fire with `--add-dir` is
  UNKNOWN (EVAL-PLAN E11).

### Secrets (`redact.py`, `writer.py`, `policy.py`, `doctor.py`)
* Secrets live only in `.env`. A secret-shaped value in any policy or pins
  YAML refuses the load.
* The writer redacts BEFORE hashing. Pattern set: Anthropic, OpenAI, xAI,
  Google, AWS access key id, GitHub, Slack, JWT, PEM private key blocks,
  `Bearer` tokens, URL userinfo, `key/secret/token/password = value`
  assignments, plus exact values from `.env` and the declared credential
  files (held in memory only). ANSI/C1 stripped first; line-wrapped tokens
  folded; base64 runs >= 32 decoded and re-matched.
* Placeholders are `[REDACTED:<pattern_id>#<ordinal>]` - no hash, no prefix,
  no length of the secret.
* `eris doctor` prints key NAMES only.

Known limits of the redactor (documented, tested):
* A wrapped secret immediately followed by an alphanumeric line is
  indistinguishable from a longer secret; the following word is swallowed
  (over-redaction). A blank line ends a wrapped token.
* Whole-buffer semantics: `StreamRedactor` buffers until `flush`. Output size
  is bounded by the launcher caps.
* Patterns are shapes, not knowledge: an unusual secret with no recognisable
  prefix that is not in `.env` or a credential file will not be caught.
* Throughput is roughly 3 MB/s (50 MB in ~16 s on this machine).

### Mechanical verification (`verify.py`)
`run_allowlisted` accepts only RAW argv and re-runs `check_command` itself
immediately before spawning; there is no way to pass it a pre-made decision.
Allowlist, not denylist: unknown flags are refused. Executable realpath +
sha256 pinned; subcommand lists; literal flags; `flag value` / `flag=value`
regexes; positional paths must realpath-resolve inside the snapshot and never
into `.git/`; response files, `-`, control characters refused. A per-tool
hard deny list (git `-c`/`-C`/`--exec-path`/`--git-dir`/`--work-tree`/
`--ext-diff`/`--textconv`/`-O`/`--output`; pytest `-c`/`-p <plugin>`/`-o`/
`--rootdir`/`--import-mode`/`--basetemp`/`--pdb*`/`--junit-xml`/`--cov*`;
ruff `--config`/`--fix*`/`--add-noqa`; mypy `--config-file`/`--shadow-file`/
`--install-types`/`-c`/`-p`/`-m`/report flags) applies even if a policy
allowlists them. The deny lists were reconciled against the captured
`--help` of the pinned versions (`tests/fixtures/help/`, 2026-08-22) and a
test asserts every entry is a real flag of that version. `pytest` executes repository code (conftest.py) and is
refused unless the policy is `trusted: true`.

### Snapshots (`snapshot.py`)
History-truncated clones: `--no-local --depth N --single-branch`, origin
removed, `FETCH_HEAD`/`ORIG_HEAD`/hooks removed, no alternates. The verifier
proves every future OBJECT (commit, tree and blob, from `git rev-list
--objects --all --not <pre_fix>` in the source mirror) fails `git cat-file -e`.

### Ledger (`writer.py`)
One writer per run (`flock`), temp+fsync+rename for blobs and manifest,
append+fsync for events, hash chain. Only a partial (non-newline-terminated)
final line is truncated, and only on explicit resume; any complete invalid
line, including the last, is INVALID. Failures raise.

## Milestone 2b controls

### Snapshot sanitization (`src/eris/sanitize.py`)
Workers whose policy says `sanitize_snapshot: true` (agy and grok in
`default.yaml`) run their proposer/critic roles on a PRIVATE COPY of the
snapshot under the run's scratch dir, removed in `finally` (a cleanup
failure is a `run.error`, never silent). Verification ALWAYS runs on the
original. The strip list is the policy's `sanitize` section on top of an
enforced minimum (R3.1): `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`,
`GEMINI.md`, `GROK.md`; `.agents`, `.claude`, `.codex`, `.gemini`, `.grok`,
`.antigravity`, `.cursor`, `.github/copilot-instructions.md` - matched by
name at any depth, case-insensitively, whatever the entry is (a file, a
directory, or a symlink named `AGENTS.md`). Files get new inodes (never
hardlinks); symlinks are kept only when relative, resolving inside the tree
and not into a stripped entry (every other link is dropped and recorded);
`.git` is copied without `hooks`. `SnapshotSanitization` records the
profile hash, the original's tree hash, the copy's tree hash, every stripped
file (relpath, size, sha256) and every dropped link.

Removing the copy restores owner rwx on the REAL directories inside the copy
root (the copy preserves the original's directory modes, and a read-only
directory blocks the removal of its own entries). Nothing outside the copy
root is touched - never a parent, and never a symlink, so a link a worker
left pointing outside cannot be used to change the mode of anything else.
A removal error that is not a permission error propagates
(`SanitizeCleanupError`); it is never swallowed.

**Residual (in-band instruction channels that remain):** comments,
docstrings, READMEs and commit messages are still read by the worker; a
worker with git tools can still `git show HEAD:AGENTS.md`; the
`.git` objects are copied verbatim. Sanitization removes what the CLIs load
AUTOMATICALLY; it does not make a repository trustworthy. **E17
(2026-08-22):** grok, asked to quote any begin-reply instructions, replied
`None` (the API then refused the reproduction prompt with a 403 safety
check, fixture `grok/1.0.5/api_error_403.json`); E1's grok reply had begun
`MANGO PINEAPPLE`. Injection was observed once and not reproduced; grok is
sanitized anyway (cheap) and the result is recorded honestly.

### Contamination scan (`src/eris/scan.py`) - tripwire, detect only
Every run is scanned twice - once to decide the `ArmRun` and the cache
entries' `scan_hits`, and a FINAL time as the genuinely last event before
finalize (after `arm.finished`, the cache-store events, the snapshot check
and the scratch removal, so nothing can append behind it) - and re-scanned read-only by the scorer: every blob, every event payload, the rendered pack and any reused
cache entry. Patterns are derived at RUN TIME - the source repository's
path (`key.json.source_repo`) and `Path.home()`-rooted vendor memory stores
(`~/.claude/projects`, `~/.codex/sessions`,
`~/.gemini/antigravity-cli/brain`), the fixed markers `athena-assistant`,
`eval/corpus/`, `key.json`, the key's fix-hunk lines and extra strings, and
policy strings - whitespace-folded and sha256-named. The ledger carries
pattern hashes and counts ONLY (`ScanResult`); no fix-hunk text exists in
this repository or in any run. A hit marks the run `contaminated` (exit 6;
the scorer excludes it from quality metrics and counts its cost); a
truncated stdout, stderr or output file, or an empty-stdout TIMEOUT, makes
the scan `scan_incomplete` (treated as contaminated); a cell with no
`ScanResult` is refused for gated categories and plumbing-only otherwise.

**False-negative limits (documented, not fixed):** a worker that read the
answer key but paraphrased it leaves no pattern; patterns shorter than 12
characters (except the fixed markers), present in the pre-fix tree, or
contained in the harness's own recorded paths (the snapshot and run
directories) are dropped as non-distinctive (counted, never listed) - a
marker that Eris's own `run.started`/`Invocation.cwd` necessarily contain
cannot discriminate; binary or truncated output is not scanned beyond the
cap. The scan is evidence of contamination when it fires; silence is not
evidence of cleanliness.

### Call cache (`src/eris/cache.py`)
Lives in `cache/` (policy `cache_dir`, gitignored, refused when equal to or
under `runs/`). Entry bytes come out of `RunWriter.put_blob` (redacted) and
the entry file is named by their sha256; blobs are copied from the run's
blob files and re-hashed. Write-once (`O_EXCL`): a different entry under the
same key is a `conflict`, never an overwrite. A HIT needs the current
executable pin, key + prompt match, same campaign (unless
`--reuse-across-campaigns`), status ok, `scan_hits == 0` (a contaminated
entry is never reused), a known model, the current schema version, the
entry hash == name and every blob re-hashing; every file is `lstat`-checked
and opened `O_NOFOLLOW`; a key, entry or blob that IS a symlink is refused
whatever it points at (an alias inside the cache root is still an alias),
and every path must RESOLVE under the cache root's realpath (an ancestor
symlink is refused); any failure is a reasoned miss and a fresh call.
A replay whose blob changes under the reusing run's redactor (a secret
learned later) is refused. Without `O_NOFOLLOW` (Windows) the cache refuses
to construct (documented; M2c adds a portable fallback).

### Verification runs on a private VERIFICATION copy (advisor round, item 4)
A trusted `pytest` executes repository code and could modify it. Every
verification command therefore runs in a fresh copy of the original
(`sanitize.VERIFICATION_PROFILE`) under the run's scratch root - never in
the original and never in a sanitized copy. That profile strips NOTHING
(verification must see the repository as it is, instruction files included)
and differs from a raw `cp -a` in exactly two documented ways: `.git/hooks`
is not copied (our allowlist runs `git`, so a repository hook would fire on
the first invocation), and a symlink that is absolute, dangling or resolves
outside the tree is dropped and recorded. File set, bytes, FILE AND
DIRECTORY modes (the copy root included), kept symlink targets and `.git`
itself are identical; a preserved read-only directory cannot wedge cleanup
(owner write is restored on retry). `evidence.SnapshotGuard` compares
the copy's tree hash after every command: a change is recorded
(`snapshot.violated`, `EvidenceItem.violated`, the item's summary) and
verification stops for the run; the original's tree hash is recorded in
`run.started` and asserted unchanged at the end (`run.error
snapshot_modified`). pytest always carries `-p no:cacheprovider`.

### The judge never sees the snapshot (item 2)
The adjudicator/summarizer cwd - and agy's `--add-dir`, codex's `-C` - is an
EMPTY private directory under the scratch root, allocated PER CALL
(`judge-<role>-<iteration>`), so an iterating judge never sees what its own
previous iteration left behind. Emptiness is re-checked immediately before
every spawn, not only when the call is planned: a non-empty workspace means
containment failed and the call is refused. Its only input is the prompt.

### Ephemeral files never live under `runs/` (item 5)
`RunWriter` is the only writer under `runs/`. Worker scratch, sanitized
copies, the pristine verification copy and the verify HOME live under the
policy `scratch_dir` (default `cache/scratch/<run_id>/`, refused under
`runs/`), are removed in `finally` on success, refusal and crash, and
orphans are swept at startup. The sweep is conservative: an entry is removed
only when it is provably not in use - not the current run's (every command
passes its own run ids: `run`, `campaign` for every planned cell, `invoke`),
not one whose run directory is unfinished while its writer lock is held (a
platform where liveness cannot be disproved counts as HELD), and not one
modified within the last hour - and both what was removed and what was kept,
with reasons, are logged. Because "unprovable" would otherwise mean "kept
forever", `Policy.scratch_retention_s` (7 days) is a HARD bound on ORPHANS:
past it an entry is swept whatever the lock says, logged as
`forced_over_retention`. **Exclusion outranks retention**: an entry whose run
id belongs to the command doing the sweep is never removed, at any age -
deleting a live run's scratch is worse than leaking a stale directory, and
an over-retention entry of a live run is a bug to be reported, not deleted.

The scratch path is validated BEFORE the run's writer opens, and the
`mkdir(exist_ok=False)` that creates it IS the reservation: it happens before
the writer opens, so an entry appearing between the check and the mkdir
refuses with no run directory, no ledger, and NOTHING deleted - the entry is
left exactly as found for the operator to inspect, and the run id is reusable
once it is cleared. A run only ever removes a scratch root it created itself.

### The ledger's last word is the scan (item 10)
After the final scan the ledger is SEALED: `RunWriter.seal()` makes any
further `append` raise, while `finalize` may still write the manifest. The
seal is DURABLE, not a property of the process that set it: a writer opened
on a ledger whose last event is `scan.result` opens SEALED, so a `--resume`
after a failed finalize cannot append behind the final scan either.

A failure in the post-scan path (a manifest write, a late cleanup) cannot be
an event. It is reported on stderr and in the exit code AND recorded in
`manifest.json` under `post_scan_errors` - the manifest is written after the
scan, so that record is durable rather than living only in a terminal that
may be gone. If the failure prevented the manifest itself, the harness
finalizes the run once more from its cleanup path so the failure still
reaches disk.

### Durability of the record: finalized vs fsynced (exit code 8)
`finalize` writes `manifest.json` as temp file -> fsync -> rename -> fsync of
the run directory. Once the rename has succeeded the run IS finalized for
every future reader (a later open refuses with `RunExists`, `campaign
--resume` skips the cell); only its survival of a power loss is unproven. A
failure of that last directory fsync is therefore NOT a finalize failure: it
raises `ManifestNotDurable`, logs `{"status": "not_durable", ...}` and exits
with its own code **8** (`EXIT_NOT_DURABLE`), distinct from 4
(`run_error`) and 2 (config refusal). Treat it as an operator signal about
the filesystem, not as a broken run: the manifest is there, and re-running
the cell would refuse it as finalized.

### Fail-closed budgeting after a corruption (operator-resolvable)
A cell whose ledger cannot be read is reserved pessimistically: every planned
call of that arm (each judge iteration included) at the worst case the retry
driver can reach - walked over the real retry budget and the real
per-attempt reservation factors, mixed chains included (a timeout ->
transient -> timeout chain reserves 5x `per_call_usd`, more than either
pure chain). One corrupted cell can therefore
exhaust `per_campaign_usd` and make later cells trip the budget pre-check.
That is deliberate - Eris refuses to spend money it cannot account for - and
it is resolvable by the operator: inspect or remove the corrupt cell
directory, or raise `per_campaign_usd`, then `--resume` the campaign.

### Records downstream are the redacted ones (item 1)
Every record a later stage consumes is re-parsed from the redacted payload
the writer persisted, so a secret or host path in a proposal never reaches
a critic or the judge, and the fresh and cache-hit paths are byte-identical.

### Prompt envelope (`src/eris/stages.py`)
DATA is one canonical-JSON document between nonce delimiters; repository
text appears only inside JSON strings; a nonce inside the data is
neutralised and recorded. Prompts over 256 KiB are refused and never
spilled to a file. Model output enters only through closed wire models;
Eris assigns every id. The judge sees executable basenames, never host
paths, and never another stage's instructions.

### Retry, budget, STOP, resume, SIGINT
Unknown failures are terminal; the judge's timeout is terminal; the retry
weight budget is 3 per call. The money pre-check (`spent_known + reserved +
per_call_usd > ceiling`, per run and per campaign) runs before EVERY spawn
and records a `BUDGET_TRIPPED` invocation without spawning. STOP files
(`runs/STOP`, `runs/<campaign>/STOP`) are checked before every step, every
worker call, every attempt and every verification command; the attempt in
flight always completes. Resume replays only stages whose blobs re-hash,
records abandoned attempts with a pessimistic cost, kills surviving process
groups recorded at spawn time (refused where `os.killpg` is missing) and
removes stale scratch. Attempt numbers are MONOTONIC across resumes: the next
number is derived from every attempt the ledger records (finished, abandoned
and interrupted alike) and the driver continues from it instead of restarting
at 1, so no two attempts of a call share a number or an invocation id, and a
crash on a later resume is never mistaken for a repeat of an earlier one. The SIGINT handler lives only in `eval/run.py`.

## Residual risks (UNKNOWN / not enforced)
* Workers other than agy READ outside the snapshot (E1, measured): see the
  USER DECISION section at the top. No corpus scoring until it is resolved.
* Worker CLIs run on the host with the user's OAuth state (`HOME` is passed).
  Relocating with `CLAUDE_CONFIG_DIR`/`CODEX_HOME`/`HOME` breaks auth (E2,
  A8): credentials cannot be separated from state that way.
* claude with `--tools ""` and a prompt that needs a tool HANGS (E8, 240 s);
  the Eris timeout is the only backstop — adjudicator prompts must never ask
  for tool actions.
* `pytest` verification on trusted repos runs that repo's code as the user.
* Supply chain: exact pins, `pip-audit` blocking in CI. Vendor CLI binaries
  are pinned by sha256 but the CLIs themselves can auto-update outside Eris;
  the doctor reports a changed hash as FAIL.
* macOS `flock` is advisory.
