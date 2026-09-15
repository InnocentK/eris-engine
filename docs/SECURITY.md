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
(which contains every fix the corpus hides), the answer keys - which now live
under `eval/keys/`, outside the corpus, which REDUCES exposure but does not
remove it on a host where a worker can read the working tree at all - and the
vendors' memory/session stores. Any defect-detection
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
* `model_executed` (claude): exactly one envelope-reported name -> that
  name; several names -> the unique model whose own `outputTokens` equals
  the result's `usage.output_tokens` (authorship by the vendor's counters;
  panel-reviewed 2026-09-14, added when claude 2.1.272 began running a
  haiku helper on every call), recorded on the RESULT only when the match
  is ALSO the requested model - a veto against the identity crowning a
  coincidence-matching helper (stop-time review, same day); no unique
  match, or a vetoed one -> `None`, never guessed. agy and codex emit no
  model id at all: `model_executed` is always `None` for them.
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
  changed hash as FAIL ("re-pin deliberately"). That fired for real: the
  binary went 1.1.18 -> 1.1.27 under the 2026-08-31 pin, the gate FAILED for
  a day, and the 2026-09-06 re-pin was preceded by re-verification against
  the NEW binary - env-var name still in strings; `gemini-3.1-pro-high` still
  listed and executed without the A9 defaulting message; all nine argv flags
  still present; envelope fields unchanged; `settings.json` still only
  `enableTelemetry`/`trustedWorkspaces`; a write attempt in Eris's headless
  shape was AUTO-DENIED (run CANCELED, empty response - fails closed); an
  outside-workspace read was ATTEMPTED and AUTO-DENIED with no leak. Three
  1.1.27 behaviors are new and recorded here: (1) stderr warns
  `--mode plan has no effect while slash command expansion is disabled` - the
  plan-mode layer Eris requests is INERT in this invocation shape; the
  containment that held under probing is the headless permission auto-deny
  plus `--sandbox` plus `--add-dir`, not plan mode, so the layer's loss is
  noted rather than load-bearing. (2) The envelope can carry a
  `denied_actions` list naming auto-denied tools - signal the parser does not
  yet read. (3) A denied tool can end the run as `status: SUCCESS`
  with an EMPTY `response` (observed; a second shape ends it `CANCELED`, an
  error in the envelope outright). What Eris then does depends on the path,
  and both are verified. CAMPAIGN stages request a schema, and the denied
  shape returns `structured_output: null` even with `--json-schema` passed
  (probed on 1.1.27), so `retry.classify` returns MALFORMED_OUTPUT -
  retryable, capped at 2 - and when the cap stops the chain the stage writes
  `worker.absent` and continues WITHOUT that worker, while the invocation
  record itself keeps `status: ok`: an absent panel member degrades the
  panel, an absent judge leaves the cell excluded as `incomplete`. The
  ad-hoc `invoke` path never classifies at all: `cmd_invoke` calls
  `run_worker` directly - no retry driver, so `classify` never runs and
  `_build_call` requests no schema either - and the empty SUCCESS envelope
  is recorded and returned to the caller as-is. That path, and only that
  path among the CLI spawn paths (campaign and single-cell runs go through
  the stage machinery above), degrades to silence. Three earlier versions of
  this sentence each misstated one clause of these semantics ("scores as a
  proposal with no findings"; "FAILS the invocation"; "classifies OK" on a
  path that has no classifier) and each was caught by stop-time review;
  every clause above now names code, a pinned test, or a probe.
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
failure is a `run.error`, never silent). Verification NEVER runs in one of
those stripped copies - and it does not run in the original either: it runs in
a separate private VERIFICATION copy (`VERIFICATION_PROFILE`, below), which
strips nothing from the working tree. The strip list is the policy's `sanitize` section on top of an
enforced minimum (R3.1): `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`,
`GEMINI.md`, `GROK.md`; `.agents`, `.claude`, `.codex`, `.gemini`, `.grok`,
`.antigravity`, `.cursor`, `.github/copilot-instructions.md` - matched by
name at any depth, case-insensitively, whatever the entry is (a file, a
directory, or a symlink named `AGENTS.md`). Files get new inodes (never
hardlinks); symlinks are kept only when relative, resolving inside the tree
and not into a stripped entry (every other link is dropped and recorded);
`.git` is copied without `hooks`, with the COPY's `.git/config` REWRITTEN FROM
AN ALLOWLIST, with `objects/info/alternates` / `objects/info/http-alternates` /
`config.worktree` deleted, and with a copy that is not one self-contained
repository refused (see the verification-copy section) - a control that fails
CLOSED (a non-regular config is replaced or refused, never skipped; an
unparseable config refuses the copy).
`SnapshotSanitization` records the
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
`eval/corpus/`, `eval/keys/`, `key.json`, the key's fix-hunk lines and its
extra strings (which must include a per-task `ERIS-KEY-CANARY-*` token; a
scored run is REFUSED unless one survives into the pattern set), and
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
blob files and re-hashed. Default pointers are write-once (`O_EXCL`) under
`keys/campaigns/<epoch>/<idempotency_key>`, where `<epoch>` is a domain-
separated sha256 of the campaign id; the reserved no-campaign epoch is
`none`. A different entry under the same campaign-scoped key is a `conflict`,
never an overwrite. The legacy unscoped `keys/<idempotency_key>` pointer is
the explicit first-writer-wins cross-campaign index only: its prior-campaign
entry or refusal cannot block publication or use of the current campaign's
pointer, and default lookup never falls back to it. A HIT needs the current
executable pin, key + prompt match, the selected pointer's campaign (unless
`--reuse-across-campaigns` explicitly selects the unscoped index), status ok,
`scan_hits == 0` (a contaminated entry is never reused), a known model, the
current schema version, the entry hash == name and every blob re-hashing;
every file is `lstat`-checked and opened `O_NOFOLLOW`; a key, entry or blob
that IS a symlink is refused whatever it points at (an alias inside the cache
root is still an alias), and every path must RESOLVE under the cache root's
realpath (an ancestor symlink is refused); any lookup failure is a reasoned
miss and a fresh call.
A replay whose blob changes under the reusing run's redactor (a secret
learned later) is refused. Without `O_NOFOLLOW` (Windows) the cache refuses
to construct (documented; M2c adds a portable fallback).

### Verification runs on a private VERIFICATION copy (advisor round, item 4)
A trusted `pytest` executes repository code and could modify it. Every
verification command therefore runs in a fresh copy of the original
(`sanitize.VERIFICATION_PROFILE`) under the run's scratch root - never in
the original and never in a sanitized copy. That profile strips NOTHING from
the WORKING TREE (verification must see the repository as it is, instruction
files included). Every deviation from a raw `cp -a` is inside `.git`, and there
are four of them, because git treats parts of `.git` as executable
configuration:

1. `.git/hooks` is not copied (our allowlist runs `git`, so a repository hook
   would fire on the first invocation).
2. **The copy's `.git/config` is NOT the original's file.** It is rewritten
   from an ALLOWLIST (`sanitize.rewrite_git_config`) - see below.
3. `.git/objects/info/alternates`, `.git/objects/info/http-alternates` and
   `.git/config.worktree` are deleted, and a copy that is not ONE
   self-contained repository is REFUSED (`.git` as a gitlink FILE,
   `.git/commondir`, `.git/worktrees/`, `.git/modules/`, or any NESTED
   `.git` below the root - see the nested-repository section below).
4. A symlink that is absolute, dangling or resolves outside the tree is
   dropped and recorded; an in-copy `.git/config` symlink is REPLACED by the
   rewritten regular file and recorded there too, and any other non-regular
   shape at a `.git` path Eris depends on refuses the copy
   (`assert_git_layout_sane`).

Otherwise the file set, bytes, FILE AND DIRECTORY modes (the copy root
included), kept symlink targets and the rest of `.git` are identical; a
preserved read-only directory cannot wedge cleanup (owner write is restored on
retry). `evidence.SnapshotGuard` compares the copy after every command: a
change is recorded (`snapshot.violated`, `EvidenceItem.violated`, the item's
summary) and verification stops for the run; the original's tree hash is
recorded in `run.started` and asserted unchanged at the end (`run.error
snapshot_modified`). pytest always carries `-p no:cacheprovider`.

#### The copy's `.git/config` is an ALLOWLIST, not the repository's config

M2c follow-up 5, the SIXTH consecutive stop-time finding against this control
and the first that is arbitrary code execution rather than an observation gap.
The previous model neutralised the keys we knew about (`core.fsmonitor`,
`core.untrackedCache`) and left the rest of the repository's config in place.
Measured on this machine, git 2.50.1, 2026-08-24, against the ALLOWLISTED
verification command `git --no-optional-locks diff HEAD`:

| vector | observed before the fix |
|---|---|
| `[diff] external = <path>` in the copy's `.git/config` | the named program **EXECUTED** |
| `[diff "evil"] textconv = <path>` + `f.txt diff=evil` in a tracked `.gitattributes` | **EXECUTED** (twice - once per side) |
| `.git/objects/info/alternates` -> another object store, in a properly history-truncated snapshot | a commit `eris.snapshot` removed went from `cat-file -e` FAILING to SUCCEEDING; its blob read out in full |

So a repository-controlled config defeated the verification allowlist entirely.
The executable pin, the subcommand lists, the per-tool hard-deny (`--ext-diff`,
`--textconv`) and the "no model may pass `-c`" rule are all irrelevant here:
the repository chose the program, not the model.

**What survives in the copy** (`GIT_CONFIG_ALLOWED_CORE_KEYS`,
`GIT_CONFIG_EXTENSIONS_KEPT`): `core.repositoryformatversion`,
`core.filemode`, `core.bare`, `core.symlinks`, `core.ignorecase`,
`core.precomposeunicode`, `core.logallrefupdates`, and - from `extensions` -
only `objectformat` and `compatobjectformat`, and only with a value in
`{sha1, sha256}`. That is the repository FORMAT and the filesystem capability
flags: `git init` writes them from what the filesystem supports, and a sha256
repository does not open at all without `extensions.objectformat`. None of them
names a command or a path git will act on.

**Any OTHER `extensions.*` REFUSES the copy**, naming the key (0.3.10;
`extensions.worktreeConfig` is the one exception, DROPPED rather than refused
because Eris deletes the `.git/config.worktree` it enables, so its absence
changes nothing). Keeping the whole section was the 0.3.9 design and it was not
evidence-backed - it asserted that no `extensions` value names anything
dangerous, over a key set git is free to grow. Refusing rather than dropping is
deliberate: an extension declares how the repository is STORED, so a copy with
one silently dropped is a repository git OPENS and then misreads. Measured
2026-08-24 on git 2.50.1, `git init --ref-format=reftable` really does write
`extensions.refstorage = reftable` at `repositoryformatversion = 1`, and a copy
without it has no `refs/` files to fall back on. Known false refusal, also
measured: at `repositoryformatversion = 0` git IGNORES `extensions.*` entirely,
so a v0 repository carrying a stray extension is refused although git would
open it happily; `git init` never writes extensions at v0, and the rule is kept
unconditional because a version-dependent one is harder to audit.

**What is dropped**: everything else. Every `diff.*`, `filter.*`, `merge.*`,
`gpg.*`, `credential.*`, `url.*`, `http.*`, `uploadpack.*`, `include.*`,
`includeIf.*`, `alias.*`, `remote.*`, `branch.*`, `user.*`, and every
path-or-command `core.*` (`worktree`, `hooksPath`, `fsmonitor`,
`untrackedCache`, `pager`, `editor`, `sshCommand`, `askPass`,
`alternateRefsCommand`, `sharedRepository`, ...). A subsectioned `[core "x"]`
or `[extensions "x"]` entry is dropped too: neither is a key git acts on.
`core.fsmonitor` and `core.untrackedCache` are therefore no longer set to
`false`; they are simply not in the file, which is strictly stronger. With no
driver DEFINED, a `.gitattributes` in the tree naming `diff=evil` or
`filter=x` is INERT - verified end to end, not assumed
(`test_verify_real_git.py::test_a_repository_textconv_driver_cannot_execute_in_the_verification_copy`).

**The rewrite is a re-serialisation, not a filter.** Every previous version of
this control scanned LINES, and git's config grammar is not line-oriented:
measured on 2026-08-24, `[core] filemode = true` and `[core]filemode=true` are
both a section header AND a variable on one line, `[core][diff] external = x`
puts the variable in `diff`, values continue across lines with a trailing
backslash, `\r\n` collapses to `\n`, a UTF-8 BOM is skipped, and `#`/`;`
outside quotes starts a comment mid-value. `sanitize.parse_git_config` is a
port of git's `config.c` (`git_parse_source` / `get_base_var` /
`get_extended_base_var` / `get_value` / `parse_value`); the output is generated
from the parsed `(section, key, value)` triples with every value re-quoted, so
a line git would read differently from the way Eris read it cannot survive into
the copy. A config Eris cannot parse REFUSES the copy - git refuses to open
such a repository too (`fatal: bad config line`), so that costs no working
repository. The parse is checked against git itself, not against Eris's own
reading: `test_verify_real_git.py::test_the_config_rewrite_keeps_exactly_the_allowlisted_keys_git_reports`
asserts that `git config --list` in the copy equals the allowlisted subset of
`git config --list` in the original.

**The ORIGINAL is never opened for writing.** The rewrite happens while the
copy is being built - before the guard takes its baseline and before any
verification command runs - and every path it touches is under the copy root.

**False refusals are the failure mode that matters.** A guard that rejects
ordinary repositories gets deleted by the next person, so an ordinary checkout
(two remotes, a user, aliases, tracking config, several branches) is pinned to
sanitize without refusing and to run the WHOLE default battery clean
(`::test_an_ordinary_repository_still_runs_the_whole_battery_after_the_rewrite`).

**The config control cannot be aliased away** (M2c follow-up 4). `.git/config`
that was not a regular file used to be skipped SILENTLY: a symlinked config
bypassed every rule above, because git follows the link and reads its target
while Eris `lstat`ed and gave up. It fails CLOSED. A link resolving INSIDE the
copy to a regular file is read, unlinked and REPLACED by a regular file holding
the rewritten bytes - the target is never written through: containment is
decided on the REALPATH, the read carries `O_NOFOLLOW|O_NONBLOCK` (a link to a
fifo fails the type check instead of blocking the run), the link is re-`lstat`ed
and must still be the same dev+inode immediately before the `unlink`, and the
replacement is created `O_CREAT|O_EXCL|O_NOFOLLOW`, so no pre-existing path
anywhere is ever opened for writing. The replacement is recorded in
`dropped_symlinks`. Every other shape - a link escaping the copy root, a
dangling link, a link to a directory or fifo, a fifo, a directory - REFUSES the
copy, naming the path and the reason. A link that escapes or dangles in the
ORIGINAL is dropped by the copier before any of this, which legitimately leaves
no config at all; that case still proceeds.

**The filesystem-monitor case is still why the copy's config matters at all**
(M2c follow-up 3). A snapshot taken from a repository that configures
`core.fsmonitor` inherits it verbatim, and dropping `.git/hooks` does not
disable it: the value may name any path in the repository. It matters in both
directions, and both are measured (2026-08-24, git 2.50.1,
`test_verify_real_git.py::test_an_inherited_fsmonitor_left_on_would_false_trip_the_guard`,
`::test_an_inherited_fsmonitor_is_off_in_the_verification_copy_never_in_the_original`):
a live monitor marks index entries fsmonitor-valid BY ITSELF on the second
refresh of a fresh copy, which the index digest reports as a violation no
verification command caused (verification would halt for the run); and a stale
cache lets a command answer from data the working tree no longer supports.

#### The repository-level escapes (M2c follow-up 5, item 2)

The config is not the only part of `.git` git treats as instructions.

* **`.git/objects/info/alternates` and `.git/objects/info/http-alternates` are
  deleted from the copy.** One line naming another object store re-exposes
  exactly the commits `eris.snapshot`'s history truncation removed. This is
  corpus contamination rather than execution, and it is the vector `eris.scan`
  would be least likely to catch: the worker never has to name a path Eris
  knows about. (`eris.snapshot` already removes `alternates` when it BUILDS a
  snapshot; the copy no longer trusts that it did.)
* **`.git/config.worktree` is deleted.** It is a second config file with the
  same execution risk, read when `extensions.worktreeConfig` is set - which the
  config rewrite also drops.
* **A copy that is not ONE self-contained repository is REFUSED**, naming the
  path and why: `.git` present as a FILE (a worktree/submodule gitlink),
  `.git/commondir` (this IS a linked worktree - its refs, config and objects
  live in a `.git` Eris has not copied), `.git/worktrees/` (this repository
  hosts linked worktrees, each with its own `config.worktree`), and
  `.git/modules/` (submodule gitdirs, each a repository with its own config).
  Refusing is the honest answer: verifying the half of the repository Eris can
  see, and reporting it as if it were the whole, is worse than saying no.
  **This is a deliberate scope reduction** - a repository with submodules or a
  checkout that is itself a linked worktree can no longer be verified at all,
  and that shows up as a refusal, never as a quiet pass.

#### Nested repositories are refused (advisor round)

The config allowlist rewrites exactly ONE file: the copy's own `.git/config`.
A NESTED repository has its own, and Eris never sees it. Measured 2026-08-24,
git 2.50.1, on an outer repository whose `sub/.git` is a FILE reading
`gitdir: <outside the snapshot>`, with that external config carrying
`diff.external`:

| state of `sub` | `status --porcelain` | `diff HEAD` | `status --porcelain=v2` |
|---|---|---|---|
| not in the index | no execution | no execution | no execution |
| registered as a gitlink (mode 160000) | **EXECUTED** | **EXECUTED** | **EXECUTED** |

No `.gitmodules` was involved, and the gitdir was outside the copy entirely, so
nothing Eris rewrites, deletes or hashes could have helped.

* `sanitize.assert_no_nested_repositories` refuses ANY `.git` below the copy
  root - directory, gitlink file or symlink, at any depth. The root's own
  `.git` is skipped; a file merely NAMED like one (`.gitignore`,
  `.gitmodules`) is not a repository.
* **Names are compared FOLDED (`_fold`: NFC + casefold), because the
  filesystem may be.** Measured 2026-08-24 on macOS/APFS: `sub/.GIT` is
  reported by `os.walk` under that literal name while `sub/.git` EXISTS and
  git resolves it, so the first version of this walk missed it - and, one
  level up, `.GIT/HOOKS` was being copied into the verification copy. The NFC
  step is a measured no-op for `.git` (pure ASCII has no decomposed form) and
  is kept only so the helper survives a future non-ASCII marker name;
  compatibility lookalikes are deliberately not folded, so a fullwidth
  `.gｉt` - a genuinely different file - is not a false refusal. On a
  case-SENSITIVE filesystem `.GIT` is a distinct directory git never reads, so
  folding costs a refused copy there and never an escape.
* A GITLINK in the index refuses the verification run, taken on the guard's
  baseline out of the `ls-files -s -v -f` output the tripwire already spawns
  (`-s` prints the mode, so it costs no extra command). This is the half the
  copier cannot see: a registered but un-checked-out submodule leaves nothing
  on disk, which is exactly what a non-recursive clone produces - and
  `eris.snapshot` clones non-recursively. Nothing can execute in that state, so
  it is a SCOPE refusal and says so.
* **Recursive sanitisation is not attempted.** It would mean rewriting a config
  tree of unbounded depth, some of it outside the snapshot, and getting that
  wrong is this bug again.
* **Cost, stated plainly: a repository that uses submodules cannot be verified
  at all**, checked out or not. This is the largest scope reduction in the M2c
  follow-ups. It shows up as a clean refusal naming the path, never as a quiet
  half-verification.

#### A repository config is not only a git problem (final round)

The config allowlist fixed `git`. Measured 2026-08-24 against the other two
allowlisted tools, and both were already true before any of this work:

| tool | what a repository config did | Eris's flag |
|---|---|---|
| `mypy` | `mypy.ini` with `plugins = ./evil_plugin.py` **EXECUTED the plugin** - arbitrary code execution, the same class as `[diff] external` | `--config-file <os.devnull>` |
| `ruff` | `ruff.toml` with `[lint] select = []` made `ruff check` report "All checks passed!" on a file with an unused import - **evidence manipulation**, not execution | `--isolated` |

Eris appends these itself (`verify.ERIS_ISOLATION_FLAGS`), on exactly the
contract `--no-optional-locks` already had: FIRST in argv, before any
subcommand or positional, and **hard-denied to a model** so a proposal can
neither double the flag nor point it somewhere else. The ruff case is not
execution, but for an engine whose one job is deciding whether an answer is
defensible *given the evidence*, a repository that can choose which findings
exist is its own kind of serious.

`os.devnull` rather than a literal `/dev/null`: Windows spells it `nul`, and
whether mypy accepts `--config-file nul` there is **UNKNOWN and untested**.
mypy also prints `<devnull>: No [mypy] section in config file` on stderr, which
lands in the recorded evidence; that noise is accepted in exchange for the
isolation.

**`pytest` gets no isolation flag, because none exists.** `conftest.py` IS
repository code that pytest imports and executes by design, and no switch turns
that off - which is exactly why `pytest` carries `requires_trusted` and is
refused unless the policy is `trusted: true`. `-p no:cacheprovider` is about
the cache directory, not about isolation.

#### What is still open after M2c follow-up 5

Stated, not implied:

* **The tree is still the repository's, and so is `.git/info/attributes`.**
  `.gitattributes`, `.gitmodules`, `.mailmap` and every other in-tree file are
  copied verbatim, by design, and `.git/info/attributes` - the
  repository-LOCAL attributes file, which is not tracked and is not
  `.gitattributes` - is copied with the rest of `.git`. Both are inert only
  for as long as nothing DEFINES the driver they name; that is a property of
  the config allowlist, so widening the allowlist is the thing to watch.
  MEASURED, both of them, on git 2.50.1 (2026-08-24): with
  `diff.evil.textconv` defined, an attributes line naming `diff=evil` executes
  the driver; with the driver unset it is inert. Neither file is removed from
  the copy, because removing it would change what verification SEES while the
  allowlist is what actually stops the execution
  (`test_verify_real_git.py::test_a_repository_textconv_driver_cannot_execute_in_the_verification_copy`,
  `::test_a_git_info_attributes_driver_cannot_execute_in_the_verification_copy`
  - the second is the test that fails first if the allowlist ever gains a
  driver-defining key).
* **`.git/info/exclude` is copied verbatim and has NOT been measured.** It
  changes which untracked files `git status` reports, so it can hide a file
  from the evidence pack. It names no program, and by the same reasoning as
  the attributes files it cannot define a driver - but that is reasoning, not
  a measurement, and it is recorded here as such.
* **Objects and refs are copied verbatim.** A malicious commit message, a
  branch name, a tag or a note is still an in-band instruction channel, and a
  worker with git tools can still read them.
* **The allowlist is checked ONCE, at the end of sanitisation.** Nothing
  re-checks it between verification commands. A command that rewrote
  `.git/config` mid-run would be caught by the guard's tree hash (`.git/config`
  is inside it), not by the rewriter.
* **Only two `extensions.*` keys are supported at all.** Everything else -
  `refstorage`, `partialclone`, `preciousObjects`, anything git adds later -
  REFUSES the copy rather than being dropped. That is a scope reduction, not a
  gap: a reftable or partial-clone repository cannot be verified.
* **Config Eris does not own is out of scope here.** System and global config
  are excluded by the launcher's `GIT_CONFIG_NOSYSTEM=1` /
  `GIT_CONFIG_GLOBAL=/dev/null` hardening and a scratch `HOME`, not by this
  control.
* **This is not a container.** It contains git's reading of the copy. It does
  not stop a worker or a trusted `pytest` from reading outside the snapshot
  (E1, above), and it does not make an adversarial repository safe -
  adversarial repositories remain OUT of scope until Phase 3.

**The general assertion (`sanitize.assert_git_layout_sane`).** Four of the first
five findings against this control were different KINDS of hole, so the fix is a
guard, not another patch. After sanitisation, every path in `GIT_REQUIRED_KINDS`
that Eris depends on must be the kind Eris assumes, or absent: `.git` a
DIRECTORY (a worktree/submodule gitlink is a FILE and is now refused - M2c
follow-up 5), `.git/config` a regular file, `.git/index` a regular file,
`.git/hooks` a directory, and the paths follow-up 5 added - `.git/config.worktree`,
`.git/objects/info/alternates`, `.git/objects/info/http-alternates`,
`.git/commondir` (files), `.git/worktrees`, `.git/modules` (directories). Every
check is an `lstat`, so a symlink is never followed and is never accepted for a
path on the list; ABSENT is always allowed (no `.git`, no index yet, the `hooks`
Eris deliberately does not copy, the paths Eris drops or refuses). Anything else
refuses the copy, naming the path, the shape found and WHY Eris depends on that
path. Adding a path Eris comes to depend on is one line there and one row in the
test table, and the test asserts the two sets are EQUAL - a new path with no row
fails. A second, separate table (`GIT_REFUSED_IF_PRESENT`,
`assert_no_repo_escapes`) refuses `.git/commondir`, `.git/worktrees/` and
`.git/modules/` on PRESENCE, whatever their shape. **What it does not cover,
stated:** it is a TYPE check on a fixed list, not a semantic one. It says nothing
about the CONTENT of those files (the config allowlist does that, and only for
the config), nothing about `.git` paths not on the list (`HEAD`, `refs/`,
`objects/`, `info/`), and nothing about a path outside `.git`. In-tree symlinks
elsewhere are still kept by design.

The guard has two halves, because one cannot do the job.

**The byte hash** covers every path in the copy except
`GUARD_EXCLUDED_RELPATHS` = `{.git/index, .git/index.lock}`. That exclusion is
forced: `.git/index` is git's stat cache, and on a freshly copied tree the
recorded stat data never matches, so a read-only command rewrites it. Measured
2026-08-24 on git 2.50.1: with `--no-optional-locks` on every invocation,
`status --porcelain`, `ls-files`, `ls-files --stage`, `ls-files -s -v -f` (the
probe itself, re-measured 2026-08-24), `log --oneline`,
`grep`, `blame`, `show` and `rev-parse` leave the file byte-identical, but the
first command that reads the working tree against the index (`diff`,
`diff HEAD`) refreshes it, flag or no flag. Hashing those bytes would trip the
guard on a legitimate allowlisted command on every run. Everything else under
`.git` - refs, objects, `HEAD`, `config`, `hooks` - stays in the hash, so a
command that rewrites history or config is still caught.

**The index digest** closes the hole that exclusion would otherwise open. The
index is not inert: `git ls-files` reads it directly and `git diff`/`git
status` compare against it, so a command that mutates it changes what LATER
evidence reports. The guard therefore also digests
`git --no-optional-locks ls-files -s -v -f` (per entry: the status letter,
then mode, blob sha, stage and path) before and after each command. Measured on the
same day: the digest is stable across every read-only command, across the stat
refresh and across an UNSTAGED working-tree edit, and moves on `git add` and on
`git rm --cached`. `git rm --cached` changes nothing else in the tree at all, so
without this digest it is invisible. Either half moving is `snapshot.violated`;
the event names which (`reason: "tree"` or `"git_index"`, the index winning when
both moved, as it does for `git add`) and records both digests before and after.

`-v` (not `--stage` alone) because of the index FLAG BITS. `--skip-worktree`
and `--assume-unchanged` change what `git status` and `git diff` report about a
file without changing any staged content: measured 2026-08-24 on git 2.50.1,
setting or clearing either one left the `ls-files --stage` digest
byte-identical - a silent tripwire bypass. `-v` prepends the per-entry status
letter (`H` cached, `S` skip-worktree, lowercase = assume-unchanged) in the
same invocation, so no extra spawn buys the coverage.
`test_verify_real_git.py::test_every_index_mutation_trips_the_guard`
ENUMERATES the mechanisms rather than chasing them one at a time:
`--skip-worktree`, `--no-skip-worktree`, `--assume-unchanged`,
`--no-assume-unchanged`, `--cacheinfo`, `--chmod=+x`, `-N`/`--intent-to-add`,
`git add` of a modified file, `git rm --cached`, `--fsmonitor-valid` and
`--no-fsmonitor-valid` all trip the guard with `reason: "git_index"`, and a new
mechanism is one line in that table.

`-f` (M2c follow-up 3) for the same reason one level down: `-v` is blind to the
per-entry FSMONITOR-VALID bit, which makes git treat a file as unchanged.
git-ls-files(1): "-f  Similar to -t, but use lowercase letters for files that
are marked as fsmonitor valid". The bit only persists with an ACTIVE monitor
returning a real update token - measured 2026-08-24 on git 2.50.1: with no
`core.fsmonitor`, `git update-index --fsmonitor-valid` exits 0 and stores
nothing; with a hook that prints nothing git warns "Empty last update token" and
clears every bit; with a hook that emits a token, the bit persists and setting
or clearing it moves the `-s -v -f` digest while leaving the `-s -v` digest
byte-identical. Without an active monitor `-f` prints exactly what `-v` prints,
so the flag costs no false positive and no extra spawn.

The digest runs on the POLICY-PINNED `git` with a FIXED Eris-internal argv. It
is deliberately not routed through the model-facing allowlist: it is neither
proposed nor influenced by a model, and `check_command` would refuse
`-s`/`-v`/`-f` (and `--stage`) anyway. The pin is still enforced by hand - an
unpinned, missing or since-changed binary yields no digest.

**What the digest does NOT cover.** Measured 2026-08-24 on git 2.50.1, each
case checked rather than assumed
(`test_verify_real_git.py::test_the_index_digest_does_not_cover_the_index_extensions`,
`::test_the_split_index_is_caught_by_the_tree_hash_not_by_the_digest`):

| index feature | tree hash | index digest |
|---|---|---|
| untracked cache (`UNTR`) | no | no (`core.untrackedCache` is not in the copy's config) |
| fsmonitor: enabling it (`core.fsmonitor`) | YES - `.git/config` is hashed | no |
| fsmonitor: the `FSMN` section and its token | no | no |
| fsmonitor: the per-entry VALID BIT | no | **YES - this is what `-f` buys** |
| cache-tree (`TREE`) | only the tree OBJECT `write-tree` writes | no |
| resolve-undo (`REUC`) | no | no |
| split index (`--split-index`) | YES - the new `.git/sharedindex.<sha>` file | no |

**fsmonitor is a chain, not a single row.** It is the one extension that
changes what a later `git status`/`git diff` reports - an fsmonitor-valid entry
is treated as unchanged - so it gets three answers rather than one. Turning it
on means writing `core.fsmonitor` into `.git/config`, which is inside the tree
hash and not in `GUARD_EXCLUDED_RELPATHS`: that step alone is `reason: "tree"`.
The per-entry valid bit is covered by the index digest, since `-f` prints it.
The `FSMN` section itself - its presence and its update token - is not visible
in any `ls-files` output at any verbosity and lives in the excluded bytes, so
nothing catches it; on its own it changes no report. And the copy starts with
`core.fsmonitor` unset (above), so an inherited monitor is off before the first
command.

The other EXTENSIONS live inside `.git/index`, which the byte hash excludes, and
`ls-files` prints no trace of them at any verbosity - so **nothing in Eris
catches them**. That is a stated gap, not an implied completeness: they are
caches and undo data, and none of them changes what a later `git status`, `git
diff` or `git ls-files` reports, which is the property the tripwire exists to
protect. If that ever stops being true for one of them, it needs a check of its
own. (The cache-tree case looks caught and is not: the guard trips there only
because `write-tree` also writes a new object under `.git/objects`. The
untracked cache is uncaught but cannot be turned on from the repository:
`core.untrackedCache` is not in the copy's allowlisted config.)

The split index is different, and the answer is measured, not assumed:
`git update-index --split-index` writes a NEW file, `.git/sharedindex.<sha>`,
which is not in `GUARD_EXCLUDED_RELPATHS`, so the tree hash DOES catch enabling
it (`reason: "tree"`). The digest is blind to the split itself - `ls-files -s
-v` prints the same entries either way - but it keeps working over a split
index: a `--skip-worktree` applied afterwards still moves it. `--no-split-index`
leaves the shared file behind, so the tree stays changed.

If the copy has a `.git` directory and no digest can be taken (git unavailable,
unpinned, non-zero exit, timeout, truncated output - including a probe that
stops working part way through a run), the guard FAILS CLOSED by REFUSING the
run (`IndexScopeUnknown`). Until 0.3.10 it degraded to hashing `.git/index`
like any other file (`index_check: "bytes_fallback"`); the advisor round found
that this was a hole rather than a fallback, because without the digest the
GITLINK scan never runs and a superproject sails straight through. Nothing real
is lost by refusing: every command in the default battery IS git, so a copy
whose pinned git cannot be run has no verification to produce. A copy with no
`.git` directory has no index to guard and is not refused (`index_check:
"none"`).

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
