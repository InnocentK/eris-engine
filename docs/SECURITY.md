# Security model (Milestone 1 + 2a)

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

**Until (1) or (2) exists, Phase 0 may run plumbing and clean-control tasks
only — NO defect-detection or ABSTAIN scoring.** This is a user decision; the
engineering recommendation is option 1.

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
  per-worker snapshot sanitization (strip `AGENTS.md`/`GEMINI.md`/
  `CLAUDE.md`/`.agents/` from the agy worktree copy, recorded in the
  manifest) — **Milestone 2b**. Until then agy proposals/critiques are
  exposed to repo-authored instructions, the same class as grok.
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
