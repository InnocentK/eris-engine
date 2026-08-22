# Security model (Milestone 1)

Single-user, self-hosted. The threat model is accidental: a worker CLI that
reads or writes where it should not, a secret that reaches the ledger, a
repository that injects instructions, a model-proposed command that executes.
Adversarial repositories are OUT of scope until containers (Phase 3).

## Boundaries that code enforces

### Worker processes (`launch.py`)
* Read-only flags per CLI, verified by experiment on 2026-08-21
  (`tests/fixtures/envelopes/*/*.meta.json`): claude `--safe-mode
  --permission-mode plan --tools <list>`; codex `exec -s read-only --ephemeral
  --ignore-user-config --ignore-rules -c project_doc_max_bytes=0`; grok
  `--permission-mode plan --disable-web-search`; gemini `--approval-mode plan`
  (UNVERIFIED: the CLI was unusable here).
* `--bare`, `bypassPermissions`, `workspace-write`, `danger-full-access`,
  `yolo`, `--dangerously-skip-permissions`, `--full-auto`, `acceptEdits`,
  `--skip-trust`, `--allow-all` are refused, case-insensitive, in every argv
  element EXCEPT the prompt (a reviewer may legitimately quote them); the
  prompt itself may not start with `-`.
* Env built from `{}`. NEVER list: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`,
  `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PYTEST_ADDOPTS`,
  `PYTEST_PLUGINS`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `NODE_OPTIONS`,
  `NODE_PATH`, `PERL5OPT`, `BASH_ENV`, `ENV`, `ZDOTDIR`,
  `GEMINI_CLI_TRUST_WORKSPACE`, `EDITOR`, `VISUAL`, and prefixes `LD_`,
  `DYLD_`, `GIT_`, `AWS_`, `PYTEST_`, `CODEX_SANDBOX`. The only `GIT_*`
  allowed are Eris's own four hardening values.
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
  model; otherwise it is `None` (never guessed).
* A worker's prompt may not start with `-`.

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
* Whether a worker can READ outside the snapshot (answer keys, the Athena
  tree, vendor memory stores) is UNKNOWN - a canary-read smoke test is
  required before corpus runs (`docs/EVAL-PLAN.md`).
* Worker CLIs run on the host with the user's OAuth state (`HOME` is passed).
  Relocating with `CLAUDE_CONFIG_DIR`/`CODEX_HOME` may break auth: UNKNOWN.
* `pytest` verification on trusted repos runs that repo's code as the user.
* Supply chain: exact pins, `pip-audit` blocking in CI. Vendor CLI binaries
  are pinned by sha256 but the CLIs themselves can auto-update outside Eris;
  the doctor reports a changed hash as FAIL.
* macOS `flock` is advisory.
