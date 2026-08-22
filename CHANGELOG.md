# Changelog

## 0.2.0 - Milestone 2a: Antigravity `agy` worker, E-experiment results (2026-08-22)

Added
* `agy` (Antigravity CLI 1.1.18) replaces the uninstalled `gemini` CLI as the
  Google lineage. `build_argv_agy`: `-p <prompt> --model <m> --mode plan
  --sandbox --output-format json --disable-slash-commands --print-timeout
  <max(30, timeout_s-30)>s [--json-schema <inline>]`; `parse_agy` (status
  ERROR → FAILED with the worker's message, usage retained, `structured_output`
  preferred, no model id / cost). Six captured agy envelopes are fixtures.
* `eris.policy`: `CliName` is `claude|codex|agy|grok`; lineage guard - an agy
  worker must declare a `gemini-*` model. `policies/default.yaml`: agy entry
  (google, `gemini-3.1-pro-high`, `AGY_CLI_DISABLE_AUTO_UPDATE=1`),
  `~/.gemini/antigravity-cli/settings.json` among the credential files.
* `FORBIDDEN_ARGV_TOKENS` += `accept-edits`, `--continue`, `--conversation`,
  `--add-dir`, `--prompt-interactive`, `--input-format`, `--new-project`,
  `--project`, `--agent`, `--log-file`; an exact-element test proves the agy
  builder never emits `-c`. NEVER env += `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
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
