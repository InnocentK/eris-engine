# Changelog

## 0.3.0 - Milestone 2b, Phase 1: harness modules (2026-08-22, in progress)

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
