# Phase 0 evaluation plan

Status: the harness is RUNNABLE as of 0.3.0 (`eval/run.py run|campaign`,
`eval/score.py`); the pre-registration text (`eval/README.md` with the
per-category decision rule and a USD ceiling from a 3-task pilot) and the
corpus keys are Milestone 2c. This file records what is settled, what the
experiments showed, and what must still run before any scored corpus run.

## Runnable now (Milestone 2b)
* `python eval/run.py run --task-file eval/corpus/<t>/task.json --arm <arm>`
  runs one cell; `campaign --campaign-id <id> --corpus eval/corpus --repeats N`
  runs every cell task-major → repeat → arms in the fixed order
  (`single` per panel worker, `consensus`, `indep_verify`,
  `indep_verify_iter`, `indep_verify_critique`); `campaign status` is
  read-only; `--resume` continues; STOP files and SIGINT are honoured;
  `python eval/score.py --campaign-dir runs/<id> --corpus eval/corpus`
  scores. Exit codes 0/2/3/4/5/6/7/130 (`eval/run.py` docstring).
* **Pre-registration notes (binding for the scorer):** arm 2 (`consensus`)
  is scored on the RAW summarizer verdict (the enforced one is recorded
  too); arms 3/3b/4 are paired only when their `propose_keys` are
  identical (one policy per campaign - a policy edit changes every key);
  categories `revert`/`planted`/`insufficient` are NOT scored without
  `ArmRun.containment == "container"` (E1 decision, exit 7, no override).
  **Caveat (testing critic, recorded):** `plan` keys are as readable to a
  worker as the others; `plan` and `control` are scored without
  containment by user decision, and their results carry the same E1 risk.
  **Malformation is first-class (M1, 0.4.1), and BINDING.**
  A cell whose FINAL adjudication carries an error-severity validator
  finding that the engine did NOT act on is EXCLUDED from quality metrics
  (`exclusion: validator_errors`) and from paired deltas: a record the
  engine judged incoherent is not evidence, and a delta against one is
  confounded with the malformation. Whether a finding was acted on is
  recorded per finding as `Finding.acted`, NOT inferred from its code - only
  SUPPORTED/REFUTED rulings are downgraded, so the same code (e.g.
  `REF_MISSING`) is consequential on one ruling and inert on a CONTESTED or
  UNSUPPORTED one. Excluding creates a new bias, because only arm 4 passes
  critiques to the validator and so only it can emit
  `DISSENT_EMPTY_WITH_CONTEST`; `summary.comparison.blocked` is therefore
  set MECHANICALLY whenever any arm dropped cells for validator findings,
  and while it is set the decision rule may NOT be applied to the per-arm
  means. One exception is stated rather than hidden: a ledger written before
  0.4.2 carries no `Finding.acted`, so those findings ARE classified by
  code, using the coarse `validate.UNHANDLED_CODES` fallback that treats
  every `REF_*` as handled and therefore UNDER-REPORTS malformation on such
  a ledger. Classification is per FINDING, so a cell counts as coarsely
  scored when ANY of its findings lacks `acted`, not only when all do, and
  is reported as `validator_basis: coarse_codes`. `summary.comparison`
  reports which arms were scored that way and is BLOCKED while any were,
  because an arm scored by code and an arm scored by `acted` are measured
  against two different definitions of malformed.
  Findings the engine DID act on do not exclude - the `REF_*` family downgrades
  its ruling and is measured by `unsupported_claim_rate`; `VERDICT_*` forces
  ACCEPT to ESCALATE. That is the engine working, and excluding it would delete
  the denominator for the very behaviour those metrics exist to report.
  `test_score.py::test_the_binding_pre_registration_matches_the_scorer` asserts
  the paragraph above is the scorer's own `M1_PRE_REGISTRATION` verbatim, so this
  document cannot state a rule the code stopped implementing.

* A campaign cell whose ledger is unreadable is reserved pessimistically
  (every planned call of that arm, judge iterations included, at the worst
  case the retry driver can reach), so a corruption can halt later cells on
  the campaign budget. Intended fail-closed behaviour, resolvable by the
  operator: inspect or remove the corrupt cell, or raise `per_campaign_usd`,
  then `--resume`.
* Until the E1 containment exists only `control`/`plan` and plumbing runs
  are scorable; a BUDGET_TRIPPED cell is MISSING; contaminated or
  `scan_incomplete` cells are excluded from quality metrics and counted in
  cost.

## Settled (from `docs/history/PHASE0-PLAN-2026-08-21.md`)
* Arms: single model x3 lineages; naive consensus; independent +
  mechanical verification + meta-judge with NO critique (arm 3); arm 3 + one
  critique round (arm 4); incumbents (`/codex:adversarial-review`,
  ultrareview on a subset). Arms 3/3b/4 are a paired ablation: proposals and
  evidence are cached under an idempotency key that excludes the arm.
* >= 2 repeats per cell (`repeat_index` is in the key).
* Metrics: per-finding precision AND recall (file+line overlap with the fix
  hunk), unsupported-claim rate (script-checked refs), confident-wrong rate,
  abstention appropriateness, cost, wall-clock.
* A budget-tripped cell is MISSING, not ABSTAIN. Every retry is an event;
  failed attempts' cost counts.
* Corpus tasks are history-truncated snapshots built by `eris.snapshot`.
* Pre-registered rule (draft, to be finalised in `eval/README.md`): build
  the orchestrator only if arm 4 beats arm 3 by >= 10 points catch rate or
  halves confident-wrong at <= 2x cost, AND arm 3 beats the incumbents.

## Flag experiments already run (2026-08-21, this machine)
Captured envelopes: `tests/fixtures/envelopes/`.

| # | Claim | Result |
|---|---|---|
| T1 | plain `claude -p` in a repo with CLAUDE.md + SessionStart hook | Hook ran; CLAUDE.md injected (`PINEAPPLE` in the reply) |
| T2b | `--safe-mode` | No hook, no injection |
| T3 | `--bare` | `is_error: true`, "Not logged in" - breaks OAuth; FORBIDDEN |
| T4 | `--permission-mode plan` under `-p`, asked to write a file | Denied in ~7 s (`FAILED`); does not hang |
| T5 | `codex exec -s read-only --ignore-rules` | Write and network blocked by the OS sandbox; repo AGENTS.md STILL injected (`MANGO`) |
| T5b | + `-c project_doc_max_bytes=0` | Injection suppressed |
| T6 | gemini 0.46.0 `--approval-mode plan -o json` | Unusable: `IneligibleTierError`; approval mode overridden in an untrusted folder. The `gemini` CLI was uninstalled on 2026-08-22; replaced by Antigravity `agy` (below) |
| T7 | grok `--permission-mode plan` | Write blocked (`stopReason: cancelled`); reports `modelUsage`, `usage`, `total_cost_usd` |

## Experiment results (2026-08-22, this machine)

Captures that became fixtures: `tests/fixtures/envelopes/agy/1.1.18/`,
`claude/2.1.239/{schema,notools_text}.json`, `grok/1.0.5/schema.json` (each
with a `.meta.json` giving the argv). The `gemini` CLI is uninstalled; the
Google lineage is Antigravity `agy` 1.1.18.

| Id | Result |
|---|---|
| E1 | **FAILED** for claude (`--safe-mode --permission-mode plan --tools Read,Grep,Glob`), codex (`-s read-only …`), grok (`--permission-mode plan`): all printed both canaries (parent dir + sibling dir). E1b grok `--sandbox strict`: still leaked. Read-only modes confine writes, not reads. **agy PASSED with `--add-dir <snapshot>`** (A16: absolute paths outside the declared workspace → `permission check failed for read_file … user denied`, rc 1, no canary; A15 proves the same argv CAN read inside the workspace). A10b's earlier denial without `--add-dir` was vacuous (A14: agy cannot read its own cwd without a declared workspace); A10 (relative path) was `invalid_args`. agy's confinement is an in-process permission check, not OS-level. Consequence and containment options: `docs/SECURITY.md`. **Decision 2026-08-22: accept-and-scan (SECURITY.md option 4); plumbing/clean-control runs only; scored defect/ABSTAIN arms blocked until a portable (container) containment exists.** |
| A12–A16 (agy `--add-dir`) | A12/A13/A14 (no `--add-dir`, with and without `--disable-slash-commands`): `read_file` of `README.md` INSIDE the cwd DENIED (A12 tried `~/workspace`; A13 relative path `invalid_args`; A14 absolute path denied, rc 1). A15 (`--add-dir $cwd`): SUCCESS, response `MANGO KIWI\nhello\n` — read works AND the workspace's `AGENTS.md`/`GEMINI.md` rules are injected. A16 (`--add-dir $cwd`, canary absolute paths outside): DENIED, no leak. Therefore `--add-dir <snapshot realpath>` is REQUIRED (exactly once, = spawn cwd) and injection mitigation is Milestone 2b. Fixtures: `read_denied_inside_no_workspace`, `read_ok_with_add_dir`, `read_denied_outside_with_add_dir`. |
| E2 | `CLAUDE_CONFIG_DIR=<empty>` → "Not logged in"; `CODEX_HOME=<empty>` → 401. Fresh config dirs relocate credentials, not only state. agy (A8): relocated `HOME` → `status ERROR "authentication failed or timed out"`, OAuth URL on stderr, 60 s wait; auth is HOME-rooted. |
| E7 | claude plan mode refuses Bash even when Bash is in `--tools` (explicit `FAILED`, 1 turn). |
| E8 | `--tools ""` with a prompt that NEEDS a tool ("list the files") **HUNG** 240 s (killed by alarm, empty stdout). E8b: same flags with a pure-text prompt → `ok`, 1 turn, $0.04. Adjudicator prompts must never request tool actions; the Eris timeout is the backstop. |
| E9 | claude inline `--json-schema` → `structured_output` object (`stop_reason` tool_use, 2 turns); grok inline `--json-schema` → `structuredOutput` object + JSON text (`parse_grok` now prefers it). Inline form confirmed for both. |
| A1–A9 (agy) | Envelope keys `conversation_id, status, response, error?, duration_seconds, num_turns, usage{input,output,thinking,cache_read,total}`; `--json-schema` adds `structured_output` (EXACTLY the schema object) + a `json_schema` echo. Plan mode: no repo write, shell denied (rc 1, status ERROR, usage retained); `--sandbox` indistinguishable from plan alone (A4 == A2); `--print-timeout 5s` → parseable ERROR envelope (A7); no model id, no cost; full argv + marker rules → "ok" (A9). Every run writes a transcript + SQLite under `~/.gemini/antigravity-cli/` (≈1 MB/run; the doctor reports the size); a background auto-updater is spawned. `--model gemini-3.1-pro-high` is listed by `agy models` but the agy log said "not in local config, defaulting" — whether that id executed is UNKNOWN (no model id in the envelope). |
| A6 / A10 / A10b / A11 / A14–A16 (agy, `--disable-slash-commands`) | stderr on every such run: `warning: --mode plan has no effect while slash command expansion is disabled.` The observed protections (write denied A6, shell denied, read outside the workspace denied A16) therefore come from agy's non-interactive permission check, not from plan mode; A16 shows it holds with `--add-dir`. The flag set is kept as specified (it still denied everything it was asked to deny) but the mechanism label in SECURITY.md is "permission check", and re-verification on any agy version change is required. |
| A9 + A11 (agy injection, NO declared workspace) | Snapshot with `GEMINI.md`/`AGENTS.md`/`CLAUDE.md` markers, `.agents/rules/r.md` marker and `.agents/hooks.json` (SessionStart touching a file); prompt asked to quote any begin-reply instructions verbatim. Response quoted only agy's own system-prompt thought-format instruction; no planted marker; hook file not created. **No injection WITHOUT a declared workspace — vacuous**: agy had not loaded the directory at all (A14). With `--add-dir` the rules ARE injected (A15, above). |

## First live plumbing run (2026-08-23, this machine)

`eval/run.py run --task-file eval/corpus/plumbing-control/task.json --arm
single --panel claude --repeat-index 0` — the first time the harness was
pointed at a real worker CLI. The harness itself behaved: the pack was built,
the missing workers were recorded as absences, the contamination scan ran
twice, the run exited 3 and nothing crashed. Two defects surfaced that no
hermetic test could have caught, because the fakes never execute a real CLI
or a real `git`.

| Id | Result |
|---|---|
| M2c-A | **`USER` is required in the worker environment.** `claude` reported `Not logged in · Please run /login` although `claude auth status` said `loggedIn: true`. Bisected: full shell env → `is_error: false`; `HOME` + `PATH` + `TMPDIR` + every var the harness adds → **`Not logged in`**; + `USER` → `ok`; + `LOGNAME` only → `Not logged in`; + `SHELL` only → `Not logged in`. The failure presents as an auth error, so it reads as an operator mistake — the worst possible symptom. FIXED: `launch.build_env` sets `USER` from `launch.resolve_user()` (passwd first, `getpass` fallback; never a filtered `os.environ`); `eris doctor` warns when it cannot be resolved. |
| M2c-B | **A read-only `git` command tripped the verification tripwire.** Ledger: `snapshot.violated argv=["/usr/bin/git","status","--porcelain"]` with different before/after tree hashes, then `verify.refused` for `git ls-files` and `git log --oneline -n 20` ("an earlier command changed the verification copy"). `git status` refreshes `.git/index` (its stat cache) — on a freshly copied verification tree the recorded stat data never matches, so it always wants to. `git ls-files` and `git log` alone do not. FIXED, both halves: Eris appends `--no-optional-locks` to every `git` verification invocation (before the subcommand; still hard-denied from a model), and the tripwire hash excludes `.git/index` and `.git/index.lock` — and nothing else, so a command that rewrites refs, objects, HEAD, config or hooks is still caught. `test_verify_real_git.py` runs the real battery against a real repo. |
| M2c-C | `pack.incomplete` on the same run was a CONSEQUENCE of M2c-B (the battery could not complete). Re-check it on the next live run; report it if it persists. NOT RE-RUN. |
| M2c-1 | `policies/default.yaml` declared `~/.grok/auth.json` as a credential file; `eris doctor` reports it absent — the Grok CLI no longer creates it. REMOVED (with the reason in the policy comment). Where grok keeps its credentials is UNKNOWN. |
| M2c-2 | **OPEN portability item.** The tracked policy holds machine-specific ABSOLUTE verify executables (`/opt/homebrew/bin/{ruff,mypy,pytest}`) while the machine-specific hashes live in the gitignored `pins.yaml`. The path belongs with the hash. Two candidate designs: (a) resolve the command by NAME against `path_env` at pin time and record only the name in the tracked policy, or (b) let `pins.yaml` supply the path alongside the sha256, the tracked policy carrying a name and a `path` only as a hint. Not fixed in M2c: it touches the policy schema and the pin command, which is a structural change. |

## Still open (must run before corpus runs)

| Id | Question | How | Status |
|---|---|---|---|
| E3 | Codex `--json` model id | Not present in any event of the 0.147.0 capture. `model_executed=None` is recorded. Check `codex exec --help` for a model-reporting flag or read `~/.codex/config.toml` as a declared (not observed) model. | OPEN |
| E6 | Per-call cost for codex and agy | grok and claude report `total_cost_usd`; codex and agy emit token usage only. Decide a pricing table source or keep cost `None` with usage (current). | OPEN |
| E10 | Redactor throughput on real worker output (currently ~3 MB/s synthetic) | Time `put_blob` on a captured 10 MB envelope. | NOT RUN |
| E11 | agy rules/hook injection WITH a declared workspace (`--add-dir`) | CONFIRMED for `AGENTS.md` + `GEMINI.md` (A15: `MANGO KIWI`). Still to measure with `--add-dir`: `CLAUDE.md`, `.agents/rules/r.md`, and whether a `.agents/hooks.json` SessionStart hook fires (the hook question referenced from SECURITY.md lives here). Re-run after any change of the pinned `agy` binary. Mitigation: E16. | INJECTED (1.1.18); hooks UNKNOWN |
| E16 | Per-worker snapshot sanitization for agy (strip `AGENTS.md`/`GEMINI.md`/`CLAUDE.md`/`.agents/` from the agy worktree copy, recorded in the manifest) — the mitigation for E11 | BUILT in 0.3.0 (`eris.sanitize`; agy and grok `sanitize_snapshot: true`; `SnapshotSanitization` record; residual channels in `docs/SECURITY.md`). Whether `.agents/hooks.json` fires from a declared workspace is still E11. | BUILT (M2b) |
| A17 | agy `--add-dir` symlink traversal: does a symlink INSIDE the declared workspace pointing outside it let agy read outside? | Live run 2026-08-22 (`scratchpad/exp2/out/A17_agy_symlink.stdout`): agy resolved `LINK_TO_OUTSIDE.txt -> ../outside` to its real path and DENIED the read (`permission check failed`). Confinement resolves symlinks; the sanitizer's symlink drop is defence in depth. | PASS |
| E17 | grok injection reproducibility (E1's reply began `MANGO PINEAPPLE`) | Live run 2026-08-22 (`scratchpad/exp2/out/E17_grok_injection.stdout`, fixture `grok/1.0.5/api_error_403.json`): asked to quote any begin-reply instructions, grok replied `None`; a second prompt was refused by the API (403 `SAFETY_CHECK_TYPE_BIO`). Injection observed once, not reproduced; grok is sanitized anyway. | NOT REPRODUCED |
| E12 | Eris env `PATH` (policy `path_env` lacks `~/.local/bin`): do agy/claude/codex spawn helpers by PATH? | `eval/run.py dry-run` per worker, then one live `invoke` each and inspect stderr / exit status. | NOT RUN |
| E13 | Which file under `HOME` agy actually needs for auth (A8: relocated HOME → auth error, so HOME-rooted) | Bisect a relocated HOME containing only `~/.gemini/antigravity-cli/` vs only `~/.gemini/oauth_creds.json`. | UNKNOWN |
| E14 | Per-worker read confinement on the host: codex restricted-read permission profile path set; claude `--settings` read-deny rules | Candidate per-worker mitigations, unverified; grok's documented strict sandbox already FAILED (E1b). | UNKNOWN |
| E15 | agy `--sandbox` mechanism and the effect of `AGY_CLI_DISABLE_AUTO_UPDATE` | Seatbelt profile strings are embedded in the binary (shell commands only, per those strings); the env name comes from the binary's strings — effect ASSUMPTION. Verify with a pinned binary and a watch on the auto-updater process. | ASSUMPTION |
| M1-1 | Is `DISSENT_EMPTY_WITH_CONTEST` gutting arm 4? | After the FIRST scored campaign read `summary.per_arm[*].validator.codes`. `_contest_exists` counts ANY non-`REFUTED` challenge and nothing ever refutes one, so every arm-4 cell with a challenge and empty dissent is excluded from quality metrics. If that share is large, the question is whether `_contest_exists` is too broad - NOT whether the finding should force ESCALATE (decided 2026-08-30: it should not). See `docs/decisions/2026-08-30-deferred-validator-decisions.md` | OPEN, checkable only from a scored run |

## Corpus (Milestone 2)
`eval/corpus/plumbing-control/` is the first entry and is a **plumbing
control, not a scored corpus task**: two functions, no defect, no distractors.
It exists to exercise the harness end to end and is excluded from Phase 0
metrics - enforced, not merely documented: `task.json` carries
`"scored": false`, campaign discovery skips it, and `eval/score.py` reports
its cells as `skipped: not a scored corpus task`. An explicit `--task-file`
still runs it. Its `snapshot/` is GENERATED, never committed — a git repository
cannot live inside another one, and `.gitignore` excludes
`eval/corpus/*/snapshot/`; the working tree is tracked in `files/` and
`eval/make_control_snapshot.py` (portable Python, not POSIX shell) rebuilds
it - see that directory's README.

The scored corpus: ~25-30 tasks from Athena's history: ~10 hunk-level reverts of real fixed
defects, 5 planted bugs, 5 plan reviews with known pitfalls, 5 clean controls,
2 insufficient-evidence tasks (correct answer = ABSTAIN). Keys in
`eval/corpus/<task>/key.json`; snapshots built with `eris.snapshot` at the
pre-fix sha. Scoring by `eval/score.py` (mechanical location match + blind
human adjudication; no participating model grades its own run).
