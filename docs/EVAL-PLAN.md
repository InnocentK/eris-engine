# Phase 0 evaluation plan

Status: pre-registration is Milestone 2 (`eval/README.md` with arms, metrics,
per-category decision rule and a USD ceiling from a 3-task pilot). This file
records what is already settled, what the flag experiments showed, and the
open experiments that must run before any corpus run.

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
| E1 | **FAILED** for claude (`--safe-mode --permission-mode plan --tools Read,Grep,Glob`), codex (`-s read-only …`), grok (`--permission-mode plan`): all printed both canaries (parent dir + sibling dir). E1b grok `--sandbox strict`: still leaked. Read-only modes confine writes, not reads. **agy PASSED** (A10b, full required argv, absolute path outside cwd): `permission check failed for read_file … user denied`, rc 1, no canary in the output — an in-process permission check, not OS-level. A10 (relative `../CANARY.txt`) was inconclusive (`invalid_args`), superseded by A10b. Consequence and containment options: `docs/SECURITY.md`. |
| E2 | `CLAUDE_CONFIG_DIR=<empty>` → "Not logged in"; `CODEX_HOME=<empty>` → 401. Fresh config dirs relocate credentials, not only state. agy (A8): relocated `HOME` → `status ERROR "authentication failed or timed out"`, OAuth URL on stderr, 60 s wait; auth is HOME-rooted. |
| E7 | claude plan mode refuses Bash even when Bash is in `--tools` (explicit `FAILED`, 1 turn). |
| E8 | `--tools ""` with a prompt that NEEDS a tool ("list the files") **HUNG** 240 s (killed by alarm, empty stdout). E8b: same flags with a pure-text prompt → `ok`, 1 turn, $0.04. Adjudicator prompts must never request tool actions; the Eris timeout is the backstop. |
| E9 | claude inline `--json-schema` → `structured_output` object (`stop_reason` tool_use, 2 turns); grok inline `--json-schema` → `structuredOutput` object + JSON text (`parse_grok` now prefers it). Inline form confirmed for both. |
| A1–A9 (agy) | Envelope keys `conversation_id, status, response, error?, duration_seconds, num_turns, usage{input,output,thinking,cache_read,total}`; `--json-schema` adds `structured_output` (EXACTLY the schema object) + a `json_schema` echo. Plan mode: no repo write, shell denied (rc 1, status ERROR, usage retained); `--sandbox` indistinguishable from plan alone (A4 == A2); `--print-timeout 5s` → parseable ERROR envelope (A7); no model id, no cost; full argv + marker rules → "ok" (A9). Every run writes a transcript + SQLite under `~/.gemini/antigravity-cli/` (≈1 MB/run; the doctor reports the size); a background auto-updater is spawned. `--model gemini-3.1-pro-high` is listed by `agy models` but the agy log said "not in local config, defaulting" — whether that id executed is UNKNOWN (no model id in the envelope). |
| A6 / A10 / A10b / A11 (agy, `--disable-slash-commands`) | stderr on every such run: `warning: --mode plan has no effect while slash command expansion is disabled.` The observed protections (write denied A6, shell denied, read outside cwd denied A10b) therefore come from agy's non-interactive permission check, not from plan mode. The flag set is kept as specified (it still denied everything it was asked to deny) but the mechanism label in SECURITY.md is "permission check", and re-verification on any agy version change is required. |
| A9 + A11 (agy injection) | Snapshot with `GEMINI.md`/`AGENTS.md`/`CLAUDE.md` markers, `.agents/rules/r.md` marker and `.agents/hooks.json` (SessionStart touching a file); prompt asked to quote any begin-reply instructions verbatim. Response quoted only agy's own system-prompt thought-format instruction; no planted marker; hook file not created. No repo-rule/hook injection observed (3 samples: A9, A11, plus A1's plain run). The binary contains rule/hook loaders, so this stays in the open list for re-verification on version change. |

## Still open (must run before corpus runs)

| Id | Question | How | Status |
|---|---|---|---|
| E3 | Codex `--json` model id | Not present in any event of the 0.147.0 capture. `model_executed=None` is recorded. Check `codex exec --help` for a model-reporting flag or read `~/.codex/config.toml` as a declared (not observed) model. | OPEN |
| E5 | `GEMINI_CLI_HOME` / `GROK_HOME` semantics | Read `--help`; test whether setting them relocates auth. Note: `~/.grok/bin/grok` exists on this machine (found by the doctor before the hermeticity fix). | UNKNOWN |
| E6 | Per-call cost for codex and agy | grok and claude report `total_cost_usd`; codex and agy emit token usage only. Decide a pricing table source or keep cost `None` with usage (current). | OPEN |
| E10 | Redactor throughput on real worker output (currently ~3 MB/s synthetic) | Time `put_blob` on a captured 10 MB envelope. | NOT RUN |
| E11 | agy rules/hook injection, STRONG form on every agy version change | Re-run A11 (markers in `GEMINI.md`, `AGENTS.md`, `CLAUDE.md`, `.agents/rules/r.md`, `.agents/hooks.json` SessionStart) after any change of the pinned `agy` binary. | 3 samples, none injected (1.1.18) |
| E12 | Eris env `PATH` (policy `path_env` lacks `~/.local/bin`): do agy/claude/codex spawn helpers by PATH? | `eval/run.py dry-run` per worker, then one live `invoke` each and inspect stderr / exit status. | NOT RUN |
| E13 | Which file under `HOME` agy actually needs for auth (A8: relocated HOME → auth error, so HOME-rooted) | Bisect a relocated HOME containing only `~/.gemini/antigravity-cli/` vs only `~/.gemini/oauth_creds.json`. | UNKNOWN |
| E14 | Per-worker read confinement on the host: codex restricted-read permission profile path set; claude `--settings` read-deny rules | Candidate per-worker mitigations, unverified; grok's documented strict sandbox already FAILED (E1b). | UNKNOWN |
| E15 | agy `--sandbox` mechanism and the effect of `AGY_CLI_DISABLE_AUTO_UPDATE` | Seatbelt profile strings are embedded in the binary (shell commands only, per those strings); the env name comes from the binary's strings — effect ASSUMPTION. Verify with a pinned binary and a watch on the auto-updater process. | ASSUMPTION |

## Corpus (Milestone 2)
~25-30 tasks from Athena's history: ~10 hunk-level reverts of real fixed
defects, 5 planted bugs, 5 plan reviews with known pitfalls, 5 clean controls,
2 insufficient-evidence tasks (correct answer = ABSTAIN). Keys in
`eval/corpus/<task>/key.json`; snapshots built with `eris.snapshot` at the
pre-fix sha. Scoring by `eval/score.py` (mechanical location match + blind
human adjudication; no participating model grades its own run).
