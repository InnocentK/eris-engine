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
| T6 | gemini 0.46.0 `--approval-mode plan -o json` | Unusable: `IneligibleTierError`; approval mode overridden in an untrusted folder |
| T7 | grok `--permission-mode plan` | Write blocked (`stopReason: cancelled`); reports `modelUsage`, `usage`, `total_cost_usd` |

## Open experiments (must run before corpus runs)

| Id | Question | How | Status |
|---|---|---|---|
| E1 | Can a worker READ outside the snapshot (answer key, Athena tree, vendor memory stores)? | Canary-read smoke test: plant a unique token in a sibling directory and in `~/.claude`/`~/.codex` memory locations; prompt each worker to find it; grep envelopes. | NOT RUN |
| E2 | Do fresh `CLAUDE_CONFIG_DIR` / `CODEX_HOME` relocate credentials (breaking auth) or only state? | Set each to an empty dir under `invoke`, observe `is_error`/auth failures. | UNKNOWN |
| E3 | Codex `--json` model id | Not present in any event of the 0.147.0 capture. `model_executed=None` is recorded. Check `codex exec --help` for a model-reporting flag or read `~/.codex/config.toml` as a declared (not observed) model. | OPEN |
| E4 | Gemini envelope shape | Cannot capture (auth broken). `parse_gemini` is defensive (`parse_mode` records json / balanced_extract / none). Alternative: Gemini via an OpenAI-compatible API endpoint (Milestone 2). | BLOCKED |
| E5 | `GEMINI_CLI_HOME` / `GROK_HOME` semantics | Read `--help`; test whether setting them relocates auth. Note: `~/.grok/bin/grok` exists on this machine (found by the doctor before the hermeticity fix). | UNKNOWN |
| E6 | Per-call cost for codex and gemini | grok and claude report `total_cost_usd`; codex emits token usage only. Decide a pricing table source or record cost as `None` with usage. | OPEN |
| E7 | Does claude `--permission-mode plan` deny consistently across tool types (Bash vs Write vs Edit)? | Repeat T4 with prompts that target each tool. | PARTIAL (T4 covered file creation) |
| E8 | Does `--tools ""` on claude fully disable tools without error? | Run with the empty list, confirm no tool use in the envelope. | NOT RUN |
| E9 | `--json-schema` argument form for claude 2.1.239 and grok 1.0.5 (inline JSON string vs file path) | `--help` + one run each with a trivial schema. The builders currently pass the JSON text inline (ASSUMPTION). | UNKNOWN |
| E10 | Redactor throughput on real worker output (currently ~3 MB/s synthetic) | Time `put_blob` on a captured 10 MB envelope. | NOT RUN |

## Corpus (Milestone 2)
~25-30 tasks from Athena's history: ~10 hunk-level reverts of real fixed
defects, 5 planted bugs, 5 plan reviews with known pitfalls, 5 clean controls,
2 insufficient-evidence tasks (correct answer = ABSTAIN). Keys in
`eval/corpus/<task>/key.json`; snapshots built with `eris.snapshot` at the
pre-fix sha. Scoring by `eval/score.py` (mechanical location match + blind
human adjudication; no participating model grades its own run).
