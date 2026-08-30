# Eris Engine — DRAFT design synthesis (for adversarial review)

> **HISTORICAL — not the live plan.** The body below is as written on 2026-08-21
> and is kept that way for provenance; only this banner was added (2026-08-30).
> Where the body describes metrics or the build/don't-build rule it is
> **out of date**: the live documents are
> [`docs/EVAL-PLAN.md`](../EVAL-PLAN.md) for the plan and rule,
> [`docs/INVARIANTS.md`](../INVARIANTS.md) for what is enforced, and
> [`docs/decisions/`](../decisions/) for why. Read those before acting on anything here.

Status: draft produced by the synthesizer after six independent role reports
(Athena reuse analyst, scope critic, workflow architect, security reviewer,
provenance architect, MVP reducer). Nothing has been built. The Eris directory
is empty and must stay empty. Reviewers: attack this document; do not edit repos.

Evidence base: Athena repo at
~/Documents/Projects/Claude/Athena/athena-assistant (read-only);
`--help` of claude 2.1.239, codex 0.147.0, gemini 0.46.0, grok 1.0.5,
hermes 0.16.0, opencode 1.18.21 on this Mac; web sources cited by the role
agents (debate literature, Anthropic/OpenAI multi-agent guidance, LangGraph,
Langfuse/Phoenix self-hosting, ultrareview docs).

## D1. Executive position (provisional)

Eris should be a SEPARATE, deliberately small repository — NOT an Athena
module, and NOT (yet) an orchestration service. Its first deliverable is an
evaluation harness + a decision ledger, because:

- Athena's provider layer is engineered as the inverse of what Eris workers
  need: neutral temp cwd, tools denylisted, no model/cwd/permission parameters,
  no cancellation, text-in/text-out (providers/base.py:37-51, claude.py:37-43,
  148-171; INVARIANTS "Providers & routing"). `ProviderRouter.route()` is a
  first-success fallback chain (router.py:161-223), not fan-out. Reuse is
  pattern-level only. Putting Eris in Athena would require reversing
  test-pinned invariants and coupling a token-heavy, write-capable workflow to
  a no-auth single-user web app.
- But the scope critic's case is strong and partly conceded: every mechanical
  ingredient already exists (Codex plugin's schema-validated adversarial
  review with sandbox read-only; `claude -w`, `gemini -w`, `hermes --worktree`;
  per-CLI read-only flags; `--json-schema`/`--output-schema`), and the
  published literature (multi-agent debate) says independence + mechanical
  verification carry the value while debate ROUNDS degrade facts and amplify
  bias. The ONLY thing no existing tool provides is a durable, content-
  addressed, hash-bound decision record with approvals and dissent.
- Therefore: the repo is justified by the LEDGER and the EVAL, not by the
  orchestrator. The orchestrator is built only if Phase 0 shows a gain.

Confidence: ~85% "not inside Athena"; ~65% "separate repo is the right home
vs. pure config over Claude Code + Codex plugin"; ~90% "do Phase 0 before
building any state machine".

Strongest counterargument: option A (skills/hooks over Claude Code + Codex
plugin + worktrees + a JSONL ledger written by a shell script) can run the
Phase 0 experiment in days with zero new runtime, and if arm 3 ≈ arm 4 the
"engine" is a shell script.

## D2. Scope

MVP = `eris review <repo> (--question|--diff|--plan) [--proposals-from ...]`
read-only; output `runs/<id>/decision.json` + `.md`.
NOT in MVP: code writing, UI, HTTP API, DB, container isolation, model-judged
risk classification, provider fallback/ranking, streaming, Hermes worker, memory.
Modes: ONE pipeline. "Synthesis" = same pipeline with `--proposals-from`
(skips PROPOSE, keeps critique+verify+adjudicate). "Direct" is Athena's job,
not Eris's; Eris's only direct-ish path is `--panel` of size 1 for verification-
only runs.

## D3. Protocol (changed from the user's hypothesis; each change has a reason)

1. TRIAGE replaces CLASSIFY_RISK: human chooses mode in MVP; later a RULES-
   based tier (protected paths, external side effect, irreversible, blast
   radius, novelty, verifiability) with a model consulted only for `unknown`
   fields and recorded as model_asserted. Reason: a model judging risk at the
   gate of a system built to distrust model judgment is self-undermining.
2. Independence = distinct VENDOR LINEAGE + separate fresh processes + no
   shared context + byte-identical prompt/evidence pack (hash recorded).
   Evidence: ~/.hermes/config.yaml → OpenAI model; ~/.codex/config.toml →
   OpenAI model; so Hermes and Codex are ONE lineage. Tier-3 needs ≥3
   lineages: Anthropic (claude), OpenAI (codex), Google (gemini), xAI (grok).
   Hermes has no read-only/sandbox flag → not a reviewer; it is a CALLER
   (Phase 4).
3. EXACTLY ONE critique round, meta-judge shape: critics see proposals, never
   each other; no rebuttal chat; a mandatory `framing` lens ("assume the
   leading proposal is wrong"). Reason: literature on debate rounds (fact loss,
   bias amplification); scope critic's hard cap.
4. Challenges must carry evidence_refs OR an executable evidence_request;
   otherwise the ENGINE drops them (code, not a model).
5. Verification: Eris executes allowlisted argv prefixes (pytest, ruff, mypy,
   git diff/log/grep/show) chosen from policy; model-proposed commands are
   REQUESTS, recorded and refused unless allowlisted. Evidence kinds:
   test_output, tool_output, repo_fact, document_quote, dry_run,
   human_attestation. `model_assertion` is stored but never adjudicable.
6. Adjudication rule, engine-enforced after the model answers: each claim →
   SUPPORTED/REFUTED/CONTESTED/UNSUPPORTED; any ref that is missing, is
   model_asserted, or predates the claim revision → downgraded to UNSUPPORTED
   and logged; 3 downgrades → swap adjudicator lineage once, then ESCALATE.
   "All models agree" with no evidence = UNSUPPORTED. Verdicts: ACCEPT |
   REVISE | ESCALATE | ABSTAIN | REJECT; dissent[] and residual_risks[] are
   REQUIRED fields (schema-invalid without them).
7. Stop: max_rounds (MVP: 1 critique round), per-run token/USD/wall ceilings,
   convergence; ceilings force ADJUDICATE (may ABSTAIN), never silent trunc.
8. Human gate = guard on any transition leaving the sandbox (egress for
   evidence collection; APPLY). Approval binds to content hash of canonical
   diff/argv + base commit + policy version; single-use, TTL, nonce; execute
   from the approved bytes in a fresh worktree; recompute hash before exec.

## D4. Architecture

- Worker Protocol (not Athena's ProviderAdapter):
  `run(prompt, context_pack, schema, perms: {cwd, mode=read_only, timeout}) -> WorkerResult{worker, family, model_executed(from envelope), success, error, text, structured, usage, cost_usd, duration_ms, argv}`; never raises.
  Impls: SubprocessWorker (claude/codex/gemini/grok CLIs) and
  OpenAICompatibleWorker (chatgpt, x.ai, Ollama; context-pack only, no repo
  access — recorded as a confound).
- Subprocess: explicit env allowlist (never os.environ.copy — Athena inherits
  the full env incl. API keys into every CLI child: zero `env=` in providers/),
  stdin=DEVNULL, argv lists, start_new_session + process-group kill on timeout,
  stdout byte cap, ANSI strip.
- Ledger: files are the source of truth. `runs/<id>/events.jsonl` (append-
  only, fsync), `blobs/sha256/..` content-addressed (write-temp+rename,
  redaction BEFORE hashing), `manifest.json` written last. SQLite index
  (stdlib, WAL, BEGIN IMMEDIATE) added in Phase 2 when eval aggregation needs
  it; rebuildable from events. No Postgres.
- Every record has `origin: model_asserted | mechanically_observed |
  human_entered`. Model rationale rendered as "model-provided rationale (not
  a trace of internal reasoning)".
- Events carry W3C-shaped trace_id/span_id so an OTLP export can be added
  later; no tracing backend in MVP (Langfuse self-host ≈ 5 containers / ~21
  GiB RAM; Phoenix is the later candidate).
- State machine: explicit table-driven, pure `transition(state, event)`;
  no LangGraph/Temporal/Prefect (LangGraph checkpoints ≠ durable side-effect
  execution; the APPLY two-phase problem is custom anyway; Temporal = a
  server on a single-user box).

## D5. Security model (Phase-gated; contested, see D7)

- Phase 1 roles on the host ONLY as policy-restricted: claude `-p --safe-mode
  --permission-mode plan --tools "Read,Grep,Glob" --no-session-persistence
  --json-schema`; codex `exec -s read-only --ignore-user-config --ignore-rules
  --ephemeral --output-schema`; gemini `-p --approval-mode plan -o json`;
  grok `-p --permission-mode plan --json-schema`. Adjudicator: no tools.
- Verification executes repo code (pytest runs conftest.py). Phase 1 permits
  this only on TRUSTED repos (Athena, own repos) after a pre-launch repo-config
  scan (.claude/, .codex/, .gemini/, AGENTS.md, CLAUDE.md, .git/hooks, core.
  hooksPath, conftest.py, .envrc, symlinks escaping the tree) hashed into the
  evidence pack with human acknowledgement. Containers (docker, `--network
  none`, cap-drop, ro bind of worktree) are REQUIRED before any untrusted repo
  or any writer role (Phase 3). Worktrees are merge hygiene, not a boundary.
- Write-time redaction at the single blob/ledger write chokepoint: known key
  shapes + exact values of Eris's own env allowlist; `[REDACTED:sha-8]`;
  record {pattern_id,count}. Ledger writes FAIL LOUDLY (not Athena's never-
  raise audit contract) — an unrecorded approval is a correctness bug.
- Supply chain: exact pins, pip-audit BLOCKING, vendor CLI version+binary
  hash captured per run and flagged on change; auto-update disabled in
  containers.

## D6. Stack

Python ≥3.12 developed on 3.14 (pydantic 2.13.x, typer, pytest 9, openai 3.x,
ruff, mypy verified importing on 3.14 in a scratch venv; Athena's own .venv is
3.14.2 — its 3.10/3.11 pins are CI/Docker only). pip+venv+exact-pinned
requirements (no uv on this machine). Pydantic v2 everywhere. argparse now,
typer if >3 subcommands. No FastAPI until Phase 4. src/eris layout. Copy from
Athena: ruff rule set (+ add I and `ruff format` day one), coverage ratchet,
pre-commit, CI skeleton (matrix 3.12/3.14, secret-free), Taskfile ci/lint/
typecheck/audit, hermeticity autouse fixture (extend: patch subprocess to
raise by default), subprocess hardening. mypy strict on src/ day one.

## D7. Known disagreements to adjudicate

1. Scope critic (don't build a separate service; config over tools first,
   75%) vs MVP reducer + reuse analyst (small separate repo now). Synthesizer
   resolution: separate repo whose Phase 0/1 content IS the experiment
   harness; orchestrator gated on results. Is this a dodge?
2. Security (container AND worktree for any exec-capable role) vs MVP
   (no containers in Phase 1). Resolution: trusted-repo-only + repo-config
   scan + human ack in Phase 1; containers mandatory at Phase 3 / untrusted
   repos. Residual risk explicitly recorded.
3. Provenance (SQLite index from the start) vs MVP (files only until ~50
   runs). Resolution: files first; SQLite in Phase 2; safe because events
   are replayable.
4. Architect's richer state machine (TRIAGE tiers, REVISE loops up to 3
   rounds, APPLY two-phase) vs scope critic's hard cap (one critique round,
   no round 2 without a new human-initiated run). Resolution: MVP = 1 round;
   the state machine is designed but only PROPOSE→CRITIQUE→VERIFY→ADJUDICATE
   is implemented in Phase 1.
5. Whether "direct" mode belongs in Eris at all. Resolution: no (Athena's
   job), except panel=1 verification-only runs.

## D8. Phase 0 experiment (pre-registered; runs BEFORE the orchestrator)

Corpus ~25–30 tasks from Athena's history: ~10 hunk-level reverts of real
fixed defects (REVIEW-3.0 F1/F4/F14, caldav ETag, SSRF, timeouts, XML
escaping, cwd bleed, hermeticity), 5 planted bugs, 5 plan reviews with known
pitfalls, 5 clean controls, 2 insufficient-evidence tasks (correct = ABSTAIN).
Arms: (1) single model ×3 families; (2) naive consensus; (3) independent +
mechanical verification + meta-judge, NO critique; (4) arm 3 + one critique
round; (5) incumbent: /codex:adversarial-review, ultrareview on a subset.
Metrics: catch rate (file+line overlap with fix hunk), FP rate on controls,
unsupported-claim rate (script-checked refs), confident-wrong rate, cost,
wall-clock, abstention appropriateness. Scoring: mechanical location match +
blind human adjudication; no participating model grades its own run.
Pre-registered decision rule: build the orchestrator only if arm 4 beats
arm 3 by ≥10 pts catch rate or halves confident-wrong at ≤2× cost, AND arm 3
beats arm 5. If arm 3 ≈ arm 4: Eris = independent workers + tests + meta-
judge + ledger (no cross-examination stage). If arm 5 ≈ arm 3: build only the
ledger/approval layer around the Codex plugin.

## D9. Repo bootstrap (after approval; nothing created yet)

README.md, AGENTS.md (canonical, with the truth-over-agreement guardrail
verbatim), CLAUDE.md (pointer), LICENSE (user decision), .gitignore,
pyproject.toml, requirements.txt, Taskfile.yml, .pre-commit-config.yaml,
.github/workflows/ci.yml, src/eris/{__init__,version,schemas,ledger,workers/
{base,subprocess_cli,openai_compat},verify,adjudicate,cli}.py (skeletons
only for Phase 1), tests/{conftest,test_schemas,test_ledger,test_workers_
hermetic}.py, docs/{ARCHITECTURE,PROTOCOL,INVARIANTS,EVAL-PLAN,SECURITY}.md,
eval/corpus/ (task keys), policies/default.yaml. git init at bootstrap.
