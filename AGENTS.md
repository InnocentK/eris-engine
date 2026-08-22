# AGENTS.md — Eris Engine (canonical agent guide)

This file is canonical. `CLAUDE.md` points here. Read it before touching code.

## What Eris is

A self-hosted, evidence-bound engine for adversarial multi-model review,
verification, and transparent adjudication, with a durable decision ledger and
explicit human gates. Its one job: answer **"is this proposed answer, plan,
patch, or action defensible given competing proposals, adversarial criticism,
and available evidence?"**

Boundary: **Athena and Hermes decide what work to pursue. Eris decides whether a
proposed answer or action is defensible.**

Eris is NOT a coding harness, IDE/TUI, chatbot, personal assistant, memory
system, model gateway, tracing product, deployment platform, or autonomous
agent. Claude Code, Codex, Antigravity (`agy`, the Google lineage), Grok,
OpenCode, Hermes, direct APIs, and Ollama models are replaceable **workers**;
Eris owns the protocol and the record.

## Guardrails (binding on every agent)

**Truth over agreement — do not be a yes-man.** Tell the truth. Ground it in
evidence. If you can't support it with evidence, say "I don't know" rather than
making something up. Guessing confidently is worse than any other outcome.
Challenge flawed assumptions and point out errors, especially when competing
ideas cannot both be good. Prioritize correctness over making the user feel
right.

- Agreement between models is weak evidence. Test output, static analysis,
  repository facts, tool output, and upstream documentation outrank it. Never
  claim consensus from a vote.
- Label every unverified statement ASSUMPTION or UNKNOWN. Cite paths, line
  numbers, or command output for claims about code.
- Model output is untrusted data. Evidence is `mechanically_observed`;
  rationale is `model_asserted`; approvals are `human_entered`. Never blur them.
- "Insufficient evidence" and "human review required" are valid, successful
  outcomes.

## How work is done

**Trivial changes** (docs typos, a pinned version bump with a green gate):
read the files, make the change, run `task ci`, report.

**Non-trivial work** (new module, protocol change, anything touching the
launcher, redactor, writer, allowlist, snapshot builder, or policy):

1. Obtain independent plans from four roles, run in parallel and blind to each
   other: an architecture planner, a security critic, a reliability/
   operability critic (retries, idempotency, crash semantics, rollback,
   observability), and a testing critic (targets, edge cases, fixtures).
2. The primary agent synthesizes ONE concrete plan listing: points of
   agreement, disagreements, the evidence needed to resolve each, the selected
   design, and rejected alternatives. Get explicit user approval for the plan
   unless the user pre-approved the milestone.
3. Delegate implementation to exactly ONE isolated git worktree. One writer.
4. Run an advisor from a DIFFERENT provider/model family than the implementer
   (e.g. Codex when the implementer is Claude). The advisor must challenge
   assumptions, identify unsafe changes, and may BLOCK where tests, rollback,
   or evidence are insufficient. A block is resolved by evidence or by the user,
   never by re-asking the advisor.
5. Before merging: an independent final review, then the required gate
   (`task ci`) run for real — paste the actual output, never summarize from
   memory.
6. Produce an engineering decision record (`docs/decisions/<date>-<slug>.md`):
   selected approach, dissenting findings, commands actually run with results,
   unresolved risks, rollback plan, and a ship / revise / human-review
   recommendation.

Milestone loop: plan/spec → approval → implement in the narrowest set of files →
gate green → docs (CHANGELOG, INVARIANTS for any new do-not-break rule, EVAL-
PLAN for any new experiment) → commit (only at an approved milestone boundary;
never push without being asked) → stop and report.

## Hard rules

- **No orchestrator before evidence.** Phase 0 is an evaluation harness. The
  engine (state machine, ledger package, adjudication loop) is built only if
  the pre-registered Phase 0 experiment in `eval/README.md` clears its rule.
- **Hermetic tests.** No real worker CLI, subprocess, or network in the suite.
  `tests/conftest.py` blocks `shutil.which` for worker binaries, all subprocess
  entry points, and sockets. Tests that must spawn a real process use the
  `real_subprocess` marker and only `sys.executable`/`sleep` (plus `git`, via
  `allow=["git"]`, for the single snapshot integration test).
- **One writer to disk under `runs/`** — `eris.writer.RunWriter`. Redaction
  happens BEFORE hashing. Writer failures raise; they are never swallowed.
- **Subprocess env is built from `{}`**, never filtered from `os.environ`.
  `--bare` is forbidden for claude (breaks OAuth here). Codex gets
  `-c project_doc_max_bytes=0` (repo `AGENTS.md` is otherwise injected even with
  `--ignore-rules` — verified 2026-08-21). `agy` gets `--mode plan --sandbox
  --disable-slash-commands --print-timeout <N>s` and must declare a `gemini-*`
  model (lineage guard; agy also serves other vendors' models).
- **Workers read outside the snapshot.** E1 (2026-08-22): claude, codex and
  grok all read the parent and sibling directories of the snapshot; only agy
  refused (in-process permission check). Until the containment decision in
  `docs/SECURITY.md` is made, Phase 0 may run plumbing and clean-control
  tasks only — no defect-detection or ABSTAIN scoring.
- **A missing worker is a recorded absence, never a substitution.** No
  fallback inside a panel — it collapses lineage diversity.
- **Secrets only in `.env`**; never in YAML, never in the ledger, never printed
  by `eris doctor` (names only).
- Read `docs/INVARIANTS.md` before editing a subsystem; each rule names its test.

## Files to read first

| File | Why |
|---|---|
| `docs/PROTOCOL.md` | The adversarial protocol, evidence rule, verdict vocabulary |
| `docs/EVAL-PLAN.md` + `eval/README.md` | Phase 0 pre-registration: arms, metrics, decision rule |
| `src/eris/schemas.py` | Every record; `origin`; canonical bytes |
| `src/eris/validate.py` | The engine-enforced adjudication rules |
| `src/eris/launch.py` | How each worker CLI is invoked (flags are load-bearing) |
| `src/eris/redact.py`, `writer.py` | The only path to disk |
| `policies/default.yaml` | Declared workers, allowlists, budgets, vendors |
| `docs/INVARIANTS.md` | Do-not-break rules with enforcing tests |
| `tests/conftest.py` | Hermeticity guards — read before writing a test |

## Related projects

Athena (`../../Athena/athena-assistant`, read-only from here): local-first
assistant; its provider adapters are deliberately the inverse of Eris workers
(neutral cwd, tools denylisted). Reuse patterns, not code. Hermes: always-on
agent runtime; a *caller* of Eris, never a reviewer (no read-only mode).
