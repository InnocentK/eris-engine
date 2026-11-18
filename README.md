# Eris Engine

A self-hosted, **evidence-bound** engine for adversarial multi-model review,
verification, and transparent adjudication — with a durable decision ledger and
explicit human gates.

> Athena and Hermes decide what work to pursue. **Eris decides whether a
> proposed answer or action is defensible.**

## Status: Phase 0 (evaluation harness) — no engine yet

Version 0.5.0 is a beta integration boundary for this harness. It is not a
public 1.0 release, a completed Phase 0 corpus, or evidence that the
pre-registered build rule has cleared.

Eris deliberately does not ship an orchestrator until a pre-registered
experiment shows that *independent proposals → adversarial critique →
mechanical verification → evidence-bound adjudication* beats a single strong
model and naive multi-model consensus on a real task corpus. The Phase 0
harness in this repository exists to run that experiment honestly:

- `src/eris/schemas.py` — schema-validated records; every record carries
  `origin: model_asserted | mechanically_observed | human_entered`.
- `src/eris/validate.py` — the engine-enforced adjudication rule: a claim is
  SUPPORTED only by evidence that exists, is mechanically observed, and is not
  stale. Model agreement alone is UNSUPPORTED.
- `src/eris/launch.py` — hardened, read-only invocation of worker CLIs
  (Claude Code, Codex, Antigravity `agy` for the Google lineage, Grok) and
  OpenAI-compatible APIs.
- `src/eris/redact.py` + `writer.py` — the single, redacting, fail-loud path
  to the run ledger.
- `src/eris/verify.py` — allowlisted mechanical verification commands.
- `src/eris/snapshot.py` — history-truncated corpus snapshots (no future
  commits reachable).
- `src/eris/{evidence,stages,arms,retry,cache,sanitize,scan,ledger}.py` —
  the M2b harness modules: evidence pack, stage contracts, arms, retry and
  budget, call cache, snapshot sanitization, contamination scan, ledger view.
- `eval/run.py` — `preflight`, `dry-run`, `invoke`, `run` (one cell),
  `campaign` / `campaign status`; `eval/score.py` — the read-only scorer;
  `eval/prompts/` — the frozen stage prompts.

**Results so far:** the question above is not answered yet. See
[`docs/decisions/2026-11-18-results-to-date.md`](docs/decisions/2026-11-18-results-to-date.md)
for what six pilot and validation campaigns measured and what they found
wrong with the harness itself.

See `docs/PROTOCOL.md` for the protocol, `docs/EVAL-PLAN.md` for the
experiment, `docs/SECURITY.md` for the threat model, and `AGENTS.md` for how
work is done here.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
task ci            # ruff + mypy + pytest (fully hermetic; no CLIs, no network)
eris doctor        # which declared workers are available (prints key NAMES only)
eris policy pin    # pin executable hashes into policies/pins.yaml
python eval/run.py run --task-file eval/corpus/<task>/task.json --arm indep_verify
python eval/run.py campaign --campaign-id c1 --corpus eval/corpus --repeats 2 --dry-run
python eval/score.py --campaign-dir runs/c1 --corpus eval/corpus
```

Until a container-based containment exists (E1, `docs/SECURITY.md`) only
`control` and `plan` tasks are scorable; the scorer refuses the others.

Worker CLIs and API keys are declared in `policies/default.yaml`; secrets live
only in `.env` (see `.env.example`).

## License

Copyright 2026 Innocent Kironji. Licensed under the Apache License, Version 2.0;
see `LICENSE`.
