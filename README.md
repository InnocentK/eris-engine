# Eris Engine

A self-hosted, **evidence-bound** engine for adversarial multi-model review,
verification, and transparent adjudication — with a durable decision ledger and
explicit human gates.

> Athena and Hermes decide what work to pursue. **Eris decides whether a
> proposed answer or action is defensible.**

## Status: Phase 0 (evaluation harness) — no engine yet

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
- `eval/` — runner, scorer, and the pre-registered experiment design.

See `docs/PROTOCOL.md` for the protocol, `docs/EVAL-PLAN.md` for the
experiment, `docs/SECURITY.md` for the threat model, and `AGENTS.md` for how
work is done here.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
task ci            # ruff + mypy + pytest (fully hermetic; no CLIs, no network)
eris doctor        # which declared workers are available (prints key NAMES only)
```

Worker CLIs and API keys are declared in `policies/default.yaml`; secrets live
only in `.env` (see `.env.example`).

## License

Not yet decided — see `docs/decisions/`. Treat as all rights reserved until a
license file is added.
