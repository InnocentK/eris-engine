# Changelog

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
