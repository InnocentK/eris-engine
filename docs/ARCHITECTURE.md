# Architecture (Milestone 1)

Python >= 3.12, `src/` layout, Pydantic v2, argparse, exact pins in
`requirements.txt`. Security-critical code lives in `src/eris/` under mypy
strict; `eval/run.py` is a thin CLI.

```
policies/default.yaml ──► policy.py ──► launch.py ──► worker CLI (read-only, in snapshot)
        │ (pins.yaml)         │            │  argv builders, env from {}, spawn, parsers
        │                     │            ▼
        │                     │         WorkerResult ──► eval/run.py ──► writer.py ──► runs/<id>/
        │                     │                              │                │  (redact → hash → fsync)
        │                     └── verify.py (allowlist)      │                ▼
        │                                                    │          events.jsonl, blobs/, manifest.json
        └── doctor.py (names only)                           │
snapshot.py (history-truncated clones)                       └── schemas.py / validate.py (pure)
```

## Modules

| Module | Responsibility | Raises? |
|---|---|---|
| `schemas.py` | Every record (`extra="forbid"`, frozen, `origin`, `schema_version`), enums, `Location`, `canonical_bytes` | Pydantic `ValidationError` on bad data |
| `validate.py` | Engine rules as `Finding`s; `enforce_rulings`; `validate_events` over bytes | Never |
| `policy.py` | Fail-closed policy model, loader (secret-shape refusal, pins merge, sha256), `pin_executables` | `PolicyError` |
| `redact.py` | Pattern set, ANSI strip, fold view, base64 rematch, exact values, `StreamRedactor`, `.env`/credential parsing | Never on input |
| `writer.py` | `RunWriter`: the only path to `runs/` | Always (never swallowed) |
| `launch.py` | argv builders, forbidden tokens, env builder + NEVER list, `spawn`, envelope parsers, `run_worker` | `run_worker` never; builders raise `LaunchRefused` |
| `verify.py` | Allowlist grammar (`check_command`), hard deny, verify env, `run_allowlisted` | `PermissionError` on a refused decision |
| `snapshot.py` | `build_snapshot`, `verify_snapshot` over an injectable git runner | `SnapshotError` |
| `doctor.py` | Preflight checks; prints names only | Never |
| `cli.py` | `eris doctor`, `eris policy pin` | exit codes |
| `eval/run.py` | `preflight`, `dry-run`, `invoke` (one worker, propose stage) | exit codes |

## Data flow of `invoke`

1. `load_policy` (refuses secret-shaped values; merges `pins.yaml`; records
   policy and pins sha256).
2. Exact secret values are collected from `.env` and the declared credential
   files into the `Redactor` (memory only).
3. `plan_call` builds argv + env (from `{}`) and the idempotency key.
4. `preflight_executable` checks path, regular file, and sha256 against the pin.
5. `spawn` runs the worker: `stdin=DEVNULL`, `start_new_session`, caps,
   SIGTERM then SIGKILL on the process group.
6. The per-CLI parser extracts text/model/usage/cost; `is_error` is checked
   before the shape.
7. `RunWriter` writes `run.started`, blobs for stdout/stderr,
   `invocation.finished`, `cost`, `proposal.raw` or `worker.absent`, then
   `manifest.json`.

## Process model and env

The subprocess environment starts from `{}`. `PATH` comes from the policy
(`path_env`), `HOME` is passed explicitly because the CLIs read their OAuth
state from it, `TMPDIR` points into the run directory. Per-CLI extras
(`DISABLE_AUTOUPDATER`, `DISABLE_TELEMETRY`, ...) and the policy's `env` /
`env_allow` names are added; the NEVER list is enforced before Eris's own four
`GIT_*` hardening values are appended.

## Storage layout

```
runs/<run_id>/
  .lock            flock'd by the writer
  events.jsonl     hash chain
  blobs/sha256/<hex>
  manifest.json    last
  scratch/         codex schema/output files, TMPDIR
policies/default.yaml   committed
policies/pins.yaml      machine-specific, gitignored
```

## Not built (by design, until Phase 0 clears its rule)

State machine, ledger package, adjudication loop, SQLite index, API workers
(`httpx` is pinned but unused in M1), arms/critique/adjudicate orchestration,
`eval/score.py`, containers.
