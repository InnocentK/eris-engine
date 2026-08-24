# plumbing-control — the first corpus entry

A **plumbing control**, not a scored corpus task. Its job is to exercise the
harness end to end (evidence pack → propose → critique → verify → adjudicate →
summarize → contamination scan) against a repository where there is nothing to
find. Two functions, no defects, no distractors, no planted anything.
`docs/EVAL-PLAN.md` records that it is excluded from Phase 0 scoring.

It is what found the two M2c defects on 2026-08-23 (`USER` missing from the
worker environment; `git status` tripping the verification tripwire).

`task.json` carries `"scored": false`, and that is enforced, not just
documented: campaign discovery skips it and `eval/score.py` reports its cells
as `skipped: not a scored corpus task`. An explicit `--task-file` still runs
it — that is the whole point of a plumbing task.

## The snapshot is GENERATED, not committed

`snapshot/` is a git repository, and a git repository cannot be committed
inside another one: git records a nested `.git` as a gitlink, never as files.
`.gitignore` also excludes `eval/corpus/*/snapshot/` for every corpus entry.
So the working tree lives in `files/` and the snapshot is built from it.

Build it:

```
.venv/bin/python eval/make_control_snapshot.py eval/corpus/plumbing-control \
    --message "plumbing control: calc.py"
```

or `task corpus:plumbing-snapshot`, which runs exactly that.

The generator is Python, not shell, so it runs unchanged on every target OS:
`shutil` does the copy and only `git` is spawned, with the commit identity
passed per invocation (`-c user.name=...`) so no global git config is read or
needed. Nothing at RUN time depends on any of this — the harness only ever
reads `snapshot/`.

Rebuilding it produces a different commit sha, which changes the harness's
idempotency keys (the base commit is part of the key). That is correct: a
re-snapshotted task never collides with the old one's cache entries.

## Running it

```
.venv/bin/python eval/run.py run \
  --task-file eval/corpus/plumbing-control/task.json \
  --arm single --panel claude --repeat-index 0
```

This spawns a real worker CLI. It is never run from the test suite.
