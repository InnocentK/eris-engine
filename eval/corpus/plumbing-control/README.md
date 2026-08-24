# plumbing-control — the first corpus entry

A **plumbing control**, not a scored corpus task. Its job is to exercise the
harness end to end (evidence pack → propose → critique → verify → adjudicate →
summarize → contamination scan) against a repository where there is nothing to
find. Two functions, no defects, no distractors, no planted anything.
`docs/EVAL-PLAN.md` records that it is excluded from Phase 0 scoring.

It is what found the two M2c defects on 2026-08-23 (`USER` missing from the
worker environment; `git status` tripping the verification tripwire).

## The snapshot is GENERATED, not committed

`snapshot/` is a git repository, and a git repository cannot be committed
inside another one: git records a nested `.git` as a gitlink, never as files.
`.gitignore` also excludes `eval/corpus/*/snapshot/` for every corpus entry.
So the working tree lives in `files/` and the snapshot is built from it.

Build it (portable — plain git, no shell tricks):

```
mkdir -p eval/corpus/plumbing-control/snapshot
cp eval/corpus/plumbing-control/files/calc.py    eval/corpus/plumbing-control/snapshot/
cp eval/corpus/plumbing-control/files/README.md  eval/corpus/plumbing-control/snapshot/
git -C eval/corpus/plumbing-control/snapshot init -q -b main
git -C eval/corpus/plumbing-control/snapshot add -A
git -C eval/corpus/plumbing-control/snapshot -c user.name="Eris Corpus" \
    -c user.email="corpus@eris.invalid" commit -qm "plumbing control: calc.py"
```

or `task corpus:plumbing-snapshot`, which runs exactly those commands.

OS note: only the file copy is shell-specific (`mkdir -p` / `cp` / `rm -rf`).
On Windows without a POSIX shell, create `snapshot/` and copy the two files
from `files/` with `New-Item` / `Copy-Item`; the four `git` commands are
identical everywhere. Nothing at RUN time depends on any of this - the
harness only ever reads `snapshot/`.

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
