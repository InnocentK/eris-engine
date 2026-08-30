# Migration plan: move the grader's answer keys out of the graded tree

## Background

Each task directory currently holds three things: `task.json` (the question),
`answers.json` (the grader's expected answers), and `workspace/` (the tree the
worker runs in, with its cwd set there).

We have measured that every worker CLI we use reads the parent and sibling
directories of its cwd. `answers.json` therefore sits one hop from a place the
graded worker can read.

## Steps

1. Create a new top-level `answers/` directory, a sibling of `tasks/`.
2. `git mv tasks/<id>/answers.json answers/<id>.json` for every task.
3. Update `grader.py` to load the key from `answers/<id>.json`.
4. Update the developer README to describe the new layout.
5. Ship. Existing runs keep working because the grader is the only thing that
   opens the key.

## Rollback

Move the files back with `git mv` and revert the grader change. No data is
destroyed at any point, so rollback is a single revert commit.

## Notes on the contamination detector

`detector.py` flags a run when its transcript contains any of a fixed list of
marker strings. The list is:

    MARKERS = ("acme-internal", "tasks/", "answers.json")

The detector is unchanged by this migration.

## Notes on the workspace tree

`workspace/` is generated from the committed `sources/` directory by
`build_workspace.py`, which copies the tree and makes one commit. It is in
`.gitignore` because a git repository cannot be committed inside another one.
Contributors run the builder once after cloning.

## Notes on the "graded" flag

`task.json` carries a `graded` flag. Two components read it: `runner.py` parses
`task.json` with pydantic, and `grader.py` reads it as plain JSON because it
must not import the runner's dependencies. Both default it to true.
