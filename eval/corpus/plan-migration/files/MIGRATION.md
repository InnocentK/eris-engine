# Migration plan: move the grader's answer keys out of the graded tree

## Background

Each task directory currently holds three things: `task.json` (the question),
`answers.json` (the grader's expected answers), and `workspace/` (the tree the
worker runs in, with its cwd set there).

We have measured that every worker CLI we use reads the parent and sibling
directories of its cwd. `answers.json` therefore sits one hop from a place the
graded worker can read. This plan moves it.

## Steps

1. Create a new top-level `answers/` directory, a sibling of `tasks/`.
2. `git mv tasks/<id>/answers.json answers/<id>.json` for every task.
3. Update `grader.py` to load the key from `answers/<id>.json`.
4. Update the developer README to describe the new layout.
5. Ship. Existing runs keep working because the grader is the only thing that
   opens the key.

## Notes on the contamination detector

`detector.py` flags a run when its transcript contains any of a fixed list of
marker strings. The list is:

    MARKERS = ("acme-internal", "tasks/", "answers.json")

The detector is unchanged by this migration.

## Rollback

Move the files back with `git mv` and revert the grader change. No data is
destroyed at any point, so rollback is a single revert commit. We have
rehearsed this on a scratch clone and it takes under a minute.

## Timing

The move touches every task directory, so it conflicts with any open branch
that adds a task. We will land it on a Tuesday, when the fewest task branches
are open, and ask contributors to rebase rather than merge.

## Reviewer assignment

Two reviewers, one from the grading team and one from the harness team. The
grading reviewer checks that no key is lost in the move; the harness reviewer
checks that nothing else in the tree still expects the old path.

## Notes on the workspace tree

`workspace/` is generated from the committed `sources/` directory by
`build_workspace.py`, which copies the tree and makes one commit. It is in
`.gitignore` because a git repository cannot be committed inside another one.
Contributors run the builder once after cloning.

## Metrics we will watch after the move

* grader run time, which should not change;
* the number of runs flagged by the detector, which should not change either;
* the number of support questions about a missing key, which we expect to rise
  briefly and then fall to zero.

## Communication

An announcement in the engineering channel the day before, a note in the
release summary, and a line in the developer README. Contributors who only run
the grader need do nothing.

## What we are deliberately not changing

The key format stays as it is. Reformatting the keys in the same change would
make the diff unreviewable, and the format is not what makes them readable by
the worker - their location is.

## Notes on the "graded" flag

`task.json` carries a `graded` flag. Two components read it: `runner.py` parses
`task.json` with pydantic, and `grader.py` reads it as plain JSON because it
must not import the runner's dependencies. Both default it to true.

## Sign-off

The grading team owns the change. Ship once both reviewers approve and the
scratch-clone rehearsal has been repeated on the final diff.
