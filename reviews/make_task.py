#!/usr/bin/env python3
"""Write a `task.json` for an unscored document review.

    .venv/bin/python reviews/make_task.py <task-dir> <doc-in-snapshot> "<question>"

Exists because the two easiest ways to get this wrong are silent:

* `TaskSpec.excerpts` defaults to an EMPTY list and the evidence pack iterates
  only what is declared, so a task without excerpts sends the question and the
  git facts and never shows the reviewers the document.
* Each excerpt is capped at `EXCERPT_MAX_LINES` (200) counted from
  `line_start`, so one excerpt over a longer file silently truncates it.

`scored` is forced false: it defaults to TRUE, and a scored task with no answer
key is refused before any worker spawns.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXCERPT_MAX_LINES = 200  # mirrors src/eris/evidence.py


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    dest, doc, question = Path(argv[1]).expanduser(), argv[2], argv[3]
    target = dest / "snapshot" / doc
    if not target.is_file():
        print(f"no such file: {target}", file=sys.stderr)
        return 2

    n = len(target.read_text(encoding="utf-8", errors="replace").splitlines())
    if n == 0:
        print(f"{target} is empty; there is nothing to review", file=sys.stderr)
        return 2
    excerpts = [
        {"path": doc, "line_start": s + 1, "line_end": min(s + EXCERPT_MAX_LINES, n)}
        for s in range(0, n, EXCERPT_MAX_LINES)
    ]
    spec = {
        "task_id": dest.name,  # load_task refuses a mismatch with the directory
        "question": question,
        "category": "plan",
        "scored": False,
        "snapshot": "snapshot",
        "excerpts": excerpts,
    }
    (dest / "task.json").write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {dest / 'task.json'}: {len(excerpts)} excerpt(s) covering lines 1-{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
