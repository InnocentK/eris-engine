"""`reviews/make_task.py` is the runbook's task generator.

The defect it exists to prevent: `docs/RUNBOOK-unscored-review.md` shipped a
`task.json` template with no `excerpts`. `TaskSpec.excerpts` defaults to an
empty list and `build_evidence_pack` iterates only what is declared, so a panel
run from that template received the question and four git facts, never saw a
line of the document under review, and returned a confident verdict on it. The
run does not fail; nothing in the output says the document was missing.

So the assertions below are about the PACK, not about the JSON: the point is
that the document's text reaches a reviewer.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from eris.evidence import EXCERPT_MAX_LINES, TaskSpec, build_evidence_pack
from eris.redact import Redactor
from eris.schemas import EvidenceKind
from eris.writer import RunWriter
from tests.test_evidence import ScriptedPopen, make_env, make_policy, make_snapshot

REPO = Path(__file__).resolve().parents[1]


def _make_task_module() -> Any:
    path = REPO / "reviews" / "make_task.py"
    spec = importlib.util.spec_from_file_location("_make_task", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(dest: Path, doc: str, question: str = "Is this defensible?") -> int:
    mod = _make_task_module()
    return int(mod.main(["make_task.py", str(dest), doc, question]))


def _doc(dest: Path, name: str, n_lines: int) -> None:
    """Write a document whose every line is individually identifiable."""
    (dest / "snapshot").mkdir(parents=True, exist_ok=True)
    body = "".join(f"claim number {i} is load-bearing\n" for i in range(1, n_lines + 1))
    (dest / "snapshot" / name).write_text(body, encoding="utf-8")


@pytest.mark.parametrize(
    ("n_lines", "expected_spans"),
    [
        (1, [(1, 1)]),
        (199, [(1, 199)]),
        (EXCERPT_MAX_LINES, [(1, 200)]),
        # 201 is the case a single hand-written excerpt gets wrong: the reader
        # caps at line_start + 200, so line 201 is dropped and only a "(capped)"
        # label records it.
        (EXCERPT_MAX_LINES + 1, [(1, 200), (201, 201)]),
        (450, [(1, 200), (201, 400), (401, 450)]),
    ],
)
def test_every_line_of_the_document_is_covered(
    tmp_path: Path, n_lines: int, expected_spans: list[tuple[int, int]]
) -> None:
    dest = tmp_path / "a-doc"
    _doc(dest, "DOC.md", n_lines)
    assert _run(dest, "DOC.md") == 0
    spec = json.loads((dest / "task.json").read_text())
    spans = [(e["line_start"], e["line_end"]) for e in spec["excerpts"]]
    assert spans == expected_spans
    assert all(e["line_end"] - e["line_start"] + 1 <= EXCERPT_MAX_LINES for e in spec["excerpts"])
    # contiguous, from 1, to the last line: no gap can hide a claim
    assert spans[0][0] == 1
    assert spans[-1][1] == n_lines
    assert all(b[0] == a[1] + 1 for a, b in zip(spans, spans[1:], strict=False))


def test_the_task_it_writes_loads_and_is_unscored(tmp_path: Path) -> None:
    """`scored` defaults to TRUE and a scored task without an answer key is
    refused before any worker spawns, so the generator must force it false."""
    dest = tmp_path / "my-design-doc"
    _doc(dest, "DOC.md", 12)
    assert _run(dest, "DOC.md") == 0
    spec = TaskSpec.model_validate(json.loads((dest / "task.json").read_text()))
    assert spec.scored is False
    assert spec.task_id == "my-design-doc"  # load_task refuses a dir/id mismatch
    assert spec.snapshot == "snapshot"


def test_the_document_text_actually_reaches_the_pack(tmp_path: Path) -> None:
    """The whole point. A pack built from the generated spec must carry the
    document's lines - this is what the omitted `excerpts` field cost."""
    snapshot = make_snapshot(tmp_path)
    n = 320  # spans two excerpts, so a one-excerpt bug shows up as missing text
    body = "".join(f"claim number {i} is load-bearing\n" for i in range(1, n + 1))
    (snapshot / "DOC.md").write_text(body, encoding="utf-8")

    dest = tmp_path / "a-doc"
    dest.mkdir()
    (dest / "snapshot").symlink_to(snapshot, target_is_directory=True)
    assert _run(dest, "DOC.md") == 0
    spec = TaskSpec.model_validate(json.loads((dest / "task.json").read_text()))

    popen = ScriptedPopen()
    writer = RunWriter(tmp_path / "runs" / "r1", Redactor([]), run_id="r1").open()
    try:
        build = build_evidence_pack(
            spec,
            env=make_env(tmp_path, snapshot, popen, make_policy(tmp_path)),
            writer=writer,
            repeat_index=0,
            policy_sha256="0" * 64,
            snapshot_sha="f" * 40,
        )
    finally:
        writer.close()
    # `rendered` is the bytes that go to the worker, not an intermediate.
    text = build.rendered.decode("utf-8")
    for line in (1, 200, 201, n):
        assert f"claim number {line} is load-bearing" in text, (
            f"line {line} of the document never reached the reviewer"
        )
    excerpts = [i for i in build.items if i.kind is EvidenceKind.REPO_FACT and i.argv is None]
    assert len(excerpts) == 2
    assert not any(i.truncated for i in excerpts)


def test_it_refuses_rather_than_writing_a_task_that_shows_nothing(tmp_path: Path) -> None:
    dest = tmp_path / "a-doc"
    (dest / "snapshot").mkdir(parents=True)
    assert _run(dest, "MISSING.md") == 2
    (dest / "snapshot" / "EMPTY.md").write_text("", encoding="utf-8")
    assert _run(dest, "EMPTY.md") == 2
    assert not (dest / "task.json").exists()


def test_bad_usage_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    mod = _make_task_module()
    assert mod.main(["make_task.py", str(tmp_path)]) == 2


def test_the_runbook_tells_the_reader_to_use_it(tmp_path: Path) -> None:
    """The generator only helps if the runbook points at it. The template it
    replaced is what shipped the defect."""
    runbook = (REPO / "docs" / "RUNBOOK-unscored-review.md").read_text()
    assert "reviews/make_task.py" in runbook
    assert "excerpts" in runbook


def test_the_cap_it_mirrors_has_not_moved() -> None:
    """`make_task.py` hardcodes 200 to stay runnable standalone; if the engine's
    cap changes, the generator's splits silently start truncating."""
    assert _make_task_module().EXCERPT_MAX_LINES == EXCERPT_MAX_LINES
