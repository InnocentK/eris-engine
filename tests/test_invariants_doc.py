"""`docs/INVARIANTS.md` is the project's do-not-break register, and AGENTS.md
requires every rule to NAME its enforcing test. That contract was broken three
times in one session - rows named tests that did not exist, rows stated rules
their named tests did not exercise, and a rule was added with no citation at
all - so the mechanical half is checked here rather than left to discipline.

**This gate fails CLOSED.** Its first version skipped any citation it could not
parse, so `:: test_foo` (a stray space) and `::tets_foo` (a typo) passed while
being checked by nothing - the row still contained `::`, so the "names a test"
check was satisfied by text the "test exists" check never looked at. Every `::`
in a test column must now parse as a real citation or the gate fails.

What it deliberately does NOT check: whether a named test EXERCISES its rule.
That is unautomatable and is what mutation-checking a new row is for. See
`docs/decisions/2026-08-26-multi-family-prelive-review.md`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INVARIANTS = REPO / "docs" / "INVARIANTS.md"
TESTS = REPO / "tests"

# A citation is `test_foo.py::test_bar`, a bare `::test_bar` continuing the
# module named earlier in the SAME cell, or a `::test_prefix_*` family wildcard.
CITATION = re.compile(r"(test_[a-z0-9_]+\.py)?::(test_[a-z0-9_]*\*?)(?![a-z0-9_*])")


def _defined_tests() -> dict[str, set[str]]:
    return {
        f.name: set(re.findall(r"^def (test_[a-z0-9_]+)", f.read_text(), re.M))
        for f in sorted(TESTS.glob("test_*.py"))
    }


def _split_row(line: str) -> list[str]:
    """Cells of a GFM table row. Outer pipes are optional; padding is arbitrary."""
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_divider(line: str) -> bool:
    return bool(line.strip()) and set(line) <= set("|-: \t")


def _rule_rows(text: str | None = None) -> tuple[list[list[str]], list[str]]:
    """(rule rows as cells, malformed lines).

    Rows are identified by TABLE MEMBERSHIP, not by a syntactic prefix. Three
    earlier versions matched individual lines and skipped whatever did not fit,
    so rules escaped validation entirely: `|rule|test|` (no padding), a row with
    no LEADING pipe (valid GFM), and a body row whose first cells happened to
    read "Rule"/"Test" (mistaken for a header). A table is a header line plus a
    divider; every line after it, until the table ends, is a rule row and MUST
    parse. The header and divider are skipped BY POSITION, so nothing in the
    body can disguise itself as one - including a row that is itself
    divider-SHAPED (`| --- | --- |`), which an earlier version skipped wherever
    it appeared.
    """
    lines = (INVARIANTS.read_text() if text is None else text).splitlines()
    rows: list[list[str]] = []
    malformed: list[str] = []
    in_table = False
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            in_table = False
            continue
        if not in_table and _is_divider(line):
            # BY POSITION: a divider is only the line directly under a header.
            # Matching divider SHAPE anywhere let `| --- | --- |` sit in a table
            # BODY and be skipped - a row escaping validation by impersonating a
            # delimiter, which is exactly what position-based skipping prevents.
            #
            # ...but skipping the HEADER by position means a rule row placed
            # directly above a divider is never validated either. The header
            # must therefore BE a header: exactly `Rule | Test`.
            # No `"|" in lines[n-2]` precondition: with one, a divider under a
            # pipe-less line (or under nothing) was not recognised as a divider,
            # so the table never started and the real problem was reported as a
            # generic "outside any table". Closes no hole - diagnostics only.
            header = _split_row(lines[n - 2]) if n >= 2 else []
            if [c.lower() for c in header] != ["rule", "test"]:
                malformed.append(
                    f"line {n - 1}: the line above a divider must be exactly "
                    f"`Rule | Test`, else a rule row in the header position is "
                    f"never validated: {lines[n - 2].strip()[:60]}"
                )
            in_table = True
            continue
        if not in_table:
            # A table-shaped line outside a table is a defect UNLESS it is a
            # header (the next line is its divider). Writing that as
            # `n < len(lines) and not _is_divider(lines[n])` exempted the LAST
            # line of the file from the check entirely - an off-by-one that
            # fails OPEN, so a bad row placed at the end escaped everything.
            is_header = n < len(lines) and _is_divider(lines[n])
            if "|" in line and not _is_divider(line) and not is_header:
                malformed.append(f"line {n}: table-shaped line outside any table: {stripped[:70]}")
            continue
        cells = _split_row(line)
        if len(cells) < 2 or not cells[0]:
            malformed.append(f"line {n}: does not parse as a rule row: {stripped[:70]}")
            continue
        rows.append(cells)
    return rows, malformed


def _parse_test_column(cell: str) -> tuple[list[tuple[str, str]], list[str]]:
    """(citations, malformed). Every `::` must yield a citation."""
    citations: list[tuple[str, str]] = []
    module = ""
    consumed = 0
    for m in CITATION.finditer(cell):
        if m.group(1):
            module = m.group(1)
        if not module:
            return citations, [f"bare `::{m.group(2)}` with no module named before it"]
        citations.append((module, m.group(2)))
        consumed += 1
    total = cell.count("::")
    if consumed != total:
        return citations, [f"{total - consumed} of {total} `::` did not parse as a citation"]
    return citations, []


def test_every_test_named_in_invariants_exists() -> None:
    """A row may not cite a test that does not exist."""
    defined = _defined_tests()

    def resolves(mod: str, name: str) -> bool:
        names = defined.get(mod, set())
        if name.endswith("*"):  # `::test_parse_agy_*` covers a family
            return any(n.startswith(name[:-1]) for n in names)
        return name in names

    missing: list[str] = []
    for cells in _rule_rows()[0]:
        for mod, name in _parse_test_column(cells[-1])[0]:
            if not resolves(mod, name):
                missing.append(f"{mod}::{name}   (rule: {cells[0][:70]}...)")
    assert not missing, "docs/INVARIANTS.md cites tests that do not exist:\n" + "\n".join(missing)


def test_invariants_citations_are_well_formed() -> None:
    """FAIL CLOSED: a `::` in a test column that does not parse is a defect.

    Without this, `:: test_foo` and `::tets_foo` satisfied "the row names a
    test" while being validated by nothing.
    """
    bad: list[str] = []
    for cells in _rule_rows()[0]:
        for problem in _parse_test_column(cells[-1])[1]:
            bad.append(f"{problem}   (rule: {cells[0][:70]}...)")
    assert not bad, "docs/INVARIANTS.md has malformed test citations:\n" + "\n".join(bad)


def test_invariants_rows_actually_cite_a_test() -> None:
    """Every rule row must name at least one enforcing test."""
    offenders = [
        cells[0][:100] for cells in _rule_rows()[0] if not _parse_test_column(cells[-1])[0]
    ]
    assert not offenders, "INVARIANTS rows with no enforcing test named:\n" + "\n".join(offenders)


def test_every_table_line_parses_as_a_rule_row() -> None:
    """FAIL CLOSED at the ROW level: a line that looks like a table row but does
    not parse is a defect, not something to skip.

    The first version of this gate collected only the rows it recognised, so a
    rule written `|rule|test|` - or with a missing trailing pipe, or a single
    cell - escaped every other check in this module.
    """
    malformed = _rule_rows()[1]
    assert not malformed, (
        "docs/INVARIANTS.md has lines that look like table rows but do not parse:\n"
        + "\n".join(malformed)
    )


# --------------------------------------------------------------- the gate's own regression net

VALID_TABLE = (
    "## A section\n"
    "| Rule | Test |\n"
    "|---|---|\n"
    "| a real rule | `test_score.py::test_a_worker_that_recorded_twice_counts_once` |\n"
)

MALFORMED_ROWS = {
    "pure divider in the body": "| --- | --- |",
    "divider with colons": "|:---|---:|",
    "single dash row": "| - | - |",
    "tab-padded divider": "|\t---\t|\t---\t|",
    "empty cells": "| | |",
    "no leading pipe": "a rule | `test_score.py::test_nope` |",
    "no leading pipe, no test": "a rule with no test |",
    "header-lookalike body row": "| Rule | Test | x |",
    "tight pipes": "|a rule|`test_score.py::test_nope`|",
    "single cell": "| a rule with no test column |",
    "no trailing pipe": "| a rule | `test_score.py::test_nope`",
}


def _gate_rejects(doc: str) -> bool:
    """True when SOME check in this module would fail on `doc`."""
    rows, malformed = _rule_rows(doc)
    if malformed:
        return True
    for cells in rows:
        citations, bad = _parse_test_column(cells[-1])
        if bad or not citations:
            return True
        for mod, name in citations:
            defined = _defined_tests().get(mod, set())
            ok = (
                any(n.startswith(name[:-1]) for n in defined)
                if name.endswith("*")
                else name in defined
            )
            if not ok:
                return True
    return False


POSITIONS = {
    "after_body": lambda hdr, good, bad: hdr + good + bad + "\n",
    "first_body_row": lambda hdr, good, bad: hdr + bad + "\n" + good,
    "between_body_rows": lambda hdr, good, bad: hdr + good + bad + "\n" + good,
    "header_position": lambda hdr, good, bad: "## A section\n" + bad + "\n|---|---|\n" + good,
}


def test_the_gate_accepts_a_well_formed_table() -> None:
    """The net must not fire on a correct document, or it proves nothing."""
    assert not _gate_rejects(VALID_TABLE)


@pytest.mark.parametrize("position", sorted(POSITIONS))
@pytest.mark.parametrize("shape", sorted(MALFORMED_ROWS), ids=lambda s: s.replace(" ", "_"))
def test_the_gate_rejects_every_known_malformed_row(shape: str, position: str) -> None:
    """This gate regressed FIVE times, each time letting through a shape - or a
    POSITION - a previous round had not thought to plant.

    Every shape ever found is planted in every position a row can occupy. The
    first version of this net planted each shape in ONE position (appended after
    the body) and reported "all caught", which is the same single-position
    blindness that let the hand-probes pass four times running: a rule sitting in
    the HEADER position was skipped and validated by nothing.
    """
    hdr = "## A section\n| Rule | Test |\n|---|---|\n"
    good = "| a real rule | `test_score.py::test_a_worker_that_recorded_twice_counts_once` |\n"
    doc = POSITIONS[position](hdr, good, MALFORMED_ROWS[shape])
    assert _gate_rejects(doc), f"a {shape!r} row in the {position} position is not rejected"


def test_a_rule_row_in_the_header_position_is_rejected() -> None:
    """The header is skipped BY POSITION, so it must be provably a header.

    Otherwise a rule row placed directly above a divider - an easy hand-edit
    mistake in a register that is maintained by hand - carries a rule nothing
    validates.
    """
    doc = (
        "## A section\n"
        "| a rule with a typo'd test | `::tets_typo` |\n"
        "|---|---|\n"
        "| a real rule | `test_score.py::test_a_worker_that_recorded_twice_counts_once` |\n"
    )
    assert _gate_rejects(doc)


# Whole-document shapes: a bad row can also escape via the table's FRAME - a
# missing or pipe-less header, or simply being the last line of the file (an
# off-by-one in the stray-line lookahead exempted it). Each of these was a live
# bypass of the header guard.
BAD_ROW = "| a rule with a typo'd test | `::tets_typo` |"
GOOD_ROW = "| a real rule | `test_score.py::test_a_worker_that_recorded_twice_counts_once` |"

MALFORMED_DOCS = {
    "no header line at all": f"## S\n|---|---|\n{BAD_ROW}\n{GOOD_ROW}\n",
    "header has no pipes": f"## S\nRule Test\n|---|---|\n{BAD_ROW}\n",
    "blank line between header and divider": f"## S\n| Rule | Test |\n\n|---|---|\n{BAD_ROW}\n",
    "bad row is the last line of the file": f"## S\n{BAD_ROW}",
    "bad row last line after a valid table": (
        f"## S\n| Rule | Test |\n|---|---|\n{GOOD_ROW}\n\n{BAD_ROW}"
    ),
    "two tables with no separator": (
        f"## S\n| Rule | Test |\n|---|---|\n{GOOD_ROW}\n| Rule | Test |\n|---|---|\n{BAD_ROW}\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(MALFORMED_DOCS), ids=lambda s: s.replace(" ", "_"))
def test_the_gate_rejects_malformed_document_frames(shape: str) -> None:
    """A row can escape via the table FRAME, not just its own text.

    All six of these bypassed the header guard: the divider was only recognised
    when the line above it contained a pipe, and the stray-line check exempted
    the last line of the file via `n < len(lines)` - an off-by-one that fails
    OPEN.
    """
    assert _gate_rejects(MALFORMED_DOCS[shape]), f"{shape!r} is not rejected"


def test_a_divider_under_a_bad_header_reports_the_header_problem() -> None:
    """Diagnostic quality, not a bypass.

    Recognising a divider only when the line above it contained a pipe closed
    NO hole - `test_the_gate_rejects_malformed_document_frames` passes either
    way - but it made a pipe-less header fall through to the generic
    "outside any table" message instead of naming the real problem. Pinned here
    so the clearer diagnostic is not silently lost.
    """
    _, malformed = _rule_rows("## S\nRule Test\n|---|---|\n| a rule | x |\n")
    assert any("must be exactly" in m for m in malformed), malformed
