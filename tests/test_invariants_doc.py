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


def _rule_rows() -> tuple[list[list[str]], list[str]]:
    """(rule rows as cells, malformed lines).

    Rows are identified by TABLE MEMBERSHIP, not by a syntactic prefix. Three
    earlier versions matched individual lines and skipped whatever did not fit,
    so rules escaped validation entirely: `|rule|test|` (no padding), a row with
    no LEADING pipe (valid GFM), and a body row whose first cells happened to
    read "Rule"/"Test" (mistaken for a header). A table is a header line plus a
    divider; every line after it, until the table ends, is a rule row and MUST
    parse. The header and divider are skipped BY POSITION, so nothing in the
    body can disguise itself as one.
    """
    lines = INVARIANTS.read_text().splitlines()
    rows: list[list[str]] = []
    malformed: list[str] = []
    in_table = False
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            in_table = False
            continue
        if _is_divider(line) and n >= 2 and "|" in lines[n - 2]:
            in_table = True  # this is the divider; the line above was the header
            continue
        if not in_table:
            # a stray table-looking line outside any table would never be
            # validated, so it is a defect rather than something to ignore
            if (
                "|" in line
                and not _is_divider(line)
                and n < len(lines)
                and not _is_divider(lines[n])
            ):
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
