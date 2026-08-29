"""`docs/INVARIANTS.md` is the project's do-not-break register, and AGENTS.md
requires every rule to NAME its enforcing test. That contract was broken twice
in one session - rows named tests that did not exist, and rows stated rules the
named tests did not exercise - so the first half is checked mechanically here
rather than left to reviewer discipline.

The second half (does the test actually EXERCISE the rule?) cannot be checked
this way; that is what mutation-checking a new row is for. See the decision
record `docs/decisions/2026-08-26-multi-family-prelive-review.md`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVARIANTS = REPO / "docs" / "INVARIANTS.md"
TESTS = REPO / "tests"

# `test_foo.py::test_bar`, a bare `::test_bar` continuing the previous module, or
# a `::test_prefix_*` wildcard (the docs use it for parser/chain families).
CITATION = re.compile(r"(?:(test_[a-z0-9_]+\.py))?::([a-z0-9_]+\*?)")


def _defined_tests() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in sorted(TESTS.glob("test_*.py")):
        out[f.name] = set(re.findall(r"^def (test_[a-z0-9_]+)", f.read_text(), re.M))
    return out


def _cited() -> list[tuple[str, str, str]]:
    """(module, test, row-excerpt) for every test cited in a table row."""
    cited: list[tuple[str, str, str]] = []
    for line in INVARIANTS.read_text().splitlines():
        if not line.startswith("|") or "::" not in line:
            continue
        module = ""
        for mod, name in CITATION.findall(line):
            if mod:
                module = mod
            if not module or not name.startswith("test_"):
                continue  # a bare `module::function` prose reference, not a test
            cited.append((module, name, line[:90]))
    return cited


def test_every_test_named_in_invariants_exists() -> None:
    """A row may not cite a test that does not exist.

    Caught twice by review in one session; now it fails the gate instead.
    """
    defined = _defined_tests()

    def resolves(mod: str, name: str) -> bool:
        names = defined.get(mod, set())
        if name.endswith("*"):  # `::test_parse_agy_*` covers a family
            return any(n.startswith(name[:-1]) for n in names)
        return name in names

    missing = [
        f"{mod}::{name}  (row: {row}...)" for mod, name, row in _cited() if not resolves(mod, name)
    ]
    assert not missing, "docs/INVARIANTS.md cites tests that do not exist:\n" + "\n".join(missing)


def test_invariants_rows_actually_cite_a_test() -> None:
    """Every rule row must name at least one enforcing test.

    A row with an empty test column is a rule nothing protects.
    """
    offenders: list[str] = []
    for line in INVARIANTS.read_text().splitlines():
        if not line.startswith("| ") or line.startswith("| Rule ") or set(line) <= set("|- "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) < 2:
            continue
        if "::" not in cells[-1]:
            offenders.append(cells[0][:100])
    assert not offenders, "INVARIANTS rows with no enforcing test named:\n" + "\n".join(offenders)
