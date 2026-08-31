"""`docs/INVARIANTS.md` is the project's do-not-break register, and AGENTS.md
requires every rule to NAME its enforcing test. That contract was broken three
times in one session - rows named tests that did not exist, rows stated rules
their named tests did not exercise, and a rule was added with no citation at
all - so the mechanical half is checked here rather than left to discipline.

**Scope of the guarantee.** For anything that IS part of a table, this gate
fails CLOSED: every line the table contains must parse as a rule row, the header
must be exactly `Rule | Test`, every rule row must cite a test, and every `::` in
a test column must parse as a real citation naming a test that exists. An earlier
version skipped what it could not parse, so `:: test_foo` (a stray space) and
`::tets_foo` (a typo) passed while being checked by nothing.

**It does NOT fail closed on one path, deliberately.** A row that loses its pipes
stops being a table line at all, and is therefore not checked. Four attempts to
detect it each rejected valid Markdown - "prose ending in a citation" and "a rule
row whose pipes were lost" are the same string - so the hazard is accepted and
stated rather than chased. `test_a_lost_pipe_row_is_a_known_unreported_gap` pins
it, so the limitation cannot quietly become prose nobody checks.

What it deliberately does NOT check: whether a named test EXERCISES its rule.
That is unautomatable and is what mutation-checking a new row is for. See
`docs/decisions/2026-08-26-multi-family-prelive-review.md`.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
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
    """A TABLE delimiter row, not a horizontal rule.

    The `"|" in line` requirement is load-bearing: a thematic break (`---`,
    `- - -`) is built from the same characters, and without it a horizontal rule
    anywhere in the document was read as a table divider - the prose line above
    it was then rejected as a malformed header and the prose below it parsed as
    table rows. That is a false positive on valid Markdown, i.e. the gate
    failing CLOSED, which is as broken as failing open.
    """
    return bool(line.strip()) and "|" in line and set(line) <= set("|-: \t")


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
        if "|" not in line:
            # A GFM table row must contain a pipe, so a pipe-less line ENDS the
            # table - it is not a malformed row. Without this a thematic break
            # (`---`) written directly under a table row was rejected as a bad
            # row: a false positive on valid Markdown.
            #
            # But ending the table must not become a way to SMUGGLE a rule past
            # every check: a line here that cites a test is a rule row whose
            # pipes were lost, and skipping it silently is fail-open. Prose
            # paragraphs that legitimately reference tests sit after a blank
            # line or heading, where `in_table` is already False.
            # ACCEPTED LIMITATION: a row that loses its pipes stops being a
            # table row and is not reported. Four rounds were spent trying to
            # detect it - `"::" in line`, then a citation anchored to
            # end-of-line - and each trigger rejected valid Markdown, because
            # "prose ending in a citation" and "a rule row whose pipes were
            # lost" are indistinguishable by text shape. A heuristic that
            # oscillates between false positives and false negatives is worse
            # than the hazard: this gate must never reject a correct document,
            # or it gets disabled and protects nothing. Such a line renders as
            # prose, so it is visibly not a rule to any reader of the register.
            in_table = False
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


# The net above only ever asked "does the gate REJECT bad input?". A gate that
# rejects everything passes all of it. These pin the other direction: ordinary
# Markdown that happens to share characters with a table delimiter must be
# ACCEPTED. Treating a thematic break (`---`) as a table divider made the gate
# reject valid documents - failing CLOSED, which is as broken as failing open.
VALID_DOCS = {
    "horizontal rule after a blank line": "\nProse.\n\n---\n\nMore prose.\n",
    "spaced thematic break": "\nProse.\n\n- - -\n\nMore prose.\n",
    "horizontal rule directly under a row": "---\n",
    "prose directly under a row": "Some prose paragraph.\n",
    "nothing after the table": "",
    "another section follows": "\n## Another section\n\nProse.\n",
    "prose citing a test after a blank line": "\nSee `test_x.py::test_y` for context.\n",
    # directly after a table row, with NO blank line - all valid Markdown that a
    # `"::" in line` trigger wrongly rejected
    "prose citing a symbol, no blank line": "See `eris.validate::enforce_rulings` for detail.\n",
    "prose citing a pytest id, no blank line": "See `test_x.py::test_y` for the details.\n",
    "bare :: in a sentence": "The judge uses stages::invoke here, which matters.\n",
    "prose ENDING in a citation": "The enforcing test is `test_x.py::test_y`.\n",
    "prose ending in a citation, no period": "The enforcing test is `test_x.py::test_y`\n",
    "bullet ending in a citation": "- covered by `test_x.py::test_y`\n",
    "sentence ending in a symbol ref": "See `eris.validate::enforce_rulings`\n",
    "a citation alone on a line": "`test_x.py::test_y`\n",
}


@pytest.mark.parametrize("shape", sorted(VALID_DOCS), ids=lambda s: s.replace(" ", "_"))
def test_the_gate_accepts_ordinary_markdown(shape: str) -> None:
    """Valid Markdown around a valid table must not be rejected."""
    doc = (
        "## A section\n| Rule | Test |\n|---|---|\n"
        "| a rule | `test_score.py::test_a_worker_that_recorded_twice_counts_once` |\n"
    ) + VALID_DOCS[shape]
    rows, malformed = _rule_rows(doc)
    assert not malformed, f"{shape!r} wrongly reported malformed: {malformed}"
    assert len(rows) == 1, f"{shape!r} changed how many rule rows were found: {rows}"


def test_a_lost_pipe_row_is_a_known_unreported_gap() -> None:
    """The one path this gate deliberately does NOT close.

    A rule row whose pipes are lost is no longer a table line, so nothing
    validates its citation. Four triggers were tried and each rejected valid
    Markdown, because the line is textually identical to prose that ends in a
    citation. The hazard is accepted: such a line renders as prose, so it is
    visibly not a rule to a reader of the register.

    This test exists so the limitation is EXECUTABLE rather than prose. If a
    future change starts reporting these lines, this fails - and whoever changes
    it must re-check the accept direction (`test_the_gate_accepts_ordinary_markdown`)
    before claiming the gate fails closed everywhere.
    """
    doc = (
        "## S\n| Rule | Test |\n|---|---|\n"
        "| a real rule | `test_score.py::test_a_worker_that_recorded_twice_counts_once` |\n"
        "a rule whose pipes were lost `::tets_typo`\n"
    )
    rows, malformed = _rule_rows(doc)
    assert not malformed, "this gap is documented as unreported; see the module docstring"
    assert len(rows) == 1, "the intact row is still validated"


def test_the_changelog_records_the_current_version() -> None:
    """`__version__` was bumped to 0.4.3 with no changelog entry at all, across
    three commits of substantive change, and nothing failed. A version number is
    a claim that a release exists; the record of what is in it is the thing that
    makes the claim checkable.

    Asserts the TOP entry, not merely that the version appears somewhere: a
    changelog whose newest entry is older than the code describes a release that
    was never written down.
    """
    from eris.version import __version__

    lines = (REPO / "CHANGELOG.md").read_text().splitlines()
    headings = [ln for ln in lines if ln.startswith("## ")]
    assert headings, "CHANGELOG.md has no version headings"
    top = headings[0]
    assert top.startswith(f"## {__version__} "), (
        f"CHANGELOG.md's newest entry is {top!r}, but eris.__version__ is {__version__!r}. "
        "Bumping the version without recording what changed leaves the release undocumented."
    )
    body = lines[lines.index(top) + 1 :]
    body = body[: next((i for i, ln in enumerate(body) if ln.startswith("## ")), len(body))]
    assert any(ln.strip() for ln in body), f"{top!r} has no body"


# Paths named in live documents that deliberately DO NOT exist. Each is named in
# order to RECORD that it was never written, so the check must still see it -
# listed here, with a reason, rather than reworded until the check stops
# matching. Rewording to silence this test is the exact failure mode it exists
# to prevent, and the first version of it was silenced that way: the paths below
# had their backticks removed, and the check only looked at backticked text.
DELIBERATELY_ABSENT: dict[str, str] = {
    # The rule that catches truncated references has to SHOW one, and a
    # demonstration of a name that does not exist must not be reworded until the
    # check stops seeing it - that is the evasion this whole rule exists to
    # prevent. Listed instead, which is what the list is for.
    # keyed on what the scan actually produces - the prefix plus the ONE
    # truncating character, since the run stops there
    "docs/EVAL-PLAN.md~": "an example of a truncated reference, in the rule that catches them",
    "docs/EVAL-PLAN.md+": "an example of a truncated reference, in the rule that catches them",
    "docs/EVAL-PLAN.md@": "an example of a truncated reference, in the rule that catches them",
    "eval/README.md": (
        "never written. Four live documents named it as the home of the Phase 0 "
        "decision rule; the rule is in docs/EVAL-PLAN.md, which says so."
    ),
}

# Filenames belonging to OTHER tools' conventions, not to this repository. The
# security and eval docs name them when describing what each vendor CLI injects
# from a worker's tree, so they are references to a convention rather than
# pointers into this checkout.
EXTERNAL_CONVENTIONS: frozenset[str] = frozenset(
    {
        "GEMINI.md",
        "GROK.md",
        "CLAUDE.local.md",
        ".github/copilot-instructions.md",
        ".agents/rules/r.md",
    }
)

# Documents NOT mention-checked, each with its reason. Everything else in the
# repository is checked, so a document added anywhere is covered the moment it
# exists. The previous version named the two directories it DID check, which
# meant every document written anywhere else - `eval/corpus/*/README.md`, say -
# was silently exempt: an allowlist of what is checked fails open by
# construction, and this one did.
UNCHECKED_DOCS: dict[str, str] = {
    "CHANGELOG.md": "a past release entry names the paths that existed at that release",
    "docs/history/*": "frozen records; each body is as written, under a banner that says so",
    "docs/decisions/*": "each records the world as it was when the decision was taken",
    "eval/prompts/*": "frozen prompt text, hashed per run - role and rules, not documentation",
    "eval/corpus/*/files/*": "corpus payload: the contents of a fixture repository",
    "eval/corpus/*/snapshot/*": "generated from files/, and gitignored",
}

# Where a repo path can be written: inside backticks, as a markdown link target,
# or bare in prose. All three are checked, because which one an author reaches
# for is a formatting choice and an invariant that turns on formatting is not an
# invariant - the first version of this rule was defeated by deleting a pair of
# backticks. Directories count as well as files: `docs/decisions/` is a pointer
# like any other.
# Formatting is REMOVED before anything is matched, rather than being enumerated
# in the pattern. Every previous version of this rule was defeated by a way of
# writing a path it did not anticipate - backticks deleted, a directory without
# an extension, a directory without a trailing slash - and the last two were
# `_docs/nowhere_` (markdown italics, whose underscore is a word character and
# so was swallowed by the lookbehind) and `` `docs`/`nowhere` `` (backticks
# around each segment). Enumerating decorations is a losing game; stripping them
# is not. Backticks and asterisks cannot appear in a path, so they are deleted
# outright, and a candidate's leading and trailing `_`/`-`/`,` are trimmed -
# emphasis and punctuation, not name.
# Backtick and asterisk become a SEPARATOR, not nothing. Deleting them merged
# `AGENTS.md`/`GEMINI.md` - two files - into one phantom path, and turned the
# glob `eval/corpus/*/snapshot/` into `eval/corpus//snapshot/`. As separators
# they read correctly: a backtick delimits a span and an asterisk is either
# emphasis or a wildcard, and in every one of those readings it ends the name.
# The cost is that `` `docs`/`nowhere` `` - one path written as two spans - is
# no longer seen as one path. That reading is genuinely ambiguous with the
# `A`/`B` enumeration above, and getting the common case right is worth more.
_DECORATION = re.compile(r"[`*]")
_RUN = re.compile(r"[A-Za-z0-9_./-]+")

# Directories whose contents are part of the SOURCE TREE. `runs/`, `cache/` and
# `scratch/` are deliberately absent: they hold runtime artefacts that do not
# exist in a checkout, so a reference to one cannot be resolved and is not a
# fault. Stated here rather than left as an unexplained list.
_SOURCE_DIRS = ("docs", "eval", "src", "tests", "policies")


# Characters that are LEGAL in a filename but absent from `_RUN`. If one follows
# a match, the name was cut short and the prefix we captured is not the name that
# was written - `docs/EVAL-PLAN.md~` truncated to `docs/EVAL-PLAN.md`, which
# exists, so a reference to a file that does not exist passed. Existence of a
# prefix proves nothing about the whole, so a truncated reference is REPORTED
# rather than resolved: the check fails closed on what it cannot read.
#
# `'` is deliberately absent: an apostrophe after a filename is an English
# possessive far more often than part of a name ("AGENTS.md's rule"), and no
# file in this repository has one.
_TRUNCATING = set("~+@%=&!$^")


def _candidates(text: str) -> set[str]:
    """Every repo-shaped path mentioned, whatever it was dressed in.

    A candidate whose name was truncated comes back with its truncating
    character attached, so it cannot resolve and is reported.
    """
    out: set[str] = set()
    text = _DECORATION.sub(" ", text)
    for m in _RUN.finditer(text):
        # leading/trailing `_` and `-` are emphasis, a trailing `.` or `,` is the
        # end of a sentence - none of them is part of a name
        ref = m.group(0).strip("_-,").rstrip(".")
        # a leading slash is the tail of a wildcard that has just been split off
        # (`eval/corpus/*/README.md` -> `/README.md`), not a path of its own
        if not ref or ref.startswith("/"):
            continue
        head, _, rest = ref.partition("/")
        if not ((head in _SOURCE_DIRS and rest) or (ref.endswith(".md") and ref != ".md")):
            continue
        nxt = text[m.end() : m.end() + 1]
        out.add(ref + nxt if nxt in _TRUNCATING else ref)
    return out


_LINK = re.compile(r"\]\(([^)\s]+)\)")
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_FENCE_SHUT = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
_INLINE_CODE = re.compile(r"`[^`]*`")


def _strip_code(text: str, doc: str, unreadable: list[str]) -> str:
    """Blank out code, and REPORT anything whose structure cannot be read.

    A `](...)` inside code renders literally and is not a link, so it must not
    be link-checked. The first version did that with one regex over the whole
    document - ```` ```.*?``` ```` under `re.S` - which fails OPEN: a document
    that merely MENTIONS ``` in prose pairs that occurrence with the next real
    fence and swallows everything between, so real broken links in that region
    stop being reported and nothing says so. Demonstrated on 2026-08-31: a
    broken link between an inline mention and a following fence disappeared
    from the results.

    Fences are therefore tracked line by line, and the two ambiguous cases are
    surfaced instead of guessed:

    * a fence still open at end of file is REPORTED - the rest of the document
      was treated as code, and that is exactly when links go unchecked;
    * a line with an odd number of backticks has an unterminated inline span,
      so the line is left ALONE and its links are still checked. Stripping on a
      guess is what loses a link; keeping it can at worst re-check something
      that renders as code, which is a visible false alarm rather than a
      silent miss.
    """
    out: list[str] = []
    fence = ""  # the OPENING run, "" when not inside a block
    opened_at = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        if fence:
            shut = _FENCE_SHUT.match(line)
            # CommonMark: a fence closes only on a run of the SAME character,
            # at least as long as the opener, with nothing after it. Toggling
            # on any fence-looking line instead makes a document that SHOWS a
            # fence inside a block mispair, and when the mispairing happens to
            # come out even there is no leftover to report - the links in
            # between are dropped in silence (demonstrated 2026-08-31).
            if shut and shut.group(1)[0] == fence[0] and len(shut.group(1)) >= len(fence):
                fence = ""
            out.append("")
            continue
        opened = _FENCE_OPEN.match(line)
        if opened:
            fence = opened.group(1)
            opened_at = lineno
            out.append("")
        elif line.count("`") % 2:
            out.append(line)
        else:
            out.append(_INLINE_CODE.sub(" ", line))
    if fence:
        unreadable.append(f"{doc}: code fence opened at line {opened_at} is never closed")
    return "\n".join(out)


# Documents whose LINKS are not checked either. Narrower than the mention
# exemptions on purpose: `docs/history/` and `docs/decisions/` ARE link-checked,
# because the banners marking the history files superseded were added by
# pointing at the live documents and a banner whose links do not resolve is
# worse than no banner. What is exempt here is content that is not ours to fix -
# a fixture repository may legitimately contain a broken link, and saying so is
# part of what makes it a realistic fixture.
LINK_UNCHECKED: tuple[str, ...] = (
    "eval/prompts/*",
    "eval/corpus/*/files/*",
    "eval/corpus/*/snapshot/*",
)


def _is_unchecked(rel: str) -> str | None:
    """The reason this document is exempt from mention-checking, if it is."""
    return next((why for pat, why in UNCHECKED_DOCS.items() if fnmatch(rel, pat)), None)


def _all_docs() -> list[Path]:
    return sorted(
        p
        for p in REPO.glob("**/*.md")
        if not any(x in p.parts for x in (".venv", "node_modules", ".git", ".ruff_cache"))
    )


def test_every_document_is_either_checked_or_exempt_for_a_stated_reason() -> None:
    """The exemption list is the whole scope, so it must be complete and true.

    A document that matches no exemption is checked; one that matches an
    exemption is not, and the reason is written down. Nothing is exempt by
    having been overlooked, which is what a list of CHECKED directories allows.
    """
    docs = _all_docs()
    assert docs, "no documents found - this test would check nothing"
    for pat in UNCHECKED_DOCS:
        assert any(fnmatch(str(d.relative_to(REPO)), pat) for d in docs), (
            f"UNCHECKED_DOCS pattern {pat!r} matches no document; "
            "an exemption for something that does not exist hides nothing and misleads"
        )


def test_the_deliberately_absent_list_is_still_true() -> None:
    """An allowlist that outlives its reason is a lie in a config file."""
    for ref, why in DELIBERATELY_ABSENT.items():
        assert not (REPO / ref).exists(), (
            f"{ref} now exists, but is listed as deliberately absent ({why}). "
            "Remove the entry so the reference is checked like any other."
        )


def test_live_docs_do_not_point_at_files_that_do_not_exist() -> None:
    """A file named eval/README.md was cited in four live documents - including
    AGENTS.md's gate condition and its own map of where the pre-registration
    lives - as the home of the Phase 0 decision rule. It had never been written.
    A reader following the repo's own signposts to find the authoritative rule
    found nothing, while the rule sat in docs/EVAL-PLAN.md.

    Backticked, bare and markdown-link forms are all checked. The first version
    of this test looked only inside backticks, and the two references that
    survived it survived because their backticks had been REMOVED to make it
    pass - an invariant that a formatting change defeats is not one. Paths that
    are named precisely because they do not exist go in `DELIBERATELY_ABSENT`,
    where a reader can see them.

    Checked over the LIVE docs only. `docs/history/` is frozen by convention and
    carries a banner saying so; a decision record describes the world as it was
    when the decision was taken; and CHANGELOG.md is the same kind of thing - a
    past release entry names the paths that existed then, and rewriting it to
    match today would destroy the record it exists to be.
    """
    live = [d for d in _all_docs() if _is_unchecked(str(d.relative_to(REPO))) is None]
    assert live, "no live docs found - this test would check nothing"
    dangling: list[str] = []
    for doc in live:
        for raw in sorted(_candidates(doc.read_text())):
            # `docs/decisions/` and `docs/decisions` name the same directory
            ref = raw.rstrip("/")
            if ref in DELIBERATELY_ABSENT or ref in EXTERNAL_CONVENTIONS:
                continue
            if (REPO / ref).exists() or (doc.parent / ref).exists():
                continue
            dangling.append(f"{doc.relative_to(REPO)} -> {raw}")
    assert not dangling, (
        "live docs name repo paths that do not exist:\n  "
        + "\n  ".join(dangling)
        + "\nFix the path, or add it to DELIBERATELY_ABSENT with the reason. Do NOT reword the "
        "reference until this test stops matching it."
    )


def test_no_document_contains_a_broken_link() -> None:
    """Links are navigation, and a broken one is broken whatever the age of the
    document. Checked EVERYWHERE, `docs/history/` included: the banners marking
    those files superseded were added by pointing at the live documents, and a
    banner whose links do not resolve is worse than no banner.
    """
    broken: list[str] = []
    unreadable: list[str] = []
    for doc in _all_docs():
        if any(fnmatch(str(doc.relative_to(REPO)), pat) for pat in LINK_UNCHECKED):
            continue
        rel = str(doc.relative_to(REPO))
        for m in _LINK.finditer(_strip_code(doc.read_text(), rel, unreadable)):
            ref = m.group(1)
            if ref.startswith(("http://", "https://", "#", "mailto:")):
                continue
            if not (doc.parent / ref.split("#")[0]).exists():
                broken.append(f"{doc.relative_to(REPO)} -> {ref}")
    assert not unreadable, (
        "code structure could not be read, so links in these documents were not "
        "fully checked:\n  " + "\n  ".join(unreadable)
    )
    assert not broken, "broken links:\n  " + "\n  ".join(broken)
