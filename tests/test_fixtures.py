"""Suite-wide guards over ``tests/fixtures``: captured envelopes are committed
only after redaction, and every capture carries a ``.meta.json`` sidecar with
the argv that produced it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import FIXTURE_REDACTIONS

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_files() -> list[Path]:
    return sorted(p for p in FIXTURES.rglob("*") if p.is_file())


def test_no_fixture_contains_a_redaction_literal() -> None:
    """No file under tests/fixtures (name or body) may contain the capturing
    user's home directory or username. The literals come from the redaction
    list in conftest (derived from the environment, not hardcoded), so the
    test is portable and the username never appears in the repository."""
    literals = sorted(FIXTURE_REDACTIONS)
    assert literals and all(len(lit) >= 3 for lit in literals)
    files = _fixture_files()
    assert files
    for path in files:
        rel = str(path.relative_to(FIXTURES))
        body = path.read_bytes().decode("utf-8", errors="replace")
        for literal in literals:
            assert literal not in rel, f"{rel}: file name contains {literal!r}"
            assert literal not in body, f"{rel}: body contains {literal!r}"
    # the placeholder is real: at least one capture was actually rewritten
    assert any(
        FIXTURE_REDACTIONS[str(Path.home())] in p.read_text(encoding="utf-8")
        for p in files
        if p.suffix == ".json"
    )


@pytest.mark.parametrize(
    "capture",
    sorted(
        str(p.relative_to(FIXTURES))
        for p in (FIXTURES / "envelopes").rglob("*")
        if p.is_file() and not p.name.endswith(".meta.json")
    ),
)
def test_every_capture_has_a_meta_sidecar_with_argv(capture: str) -> None:
    path = FIXTURES / capture
    meta_path = path.with_suffix(".meta.json")
    assert meta_path.is_file(), f"{capture} has no .meta.json sidecar"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["cli"] == path.parts[-3] and meta["version"] == path.parts[-2]
    assert (
        isinstance(meta["argv"], list)
        and meta["argv"]
        and meta["argv"][0]
        in (
            meta["cli"],
            "env",
        )
    )
    assert meta["redacted"] in (True, False) and meta["captured_at"].startswith("2026-")
