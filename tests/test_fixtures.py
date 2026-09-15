"""Suite-wide guards over ``tests/fixtures``: captured envelopes are committed
only after redaction, and every capture carries a ``.meta.json`` sidecar with
the argv that produced it (mechanically captured or labelled reconstructed)."""

from __future__ import annotations

import getpass
import json
import re
from pathlib import Path

import pytest

from tests.conftest import FIXTURE_HOME_PLACEHOLDER, FIXTURE_OUTSIDE_PLACEHOLDER

FIXTURES = Path(__file__).parent / "fixtures"
# Placeholder account names that may follow /Users/ or /home/ (``/home/user``
# is a generic example in captured man pages).
PLACEHOLDER_NAMES = frozenset({"USER", "user"})
_USER_PATH = re.compile(r"/(?:Users|home)/([^/\s\"'`)\]]+)")
# The experiment directory of the capturing session embedded the username in
# its own name; any survivor of that form is a leak.
_SCRATCH_PATH = re.compile(r"/private/tmp/claude-[^/\s\"']*/-Users-[^/\s\"']*")
CAPTURED = "argv as recorded in scratchpad/exp2/run.sh (experiment battery 2)"
CAPTURED_FLAGTEST = "argv as recorded in scratchpad/flagtest/claude_tests.sh (flag battery 1)"
RECONSTRUCTED = (
    "reconstructed by the synthesizer from the experiment script; not mechanically captured"
)
# 2026-09-13: captures can now come from LIVE RUN LEDGERS - the strongest
# provenance of the four (RunWriter recorded the argv mechanically, hash-
# chained). The sidecar's note names the run id; absolute paths (which the
# ledger records for argv[0]) stay OUT of fixtures per the hygiene tests.
CAPTURED_LEDGER = (
    "argv as recorded by the RunWriter ledger of the capturing run (run id in note; "
    "argv[0] was the pinned absolute CLI path, normalised to the bare name here)"
)
CAPTURED_PROBE = (
    "argv as written and executed by the maintaining session's re-pin probe (exact, single command)"
)
ARGV_SOURCES = (CAPTURED, CAPTURED_FLAGTEST, RECONSTRUCTED, CAPTURED_LEDGER, CAPTURED_PROBE)


def _fixture_files() -> list[Path]:
    return sorted(p for p in FIXTURES.rglob("*") if p.is_file())


def test_no_fixture_contains_a_user_path() -> None:
    """Portable scan: any ``/Users/<name>`` or ``/home/<name>`` whose <name>
    is not a placeholder, or any ``/private/tmp/claude-*/-Users-*`` session
    path, anywhere under tests/fixtures (file name or body) is a leak of the
    capturing user's identity. No username literal lives in the repository."""
    files = _fixture_files()
    assert files
    offenders: list[str] = []
    for path in files:
        rel = str(path.relative_to(FIXTURES))
        body = path.read_bytes().decode("utf-8", errors="replace")
        for text, where in ((rel, "name"), (body, "body")):
            for m in _USER_PATH.finditer(text):
                if m.group(1) not in PLACEHOLDER_NAMES:
                    offenders.append(f"{rel} ({where}): {m.group(0)!r}")
            for m in _SCRATCH_PATH.finditer(text):
                offenders.append(
                    f"{rel} ({where}): {m.group(0)!r} (must be {FIXTURE_OUTSIDE_PLACEHOLDER})"
                )
    assert offenders == [], "\n".join(offenders)
    # the placeholders are real: captures were actually rewritten
    bodies = [p.read_text(encoding="utf-8") for p in files if p.suffix == ".json"]
    assert any(FIXTURE_HOME_PLACEHOLDER in b for b in bodies)
    assert any(FIXTURE_OUTSIDE_PLACEHOLDER in b for b in bodies)


def test_no_fixture_contains_the_local_user() -> None:
    """Additional LOCAL check (cannot see other capturers' names, so it is
    not the portable guard): the user running the suite must not appear in
    any fixture. Skipped where the account name cannot be determined."""
    try:
        name = getpass.getuser()
    except Exception:  # noqa: BLE001 - no account name available (containers, CI oddities)
        pytest.skip("getpass.getuser() unavailable")
    if not name or len(name) < 3 or name in PLACEHOLDER_NAMES:
        pytest.skip(f"local account name {name!r} is too generic to scan for")
    for path in _fixture_files():
        rel = str(path.relative_to(FIXTURES))
        assert name not in rel and name not in path.read_bytes().decode(
            "utf-8", errors="replace"
        ), f"{rel} mentions the local user"


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
    assert isinstance(meta["argv"], list) and meta["argv"]
    assert meta["argv"][0] in (meta["cli"], "env")
    assert meta["redacted"] in (True, False) and meta["captured_at"].startswith("2026-")
    # provenance is explicit: either the battery script recorded it, or the
    # sidecar says the argv was reconstructed and not mechanically captured
    if "argv_source" in meta:
        assert meta["argv_source"] in ARGV_SOURCES, meta["argv_source"]
    else:
        assert meta["captured_at"] == "2026-08-21"  # the M1 captures (claude/codex/grok)


def test_agy_sidecars_state_the_canonical_argv_order() -> None:
    """Every agy sidecar whose argv carries the full flag set lists it in the
    canonical order of build_argv_agy; runs without --add-dir say so."""
    canonical = [
        "--mode",
        "plan",
        "--sandbox",
        "--add-dir",
        "--output-format",
        "json",
        "--disable-slash-commands",
        "--print-timeout",
    ]
    for meta_path in sorted((FIXTURES / "envelopes" / "agy").rglob("*.meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        argv: list[str] = meta["argv"]
        if "--disable-slash-commands" not in argv:
            continue  # early battery runs (A1/A3/A5) used a subset; argv recorded verbatim
        present = [
            a for a in canonical if a in argv and not (a == "json" and "--add-dir" not in argv)
        ]
        positions = [argv.index(a) for a in present]
        assert positions == sorted(positions), f"{meta_path.name}: {argv}"
        if "--add-dir" in argv:
            assert argv.index("--add-dir") == argv.index("--sandbox") + 1, meta_path.name
        else:
            assert "WITHOUT --add-dir" in meta["note"], meta_path.name
