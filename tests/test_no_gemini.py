"""Source-level guard: the `gemini` CLI worker is gone (M2a). No gemini
builder, parser, CLI name or literal may remain under src/eris, so that a
dead code path can never be resurrected by accident.

Allowed occurrences (each is about something that still exists):
* env names on the NEVER list that contain GEMINI (``GEMINI_CLI_TRUST_WORKSPACE``,
  ``GEMINI_API_KEY``, ``GOOGLE_GEMINI_BASE_URL``) - taken from
  ``launch.NEVER_ENV_EXACT`` itself, so the allowance cannot outlive the entry;
* ``~/.gemini/`` / ``.gemini/`` - paths: agy stores its state and the old
  OAuth file there (credential_files, brain-dir derivation);
* the model-id prefix ``"gemini-"`` - the agy lineage guard in policy.py;
* ``GEMINI.md`` - the repository rules file agy injects from a declared
  workspace (A15), named in the ``TODO(m2b)`` sanitization note.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from eris.launch import NEVER_ENV_EXACT

SRC = Path(__file__).resolve().parents[1] / "src" / "eris"
ALLOWED: tuple[str, ...] = (
    *sorted(name for name in NEVER_ENV_EXACT if "GEMINI" in name),
    "~/.gemini/",
    ".gemini/",
    '"gemini-"',
    "GEMINI.md",
)
_GEMINI = re.compile(r"gemini", re.IGNORECASE)


def _strip_allowed(line: str) -> str:
    for token in ALLOWED:
        line = line.replace(token, "")
    return line


@pytest.mark.parametrize("path", sorted(SRC.glob("*.py")), ids=lambda p: p.name)
def test_no_gemini_literal_in_source(path: Path) -> None:
    offenders = [
        f"{path.name}:{n}: {line.strip()}"
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _GEMINI.search(_strip_allowed(line))
    ]
    assert offenders == [], "\n".join(offenders)


def test_no_gemini_builder_parser_or_cli_name() -> None:
    from typing import get_args

    import eris.launch as launch
    import eris.policy as policy

    assert not hasattr(launch, "build_argv_gemini") and not hasattr(launch, "parse_gemini")
    assert not hasattr(launch, "first_balanced_json")  # only caller was parse_gemini
    assert "gemini" not in launch.PARSERS and "gemini" not in launch.PER_CLI_ENV
    assert set(get_args(policy.CliName)) == {"claude", "codex", "agy", "grok"}
    assert "agy" in launch.PARSERS and hasattr(launch, "build_argv_agy")


def test_the_allowed_gemini_occurrences_are_the_only_ones() -> None:
    """Each allowance is load-bearing: if one disappears from the source the
    allow-list should shrink with it (so it cannot mask a new occurrence)."""
    text = "\n".join(p.read_text(encoding="utf-8") for p in SRC.glob("*.py"))
    assert {"GEMINI_CLI_TRUST_WORKSPACE", "GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL"} <= set(
        ALLOWED
    )
    assert '"gemini-"' in text  # AGY_MODEL_PREFIX
    assert ".gemini/" in text  # brain-dir / credential paths
    assert "GEMINI.md" in text and "TODO(m2b)" in text  # the sanitization note
