"""M2c follow-up 5, final round, item 2: a repository config is not only a git
problem, and the two other allowlisted tools are worse than they looked.

Measured 2026-08-24, this machine, against the REAL pinned tools:

* **mypy** - a repository ``mypy.ini`` with ``plugins = ./evil_plugin.py``
  EXECUTED the plugin. That is arbitrary code execution, the same class as
  ``[diff] external``, and it is PRE-EXISTING: nothing in the M2c config work
  introduced it, and nothing in it would have caught it either.
  ``--config-file <devnull>`` stops it.
* **ruff** - a repository ``ruff.toml`` with ``[lint] select = []`` made
  ``ruff check`` report "All checks passed!" on a file with an unused import.
  Not execution: EVIDENCE MANIPULATION. For an engine whose one job is
  deciding whether an answer is defensible given the evidence, a repository
  that can choose which lint findings exist is its own kind of serious.
  ``--isolated`` stops it - the same run then reports F401.

Eris now supplies both flags itself, on exactly the contract
``--no-optional-locks`` already had (:data:`eris.verify.ERIS_ISOLATION_FLAGS`):
first in argv, before any subcommand or positional, and hard-denied to a model.

This module spawns real processes but needs no ``allow`` list: every command
runs as ``sys.executable -m <tool>``, which the ``real_subprocess`` marker
already permits. The argv is not invented here - it is the argv
``check_command`` actually produced, with only argv[0] swapped for the
interpreter, so what is proved is the flag Eris really emits.

``pytest`` is deliberately absent from the isolation table: its ``conftest.py``
IS repository code and no flag isolates it, which is exactly why ``pytest``
requires ``trusted: true``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from eris.policy import Policy
from eris.sanitize import VERIFICATION_PROFILE, sanitize_snapshot
from eris.verify import ERIS_ISOLATION_FLAGS, check_command

pytestmark = pytest.mark.real_subprocess()

MARKER = "PLUGIN_EXECUTED"

EVIL_PLUGIN = """\
from pathlib import Path

Path({marker!r}).write_text("EXECUTED")

from mypy.plugin import Plugin


class _E(Plugin):
    pass


def plugin(version: str):
    return _E
"""


def _policy(tmp_path: Path, name: str, **spec: Any) -> Policy:
    """A policy whose pinned executable is the INTERPRETER: the tools run as
    `python -m <tool>`, so the suite never spawns a third-party binary."""
    exe = Path(sys.executable).resolve()
    return Policy.model_validate(
        {
            "policy_version": "t",
            "vendors_allowed": ["x"],
            "workers": {},
            "budgets": {"per_run_usd": 1, "per_call_usd": 1},
            "verify": {
                "commands": {
                    name: {
                        "executable": str(exe),
                        "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                        "positional": ["path"],
                        **spec,
                    }
                }
            },
        }
    )


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(cwd.parent / "home")}
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True)


def _as_module(argv: tuple[str, ...] | list[str], tool: str) -> list[str]:
    """The argv Eris built, with the pinned executable replaced by
    `python -m <tool>`. Everything Eris appended is kept verbatim."""
    return [sys.executable, "-m", tool, *argv[1:]]


def test_a_repository_mypy_plugin_cannot_execute_in_the_verification_copy(
    tmp_path: Path,
) -> None:
    """The vector, end to end, with the anti-vacuity half: the plugin DOES
    execute in the untouched original and does NOT under the argv Eris
    builds."""
    marker = tmp_path / MARKER
    source = tmp_path / "snapshot"
    (source / "src").mkdir(parents=True)
    (source / "src" / "m.py").write_text("x: int = 1\n")
    (source / "evil_plugin.py").write_text(EVIL_PLUGIN.format(marker=str(marker)))
    (source / "mypy.ini").write_text("[mypy]\nplugins = ./evil_plugin.py\n")

    # the vector is REAL: the repository's own config runs its own code
    marker.unlink(missing_ok=True)
    plain = _run([sys.executable, "-m", "mypy", "src"], source)
    assert marker.exists(), (
        f"the repository's mypy plugin did NOT run in the original; "
        f"the test has gone vacuous. exit={plain.returncode} {plain.stderr[:400]!r}"
    )

    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    assert (repo / "mypy.ini").is_file()  # tree content: copied, by design
    assert (repo / "evil_plugin.py").is_file()  # the payload is still there

    policy = _policy(tmp_path, "mypy", literal_flags=["--no-error-summary"])
    decision = check_command(
        ["mypy", "--no-error-summary", "src"], policy=policy, snapshot_root=repo
    )
    assert decision.allowed, decision.reason
    assert list(decision.argv[1:3]) == ["--config-file", os.devnull]

    marker.unlink(missing_ok=True)
    isolated = _run(_as_module(decision.argv, "mypy"), repo)
    assert not marker.exists(), "the repository's mypy plugin RAN in the verification copy"
    assert isolated.returncode == 0, isolated.stderr[:400]


def test_a_repository_ruff_config_cannot_choose_the_findings(tmp_path: Path) -> None:
    """The same shape one notch down: not execution, but a repository choosing
    what the evidence SAYS. Measured - with `[lint] select = []` in the tree,
    `ruff check` reports "All checks passed!" on a file with an unused import;
    with Eris's `--isolated` the same run reports F401."""
    source = tmp_path / "snapshot"
    (source / "src").mkdir(parents=True)
    (source / "src" / "bad.py").write_text("import os\n")  # F401
    (source / "ruff.toml").write_text("[lint]\nselect = []\n")

    # the vector is REAL: the repository silences the finding
    plain = _run([sys.executable, "-m", "ruff", "check", "src"], source)
    assert plain.returncode == 0 and b"F401" not in plain.stdout, (
        f"the repository config did NOT silence ruff; the test has gone vacuous. "
        f"exit={plain.returncode} {plain.stdout[:300]!r}"
    )

    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    assert (repo / "ruff.toml").is_file()  # tree content: copied, by design

    policy = _policy(tmp_path, "ruff", subcommands=["check"], literal_flags=["--no-fix"])
    decision = check_command(
        ["ruff", "check", "--no-fix", "src"], policy=policy, snapshot_root=repo
    )
    assert decision.allowed, decision.reason
    assert decision.argv[1] == "--isolated"

    isolated = _run(_as_module(decision.argv, "ruff"), repo)
    assert b"F401" in isolated.stdout, isolated.stdout[:400]
    assert isolated.returncode != 0  # the finding the repository tried to hide


def test_pytest_gets_no_isolation_flag_because_none_exists(tmp_path: Path) -> None:
    """Stated rather than implied. `conftest.py` is repository code that pytest
    imports and executes by design; there is no flag that turns that off, so
    pytest is not in the isolation table and is instead refused unless the
    policy is `trusted: true`. `-p no:cacheprovider` is about the cache
    directory, not about isolation."""
    assert "pytest" not in ERIS_ISOLATION_FLAGS

    source = tmp_path / "snapshot"
    source.mkdir()
    (source / "conftest.py").write_text("raise SystemExit('conftest ran')\n")
    policy = _policy(tmp_path, "pytest", requires_trusted=True, literal_flags=["-q"])
    decision = check_command(["pytest", "-q"], policy=policy, snapshot_root=source)
    assert not decision.allowed and "executes repository code" in decision.reason
