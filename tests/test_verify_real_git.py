"""M2c defect B, against a REAL git: the default evidence battery must run to
completion without tripping the verification tripwire.

The first live run of the harness (2026-08-23) recorded

    snapshot.violated  argv=["/usr/bin/git","status","--porcelain"]
    verify.refused     git ls-files   "an earlier command changed ..."
    verify.refused     git log --oneline -n 20   (same)

because ``git status`` refreshes ``.git/index`` (its stat cache), the copy's
tree hash changed, and every remaining verification command was refused. No
hermetic test could catch that: the fakes never execute a real ``git``.

This is the second and last test allowed to spawn ``git``
(``real_subprocess(allow=["git"])``; the other is
``test_snapshot.py::test_snapshot_has_no_future``). It runs the real code
path - ``build_evidence_pack`` -> ``run_allowlisted`` -> ``spawn`` - against a
real one-commit repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from eris.evidence import PACK_COMMANDS, SnapshotGuard, TaskSpec, VerifyEnv, build_evidence_pack
from eris.policy import Policy
from eris.redact import Redactor
from eris.sanitize import VERIFICATION_PROFILE, sanitize_snapshot
from eris.schemas import EvidenceKind
from eris.writer import RunWriter

pytestmark = pytest.mark.real_subprocess(allow=["git"])


def _git_executable() -> Path:
    """Resolved at test time, never from a tracked machine-specific path."""
    found = shutil.which("git")
    if found is None:  # pragma: no cover - git is a hard requirement of the repo
        pytest.skip("git is not on PATH")
    return Path(found).resolve()


def _make_repo(root: Path, git: Path) -> None:
    root.mkdir(parents=True)
    (root / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    (root / "README.md").write_text("# real repo\n")
    common = [
        str(git),
        "-c",
        "user.name=Eris Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "init.defaultBranch=main",
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(root.parent / "git-home"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    for argv in ([*common, "init", "-q"], [*common, "add", "-A"], [*common, "commit", "-qm", "c1"]):
        subprocess.run(argv, cwd=root, env=env, check=True, capture_output=True)


def _policy(tmp_path: Path, git: Path) -> Policy:
    return Policy.model_validate(
        {
            "policy_version": "t",
            "vendors_allowed": ["xai"],
            "workers": {},
            "runs_dir": str(tmp_path / "runs"),
            "path_env": os.environ.get("PATH", "/usr/bin:/bin"),
            "budgets": {"per_run_usd": 1, "per_call_usd": 1},
            "verify": {
                "max_output_bytes": 1_000_000,
                "commands": {
                    "git": {
                        "executable": str(git),
                        "executable_sha256": hashlib.sha256(git.read_bytes()).hexdigest(),
                        "subcommands": ["rev-parse", "status", "ls-files", "log"],
                        "literal_flags": ["--porcelain", "--oneline", "--no-color"],
                        "value_flags": {"-n": "^[0-9]{1,4}$"},
                        "positional": ["path", "^(HEAD(~[0-9]{1,3})?|[0-9a-f]{7,40})$"],
                        "timeout_s": 60,
                    }
                },
            },
        }
    )


def test_the_default_battery_runs_clean_against_a_real_git_repository(tmp_path: Path) -> None:
    git = _git_executable()
    source = tmp_path / "snapshot"
    _make_repo(source, git)
    # The battery runs on the pristine COPY, exactly as the harness does. That
    # is load-bearing here: the copied working tree no longer matches the stat
    # data recorded in .git/index, so `git status` WANTS to rewrite the index -
    # which is precisely what tripped the guard in the live run.
    repo = tmp_path / "verify-copy"
    sanitize_snapshot(source, repo, profile=VERIFICATION_PROFILE, worker_id="verify")
    policy = _policy(tmp_path, git)
    env = VerifyEnv(
        policy=policy,
        snapshot_root=repo,
        scratch_home=tmp_path / "verify-home",
        popen=subprocess.Popen,
        killpg=os.killpg,
        guard=SnapshotGuard.over(repo),
    )
    writer = RunWriter(tmp_path / "runs" / "r", Redactor(), run_id="r").open()
    task = TaskSpec.model_validate(
        {
            "task_id": "t_real",
            "question": "Does the battery complete?",
            "category": "control",
            "snapshot": "snapshot",
        }
    )
    build = build_evidence_pack(
        task,
        env=env,
        writer=writer,
        repeat_index=0,
        policy_sha256="0" * 64,
        snapshot_sha=None,
    )
    writer.close()

    events: list[dict[str, Any]] = [
        json.loads(line)
        for line in (tmp_path / "runs" / "r" / "events.jsonl").read_bytes().splitlines()
    ]
    kinds = [e["kind"] for e in events]
    assert "snapshot.violated" not in kinds, [
        e["payload"] for e in events if e["kind"] == "snapshot.violated"
    ]
    assert "verify.refused" not in kinds, [
        e["payload"] for e in events if e["kind"] == "verify.refused"
    ]
    assert build.refused == 0 and env.violated is False
    # the four default commands all produced evidence, in order
    assert len(build.executed_argv) == len(PACK_COMMANDS) == 4
    facts = [i for i in build.items if i.kind is EvidenceKind.REPO_FACT]
    assert len(facts) == 4
    assert [i.label.split(": ", 1)[1] for i in facts] == [" ".join(a) for a in PACK_COMMANDS]
    assert all(i.exit_code == 0 for i in facts)
    # every executed git argv carries the Eris-appended global, before the
    # subcommand - this is what keeps `status` from rewriting .git/index
    for argv in build.executed_argv:
        assert argv[1] == "--no-optional-locks" and not argv[2].startswith("-")
    by_label = {i.label.split(": ", 1)[1]: i for i in facts}
    assert by_label["git rev-parse HEAD"].content.strip().isalnum()
    assert by_label["git status --porcelain"].content == ""  # a clean tree
    assert set(by_label["git ls-files"].content.split()) == {"README.md", "calc.py"}
    assert "c1" in by_label["git log --oneline -n 20"].content
