from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from eris.launch import GIT_HARDENING, LaunchRefused
from eris.policy import UNPINNED, Policy
from eris.verify import HARD_DENY, Decision, build_verify_env, check_command, run_allowlisted
from tests.conftest import FakeProcessFactory


def fake_exe(tmp_path: Path, name: str) -> tuple[Path, str]:
    exe = tmp_path / "bin" / name
    exe.parent.mkdir(exist_ok=True)
    exe.write_bytes(f"#!/bin/sh\necho {name}\n".encode())
    exe.chmod(0o755)
    return exe, hashlib.sha256(exe.read_bytes()).hexdigest()


def policy_with(tmp_path: Path, *, trusted: bool = False, **commands: dict[str, Any]) -> Policy:
    return Policy.model_validate(
        {
            "policy_version": "t",
            "trusted": trusted,
            "vendors_allowed": ["x"],
            "workers": {},
            "budgets": {"per_run_usd": 1, "per_call_usd": 1},
            "verify": {"commands": commands},
        }
    )


@pytest.fixture
def world(tmp_path: Path) -> tuple[Policy, Path]:
    git, git_sha = fake_exe(tmp_path, "git")
    pytest_exe, pytest_sha = fake_exe(tmp_path, "pytest")
    ruff, ruff_sha = fake_exe(tmp_path, "ruff")
    snapshot = tmp_path / "snap"
    (snapshot / "src").mkdir(parents=True)
    (snapshot / "src" / "a.py").write_text("x = 1\n")
    (snapshot / ".git").mkdir()
    (snapshot / ".git" / "config").write_text("")
    outside = tmp_path / "outside.py"
    outside.write_text("")
    os.symlink(outside, snapshot / "escape.py")
    policy = policy_with(
        tmp_path,
        git={
            "executable": str(git),
            "executable_sha256": git_sha,
            "subcommands": ["diff", "log", "grep", "show"],
            "literal_flags": ["--stat", "--name-only", "-p", "--no-color"],
            "value_flags": {
                "-n": "^[0-9]{1,4}$",
                "-e": "^[^\\x00\\n]{1,200}$",
                "--max-count": "^[0-9]+$",
            },
            "positional": ["path", "^(HEAD(~[0-9]{1,3})?|[0-9a-f]{7,40})$"],
            "max_args": 12,
        },
        pytest={
            "executable": str(pytest_exe),
            "executable_sha256": pytest_sha,
            "requires_trusted": True,
            "literal_flags": ["-q", "-x"],
            "value_flags": {"-p": "^no:[A-Za-z0-9_]+$", "-k": "^[A-Za-z0-9_ ]{1,120}$"},
            "positional": ["path"],
        },
        ruff={
            "executable": str(ruff),
            "executable_sha256": ruff_sha,
            "subcommands": ["check"],
            "literal_flags": ["--no-fix", "--isolated", "--output-format=json"],
            "value_flags": {"--select": "^[A-Z0-9,]{1,64}$"},
            "positional": ["path"],
        },
    )
    return policy, snapshot


# --------------------------------------------------------------------------- positive


def test_git_diff_with_paths_is_allowed(world: tuple[Policy, Path]) -> None:
    policy, snap = world
    d = check_command(["git", "diff", "--stat", "HEAD~1", "--", "src/a.py"], policy, snap)
    assert d.allowed, d.reason
    assert d.command == "git" and d.timeout_s == 600
    assert d.argv[0] == str(Path(policy.verify.commands["git"].executable).resolve())
    assert d.argv[1:] == ("diff", "--stat", "HEAD~1", "--", "src/a.py")


def test_value_flags_both_forms(world: tuple[Policy, Path]) -> None:
    policy, snap = world
    assert check_command(["git", "log", "-n", "5", "src"], policy, snap).allowed
    assert check_command(["git", "log", "--max-count=5", "src"], policy, snap).allowed
    assert check_command(["git", "grep", "-e", "TODO", "--", "src"], policy, snap).allowed
    assert check_command(
        ["ruff", "check", "--select", "E9,F", "--output-format=json", "src"], policy, snap
    ).allowed


def test_executable_path_as_argv0_is_accepted(world: tuple[Policy, Path]) -> None:
    policy, snap = world
    exe = policy.verify.commands["git"].executable
    assert check_command([exe, "show", "HEAD"], policy, snap).allowed


def test_pytest_allowed_only_when_trusted(world: tuple[Policy, Path], tmp_path: Path) -> None:
    policy, snap = world
    d = check_command(["pytest", "-q", "src"], policy, snap)
    assert not d.allowed and "not trusted" in d.reason
    trusted = policy.model_copy(update={"trusted": True})
    assert check_command(
        ["pytest", "-q", "-p", "no:cacheprovider", "-k", "test_x", "src"], trusted, snap
    ).allowed


# --------------------------------------------------------------------------- refuse list


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        ([], "empty argv"),
        (["bash", "-c", "true"], "not allowlisted"),
        (["git", "push"], "subcommand"),
        (["git"], "subcommand"),
        (["git", "diff", "--ext-diff"], "hard-denied"),
        (["git", "diff", "-c", "core.pager=evil"], "hard-denied"),
        (["git", "-C", "/", "log"], "subcommand"),
        (["git", "log", "--output=/tmp/x"], "hard-denied"),
        (["git", "log", "-O/tmp/x"], "hard-denied"),
        (["git", "log", "--exec-path=/tmp"], "hard-denied"),
        (["git", "diff", "--unknown-flag"], "not allowlisted"),
        (["git", "diff", "-pq"], "not allowlisted"),
        (["git", "log", "-n", "abc"], "does not match"),
        (["git", "log", "-n"], "needs a value"),
        (["git", "log", "@args"], "response files"),
        (["git", "diff", "--", "-"], "stdin"),
        (["git", "diff", "../outside.py"], "neither a snapshot path"),
        (["git", "diff", "--", "../outside.py"], "escapes the snapshot"),
        (["git", "diff", "/etc/passwd"], "neither a snapshot path"),
        (["git", "diff", "escape.py"], "neither a snapshot path"),
        (["git", "diff", "--", "escape.py"], "escapes the snapshot"),
        (["git", "show", ".git/config"], "neither a snapshot path"),
        (["git", "show", "--", ".git/config"], "points into .git"),
        (["git", "show", "HEAD\nrm"], "control character"),
        (["git", "show", "a\x00b"], "control character"),
        (
            [
                "git",
                "log",
                "--",
                "src",
                "src",
                "src",
                "src",
                "src",
                "src",
                "src",
                "src",
                "src",
                "src",
            ],
            "too many",
        ),
        (["ruff", "check", "--fix", "src"], "hard-denied"),
        (["ruff", "check", "--config=evil.toml", "src"], "hard-denied"),
        (["ruff", "format", "src"], "subcommand"),
    ],
)
def test_refused(world: tuple[Policy, Path], argv: list[str], reason: str) -> None:
    policy, snap = world
    d = check_command(argv, policy, snap)
    assert not d.allowed, f"{argv} should be refused"
    assert reason in d.reason, d.reason


def test_no_shell_so_metacharacters_stay_one_argument(world: tuple[Policy, Path]) -> None:
    """There is no shell: a positional like 'HEAD; rm -rf /' is one literal
    argv element that resolves inside the snapshot (git will reject it as an
    unknown path). Allowing it is correct; splitting it would be the bug."""
    policy, snap = world
    d = check_command(["git", "show", "HEAD; rm -rf /"], policy, snap)
    assert d.allowed and d.argv[-1] == "HEAD; rm -rf /"
    d = check_command(["git", "show", "$(whoami)"], policy, snap)
    assert d.allowed and d.argv[-1] == "$(whoami)"


def test_pytest_hard_deny_even_when_trusted(world: tuple[Policy, Path]) -> None:
    policy, snap = world
    trusted = policy.model_copy(update={"trusted": True})
    for bad in (
        ["pytest", "-c", "x.ini"],
        ["pytest", "-p", "evilplugin"],
        ["pytest", "--rootdir=/", "src"],
        ["pytest", "-o", "addopts=-p evil"],
        ["pytest", "--pdb"],
        ["pytest", "-pevil"],
    ):
        d = check_command(bad, trusted, snap)
        assert not d.allowed, bad
    # Even a policy that tries to allowlist -c for pytest is overruled by HARD_DENY.
    loose = trusted.model_copy(
        update={
            "verify": trusted.verify.model_copy(
                update={
                    "commands": {
                        **trusted.verify.commands,
                        "pytest": trusted.verify.commands["pytest"].model_copy(
                            update={"literal_flags": ["-q", "-c"]}
                        ),
                    }
                }
            )
        }
    )
    d = check_command(["pytest", "-c", "src"], loose, snap)
    assert not d.allowed and "hard-denied" in d.reason
    assert "-c" in HARD_DENY["pytest"] and "--config-file" in HARD_DENY["mypy"]


def test_pin_and_binary_checks(world: tuple[Policy, Path], tmp_path: Path) -> None:
    policy, snap = world
    git_cmd = policy.verify.commands["git"]

    def with_git(**update: Any) -> Policy:
        return policy.model_copy(
            update={
                "verify": policy.verify.model_copy(
                    update={
                        "commands": {
                            **policy.verify.commands,
                            "git": git_cmd.model_copy(update=update),
                        }
                    }
                )
            }
        )

    d = check_command(["git", "log"], with_git(executable_sha256=UNPINNED), snap)
    assert not d.allowed and "UNPINNED" in d.reason
    d = check_command(["git", "log"], with_git(executable_sha256="f" * 64), snap)
    assert not d.allowed and "hash mismatch" in d.reason
    d = check_command(["git", "log"], with_git(executable=str(tmp_path / "bin" / "nope")), snap)
    assert not d.allowed and "missing" in d.reason
    d = check_command(["git", "log"], policy, tmp_path / "no-such-snapshot")
    assert not d.allowed and "not a directory" in d.reason
    # a swapped binary invalidates the pin
    Path(git_cmd.executable).write_bytes(b"#!/bin/sh\necho pwned\n")
    d = check_command(["git", "log"], policy, snap)
    assert not d.allowed and "hash mismatch" in d.reason


# --------------------------------------------------------------------------- env + execution


def test_verify_env_is_built_from_empty_and_git_hardened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LEAK_CANARY", "1")
    env = build_verify_env(path_env="/usr/bin", scratch_home=tmp_path)
    assert "LEAK_CANARY" not in env
    for k, v in GIT_HARDENING.items():
        assert env[k] == v
    assert env["HOME"] == str(tmp_path) and env["PYTHONHASHSEED"] == "0"
    for never in ("PYTHONPATH", "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "SSH_AUTH_SOCK"):
        assert never not in env


def test_run_allowlisted_refuses_denied_decisions(
    world: tuple[Policy, Path], tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    policy, snap = world
    factory = fake_process(stdout=b"ok")
    with pytest.raises(PermissionError):
        run_allowlisted(Decision(False, "nope"), policy, snap, tmp_path / "scratch", popen=factory)
    assert factory.instances == []
    d = check_command(["git", "diff", "--stat", "src"], policy, snap)
    res = run_allowlisted(
        d, policy, snap, tmp_path / "scratch", popen=factory, killpg=lambda *_: None
    )
    assert res.stdout == b"ok" and res.exit_code == 0
    kw = factory.instances[0].popen_kwargs
    assert kw["cwd"] == str(snap.resolve()) and kw["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert kw["env"]["HOME"] == str(tmp_path / "scratch")
    assert list(factory.instances[0].args) == list(d.argv)


def test_run_allowlisted_passes_through_launch_refusal(
    world: tuple[Policy, Path], tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    policy, snap = world
    forged = Decision(True, "forged", "git", ("git", "--bare"), 10)
    with pytest.raises(LaunchRefused):
        run_allowlisted(forged, policy, snap, tmp_path / "s", popen=fake_process())
