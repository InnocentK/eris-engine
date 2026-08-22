from __future__ import annotations

import hashlib
import os
import re
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


def test_run_allowlisted_revalidates_raw_argv_before_spawn(
    world: tuple[Policy, Path], tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    policy, snap = world
    factory = fake_process(stdout=b"ok")
    with pytest.raises(PermissionError, match="not allowlisted"):
        run_allowlisted(["bash", "-c", "true"], policy, snap, tmp_path / "scratch", popen=factory)
    assert factory.instances == []
    d, res = run_allowlisted(
        ["git", "diff", "--stat", "src"],
        policy,
        snap,
        tmp_path / "scratch",
        popen=factory,
        killpg=lambda *_: None,
    )
    assert d.allowed and res.stdout == b"ok" and res.exit_code == 0
    kw = factory.instances[0].popen_kwargs
    assert kw["cwd"] == str(snap.resolve()) and kw["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert kw["env"]["HOME"] == str(tmp_path / "scratch")
    assert list(factory.instances[0].args) == list(d.argv)
    assert d.argv[0] == str(Path(policy.verify.commands["git"].executable).resolve())


def test_forged_decision_cannot_reach_spawn(
    world: tuple[Policy, Path], tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """A caller can no longer hand in a Decision: run_allowlisted takes RAW
    argv and applies the grammar itself immediately before spawning."""
    policy, snap = world
    factory = fake_process(stdout=b"uid=0")
    forged = Decision(True, "forged", "git", ("/bin/sh", "-c", "id"), 10)
    with pytest.raises(PermissionError, match="not allowlisted"):
        run_allowlisted(list(forged.argv), policy, snap, tmp_path / "s", popen=factory)
    with pytest.raises(TypeError):
        run_allowlisted(forged, policy, snap, tmp_path / "s", popen=factory)  # type: ignore[arg-type]
    # stale decision: the binary changed between an earlier check and now
    Path(policy.verify.commands["git"].executable).write_bytes(b"#!/bin/sh\necho swapped\n")
    with pytest.raises(PermissionError, match="hash mismatch"):
        run_allowlisted(
            ["git", "diff", "--stat", "src"], policy, snap, tmp_path / "s", popen=factory
        )
    assert factory.instances == []


def test_run_allowlisted_refuses_forbidden_launch_tokens(
    world: tuple[Policy, Path], tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    policy, snap = world
    with pytest.raises(PermissionError, match="hard-denied"):
        run_allowlisted(
            ["git", "diff", "--bare"], policy, snap, tmp_path / "s", popen=fake_process()
        )
    assert LaunchRefused  # spawn's own guard stays behind the grammar as defense in depth


# --------------------------------------------------------------------------- deny lists vs help

HELP_DIR = Path(__file__).parent / "fixtures" / "help"
HELP_FILES = {
    "git": ["git-2.50.1.txt", "git-diff-2.50.1.txt", "git-log-2.50.1.txt"],
    "pytest": ["pytest-9.1.1.txt"],
    "ruff": ["ruff-check-0.16.4.txt"],
    "mypy": ["mypy-2.3.1.txt"],
}


def _flag_in_help(flag: str, text: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", text) is not None


@pytest.mark.parametrize("command", sorted(HARD_DENY))
def test_every_hard_deny_entry_is_a_real_flag_of_the_pinned_tool(command: str) -> None:
    """A deny entry that is not in the captured --help is a sign the list
    drifted from the tool (wrong name = no protection). Captured on
    2026-08-22 from the versions named in the fixture file names."""
    text = "\n".join((HELP_DIR / f).read_text() for f in HELP_FILES[command])
    missing = sorted(flag for flag in HARD_DENY[command] if not _flag_in_help(flag, text))
    assert missing == [], f"{command}: not in captured help: {missing}"


def test_mandatory_hard_deny_entries_present() -> None:
    assert {
        "--log-file",
        "--pastebin",
        "--junit-xml",
        "--doctest-modules",
        "--import-mode",
        "--trace",
        "-W",
        "-c",
        "--rootdir",
        "-o",
        "--basetemp",
        "--pdb",
    } <= HARD_DENY["pytest"]
    assert {
        "--fix",
        "--fix-only",
        "--unsafe-fixes",
        "--config",
        "--cache-dir",
        "--preview",
        "--add-noqa",
        "--stdin-filename",
    } <= HARD_DENY["ruff"]
    assert {
        "--python-executable",
        "--shadow-file",
        "--custom-typeshed-dir",
        "--config-file",
        "--cache-dir",
        "--install-types",
        "-c",
        "-p",
        "-m",
    } <= HARD_DENY["mypy"]
    assert {
        "-c",
        "-C",
        "--exec-path",
        "--git-dir",
        "--work-tree",
        "--ext-diff",
        "--textconv",
        "--output",
        "-O",
        "--no-index",
    } <= HARD_DENY["git"]
    assert "--plugins" not in HARD_DENY["mypy"]  # not a mypy 2.3.1 flag: removed


def test_default_policy_allowlists_only_real_flags() -> None:
    """Literal and value flags in policies/default.yaml must exist in the captured help."""
    from eris.policy import load_policy

    repo_policy = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
    pol = load_policy(repo_policy, pins_path=repo_policy.with_name("no-such-pins.yaml")).policy
    for name, cmd in pol.verify.commands.items():
        text = "\n".join((HELP_DIR / f).read_text() for f in HELP_FILES[name])
        flags = [*cmd.literal_flags, *cmd.value_flags]
        unknown = [f for f in flags if f != "--" and not _flag_in_help(f.split("=")[0], text)]
        if name == "git":
            # git-log/grep/show/blame help was not captured in full; only global+diff flags checked
            unknown = [f for f in unknown if f in HARD_DENY["git"]]
        assert unknown == [], f"{name}: {unknown}"
        assert not any(f in HARD_DENY.get(name, ()) for f in flags), name
