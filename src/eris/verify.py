"""Allowlisted mechanical verification commands.

Model-proposed commands are REQUESTS. :func:`check_command` decides, from the
policy's ``verify.commands`` grammar, whether Eris may execute one:

* ``argv[0]`` must name a declared command; its executable's realpath and
  sha256 must match the pin.
* Subcommands (when declared) come from a fixed list.
* Flags are allowlisted: exact literals, or ``flag value`` / ``flag=value``
  whose value matches the declared regex. Unknown flags, combined short
  flags, response files (``@file``) and ``-`` (stdin) are refused.
* Positional arguments must be paths whose realpath is inside the snapshot
  (never inside ``.git/``) or match a declared regex (e.g. a git revision).
* A hard deny list per tool (config/plugin/exec-path style flags) applies
  even if a policy tries to allowlist them.
* Commands that execute repository code (``requires_trusted``) are refused
  unless the policy is ``trusted``.

The execution environment is built from ``{}`` with git hardening
(``GIT_CONFIG_GLOBAL=/dev/null``, ``GIT_CONFIG_NOSYSTEM=1``, ``GIT_PAGER=cat``,
``GIT_TERMINAL_PROMPT=0``) and the launcher's NEVER list.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from eris.launch import (
    BASE_ENV,
    GIT_HARDENING,
    KillPg,
    PopenFactory,
    SpawnResult,
    assert_env_safe,
    spawn,
)
from eris.policy import Policy, VerifyCommand, sha256_file

# Defense in depth: refused for these tools regardless of the policy grammar.
# Every entry was verified against the captured --help output of the pinned
# tool versions in tests/fixtures/help/ (git 2.50.1, pytest 9.1.1, ruff 0.16.4,
# mypy 2.3.1); tests/test_verify_allowlist.py asserts each entry appears there.
HARD_DENY: dict[str, frozenset[str]] = {
    "git": frozenset(
        {
            # global options (git-2.50.1.txt)
            "-c",
            "-C",
            "--exec-path",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--config-env",
            "--bare",
            "--paginate",
            # diff family (git-diff-2.50.1.txt): external programs / writes / outside-repo
            "--ext-diff",
            "--textconv",
            "--output",
            "-O",
            "--no-index",
        }
    ),
    "pytest": frozenset(
        {
            "-c",
            "--config-file",
            "--rootdir",
            "-o",
            "--override-ini",
            "--import-mode",
            "--basetemp",
            "--pdb",
            "--pdbcls",
            "--trace",
            "--junitxml",
            "--junit-xml",
            "--junitprefix",
            "--junit-prefix",
            "--cov",
            "--cov-report",
            "--cov-config",
            "--cov-append",
            "--confcutdir",
            "--pyargs",
            "--lf",
            "--last-failed",
            "--ff",
            "--failed-first",
            "--nf",
            "--new-first",
            "--sw",
            "--stepwise",
            "-W",
            "--pythonwarnings",
            "--doctest-modules",
            "--doctest-glob",
            "--log-file",
            "--log-file-mode",
            "--pastebin",
            "--debug",
            "--cache-clear",
            "--assert",
        }
    ),
    "ruff": frozenset(
        {
            "--config",
            "--fix",
            "--fix-only",
            "--unsafe-fixes",
            "--add-noqa",
            "--add-ignore",
            "--cache-dir",
            "--preview",
            "--extension",
            "--stdin-filename",
            "-e",
            "--exit-zero",
            "--exit-non-zero-on-fix",
            "-o",
            "--output-file",
            "-w",
            "--watch",
            "--show-settings",
        }
    ),
    "mypy": frozenset(
        {
            "--config-file",
            "--python-executable",
            "--shadow-file",
            "--custom-typeshed-dir",
            "--custom-typing-module",
            "--cache-dir",
            "--sqlite-cache",
            "--install-types",
            "--non-interactive",
            "-c",
            "--command",
            "-p",
            "--package",
            "-m",
            "--module",
            "--junit-xml",
            "--pdb",
            "--any-exprs-report",
            "--cobertura-xml-report",
            "--html-report",
            "--linecount-report",
            "--linecoverage-report",
            "--lineprecision-report",
            "--txt-report",
            "--xml-report",
            "--xslt-html-report",
            "--xslt-txt-report",
        }
    ),
}

_PYTEST_P_OK = re.compile(r"^no:[A-Za-z0-9_]+$")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    command: str | None = None
    argv: tuple[str, ...] = ()
    timeout_s: int = 0


def _refuse(reason: str, command: str | None = None) -> Decision:
    return Decision(False, reason, command)


def _is_denied(command: str, arg: str) -> bool:
    deny = HARD_DENY.get(command, frozenset())
    if arg in deny:
        return True
    for flag in deny:
        if flag.startswith("--") and arg.startswith(flag + "="):
            return True
        if not flag.startswith("--") and len(flag) == 2 and arg.startswith(flag) and len(arg) > 2:
            return True  # combined short flag like -cfoo / -pplugin
    return False


def _path_ok(arg: str, root: Path) -> str | None:
    """None when the path is acceptable, else the reason."""
    if arg == "-" or arg == "":
        return "stdin/empty path"
    candidate = Path(arg)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()
    try:
        rel = resolved.relative_to(root)
    except ValueError:
        return f"path {arg!r} escapes the snapshot"
    if ".git" in rel.parts:
        return f"path {arg!r} points into .git"
    return None


def check_command(
    argv: Sequence[str],
    policy: Policy,
    snapshot_root: Path,
    *,
    hasher: Callable[[Path], str] = sha256_file,
) -> Decision:
    if not argv:
        return _refuse("empty argv")
    for i, arg in enumerate(argv):
        if "\x00" in arg or "\n" in arg or "\r" in arg:
            return _refuse(f"argv[{i}] contains a control character")
    name = argv[0]
    spec: VerifyCommand | None = policy.verify.commands.get(name)
    if spec is None:
        for cmd_name, cmd in policy.verify.commands.items():
            if cmd.executable == name:
                name, spec = cmd_name, cmd
                break
    if spec is None:
        return _refuse(f"command {argv[0]!r} is not allowlisted")
    if spec.requires_trusted and not policy.trusted:
        return _refuse(f"{name} executes repository code; policy is not trusted", name)
    if not spec.pinned:
        return _refuse(f"{name} executable is UNPINNED (run `eris policy pin`)", name)
    exe = Path(spec.executable)
    if not exe.is_file():
        return _refuse(f"{name} executable {exe} is missing (recorded absence)", name)
    if exe.resolve() != exe and not exe.resolve().is_file():
        return _refuse(f"{name} executable resolves outside a regular file", name)
    actual = hasher(exe.resolve())
    if actual != spec.executable_sha256:
        return _refuse(f"{name} executable hash mismatch (binary changed since pin)", name)
    if len(argv) > spec.max_args:
        return _refuse(f"too many arguments ({len(argv)} > {spec.max_args})", name)
    root = Path(snapshot_root).resolve()
    if not root.is_dir():
        return _refuse(f"snapshot {root} is not a directory", name)

    rest = list(argv[1:])
    out: list[str] = [str(exe.resolve())]
    if spec.subcommands:
        if not rest or rest[0] not in spec.subcommands:
            return _refuse(f"{name} subcommand must be one of {sorted(spec.subcommands)}", name)
        out.append(rest.pop(0))

    only_paths = False
    i = 0
    while i < len(rest):
        arg = rest[i]
        i += 1
        if _is_denied(name, arg):
            return _refuse(f"{name}: {arg!r} is hard-denied", name)
        if only_paths:
            why = _path_ok(arg, root)
            if why:
                return _refuse(why, name)
            out.append(arg)
            continue
        if arg == "--":
            only_paths = True
            out.append(arg)
            continue
        if arg.startswith("@"):
            return _refuse("response files (@file) are refused", name)
        if arg.startswith("-"):
            if arg in spec.value_flags:
                if i >= len(rest):
                    return _refuse(f"flag {arg} needs a value", name)
                value = rest[i]
                i += 1
                if not re.fullmatch(spec.value_flags[arg], value):
                    return _refuse(f"value for {arg} does not match its allowlist regex", name)
                if name == "pytest" and arg == "-p" and not _PYTEST_P_OK.fullmatch(value):
                    return _refuse("pytest -p may only disable plugins (no:<name>)", name)
                out += [arg, value]
                continue
            if arg in spec.literal_flags:
                out.append(arg)
                continue
            flag, eq, value = arg.partition("=")
            if eq and flag in spec.value_flags and re.fullmatch(spec.value_flags[flag], value):
                out.append(arg)
                continue
            return _refuse(f"flag {arg!r} is not allowlisted for {name}", name)
        matched = False
        for rule in spec.positional:
            if rule == "path":
                if _path_ok(arg, root) is None:
                    matched = True
                    break
            elif re.fullmatch(rule, arg):
                matched = True
                break
        if not matched:
            return _refuse(
                f"positional {arg!r} is neither a snapshot path nor an allowed pattern", name
            )
        out.append(arg)
    return Decision(True, "allowlisted", name, tuple(out), spec.timeout_s)


def build_verify_env(*, path_env: str, scratch_home: Path) -> dict[str, str]:
    """From ``{}``: locale/pager hygiene, HOME/TMPDIR in a scratch dir, git hardening."""
    env: dict[str, str] = {}
    env.update(BASE_ENV)
    env["PATH"] = path_env
    env["HOME"] = str(scratch_home)
    env["TMPDIR"] = str(scratch_home)
    env["PYTHONHASHSEED"] = "0"
    env["MYPY_CACHE_DIR"] = str(Path(scratch_home) / "mypy_cache")
    env["RUFF_CACHE_DIR"] = str(Path(scratch_home) / "ruff_cache")
    assert_env_safe(env)
    env.update(GIT_HARDENING)
    return env


def run_allowlisted(
    argv: Sequence[str],
    policy: Policy,
    snapshot_root: Path,
    scratch_home: Path,
    *,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
    clock: Callable[[], float] = time.monotonic,
    hasher: Callable[[Path], str] = sha256_file,
) -> tuple[Decision, SpawnResult]:
    """Validate RAW argv with :func:`check_command` immediately before spawning.

    Callers cannot hand in a pre-made ``Decision``: the grammar is re-applied
    here so a forged or stale decision can never reach ``spawn``.
    """
    decision = check_command(argv, policy, Path(snapshot_root), hasher=hasher)
    if not decision.allowed or not decision.argv:
        raise PermissionError(f"refusing to run: {decision.reason}")
    Path(scratch_home).mkdir(parents=True, exist_ok=True)
    env = build_verify_env(path_env=policy.path_env, scratch_home=Path(scratch_home))
    result = spawn(
        list(decision.argv),
        env=env,
        cwd=Path(snapshot_root),
        timeout_s=decision.timeout_s,
        max_stdout_bytes=policy.verify.max_output_bytes,
        max_stderr_bytes=policy.verify.max_output_bytes,
        popen=popen,
        killpg=killpg,
        clock=clock,
    )
    return decision, result
