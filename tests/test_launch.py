from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from eris.launch import (
    FORBIDDEN_ARGV_TOKENS,
    GIT_HARDENING,
    PARSERS,
    PER_CLI_ENV,
    LaunchRefused,
    WorkerCall,
    agy_print_timeout_s,
    assert_agy_workspace,
    assert_argv_safe,
    assert_env_safe,
    build_argv_agy,
    build_argv_claude,
    build_argv_codex,
    build_argv_grok,
    build_env,
    idempotency_key,
    invocation_id_for,
    parse_agy,
    parse_claude,
    parse_codex,
    parse_grok,
    plan_call,
    preflight_executable,
    run_worker,
    spawn,
)
from eris.policy import UNPINNED, WorkerPolicy
from eris.schemas import Stage, Transport, WorkerStatus
from tests.conftest import FakeProcess, FakeProcessFactory

FIX = Path(__file__).parent / "fixtures" / "envelopes"
PROMPT = "Review the change and reply in JSON."


def fixture(cli: str, version: str, name: str) -> bytes:
    return (FIX / cli / version / name).read_bytes()


# --------------------------------------------------------------------------- argv


def test_claude_argv_exactly_as_specified() -> None:
    argv = build_argv_claude(
        "/x/claude", PROMPT, tools=["Read", "Grep", "Glob"], schema_json="{}", max_budget_usd=0.5
    )
    assert argv == [
        "/x/claude",
        "-p",
        PROMPT,
        "--safe-mode",
        "--permission-mode",
        "plan",
        "--tools",
        "Read,Grep,Glob",
        "--no-session-persistence",
        "--output-format",
        "json",
        "--json-schema",
        "{}",
        "--max-budget-usd",
        "0.5",
    ]
    assert build_argv_claude("/x/claude", PROMPT)[7] == ""  # no tools -> --tools ""
    assert "--model" in build_argv_claude("/x/claude", PROMPT, model="m")


def test_codex_argv_exactly_as_specified(tmp_path: Path) -> None:
    argv = build_argv_codex(
        "/x/codex",
        PROMPT,
        cwd=tmp_path,
        model="gpt-5.4",
        schema_path=tmp_path / "s.json",
        output_path=tmp_path / "o.json",
    )
    assert argv == [
        "/x/codex",
        "exec",
        "-C",
        str(tmp_path),
        "-s",
        "read-only",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "-c",
        "project_doc_max_bytes=0",
        "--skip-git-repo-check",
        "-m",
        "gpt-5.4",
        "--json",
        "--output-schema",
        str(tmp_path / "s.json"),
        "-o",
        str(tmp_path / "o.json"),
        PROMPT,
    ]


def _agy_argv(tmp_path: Path, **kw: Any) -> list[str]:
    prompt = kw.pop("prompt", PROMPT)
    base: dict[str, Any] = {
        "model": "gemini-3.1-pro-high",
        "workspace": tmp_path,
        "print_timeout_s": 30,
    }
    base.update(kw)
    return build_argv_agy("/x/agy", prompt, **base)


def test_agy_argv_exactly_as_specified(tmp_path: Path) -> None:
    ws = tmp_path / "snap"
    ws.mkdir()
    argv = build_argv_agy(
        "/x/agy",
        PROMPT,
        model="gemini-3.1-pro-high",
        workspace=ws,
        print_timeout_s=570,
        schema_json="{}",
    )
    assert argv == [
        "/x/agy",
        "-p",
        PROMPT,
        "--model",
        "gemini-3.1-pro-high",
        "--mode",
        "plan",
        "--sandbox",
        "--add-dir",
        str(ws.resolve()),
        "--output-format",
        "json",
        "--disable-slash-commands",
        "--print-timeout",
        "570s",
        "--json-schema",
        "{}",
    ]
    bare = build_argv_agy(
        "/x/agy", PROMPT, model="gemini-3.1-pro-high", workspace=ws, print_timeout_s=30
    )
    assert bare == argv[:-4] + ["--print-timeout", "30s"] and "--json-schema" not in bare
    with pytest.raises(LaunchRefused, match="print-timeout"):
        build_argv_agy(
            "/x/agy", PROMPT, model="gemini-3.1-pro-high", workspace=ws, print_timeout_s=0
        )


def test_agy_add_dir_is_the_workspace_realpath_exactly_once(tmp_path: Path) -> None:
    """--add-dir is REQUIRED (A14: without it agy cannot read its own cwd) and
    must be exactly the spawn cwd (A16: reads outside it are denied). A
    symlinked workspace is resolved; the check is element-exact."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    argv = _agy_argv(tmp_path, workspace=link)
    assert argv.count("--add-dir") == 1
    assert argv[argv.index("--add-dir") + 1] == str(real.resolve())
    assert_agy_workspace(argv, link)  # same cwd via the link resolves equal
    assert_agy_workspace(argv, real)
    with pytest.raises(LaunchRefused, match="must equal the spawn cwd"):
        assert_agy_workspace(argv, tmp_path)  # points elsewhere
    with pytest.raises(LaunchRefused, match="exactly one --add-dir"):
        assert_agy_workspace(argv + ["--add-dir", str(real)], real)  # a second workspace
    with pytest.raises(LaunchRefused, match="exactly one --add-dir"):
        assert_agy_workspace([a for a in argv if a != "--add-dir"], real)  # none
    truncated = argv[: argv.index("--add-dir") + 1]
    with pytest.raises(LaunchRefused, match="must equal"):
        assert_agy_workspace(truncated, real)  # flag without a value
    # the prompt may mention --add-dir without counting as a workspace ...
    quoted = _agy_argv(tmp_path, workspace=real, prompt="is --add-dir safe?")
    assert quoted[2] == "is --add-dir safe?" and quoted.count("--add-dir") == 1
    assert_agy_workspace(quoted, real)
    # ... and even an element that IS exactly "--add-dir" at the prompt index is
    # not a workspace (the builder refuses such a prompt anyway: starts with '-')
    spoofed = list(argv)
    spoofed[2] = "--add-dir"
    assert_agy_workspace(spoofed, real)


def test_agy_argv_never_contains_continue_or_edit_flags(tmp_path: Path) -> None:
    """`-c` (continue a conversation) is not a substring token (it would hit
    codex `-c project_doc_max_bytes=0` and git `--cached`), so the agy builder
    is checked element by element: no `-c`, no `--continue`, no accept-edits,
    no `--dangerously-skip-permissions`, with and without a schema."""
    for schema in (None, "{}", '{"type":"object"}'):
        argv = _agy_argv(tmp_path, schema_json=schema)
        for element in argv[1:]:
            assert element != "-c"
            assert element != "--continue" and element != "--conversation"
            assert element not in ("--mode=accept-edits", "accept-edits", "--sandbox=off")
            assert element != "--dangerously-skip-permissions"
        assert argv[argv.index("--mode") + 1] == "plan"
        assert argv.count("--mode") == 1 and argv.count("--print-timeout") == 1
        assert argv.count("--add-dir") == 1
    # and the substring scan does refuse the long forms outside the prompt
    for bad in ("--continue", "--conversation", "accept-edits", "--project", "--agent"):
        with pytest.raises(LaunchRefused, match="forbidden token"):
            _agy_argv(tmp_path, model=f"gemini-{bad}")
    assert "--add-dir" not in FORBIDDEN_ARGV_TOKENS  # required, not forbidden (A14/A16)


@pytest.mark.parametrize(
    ("timeout_s", "expected"),
    [(86_400, 86_370), (600, 570), (61, 31), (60, 30), (31, 15), (30, 15), (5, 2), (3, 1), (2, 1)],
)
def test_agy_print_timeout_derivation(timeout_s: int, expected: int) -> None:
    """timeout_s - 30 above 60 s, else max(1, timeout_s // 2): agy's own timer
    ALWAYS fires before Eris's and still emits an envelope (A7)."""
    assert agy_print_timeout_s(timeout_s) == expected
    assert 1 <= agy_print_timeout_s(timeout_s) < timeout_s


@pytest.mark.parametrize("timeout_s", [1, 2, 30, 31, 60, 61, 86_400])
def test_agy_print_timeout_is_strictly_before_eris_timeout(timeout_s: int) -> None:
    """Boundary values. With whole seconds there is no positive value strictly
    below 1, so a 1 s policy timeout is refused instead of letting the two
    timers coincide."""
    if timeout_s < 2:
        with pytest.raises(LaunchRefused, match="timeout_s >= 2"):
            agy_print_timeout_s(timeout_s)
        return
    assert agy_print_timeout_s(timeout_s) < timeout_s


def test_run_worker_agy_refuses_one_second_timeout(tmp_path: Path) -> None:
    res = run_worker(
        make_call(tmp_path, _agy_policy(tmp_path, timeout_s=1)), popen=FakeProcessFactory()
    )
    assert res.status is WorkerStatus.REFUSED and "timeout_s >= 2" in str(res.error)


def test_grok_argv_exactly_as_specified() -> None:
    assert build_argv_grok("/x/grok", PROMPT, model="grok-4.6", schema_json="{}") == [
        "/x/grok",
        "-p",
        PROMPT,
        "-m",
        "grok-4.6",
        "--permission-mode",
        "plan",
        "--disable-web-search",
        "--output-format",
        "json",
        "--json-schema",
        "{}",
    ]


@pytest.mark.parametrize("token", FORBIDDEN_ARGV_TOKENS)
def test_forbidden_tokens_are_refused_outside_the_prompt(token: str) -> None:
    with pytest.raises(LaunchRefused, match="forbidden token"):
        assert_argv_safe(["/x/claude", "-p", "hi", token])
    with pytest.raises(LaunchRefused):
        assert_argv_safe(["/x/claude", token.upper()])
    with pytest.raises(LaunchRefused):
        build_argv_claude(f"/x/{token}/claude", "hi")
    with pytest.raises(LaunchRefused):
        build_argv_grok("/x/grok", "hi", model=f"m-{token}")
    ws = Path("/")
    with pytest.raises(LaunchRefused):
        build_argv_agy("/x/agy", "hi", model=f"gemini-{token}", workspace=ws, print_timeout_s=30)
    with pytest.raises(LaunchRefused):
        build_argv_agy(
            "/x/agy", "hi", model="gemini-x", workspace=ws, print_timeout_s=30, schema_json=token
        )
    with pytest.raises(LaunchRefused):
        build_argv_agy("/x/agy", "hi", model="gemini-x", workspace=ws / token, print_timeout_s=30)
    # The prompt element is exempt: reviewers legitimately quote these flags.
    argv = build_argv_claude("/x/claude", f"Is using {token} here defensible?")
    assert argv[2] == f"Is using {token} here defensible?"
    codex = build_argv_codex("/x/codex", f"Explain {token}", cwd=Path("/"), model="m")
    assert codex[-1] == f"Explain {token}"
    assert build_argv_grok("/x/grok", f"review {token}", model="m")[2] == f"review {token}"
    agy = build_argv_agy(
        "/x/agy", f"review {token}", model="gemini-x", workspace=ws, print_timeout_s=30
    )
    assert agy[2] == f"review {token}"
    # spawn honours the same exemption, and only for the declared index
    with pytest.raises(LaunchRefused):
        assert_argv_safe(["/x/claude", "-p", token], exempt=(1,))
    assert_argv_safe(["/x/claude", "-p", token], exempt=(2,))


def test_argv_hygiene() -> None:
    with pytest.raises(LaunchRefused, match="empty"):
        assert_argv_safe([])
    with pytest.raises(LaunchRefused, match="NUL"):
        assert_argv_safe(["a\x00b"])
    with pytest.raises(LaunchRefused, match="starts with '-'"):
        build_argv_grok("/x/grok", "--help", model="m")
    with pytest.raises(LaunchRefused, match="starts with '-'"):
        build_argv_agy("/x/agy", " -c", model="gemini-x", workspace=Path("/"), print_timeout_s=30)
    with pytest.raises(LaunchRefused, match="empty prompt"):
        build_argv_codex("/x/codex", "  ", cwd=Path("/"), model="m")
    # The existing builders are unaffected by the agy token additions.
    assert "--no-session-persistence" in build_argv_claude("/x/claude", "ok")
    assert "project_doc_max_bytes=0" in build_argv_codex("/x/codex", "ok", cwd=Path("/"), model="m")
    assert "--permission-mode" in build_argv_claude("/x/claude", "ok")
    assert "bypassPermissions" not in " ".join(build_argv_claude("/x/claude", "ok"))


# --------------------------------------------------------------------------- env


def test_env_is_built_from_empty_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ERIS_CANARY_SHOULD_NOT_LEAK", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "from-os-environ")
    env = build_env("claude", path_env="/usr/bin", home="/h", tmpdir="/t")
    assert "ERIS_CANARY_SHOULD_NOT_LEAK" not in env
    assert "OPENAI_API_KEY" not in env
    assert env["PATH"] == "/usr/bin" and env["HOME"] == "/h" and env["TMPDIR"] == "/t"
    assert env["DISABLE_AUTOUPDATER"] == "1"
    for k, v in GIT_HARDENING.items():
        assert env[k] == v
    assert "CLAUDECODE" not in env and "CLAUDE_CODE_ENTRYPOINT" not in env


@pytest.mark.parametrize(
    "name",
    [
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "GIT_DIR",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "SSH_AUTH_SOCK",
        "AWS_SECRET_ACCESS_KEY",
        "CLAUDECODE",
        "NODE_OPTIONS",
        "GEMINI_CLI_TRUST_WORKSPACE",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_GEMINI_BASE_URL",
        "AGY_ADC_AUTH",
        "ANTIGRAVITY_SOMETHING",
    ],
)
def test_never_list_names_are_refused(name: str) -> None:
    with pytest.raises(LaunchRefused, match="NEVER list"):
        build_env("codex", path_env="/usr/bin", home="/h", tmpdir="/t", policy_env={name: "x"})
    with pytest.raises(LaunchRefused):
        build_env("codex", path_env="/usr/bin", home="/h", tmpdir="/t", secrets={name: "x"})
    with pytest.raises(LaunchRefused):
        build_env("agy", path_env="/usr/bin", home="/h", tmpdir="/t", policy_env={name: "x"})


def test_agy_env_disables_auto_update_and_agy_prefix_is_not_banned() -> None:
    env = build_env("agy", path_env="/usr/bin", home="/h", tmpdir="/t")
    assert env["AGY_CLI_DISABLE_AUTO_UPDATE"] == "1" and PER_CLI_ENV["agy"] == {
        "AGY_CLI_DISABLE_AUTO_UPDATE": "1"
    }
    assert "DISABLE_AUTOUPDATER" not in env  # claude's knob is not sprayed on agy
    # the policy may set the same name (default.yaml does); AGY_ is not a banned prefix
    env = build_env(
        "agy",
        path_env="/usr/bin",
        home="/h",
        tmpdir="/t",
        policy_env={"AGY_CLI_DISABLE_AUTO_UPDATE": "1"},
    )
    assert env["AGY_CLI_DISABLE_AUTO_UPDATE"] == "1"


def test_git_hardening_values_are_the_only_git_vars_allowed() -> None:
    assert_env_safe(dict(GIT_HARDENING))
    with pytest.raises(LaunchRefused):
        assert_env_safe({"GIT_CONFIG_GLOBAL": "/home/me/.gitconfig"})
    with pytest.raises(LaunchRefused, match="bad env name"):
        assert_env_safe({"BAD-NAME": "x"})
    with pytest.raises(LaunchRefused, match="NUL"):
        assert_env_safe({"X": "a\x00"})


# --------------------------------------------------------------------------- spawn


def test_spawn_passes_hardened_popen_kwargs(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(stdout=b"out", stderr=b"err", returncode=0)
    env = build_env("grok", path_env="/usr/bin", home=str(tmp_path), tmpdir=str(tmp_path))
    res = spawn(
        ["/x/grok", "-p", "hi"],
        env=env,
        cwd=tmp_path,
        timeout_s=5,
        max_stdout_bytes=100,
        max_stderr_bytes=100,
        popen=factory,
        killpg=lambda *_: None,
    )
    proc = factory.instances[0]
    kw = proc.popen_kwargs
    assert kw["stdin"] is subprocess.DEVNULL
    assert kw["stdout"] is subprocess.PIPE and kw["stderr"] is subprocess.PIPE
    assert kw["start_new_session"] is True and kw["shell"] is False and kw["close_fds"] is True
    assert kw["cwd"] == str(tmp_path.resolve()) and kw["env"] == env
    assert res.stdout == b"out" and res.stderr == b"err" and res.exit_code == 0
    assert not res.timed_out and not res.stdout_truncated


def test_spawn_caps_stdout_and_stderr(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(stdout=b"a" * 1_000_000, stderr=b"b" * 5000)
    res = spawn(
        ["/x/y"],
        env={},
        cwd=tmp_path,
        timeout_s=5,
        max_stdout_bytes=1000,
        max_stderr_bytes=100,
        popen=factory,
        killpg=lambda *_: None,
    )
    assert len(res.stdout) == 1000 and res.stdout_truncated
    assert len(res.stderr) == 100 and res.stderr_truncated


def test_spawn_refuses_bad_cwd_and_bad_argv(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process()
    with pytest.raises(LaunchRefused, match="not a directory"):
        spawn(
            ["/x/y"],
            env={},
            cwd=tmp_path / "nope",
            timeout_s=1,
            max_stdout_bytes=1,
            max_stderr_bytes=1,
            popen=factory,
        )
    with pytest.raises(LaunchRefused):
        spawn(
            ["/x/y", "--bare"],
            env={},
            cwd=tmp_path,
            timeout_s=1,
            max_stdout_bytes=1,
            max_stderr_bytes=1,
            popen=factory,
        )
    with pytest.raises(LaunchRefused):
        spawn(
            ["/x/y"],
            env={"PYTHONPATH": "x"},
            cwd=tmp_path,
            timeout_s=1,
            max_stdout_bytes=1,
            max_stderr_bytes=1,
            popen=factory,
        )
    assert factory.instances == []  # nothing spawned


def test_timeout_kills_process_group_sigterm_then_reaps(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(hang=True, pid=4242)
    calls: list[tuple[int, int]] = []

    def killpg(pgid: int, sig: int) -> None:
        calls.append((pgid, sig))
        factory.instances[0].send_signal(sig)

    res = spawn(
        ["/x/y"],
        env={},
        cwd=tmp_path,
        timeout_s=0.05,
        max_stdout_bytes=10,
        max_stderr_bytes=10,
        popen=factory,
        killpg=killpg,
        grace_s=0.2,
    )
    # SIGTERM ended the leader, but the group is ALWAYS swept with SIGKILL afterwards
    assert res.timed_out and calls == [(4242, signal.SIGTERM), (4242, signal.SIGKILL)]
    assert res.killed_with == signal.SIGTERM and res.exit_code == -signal.SIGTERM


def test_timeout_escalates_to_sigkill(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(hang=True, pid=77)
    calls: list[int] = []

    def killpg(_pgid: int, sig: int) -> None:
        calls.append(sig)
        if sig == signal.SIGKILL:
            factory.instances[0].send_signal(sig)  # ignores SIGTERM

    res = spawn(
        ["/x/y"],
        env={},
        cwd=tmp_path,
        timeout_s=0.05,
        max_stdout_bytes=10,
        max_stderr_bytes=10,
        popen=factory,
        killpg=killpg,
        grace_s=0.1,
    )
    assert calls == [signal.SIGTERM, signal.SIGKILL] and res.killed_with == signal.SIGKILL


def test_timeout_process_already_gone(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(hang=True)
    calls: list[int] = []

    def killpg(_pgid: int, sig: int) -> None:
        # The group vanished concurrently: the leader exits, killpg reports no such group.
        calls.append(sig)
        factory.instances[0].send_signal(sig)
        raise ProcessLookupError

    res = spawn(
        ["/x/y"],
        env={},
        cwd=tmp_path,
        timeout_s=0.05,
        max_stdout_bytes=10,
        max_stderr_bytes=10,
        popen=factory,
        killpg=killpg,
        grace_s=0.1,
    )
    assert res.timed_out and res.killed_with == signal.SIGTERM
    assert calls == [signal.SIGTERM, signal.SIGKILL]  # ProcessLookupError is tolerated for both


def test_timeout_unkillable_raises(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(hang=True)
    with pytest.raises(LaunchRefused, match="survived SIGKILL"):
        spawn(
            ["/x/y"],
            env={},
            cwd=tmp_path,
            timeout_s=0.05,
            max_stdout_bytes=10,
            max_stderr_bytes=10,
            popen=factory,
            killpg=lambda *_: None,
            grace_s=0.05,
        )


GRANDPARENT = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
print(child.pid, flush=True)
time.sleep(120)
"""


@pytest.mark.real_subprocess
def test_real_process_group_kill_reaches_grandchildren(tmp_path: Path) -> None:
    res = spawn(
        [sys.executable, "-c", GRANDPARENT],
        env={"PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        timeout_s=1.5,
        max_stdout_bytes=1000,
        max_stderr_bytes=1000,
        grace_s=1.0,
    )
    assert res.timed_out
    grandchild = int(res.stdout.decode().strip())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail(f"grandchild {grandchild} survived the process-group kill")


GRANDPARENT_TERM_IGNORING_CHILD = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c",
    "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)"])
print(child.pid, flush=True)
time.sleep(120)
"""


def _wait_gone(pid: int, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


@pytest.mark.real_subprocess
def test_real_group_kill_sweeps_members_that_ignore_sigterm(tmp_path: Path) -> None:
    """Leader dies on SIGTERM; the grandchild ignores SIGTERM. Only an
    unconditional SIGKILL sweep of the group reaches it."""
    res = spawn(
        [sys.executable, "-c", GRANDPARENT_TERM_IGNORING_CHILD],
        env={"PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        timeout_s=1.5,
        max_stdout_bytes=1000,
        max_stderr_bytes=1000,
        grace_s=1.0,
    )
    assert res.timed_out and res.killed_with == signal.SIGTERM  # leader honoured TERM
    grandchild = int(res.stdout.decode().strip())
    assert _wait_gone(grandchild), f"grandchild {grandchild} survived: SIGKILL sweep missing"


@pytest.mark.real_subprocess
def test_real_caps_and_stdin_devnull(tmp_path: Path) -> None:
    script = "import sys; print(sys.stdin.read() == ''); sys.stdout.write('x' * 50000)"
    res = spawn(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        timeout_s=30,
        max_stdout_bytes=2000,
        max_stderr_bytes=100,
    )
    assert res.exit_code == 0 and res.stdout.startswith(b"True") and len(res.stdout) == 2000
    assert res.stdout_truncated


# --------------------------------------------------------------------------- envelopes


def test_parse_claude_control_fixture() -> None:
    env = parse_claude(fixture("claude", "2.1.239", "control.json"))
    assert not env.is_error and env.error is None
    assert env.text == "PINEAPPLE\n\nok"  # CLAUDE.md leaked without --safe-mode
    assert env.model_executed == "claude-opus-5" and env.models_used == ["claude-opus-5"]
    assert env.cost_usd == 0.011819
    assert env.usage is not None
    assert (env.usage.input_tokens, env.usage.output_tokens, env.usage.cached_input_tokens) == (
        2,
        13,
        22968,
    )
    assert env.usage.reasoning_tokens == 0 and env.parse_mode == "json"


def test_parse_claude_safemode_two_models_means_unknown_model() -> None:
    """modelUsage lists a helper model AND the primary: which one 'executed'
    is not observable from the envelope, so it is None (never guessed)."""
    env = parse_claude(fixture("claude", "2.1.239", "safemode.json"))
    assert env.text == "ok"
    assert env.model_executed is None
    assert set(env.models_used) == {"claude-haiku-4-5-20251001", "claude-fable-5"}
    assert env.cost_usd == 0.080129
    single = parse_claude(fixture("claude", "2.1.239", "control.json"))
    assert single.model_executed == "claude-opus-5" and single.models_used == ["claude-opus-5"]


def test_parse_claude_is_error_checked_before_shape() -> None:
    env = parse_claude(fixture("claude", "2.1.239", "bare_not_logged_in.json"))
    assert env.is_error and env.error == "Not logged in · Please run /login"
    assert env.text is None and env.model_executed is None
    # is_error wins even when the rest of the shape is garbage
    env = parse_claude(b'{"is_error": true, "result": "boom"}')
    assert env.is_error and env.error == "boom"
    env = parse_claude(b'{"is_error": true}')
    assert env.is_error and env.error == "is_error"


def test_parse_claude_plan_mode_denied_write() -> None:
    env = parse_claude(fixture("claude", "2.1.239", "plan_write_denied.json"))
    assert env.text == "FAILED" and not env.is_error
    assert env.usage is not None and env.usage.reasoning_tokens == 201


def test_parse_claude_bad_shapes() -> None:
    assert parse_claude(b"not json").is_error
    assert parse_claude(b"[1,2]").is_error
    assert "unexpected envelope shape" in str(parse_claude(b'{"type": "other"}').error)
    env = parse_claude(b'{"type":"result","result":"{\\"a\\":1}","subtype":"weird"}')
    assert env.structured == {"a": 1} and env.error == "claude: subtype='weird'"
    env = parse_claude(
        b'{"type":"result","result":"x","structured_output":{"k":2},"modelUsage":{"m":{}}}'
    )
    assert env.structured == {"k": 2} and env.model_executed == "m"


def test_parse_claude_strips_ansi() -> None:
    raw = b"\x1b[32m" + fixture("claude", "2.1.239", "control.json") + b"\x1b[0m"
    assert parse_claude(raw).text == "PINEAPPLE\n\nok"


def test_parse_codex_readonly_fixture() -> None:
    env = parse_codex(fixture("codex", "0.147.0", "exec_readonly.jsonl"))
    assert not env.is_error and env.parse_mode == "jsonl"
    assert env.text == "MANGO\nFILE: FAILED\nNET: FAILED"  # LAST agent_message
    assert env.model_executed is None  # no model id in the events: unknown, not guessed
    assert env.cost_usd is None
    assert env.usage is not None
    assert (env.usage.input_tokens, env.usage.output_tokens) == (22480, 325)
    assert (env.usage.cached_input_tokens, env.usage.reasoning_tokens) == (11099, 76)


def test_parse_codex_nodoc_fixture_and_errors() -> None:
    env = parse_codex(fixture("codex", "0.147.0", "exec_nodoc.jsonl"))
    assert env.text == "ok" and not env.is_error
    env = parse_codex(b"Reading additional input from stdin...\n")
    assert env.is_error and "no JSONL events" in str(env.error)
    env = parse_codex(b'{"type":"turn.started"}\n{broken\n')
    assert env.is_error and "no turn.completed" in str(env.error)
    env = parse_codex(b'{"type":"error","message":"quota"}\n{"type":"turn.completed","usage":{}}\n')
    assert env.is_error and env.error == "codex: quota"
    env = parse_codex(
        b'{"type":"item.completed","item":{"type":"agent_message","text":"{\\"x\\":1}"}}\n{"type":"turn.completed","usage":{"input_tokens":1}}\n'
    )
    assert env.structured == {"x": 1} and env.usage is not None and env.usage.output_tokens is None


def test_parse_grok_plan_fixture() -> None:
    env = parse_grok(fixture("grok", "1.0.5", "plan.json"))
    assert env.text is not None and env.text.startswith("I'll create `GROK_WROTE`")
    assert env.model_executed == "grok-4.6" and env.models_used == ["grok-4.6"]
    assert env.cost_usd == 0.031262
    assert env.usage is not None
    assert (
        env.usage.input_tokens,
        env.usage.output_tokens,
        env.usage.cached_input_tokens,
        env.usage.reasoning_tokens,
    ) == (13638, 643, 256, 485)
    assert not env.is_error and env.error == "grok: stopReason='cancelled'"


def test_parse_grok_bad_shapes() -> None:
    assert parse_grok(b"nope").is_error
    assert parse_grok(b"{}").error == "grok: envelope has no text"
    assert parse_grok(b'{"text":"x","stopReason":"error"}').is_error
    assert parse_grok(b'{"text":"x","stopReason":"stop"}').error is None


def test_parse_grok_schema_fixture_prefers_structured_output() -> None:
    """E9: with --json-schema the object lives under camelCase `structuredOutput`
    and `text` holds the JSON string; the object is preferred."""
    env = parse_grok(fixture("grok", "1.0.5", "schema.json"))
    assert not env.is_error and env.error is None
    assert env.structured == {"answer": "ok", "n": 7} and env.text == '{"answer":"ok","n":7}'
    assert env.model_executed == "grok-4.6" and env.cost_usd == 0.034884
    # structuredOutput wins over a text that parses differently; absent -> text is parsed
    env = parse_grok(b'{"text":"{\\"a\\":1}","stopReason":"end_turn","structuredOutput":{"b":2}}')
    assert env.structured == {"b": 2}
    env = parse_grok(b'{"text":"{\\"a\\":1}","stopReason":"end_turn"}')
    assert env.structured == {"a": 1}


def test_parse_claude_schema_and_notools_fixtures() -> None:
    env = parse_claude(fixture("claude", "2.1.239", "schema.json"))
    assert not env.is_error and env.structured == {"answer": "ok", "n": 7}
    assert env.text == '{"answer":"ok","n":7}' and env.model_executed is None  # two models
    env = parse_claude(fixture("claude", "2.1.239", "notools_text.json"))
    assert env.text == "ok" and not env.is_error and env.cost_usd == 0.041041


# --------------------------------------------------------------------------- agy envelopes


def test_parse_agy_plain_fixture() -> None:
    """A1: SUCCESS; no model id and no cost anywhere in the envelope."""
    env = parse_agy(fixture("agy", "1.1.18", "plain.json"))
    assert not env.is_error and env.error is None and env.parse_mode == "json"
    assert env.text == "ok\n" and env.structured is None
    assert env.model_executed is None and env.models_used == [] and env.cost_usd is None
    assert env.usage is not None
    assert (
        env.usage.input_tokens,
        env.usage.output_tokens,
        env.usage.cached_input_tokens,
        env.usage.reasoning_tokens,
    ) == (13674, 27, 0, 26)
    assert env.conversation_id == "ed889929-a04c-457f-91d1-194be848aa04"
    assert env.worker_reported_duration_ms == 2646  # duration_seconds 2.64583
    assert isinstance(env.raw, dict) and env.raw["usage"]["total_tokens"] == 13701  # kept in raw


def test_parse_agy_schema_fixture_structured_output_is_exact() -> None:
    """A3: structured_output is EXACTLY the schema object; the toolAction /
    toolSummary extras live only inside the prose response."""
    env = parse_agy(fixture("agy", "1.1.18", "schema.json"))
    assert not env.is_error
    assert env.structured == {"answer": "ok", "n": 7}
    assert env.text is not None and "toolAction" in env.text and "/Users/USER/" in env.text
    assert env.usage is not None and env.usage.cached_input_tokens == 16274
    assert env.worker_reported_duration_ms == 18263


@pytest.mark.parametrize(
    ("name", "error_fragment", "input_tokens"),
    [
        ("shell_denied.json", 'permission check failed for command "pwd"', 45924),
        ("read_denied.json", "permission check failed for read_file", 6765),
        ("print_timeout.json", "timeout waiting for response", 0),
        ("auth_failed.json", "authentication failed or timed out", 0),
    ],
)
def test_parse_agy_error_fixtures_retain_usage(
    name: str, error_fragment: str, input_tokens: int
) -> None:
    """status ERROR -> is_error with the worker's message; usage is still
    recorded (a denied tool call consumed 45k input tokens in A5)."""
    env = parse_agy(fixture("agy", "1.1.18", name))
    assert env.is_error and env.error is not None and env.error.startswith("agy: ")
    assert error_fragment in env.error
    assert env.text is None and env.structured is None  # response "" -> None
    assert env.usage is not None and env.usage.input_tokens == input_tokens
    assert env.model_executed is None and env.cost_usd is None


def test_parse_agy_auth_failed_has_no_conversation() -> None:
    env = parse_agy(fixture("agy", "1.1.18", "auth_failed.json"))
    assert env.conversation_id is None  # "" -> None
    assert env.worker_reported_duration_ms == 0
    env = parse_agy(fixture("agy", "1.1.18", "print_timeout.json"))
    assert env.conversation_id == "913ea46c-5260-448e-9354-ed32e0dab003"
    assert env.worker_reported_duration_ms == 1627


def test_parse_agy_bad_shapes() -> None:
    assert parse_agy(b"not json").is_error and "not JSON" in str(parse_agy(b"not json").error)
    assert parse_agy(b"[1]").error == "agy: stdout JSON is not an object"
    assert parse_agy(b"").is_error
    env = parse_agy(b"{}")
    assert env.is_error and env.error == "agy: status missing" and env.usage is not None
    env = parse_agy(b'{"status":"WEIRD","response":"partial"}')
    assert env.is_error and env.error == "agy: status='WEIRD'" and env.text == "partial"
    env = parse_agy(b'{"status":"ERROR","error":""}')
    assert env.error == "agy: status='ERROR'"  # empty error string falls back to the status
    env = parse_agy(b'{"status":"ERROR","error":{"code":1}}')
    assert env.error == "agy: status='ERROR'"  # non-string error is not interpolated
    env = parse_agy(b'{"status":"SUCCESS","response":"{\\"a\\":1}"}')
    assert env.structured == {"a": 1} and env.text == '{"a":1}'
    env = parse_agy(b'{"status":"SUCCESS","response":"ok","usage":{"input_tokens":true}}')
    assert env.usage is not None and env.usage.input_tokens is None  # bool is not a count
    env = parse_agy(b'{"status":"SUCCESS","response":"ok","duration_seconds":"3"}')
    assert env.worker_reported_duration_ms is None and env.conversation_id is None
    env = parse_agy(b'{"status":"SUCCESS","response":"ok","duration_seconds":-1}')
    assert env.worker_reported_duration_ms is None
    env = parse_agy(b'{"status":"SUCCESS","response":"","conversation_id":7}')
    assert env.text is None and env.conversation_id is None and not env.is_error


def test_parse_agy_structured_output_any_shape_and_extra_keys() -> None:
    """Synthetic: the envelope is recorded as-is - extra keys inside
    structured_output are kept (the schema is not strictly enforced by agy),
    and a non-object structured_output is still recorded."""
    raw = json.loads(fixture("agy", "1.1.18", "schema.json"))
    raw["structured_output"] = {"answer": "ok", "n": 7, "toolAction": "x", "toolSummary": "y"}
    env = parse_agy(json.dumps(raw).encode())
    assert env.structured == {"answer": "ok", "n": 7, "toolAction": "x", "toolSummary": "y"}
    raw["structured_output"] = [1, 2]
    assert parse_agy(json.dumps(raw).encode()).structured == [1, 2]
    raw["structured_output"] = None  # explicit null -> fall back to the response text
    raw["response"] = '{"from":"text"}'
    assert parse_agy(json.dumps(raw).encode()).structured == {"from": "text"}
    raw["unexpected_top_level"] = {"kept": True}
    env = parse_agy(json.dumps(raw).encode())
    assert env.raw["unexpected_top_level"] == {"kept": True}


def test_parse_agy_strips_ansi() -> None:
    raw = b"\x1b[32m" + fixture("agy", "1.1.18", "plain.json") + b"\x1b[0m"
    assert parse_agy(raw).text == "ok\n"


def test_parsers_table_matches_cli_names() -> None:
    assert set(PARSERS) == {"claude", "codex", "agy", "grok"}


# --------------------------------------------------------------------------- worker calls


def make_policy(tmp_path: Path, cli: str = "grok", **kw: Any) -> WorkerPolicy:
    exe = tmp_path / "bin" / cli
    exe.parent.mkdir(exist_ok=True)
    exe.write_bytes(b"#!/bin/sh\n")
    base: dict[str, Any] = {
        "transport": Transport.CLI,
        "cli": cli,
        "provider": "xai",
        "model": "grok-4.6",
        "executable": str(exe),
        "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "timeout_s": 5,
        "max_stdout_bytes": 100_000,
        "max_stderr_bytes": 10_000,
    }
    base.update(kw)
    return WorkerPolicy(**base)


def make_call(tmp_path: Path, policy: WorkerPolicy, **kw: Any) -> WorkerCall:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir(exist_ok=True)
    base: dict[str, Any] = {
        "worker_id": "w",
        "policy": policy,
        "prompt": PROMPT,
        "cwd": snapshot,
        "task_id": "t_01",
        "stage": Stage.PROPOSE,
        "repeat_index": 0,
        "policy_sha256": "0" * 64,
        "home": str(tmp_path / "home"),
        "tmpdir": str(tmp_path / "tmp"),
        "path_env": "/usr/bin:/bin",
    }
    base.update(kw)
    return WorkerCall(**base)


def test_idempotency_key_excludes_arm_includes_repeat(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    call = make_call(tmp_path, policy)
    assert idempotency_key(call) == idempotency_key(make_call(tmp_path, policy))
    assert idempotency_key(call) != idempotency_key(make_call(tmp_path, policy, repeat_index=1))
    assert idempotency_key(call) != idempotency_key(make_call(tmp_path, policy, prompt="other"))
    assert idempotency_key(call) != idempotency_key(
        make_call(tmp_path, policy, schema={"type": "object"})
    )
    assert idempotency_key(call) != idempotency_key(
        make_call(tmp_path, policy, stage=Stage.CRITIQUE)
    )
    assert "arm" not in WorkerCall.__dataclass_fields__
    # a re-snapshotted task (different base commit) never collides
    assert idempotency_key(call) != idempotency_key(
        make_call(tmp_path, policy, snapshot_sha="a" * 40)
    )
    assert idempotency_key(make_call(tmp_path, policy, snapshot_sha="a" * 40)) != idempotency_key(
        make_call(tmp_path, policy, snapshot_sha="b" * 40)
    )
    # M2b: the pinned executable is key material (a cache entry from another binary never hits)
    repinned = make_policy(tmp_path, executable_sha256="e" * 64)
    assert idempotency_key(call) != idempotency_key(make_call(tmp_path, repinned))
    from eris.launch import idempotency_material

    material = idempotency_material(call)
    assert material["executable_sha256"] == policy.executable_sha256
    assert "attempt" not in material and "arm" not in material


def test_plan_call_builds_argv_env_cwd_without_spawning(tmp_path: Path) -> None:
    policy = make_policy(tmp_path, env_allow=["XAI_API_KEY"])
    call = make_call(tmp_path, policy, secrets={"XAI_API_KEY": "xai-secret", "OTHER": "no"})
    plan = plan_call(call)
    assert plan.argv[0] == policy.executable and plan.argv[1:3] == ["-p", PROMPT]
    assert plan.env["XAI_API_KEY"] == "xai-secret" and "OTHER" not in plan.env
    assert plan.cwd == (tmp_path / "snapshot").resolve()
    assert plan.idempotency_key == idempotency_key(call)
    with pytest.raises(LaunchRefused, match="env_allow names not provided"):
        plan_call(make_call(tmp_path, policy))


def test_plan_call_per_cli(tmp_path: Path) -> None:
    claude = make_policy(
        tmp_path, "claude", provider="anthropic", model=None, tools=["Read"], max_budget_usd=1
    )
    assert "--safe-mode" in plan_call(make_call(tmp_path, claude)).argv
    codex = make_policy(tmp_path, "codex", provider="openai", model="gpt-5.4")
    plan = plan_call(
        make_call(tmp_path, codex, schema={"type": "object"}, scratch_dir=tmp_path / "s")
    )
    assert plan.schema_path is not None and plan.schema_path.name == "schema.json"
    assert plan.schema_path.parent.parent == tmp_path / "s"  # per-call scratch subdir
    assert plan.schema_path.parent.name.startswith("call-") and "--output-schema" in plan.argv
    with pytest.raises(LaunchRefused, match="scratch_dir"):
        plan_call(make_call(tmp_path, codex, schema={"type": "object"}))
    with pytest.raises(LaunchRefused, match="requires a model"):
        plan_call(
            make_call(tmp_path, make_policy(tmp_path, "codex", provider="openai", model=None))
        )
    agy = make_policy(tmp_path, "agy", provider="google", model="gemini-3.1-pro-high")
    plan = plan_call(make_call(tmp_path, agy))
    argv = plan.argv
    assert argv[1:3] == ["-p", PROMPT] and "--mode" in argv and "--sandbox" in argv
    assert "--json-schema" not in argv
    # --add-dir is exactly the cwd that spawn receives
    assert argv.count("--add-dir") == 1
    assert (
        argv[argv.index("--add-dir") + 1] == str(plan.cwd) == str((tmp_path / "snapshot").resolve())
    )
    assert_agy_workspace(argv, plan.cwd)
    with_schema = plan_call(make_call(tmp_path, agy, schema={"b": 1, "a": 2})).argv
    assert with_schema[-2:] == ["--json-schema", '{"a": 2, "b": 1}']  # inline, sorted keys
    # the policy's lineage guard makes model=None unconstructible; the launcher
    # still refuses it when reached through an unvalidated copy
    unvalidated = agy.model_copy(update={"model": None})
    with pytest.raises(LaunchRefused, match="agy requires a model"):
        plan_call(make_call(tmp_path, unvalidated))
    with pytest.raises(LaunchRefused, match="requires a model"):
        plan_call(make_call(tmp_path, make_policy(tmp_path, model=None)))


def test_plan_call_agy_print_timeout_tracks_policy_timeout(tmp_path: Path) -> None:
    """--print-timeout = timeout_s - 30 above 60 s else max(1, timeout_s // 2),
    rendered as '<N>s'."""
    for timeout_s, expected in ((600, "570s"), (5, "2s"), (60, "30s"), (100, "70s"), (2, "1s")):
        agy = make_policy(
            tmp_path, "agy", provider="google", model="gemini-3.1-pro-high", timeout_s=timeout_s
        )
        argv = plan_call(make_call(tmp_path, agy)).argv
        assert argv[argv.index("--print-timeout") + 1] == expected
        assert argv.index("--print-timeout") > argv.index("--disable-slash-commands")
    api = WorkerPolicy(
        transport=Transport.API,
        provider="openai",
        base_url="https://api.openai.com/v1",
        api_key_env="K",
        executable_sha256=UNPINNED,
        timeout_s=1,
        max_stdout_bytes=1,
    )
    with pytest.raises(LaunchRefused, match="not a cli worker"):
        plan_call(make_call(tmp_path, api))
    with pytest.raises(LaunchRefused, match="no executable path"):
        plan_call(make_call(tmp_path, make_policy(tmp_path, executable=None)))


def test_preflight_executable(tmp_path: Path) -> None:
    policy = make_policy(tmp_path)
    digest, real = preflight_executable(policy)
    assert digest == policy.executable_sha256 and real == Path(str(policy.executable)).resolve()
    with pytest.raises(LaunchRefused, match="UNPINNED"):
        preflight_executable(make_policy(tmp_path, executable_sha256=UNPINNED))
    with pytest.raises(LaunchRefused, match="sha256"):
        preflight_executable(make_policy(tmp_path, executable_sha256="f" * 64))
    with pytest.raises(FileNotFoundError):
        preflight_executable(make_policy(tmp_path, executable=str(tmp_path / "missing")))
    with pytest.raises(LaunchRefused, match="unpinned"):
        preflight_executable(make_policy(tmp_path, executable=None))


def test_preflight_hashes_and_executes_the_realpath(tmp_path: Path) -> None:
    pinned = make_policy(tmp_path)  # pin computed over bin/grok
    other = tmp_path / "bin" / "other"
    other.write_bytes(b"#!/bin/sh\necho other\n")
    link = tmp_path / "bin" / "grok-link"
    link.symlink_to(other)
    # symlink whose target differs from the pinned file -> refused
    with pytest.raises(LaunchRefused, match="sha256"):
        preflight_executable(make_policy(tmp_path, executable=str(link)))
    # symlink to the pinned file -> accepted, and argv[0] becomes the realpath
    good = tmp_path / "bin" / "good-link"
    good.symlink_to(Path(str(pinned.executable)))
    via_link = make_policy(tmp_path, executable=str(good))
    digest, real = preflight_executable(via_link)
    assert digest == pinned.executable_sha256 and real == Path(str(pinned.executable)).resolve()
    res = run_worker(
        make_call(tmp_path, via_link),
        popen=FakeProcessFactory(stdout=grok_ok()),
        killpg=lambda *_: None,
    )
    assert res.status is WorkerStatus.OK
    assert res.argv[0] == str(real) and res.argv[0] != str(good)
    # symlink retargeted AFTER pinning -> refused (the hash is of the realpath)
    good.unlink()
    good.symlink_to(other)
    with pytest.raises(LaunchRefused, match="sha256"):
        preflight_executable(via_link)
    assert run_worker(make_call(tmp_path, via_link), popen=FakeProcessFactory()).status is (
        WorkerStatus.REFUSED
    )
    dangling = tmp_path / "bin" / "dangling"
    dangling.symlink_to(tmp_path / "nowhere")
    with pytest.raises(FileNotFoundError):
        preflight_executable(make_policy(tmp_path, executable=str(dangling)))


def grok_ok(text: str = "hello") -> bytes:
    return json.dumps(
        {
            "text": text,
            "stopReason": "stop",
            "total_cost_usd": 0.01,
            "usage": {"input_tokens": 1, "output_tokens": 2},
            "modelUsage": {"grok-4.6": {"costUSD": 0.01}},
        }
    ).encode()


def test_run_worker_happy_path(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(stdout=grok_ok('{"verdict": "ok"}'), stderr=b"warn\n")
    policy = make_policy(tmp_path)
    res = run_worker(make_call(tmp_path, policy), popen=factory, killpg=lambda *_: None)
    assert res.status is WorkerStatus.OK and res.error is None
    assert res.text == '{"verdict": "ok"}' and res.structured == {"verdict": "ok"}
    assert res.model_executed == "grok-4.6" and res.model_requested == "grok-4.6"
    assert res.cost_usd == 0.01 and res.exit_code == 0 and res.stderr == b"warn\n"
    assert res.executable_sha256 == policy.executable_sha256
    assert res.env_names == sorted(plan_call(make_call(tmp_path, policy)).env)
    assert "XAI_API_KEY" not in res.env_names
    assert factory.instances[0].popen_kwargs["cwd"] == str((tmp_path / "snapshot").resolve())


def test_run_worker_absences_are_statuses_not_exceptions(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    factory = fake_process(stdout=grok_ok())
    missing = make_policy(tmp_path, executable=str(tmp_path / "gone"))
    res = run_worker(make_call(tmp_path, missing), popen=factory)
    assert res.status is WorkerStatus.MISSING and factory.instances == []
    assert res.idempotency_key == idempotency_key(make_call(tmp_path, missing))

    res = run_worker(
        make_call(tmp_path, make_policy(tmp_path, executable_sha256=UNPINNED)), popen=factory
    )
    assert res.status is WorkerStatus.REFUSED and "UNPINNED" in str(res.error)

    res = run_worker(
        make_call(tmp_path, make_policy(tmp_path, executable_sha256="e" * 64)), popen=factory
    )
    assert res.status is WorkerStatus.REFUSED and "sha256" in str(res.error)

    res = run_worker(
        make_call(tmp_path, make_policy(tmp_path, env={"PYTHONPATH": "x"})), popen=factory
    )
    assert res.status is WorkerStatus.REFUSED and "NEVER list" in str(res.error)
    assert factory.instances == []

    res = run_worker(make_call(tmp_path, make_policy(tmp_path), prompt="--bare"), popen=factory)
    assert res.status is WorkerStatus.REFUSED


def test_run_worker_failures(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    policy = make_policy(tmp_path)
    res = run_worker(
        make_call(tmp_path, policy), popen=fake_process(stdout=grok_ok(), returncode=3)
    )
    assert res.status is WorkerStatus.FAILED and res.error == "exit code 3"
    res = run_worker(make_call(tmp_path, policy), popen=fake_process(stdout=b"garbage"))
    assert res.status is WorkerStatus.FAILED and "not JSON" in str(res.error)

    def boom(*_a: Any, **_k: Any) -> FakeProcess:
        raise PermissionError("denied")

    res = run_worker(make_call(tmp_path, policy), popen=boom)
    assert res.status is WorkerStatus.FAILED and "spawn failed" in str(res.error)

    factory = fake_process(hang=True)

    def killpg(_pgid: int, sig: int) -> None:
        factory.instances[0].send_signal(sig)

    fast = make_policy(tmp_path, timeout_s=1)
    res = run_worker(make_call(tmp_path, fast), popen=factory, killpg=killpg, clock=time.monotonic)
    assert res.status is WorkerStatus.TIMEOUT and res.timed_out and "signal 15" in str(res.error)

    unkillable = fake_process(hang=True)
    res = run_worker(make_call(tmp_path, fast), popen=unkillable, killpg=lambda *_: None)
    assert res.status is WorkerStatus.REFUSED and "survived" in str(res.error)


def _agy_policy(tmp_path: Path, **kw: Any) -> WorkerPolicy:
    return make_policy(tmp_path, "agy", provider="google", model="gemini-3.1-pro-high", **kw)


def test_run_worker_agy_success_threads_conversation_and_duration(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    t = iter([100.0, 100.5, 100.5, 100.5])
    factory = fake_process(stdout=fixture("agy", "1.1.18", "plain.json"))
    res = run_worker(
        make_call(tmp_path, _agy_policy(tmp_path)),
        popen=factory,
        killpg=lambda *_: None,
        clock=lambda: next(t),
    )
    assert res.status is WorkerStatus.OK and res.error is None and res.text == "ok\n"
    assert res.model_executed is None and res.model_requested == "gemini-3.1-pro-high"
    assert res.cost_usd is None and res.parse_mode == "json"
    assert res.conversation_id == "ed889929-a04c-457f-91d1-194be848aa04"
    # the worker's own figure is recorded separately; duration_ms stays clock-derived
    assert res.worker_reported_duration_ms == 2646 and res.duration_ms == 500
    env = factory.instances[0].popen_kwargs["env"]
    assert env["AGY_CLI_DISABLE_AUTO_UPDATE"] == "1" and env["HOME"] == str(tmp_path / "home")
    assert "--sandbox" in res.argv and "-c" not in res.argv
    # the workspace handed to agy is the very cwd the process was spawned in
    assert res.argv[res.argv.index("--add-dir") + 1] == factory.instances[0].popen_kwargs["cwd"]
    assert res.argv.count("--add-dir") == 1 and res.cwd == str((tmp_path / "snapshot").resolve())


def test_plan_call_agy_refuses_a_tampered_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the builder ever emitted a second or a different --add-dir, plan_call
    refuses before anything can spawn (and run_worker records REFUSED)."""
    import eris.launch as launch

    real_build = launch.build_argv_agy

    def extra_dir(*a: Any, **kw: Any) -> list[str]:
        return real_build(*a, **kw) + ["--add-dir", str(tmp_path)]

    monkeypatch.setattr(launch, "build_argv_agy", extra_dir)
    with pytest.raises(LaunchRefused, match="exactly one --add-dir"):
        plan_call(make_call(tmp_path, _agy_policy(tmp_path)))
    res = run_worker(make_call(tmp_path, _agy_policy(tmp_path)), popen=FakeProcessFactory())
    assert res.status is WorkerStatus.REFUSED and "exactly one --add-dir" in str(res.error)

    def elsewhere(*a: Any, **kw: Any) -> list[str]:
        kw["workspace"] = tmp_path / "elsewhere"
        return real_build(*a, **kw)

    monkeypatch.setattr(launch, "build_argv_agy", elsewhere)
    with pytest.raises(LaunchRefused, match="must equal the spawn cwd"):
        plan_call(make_call(tmp_path, _agy_policy(tmp_path)))


def test_parse_agy_add_dir_battery_fixtures() -> None:
    """A14: no workspace -> even README.md inside the cwd is denied. A15: with
    --add-dir the read succeeds AND the workspace rules are injected (MANGO
    KIWI). A16: with --add-dir, an absolute path outside is denied."""
    env = parse_agy(fixture("agy", "1.1.18", "read_denied_inside_no_workspace.json"))
    assert env.is_error and "read_file" in str(env.error) and "/snap/README.md" in str(env.error)
    assert env.usage is not None and env.usage.input_tokens == 6670
    env = parse_agy(fixture("agy", "1.1.18", "read_ok_with_add_dir.json"))
    assert not env.is_error and env.text == "MANGO KIWI\nhello\n"  # injection is in the record
    assert env.conversation_id == "1c8f8ae9-9ead-44af-bf4f-54bc4ec62f90"
    env = parse_agy(fixture("agy", "1.1.18", "read_denied_outside_with_add_dir.json"))
    assert env.is_error and "/OUTSIDE/CANARY.txt" in str(env.error) and env.text is None
    assert "CANARY-" not in json.dumps(env.raw)  # nothing leaked


def test_run_worker_agy_status_error_is_failed_even_with_exit_code_zero(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """A5/A10b shape with rc 0 (synthetic): the envelope's status wins."""
    for name in ("shell_denied.json", "read_denied.json", "auth_failed.json"):
        res = run_worker(
            make_call(tmp_path, _agy_policy(tmp_path)),
            popen=fake_process(stdout=fixture("agy", "1.1.18", name), returncode=0),
            killpg=lambda *_: None,
        )
        assert res.status is WorkerStatus.FAILED, name
        assert res.error is not None and res.error.startswith("agy: ")
        assert res.exit_code == 0 and res.text is None and res.usage is not None
    # and with the real rc 1 the message is the worker's, not "exit code 1"
    res = run_worker(
        make_call(tmp_path, _agy_policy(tmp_path)),
        popen=fake_process(stdout=fixture("agy", "1.1.18", "shell_denied.json"), returncode=1),
        killpg=lambda *_: None,
    )
    assert res.status is WorkerStatus.FAILED and 'command "pwd"' in str(res.error)
    assert res.conversation_id == "67cbd893-cd84-463d-8067-3f898454ebec"


def test_run_worker_agy_print_timeout_envelope_is_failed_with_zero_usage(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """A7: agy's own --print-timeout fired first: a parseable ERROR envelope,
    FAILED (not TIMEOUT - Eris's timer did not fire), usage zeros retained."""
    res = run_worker(
        make_call(tmp_path, _agy_policy(tmp_path)),
        popen=fake_process(stdout=fixture("agy", "1.1.18", "print_timeout.json"), returncode=1),
        killpg=lambda *_: None,
    )
    assert res.status is WorkerStatus.FAILED and not res.timed_out
    assert res.error == "agy: timeout waiting for response"
    assert res.usage is not None and res.usage.input_tokens == 0 and res.usage.output_tokens == 0
    assert res.worker_reported_duration_ms == 1627


def test_run_worker_agy_eris_timeout_has_no_usage(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """Backstop: agy hangs past Eris's timeout_s -> group kill, TIMEOUT, usage
    None, no conversation id (nothing parseable was emitted)."""
    factory = fake_process(hang=True)

    def killpg(_pgid: int, sig: int) -> None:
        factory.instances[0].send_signal(sig)

    res = run_worker(
        make_call(tmp_path, _agy_policy(tmp_path, timeout_s=2)), popen=factory, killpg=killpg
    )
    assert res.status is WorkerStatus.TIMEOUT and res.timed_out
    assert res.usage is None and res.conversation_id is None
    assert res.worker_reported_duration_ms is None and "timed out after 2s" in str(res.error)
    assert res.argv[res.argv.index("--print-timeout") + 1] == "1s"  # agy's timer was set first


@pytest.mark.parametrize(
    "raw_seconds",
    [
        "Infinity",
        "-Infinity",
        "NaN",
        "1e309",
        "-1",
        "-0.5",
        '"3"',
        "true",
        "null",
        "[3]",
        "10000001",
        "1" + "0" * 400,
    ],
)
def test_parse_agy_duration_is_contained(raw_seconds: str) -> None:
    """Only a finite number in [0, 1e7] s becomes worker_reported_duration_ms;
    Infinity/NaN/1e309/huge ints/negatives/strings record None and never raise
    (int(round(inf)) would have raised OverflowError)."""
    stdout = (
        '{"status":"SUCCESS","response":"ok","duration_seconds":' + raw_seconds + "}"
    ).encode()
    env = parse_agy(stdout)
    assert env.worker_reported_duration_ms is None and not env.is_error and env.text == "ok"
    assert (
        parse_agy(
            b'{"status":"SUCCESS","response":"ok","duration_seconds":10000000}'
        ).worker_reported_duration_ms
        == 10_000_000_000
    )
    assert (
        parse_agy(
            b'{"status":"SUCCESS","response":"ok","duration_seconds":0.0004}'
        ).worker_reported_duration_ms
        == 0
    )


def test_run_worker_never_raises_on_a_parser_bug(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parser exception is contained in _execute: FAILED with a 'parser
    failure' message, parse_mode none, raw stdout retained (capped)."""
    import eris.launch as launch

    def broken(_stdout: bytes) -> Any:
        raise RuntimeError("boom " + "x" * 500)

    monkeypatch.setitem(launch.PARSERS, "agy", broken)
    res = run_worker(
        make_call(tmp_path, _agy_policy(tmp_path)),
        popen=fake_process(stdout=fixture("agy", "1.1.18", "plain.json"), returncode=0),
        killpg=lambda *_: None,
    )
    assert res.status is WorkerStatus.FAILED and res.parse_mode == "none"
    assert res.error is not None and res.error.startswith("agy: parser failure: boom ")
    assert len(res.error) <= len("agy: parser failure: ") + 120
    assert res.text is None and res.usage is None and res.stdout.startswith(b"{")
    # the same containment holds for every CLI's parser
    monkeypatch.setitem(launch.PARSERS, "grok", broken)
    res = run_worker(
        make_call(tmp_path, make_policy(tmp_path)), popen=fake_process(stdout=grok_ok())
    )
    assert res.status is WorkerStatus.FAILED and "grok: parser failure" in str(res.error)


def test_run_worker_codex_output_file_never_stays_on_disk(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    codex = make_policy(tmp_path, "codex", provider="openai", model="gpt-5.4")
    stdout = fixture("codex", "0.147.0", "exec_nodoc.jsonl")
    factory = fake_process(stdout=stdout)
    secret = "sk-proj-" + "Lz8" * 16
    seen: dict[str, str] = {}

    def popen(args: list[str], **kw: Any) -> FakeProcess:
        # The real codex writes `-o` (unredacted) and reads `--output-schema`.
        out_path = Path(args[args.index("-o") + 1])
        schema_path = Path(args[args.index("--output-schema") + 1])
        seen["schema"] = schema_path.read_text()
        out_path.write_text(json.dumps({"verdict": "ok", "leak": secret}))
        seen["out"] = str(out_path)
        return factory(args, **kw)

    scratch = tmp_path / "s"
    res = run_worker(
        make_call(tmp_path, codex, schema={"type": "object"}, scratch_dir=scratch), popen=popen
    )
    assert res.status is WorkerStatus.OK and res.text == "ok" and res.model_executed is None
    assert json.loads(seen["schema"]) == {"type": "object"}
    assert "-c" in res.argv and "project_doc_max_bytes=0" in res.argv
    # the -o content came back IN MEMORY and is the structured output ...
    assert res.output_file is not None and secret.encode() in res.output_file
    assert res.structured == {"verdict": "ok", "leak": secret}
    # ... and NO raw output file or schema remains anywhere under scratch
    assert not Path(seen["out"]).exists()
    assert [p for p in scratch.rglob("*") if p.is_file()] == []
    assert not (scratch / Path(seen["out"]).parent.name).exists()


def _codex_call(tmp_path: Path, scratch: Path, **kw: Any) -> WorkerCall:
    codex = make_policy(tmp_path, "codex", provider="openai", model="gpt-5.4")
    return make_call(tmp_path, codex, schema={"type": "object"}, scratch_dir=scratch, **kw)


def _call_dir(call: WorkerCall) -> Path:
    assert call.scratch_dir is not None
    return Path(call.scratch_dir) / f"call-{idempotency_key(call)[:16]}"


def test_run_worker_codex_cleanup_failure_is_surfaced(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_rmtree(path: Any, *a: Any, **k: Any) -> None:
        raise OSError(f"EBUSY {path}")

    monkeypatch.setattr("eris.launch.shutil.rmtree", broken_rmtree)
    call = _codex_call(tmp_path, tmp_path / "s")
    res = run_worker(
        call, popen=fake_process(stdout=fixture("codex", "0.147.0", "exec_nodoc.jsonl"))
    )
    assert res.status is WorkerStatus.OK  # the worker itself succeeded ...
    assert res.cleanup_error is not None and "EBUSY" in res.cleanup_error  # ... but never silently
    assert _call_dir(call).exists()  # the leftover is real, and reported


def test_run_worker_refuses_preexisting_symlink_scratch(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    scratch = tmp_path / "s"
    call = _codex_call(tmp_path, scratch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    scratch.mkdir()
    _call_dir(call).symlink_to(elsewhere)  # planted link at the exact per-call path
    factory = fake_process(stdout=b"{}")
    res = run_worker(call, popen=factory)
    assert res.status is WorkerStatus.REFUSED and "symlink" in str(res.error)
    assert factory.instances == [] and list(elsewhere.iterdir()) == []
    assert _call_dir(call).is_symlink()  # not ours: left untouched
    # a pre-existing plain directory is refused too (exist_ok=False)
    _call_dir(call).unlink()
    _call_dir(call).mkdir()
    res = run_worker(call, popen=factory)
    assert res.status is WorkerStatus.REFUSED and "already exists" in str(res.error)
    # and a symlinked scratch parent
    link_parent = tmp_path / "link-parent"
    link_parent.symlink_to(elsewhere)
    res = run_worker(_codex_call(tmp_path, link_parent), popen=factory)
    assert res.status is WorkerStatus.REFUSED and "symlink" in str(res.error)
    assert factory.instances == []


def test_run_worker_refuses_symlinked_output_file(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    scratch = tmp_path / "s"
    call = _codex_call(tmp_path, scratch)
    target = tmp_path / "victim.json"
    target.write_text('{"stolen": "sk-proj-' + "Vv5" * 16 + '"}')
    factory = fake_process(stdout=fixture("codex", "0.147.0", "exec_nodoc.jsonl"))

    def popen(args: list[str], **kw: Any) -> FakeProcess:
        out_path = Path(args[args.index("-o") + 1])
        out_path.symlink_to(target)  # the worker replaced its output with a link
        return factory(args, **kw)

    res = run_worker(call, popen=popen)
    assert res.status is WorkerStatus.REFUSED and "not a regular file" in str(res.error)
    assert res.output_file is None and res.structured is None
    assert target.exists()  # the link target is untouched and was never read
    assert not _call_dir(call).exists()  # our scratch (with the link) is gone
    assert res.cleanup_error is None


def test_run_worker_codex_output_file_truncation_flag(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    codex = make_policy(
        tmp_path, "codex", provider="openai", model="gpt-5.4", max_stdout_bytes=4096
    )
    call = make_call(tmp_path, codex, schema={"type": "object"}, scratch_dir=tmp_path / "s")
    factory = fake_process(stdout=fixture("codex", "0.147.0", "exec_nodoc.jsonl"))
    big = b"x" * 10_000

    def popen(args: list[str], **kw: Any) -> FakeProcess:
        Path(args[args.index("-o") + 1]).write_bytes(big)
        return factory(args, **kw)

    res = run_worker(call, popen=popen)
    assert res.status is WorkerStatus.OK
    assert res.output_file_truncated is True and res.output_file_size == 10_000
    assert res.output_file == big[:4096]
    # under the cap: not flagged
    small = fake_process(stdout=fixture("codex", "0.147.0", "exec_nodoc.jsonl"))

    def popen_small(args: list[str], **kw: Any) -> FakeProcess:
        Path(args[args.index("-o") + 1]).write_bytes(b"{}")
        return small(args, **kw)

    res = run_worker(call, popen=popen_small)
    assert res.output_file_truncated is False and res.output_file_size == 2


def test_run_worker_cleanup_error_reaches_failed_and_refused_results(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every return path after the scratch dir exists carries cleanup_error."""

    def broken_rmtree(path: Any, *a: Any, **k: Any) -> None:
        raise OSError(f"EBUSY {path}")

    monkeypatch.setattr("eris.launch.shutil.rmtree", broken_rmtree)

    def boom(*_a: Any, **_k: Any) -> FakeProcess:
        raise PermissionError("denied")

    # spawn fails with OSError -> FAILED, cleanup_error present
    res = run_worker(_codex_call(tmp_path, tmp_path / "s1"), popen=boom)
    assert res.status is WorkerStatus.FAILED and "spawn failed" in str(res.error)
    assert res.cleanup_error is not None and "EBUSY" in res.cleanup_error
    # spawn refuses (cwd vanished after planning) -> REFUSED, cleanup_error present
    call = _codex_call(tmp_path, tmp_path / "s2")
    Path(call.cwd).rmdir()
    res = run_worker(call, popen=fake_process(stdout=b"{}"))
    assert res.status is WorkerStatus.REFUSED and "not a directory" in str(res.error)
    assert res.cleanup_error is not None and "EBUSY" in res.cleanup_error
    # `-o` refused (symlink) -> REFUSED, cleanup_error present
    target = tmp_path / "victim"
    target.write_text("x")
    factory = fake_process(stdout=fixture("codex", "0.147.0", "exec_nodoc.jsonl"))

    def popen_link(args: list[str], **kw: Any) -> FakeProcess:
        Path(args[args.index("-o") + 1]).symlink_to(target)
        return factory(args, **kw)

    res = run_worker(_codex_call(tmp_path, tmp_path / "s3"), popen=popen_link)
    assert res.status is WorkerStatus.REFUSED and res.cleanup_error is not None
    # a pre-scratch refusal has nothing of ours to clean: no cleanup_error
    scratch = tmp_path / "s4"
    call = _codex_call(tmp_path, scratch)
    scratch.mkdir()
    _call_dir(call).mkdir()
    res = run_worker(call, popen=fake_process(stdout=b"{}"))
    assert res.status is WorkerStatus.REFUSED and res.cleanup_error is None


def test_run_worker_output_open_race_is_refused_not_raised(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    """lstat passes but the O_NOFOLLOW open fails (file swapped for a symlink
    in between): run_worker returns REFUSED, never raises, still cleans up."""
    import errno

    real_open = os.open

    def racy_open(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if str(path).endswith("last_message.json"):
            assert flags & os.O_NOFOLLOW
            raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(path))
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", racy_open)
    factory = fake_process(stdout=fixture("codex", "0.147.0", "exec_nodoc.jsonl"))

    def popen(args: list[str], **kw: Any) -> FakeProcess:
        Path(args[args.index("-o") + 1]).write_bytes(b'{"ok": 1}')  # a regular file for lstat
        return factory(args, **kw)

    call = _codex_call(tmp_path, tmp_path / "s")
    res = run_worker(call, popen=popen)
    assert res.status is WorkerStatus.REFUSED
    assert "could not be read safely" in str(res.error) and "symbolic links" in str(res.error)
    assert res.output_file is None and res.structured is None
    assert not _call_dir(call).exists() and res.cleanup_error is None


def test_run_worker_codex_scratch_removed_even_on_spawn_failure(tmp_path: Path) -> None:
    codex = make_policy(tmp_path, "codex", provider="openai", model="gpt-5.4")

    def boom(*_a: Any, **_k: Any) -> FakeProcess:
        raise PermissionError("denied")

    scratch = tmp_path / "s"
    res = run_worker(
        make_call(tmp_path, codex, schema={"type": "object"}, scratch_dir=scratch), popen=boom
    )
    assert res.status is WorkerStatus.FAILED
    assert [p for p in scratch.rglob("*") if p.is_file()] == []


# --------------------------------------------------------------------------- M2b defect fixes


def test_parse_claude_budget_tripped_fixture_keeps_usage_and_cost() -> None:
    """F1 (T2 capture): the --max-budget-usd cap tripped with NO result key.
    The envelope is an error, but the spend is real: cost_usd 0.129044 on a
    $0.10 cap (the cap overshoots), usage retained, both model names kept,
    and the message names the subtype and terminal_reason."""
    env = parse_claude(fixture("claude", "2.1.239", "budget_tripped.json"))
    assert env.is_error and env.text is None and env.structured is None
    assert env.cost_usd == 0.129044
    assert env.usage is not None and env.usage.output_tokens == 0
    assert env.model_executed is None  # two models in modelUsage -> unknown, never guessed
    assert set(env.models_used) == {"claude-haiku-4-5-20251001", "claude-fable-5"}
    assert env.error == (
        "claude: subtype='error_max_budget_usd' terminal_reason='budget_exhausted': "
        "Reached maximum budget ($0.1)"
    )


def test_parse_claude_error_message_composition() -> None:
    """`result` wins verbatim; otherwise subtype / terminal_reason / errors[]
    compose the message; an envelope that says nothing is `is_error`."""
    assert parse_claude(b'{"is_error":true,"result":"boom","subtype":"x"}').error == "boom"
    assert parse_claude(b'{"is_error":true}').error == "is_error"
    assert parse_claude(b'{"is_error":true,"subtype":"success"}').error == "is_error"
    env = parse_claude(b'{"is_error":true,"subtype":"error_during_execution"}')
    assert env.error == "claude: subtype='error_during_execution'"
    env = parse_claude(b'{"is_error":true,"terminal_reason":"api_error","errors":["a","b",3]}')
    assert env.error == "claude: terminal_reason='api_error': a; b"
    assert parse_claude(b'{"is_error":true,"errors":["only"]}').error == "claude: only"
    # no usage object -> usage None (never a zero-filled guess)
    assert parse_claude(b'{"is_error":true}').usage is None
    assert parse_claude(b'{"is_error":true,"total_cost_usd":0.5}').cost_usd == 0.5


def test_parse_codex_401_fixture_is_auth_error_without_usage() -> None:
    """E2 capture: ten reconnect errors, then `turn.failed` whose `error` is an
    object. The message is the 401, there is no usage and no text."""
    env = parse_codex(fixture("codex", "0.147.0", "auth_401.jsonl"))
    assert env.is_error and env.parse_mode == "jsonl"
    assert env.error is not None
    assert env.error.startswith("codex: unexpected status 401 Unauthorized")
    assert "{'message'" not in env.error  # the dict is unwrapped, not repr'd
    assert env.usage is None and env.text is None and env.structured is None
    assert env.cost_usd is None and env.model_executed is None


def test_parse_grok_api_error_fixture_surfaces_message() -> None:
    """E17 capture: {type: error, message: ...} with no text key -> the API's
    message is the error (a 403 content-policy refusal), not 'no text'."""
    env = parse_grok(fixture("grok", "1.0.5", "api_error_403.json"))
    assert env.is_error and env.text is None and env.usage is None
    assert env.error is not None and env.error.startswith("grok: Internal error")
    assert "403 Forbidden" in env.error and "permission-denied" in env.error
    # other shapes without text keep the generic message
    assert parse_grok(b'{"type":"error"}').error == "grok: envelope has no text"
    assert parse_grok(b'{"stopReason":"stop"}').error == "grok: envelope has no text"


def test_run_worker_ok_with_warning_keeps_status_ok(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """F3: a completed run that flags something (grok `cancelled`) is OK with
    a WARNING; `error` stays None (reserved for non-OK statuses)."""
    policy = make_policy(tmp_path)
    res = run_worker(
        make_call(tmp_path, policy),
        popen=fake_process(stdout=fixture("grok", "1.0.5", "plan.json")),
        killpg=lambda *_: None,
    )
    assert res.status is WorkerStatus.OK and res.error is None
    assert res.warning == "grok: stopReason='cancelled'"
    assert res.cost_usd == 0.031262 and res.text is not None
    ok = run_worker(
        make_call(tmp_path, policy), popen=fake_process(stdout=grok_ok()), killpg=lambda *_: None
    )
    assert ok.status is WorkerStatus.OK and ok.warning is None and ok.error is None
    failed = run_worker(
        make_call(tmp_path, policy),
        popen=fake_process(stdout=fixture("grok", "1.0.5", "api_error_403.json")),
        killpg=lambda *_: None,
    )
    assert failed.status is WorkerStatus.FAILED and failed.warning is None
    assert failed.error is not None and "403" in failed.error


def test_invocation_id_is_unique_per_attempt() -> None:
    """F2: the idempotency key excludes the attempt, the invocation id must not."""
    key = "f" * 64
    ids = {invocation_id_for(key, n) for n in (1, 2, 3)}
    assert ids == {"inv-ffffffffffffffff-a1", "inv-ffffffffffffffff-a2", "inv-ffffffffffffffff-a3"}
    assert invocation_id_for("a" * 64, 1) != invocation_id_for("b" * 64, 1)
    with pytest.raises(ValueError):
        invocation_id_for(key, 0)
