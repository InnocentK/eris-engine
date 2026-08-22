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
    LaunchRefused,
    WorkerCall,
    assert_argv_safe,
    assert_env_safe,
    build_argv_claude,
    build_argv_codex,
    build_argv_gemini,
    build_argv_grok,
    build_env,
    first_balanced_json,
    idempotency_key,
    parse_claude,
    parse_codex,
    parse_gemini,
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


def test_gemini_and_grok_argv_exactly_as_specified() -> None:
    assert build_argv_gemini("/x/gemini", PROMPT, model="g") == [
        "/x/gemini",
        "-p",
        PROMPT,
        "-m",
        "g",
        "--approval-mode",
        "plan",
        "-o",
        "json",
    ]
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
    # The prompt element is exempt: reviewers legitimately quote these flags.
    argv = build_argv_claude("/x/claude", f"Is using {token} here defensible?")
    assert argv[2] == f"Is using {token} here defensible?"
    codex = build_argv_codex("/x/codex", f"Explain {token}", cwd=Path("/"), model="m")
    assert codex[-1] == f"Explain {token}"
    assert build_argv_grok("/x/grok", f"review {token}", model="m")[2] == f"review {token}"
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
    with pytest.raises(LaunchRefused, match="empty prompt"):
        build_argv_codex("/x/codex", "  ", cwd=Path("/"), model="m")
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
    ],
)
def test_never_list_names_are_refused(name: str) -> None:
    with pytest.raises(LaunchRefused, match="NEVER list"):
        build_env("codex", path_env="/usr/bin", home="/h", tmpdir="/t", policy_env={name: "x"})
    with pytest.raises(LaunchRefused):
        build_env("codex", path_env="/usr/bin", home="/h", tmpdir="/t", secrets={name: "x"})


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


def test_parse_gemini_defensive_modes() -> None:
    whole = json.dumps({"response": "hello", "stats": {"models": {"gemini-2.5-pro": {}}}}).encode()
    env = parse_gemini(whole)
    assert (
        env.parse_mode == "json" and env.text == "hello" and env.model_executed == "gemini-2.5-pro"
    )
    noisy = b'Loaded extensions...\n{"response": "embedded {\\"x\\": 1}"}\ntrailing'
    env = parse_gemini(noisy)
    assert env.parse_mode == "balanced_extract" and env.text == 'embedded {"x": 1}'
    env = parse_gemini(b"just prose, no json { unbalanced")
    assert (
        env.parse_mode == "none"
        and env.text == "just prose, no json { unbalanced"
        and not env.is_error
    )
    env = parse_gemini(b"")
    assert env.is_error and env.error == "gemini: empty stdout"
    env = parse_gemini(b'{"error": "IneligibleTierError"}')
    assert env.is_error and env.error == "IneligibleTierError"
    env = parse_gemini(b'{"unknown": 1}')
    assert env.is_error and env.error == "gemini: no response text"
    env = parse_gemini(b'{"text": "[1, 2]"}')
    assert env.structured == [1, 2]


def test_first_balanced_json() -> None:
    assert first_balanced_json('x {"a": "}"} y') == '{"a": "}"}'
    assert first_balanced_json('{"a": "\\"}"}') == '{"a": "\\"}"}'
    assert first_balanced_json("{ unbalanced {") is None
    assert first_balanced_json("none") is None
    assert first_balanced_json('{bad} {"ok": 1}') == "{bad}"


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
    gemini = make_policy(tmp_path, "gemini", provider="google", model="g")
    assert "--approval-mode" in plan_call(make_call(tmp_path, gemini)).argv
    with pytest.raises(LaunchRefused, match="requires a model"):
        plan_call(
            make_call(tmp_path, make_policy(tmp_path, "gemini", provider="google", model=None))
        )
    with pytest.raises(LaunchRefused, match="requires a model"):
        plan_call(make_call(tmp_path, make_policy(tmp_path, model=None)))
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
