from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
import yaml

from eris.cli import main as eris_main
from eris.doctor import default_probe_runner, run_doctor
from eris.policy import UNPINNED
from tests.conftest import HermeticityViolation

PLANTED = "sk-proj-PLANTEDSECRETVALUE0123456789abcdef"
CRED_TOKEN = "codex-access-token-PLANTED-" + "z" * 20


def write_policy(tmp_path: Path, exe: Path | None, pinned: bool, **extra: object) -> Path:
    worker: dict[str, object] = {
        "transport": "cli",
        "cli": "grok",
        "provider": "xai",
        "model": "grok-4.6",
        "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest()
        if (exe and pinned)
        else UNPINNED,
        "timeout_s": 10,
        "max_stdout_bytes": 1000,
        "env_allow": ["XAI_API_KEY"],
    }
    if exe is not None:
        worker["executable"] = str(exe)
    data: dict[str, object] = {
        "policy_version": "t",
        "runs_dir": str(tmp_path / "runs"),
        "vendors_allowed": ["xai", "openai"],
        "api_hosts_allowed": ["api.openai.com"],
        "credential_files": [str(tmp_path / "auth.json"), "~/.nope/creds.json"],
        "workers": {
            "grok": worker,
            "openai-api": {
                "transport": "api",
                "provider": "openai",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "OPENAI_API_KEY",
                "executable_sha256": UNPINNED,
                "timeout_s": 10,
                "max_stdout_bytes": 10,
            },
        },
        "verify": {
            "commands": {"git": {"executable": "/usr/bin/git", "executable_sha256": UNPINNED}}
        },
        "budgets": {"per_run_usd": 1, "per_call_usd": 1},
    }
    data.update(extra)
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def write_env(tmp_path: Path) -> Path:
    env = tmp_path / ".env"
    env.write_text(f"OPENAI_API_KEY={PLANTED}\nXAI_API_KEY=\n")
    env.chmod(0o600)
    (tmp_path / "auth.json").write_text(json.dumps({"tokens": {"access_token": CRED_TOKEN}}))
    return env


def fake_exe(tmp_path: Path) -> Path:
    exe = tmp_path / "grok"
    exe.write_bytes(b"#!/bin/sh\necho grok 1.0.5\n")
    exe.chmod(0o755)
    return exe


def by_name(report_text: str, name: str) -> str:
    for line in report_text.splitlines():
        if line[5:].startswith(name + ":"):
            return line
    raise AssertionError(f"no check named {name} in:\n{report_text}")


def test_doctor_never_prints_secret_values(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True),
        env_file=write_env(tmp_path),
        home=tmp_path,
        which=lambda n: "/usr/bin/git" if n == "git" else None,
    )
    text = report.render()
    assert PLANTED not in text and PLANTED[-12:] not in text
    assert CRED_TOKEN not in text
    assert "OPENAI_API_KEY present" in by_name(text, "worker.openai-api")
    assert "XAI_API_KEY" in by_name(text, "worker.grok.env")  # name only; value was empty
    assert by_name(text, "worker.grok").startswith("OK")
    assert by_name(text, "credential-file").startswith("OK")
    assert "absent" in text  # the ~/.nope credential file
    assert by_name(text, "runs-dir").startswith("OK") and "flock works" in text
    assert by_name(text, "verify.git").startswith("WARN") and "UNPINNED" in by_name(
        text, "verify.git"
    )
    assert by_name(text, "git").startswith("OK")
    assert report.ok and text.endswith("checks)")
    assert not (tmp_path / "runs" / ".doctor.lock").exists()


def test_agy_state_dir_size_is_reported_and_warns_when_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """agy writes ~1 MB of transcript/SQLite state per run under
    ~/.gemini/antigravity-cli/. The doctor reports the size (never the
    content) and WARNs past the threshold; Eris never deletes vendor state."""
    import eris.doctor as doctor

    write_env(tmp_path)
    agy = {
        "transport": "cli",
        "cli": "agy",
        "provider": "google",
        "model": "gemini-3.1-pro-high",
        "executable_sha256": UNPINNED,
        "timeout_s": 10,
        "max_stdout_bytes": 1000,
    }
    policy = write_policy(tmp_path, None, pinned=False, vendors_allowed=["xai", "openai", "google"])
    data = yaml.safe_load(policy.read_text())
    data["workers"]["agy"] = agy
    policy.write_text(yaml.safe_dump(data))
    report = run_doctor(policy_path=policy, env_file=tmp_path / ".env", home=tmp_path)
    line = by_name(report.render(), "worker.agy.state")
    assert line.startswith("OK") and "absent" in line
    brain = tmp_path / ".gemini" / "antigravity-cli" / "brain" / "conv-1"
    brain.mkdir(parents=True)
    (brain / "plan.md").write_bytes(b"x" * 2048)
    (tmp_path / ".gemini" / "antigravity-cli" / "brain" / "link").symlink_to(tmp_path / "runs")
    report = run_doctor(policy_path=policy, env_file=tmp_path / ".env", home=tmp_path)
    line = by_name(report.render(), "worker.agy.state")
    assert line.startswith("OK") and "brain 0.0 MiB" in line and "conversations" not in line
    assert "plan.md" not in line  # sizes only, never names of the worker's files
    monkeypatch.setattr(doctor, "AGY_STATE_WARN_BYTES", 1024)
    report = run_doctor(policy_path=policy, env_file=tmp_path / ".env", home=tmp_path)
    line = by_name(report.render(), "worker.agy.state")
    assert line.startswith("WARN") and "clean up manually" in line and report.ok
    assert "worker.grok.state" not in report.render()  # only agy has a state check


def test_missing_worker_is_warn_not_fail(tmp_path: Path) -> None:
    write_env(tmp_path)
    report = run_doctor(
        policy_path=write_policy(tmp_path, tmp_path / "gone", pinned=False),
        env_file=tmp_path / ".env",
        home=tmp_path,
    )
    line = by_name(report.render(), "worker.grok")
    assert line.startswith("WARN") and "recorded absence" in line
    assert report.ok

    report = run_doctor(
        policy_path=write_policy(tmp_path, None, pinned=False),
        env_file=tmp_path / ".env",
        home=tmp_path,
    )
    line = by_name(report.render(), "worker.grok")
    assert line.startswith("WARN") and "not found on PATH" in line  # guard hides the real grok

    report = run_doctor(
        policy_path=write_policy(tmp_path, None, pinned=False),
        env_file=tmp_path / ".env",
        home=tmp_path,
        which=lambda n: "/opt/homebrew/bin/grok" if n == "grok" else "/usr/bin/git",
    )
    assert "UNPINNED" in by_name(report.render(), "worker.grok")


def test_changed_binary_is_fail(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    policy = write_policy(tmp_path, exe, pinned=True)
    exe.write_bytes(b"#!/bin/sh\necho tampered\n")
    report = run_doctor(policy_path=policy, env_file=write_env(tmp_path), home=tmp_path)
    assert by_name(report.render(), "worker.grok").startswith("FAIL")
    assert not report.ok and report.render().endswith(
        "doctor: FAIL (%d checks)" % len(report.checks)
    )


def test_unpinned_present_binary_is_warn(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=False),
        env_file=write_env(tmp_path),
        home=tmp_path,
    )
    assert "UNPINNED" in by_name(report.render(), "worker.grok")


def test_bad_policy_and_env_file_states(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("workers: 1\n")
    report = run_doctor(policy_path=bad, env_file=tmp_path / ".env", home=tmp_path)
    assert not report.ok and by_name(report.render(), "policy").startswith("FAIL")
    assert len(report.checks) == 2  # python + policy, then stop

    exe = fake_exe(tmp_path)
    policy = write_policy(tmp_path, exe, pinned=True)
    report = run_doctor(policy_path=policy, env_file=tmp_path / "missing.env", home=tmp_path)
    assert by_name(report.render(), "env-file").startswith("WARN")
    loose = tmp_path / "loose.env"
    loose.write_text("OPENAI_API_KEY=x\n")
    loose.chmod(0o644)
    report = run_doctor(policy_path=policy, env_file=loose, home=tmp_path)
    assert "chmod 600" in by_name(report.render(), "env-file")


def test_probe_uses_injected_runner_with_hardened_env(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    seen: list[tuple[list[str], dict[str, str]]] = []

    def runner(argv: list[str], env: dict[str, str]) -> str | None:
        seen.append((argv, env))
        return "grok 1.0.5"

    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True),
        env_file=write_env(tmp_path),
        probe=True,
        runner=runner,
        home=tmp_path,
    )
    assert seen[0][0] == [str(exe), "--version"]
    assert seen[0][1]["HOME"] == str(tmp_path) and "OPENAI_API_KEY" not in seen[0][1]
    assert "--version: grok 1.0.5" in by_name(report.render(), "worker.grok.probe")
    assert len(seen) == 1  # only the pinned, hash-verified worker was probed
    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True),
        env_file=write_env(tmp_path),
        probe=True,
        runner=lambda _a, _e: None,
        home=tmp_path,
    )
    assert by_name(report.render(), "worker.grok.probe").startswith("WARN")


def test_probe_output_is_redacted_and_mismatched_binary_is_never_probed(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    env = write_env(tmp_path)
    leak = "xai-" + "Pq2" * 12
    calls: list[list[str]] = []

    def runner(argv: list[str], _env: dict[str, str]) -> str | None:
        calls.append(argv)
        return f"grok 1.0.5 (key {leak}; planted {PLANTED}; cred {CRED_TOKEN})"

    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True),
        env_file=env,
        probe=True,
        runner=runner,
        home=tmp_path,
    )
    text = report.render()
    line = by_name(text, "worker.grok.probe")
    assert line.startswith("OK") and "grok 1.0.5" in line
    for secret in (leak, PLANTED, CRED_TOKEN):
        assert secret not in text and secret[-10:] not in text
    assert "[REDACTED:" in line

    # tampered binary: hash mismatch -> FAIL and the probe must NOT execute it
    calls.clear()
    policy = write_policy(tmp_path, exe, pinned=True)
    exe.write_bytes(b"#!/bin/sh\necho tampered\n")
    report = run_doctor(policy_path=policy, env_file=env, probe=True, runner=runner, home=tmp_path)
    assert calls == []
    assert by_name(report.render(), "worker.grok").startswith("FAIL")
    assert "skipped" in by_name(report.render(), "worker.grok.probe")
    # unpinned binary: not probed either
    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=False),
        env_file=env,
        probe=True,
        runner=runner,
        home=tmp_path,
    )
    assert calls == [] and "skipped" in by_name(report.render(), "worker.grok.probe")


def test_unparsable_credential_file_is_fail_missing_is_warn(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    env = write_env(tmp_path)
    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True), env_file=env, home=tmp_path
    )
    lines = [line for line in report.render().splitlines() if "credential-file" in line]
    assert any(line.startswith("OK") and "auth.json: present" in line for line in lines)
    assert any(line.startswith("WARN") and "absent" in line for line in lines)
    (tmp_path / "auth.json").write_text("{not json")
    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True), env_file=env, home=tmp_path
    )
    line = by_name(report.render(), "credential-file")
    assert line.startswith("FAIL") and "cannot be parsed" in line and not report.ok


def test_probe_skipped_entirely_on_credential_parse_failure(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    env = write_env(tmp_path)
    (tmp_path / "auth.json").write_text("{not json")
    calls: list[list[str]] = []

    def runner(argv: list[str], _env: dict[str, str]) -> str | None:
        calls.append(argv)
        return "grok 1.0.5"

    report = run_doctor(
        policy_path=write_policy(tmp_path, exe, pinned=True),
        env_file=env,
        probe=True,
        runner=runner,
        home=tmp_path,
    )
    assert calls == []  # a pinned, hash-verified worker was still NOT probed
    assert by_name(report.render(), "credential-file").startswith("FAIL")
    assert "skipped (credential parse failure)" in by_name(report.render(), "worker.grok.probe")
    assert not report.ok


def test_default_probe_runner_is_a_real_subprocess_call() -> None:
    with pytest.raises(HermeticityViolation):
        default_probe_runner(["/usr/bin/true", "--version"], {})


def test_flock_probe_failure_is_fail(tmp_path: Path) -> None:
    exe = fake_exe(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.write_text("not a dir")
    policy = write_policy(tmp_path, exe, pinned=True, runs_dir=str(blocked))
    report = run_doctor(policy_path=policy, env_file=write_env(tmp_path), home=tmp_path)
    assert by_name(report.render(), "runs-dir").startswith("FAIL")


def test_cli_doctor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = fake_exe(tmp_path)
    policy = write_policy(tmp_path, exe, pinned=True)
    env = write_env(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    rc = eris_main(["doctor", "--policy", str(policy), "--env-file", str(env)])
    out = capsys.readouterr().out
    assert rc == 0 and "doctor: " in out and PLANTED not in out
    assert os.path.basename(str(exe)) in out
