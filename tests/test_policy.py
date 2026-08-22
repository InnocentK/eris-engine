from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest
import yaml

from eris.cli import main as eris_main
from eris.policy import (
    UNPINNED,
    PolicyError,
    WorkerPolicy,
    load_policy,
    pin_executables,
    refuse_secret_shaped,
)

REPO_POLICY = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


def minimal_policy(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "policy_version": "test.1",
        "vendors_allowed": ["anthropic", "openai"],
        "api_hosts_allowed": ["api.openai.com", "localhost"],
        "workers": {
            "claude": {
                "transport": "cli",
                "cli": "claude",
                "provider": "anthropic",
                "executable_sha256": UNPINNED,
                "timeout_s": 60,
                "max_stdout_bytes": 1000,
            }
        },
        "budgets": {"per_run_usd": 1.0, "per_call_usd": 0.5},
    }
    data.update(overrides)
    return data


def write(tmp_path: Path, data: dict[str, object], name: str = "policy.yaml") -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- happy path


def test_repo_default_policy_loads_and_is_untrusted_and_unpinned() -> None:
    loaded = load_policy(REPO_POLICY, pins_path=REPO_POLICY.with_name("no-such-pins.yaml"))
    pol = loaded.policy
    assert pol.trusted is False
    assert set(pol.workers) == {"claude", "codex", "grok", "gemini", "openai-api"}
    assert all(not w.pinned for w in pol.workers.values())
    assert loaded.sha256 == hashlib.sha256(REPO_POLICY.read_bytes()).hexdigest()
    assert loaded.pins_sha256 is None
    assert pol.verify.commands["pytest"].requires_trusted is True
    assert "--bare" not in str(pol.workers["claude"])


def test_minimal_policy_loads_with_defaults(tmp_path: Path) -> None:
    loaded = load_policy(write(tmp_path, minimal_policy()))
    assert loaded.policy.trusted is False
    assert loaded.policy.runs_dir == "runs"
    assert loaded.policy.workers["claude"].max_stderr_bytes == 1_000_000
    assert loaded.pins_path == tmp_path / "pins.yaml"


# --------------------------------------------------------------------------- fail closed


@pytest.mark.parametrize("missing", ["executable_sha256", "timeout_s", "max_stdout_bytes"])
def test_missing_required_worker_field_refuses(tmp_path: Path, missing: str) -> None:
    data = minimal_policy()
    workers = data["workers"]
    assert isinstance(workers, dict)
    del workers["claude"][missing]
    with pytest.raises(PolicyError, match=missing):
        load_policy(write(tmp_path, data))


def test_missing_vendors_allowed_refuses(tmp_path: Path) -> None:
    data = minimal_policy()
    del data["vendors_allowed"]
    with pytest.raises(PolicyError, match="vendors_allowed"):
        load_policy(write(tmp_path, data))


def test_unknown_key_refuses(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="surprise"):
        load_policy(write(tmp_path, minimal_policy(surprise=1)))


def test_provider_not_in_vendors_refuses(tmp_path: Path) -> None:
    data = minimal_policy(vendors_allowed=["openai"])
    with pytest.raises(PolicyError, match="not in vendors_allowed"):
        load_policy(write(tmp_path, data))


@pytest.mark.parametrize(
    "value",
    [
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
        "xai-abcdefghijklmnopqrstuvwxyz012345",
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_" + "a" * 36,
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "https://user:hunter2pass@example.com/x",
    ],
)
def test_secret_shaped_value_refuses_load(tmp_path: Path, value: str) -> None:
    data = minimal_policy()
    workers = data["workers"]
    assert isinstance(workers, dict)
    workers["claude"]["env"] = {"SOMETHING": value}
    with pytest.raises(PolicyError, match="looks like a secret"):
        load_policy(write(tmp_path, data))
    with pytest.raises(PolicyError):
        refuse_secret_shaped({"nested": [{"deep": value}]})


def test_env_names_only_are_not_secret_shaped() -> None:
    refuse_secret_shaped({"env_allow": ["OPENAI_API_KEY", "XAI_API_KEY"], "api_key_env": "K"})


def test_api_worker_host_and_scheme_rules(tmp_path: Path) -> None:
    def api(url: str) -> dict[str, object]:
        return {
            "transport": "api",
            "provider": "openai",
            "base_url": url,
            "api_key_env": "OPENAI_API_KEY",
            "executable_sha256": UNPINNED,
            "timeout_s": 10,
            "max_stdout_bytes": 100,
        }

    ok = minimal_policy(workers={"o": api("https://api.openai.com/v1")})
    assert load_policy(write(tmp_path, ok)).policy.workers["o"].base_url
    local = minimal_policy(workers={"o": api("http://localhost:11434/v1")})
    assert load_policy(write(tmp_path, local, "l.yaml"))
    with pytest.raises(PolicyError, match="not in api_hosts_allowed"):
        load_policy(write(tmp_path, minimal_policy(workers={"o": api("https://evil.example/v1")})))
    with pytest.raises(PolicyError, match="must be https"):
        load_policy(write(tmp_path, minimal_policy(workers={"o": api("http://api.openai.com/v1")})))
    with pytest.raises(PolicyError, match="not in api_hosts_allowed"):
        load_policy(
            write(
                tmp_path,
                minimal_policy(workers={"o": api("https://api.openai.com@evil.example/v1")}),
            )
        )


def test_transport_field_consistency() -> None:
    base = {"provider": "x", "executable_sha256": UNPINNED, "timeout_s": 1, "max_stdout_bytes": 1}
    with pytest.raises(ValueError, match="requires `cli`"):
        WorkerPolicy(transport="cli", **base)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="absolute"):
        WorkerPolicy(transport="cli", cli="codex", executable="codex", **base)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires `base_url`"):
        WorkerPolicy(transport="api", **base)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="UPPER_SNAKE"):
        WorkerPolicy(transport="cli", cli="grok", env_allow=["lower"], **base)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        WorkerPolicy.model_validate(
            {**base, "transport": "cli", "cli": "grok", "executable_sha256": "deadbeef"}
        )


def test_bad_yaml_and_non_mapping_refuse(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text("workers: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(p)
    p.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="mapping"):
        load_policy(p)
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "missing.yaml")


def test_bad_verify_regex_refuses(tmp_path: Path) -> None:
    data = minimal_policy(
        verify={
            "commands": {
                "git": {
                    "executable": "/usr/bin/git",
                    "executable_sha256": UNPINNED,
                    "value_flags": {"-n": "("},
                }
            }
        }
    )
    with pytest.raises(PolicyError, match="bad regex"):
        load_policy(write(tmp_path, data))


# --------------------------------------------------------------------------- pins


def fake_executable(tmp_path: Path, name: str, content: bytes = b"#!/bin/sh\necho hi\n") -> Path:
    exe = tmp_path / "bin" / name
    exe.parent.mkdir(exist_ok=True)
    exe.write_bytes(content)
    exe.chmod(0o755)
    return exe


def test_pin_executables_hermetic(tmp_path: Path) -> None:
    exe = fake_executable(tmp_path, "claude")
    policy_path = write(tmp_path, minimal_policy())
    assert shutil.which("claude") is None  # guard: the real CLI must not be consulted

    def which(name: str) -> str | None:
        return str(exe) if name == "claude" else None

    report = pin_executables(policy_path, which=which)
    expected = hashlib.sha256(exe.read_bytes()).hexdigest()
    assert report.pinned == {"claude": expected}
    assert report.missing == []
    pins = yaml.safe_load(report.pins_path.read_text())
    assert pins["workers"]["claude"]["sha256"] == expected
    assert pins["workers"]["claude"]["executable"] == str(exe)

    loaded = load_policy(policy_path)
    w = loaded.policy.workers["claude"]
    assert w.pinned and w.executable_sha256 == expected and w.executable == str(exe)
    assert loaded.pins_sha256 == hashlib.sha256(report.pins_path.read_bytes()).hexdigest()

    # Changing the binary invalidates the pin (hash differs) - detected by the launcher.
    exe.write_bytes(b"#!/bin/sh\necho changed\n")
    assert hashlib.sha256(exe.read_bytes()).hexdigest() != expected


def test_pin_missing_executable_is_recorded_absence(tmp_path: Path) -> None:
    policy_path = write(tmp_path, minimal_policy())
    report = pin_executables(policy_path, which=lambda _name: None)
    assert report.missing == ["claude"]
    assert report.pinned == {}
    assert load_policy(policy_path).policy.workers["claude"].pinned is False


def test_pin_verify_commands(tmp_path: Path) -> None:
    git = fake_executable(tmp_path, "git")
    data = minimal_policy(
        verify={
            "commands": {
                "git": {"executable": str(git), "executable_sha256": UNPINNED},
                "ruff": {"executable": str(tmp_path / "nope"), "executable_sha256": UNPINNED},
            }
        }
    )
    policy_path = write(tmp_path, data)
    report = pin_executables(policy_path, which=lambda _n: None)
    assert "verify.git" in report.pinned and "verify.ruff" in report.missing
    assert load_policy(policy_path).policy.verify.commands["git"].pinned


def test_secret_in_pins_file_refuses(tmp_path: Path) -> None:
    policy_path = write(tmp_path, minimal_policy())
    (tmp_path / "pins.yaml").write_text(
        "workers:\n  claude:\n    sha256: sk-ant-api03-abcdefghijklmnopqrstuvwxyz\n"
    )
    with pytest.raises(PolicyError, match="looks like a secret"):
        load_policy(policy_path)


def test_cli_policy_pin(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exe = fake_executable(tmp_path, "claude")
    data = minimal_policy()
    workers = data["workers"]
    assert isinstance(workers, dict)
    workers["claude"]["executable"] = str(exe)
    policy_path = write(tmp_path, data)
    rc = eris_main(["policy", "pin", "--policy", str(policy_path)])
    out = capsys.readouterr().out
    assert rc == 0 and "PINNED  claude:" in out and "wrote" in out
    rc = eris_main(["policy", "pin", "--policy", str(tmp_path / "missing.yaml")])
    assert rc == 2 and "FAIL" in capsys.readouterr().err
