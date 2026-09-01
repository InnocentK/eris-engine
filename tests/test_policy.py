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
    assert set(pol.workers) == {"claude", "judge", "codex", "grok", "agy", "openai-api"}
    assert all(not w.pinned for w in pol.workers.values())
    assert loaded.sha256 == hashlib.sha256(REPO_POLICY.read_bytes()).hexdigest()
    assert loaded.pins_sha256 is None
    assert pol.verify.commands["pytest"].requires_trusted is True
    assert "--bare" not in str(pol.workers["claude"])


def test_repo_default_policy_agy_entry() -> None:
    """The Google lineage is Antigravity `agy` (the `gemini` CLI is gone):
    provider google, a gemini-* model, the auto-update opt-out env, and the
    agy settings file among the credential files."""
    pol = load_policy(REPO_POLICY, pins_path=REPO_POLICY.with_name("no-such-pins.yaml")).policy
    agy = pol.workers["agy"]
    assert agy.cli == "agy" and agy.provider == "google"
    assert agy.model is not None and agy.model.startswith("gemini-")
    assert agy.env == {"AGY_CLI_DISABLE_AUTO_UPDATE": "1"} and agy.timeout_s == 600
    assert "~/.gemini/antigravity-cli/settings.json" in pol.credential_files
    assert "~/.gemini/oauth_creds.json" in pol.credential_files  # harmless, kept
    assert not any(w.cli == "gemini" for w in pol.workers.values())  # type: ignore[comparison-overlap]


def test_repo_default_policy_no_longer_declares_the_grok_credential_file() -> None:
    """M2c: `~/.grok/auth.json` was declared until 2026-08-23 and removed -
    `eris doctor` reports it absent; the Grok CLI no longer creates it. A
    declared file that never exists is a permanent WARN that trains the
    operator to ignore the doctor."""
    pol = load_policy(REPO_POLICY, pins_path=REPO_POLICY.with_name("no-such-pins.yaml")).policy
    assert "~/.grok/auth.json" not in pol.credential_files
    assert not any("grok" in f for f in pol.credential_files)
    assert len(pol.credential_files) == 4


def _agy(model: str | None) -> dict[str, object]:
    worker: dict[str, object] = {
        "transport": "cli",
        "cli": "agy",
        "provider": "google",
        "executable_sha256": UNPINNED,
        "timeout_s": 60,
        "max_stdout_bytes": 1000,
    }
    if model is not None:
        worker["model"] = model
    return minimal_policy(vendors_allowed=["google"], workers={"agy": worker})


def test_gemini_cli_is_no_longer_a_valid_cli_name(tmp_path: Path) -> None:
    data = _agy("gemini-3.1-pro-high")
    workers = data["workers"]
    assert isinstance(workers, dict)
    workers["agy"]["cli"] = "gemini"
    with pytest.raises(PolicyError, match="cli"):
        load_policy(write(tmp_path, data))


def test_agy_loads_with_a_gemini_model(tmp_path: Path) -> None:
    loaded = load_policy(write(tmp_path, _agy("gemini-3.1-pro-high")))
    assert loaded.policy.workers["agy"].model == "gemini-3.1-pro-high"


@pytest.mark.parametrize(
    "model",
    [
        None,
        "",
        "claude-fable-5",
        "gpt-oss-120b",
        "Gemini-3",
        "gemini",
        "gemini-",  # at least one char after the dash
        "gemini- ",
        " gemini-x",  # nothing before the prefix
        "GEMINI-x",  # exact lowercase prefix
        "xgemini-y",
        "gemini-3 pro",  # no whitespace inside an id
    ],
)
def test_agy_lineage_guard_refuses_non_gemini_models(tmp_path: Path, model: str | None) -> None:
    """agy also serves Claude and GPT-OSS ids: an agy worker without a
    gemini-* model is refused at policy load with a clear message. The guard
    is SYNTACTIC: it cannot prove which model executed."""
    with pytest.raises(PolicyError, match="lineage guard: cli `agy` requires `model`"):
        load_policy(write(tmp_path, _agy(model)))
    # other CLIs are not subject to the guard
    loaded = load_policy(write(tmp_path, minimal_policy(), "other.yaml"))
    assert loaded.policy.workers["claude"].model is None


@pytest.mark.parametrize("model", ["gemini-3.1-pro-high", "gemini-x", "gemini-2.5-flash_preview"])
def test_agy_lineage_guard_accepts_gemini_ids(tmp_path: Path, model: str) -> None:
    assert load_policy(write(tmp_path, _agy(model))).policy.workers["agy"].model == model


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_s", "60"),
        ("timeout_s", 60.0),
        ("timeout_s", True),
        ("timeout_s", 0),
        ("timeout_s", 86_401),
        ("max_stdout_bytes", "1000"),
        ("max_stdout_bytes", 1000.0),
        ("max_stdout_bytes", True),
        ("max_stderr_bytes", "1"),
        ("max_stderr_bytes", 1.0),
    ],
)
def test_worker_int_limits_are_strict(tmp_path: Path, field: str, value: object) -> None:
    """timeout_s / max_*_bytes feed timers and caps: no string, float or bool
    coercion, and timeout_s is bounded to [1, 86400]."""
    data = minimal_policy()
    workers = data["workers"]
    assert isinstance(workers, dict)
    workers["claude"][field] = value
    with pytest.raises(PolicyError, match=field):
        load_policy(write(tmp_path, data))
    workers["claude"][field] = 86_400 if field == "timeout_s" else 7
    assert load_policy(write(tmp_path, data, "ok.yaml")).policy.workers["claude"]


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


# --------------------------------------------------------------------------- M2b policy additions


def test_repo_default_policy_m2b_fields() -> None:
    """cache_dir, sanitize_snapshot for agy and grok, evidence-request caps,
    per-campaign budget, sanitize/scan sections - and the R3.1 minimum strip
    list is always in effect (the policy can only add to it)."""
    from eris.policy import SANITIZE_MIN_DIRS, SANITIZE_MIN_NAMES

    pol = load_policy(REPO_POLICY, pins_path=REPO_POLICY.with_name("no-such-pins.yaml")).policy
    assert pol.cache_dir == "cache" and pol.runs_dir == "runs"
    assert pol.workers["agy"].sanitize_snapshot and pol.workers["grok"].sanitize_snapshot
    assert not pol.workers["claude"].sanitize_snapshot
    assert not pol.workers["codex"].sanitize_snapshot
    assert pol.verify.max_requests_per_run == 12 and pol.verify.max_wall_s == 1800
    assert pol.budgets.per_campaign_usd == 200.0
    minimum_names = {"AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", "GROK.md"}
    minimum_dirs = {
        ".agents",
        ".claude",
        ".codex",
        ".gemini",
        ".grok",
        ".antigravity",
        ".cursor",
        ".github/copilot-instructions.md",
    }
    assert minimum_names <= SANITIZE_MIN_NAMES and minimum_dirs <= SANITIZE_MIN_DIRS
    assert pol.sanitize.effective_names >= SANITIZE_MIN_NAMES
    assert pol.sanitize.effective_dirs >= SANITIZE_MIN_DIRS
    assert pol.scan.patterns_from_policy == []


def test_sanitize_policy_adds_but_never_removes_the_minimum(tmp_path: Path) -> None:
    from eris.policy import SANITIZE_MIN_DIRS, SANITIZE_MIN_NAMES

    data = minimal_policy(sanitize={"strip_names": ["NOTES.md"], "strip_dirs": [".vscode"]})
    pol = load_policy(write(tmp_path, data)).policy
    assert "NOTES.md" in pol.sanitize.effective_names
    assert pol.sanitize.effective_names > SANITIZE_MIN_NAMES
    assert ".vscode" in pol.sanitize.effective_dirs
    assert pol.sanitize.effective_dirs > SANITIZE_MIN_DIRS
    for bad in ("", "/etc", "..", "."):
        with pytest.raises(PolicyError):
            load_policy(write(tmp_path, minimal_policy(sanitize={"strip_names": [bad]})))


def test_cache_dir_must_not_be_under_runs(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cache_dir"):
        load_policy(write(tmp_path, minimal_policy(runs_dir="runs", cache_dir="runs/cache")))
    with pytest.raises(PolicyError, match="cache_dir"):
        load_policy(write(tmp_path, minimal_policy(runs_dir="runs", cache_dir="runs")))
    pol = load_policy(write(tmp_path, minimal_policy(runs_dir="runs", cache_dir="elsewhere")))
    assert pol.policy.cache_dir == "elsewhere"


def _claude_worker(**kw: object) -> WorkerPolicy:
    base: dict[str, object] = {
        "transport": "cli",
        "cli": "claude",
        "provider": "anthropic",
        "executable_sha256": UNPINNED,
        "timeout_s": 60,
        "max_stdout_bytes": 1000,
    }
    base.update(kw)
    return WorkerPolicy.model_validate(base)


def test_role_tools_keys_are_validated_and_override_tools() -> None:
    w = _claude_worker(tools=["Read", "Grep"], role_tools={"adjudicator": [], "summarizer": []})
    assert w.tools_for_role("proposer") == ["Read", "Grep"]
    assert w.tools_for_role("adjudicator") == [] and w.tools_for_role("summarizer") == []
    with pytest.raises(ValueError, match="role_tools"):
        _claude_worker(role_tools={"judge": []})
    assert _claude_worker().sanitize_snapshot is False  # default: the original snapshot


def test_verify_caps_and_campaign_budget_are_strict(tmp_path: Path) -> None:
    ok = minimal_policy(verify={"max_requests_per_run": 0, "max_wall_s": 1})
    assert load_policy(write(tmp_path, ok)).policy.verify.max_requests_per_run == 0
    for bad in ({"max_requests_per_run": "12"}, {"max_wall_s": 0}, {"max_wall_s": 1.5}):
        with pytest.raises(PolicyError):
            load_policy(write(tmp_path, minimal_policy(verify=bad)))
    budgets = {"per_run_usd": 1, "per_call_usd": 1, "per_campaign_usd": 0}
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, minimal_policy(budgets=budgets)))


def test_scratch_dir_defaults_under_cache_and_never_under_runs(tmp_path: Path) -> None:
    """Item 5: every ephemeral file lives under scratch_dir (default
    cache/scratch), which may not be the runs dir or inside it."""
    pol = load_policy(REPO_POLICY, pins_path=REPO_POLICY.with_name("no-such-pins.yaml")).policy
    assert pol.scratch_dir == "cache/scratch"
    for bad in ("runs", "runs/scratch"):
        with pytest.raises(PolicyError, match="scratch_dir"):
            load_policy(write(tmp_path, minimal_policy(runs_dir="runs", scratch_dir=bad)))
    ok = load_policy(write(tmp_path, minimal_policy(runs_dir="runs", scratch_dir="tmp/s"))).policy
    assert ok.scratch_dir == "tmp/s"


def test_scratch_retention_is_a_strict_bounded_int(tmp_path: Path) -> None:
    """New consequence 2: the hard retention bound is policy-configurable and
    strictly validated (an hour to a year)."""
    pol = load_policy(REPO_POLICY, pins_path=REPO_POLICY.with_name("no-such-pins.yaml")).policy
    assert pol.scratch_retention_s == 604_800  # 7 days
    ok = load_policy(write(tmp_path, minimal_policy(scratch_retention_s=7200))).policy
    assert ok.scratch_retention_s == 7200
    for bad in (60, "604800", 1.5, 40_000_000):
        with pytest.raises(PolicyError):
            load_policy(write(tmp_path, minimal_policy(scratch_retention_s=bad)))


def test_containment_declaration_is_refused_until_a_mechanism_exists(tmp_path: Path) -> None:
    """H2: the scorer gates defect/ABSTAIN categories on `containment ==
    "container"` and cannot verify it. No container exists anywhere in the tree,
    so accepting the declaration would let one YAML word satisfy the gate while
    workers still run through plain Popen. Delete this test in the SAME change
    that builds the mechanism."""
    with pytest.raises(PolicyError, match="no containment mechanism"):
        load_policy(write(tmp_path, minimal_policy(containment="container")))
    # the unset case still loads
    assert load_policy(write(tmp_path, minimal_policy())).policy.containment is None


def test_a_call_cap_larger_than_the_reservation_is_refused(tmp_path: Path) -> None:
    """`per_call_usd` is the pre-call margin, so no cap may exceed it.

    `BudgetLedger.precheck` admits a call when `committed + per_call_usd <=
    run_ceiling_usd`, and the ceiling is tested BEFORE a call, never after. A
    worker whose `max_budget_usd` is larger than `per_call_usd` can therefore be
    admitted with that much headroom and then spend more, carrying the cell past
    `per_run_usd` with nothing to refuse it.

    Raising claude's cap from $1 to $4 against a $2 `per_call_usd` was committed
    on 2026-08-31 with the claim that a runaway would still stop "well inside
    per_run_usd $20". The code did not say that. Two numbers that must move
    together are a refusal, not a thing to remember.

    What this pins is the DESIGNED gap only. The vendor cap is observed after a
    charge, so a call aborts past its limit by up to one indivisible charge -
    measured at +3.8% and +13.2% on a $1.00 cap here. `per_run_usd` stays a soft
    bound and `Policy._call_cap_fits_the_reservation` says so; this test does
    not claim otherwise, and there is nothing here that could enforce it.
    """
    raw = yaml.safe_load(REPO_POLICY.read_text(encoding="utf-8"))
    raw["budgets"]["per_call_usd"] = 2.0
    raw["workers"]["claude"]["max_budget_usd"] = 4.0
    bad = tmp_path / "cap-too-big.yaml"
    bad.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(PolicyError, match="smaller than max_budget_usd"):
        load_policy(bad)

    # Equal is fine: the margin exactly covers the worst admitted call.
    raw["budgets"]["per_call_usd"] = 4.0
    ok = tmp_path / "cap-equal.yaml"
    ok.write_text(yaml.safe_dump(raw), encoding="utf-8")
    assert load_policy(ok).policy.budgets.per_call_usd == 4.0

    # An UNCAPPED worker is not bounded by this and must not be refused for it -
    # `per_call_usd` is what Eris books for such a worker, not a limit it obeys.
    raw["budgets"]["per_call_usd"] = 1.0
    raw["workers"]["claude"]["max_budget_usd"] = None
    raw["workers"]["judge"]["max_budget_usd"] = None
    unc = tmp_path / "uncapped.yaml"
    unc.write_text(yaml.safe_dump(raw), encoding="utf-8")
    assert load_policy(unc).policy.budgets.per_call_usd == 1.0
