from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from eris.cli import build_parser
from eris.cli import main as eris_main
from eris.policy import LoadedPolicy, Policy, load_policy
from eris.refresh import (
    CampaignSpecV1,
    CheckStatus,
    CommandResult,
    Decision,
    DriftStatus,
    LiveProbeResult,
    RefreshNotDurable,
    VerifyReceiptV1,
    VersionClass,
    apply,
    classify_version,
    detect,
    doctor_output_allows_preflight,
    preflight,
    provider_manifest,
    required_worker_credentials,
    verification_manifest,
    verify,
)


def _spec(tmp_path: Path, **overrides: object) -> dict[str, object]:
    repo = tmp_path / "repo"
    runner = repo / "eval" / "run.py"
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.write_text("# runner\n", encoding="utf-8")
    data: dict[str, object] = {
        "spec_version": 1,
        "repo_root": str(repo.resolve()),
        "candidate_revision": "a" * 40,
        "runner_path": "eval/run.py",
        "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
        "campaign_id": "campaign-1",
        "policy_path": str((repo / "policies" / "default.yaml").resolve()),
        "env_file": str((repo / ".env").resolve()),
        "prompts_dir": str((repo / "eval" / "prompts").resolve()),
        "runs_dir": str((repo / "runs").resolve()),
        "cache_dir": str((repo / "cache").resolve()),
        "corpus": str((repo / "eval" / "corpus").resolve()),
        "task_files": [],
        "arms": ["single", "indep_verify_critique"],
        "repeats": 1,
        "panel": ["claude", "grok"],
        "critics": ["codex"],
        "judge": "judge",
        "no_cache": False,
        "fresh": True,
        "reuse_across_campaigns": False,
    }
    data.update(overrides)
    return data


def test_campaign_spec_is_strict_and_requires_exactly_one_task_source(tmp_path: Path) -> None:
    spec = CampaignSpecV1.model_validate(_spec(tmp_path))
    assert spec.spec_version == 1

    for update in (
        {"surprise": True},
        {"spec_version": 2},
        {"corpus": None, "task_files": []},
        {"task_files": [str((tmp_path / "task.json").resolve())]},
        {"arms": "single"},
        {"panel": ["claude", "claude"]},
        {"no_cache": True, "fresh": True},
        {"runner_path": "other.py"},
        {"repo_root": "relative"},
    ):
        with pytest.raises(ValidationError):
            CampaignSpecV1.model_validate(_spec(tmp_path, **update))

    both = _spec(
        tmp_path,
        task_files=[str((tmp_path / "task.json").resolve())],
    )
    with pytest.raises(ValidationError):
        CampaignSpecV1.model_validate(both)


def test_campaign_spec_load_refuses_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "campaign.json"
    path.write_text('{"spec_version":1,"spec_version":1}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        CampaignSpecV1.load(path)


def test_campaign_spec_renders_exact_campaign_argv_and_worker_scope(tmp_path: Path) -> None:
    spec = CampaignSpecV1.model_validate(_spec(tmp_path))
    repo = Path(spec.repo_root)
    assert spec.campaign_argv(python=sys.executable) == [
        sys.executable,
        str(repo / "eval" / "run.py"),
        "campaign",
        "--policy",
        spec.policy_path,
        "--env-file",
        spec.env_file,
        "--prompts-dir",
        spec.prompts_dir,
        "--runs-dir",
        spec.runs_dir,
        "--cache-dir",
        spec.cache_dir,
        "--fresh",
        "--panel",
        "claude,grok",
        "--critics",
        "codex",
        "--judge",
        "judge",
        "--campaign-id",
        "campaign-1",
        "--corpus",
        spec.corpus,
        "--repeats",
        "1",
        "--arms",
        "single,indep_verify_critique",
        "--dry-run",
    ]
    assert spec.used_worker_ids() == ("claude", "grok", "codex", "judge")

    single = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], critics=[], judge="unused")
    )
    assert single.used_worker_ids() == ("claude", "grok")


def test_campaign_spec_canonical_bytes_are_stable(tmp_path: Path) -> None:
    spec = CampaignSpecV1.model_validate(_spec(tmp_path))
    raw = spec.canonical_bytes()
    assert raw == json.dumps(
        spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    assert spec.sha256 == hashlib.sha256(raw).hexdigest()


def _loaded_policy(tmp_path: Path) -> LoadedPolicy:
    shared = tmp_path / "bin" / "shared-claude"
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_bytes(b"claude")
    shared.chmod(0o755)
    claude = tmp_path / "bin" / "claude"
    judge = tmp_path / "bin" / "judge"
    claude.symlink_to(shared.name)
    judge.symlink_to(shared.name)
    grok = tmp_path / "bin" / "grok"
    grok.write_bytes(b"new-grok")
    grok.chmod(0o755)
    git = tmp_path / "bin" / "git"
    ruff = tmp_path / "bin" / "ruff"
    mypy = tmp_path / "bin" / "mypy"
    for path in (git, ruff, mypy):
        path.write_bytes(path.name.encode())
        path.chmod(0o755)
    shared_sha = hashlib.sha256(shared.read_bytes()).hexdigest()
    data = {
        "policy_version": "test.1",
        "vendors_allowed": ["anthropic", "xai"],
        "workers": {
            "claude": {
                "transport": "cli",
                "cli": "claude",
                "provider": "anthropic",
                "model": "claude-fable-5",
                "executable": str(claude),
                "executable_sha256": shared_sha,
                "timeout_s": 60,
                "max_stdout_bytes": 1000,
            },
            "judge": {
                "transport": "cli",
                "cli": "claude",
                "provider": "anthropic",
                "model": "claude-fable-5",
                "executable": str(judge),
                "executable_sha256": shared_sha,
                "timeout_s": 60,
                "max_stdout_bytes": 1000,
            },
            "grok": {
                "transport": "cli",
                "cli": "grok",
                "provider": "xai",
                "model": "grok-4.6",
                "executable": str(grok),
                "executable_sha256": "0" * 64,
                "timeout_s": 60,
                "max_stdout_bytes": 1000,
            },
        },
        "verify": {
            "commands": {
                name: {
                    "executable": str(path),
                    "executable_sha256": (
                        hashlib.sha256(path.read_bytes()).hexdigest()
                        if name != "ruff"
                        else "1" * 64
                    ),
                }
                for name, path in {"git": git, "ruff": ruff, "mypy": mypy}.items()
            }
        },
        "budgets": {"per_run_usd": 4.0, "per_call_usd": 4.0},
    }
    policy_path = tmp_path / "policy.yaml"
    raw = yaml.safe_dump(data, sort_keys=True).encode()
    policy_path.write_bytes(raw)
    pins = tmp_path / "pins.yaml"
    pins.write_text(
        yaml.safe_dump(
            {
                "manifest_version": 1,
                "workers": {
                    "claude": {
                        "executable": str(claude),
                        "realpath": str(shared.resolve()),
                        "sha256": shared_sha,
                        "version": "2.1.273",
                        "pinned_at": "2026-09-15T00:00:00Z",
                    },
                    "judge": {
                        "executable": str(judge),
                        "realpath": str(shared.resolve()),
                        "sha256": shared_sha,
                        "version": "2.1.273",
                        "pinned_at": "2026-09-15T00:00:00Z",
                    },
                },
                "verify": {},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return LoadedPolicy(
        Policy.model_validate(data),
        policy_path,
        hashlib.sha256(raw).hexdigest(),
        pins,
        hashlib.sha256(pins.read_bytes()).hexdigest(),
    )


def test_detect_is_read_only_arm_aware_and_closes_alias_groups(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    task = tmp_path / "task.json"
    task.write_text(
        json.dumps(
            {
                "task_id": "t",
                "question": "q",
                "category": "plan",
                "snapshot": "snapshot",
                "battery": [["ruff", "check", "."]],
            }
        ),
        encoding="utf-8",
    )
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            corpus=None,
            task_files=[str(task.resolve())],
            arms=["single"],
            panel=["claude"],
            critics=[],
            judge="judge",
        )
    )

    report = detect(spec, loaded)
    by_id = {item.logical_id: item for item in report.items}
    assert by_id["claude"].status is DriftStatus.CLEAN
    assert by_id["judge"].status is DriftStatus.CLEAN
    assert by_id["judge"].used is True  # transitive alias closure with used claude
    assert by_id["grok"].status is DriftStatus.UNUSED_DRIFT
    assert by_id["verify.git"].used is True
    assert by_id["verify.ruff"].status is DriftStatus.USED_DRIFT
    assert by_id["verify.mypy"].used is False
    assert report.blocking is True
    assert report.policy_sha256 == loaded.sha256
    assert report.pins_sha256 == loaded.pins_sha256
    assert all(item.version == "UNKNOWN" for item in report.items)


def test_same_cli_on_distinct_executables_is_not_an_alias_group(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    judge_locator = Path(loaded.policy.workers["judge"].executable or "")
    distinct_judge = tmp_path / "bin" / "distinct-judge"
    distinct_judge.write_bytes((tmp_path / "bin" / "shared-claude").read_bytes())
    distinct_judge.chmod(0o755)
    judge_locator.unlink()
    judge_locator.symlink_to(distinct_judge.name)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )

    report = detect(spec, loaded)
    by_id = {item.logical_id: item for item in report.items}
    assert by_id["claude"].alias_group == ("claude",)
    assert by_id["judge"].alias_group == ("judge",)
    assert by_id["judge"].used is False
    assert by_id["judge"].status is DriftStatus.UNUSED_DRIFT

    state = tmp_path / "pin-state"
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=by_id["claude"].sha256 or "",
        state_dir=state,
        runner=CannedRunner([]),
    )
    assert registered.receipt.logical_ids == ["claude"]
    before = yaml.safe_load(loaded.pins_path.read_text(encoding="utf-8"))["workers"]["judge"]
    apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)
    after = yaml.safe_load(loaded.pins_path.read_text(encoding="utf-8"))["workers"]["judge"]
    assert after == before


def test_detect_treats_changed_realpath_with_identical_bytes_as_path_only_drift(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    shared = tmp_path / "bin" / "shared-claude"
    pins = yaml.safe_load(loaded.pins_path.read_text(encoding="utf-8"))
    pins["workers"]["claude"]["realpath"] = str(shared.resolve())
    pins["workers"]["judge"]["realpath"] = str(shared.resolve())
    loaded.pins_path.write_text(yaml.safe_dump(pins, sort_keys=True), encoding="utf-8")
    loaded = LoadedPolicy(
        loaded.policy,
        loaded.path,
        loaded.sha256,
        loaded.pins_path,
        hashlib.sha256(loaded.pins_path.read_bytes()).hexdigest(),
    )
    replacement = tmp_path / "bin" / "shared-claude-moved"
    replacement.write_bytes(shared.read_bytes())
    replacement.chmod(0o755)
    for locator in (tmp_path / "bin" / "claude", tmp_path / "bin" / "judge"):
        locator.unlink()
        locator.symlink_to(replacement.name)

    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    report = detect(spec, loaded)
    by_id = {item.logical_id: item for item in report.items}
    assert by_id["claude"].status is DriftStatus.USED_DRIFT
    assert by_id["claude"].sha256 == by_id["claude"].expected_sha256
    assert report.blocking


def test_detect_reports_missing_and_unsafe_paths_without_following_special_files(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    missing = Path(loaded.policy.workers["claude"].executable or "")
    missing.unlink()
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    report = detect(spec, loaded)
    claude = next(item for item in report.items if item.logical_id == "claude")
    assert claude.status is DriftStatus.MISSING
    assert claude.sha256 is None and report.blocking


@pytest.mark.parametrize(
    ("old", "new", "same_sha", "expected"),
    [
        ("2.1.3", "2.1.3", True, VersionClass.PATH_ONLY),
        ("2.1.3", "2.1.4", False, VersionClass.PATCH),
        ("2.1.3", "2.2.0", False, VersionClass.MINOR),
        ("2.1.3", "3.0.0", False, VersionClass.MAJOR),
        ("2.1.3", "2.1.2", False, VersionClass.DOWNGRADE),
        ("2.1.3", "2.1.3", False, VersionClass.SAME_VERSION_NEW_BYTES),
        ("2.1.3", "2.1.4-rc.1", False, VersionClass.PRERELEASE),
        ("UNKNOWN", "2.1.4", False, VersionClass.UNKNOWN),
        ("1.2", "1.2.1", False, VersionClass.UNKNOWN),
    ],
)
def test_version_classification_is_fail_closed(
    old: str, new: str, same_sha: bool, expected: VersionClass
) -> None:
    assert classify_version(old, new, same_sha=same_sha) is expected


def test_provider_manifests_are_specific_and_keep_unknowns_blocking() -> None:
    claude = provider_manifest("claude")
    assert claude.version_argv == ("--version",)
    assert claude.help_argv == ("--help",)
    assert claude.auth_argv == ("auth", "status", "--json")
    assert "--bare" in claude.forbidden_tokens
    assert claude.auto_publish_audit is False

    grok = provider_manifest("grok")
    assert grok.auth_argv is None and grok.auth_status == "UNKNOWN"
    assert "--disable-web-search" in grok.required_help_tokens

    codex = provider_manifest("codex")
    assert codex.help_argv == ("exec", "--help")
    assert codex.auth_argv == ("login", "status")
    assert codex.executed_identity == "UNKNOWN"

    agy = provider_manifest("agy")
    assert agy.version_argv is None
    assert agy.execution_forbidden is True
    assert agy.auto_publish_audit is False

    with pytest.raises(ValueError, match="unsupported provider manifest"):
        provider_manifest("unknown")

    assert verification_manifest("git").version_argv == ("--version",)
    assert verification_manifest("ruff").help_argv == ("check", "--help")
    assert verification_manifest("mypy").help_argv == ("--help",)
    assert verification_manifest("pytest").version_argv == ("--version",)
    with pytest.raises(ValueError, match="unsupported verification manifest"):
        verification_manifest("unknown")


class CannedRunner:
    def __init__(self, outputs: list[bytes]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[list[str], dict[str, str], Path]] = []

    def __call__(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: Path,
        timeout_s: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> CommandResult:
        self.calls.append((argv, env, cwd))
        return CommandResult(0, self.outputs.pop(0), b"CANARY-RAW-STDERR", False, False, False)


def test_verify_path_only_registers_eligible_receipt_without_executing_candidate(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    task = tmp_path / "task.json"
    task.write_text(
        json.dumps(
            {
                "task_id": "t",
                "question": "q",
                "category": "plan",
                "snapshot": "snapshot",
            }
        ),
        encoding="utf-8",
    )
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            corpus=None,
            task_files=[str(task.resolve())],
            arms=["single"],
            panel=["claude"],
            critics=[],
        )
    )
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    runner = CannedRunner([])

    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=tmp_path / "pin-state",
        runner=runner,
    )
    assert registered.receipt.decision is Decision.ELIGIBLE
    assert registered.receipt.version_class is VersionClass.PATH_ONLY
    assert registered.receipt.probe_count == 0
    assert runner.calls == []
    assert registered.path.name == registered.sha256 + ".json"
    assert hashlib.sha256(registered.path.read_bytes()).hexdigest() == registered.sha256


def test_verify_changed_claude_projects_typed_checks_and_never_persists_raw_output(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    candidate_path = tmp_path / "bin" / "shared-claude"
    candidate_path.write_bytes(b"new-claude")
    candidate = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    manifest = provider_manifest("claude")
    help_text = " ".join(sorted(manifest.required_help_tokens)).encode()
    runner = CannedRunner(
        [
            b"2.1.274 (Claude Code)\n",
            help_text,
            b'{"loggedIn":true,"email":"CANARY-RAW-EMAIL"}',
        ]
    )

    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=tmp_path / "pin-state",
        runner=runner,
    )
    receipt = registered.receipt
    assert receipt.decision is Decision.REVIEW_REQUIRED  # old version/audit remains UNKNOWN/off
    assert receipt.candidate_version == "2.1.274"
    assert receipt.stable_bracket
    assert receipt.model_executed == "UNKNOWN"
    assert receipt.checks and all(check.status is CheckStatus.PASS for check in receipt.checks)
    persisted = registered.path.read_text(encoding="utf-8")
    assert "CANARY-RAW" not in persisted and "email" not in persisted
    assert len(runner.calls) == 3
    assert all(call[1] is not None and "PYTHONPATH" not in call[1] for call in runner.calls)


def test_verify_projects_forbidden_canonical_argv_as_a_failed_manifest_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import eris.refresh as refresh_module

    loaded = _loaded_policy(tmp_path)
    candidate_path = tmp_path / "bin" / "shared-claude"
    candidate_path.write_bytes(b"new-claude")
    candidate = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    manifest = provider_manifest("claude")
    runner = CannedRunner(
        [
            b"2.1.274 (Claude Code)",
            " ".join(sorted(manifest.required_help_tokens)).encode(),
            b'{"loggedIn":true}',
        ]
    )
    monkeypatch.setattr(
        refresh_module,
        "plan_call",
        lambda _call: SimpleNamespace(
            argv=[str(candidate_path), "--bare", "REFRESH_MANIFEST_CHECK"],
            prompt_index=2,
        ),
    )

    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=tmp_path / "pin-state",
        runner=runner,
    )

    check = next(item for item in registered.receipt.checks if item.name == "canonical_argv")
    assert check.status is CheckStatus.FAIL
    assert check.code == "FORBIDDEN_FLAG"
    assert registered.receipt.decision is Decision.REVIEW_REQUIRED


def test_verify_stops_when_candidate_identity_changes_during_a_check(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    candidate_path = tmp_path / "bin" / "shared-claude"
    candidate_path.write_bytes(b"new-claude")
    authorized_sha = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    calls = 0

    def replacing_runner(
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: Path,
        timeout_s: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> CommandResult:
        nonlocal calls
        calls += 1
        candidate_path.write_bytes(b"replacement-during-verification")
        return CommandResult(0, b"2.1.274", b"", False, False, False)

    with pytest.raises(RuntimeError, match="identity changed"):
        verify(
            spec,
            loaded,
            worker_id="claude",
            authorized_sha256=authorized_sha,
            state_dir=tmp_path / "pin-state",
            runner=replacing_runner,
        )

    assert calls == 1
    assert not (tmp_path / "pin-state" / "receipts").exists()


def test_live_probe_is_claimed_durably_before_call_and_never_retried(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    candidate_path = tmp_path / "bin" / "shared-claude"
    candidate_path.write_bytes(b"new-claude")
    candidate = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    Path(spec.env_file).write_text("", encoding="utf-8")
    manifest = provider_manifest("claude")
    offline = CannedRunner(
        [
            b"2.1.274 (Claude Code)",
            " ".join(sorted(manifest.required_help_tokens)).encode(),
            b'{"loggedIn":true}',
        ]
    )
    probe_calls = 0

    def probe(_call: object) -> LiveProbeResult:
        nonlocal probe_calls
        probe_calls += 1
        claims = list((tmp_path / "pin-state" / "probe-claims").glob("*.json"))
        assert len(claims) == 1  # durable claim-before-call, not a later receipt annotation
        return LiveProbeResult(True, "OK", "claude-fable-5", 0.01, True)

    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=tmp_path / "pin-state",
        runner=offline,
        live_probe=True,
        live_probe_runner=probe,
    )
    assert registered.receipt.probe_count == 1
    assert registered.receipt.model_executed == "claude-fable-5"
    assert registered.receipt.reported_cost_usd == 0.01
    assert registered.receipt.cost_ceiling_enforced is True
    assert probe_calls == 1

    with pytest.raises(RuntimeError, match="already claimed"):
        verify(
            spec,
            loaded,
            worker_id="claude",
            authorized_sha256=candidate,
            state_dir=tmp_path / "pin-state",
            runner=CannedRunner(
                [
                    b"2.1.274 (Claude Code)",
                    " ".join(sorted(manifest.required_help_tokens)).encode(),
                    b'{"loggedIn":true}',
                ]
            ),
            live_probe=True,
            live_probe_runner=probe,
        )
    assert probe_calls == 1


def test_secret_shaped_mismatched_live_probe_identity_is_not_persisted(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    candidate_path = tmp_path / "bin" / "shared-claude"
    candidate_path.write_bytes(b"new-claude")
    candidate = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    Path(spec.env_file).write_text("", encoding="utf-8")
    manifest = provider_manifest("claude")
    offline = CannedRunner(
        [
            b"2.1.274 (Claude Code)",
            " ".join(sorted(manifest.required_help_tokens)).encode(),
            b'{"loggedIn":true}',
        ]
    )
    secret_identity = "sk-proj-" + "S" * 32

    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=tmp_path / "pin-state",
        runner=offline,
        live_probe=True,
        live_probe_runner=lambda call: LiveProbeResult(
            False,
            "PROBE_CONTRACT_FAILED",
            secret_identity,
            None,
            True,
        ),
    )

    assert registered.receipt.decision is Decision.REVIEW_REQUIRED
    assert registered.receipt.model_executed == "UNKNOWN"
    assert secret_identity.encode() not in registered.path.read_bytes()


def test_verify_authority_mismatch_or_unused_worker_executes_nothing(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    runner = CannedRunner([])
    with pytest.raises(RuntimeError, match="authority"):
        verify(
            spec,
            loaded,
            worker_id="claude",
            authorized_sha256="f" * 64,
            state_dir=tmp_path / "pin-state",
            runner=runner,
        )
    with pytest.raises(RuntimeError, match="unused"):
        verify(
            spec,
            loaded,
            worker_id="grok",
            authorized_sha256="0" * 64,
            state_dir=tmp_path / "pin-state",
            runner=runner,
        )
    assert runner.calls == []


@pytest.mark.parametrize("unsafe_shape", ["hardlink", "fifo"])
def test_verify_refuses_unsafe_candidate_paths_before_execution(
    tmp_path: Path, unsafe_shape: str
) -> None:
    if unsafe_shape == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is unavailable on this platform")
    loaded = _loaded_policy(tmp_path)
    locator = Path(loaded.policy.workers["claude"].executable or "")
    candidate = tmp_path / "bin" / "shared-claude"
    authorized_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if unsafe_shape == "hardlink":
        os.link(candidate, tmp_path / "bin" / "shared-claude-hardlink")
    else:
        locator.unlink()
        os.mkfifo(locator)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    runner = CannedRunner([])

    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        verify(
            spec,
            loaded,
            worker_id="claude",
            authorized_sha256=authorized_sha,
            state_dir=tmp_path / "pin-state",
            runner=runner,
        )

    assert runner.calls == []
    assert not (tmp_path / "pin-state" / "receipts").exists()


@pytest.mark.parametrize("unsafe_shape", ["hardlink", "fifo"])
def test_apply_rederives_and_refuses_candidate_paths_that_became_unsafe(
    tmp_path: Path, unsafe_shape: str
) -> None:
    if unsafe_shape == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is unavailable on this platform")
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = tmp_path / "bin" / "shared-claude"
    authorized_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=authorized_sha,
        state_dir=state,
        runner=CannedRunner([]),
    )
    prior_pins = loaded.pins_path.read_bytes()
    if unsafe_shape == "hardlink":
        os.link(candidate, tmp_path / "bin" / "shared-claude-hardlink")
    else:
        locator = Path(loaded.policy.workers["claude"].executable or "")
        locator.unlink()
        os.mkfifo(locator)

    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)

    assert loaded.pins_path.read_bytes() == prior_pins
    assert not (state / "consumed" / registered.sha256).exists()


def test_apply_consumes_registered_receipt_and_updates_alias_group_atomically(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    loaded.pins_path.chmod(0o644)
    assert stat.S_IMODE(loaded.pins_path.stat().st_mode) == 0o644
    task = tmp_path / "task.json"
    task.write_text(
        json.dumps({"task_id": "t", "question": "q", "category": "plan", "snapshot": "snapshot"}),
        encoding="utf-8",
    )
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            corpus=None,
            task_files=[str(task.resolve())],
            arms=["single"],
            panel=["claude"],
            critics=[],
        )
    )
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    state = tmp_path / "pin-state"
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )

    result = apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)
    assert result.status == "REFRESHED"
    pins = yaml.safe_load(loaded.pins_path.read_text(encoding="utf-8"))
    assert pins["workers"]["claude"]["sha256"] == candidate
    assert pins["workers"]["judge"]["sha256"] == candidate
    assert pins["workers"]["claude"]["realpath"].endswith("shared-claude")
    assert result.new_pins_sha256 == hashlib.sha256(loaded.pins_path.read_bytes()).hexdigest()
    assert stat.S_IMODE(loaded.pins_path.stat().st_mode) == 0o600
    assert (state / "consumed" / registered.sha256).is_file()
    assert (state / "history" / f"{loaded.pins_sha256}.yaml").is_file()

    with pytest.raises(RuntimeError, match="consumed"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
def test_apply_refuses_group_or_other_writable_pins(tmp_path: Path, mode: int) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    loaded.pins_path.chmod(mode)

    with pytest.raises(RuntimeError, match="group/other writable"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


def test_apply_refuses_symlinked_pins(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    target = tmp_path / "pins-target.yaml"
    loaded.pins_path.replace(target)
    loaded.pins_path.symlink_to(target.name)

    with pytest.raises(RuntimeError, match="cannot safely open regular file"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


@pytest.mark.parametrize("replacement", ["hardlink", "directory"])
def test_apply_refuses_hardlinked_or_special_pins(tmp_path: Path, replacement: str) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    if replacement == "hardlink":
        os.link(loaded.pins_path, tmp_path / "pins-hardlink.yaml")
    else:
        loaded.pins_path.unlink()
        loaded.pins_path.mkdir()

    with pytest.raises(RuntimeError, match="regular file with exactly one hard link"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


def test_apply_refuses_pins_owned_by_another_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import eris.refresh as refresh_module

    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    real_fstat = os.fstat
    pins_identity = (loaded.pins_path.stat().st_dev, loaded.pins_path.stat().st_ino)

    def foreign_owner(fd: int) -> os.stat_result | SimpleNamespace:
        observed = real_fstat(fd)
        if (observed.st_dev, observed.st_ino) != pins_identity:
            return observed
        return SimpleNamespace(
            st_mode=observed.st_mode,
            st_nlink=observed.st_nlink,
            st_uid=observed.st_uid + 1,
        )

    monkeypatch.setattr(refresh_module.os, "fstat", foreign_owner)
    with pytest.raises(RuntimeError, match="owned by the current user"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


def test_apply_keeps_registered_receipts_owner_private(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    (state / "receipts" / f"{registered.sha256}.json").chmod(0o644)

    with pytest.raises(RuntimeError, match="private state file"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


def test_apply_refuses_unregistered_and_noneligible_receipts(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    with pytest.raises(RuntimeError, match="registered"):
        apply(spec, loaded, receipt_sha256="a" * 64, state_dir=state)

    candidate_path = tmp_path / "bin" / "shared-claude"
    candidate_path.write_bytes(b"changed")
    candidate = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    manifest = provider_manifest("claude")
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner(
            [
                b"2.1.274 (Claude Code)",
                " ".join(manifest.required_help_tokens).encode(),
                b'{"loggedIn":true}',
            ]
        ),
    )
    assert registered.receipt.decision is Decision.REVIEW_REQUIRED
    with pytest.raises(RuntimeError, match="not eligible"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)


def test_apply_refuses_windows_before_any_state_or_pin_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import eris.refresh as refresh_module

    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    prior = loaded.pins_path.read_bytes()
    monkeypatch.setattr(refresh_module.os, "name", "nt")

    with pytest.raises(RuntimeError, match="refused on Windows"):
        apply(spec, loaded, receipt_sha256="a" * 64, state_dir=tmp_path / "pin-state")

    assert loaded.pins_path.read_bytes() == prior
    assert not (tmp_path / "pin-state").exists()


def test_apply_exclusive_create_lock_refuses_a_concurrent_writer(tmp_path: Path) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    prior = loaded.pins_path.read_bytes()
    lock = state / "refresh.lock"
    lock.write_text("concurrent writer", encoding="utf-8")
    lock.chmod(0o600)

    with pytest.raises(RuntimeError, match="never automatically broken"):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)

    assert loaded.pins_path.read_bytes() == prior
    assert lock.read_text(encoding="utf-8") == "concurrent writer"
    assert not (state / "consumed" / registered.sha256).exists()


def test_agy_verify_and_apply_are_both_refused_without_execution_or_pin_write(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    agy_path = tmp_path / "bin" / "agy"
    agy_path.write_bytes(b"agy")
    agy_path.chmod(0o755)
    agy_sha = hashlib.sha256(agy_path.read_bytes()).hexdigest()
    agy_worker = loaded.policy.workers["claude"].model_copy(
        update={
            "cli": "agy",
            "provider": "google",
            "model": "gemini-3-pro-preview",
            "executable": str(agy_path),
            "executable_sha256": agy_sha,
        }
    )
    loaded = LoadedPolicy(
        loaded.policy.model_copy(
            update={
                "vendors_allowed": [*loaded.policy.vendors_allowed, "google"],
                "workers": {**loaded.policy.workers, "agy": agy_worker},
            }
        ),
        loaded.path,
        loaded.sha256,
        loaded.pins_path,
        loaded.pins_sha256,
    )
    pins = yaml.safe_load(loaded.pins_path.read_text(encoding="utf-8"))
    pins["workers"]["agy"] = {
        "executable": str(agy_path),
        "realpath": str(agy_path.resolve()),
        "sha256": agy_sha,
        "version": "1.1.18",
        "pinned_at": "2026-09-15T00:00:00Z",
    }
    loaded.pins_path.write_text(yaml.safe_dump(pins, sort_keys=True), encoding="utf-8")
    loaded = LoadedPolicy(
        loaded.policy,
        loaded.path,
        loaded.sha256,
        loaded.pins_path,
        hashlib.sha256(loaded.pins_path.read_bytes()).hexdigest(),
    )
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["agy"], critics=[])
    )
    state = tmp_path / "pin-state"
    runner = CannedRunner([])

    with pytest.raises(RuntimeError, match="execution is forbidden"):
        verify(
            spec,
            loaded,
            worker_id="agy",
            authorized_sha256=agy_sha,
            state_dir=state,
            runner=runner,
        )
    assert runner.calls == []

    state.mkdir(mode=0o700)
    receipts = state / "receipts"
    receipts.mkdir(mode=0o700)
    forged = VerifyReceiptV1(
        manifest_version=1,
        installation_id=hashlib.sha256(str(state.resolve()).encode()).hexdigest(),
        helper_revision=spec.candidate_revision,
        campaign_spec_sha256=spec.sha256,
        policy_sha256=loaded.sha256,
        old_pins_sha256=loaded.pins_sha256,
        logical_ids=["agy"],
        worker_id="agy",
        cli="agy",
        candidate_sha256=agy_sha,
        previous_sha256=agy_sha,
        candidate_realpath=str(agy_path.resolve()),
        previous_version="1.1.18",
        candidate_version="1.1.18",
        version_class=VersionClass.PATH_ONLY,
        checks=[],
        decision=Decision.ELIGIBLE,
        stable_bracket=True,
        probe_count=0,
        reported_cost_usd=None,
        cost_ceiling_enforced=False,
        model_requested="gemini-3-pro-preview",
        model_executed="UNKNOWN",
        created_at="2026-09-15T00:00:00Z",
    )
    raw = forged.canonical_bytes()
    receipt_sha = hashlib.sha256(raw).hexdigest()
    receipt_path = receipts / f"{receipt_sha}.json"
    receipt_path.write_bytes(raw)
    receipt_path.chmod(0o600)
    prior = loaded.pins_path.read_bytes()

    with pytest.raises(RuntimeError, match="execution is forbidden"):
        apply(spec, loaded, receipt_sha256=receipt_sha, state_dir=state)

    assert loaded.pins_path.read_bytes() == prior
    assert not (state / "consumed" / receipt_sha).exists()


def test_apply_postcheck_failure_restores_prior_generation_and_consumes_receipt(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    prior = loaded.pins_path.read_bytes()

    def fail_postcheck() -> None:
        raise RuntimeError("injected postcheck failure")

    with pytest.raises(RuntimeError, match="prior pins were restored"):
        apply(
            spec,
            loaded,
            receipt_sha256=registered.sha256,
            state_dir=state,
            postcheck=fail_postcheck,
        )
    assert loaded.pins_path.read_bytes() == prior
    assert not (state / "refresh.lock").exists()
    assert (state / "consumed" / registered.sha256).is_file()
    journal = json.loads((state / "transaction.json").read_text(encoding="utf-8"))
    assert journal["phase"] == "ROLLED_BACK"


def test_replace_then_directory_fsync_failure_retains_lock_without_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import eris.refresh as refresh_module

    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    real_fsync_dir = refresh_module._fsync_dir

    def fail_pins_directory(path: Path) -> None:
        if Path(path) == loaded.pins_path.parent:
            raise OSError("injected directory fsync failure")
        real_fsync_dir(path)

    monkeypatch.setattr(refresh_module, "_fsync_dir", fail_pins_directory)
    with pytest.raises(RefreshNotDurable):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)
    assert (state / "refresh.lock").is_file()
    journal = json.loads((state / "transaction.json").read_text(encoding="utf-8"))
    assert journal["phase"] == "REPLACING"


def test_fresh_no_receipt_preflight_refuses_retained_not_durable_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import eris.refresh as refresh_module

    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            policy_path=str(loaded.path.resolve()),
            arms=["single"],
            panel=["claude"],
            critics=[],
        )
    )
    state = tmp_path / "pin-state"
    candidate = hashlib.sha256((tmp_path / "bin" / "shared-claude").read_bytes()).hexdigest()
    registered = verify(
        spec,
        loaded,
        worker_id="claude",
        authorized_sha256=candidate,
        state_dir=state,
        runner=CannedRunner([]),
    )
    real_fsync_dir = refresh_module._fsync_dir

    def fail_pins_directory(path: Path) -> None:
        if Path(path) == loaded.pins_path.parent:
            raise OSError("injected directory fsync failure")
        real_fsync_dir(path)

    monkeypatch.setattr(refresh_module, "_fsync_dir", fail_pins_directory)
    with pytest.raises(RefreshNotDurable):
        apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)

    # A later invocation reloads the newly visible pins. The retained lock and
    # REPLACING journal must still refuse before any shell or dry-run command.
    reloaded = load_policy(loaded.path, loaded.pins_path)
    assert reloaded.pins_sha256 != loaded.pins_sha256
    spec_path = tmp_path / "campaign.json"
    spec_path.write_bytes(spec.canonical_bytes())
    rc = eris_main(
        [
            "policy",
            "refresh",
            "preflight",
            "--campaign-spec",
            str(spec_path),
            "--state-dir",
            str(state),
        ]
    )

    assert rc == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload["status"] == "MANIFEST_NOT_DURABLE"
    assert "retained refresh lock" in payload["error"]
    assert json.loads((state / "transaction.json").read_bytes())["phase"] == "REPLACING"


def test_path_only_verification_tool_receipt_can_update_only_verify_section(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    task = tmp_path / "task.json"
    task.write_text(
        json.dumps({"task_id": "t", "question": "q", "category": "plan", "snapshot": "s"}),
        encoding="utf-8",
    )
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            corpus=None,
            task_files=[str(task.resolve())],
            arms=["single"],
            panel=["claude"],
            critics=[],
        )
    )
    digest = hashlib.sha256((tmp_path / "bin" / "git").read_bytes()).hexdigest()
    state = tmp_path / "pin-state"
    registered = verify(
        spec,
        loaded,
        worker_id="verify.git",
        authorized_sha256=digest,
        state_dir=state,
        runner=CannedRunner([]),
    )
    assert registered.receipt.decision is Decision.ELIGIBLE
    result = apply(spec, loaded, receipt_sha256=registered.sha256, state_dir=state)
    pins = yaml.safe_load(loaded.pins_path.read_text(encoding="utf-8"))
    assert result.status == "REFRESHED"
    assert pins["verify"]["git"]["sha256"] == digest
    assert set(pins["workers"]) == {"claude", "judge"}


def test_preflight_runs_exact_source_scope_shell_gate_and_frozen_dry_run(
    tmp_path: Path,
) -> None:
    loaded = _loaded_policy(tmp_path)
    repo = tmp_path / "repo"
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            policy_path=str(loaded.path.resolve()),
            arms=["single"],
            panel=["claude"],
            critics=[],
        )
    )
    runner = CannedRunner(
        [
            (str(repo.resolve()) + "\n").encode(),
            (spec.candidate_revision + "\n").encode(),
            b"",
            b"preconditions passed",
            b"dry run",
            (str(repo.resolve()) + "\n").encode(),
            (spec.candidate_revision + "\n").encode(),
            b"",
        ]
    )

    result = preflight(spec, loaded, state_dir=tmp_path / "pin-state", runner=runner)
    assert result["status"] == "PREFLIGHT_PASS"
    shell_argv, shell_env, shell_cwd = runner.calls[3]
    assert shell_argv == ["/bin/bash", str(repo / "eval" / "live_preconditions.sh")]
    assert shell_env["ERIS_USED_WORKERS"] == "claude"
    assert shell_env["ERIS_USED_CLI_WORKERS"] == "claude,judge"
    assert shell_env["ERIS_CORPUS"] == spec.corpus
    assert json.loads(shell_env["ERIS_TASK_FILES_JSON"]) == []
    assert shell_env["CAMPAIGN_IDS"] == spec.campaign_id
    assert shell_env["SINGLE_RUN_IDS"] == ""
    assert shell_cwd == repo
    assert runner.calls[4][0] == spec.campaign_argv(python=sys.executable)


@pytest.mark.parametrize(
    "journal",
    [
        {"journal_version": 1, "phase": "PREPARED", "receipt_sha256": "a" * 64},
        {"phase": "COMMITTED"},
    ],
)
def test_preflight_refuses_nonterminal_or_uncertain_journal_before_commands(
    tmp_path: Path, journal: dict[str, object]
) -> None:
    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            policy_path=str(loaded.path.resolve()),
            arms=["single"],
            panel=["claude"],
            critics=[],
        )
    )
    state = tmp_path / "pin-state"
    state.mkdir(mode=0o700)
    transaction = state / "transaction.json"
    transaction.write_text(
        json.dumps(journal, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    transaction.chmod(0o600)
    runner = CannedRunner([b"unused"] * 8)

    with pytest.raises(RefreshNotDurable, match="journal"):
        preflight(spec, loaded, state_dir=state, runner=runner)

    assert runner.calls == []


def test_preflight_scopes_api_warnings_and_cli_credentials_by_exact_worker_policy(
    tmp_path: Path,
) -> None:
    from eris.doctor import run_doctor

    loaded = _loaded_policy(tmp_path)
    worker_type = type(loaded.policy.workers["claude"])
    api_used = worker_type.model_validate(
        {
            "transport": "api",
            "provider": "openai",
            "model": "gpt-test",
            "base_url": "https://api.openai.com/v1",
            "api_key_env": "OPENAI_API_KEY",
            "executable_sha256": "UNPINNED",
            "timeout_s": 60,
            "max_stdout_bytes": 1000,
        }
    )
    grok_path = tmp_path / "bin" / "grok"
    renamed_grok = loaded.policy.workers["grok"].model_copy(
        update={
            "executable_sha256": hashlib.sha256(grok_path.read_bytes()).hexdigest(),
            "env_allow": ["XAI_API_KEY"],
        }
    )
    workers = {
        "claude": loaded.policy.workers["claude"],
        "judge": loaded.policy.workers["judge"],
        "xai-cli": renamed_grok,
        "api-used": api_used,
        "api-unused": api_used,
    }
    loaded = LoadedPolicy(
        loaded.policy.model_copy(
            update={
                "vendors_allowed": [*loaded.policy.vendors_allowed, "openai"],
                "workers": workers,
            }
        ),
        loaded.path,
        loaded.sha256,
        loaded.pins_path,
        loaded.pins_sha256,
    )
    repo = tmp_path / "repo"
    spec = CampaignSpecV1.model_validate(
        _spec(
            tmp_path,
            policy_path=str(loaded.path.resolve()),
            arms=["single"],
            panel=["claude", "api-used", "xai-cli"],
            critics=[],
        )
    )
    runner = CannedRunner(
        [
            (str(repo.resolve()) + "\n").encode(),
            (spec.candidate_revision + "\n").encode(),
            b"",
            b"preconditions passed",
            b"dry run",
            (str(repo.resolve()) + "\n").encode(),
            (spec.candidate_revision + "\n").encode(),
            b"",
        ]
    )

    preflight(spec, loaded, state_dir=tmp_path / "pin-state", runner=runner)

    shell_env = runner.calls[3][1]
    assert shell_env["ERIS_USED_WORKERS"] == "claude,api-used,xai-cli"
    assert shell_env["ERIS_USED_CLI_WORKERS"] == "claude,judge,xai-cli"
    assert required_worker_credentials(loaded.policy, spec.used_worker_ids()) == {
        "api-used": ("OPENAI_API_KEY",),
        "xai-cli": ("XAI_API_KEY",),
    }
    verify_commands = {
        name: command.model_copy(
            update={
                "executable_sha256": hashlib.sha256(
                    Path(command.executable).read_bytes()
                ).hexdigest()
            }
        )
        for name, command in loaded.policy.verify.commands.items()
    }
    policy_for_doctor = loaded.policy.model_copy(
        update={
            "runs_dir": str(tmp_path / "doctor-runs"),
            "api_hosts_allowed": ["api.openai.com"],
            "verify": loaded.policy.verify.model_copy(update={"commands": verify_commands}),
        }
    )
    loaded.path.write_text(
        yaml.safe_dump(policy_for_doctor.model_dump(mode="json")), encoding="utf-8"
    )
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    env_file.chmod(0o600)
    doctor_output = run_doctor(
        policy_path=loaded.path,
        env_file=env_file,
        home=tmp_path,
        user_resolver=lambda: "test-user",
    ).render()
    assert "WARN worker.api-used:" in doctor_output
    assert "WARN worker.api-unused:" in doctor_output
    assert "WARN worker.xai-cli.env:" in doctor_output
    declared_worker_ids = tuple(loaded.policy.workers)
    assert not doctor_output_allows_preflight(
        doctor_output, spec.used_worker_ids(), declared_worker_ids
    )
    assert doctor_output_allows_preflight(doctor_output, ("claude",), declared_worker_ids)
    assert doctor_output_allows_preflight(
        "WARN worker.api-unused.env: missing key\ndoctor: WARN",
        ("api",),
        ("api", "api-unused"),
    )


def test_live_preconditions_uses_explicit_campaign_scope_without_running_bash() -> None:
    script = (Path(__file__).parents[1] / "eval" / "live_preconditions.sh").read_text(
        encoding="utf-8"
    )
    assert "ERIS_USED_WORKERS" in script
    assert "ERIS_CORPUS" in script
    assert "ERIS_TASK_FILES_JSON" in script
    assert 'json.loads(os.environ["ERIS_TASK_FILES_JSON"])' in script


def test_refresh_cli_exposes_explicit_live_probe_and_machine_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = build_parser().parse_args(
        [
            "policy",
            "refresh",
            "verify",
            "--campaign-spec",
            "campaign.json",
            "--worker",
            "claude",
            "--authorize-sha",
            "a" * 64,
            "--live-probe",
        ]
    )
    assert args.live_probe is True
    assert (
        eris_main(
            ["policy", "refresh", "detect", "--campaign-spec", str(tmp_path / "missing.json")]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["status"] == "ERROR"


def test_refresh_detect_cli_returns_zero_for_only_unused_drift_and_one_for_used_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import eris.cli as cli

    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(
        _spec(tmp_path, arms=["single"], panel=["claude"], critics=[])
    )
    monkeypatch.setattr(
        cli, "_refresh_inputs", lambda _args: (spec, loaded, tmp_path / "pin-state")
    )
    argv = ["policy", "refresh", "detect", "--campaign-spec", "ignored.json"]
    assert eris_main(argv) == 0
    capsys.readouterr()

    (tmp_path / "bin" / "shared-claude").write_bytes(b"used drift")
    assert eris_main(argv) == 1
    payload = json.loads(capsys.readouterr().out)
    assert any(item["status"] == "USED_DRIFT" for item in payload["items"])


def test_refresh_preflight_receipt_keeps_full_gate_inside_apply_rollback_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import eris.cli as cli
    import eris.policy as policy_module

    loaded = _loaded_policy(tmp_path)
    spec = CampaignSpecV1.model_validate(_spec(tmp_path, policy_path=str(loaded.path.resolve())))
    state = tmp_path / "pin-state"
    calls: list[str] = []

    monkeypatch.setattr(cli, "_refresh_inputs", lambda _args: (spec, loaded, state))
    monkeypatch.setattr(policy_module, "load_policy", lambda _path: loaded)

    def fake_preflight(
        _spec: object,
        _loaded: object,
        *,
        state_dir: Path,
        active_receipt_sha256: str,
    ) -> dict[str, str]:
        assert state_dir == state
        assert active_receipt_sha256 == "b" * 64
        calls.append("preflight")
        return {"status": "PREFLIGHT_PASS", "campaign_spec_sha256": spec.sha256}

    def fake_apply(
        _spec: object,
        _loaded: object,
        *,
        receipt_sha256: str,
        state_dir: Path,
        postcheck: object,
    ) -> object:
        assert receipt_sha256 == "b" * 64 and state_dir == state
        calls.append("apply")
        assert callable(postcheck)
        postcheck()
        return object()

    monkeypatch.setattr(cli, "preflight", fake_preflight)
    monkeypatch.setattr(cli, "apply_refresh", fake_apply)
    rc = eris_main(
        [
            "policy",
            "refresh",
            "preflight",
            "--campaign-spec",
            "ignored.json",
            "--receipt",
            "b" * 64,
        ]
    )
    assert rc == 0 and calls == ["apply", "preflight"]
    assert json.loads(capsys.readouterr().out)["status"] == "PREFLIGHT_PASS"
