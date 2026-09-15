"""Deterministic CLI drift detection and refresh contracts.

This module is operational configuration, not a ledger wire schema. Its JSON
models are independently versioned and fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from eris.arms import ARM_ORDER, ARM_STEPS, JUDGED_ARMS
from eris.evidence import TaskSpec
from eris.launch import WorkerCall, build_env, resolve_user, run_worker, spawn
from eris.policy import LoadedPolicy, load_policy, refuse_secret_shaped, sha256_file
from eris.schemas import SHA256_PATTERN, Arm, Stage, WorkerStatus, now_ts


class RefreshError(RuntimeError):
    """A refresh operation cannot proceed safely."""


class RefreshNotDurable(RefreshError):
    """A visible replacement could not be proved durable; retain lock/journal."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _load_strict_json(path: Path) -> Any:
    try:
        return json.loads(
            Path(path).read_bytes(),
            object_pairs_hook=_object_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {value}")
            ),
        )
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError(f"cannot load strict JSON {path}: {exc}") from exc


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class CampaignSpecV1(_StrictModel):
    """Exact source checkout and campaign inputs for one preflight."""

    spec_version: Literal[1]
    repo_root: str
    candidate_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    runner_path: Literal["eval/run.py"]
    runner_sha256: str = Field(pattern=SHA256_PATTERN)
    campaign_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    policy_path: str
    env_file: str
    prompts_dir: str
    runs_dir: str
    cache_dir: str
    corpus: str | None
    task_files: list[str]
    arms: list[Arm] = Field(min_length=1)
    repeats: int = Field(strict=True, ge=1)
    panel: list[str] = Field(min_length=1)
    critics: list[str]
    judge: str = Field(min_length=1)
    no_cache: StrictBool
    fresh: StrictBool
    reuse_across_campaigns: StrictBool

    @model_validator(mode="after")
    def _validate_contract(self) -> Self:
        paths = {
            "repo_root": self.repo_root,
            "policy_path": self.policy_path,
            "env_file": self.env_file,
            "prompts_dir": self.prompts_dir,
            "runs_dir": self.runs_dir,
            "cache_dir": self.cache_dir,
            **({"corpus": self.corpus} if self.corpus is not None else {}),
            **{f"task_files[{i}]": p for i, p in enumerate(self.task_files)},
        }
        for label, raw in paths.items():
            if not raw or "\x00" in raw or not Path(raw).is_absolute():
                raise ValueError(f"{label} must be a non-empty absolute path")
        if Path(self.repo_root).resolve() != Path(self.repo_root):
            raise ValueError("repo_root must be its canonical absolute realpath")
        if (self.corpus is None) == (not self.task_files):
            raise ValueError("exactly one of corpus or non-empty task_files is required")
        for label, values in (
            ("arms", [arm.value for arm in self.arms]),
            ("panel", self.panel),
            ("critics", self.critics),
            ("task_files", self.task_files),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must not contain duplicates")
        if self.no_cache and (self.fresh or self.reuse_across_campaigns):
            raise ValueError("no_cache contradicts fresh/reuse_across_campaigns")
        return self

    @classmethod
    def load(cls, path: Path) -> CampaignSpecV1:
        return cls.model_validate(_load_strict_json(path))

    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def ordered_arms(self) -> tuple[Arm, ...]:
        selected = set(self.arms)
        return tuple(arm for arm in ARM_ORDER if arm in selected)

    def used_worker_ids(self) -> tuple[str, ...]:
        out: list[str] = []

        def add_many(values: list[str] | tuple[str, ...]) -> None:
            for value in values:
                if value not in out:
                    out.append(value)

        add_many(self.panel)
        if Arm.INDEP_VERIFY_CRITIQUE in self.arms:
            add_many(self.critics)
        if any(arm in JUDGED_ARMS for arm in self.arms):
            add_many((self.judge,))
        return tuple(out)

    def campaign_argv(self, *, python: str) -> list[str]:
        argv = [
            python,
            str(Path(self.repo_root) / self.runner_path),
            "campaign",
            "--policy",
            self.policy_path,
            "--env-file",
            self.env_file,
            "--prompts-dir",
            self.prompts_dir,
            "--runs-dir",
            self.runs_dir,
            "--cache-dir",
            self.cache_dir,
        ]
        if self.no_cache:
            argv.append("--no-cache")
        if self.fresh:
            argv.append("--fresh")
        if self.reuse_across_campaigns:
            argv.append("--reuse-across-campaigns")
        argv += [
            "--panel",
            ",".join(self.panel),
            "--critics",
            ",".join(self.critics),
            "--judge",
            self.judge,
            "--campaign-id",
            self.campaign_id,
        ]
        if self.corpus is not None:
            argv += ["--corpus", self.corpus]
        else:
            for task_file in self.task_files:
                argv += ["--task-file", task_file]
        argv += [
            "--repeats",
            str(self.repeats),
            "--arms",
            ",".join(arm.value for arm in self.ordered_arms()),
            "--dry-run",
        ]
        return argv


class DriftStatus(StrEnum):
    CLEAN = "CLEAN"
    USED_DRIFT = "USED_DRIFT"
    UNUSED_DRIFT = "UNUSED_DRIFT"
    MISSING = "MISSING"
    UNSAFE_PATH = "UNSAFE_PATH"


class VersionClass(StrEnum):
    PATH_ONLY = "PATH_ONLY"
    PATCH = "PATCH"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    DOWNGRADE = "DOWNGRADE"
    PRERELEASE = "PRERELEASE"
    SAME_VERSION_NEW_BYTES = "SAME_VERSION_NEW_BYTES"
    UNKNOWN = "UNKNOWN"


_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def classify_version(old: str, new: str, *, same_sha: bool) -> VersionClass:
    old_match = _SEMVER_RE.fullmatch(old)
    new_match = _SEMVER_RE.fullmatch(new)
    if old_match is None or new_match is None:
        return VersionClass.UNKNOWN
    if old_match.group(4) is not None or new_match.group(4) is not None:
        return VersionClass.PRERELEASE
    old_parts = tuple(int(old_match.group(i)) for i in range(1, 4))
    new_parts = tuple(int(new_match.group(i)) for i in range(1, 4))
    if new_parts < old_parts:
        return VersionClass.DOWNGRADE
    if new_parts == old_parts:
        return VersionClass.PATH_ONLY if same_sha else VersionClass.SAME_VERSION_NEW_BYTES
    if new_parts[0] != old_parts[0]:
        return VersionClass.MAJOR
    if new_parts[1] != old_parts[1]:
        return VersionClass.MINOR
    return VersionClass.PATCH


@dataclass(frozen=True)
class ProviderManifest:
    cli: str
    version_argv: tuple[str, ...] | None
    help_argv: tuple[str, ...]
    auth_argv: tuple[str, ...] | None
    required_help_tokens: frozenset[str]
    forbidden_tokens: frozenset[str]
    auth_status: str
    executed_identity: str
    execution_forbidden: bool = False
    auto_publish_audit: bool = False


_MANIFESTS: dict[str, ProviderManifest] = {
    "claude": ProviderManifest(
        "claude",
        ("--version",),
        ("--help",),
        ("auth", "status", "--json"),
        frozenset(
            {
                "-p",
                "--safe-mode",
                "--permission-mode",
                "--tools",
                "--no-session-persistence",
                "--output-format",
                "--model",
                "--json-schema",
                "--max-budget-usd",
            }
        ),
        frozenset({"--bare", "bypassPermissions"}),
        "JSON_LOGGED_IN",
        "ENVELOPE_COUNTERS",
    ),
    "grok": ProviderManifest(
        "grok",
        ("--version",),
        ("--help",),
        None,
        frozenset(
            {
                "-p",
                "-m",
                "--permission-mode",
                "--disable-web-search",
                "--output-format",
                "--json-schema",
            }
        ),
        frozenset({"--dangerously-skip-permissions", "--full-auto"}),
        "UNKNOWN",
        "MODEL_USAGE",
    ),
    "codex": ProviderManifest(
        "codex",
        ("--version",),
        ("exec", "--help"),
        ("login", "status"),
        frozenset(
            {
                "-C",
                "-s",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "-c",
                "--skip-git-repo-check",
                "-m",
                "--json",
                "--output-schema",
                "-o",
            }
        ),
        frozenset({"workspace-write", "danger-full-access", "--full-auto"}),
        "TEXT_ONLY",
        "UNKNOWN",
    ),
    "agy": ProviderManifest(
        "agy",
        None,
        ("--help",),
        None,
        frozenset(
            {
                "-p",
                "--model",
                "--mode",
                "--sandbox",
                "--add-dir",
                "--output-format",
                "--disable-slash-commands",
                "--print-timeout",
                "--json-schema",
            }
        ),
        frozenset({"--continue", "--conversation", "accept-edits", "--log-file"}),
        "UNKNOWN",
        "UNKNOWN",
        execution_forbidden=True,
    ),
}


def provider_manifest(cli: str) -> ProviderManifest:
    try:
        return _MANIFESTS[cli]
    except KeyError:
        raise ValueError(f"unsupported provider manifest {cli!r}") from None


@dataclass(frozen=True)
class VerificationManifest:
    cli: str
    version_argv: tuple[str, ...]
    help_argv: tuple[str, ...]
    required_help_tokens: frozenset[str]
    auto_publish_audit: bool = False


_VERIFICATION_MANIFESTS: dict[str, VerificationManifest] = {
    "git": VerificationManifest(
        "git", ("--version",), ("help", "-a"), frozenset({"status", "diff", "rev-parse"})
    ),
    "ruff": VerificationManifest(
        "ruff", ("--version",), ("check", "--help"), frozenset({"--no-cache", "--output-format"})
    ),
    "mypy": VerificationManifest(
        "mypy", ("--version",), ("--help",), frozenset({"--no-incremental", "--cache-dir"})
    ),
    "pytest": VerificationManifest(
        "pytest", ("--version",), ("--help",), frozenset({"--basetemp", "--disable-warnings"})
    ),
}


def verification_manifest(cli: str) -> VerificationManifest:
    try:
        return _VERIFICATION_MANIFESTS[cli]
    except KeyError:
        raise ValueError(f"unsupported verification manifest {cli!r}") from None


class CheckStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class Decision(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNUSED_DRIFT = "UNUSED_DRIFT"


class CheckResultV1(_StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    status: CheckStatus
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


class VerifyReceiptV1(_StrictModel):
    manifest_version: Literal[1]
    installation_id: str = Field(pattern=SHA256_PATTERN)
    helper_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    campaign_spec_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    old_pins_sha256: str | None
    logical_ids: list[str] = Field(min_length=1)
    worker_id: str
    cli: str
    candidate_sha256: str = Field(pattern=SHA256_PATTERN)
    previous_sha256: str = Field(pattern=rf"^(?:UNKNOWN|{SHA256_PATTERN[1:-1]})$")
    candidate_realpath: str
    previous_version: str
    candidate_version: str
    version_class: VersionClass
    checks: list[CheckResultV1]
    decision: Decision
    stable_bracket: StrictBool
    probe_count: int = Field(strict=True, ge=0, le=1)
    reported_cost_usd: float | None = Field(default=None, ge=0)
    cost_ceiling_enforced: StrictBool
    model_requested: str | None
    model_executed: str
    created_at: str

    @model_validator(mode="after")
    def _non_secret_paths(self) -> Self:
        home = str(Path.home())
        if home and home in self.candidate_realpath:
            raise ValueError("receipt path must abbreviate the home directory")
        if not self.logical_ids or len(self.logical_ids) != len(set(self.logical_ids)):
            raise ValueError("logical_ids must be unique and non-empty")
        return self

    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.model_dump(mode="json"))


@dataclass(frozen=True)
class RegisteredReceipt:
    receipt: VerifyReceiptV1
    sha256: str
    path: Path


@dataclass(frozen=True)
class CommandResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: Path,
        timeout_s: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> CommandResult: ...


@dataclass(frozen=True)
class LiveProbeResult:
    """Typed projection returned by the fixed live probe; never raw model output."""

    passed: bool
    code: str
    model_executed: str
    reported_cost_usd: float | None
    cost_ceiling_enforced: bool


class LiveProbeRunner(Protocol):
    def __call__(self, call: WorkerCall) -> LiveProbeResult: ...


def _default_live_probe_runner(call: WorkerCall) -> LiveProbeResult:
    result = run_worker(call)
    model = result.model_executed or "UNKNOWN"
    exact_text = (result.text or "").strip() == "REFRESH_PROBE_OK"
    identity_ok = call.policy.cli == "codex" or model == call.policy.model
    cost_ok = True
    ceiling = False
    if call.policy.cli == "claude":
        ceiling = True
        cost_ok = result.cost_usd is not None and result.cost_usd <= 0.20
    elif call.policy.cli == "grok":
        cost_ok = result.cost_usd is not None
    passed = (
        result.status is WorkerStatus.OK
        and exact_text
        and identity_ok
        and result.usage is not None
        and cost_ok
        and not result.stdout_truncated
        and not result.stderr_truncated
        and not result.timed_out
    )
    return LiveProbeResult(
        passed,
        "OK" if passed else "PROBE_CONTRACT_FAILED",
        model,
        result.cost_usd,
        ceiling,
    )


def _default_runner(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_s: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> CommandResult:
    result = spawn(
        argv,
        env=env,
        cwd=cwd,
        timeout_s=timeout_s,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )
    return CommandResult(
        result.exit_code,
        result.stdout,
        result.stderr,
        result.stdout_truncated,
        result.stderr_truncated,
        result.timed_out,
    )


def _ensure_state_dir(path: Path) -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RefreshError("safe no-follow state writes are unsupported on this platform")
    if os.name == "nt":
        raise RefreshError("refresh state writes are refused on Windows until ACL controls exist")
    if path.is_symlink():
        raise RefreshError(f"state directory {path} is a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise RefreshError(f"state directory {path} must be an owner-private real directory")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_regular_nofollow(path: Path, *, private: bool = False) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RefreshError("safe no-follow reads are unsupported on this platform")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise RefreshError(f"cannot safely open regular file {path}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RefreshError(f"{path} must be a regular file with exactly one hard link")
        if private and stat.S_IMODE(st.st_mode) & 0o077:
            raise RefreshError(f"private state file {path} has group/other permissions")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _write_once_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise RefreshError(f"state path {path.parent} is a symlink")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        existing = _read_regular_nofollow(path, private=True)
        if existing != data:
            raise RefreshError(f"content-addressed state collision at {path}") from None
        return
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(path.parent)
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _candidate_version(cli: str, stdout: bytes) -> str:
    text = stdout.decode("utf-8", errors="replace").strip().splitlines()
    first = text[0] if text else ""
    patterns = {
        "claude": r"^(\d+\.\d+\.\d+)(?:\s.*)?$",
        "grok": r"^grok\s+(\d+\.\d+\.\d+)(?:\s|$).+\[stable\]$",
        "codex": r"^codex-cli\s+(\d+\.\d+\.\d+)$",
        "git": r"^git version\s+(\d+\.\d+\.\d+)(?:\s.*)?$",
        "ruff": r"^ruff\s+(\d+\.\d+\.\d+)$",
        "mypy": r"^mypy\s+(\d+\.\d+\.\d+)(?:\s.*)?$",
        "pytest": r"^pytest\s+(\d+\.\d+\.\d+)$",
    }
    match = re.fullmatch(patterns.get(cli, r"a^"), first)
    return match.group(1) if match else "UNKNOWN"


def _accepted_metadata(pins_path: Path, logical_id: str) -> tuple[str, str | None]:
    try:
        data = yaml.safe_load(pins_path.read_bytes())
        section, name = (
            ("verify", logical_id.removeprefix("verify."))
            if logical_id.startswith("verify.")
            else ("workers", logical_id)
        )
        entry = data.get(section, {}).get(name, {}) if isinstance(data, dict) else {}
        version = entry.get("version") if isinstance(entry, dict) else None
        realpath = entry.get("realpath") if isinstance(entry, dict) else None
    except (OSError, yaml.YAMLError):
        return "UNKNOWN", None
    accepted_version = (
        version if isinstance(version, str) and _SEMVER_RE.fullmatch(version) else "UNKNOWN"
    )
    accepted_realpath = realpath if isinstance(realpath, str) and realpath else None
    return accepted_version, accepted_realpath


def _claim_live_probe(
    state_dir: Path, *, cli: str, candidate_sha256: str, policy_sha256: str
) -> Path:
    key = hashlib.sha256(
        _canonical_json_bytes(
            {
                "cli": cli,
                "candidate_sha256": candidate_sha256,
                "manifest_version": 1,
                "policy_sha256": policy_sha256,
            }
        )
    ).hexdigest()
    path = state_dir / "probe-claims" / f"{key}.json"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = _canonical_json_bytes(
        {
            "claim_version": 1,
            "cli": cli,
            "candidate_sha256": candidate_sha256,
            "manifest_version": 1,
            "policy_sha256": policy_sha256,
        }
    )
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise RefreshError(f"live probe {key} was already claimed; it is never retried") from None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(path.parent)
    except BaseException:
        # Retain any claim that may have reached storage. Ambiguity must not
        # authorize a second model call.
        raise
    return path


def _reobserve_exact(item: Observation, authorized_sha256: str) -> Observation:
    current = _observe(
        item.logical_id,
        item.kind,
        item.cli,
        item.provider,
        Path(item.locator).expanduser(),
        item.expected_sha256,
        item.used,
    )
    if current.sha256 != authorized_sha256 or current.realpath != item.realpath:
        raise RefreshError("candidate identity changed; exact-SHA authority is no longer valid")
    return current


def verify(
    spec: CampaignSpecV1,
    loaded: LoadedPolicy,
    *,
    worker_id: str,
    authorized_sha256: str,
    state_dir: Path,
    runner: CommandRunner = _default_runner,
    live_probe: bool = False,
    live_probe_runner: LiveProbeRunner = _default_live_probe_runner,
) -> RegisteredReceipt:
    """Verify one exact observed SHA. Never writes the pin sidecar."""
    report = detect(spec, loaded)
    by_id = {item.logical_id: item for item in report.items}
    item = by_id.get(worker_id)
    if item is None:
        raise RefreshError(f"unknown worker {worker_id!r}")
    if not item.used:
        raise RefreshError(f"worker {worker_id!r} is unused by this campaign")
    if item.sha256 != authorized_sha256:
        raise RefreshError("candidate SHA does not match the explicit authority")
    if item.realpath is None or item.cli is None:
        raise RefreshError("candidate path is unavailable or unsafe")
    if item.kind == "worker":
        manifest: ProviderManifest | VerificationManifest = provider_manifest(item.cli)
    else:
        manifest = verification_manifest(item.cli)
    candidate_realpath = item.realpath
    if isinstance(manifest, ProviderManifest) and manifest.execution_forbidden:
        raise RefreshError(f"{item.cli} execution is forbidden pending a stable provider audit")
    if live_probe and (item.kind != "worker" or authorized_sha256 == item.expected_sha256):
        raise RefreshError("live probe is allowed only for changed provider bytes")
    checks: list[CheckResultV1] = []
    previous_version, _previous_realpath = _accepted_metadata(loaded.pins_path, worker_id)
    candidate_version = previous_version
    version_class = VersionClass.PATH_ONLY
    stable = True
    probe_count = 0
    reported_cost_usd: float | None = None
    cost_ceiling_enforced = False
    model_requested = loaded.policy.workers[worker_id].model if item.kind == "worker" else None
    model_executed = "UNKNOWN"
    if authorized_sha256 != item.expected_sha256:
        _ensure_state_dir(Path(state_dir))
        scratch = Path(tempfile.mkdtemp(prefix="verify-", dir=state_dir))
        try:
            before_files = {path.relative_to(scratch) for path in scratch.rglob("*")}
            if item.kind == "worker":
                worker = loaded.policy.workers[worker_id]
                env = build_env(
                    item.cli,
                    path_env=loaded.policy.path_env,
                    home=str(Path.home()),
                    tmpdir=str(scratch),
                    user=resolve_user(),
                    policy_env=worker.env,
                )
            else:
                from eris.verify import build_verify_env

                env = build_verify_env(path_env=loaded.policy.path_env, scratch_home=scratch)

            def run_check(name: str, suffix: tuple[str, ...]) -> CommandResult:
                _reobserve_exact(item, authorized_sha256)
                result = runner(
                    [str(Path(candidate_realpath).expanduser()), *suffix],
                    env=env,
                    cwd=scratch,
                    timeout_s=min(
                        loaded.policy.workers[worker_id].timeout_s
                        if item.kind == "worker"
                        else loaded.policy.verify.max_wall_s,
                        60,
                    ),
                    max_stdout_bytes=min(
                        loaded.policy.workers[worker_id].max_stdout_bytes
                        if item.kind == "worker"
                        else 1_000_000,
                        1_000_000,
                    ),
                    max_stderr_bytes=min(
                        loaded.policy.workers[worker_id].max_stderr_bytes
                        if item.kind == "worker"
                        else 1_000_000,
                        1_000_000,
                    ),
                )
                _reobserve_exact(item, authorized_sha256)
                ok = (
                    result.exit_code == 0
                    and not result.timed_out
                    and not result.stdout_truncated
                    and not result.stderr_truncated
                )
                checks.append(
                    CheckResultV1(
                        name=name,
                        status=CheckStatus.PASS if ok else CheckStatus.FAIL,
                        code="OK" if ok else "COMMAND_FAILED",
                    )
                )
                return result

            if manifest.version_argv is None:
                raise RefreshError(f"{item.cli} has no safe deterministic version command")
            version_result = run_check("version", manifest.version_argv)
            candidate_version = _candidate_version(item.cli, version_result.stdout)
            if candidate_version == "UNKNOWN":
                checks.append(
                    CheckResultV1(
                        name="version_parse", status=CheckStatus.UNKNOWN, code="UNKNOWN_VERSION"
                    )
                )
            else:
                checks.append(
                    CheckResultV1(name="version_parse", status=CheckStatus.PASS, code="OK")
                )
            help_result = run_check("help", manifest.help_argv)
            help_text = help_result.stdout.decode(
                "utf-8", errors="replace"
            ) + help_result.stderr.decode("utf-8", errors="replace")
            help_ok = all(token in help_text for token in manifest.required_help_tokens)
            checks.append(
                CheckResultV1(
                    name="required_flags",
                    status=CheckStatus.PASS if help_ok else CheckStatus.FAIL,
                    code="OK" if help_ok else "FLAG_MISSING",
                )
            )
            if isinstance(manifest, ProviderManifest):
                if manifest.auth_argv is None:
                    checks.append(
                        CheckResultV1(name="auth", status=CheckStatus.UNKNOWN, code="AUTH_UNKNOWN")
                    )
                else:
                    auth_result = run_check("auth_command", manifest.auth_argv)
                    auth_ok = False
                    if item.cli == "claude" and auth_result.exit_code == 0:
                        try:
                            auth_data = json.loads(auth_result.stdout)
                            auth_ok = (
                                isinstance(auth_data, dict) and auth_data.get("loggedIn") is True
                            )
                        except ValueError:
                            auth_ok = False
                    status_value = CheckStatus.PASS if auth_ok else CheckStatus.UNKNOWN
                    checks.append(
                        CheckResultV1(
                            name="auth",
                            status=status_value,
                            code="OK" if auth_ok else "AUTH_UNKNOWN",
                        )
                    )
            after_files = {path.relative_to(scratch) for path in scratch.rglob("*")}
            unexpected = after_files - before_files
            checks.append(
                CheckResultV1(
                    name="unexpected_files",
                    status=CheckStatus.FAIL if unexpected else CheckStatus.PASS,
                    code="UNEXPECTED_FILES" if unexpected else "OK",
                )
            )
            version_class = classify_version(
                previous_version,
                candidate_version,
                same_sha=authorized_sha256 == item.expected_sha256,
            )
        finally:
            shutil.rmtree(scratch)

        if live_probe:
            assert item.kind == "worker"
            _claim_live_probe(
                Path(state_dir),
                cli=item.cli,
                candidate_sha256=authorized_sha256,
                policy_sha256=loaded.sha256,
            )
            probe_root = Path(tempfile.mkdtemp(prefix="probe-", dir=state_dir))
            try:
                cwd = probe_root / "cwd"
                home = probe_root / "home"
                tmp = probe_root / "tmp"
                for path in (cwd, home, tmp):
                    path.mkdir(mode=0o700)
                marker = cwd / "MUST_NOT_EXIST"
                baseline = {path.relative_to(probe_root) for path in probe_root.rglob("*")}
                worker = loaded.policy.workers[worker_id].model_copy(
                    update={
                        "executable": str(Path(candidate_realpath).expanduser()),
                        "executable_sha256": authorized_sha256,
                    }
                )
                from eris.redact import parse_dotenv

                dotenv = parse_dotenv(Path(spec.env_file).read_text(encoding="utf-8"))
                secrets = {name: dotenv[name] for name in worker.env_allow if dotenv.get(name)}
                call = WorkerCall(
                    worker_id=worker_id,
                    policy=worker,
                    prompt=(
                        f"Attempt to create the file {marker}. The sandbox must deny it. "
                        "Then reply with exactly REFRESH_PROBE_OK and nothing else."
                    ),
                    cwd=cwd,
                    task_id="refresh-probe",
                    stage=Stage.PROPOSE,
                    repeat_index=0,
                    policy_sha256=loaded.sha256,
                    user=resolve_user(),
                    scratch_dir=tmp,
                    home=str(home),
                    tmpdir=str(tmp),
                    path_env=loaded.policy.path_env,
                    secrets=secrets,
                    snapshot_sha=hashlib.sha256(b"refresh-probe-empty-cwd-v1").hexdigest(),
                )
                _reobserve_exact(item, authorized_sha256)
                outcome = live_probe_runner(call)
                _reobserve_exact(item, authorized_sha256)
                unexpected = {
                    path.relative_to(probe_root) for path in probe_root.rglob("*")
                } - baseline
                passed = outcome.passed and not marker.exists() and not unexpected
                checks.append(
                    CheckResultV1(
                        name="live_probe",
                        status=CheckStatus.PASS if passed else CheckStatus.FAIL,
                        code="OK" if passed else outcome.code,
                    )
                )
                probe_count = 1
                reported_cost_usd = outcome.reported_cost_usd
                cost_ceiling_enforced = outcome.cost_ceiling_enforced
                model_executed = outcome.model_executed
            finally:
                shutil.rmtree(probe_root)

    all_pass = bool(checks) and all(check.status is CheckStatus.PASS for check in checks)
    eligible = version_class is VersionClass.PATH_ONLY or (
        version_class is VersionClass.PATCH and all_pass and manifest.auto_publish_audit
    )
    receipt = VerifyReceiptV1(
        manifest_version=1,
        installation_id=hashlib.sha256(str(Path(state_dir).resolve()).encode()).hexdigest(),
        helper_revision=spec.candidate_revision,
        campaign_spec_sha256=spec.sha256,
        policy_sha256=loaded.sha256,
        old_pins_sha256=loaded.pins_sha256,
        logical_ids=list(item.alias_group),
        worker_id=worker_id,
        cli=item.cli,
        candidate_sha256=authorized_sha256,
        previous_sha256=item.expected_sha256,
        candidate_realpath=candidate_realpath,
        previous_version=previous_version,
        candidate_version=candidate_version,
        version_class=version_class,
        checks=checks,
        decision=Decision.ELIGIBLE if eligible else Decision.REVIEW_REQUIRED,
        stable_bracket=stable,
        probe_count=probe_count,
        reported_cost_usd=reported_cost_usd,
        cost_ceiling_enforced=cost_ceiling_enforced,
        model_requested=model_requested,
        model_executed=model_executed,
        created_at=now_ts(),
    )
    _ensure_state_dir(Path(state_dir))
    data = receipt.canonical_bytes()
    digest = hashlib.sha256(data).hexdigest()
    path = Path(state_dir) / "receipts" / f"{digest}.json"
    _write_once_private(path, data)
    return RegisteredReceipt(receipt, digest, path)


@dataclass(frozen=True)
class ApplyResult:
    status: str
    old_pins_sha256: str
    new_pins_sha256: str
    receipt_sha256: str


def _atomic_replace_private(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise RefreshError(f"refusing to replace symlink {path}")
    if path.exists():
        existing = os.lstat(path)
        if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
            raise RefreshError(f"refusing to replace non-regular or hard-linked file {path}")
    temp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise
    try:
        _fsync_dir(path.parent)
    except OSError as exc:
        raise RefreshNotDurable(
            f"{path} was replaced but its directory fsync failed; durability is unknown"
        ) from exc


def _journal(state_dir: Path, phase: str, receipt_sha256: str, **extra: str) -> None:
    data = _canonical_json_bytes(
        {"journal_version": 1, "phase": phase, "receipt_sha256": receipt_sha256, **extra}
    )
    _atomic_replace_private(state_dir / "transaction.json", data)


def _acquire_lock(state_dir: Path, receipt_sha256: str) -> Path:
    lock = state_dir / "refresh.lock"
    data = _canonical_json_bytes(
        {"lock_version": 1, "receipt_sha256": receipt_sha256, "pid": os.getpid()}
    )
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise RefreshError(
            f"refresh lock {lock} exists; it is never automatically broken"
        ) from None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_dir(state_dir)
    except BaseException:
        # A lock whose durability is uncertain is retained: deleting it could
        # admit a second writer while the first transaction is ambiguous.
        raise
    return lock


def _release_lock(lock: Path) -> None:
    lock.unlink()
    _fsync_dir(lock.parent)


def bootstrap_write_pins(pins_path: Path, data: bytes) -> None:
    """Atomic, locked writer used only to add missing bootstrap pins."""
    pins_path = Path(pins_path)
    state_dir = pins_path.parent / "pin-state"
    _ensure_state_dir(state_dir)
    lock = _acquire_lock(state_dir, "0" * 64)
    replaced = False
    try:
        _journal(state_dir, "BOOTSTRAP_PREPARED", "0" * 64)
        _atomic_replace_private(pins_path, data)
        replaced = True
        _journal(
            state_dir,
            "BOOTSTRAP_COMMITTED",
            "0" * 64,
            new_pins_sha256=hashlib.sha256(data).hexdigest(),
        )
        _release_lock(lock)
    except RefreshNotDurable:
        raise
    except BaseException:
        if not replaced and lock.exists():
            try:
                _journal(state_dir, "BOOTSTRAP_BLOCKED", "0" * 64)
                _release_lock(lock)
            except BaseException:
                pass
        raise


def _registered_receipt(state_dir: Path, receipt_sha256: str) -> VerifyReceiptV1:
    if not re.fullmatch(SHA256_PATTERN, receipt_sha256):
        raise RefreshError("receipt digest is not a sha256")
    path = state_dir / "receipts" / f"{receipt_sha256}.json"
    if path.is_symlink() or not path.is_file():
        raise RefreshError(f"receipt {receipt_sha256} is not registered in local state")
    raw = _read_regular_nofollow(path, private=True)
    if hashlib.sha256(raw).hexdigest() != receipt_sha256:
        raise RefreshError("registered receipt bytes do not hash to their name")
    receipt = VerifyReceiptV1.model_validate(_load_strict_json(path))
    if receipt.canonical_bytes() != raw:
        raise RefreshError("registered receipt is not canonical JSON")
    return receipt


def _pins_mapping(raw: bytes) -> dict[str, Any]:
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RefreshError(f"pins sidecar is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RefreshError("pins sidecar must be a mapping")
    refuse_secret_shaped(data)
    for section in ("workers", "verify"):
        if section not in data:
            data[section] = {}
        if not isinstance(data[section], dict):
            raise RefreshError(f"pins {section} must be a mapping")
    return data


def apply(
    spec: CampaignSpecV1,
    loaded: LoadedPolicy,
    *,
    receipt_sha256: str,
    state_dir: Path,
    postcheck: Callable[[], None] | None = None,
) -> ApplyResult:
    """CAS-publish one registered full-PASS receipt, or refuse without weakening."""
    state_dir = Path(state_dir)
    _ensure_state_dir(state_dir)
    receipt = _registered_receipt(state_dir, receipt_sha256)
    consumed = state_dir / "consumed" / receipt_sha256
    if consumed.exists() or consumed.is_symlink():
        raise RefreshError(f"receipt {receipt_sha256} was already consumed")
    if receipt.decision is not Decision.ELIGIBLE:
        raise RefreshError("receipt is not eligible for automatic publication")
    if receipt.version_class is not VersionClass.PATH_ONLY:
        manifest = provider_manifest(receipt.cli)
        if (
            receipt.version_class is not VersionClass.PATCH
            or not manifest.auto_publish_audit
            or not receipt.checks
            or any(check.status is not CheckStatus.PASS for check in receipt.checks)
        ):
            raise RefreshError("receipt eligibility cannot be re-derived")
    if (
        receipt.campaign_spec_sha256 != spec.sha256
        or receipt.helper_revision != spec.candidate_revision
    ):
        raise RefreshError("receipt does not bind this exact campaign/source candidate")
    if receipt.policy_sha256 != loaded.sha256 or receipt.old_pins_sha256 != loaded.pins_sha256:
        raise RefreshError("receipt CAS does not match the loaded policy/pins")
    if receipt.installation_id != hashlib.sha256(str(state_dir.resolve()).encode()).hexdigest():
        raise RefreshError("receipt belongs to a different local installation")
    policy_now = hashlib.sha256(_read_regular_nofollow(loaded.path)).hexdigest()
    pins_raw = _read_regular_nofollow(loaded.pins_path, private=True)
    pins_now = hashlib.sha256(pins_raw).hexdigest()
    if policy_now != loaded.sha256 or pins_now != loaded.pins_sha256:
        raise RefreshError("policy or pins changed after receipt creation")

    report = detect(spec, loaded)
    item = next((entry for entry in report.items if entry.logical_id == receipt.worker_id), None)
    if (
        item is None
        or item.sha256 != receipt.candidate_sha256
        or item.realpath != receipt.candidate_realpath
    ):
        raise RefreshError("candidate changed after verification")
    if tuple(receipt.logical_ids) != item.alias_group:
        raise RefreshError("alias group changed after verification")
    if (
        receipt.version_class is VersionClass.PATH_ONLY
        and receipt.candidate_sha256 != receipt.previous_sha256
    ):
        raise RefreshError("path-only receipt changed executable bytes")

    lock = _acquire_lock(state_dir, receipt_sha256)
    replaced_durable = False
    try:
        _journal(state_dir, "PREPARED", receipt_sha256, old_pins_sha256=pins_now)
        _write_once_private(state_dir / "history" / f"{pins_now}.yaml", pins_raw)
        _write_once_private(consumed, _canonical_json_bytes({"receipt_sha256": receipt_sha256}))
        pins = _pins_mapping(pins_raw)
        workers = pins["workers"]
        verify_pins = pins["verify"]
        for logical_id in receipt.logical_ids:
            if logical_id.startswith("verify."):
                name = logical_id.removeprefix("verify.")
                command = loaded.policy.verify.commands.get(name)
                if command is None:
                    raise RefreshError(f"alias member {logical_id!r} is absent from policy")
                verify_pins[name] = {
                    "executable": command.executable,
                    "realpath": receipt.candidate_realpath,
                    "sha256": receipt.candidate_sha256,
                    "version": receipt.candidate_version,
                    "pinned_at": receipt.created_at,
                }
            else:
                policy_worker = loaded.policy.workers.get(logical_id)
                if policy_worker is None or policy_worker.executable is None:
                    raise RefreshError(f"alias member {logical_id!r} is absent from policy")
                workers[logical_id] = {
                    "executable": policy_worker.executable,
                    "realpath": receipt.candidate_realpath,
                    "sha256": receipt.candidate_sha256,
                    "version": receipt.candidate_version,
                    "pinned_at": receipt.created_at,
                }
        pins["manifest_version"] = 1
        refuse_secret_shaped(pins)
        new_raw = yaml.safe_dump(pins, sort_keys=True).encode("utf-8")
        # Strict policy reload against the candidate bytes before publication.
        candidate_path = (
            loaded.pins_path.parent / f".{loaded.pins_path.name}.validate-{uuid.uuid4().hex}"
        )
        fd = os.open(
            candidate_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as candidate_handle:
            candidate_handle.write(new_raw)
            candidate_handle.flush()
            os.fsync(candidate_handle.fileno())
        try:
            load_policy(loaded.path, candidate_path)
        finally:
            candidate_path.unlink(missing_ok=True)
        _journal(state_dir, "REPLACING", receipt_sha256, old_pins_sha256=pins_now)
        try:
            _atomic_replace_private(loaded.pins_path, new_raw)
        except RefreshNotDurable:
            # Deliberately retain nonterminal journal + lock. Neither generation
            # can be proved durable after replace plus failed directory fsync.
            raise
        replaced_durable = True
        new_sha = hashlib.sha256(new_raw).hexdigest()
        _journal(state_dir, "REPLACED_DURABLE", receipt_sha256, new_pins_sha256=new_sha)
        try:
            if postcheck is not None:
                postcheck()
            else:
                from eris.launch import preflight_executable

                refreshed = load_policy(loaded.path, loaded.pins_path)
                for logical_id in receipt.logical_ids:
                    if logical_id.startswith("verify."):
                        name = logical_id.removeprefix("verify.")
                        command = refreshed.policy.verify.commands[name]
                        real = Path(command.executable).resolve(strict=True)
                        if sha256_file(real) != command.executable_sha256:
                            raise RefreshError(f"verification executable {name!r} failed postcheck")
                    else:
                        preflight_executable(refreshed.policy.workers[logical_id])
        except BaseException as exc:
            _journal(state_dir, "ROLLING_BACK", receipt_sha256, new_pins_sha256=new_sha)
            try:
                _atomic_replace_private(loaded.pins_path, pins_raw)
            except BaseException as rollback_exc:
                raise RefreshError(
                    "postcheck failed and rollback could not be proved"
                ) from rollback_exc
            restored = hashlib.sha256(
                _read_regular_nofollow(loaded.pins_path, private=True)
            ).hexdigest()
            if restored != pins_now:
                raise RefreshError("postcheck failed and restored pins hash is wrong") from exc
            _journal(state_dir, "ROLLED_BACK", receipt_sha256, old_pins_sha256=pins_now)
            _release_lock(lock)
            raise RefreshError("postcheck failed; prior pins were restored") from exc
        _journal(state_dir, "COMMITTED", receipt_sha256, new_pins_sha256=new_sha)
        _release_lock(lock)
        return ApplyResult("REFRESHED", pins_now, new_sha, receipt_sha256)
    except RefreshNotDurable:
        raise
    except BaseException:
        if not replaced_durable and lock.exists():
            try:
                _journal(state_dir, "BLOCKED", receipt_sha256, old_pins_sha256=pins_now)
                _release_lock(lock)
            except BaseException:
                pass
        raise


@dataclass(frozen=True)
class Observation:
    logical_id: str
    kind: str
    cli: str | None
    provider: str | None
    used: bool
    locator: str
    symlink_target: str | None
    realpath: str | None
    file_identity: tuple[int, int] | None
    regular_file: bool
    sha256: str | None
    expected_sha256: str
    version: Literal["UNKNOWN"]
    status: DriftStatus
    alias_group: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectionReport:
    spec_sha256: str
    policy_sha256: str
    pins_sha256: str | None
    manifest_version: int
    items: tuple[Observation, ...]

    @property
    def blocking(self) -> bool:
        return any(
            item.used and item.status not in (DriftStatus.CLEAN, DriftStatus.UNUSED_DRIFT)
            for item in self.items
        )


def _display_path(path: Path) -> str:
    home = Path.home()
    try:
        return "~/" + str(path.relative_to(home))
    except ValueError:
        return str(path)


def _task_files(spec: CampaignSpecV1) -> list[Path]:
    if spec.task_files:
        return [Path(path) for path in spec.task_files]
    assert spec.corpus is not None
    out: list[Path] = []
    for path in sorted(Path(spec.corpus).glob("*/task.json")):
        task = TaskSpec.model_validate_json(path.read_bytes())
        if task.scored:
            out.append(path)
    return out


def used_verify_commands(spec: CampaignSpecV1, loaded: LoadedPolicy) -> frozenset[str]:
    """Verification executables the exact campaign can reach."""
    used = {"git"} if "git" in loaded.policy.verify.commands else set()
    for path in _task_files(spec):
        task = TaskSpec.model_validate_json(path.read_bytes())
        if task.diff_rev and "git" in loaded.policy.verify.commands:
            used.add("git")
        used.update(
            argv[0] for argv in task.battery if argv and argv[0] in loaded.policy.verify.commands
        )
    if any("verify" in ARM_STEPS[arm] or "verify2" in ARM_STEPS[arm] for arm in spec.arms):
        used.update(loaded.policy.verify.commands)
    return frozenset(used)


def _observe(
    logical_id: str,
    kind: str,
    cli: str | None,
    provider: str | None,
    locator: Path,
    expected_sha256: str,
    used: bool,
) -> Observation:
    display = _display_path(locator)
    try:
        locator_st = os.lstat(locator)
    except FileNotFoundError:
        return Observation(
            logical_id,
            kind,
            cli,
            provider,
            used,
            display,
            None,
            None,
            None,
            False,
            None,
            expected_sha256,
            "UNKNOWN",
            DriftStatus.MISSING,
        )
    target = os.readlink(locator) if stat.S_ISLNK(locator_st.st_mode) else None
    try:
        real = locator.resolve(strict=True)
        before = os.stat(real, follow_symlinks=False)
    except (FileNotFoundError, OSError, RuntimeError):
        return Observation(
            logical_id,
            kind,
            cli,
            provider,
            used,
            display,
            target,
            None,
            None,
            False,
            None,
            expected_sha256,
            "UNKNOWN",
            DriftStatus.UNSAFE_PATH,
        )
    regular = stat.S_ISREG(before.st_mode)
    if not regular:
        return Observation(
            logical_id,
            kind,
            cli,
            provider,
            used,
            display,
            target,
            _display_path(real),
            (before.st_dev, before.st_ino),
            False,
            None,
            expected_sha256,
            "UNKNOWN",
            DriftStatus.UNSAFE_PATH,
        )
    try:
        digest = sha256_file(real)
        after = os.stat(real, follow_symlinks=False)
    except OSError:
        digest = None
        after = before
    identity = (before.st_dev, before.st_ino)
    stable = (
        digest is not None
        and identity == (after.st_dev, after.st_ino)
        and before.st_nlink == after.st_nlink == 1
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
    )
    if not stable:
        status = DriftStatus.UNSAFE_PATH
    elif digest == expected_sha256:
        status = DriftStatus.CLEAN
    else:
        status = DriftStatus.USED_DRIFT if used else DriftStatus.UNUSED_DRIFT
    return Observation(
        logical_id,
        kind,
        cli,
        provider,
        used,
        display,
        target,
        _display_path(real),
        identity,
        True,
        digest,
        expected_sha256,
        "UNKNOWN",
        status,
    )


def detect(spec: CampaignSpecV1, loaded: LoadedPolicy) -> DetectionReport:
    """Observe exact paths and bytes without executing any candidate."""
    used_workers = set(spec.used_worker_ids())
    used_verify = used_verify_commands(spec, loaded)
    observed: list[Observation] = []
    for name, worker in loaded.policy.workers.items():
        if worker.cli is None or worker.executable is None:
            continue
        item = _observe(
            name,
            "worker",
            worker.cli,
            worker.provider,
            Path(worker.executable),
            worker.executable_sha256,
            name in used_workers,
        )
        _version, accepted_realpath = _accepted_metadata(loaded.pins_path, name)
        if (
            accepted_realpath is not None
            and item.status is DriftStatus.CLEAN
            and item.realpath != _display_path(Path(accepted_realpath).expanduser())
        ):
            item = replace(
                item, status=DriftStatus.USED_DRIFT if item.used else DriftStatus.UNUSED_DRIFT
            )
        observed.append(item)
    for name, command in loaded.policy.verify.commands.items():
        logical_id = f"verify.{name}"
        item = _observe(
            logical_id,
            "verify",
            name,
            None,
            Path(command.executable),
            command.executable_sha256,
            name in used_verify,
        )
        _version, accepted_realpath = _accepted_metadata(loaded.pins_path, logical_id)
        if (
            accepted_realpath is not None
            and item.status is DriftStatus.CLEAN
            and item.realpath != _display_path(Path(accepted_realpath).expanduser())
        ):
            item = replace(
                item, status=DriftStatus.USED_DRIFT if item.used else DriftStatus.UNUSED_DRIFT
            )
        observed.append(item)

    parent = list(range(len(observed)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        lroot, rroot = find(left), find(right)
        if lroot != rroot:
            parent[rroot] = lroot

    for left in range(len(observed)):
        for right in range(left + 1, len(observed)):
            a, b = observed[left], observed[right]
            same_worker_cli = a.kind == b.kind == "worker" and a.cli == b.cli
            same_file = (
                a.realpath is not None
                and a.realpath == b.realpath
                and a.file_identity is not None
                and a.file_identity == b.file_identity
            )
            if same_worker_cli or same_file:
                union(left, right)
    groups: dict[int, list[int]] = {}
    for index in range(len(observed)):
        groups.setdefault(find(index), []).append(index)
    final = list(observed)
    for indexes in groups.values():
        group_ids = tuple(sorted(observed[index].logical_id for index in indexes))
        group_used = any(observed[index].used for index in indexes)
        for index in indexes:
            item = observed[index]
            status = item.status
            if group_used and status is DriftStatus.UNUSED_DRIFT:
                status = DriftStatus.USED_DRIFT
            final[index] = replace(item, used=group_used, status=status, alias_group=group_ids)
    return DetectionReport(spec.sha256, loaded.sha256, loaded.pins_sha256, 1, tuple(final))


def _run_checked(
    runner: CommandRunner,
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_s: float = 120,
) -> CommandResult:
    result = runner(
        argv,
        env=env,
        cwd=cwd,
        timeout_s=timeout_s,
        max_stdout_bytes=1_000_000,
        max_stderr_bytes=1_000_000,
    )
    if (
        result.exit_code != 0
        or result.timed_out
        or result.stdout_truncated
        or result.stderr_truncated
    ):
        raise RefreshError(f"preflight command failed with exit {result.exit_code}")
    return result


def _validate_source_candidate(
    spec: CampaignSpecV1, loaded: LoadedPolicy, runner: CommandRunner
) -> None:
    from eris.verify import build_verify_env

    root = Path(spec.repo_root)
    runner_path = root / spec.runner_path
    if root.resolve(strict=True) != root or runner_path.is_symlink() or not runner_path.is_file():
        raise RefreshError("repository root/runner path is not canonical and regular")
    if sha256_file(runner_path) != spec.runner_sha256:
        raise RefreshError("campaign runner SHA differs from CampaignSpecV1")
    git = loaded.policy.verify.commands.get("git")
    if git is None or not git.pinned:
        raise RefreshError("policy-pinned git is required to bind the source candidate")
    git_path = Path(git.executable).resolve(strict=True)
    if sha256_file(git_path) != git.executable_sha256:
        raise RefreshError("git executable differs from its policy pin")
    scratch = Path(tempfile.mkdtemp(prefix="eris-refresh-source-"))
    try:
        env = build_verify_env(path_env=loaded.policy.path_env, scratch_home=scratch)
        observed_root = (
            _run_checked(
                runner,
                [str(git_path), "--no-optional-locks", "rev-parse", "--show-toplevel"],
                env=env,
                cwd=root,
            )
            .stdout.decode()
            .strip()
        )
        head = (
            _run_checked(
                runner,
                [str(git_path), "--no-optional-locks", "rev-parse", "HEAD"],
                env=env,
                cwd=root,
            )
            .stdout.decode()
            .strip()
        )
        status = _run_checked(
            runner,
            [str(git_path), "--no-optional-locks", "status", "--porcelain"],
            env=env,
            cwd=root,
        ).stdout
    finally:
        shutil.rmtree(scratch)
    if observed_root != spec.repo_root or head != spec.candidate_revision or status.strip():
        raise RefreshError("repository root, HEAD, or clean status differs from CampaignSpecV1")


def preflight(
    spec: CampaignSpecV1, loaded: LoadedPolicy, *, runner: CommandRunner = _default_runner
) -> dict[str, str]:
    """Run exact source, selected pin, scoped free, and frozen dry-run gates."""
    if os.name == "nt":
        raise RefreshError("preflight shell gate is refused on Windows in this milestone")
    _validate_source_candidate(spec, loaded, runner)
    report = detect(spec, loaded)
    if report.blocking:
        raise RefreshError("used executable drift blocks campaign preflight")
    from eris.launch import preflight_executable
    from eris.verify import build_verify_env

    for item in report.items:
        if item.used and item.kind == "worker":
            preflight_executable(loaded.policy.workers[item.logical_id])
    scratch = Path(tempfile.mkdtemp(prefix="eris-refresh-preflight-"))
    try:
        env = build_verify_env(path_env=loaded.policy.path_env, scratch_home=scratch)
        env.update(
            {
                "PY": sys.executable,
                "POLICY": spec.policy_path,
                "ENVFILE": spec.env_file,
                "ERIS_USED_WORKERS": ",".join(
                    item.logical_id for item in report.items if item.used and item.kind == "worker"
                ),
                "ERIS_CORPUS": spec.corpus or "",
                "ERIS_TASK_FILES_JSON": json.dumps(spec.task_files, separators=(",", ":")),
                "CAMPAIGN_IDS": spec.campaign_id,
                "SINGLE_RUN_IDS": "",
            }
        )
        _run_checked(
            runner,
            ["/bin/bash", str(Path(spec.repo_root) / "eval" / "live_preconditions.sh")],
            env=env,
            cwd=Path(spec.repo_root),
            timeout_s=600,
        )
        _run_checked(
            runner,
            spec.campaign_argv(python=sys.executable),
            env=env,
            cwd=Path(spec.repo_root),
            timeout_s=600,
        )
    finally:
        shutil.rmtree(scratch)
    _validate_source_candidate(spec, loaded, runner)
    if hashlib.sha256(loaded.pins_path.read_bytes()).hexdigest() != loaded.pins_sha256:
        raise RefreshError("pins changed during preflight")
    return {"status": "PREFLIGHT_PASS", "campaign_spec_sha256": spec.sha256}


__all__ = [
    "CampaignSpecV1",
    "CheckStatus",
    "CommandResult",
    "Decision",
    "DetectionReport",
    "DriftStatus",
    "LiveProbeResult",
    "Observation",
    "RefreshError",
    "RefreshNotDurable",
    "VersionClass",
    "apply",
    "classify_version",
    "detect",
    "preflight",
    "provider_manifest",
    "used_verify_commands",
    "verification_manifest",
    "verify",
]
