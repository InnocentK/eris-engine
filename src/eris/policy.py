"""Declared workers, allowlists, budgets, vendors. Fails closed.

* ``extra="forbid"`` everywhere; ``executable_sha256``, ``timeout_s``,
  ``max_stdout_bytes`` and ``vendors_allowed`` are REQUIRED (no defaults).
* ``trusted`` defaults to ``False`` (verification may not execute repo code).
* Any secret-shaped string value anywhere in the YAML refuses the load.
* API workers must use an allowlisted host over https (http only for
  loopback).
* The policy file's sha256 is computed at load and recorded on every run.

Executable pins are machine-specific, so ``eris policy pin`` writes them to a
sidecar ``pins.yaml`` (gitignored) which the loader merges over the policy's
``UNPINNED`` placeholders. An unpinned worker loads but is refused at launch.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from eris.redact import scan
from eris.schemas import SHA256_PATTERN, Transport, now_ts

UNPINNED = "UNPINNED"
CliName = Literal["claude", "codex", "agy", "grok"]
ROLE_NAMES: frozenset[str] = frozenset({"proposer", "critic", "adjudicator", "summarizer"})
# Sanitization minimum (security R3.1): these names/dirs are stripped from a
# worker's private snapshot copy at ANY depth, case-insensitively, whatever
# the policy says (a policy may only ADD entries). Entries containing "/"
# match a relative path suffix (".github/copilot-instructions.md").
SANITIZE_MIN_NAMES: frozenset[str] = frozenset(
    {"AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", "GROK.md"}
)
SANITIZE_MIN_DIRS: frozenset[str] = frozenset(
    {
        ".agents",
        ".claude",
        ".codex",
        ".gemini",
        ".grok",
        ".antigravity",
        ".cursor",
        ".github/copilot-instructions.md",
    }
)
# Lineage guard: Antigravity's `agy` also serves Claude and GPT-OSS model ids
# (`agy models`, 2026-08-22). An agy worker must pin a Google model or the
# Google lineage of a panel could silently collapse into another vendor's.
# SYNTACTIC only: exact lowercase prefix, at least one non-space char after
# the dash, nothing before it. agy reports no executed model and may silently
# default (A9 log), so this cannot prove which model ran.
AGY_MODEL_PREFIX = "gemini-"
_AGY_MODEL_RE = re.compile(rf"^{re.escape(AGY_MODEL_PREFIX)}\S+$")
_SHA_RE = re.compile(SHA256_PATTERN)
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


class PolicyError(ValueError):
    """The policy cannot be loaded; nothing may run."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkerPolicy(_Strict):
    transport: Transport
    provider: str = Field(min_length=1)
    model: str | None = None
    # cli transport
    cli: CliName | None = None
    executable: str | None = None
    executable_sha256: str = Field(pattern=rf"^(?:{UNPINNED}|[0-9a-f]{{64}})$")
    # strict: "60", 60.0 and true are refused, not coerced (they feed timers and caps)
    timeout_s: int = Field(strict=True, ge=1, le=86_400)
    max_stdout_bytes: int = Field(strict=True, gt=0)
    max_stderr_bytes: int = Field(default=1_000_000, strict=True, gt=0)
    max_budget_usd: float | None = Field(default=None, gt=0)
    tools: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    env_allow: list[str] = Field(default_factory=list)
    # M2b: run proposer/critic roles on a private, sanitized copy of the
    # snapshot (instruction files stripped; see eris.sanitize). Verification
    # ALWAYS runs on the original. Per-role tool lists (the judge/summarizer
    # get none) override `tools` for that role.
    sanitize_snapshot: bool = False
    role_tools: dict[str, list[str]] = Field(default_factory=dict)
    # api transport
    base_url: str | None = None
    api_key_env: str | None = None

    @model_validator(mode="after")
    def _transport_fields(self) -> WorkerPolicy:
        if self.transport is Transport.CLI:
            if self.cli is None:
                raise ValueError("cli transport requires `cli`")
            if self.executable is not None and not Path(self.executable).is_absolute():
                raise ValueError("`executable` must be an absolute path")
            if self.base_url or self.api_key_env:
                raise ValueError("cli transport must not set base_url/api_key_env")
            if self.cli == "agy" and not _AGY_MODEL_RE.fullmatch(self.model or ""):
                raise ValueError(
                    f"lineage guard: cli `agy` requires `model` to start with "
                    f"{AGY_MODEL_PREFIX!r} (got {self.model!r}); agy also serves non-Google "
                    "models and an unpinned default would break the Google lineage"
                )
        else:
            if not self.base_url or not self.api_key_env:
                raise ValueError("api transport requires `base_url` and `api_key_env`")
            if self.cli or self.executable:
                raise ValueError("api transport must not set cli/executable")
        for name in (*self.env_allow, *self.env):
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                raise ValueError(f"env name {name!r} must be UPPER_SNAKE")
        for role in self.role_tools:
            if role not in ROLE_NAMES:
                raise ValueError(f"role_tools key {role!r} is not one of {sorted(ROLE_NAMES)}")
        return self

    def tools_for_role(self, role: str) -> list[str]:
        """The tool list for ``role`` (``role_tools`` overrides ``tools``)."""
        return list(self.role_tools.get(role, self.tools))

    @property
    def pinned(self) -> bool:
        return self.executable_sha256 != UNPINNED


class VerifyCommand(_Strict):
    executable: str
    executable_sha256: str = Field(pattern=rf"^(?:{UNPINNED}|[0-9a-f]{{64}})$")
    subcommands: list[str] = Field(default_factory=list)
    literal_flags: list[str] = Field(default_factory=list)
    value_flags: dict[str, str] = Field(default_factory=dict)
    positional: list[str] = Field(default_factory=list)
    max_args: int = Field(default=32, gt=0)
    requires_trusted: bool = False
    timeout_s: int = Field(default=600, gt=0)

    @model_validator(mode="after")
    def _regexes_compile(self) -> VerifyCommand:
        for rx in (*self.value_flags.values(), *(p for p in self.positional if p != "path")):
            try:
                re.compile(rx)
            except re.error as exc:
                raise ValueError(f"bad regex {rx!r}: {exc}") from exc
        if not Path(self.executable).is_absolute():
            raise ValueError("verify executable must be an absolute path")
        return self

    @property
    def pinned(self) -> bool:
        return self.executable_sha256 != UNPINNED


class VerifyPolicy(_Strict):
    commands: dict[str, VerifyCommand] = Field(default_factory=dict)
    max_output_bytes: int = Field(default=2_000_000, gt=0)
    # M2b evidence-request loop caps (per run): model-proposed commands
    # executed, and the wall-clock budget for all of them together.
    max_requests_per_run: int = Field(default=12, strict=True, ge=0, le=1000)
    max_wall_s: int = Field(default=1800, strict=True, ge=1, le=86_400)


class Budgets(_Strict):
    per_run_usd: float = Field(gt=0)
    per_call_usd: float = Field(gt=0)
    per_campaign_usd: float | None = Field(default=None, gt=0)


class SanitizePolicy(_Strict):
    """Extra names/dirs to strip from sanitized snapshot copies. The R3.1
    minimum (``SANITIZE_MIN_NAMES``/``SANITIZE_MIN_DIRS``) always applies."""

    strip_names: list[str] = Field(default_factory=list)
    strip_dirs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _entries_are_names(self) -> SanitizePolicy:
        for entry in (*self.strip_names, *self.strip_dirs):
            if not entry or entry in (".", "..") or entry.startswith("/") or "\x00" in entry:
                raise ValueError(f"sanitize entry {entry!r} must be a relative name")
        return self

    @property
    def effective_names(self) -> frozenset[str]:
        return SANITIZE_MIN_NAMES | frozenset(self.strip_names)

    @property
    def effective_dirs(self) -> frozenset[str]:
        return SANITIZE_MIN_DIRS | frozenset(self.strip_dirs)


class ScanPolicy(_Strict):
    """Extra contamination-scan strings (``eris.scan``); the key-derived
    patterns (source path, fix hunks) never live in a policy file."""

    patterns_from_policy: list[str] = Field(default_factory=list)


class Policy(_Strict):
    policy_version: str = Field(min_length=1)
    trusted: bool = False
    runs_dir: str = "runs"
    cache_dir: str = "cache"  # M2b: worker-call cache; NEVER under runs/
    path_env: str = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
    vendors_allowed: list[str] = Field(min_length=1)
    api_hosts_allowed: list[str] = Field(default_factory=list)
    credential_files: list[str] = Field(default_factory=list)
    workers: dict[str, WorkerPolicy]
    verify: VerifyPolicy = Field(default_factory=VerifyPolicy)
    budgets: Budgets
    sanitize: SanitizePolicy = Field(default_factory=SanitizePolicy)
    scan: ScanPolicy = Field(default_factory=ScanPolicy)

    @model_validator(mode="after")
    def _cross_checks(self) -> Policy:
        for name, w in self.workers.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
                raise ValueError(f"worker id {name!r} is not a valid record id")
            if w.provider not in self.vendors_allowed:
                raise ValueError(f"worker {name!r}: provider {w.provider!r} not in vendors_allowed")
            if w.transport is Transport.API and w.base_url is not None:
                _check_api_url(name, w.base_url, self.api_hosts_allowed)
        for label, value in (("runs_dir", self.runs_dir), ("cache_dir", self.cache_dir)):
            if not value or "\x00" in value:
                raise ValueError(f"{label} must be a non-empty path")
        if Path(self.cache_dir).resolve() == Path(self.runs_dir).resolve() or _is_under(
            Path(self.cache_dir), Path(self.runs_dir)
        ):
            raise ValueError("cache_dir must not be the runs dir or inside it")
        return self


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _check_api_url(name: str, url: str, hosts: list[str]) -> None:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host not in hosts:
        raise ValueError(f"worker {name!r}: host {host!r} not in api_hosts_allowed")
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and host in _LOOPBACK:
        return
    raise ValueError(f"worker {name!r}: base_url must be https (http only for loopback)")


# --------------------------------------------------------------------------- loading


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    path: Path
    sha256: str
    pins_path: Path
    pins_sha256: str | None


def _string_leaves(obj: Any, trail: str = "$") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            out.extend(_string_leaves(v, f"{trail}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_string_leaves(v, f"{trail}[{i}]"))
    elif isinstance(obj, str):
        out.append((trail, obj))
    return out


def refuse_secret_shaped(data: Any) -> None:
    for trail, value in _string_leaves(data):
        hits = scan(value)
        if hits:
            raise PolicyError(
                f"refusing to load: {trail} looks like a secret ({', '.join(hits)}). "
                "Secrets belong in .env only."
            )


def default_pins_path(policy_path: Path) -> Path:
    return policy_path.with_name("pins.yaml")


def _merge_pins(data: dict[str, Any], pins: Mapping[str, Any]) -> None:
    for section in ("workers", "verify"):
        entries = pins.get(section)
        if not isinstance(entries, Mapping):
            continue
        target = data.get(section)
        if section == "verify" and isinstance(target, Mapping):
            target = target.get("commands")
        if not isinstance(target, dict):
            continue
        for name, pin in entries.items():
            slot = target.get(name)
            if isinstance(slot, dict) and isinstance(pin, Mapping):
                if isinstance(pin.get("sha256"), str):
                    slot["executable_sha256"] = pin["sha256"]
                if isinstance(pin.get("executable"), str):
                    slot["executable"] = pin["executable"]


def load_policy(path: Path, pins_path: Path | None = None) -> LoadedPolicy:
    path = Path(path)
    pins_path = pins_path or default_pins_path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy {path} must be a mapping at top level")
    refuse_secret_shaped(data)
    pins_sha: str | None = None
    if pins_path.exists():
        pins_raw = pins_path.read_bytes()
        try:
            pins = yaml.safe_load(pins_raw)
        except yaml.YAMLError as exc:
            raise PolicyError(f"pins {pins_path} is not valid YAML: {exc}") from exc
        if not isinstance(pins, dict):
            raise PolicyError(f"pins {pins_path} must be a mapping")
        refuse_secret_shaped(pins)
        _merge_pins(data, pins)
        pins_sha = hashlib.sha256(pins_raw).hexdigest()
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"policy {path} rejected:\n{exc}") from exc
    return LoadedPolicy(policy, path, hashlib.sha256(raw).hexdigest(), pins_path, pins_sha)


# --------------------------------------------------------------------------- pinning


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class PinReport:
    pinned: dict[str, str]
    missing: list[str]
    pins_path: Path


def pin_executables(
    policy_path: Path,
    pins_path: Path | None = None,
    *,
    which: Callable[[str], str | None] | None = None,
) -> PinReport:
    """Compute sha256 of every declared executable and write ``pins.yaml``.

    Uses only ``which`` (injectable) and hashlib; never runs anything.
    Workers whose executable cannot be found are reported as missing and
    left UNPINNED (a recorded absence, never a substitution).
    """
    which = which or shutil.which  # resolved at call time (see doctor.run_doctor)
    loaded = load_policy(policy_path, pins_path)
    pins_path = loaded.pins_path
    pinned: dict[str, str] = {}
    missing: list[str] = []
    workers_out: dict[str, dict[str, str]] = {}
    verify_out: dict[str, dict[str, str]] = {}
    ts = now_ts()
    for name, w in loaded.policy.workers.items():
        if w.transport is not Transport.CLI or w.cli is None:
            continue
        exe = w.executable or which(w.cli)
        if exe is None or not Path(exe).is_file():
            missing.append(name)
            continue
        digest = sha256_file(Path(exe))
        workers_out[name] = {"executable": str(Path(exe)), "sha256": digest, "pinned_at": ts}
        pinned[name] = digest
    for name, cmd in loaded.policy.verify.commands.items():
        exe_path = Path(cmd.executable)
        if not exe_path.is_file():
            missing.append(f"verify.{name}")
            continue
        digest = sha256_file(exe_path)
        verify_out[name] = {"executable": str(exe_path), "sha256": digest, "pinned_at": ts}
        pinned[f"verify.{name}"] = digest
    payload = {"workers": workers_out, "verify": verify_out}
    pins_path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return PinReport(pinned, missing, pins_path)


def is_sha256(value: str) -> bool:
    return bool(_SHA_RE.fullmatch(value))
