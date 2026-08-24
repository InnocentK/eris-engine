"""Evidence pack (built ONCE per (task, repeat) from the ORIGINAL snapshot)
and the model-proposed evidence-request loop.

The pack is what every panel member receives. Its items are
content-derived (``ev-<sha256[:16]>`` over kind/origin/argv/label/content)
so the pack is identical across arms and the proposer calls share an
idempotency key; the rendered pack carries NO timestamp and NO run id.
Items:

* the task question (``document_quote``, ``human_entered``);
* the plan text from ``task.json`` when present (``document_quote``,
  ``human_entered``) and/or the diff of ``diff_rev`` via ``git show``
  (``repo_fact``, ``mechanically_observed``);
* repo facts through :func:`eris.verify.run_allowlisted` (``git rev-parse
  HEAD``, ``git status --porcelain``, ``git ls-files``, ``git log --oneline
  -n 20``) and the task battery (``tool_output``);
* file excerpts named in ``task.json`` (capped; confined to the snapshot,
  never ``.git``, never through a symlink).

Every content byte goes through ``RunWriter.put_blob`` (redacted) BEFORE it
is hashed into an id or the pack; ``pack_sha256`` is the sha256 of the
rendered (redacted) pack, which is itself a blob of the run.

Evidence requests come ONLY from structured model output. Each request is
re-checked by ``check_command`` inside ``run_allowlisted`` on the ORIGINAL
snapshot; refusals are EVENTS (``verify.refused{argv, reason}``; the
challenge stays UNVERIFIED), duplicates by canonical argv are
``verify.duplicate``, the per-run cap (``verify.max_requests_per_run``) and
wall budget (``verify.max_wall_s``) refuse with a reason, STOP is checked
before EVERY command (:class:`EvidenceStopped`). ``scratch_home`` for the
commands is a ``make_private_dir`` under the run dir (after the writer
holds the lock) removed in ``finally``; a cleanup failure is a
``run.error`` AND raises :class:`EvidenceCleanupError`.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from eris.launch import KillPg, LaunchRefused, PopenFactory, make_private_dir, spawn
from eris.policy import Policy, sha256_file
from eris.sanitize import tree_sha256
from eris.schemas import (
    EvidenceItem,
    EvidenceKind,
    EvidencePack,
    EvidenceRequest,
    Origin,
    Phase,
    TaskCategory,
    canonical_bytes,
    now_ts,
    sha256_hex,
)
from eris.verify import (
    GIT_ERIS_GLOBALS,
    build_verify_env,
    check_command,
    run_allowlisted,
)
from eris.writer import BlobRef, RunWriter

PACK_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("git", "rev-parse", "HEAD"),
    ("git", "status", "--porcelain"),
    ("git", "ls-files"),
    ("git", "log", "--oneline", "-n", "20"),
)
EXCERPT_MAX_LINES = 200
ITEM_HEAD_BYTES = 48 * 1024
ITEM_TAIL_BYTES = 16 * 1024
NONCE_PREFIX = "eris-envelope"


class EvidenceError(RuntimeError):
    pass


class EvidenceStopped(EvidenceError):
    """A STOP file appeared; no further command is run."""


class EvidenceCleanupError(EvidenceError):
    """The verification scratch dir could not be removed (run.error written)."""


class NestedRepositoryRefused(EvidenceError):
    """The copy's index registers a SUBMODULE: it is a superproject, and Eris
    verifies one self-contained repository or none. A deliberate refusal, not a
    failure - the harness reports it as ``refused``."""


# --------------------------------------------------------------------------- task.json


class Excerpt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> Excerpt:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class TaskSpec(BaseModel):
    """``task.json``: what the harness (and the workers) may see. The answer
    key (``key.json``) is a different file: the harness opens it ONLY to
    derive contamination-scan patterns (hashed); it never reaches a prompt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    question: str = Field(min_length=1)
    category: TaskCategory
    snapshot: str = Field(min_length=1)
    battery: list[list[str]] = Field(default_factory=list)
    excerpts: list[Excerpt] = Field(default_factory=list)
    diff_rev: str | None = None
    plan_text: str | None = None
    # False = a PLUMBING task: it exercises the harness and is deliberately
    # excluded from Phase 0 metrics. Campaign discovery skips it and the
    # scorer refuses to score it. An explicit --task-file still runs it (that
    # is the whole point of a plumbing task). Default True so every real
    # corpus entry is scored unless someone opts out on purpose.
    scored: bool = True


def derive_nonce(
    *, snapshot_sha: str | None, task_id: str, repeat_index: int, stage: str, policy_sha256: str
) -> str:
    material = "|".join(
        [NONCE_PREFIX, snapshot_sha or "", task_id, str(repeat_index), stage, policy_sha256]
    )
    return sha256_hex(material.encode("utf-8"))[:32]


# --------------------------------------------------------------------------- items


@dataclass(frozen=True)
class PackItem:
    """One rendered item (redacted content). ``evidence_id`` is content-derived."""

    evidence_id: str
    kind: EvidenceKind
    origin: Origin
    label: str
    argv: list[str] | None
    exit_code: int | None
    content: str
    truncated: bool
    blob: BlobRef
    violated: bool = False

    def rendered(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "origin": self.origin.value,
            "label": self.label,
            "argv": self.argv,
            "exit_code": self.exit_code,
            "content": self.content,
            "truncated": self.truncated,
        }


def _cap(content: str) -> tuple[str, bool]:
    data = content.encode("utf-8")
    if len(data) <= ITEM_HEAD_BYTES + ITEM_TAIL_BYTES:
        return content, False
    head = data[:ITEM_HEAD_BYTES].decode("utf-8", errors="ignore")
    tail = data[-ITEM_TAIL_BYTES:].decode("utf-8", errors="ignore")
    return f"{head}\n…[{len(data) - len(head) - len(tail)} bytes elided]…\n{tail}", True


def _item(
    writer: RunWriter,
    *,
    kind: EvidenceKind,
    origin: Origin,
    label: str,
    content: bytes,
    argv: Sequence[str] | None,
    exit_code: int | None,
    violated: bool = False,
) -> PackItem:
    blob = writer.put_blob(content)  # redacted before anything is hashed or rendered
    redacted = blob.path.read_bytes().decode("utf-8", errors="replace")
    text, truncated = _cap(redacted)
    # id material: the executable's BASENAME (the resolved host path is a
    # fact for the record, not for the id - the same command on two hosts
    # must yield the same evidence id)
    id_argv = [Path(argv[0]).name, *argv[1:]] if argv else None
    material = {
        "kind": kind.value,
        "origin": origin.value,
        "label": label,
        "argv": id_argv,
        "exit_code": exit_code,
        "content_sha256": blob.sha256,
    }
    return PackItem(
        evidence_id=f"ev-{sha256_hex(canonical_bytes(material))[:16]}",
        kind=kind,
        origin=origin,
        label=label,
        argv=list(argv) if argv is not None else None,
        exit_code=exit_code,
        content=text,
        truncated=truncated,
        blob=blob,
        violated=violated,
    )


def _record(
    writer: RunWriter, item: PackItem, *, task_id: str, phase: Phase, ts: str
) -> EvidenceItem:
    record = EvidenceItem(
        origin=item.origin,
        evidence_id=item.evidence_id,
        task_id=task_id,
        kind=item.kind,
        phase=phase,
        content_sha256=item.blob.sha256,
        size_bytes=item.blob.size_bytes,
        created_at=ts,
        argv=item.argv,
        exit_code=item.exit_code,
        summary=item.label,
        redaction_counts=dict(item.blob.redaction_counts),
        violated=item.violated,
    )
    # the record later stages consume is the REDACTED one the writer persisted
    return EvidenceItem.model_validate(writer.append("evidence.item", record).payload)


# --------------------------------------------------------------------------- commands


# The ONLY paths the verification tripwire ignores BY BYTES. `.git/index` is
# git's stat cache, not history: a read-only command rewrites it (M2c defect B -
# `git status` did, which tripped the guard and refused every later command in
# the first live run; measured again 2026-08-24, `git diff`/`git diff HEAD`
# refresh it too, with or without `--no-optional-locks`). `.git/index.lock` is
# the transient file it writes it through.
#
# The exclusion is NOT a blind spot any more: the index is covered SEMANTICALLY
# by :func:`git_index_prober` (a digest of `git ls-files -s -v`), which is
# blind to the stat refresh and sensitive to real staging changes - `git add`
# and `git rm --cached` both move it (measured 2026-08-24). `git rm --cached`
# changes NOTHING else in the tree, so without the semantic digest it would be
# invisible.
#
# What the digest does NOT see is documented in `docs/SECURITY.md`: the index
# EXTENSIONS (untracked cache, fsmonitor, cache-tree, resolve-undo) live inside
# `.git/index`, which the byte hash excludes, and `ls-files` prints no trace of
# them - measured 2026-08-24, neither half of the guard moves for any of the
# four. Enabling the SPLIT index is caught, by the tree hash: it writes a new
# `.git/sharedindex.<sha>` file, which is not in the excluded set.
#
# Everything else under `.git` - refs, objects, HEAD, config, hooks - STAYS in
# the byte hash, so a command that rewrites history or config is still caught.
# Excluding `.git` wholesale would hide exactly that.
GUARD_EXCLUDED_RELPATHS: frozenset[str] = frozenset({".git/index", ".git/index.lock"})

# Eris-internal, FIXED argv. It is deliberately NOT routed through
# `check_command`/`run_allowlisted`: the model-facing allowlist governs
# model-proposed requests, and this command is neither proposed nor influenced
# by a model. (Neither `-s` nor `-v` is an allowlisted flag in the repo policy,
# so routing it there would refuse it.) The pin on the git executable is still
# enforced here, by hand.
#
# `-s` (= `--stage`) prints mode, blob sha, stage and path; `-v` prepends the
# per-entry STATUS LETTER in the SAME invocation - `H` cached, `S`
# skip-worktree, lowercase = assume-unchanged. Those flag bits change what
# `git status`/`git diff` report about a file without changing any staged
# content, so `--stage` alone left them silent (measured 2026-08-24, git
# 2.50.1: setting or clearing `--skip-worktree`/`--assume-unchanged` leaves the
# `--stage` digest byte-identical and moves the `-s -v` digest). The letter is
# NOT a working-tree comparison: an unstaged edit, and the stat refresh, both
# leave it `H`, so this costs no false positive.
#
# `-f` is the third flag, for the same reason `-v` is the second: `-v` alone is
# blind to the per-entry FSMONITOR-VALID bit, which makes git treat a file as
# unchanged. git-ls-files(1): "-f  Similar to -t, but use lowercase letters for
# files that are marked as fsmonitor valid". Measured 2026-08-24, git 2.50.1
# (`test_verify_real_git.py::test_every_index_mutation_trips_the_guard`, the
# two fsmonitor cases): with a `core.fsmonitor` hook returning a real token,
# `update-index --fsmonitor-valid`/`--no-fsmonitor-valid` move the `-s -v -f`
# digest and leave the `-s -v` digest byte-identical. Without an active
# fsmonitor the bit cannot be stored at all and `-f` prints exactly what `-v`
# prints, so this costs no false positive and no extra spawn - and the
# verification copy unsets `core.fsmonitor` anyway (`eris.sanitize`), which is
# what keeps a live daemon from marking entries valid mid-run.
GIT_INDEX_DIGEST_ARGS: tuple[str, ...] = (*GIT_ERIS_GLOBALS, "ls-files", "-s", "-v", "-f")

# What the guard is doing about `.git/index` for a given run.
INDEX_CHECK_SEMANTIC = "semantic"
INDEX_CHECK_BYTES_FALLBACK = "bytes_fallback"
INDEX_CHECK_NONE = "none"  # the copy has no `.git` directory: no index to guard

#: The octal mode `git ls-files -s` prints for a GITLINK - a submodule entry.
#: A repository that has one is a SUPERPROJECT, which Eris does not verify.
GITLINK_MODE = "160000"


@dataclass(frozen=True)
class IndexProbeResult:
    """What one run of :data:`GIT_INDEX_DIGEST_ARGS` tells the guard.

    ``digest`` is the tripwire's semantic index digest, unchanged. ``gitlinks``
    are the paths of any submodule entries in the same output - free, from the
    same spawn, because ``-s`` already prints the mode."""

    digest: str
    gitlinks: tuple[str, ...] = ()


#: ``(root) -> result``, or ``None`` when the probe cannot be taken (git
#: missing, unpinned, changed since the pin, non-zero exit, timeout).
IndexProbe = Callable[[Path], IndexProbeResult | None]


def _gitlink_paths(stdout: bytes) -> tuple[str, ...]:
    """Submodule entries in `ls-files -s -v -f` output, whose lines are
    ``<letter> <mode> <sha> <stage>\t<path>``. Anything that does not have
    that shape is ignored: this is a scope signal, and the DIGEST is what the
    tripwire relies on."""
    out: list[str] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        head, tab, path = line.partition("\t")
        fields = head.split()
        if tab and len(fields) == 4 and fields[1] == GITLINK_MODE:
            out.append(path)
    return tuple(out)


def git_index_prober(
    policy: Policy,
    scratch_home: Path,
    *,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
    hasher: Callable[[Path], str] = sha256_file,
    timeout_s: float = 60.0,
) -> IndexProbe:
    """An :data:`IndexProbe` over the POLICY-PINNED git, run with
    :data:`GIT_INDEX_DIGEST_ARGS` and the hardened verification env.

    Returns ``None`` (never raises, never a partial digest) on any doubt; the
    caller treats that as "fail closed"."""

    def probe(root: Path) -> IndexProbeResult | None:
        spec = policy.verify.commands.get("git")
        if spec is None or not spec.pinned:
            return None
        exe = Path(spec.executable)
        try:
            if not exe.is_file():
                return None
            real = exe.resolve()
            if not real.is_file() or hasher(real) != spec.executable_sha256:
                return None
            Path(scratch_home).mkdir(parents=True, exist_ok=True)
            env = build_verify_env(path_env=policy.path_env, scratch_home=Path(scratch_home))
            result = spawn(
                [str(real), *GIT_INDEX_DIGEST_ARGS],
                env=env,
                cwd=Path(root),
                timeout_s=timeout_s,
                max_stdout_bytes=policy.verify.max_output_bytes,
                max_stderr_bytes=policy.verify.max_output_bytes,
                popen=popen,
                killpg=killpg,
            )
        except (LaunchRefused, OSError, ValueError):
            return None
        if result.exit_code != 0 or result.timed_out or result.stdout_truncated:
            return None
        return IndexProbeResult(sha256_hex(result.stdout), _gitlink_paths(result.stdout))

    return probe


def _guard_skip(rel: PurePosixPath) -> bool:
    return rel.as_posix() in GUARD_EXCLUDED_RELPATHS


@dataclass(frozen=True)
class GuardChange:
    """What the tripwire saw. ``reason`` is ``"git_index"`` when the staged
    content moved and ``"tree"`` otherwise. The index wins when both moved
    (`git add` writes a loose object AND stages it): it is the more specific
    and the more security-relevant of the two."""

    reason: str
    tree_after: str
    index_digest_after: str | None


@dataclass
class SnapshotGuard:
    """Tripwire over the PRISTINE verification copy: a command that changes it
    is recorded (``snapshot.violated``, the item's ``violated`` flag) and
    verification stops for the run.

    Two halves, because one cannot do the job:

    * a tree hash over every byte except :data:`GUARD_EXCLUDED_RELPATHS`;
    * a digest of the git index CONTENT (:data:`GIT_INDEX_DIGEST_ARGS`), which
      is what `git ls-files`, `git diff` and `git status` report against - so
      an index mutation changes what LATER evidence says.

    Either one moving is a violation. With no usable git the guard FAILS
    CLOSED: it drops the byte exclusion instead (``index_check ==
    "bytes_fallback"``) and hashes `.git/index` like any other file, which
    costs false positives on the stat refresh but never silently skips the
    check."""

    root: Path
    baseline: str
    index_digest: str | None = None
    index_check: str = INDEX_CHECK_NONE
    probe: IndexProbe | None = None

    @classmethod
    def over(cls, root: Path, *, probe: IndexProbe | None = None) -> SnapshotGuard:
        root = Path(root)
        if not (root / ".git").is_dir():
            return cls(root, tree_sha256(root, skip=_guard_skip), None, INDEX_CHECK_NONE)
        result = probe(root) if probe is not None else None
        if result is None:  # fail closed: no semantic cover -> hash the bytes
            return cls(root, tree_sha256(root), None, INDEX_CHECK_BYTES_FALLBACK)
        if result.gitlinks:
            # The copier already refuses a nested `.git` that is PRESENT
            # (`sanitize.assert_no_nested_repositories`). This is the other
            # half, and the only one git can answer: a gitlink whose submodule
            # is not checked out leaves nothing on disk to find. A non-recursive
            # clone - which is what `eris.snapshot` builds - produces exactly
            # that, so a superproject reaches here looking like an ordinary
            # repository.
            raise NestedRepositoryRefused(
                f"{', '.join(result.gitlinks)}: the index registers "
                f"{len(result.gitlinks)} submodule(s) (mode {GITLINK_MODE}); refusing to verify "
                "(Eris does not copy submodule or worktree repositories - their `.git` holds a "
                "config Eris never rewrites, and initialising one mid-run would create it)"
            )
        return cls(
            root, tree_sha256(root, skip=_guard_skip), result.digest, INDEX_CHECK_SEMANTIC, probe
        )

    @property
    def _skip(self) -> Callable[[PurePosixPath], bool] | None:
        return None if self.index_check == INDEX_CHECK_BYTES_FALLBACK else _guard_skip

    def changed(self) -> GuardChange | None:
        # A probe that stops working mid-run reads as a change, not as a pass.
        result = self.probe(self.root) if self.probe is not None else None
        index_now = result.digest if result is not None else None
        tree_now = tree_sha256(self.root, skip=self._skip)
        if self.index_check == INDEX_CHECK_SEMANTIC and index_now != self.index_digest:
            return GuardChange("git_index", tree_now, index_now)
        if tree_now != self.baseline:
            return GuardChange("tree", tree_now, index_now)
        return None


PYTEST_ISOLATION_FLAGS: tuple[str, ...] = ("-p", "no:cacheprovider")


@dataclass
class RunOutcome:
    argv: list[str]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    violated: bool = False
    tree_after: str | None = None
    violation_reason: str | None = None  # "tree" | "git_index"
    index_digest_after: str | None = None


@dataclass
class VerifyEnv:
    """Everything a mechanical command needs; injectable for the hermetic
    suite. ``snapshot_root`` is the PRISTINE copy (never the original, never
    a sanitized copy); ``guard`` trips when a command changes it."""

    policy: Policy
    snapshot_root: Path
    scratch_home: Path
    popen: PopenFactory
    killpg: KillPg
    hasher: Callable[[Path], str] = sha256_file
    clock: Callable[[], float] = time.monotonic
    guard: SnapshotGuard | None = None
    violated: bool = False

    def run(self, argv: Sequence[str]) -> RunOutcome:
        """Raises PermissionError (refused), LaunchRefused or OSError."""
        if self.violated:
            raise PermissionError(
                "refusing to run: an earlier command changed the verification copy "
                "(snapshot.violated); verification is stopped for this run"
            )
        argv = list(argv)
        if argv and Path(argv[0]).name == "pytest" and "no:cacheprovider" not in argv:
            argv.extend(PYTEST_ISOLATION_FLAGS)  # re-checked by run_allowlisted
        decision, result = run_allowlisted(
            argv,
            self.policy,
            self.snapshot_root,
            self.scratch_home,
            popen=self.popen,
            killpg=self.killpg,
            clock=self.clock,
            hasher=self.hasher,
        )
        outcome = RunOutcome(
            list(decision.argv),
            result.exit_code,
            result.stdout,
            result.stderr,
            result.timed_out,
        )
        if self.guard is not None:
            changed = self.guard.changed()
            if changed is not None:
                self.violated = True
                outcome.violated = True
                outcome.tree_after = changed.tree_after
                outcome.violation_reason = changed.reason
                outcome.index_digest_after = changed.index_digest_after
        return outcome


def _refused(writer: RunWriter, argv: Sequence[str], reason: str, source: str) -> None:
    writer.append("verify.refused", {"argv": list(argv), "reason": reason, "source": source})


def _run_recorded(
    env: VerifyEnv, writer: RunWriter, argv: Sequence[str], *, source: str
) -> RunOutcome | None:
    try:
        outcome = env.run(argv)
    except (PermissionError, LaunchRefused, OSError) as exc:
        _refused(writer, argv, f"{type(exc).__name__}: {exc}", source)
        return None
    if outcome.violated:
        writer.append(
            "snapshot.violated",
            {
                "argv": outcome.argv,
                "source": source,
                # which half of the tripwire moved, and what it is doing about
                # `.git/index` this run (semantic / bytes_fallback / none)
                "reason": outcome.violation_reason,
                "index_check": env.guard.index_check if env.guard else None,
                "tree_sha256_before": env.guard.baseline if env.guard else None,
                "tree_sha256_after": outcome.tree_after,
                "git_index_digest_before": env.guard.index_digest if env.guard else None,
                "git_index_digest_after": outcome.index_digest_after,
            },
        )
    return outcome


# --------------------------------------------------------------------------- pack


@dataclass
class PackBuild:
    pack: EvidencePack
    items: list[PackItem]
    records: list[EvidenceItem]
    rendered: bytes
    blob: BlobRef
    refused: int = 0
    executed_argv: list[list[str]] = field(default_factory=list)


def _excerpt(snapshot_root: Path, ex: Excerpt) -> tuple[bytes, bool] | str:
    """The excerpt bytes (+ truncated flag) or a refusal reason."""
    root = snapshot_root.resolve()
    candidate = Path(ex.path)
    if candidate.is_absolute():
        return f"excerpt path {ex.path!r} must be relative to the snapshot"
    target = root / candidate
    try:
        resolved = target.resolve(strict=True)
    except (OSError, RuntimeError):
        return f"excerpt path {ex.path!r} does not exist"
    # no symlink anywhere on the path below the root (checked before containment:
    # a link's target may well lie outside, but the refusal names the link)
    walk = root
    for part in Path(ex.path).parts:
        walk = walk / part
        if walk.is_symlink():
            return f"excerpt path {ex.path!r} goes through a symlink"
    try:
        rel = resolved.relative_to(root)
    except ValueError:
        return f"excerpt path {ex.path!r} escapes the snapshot"
    if ".git" in rel.parts:
        return f"excerpt path {ex.path!r} points into .git"
    if not stat.S_ISREG(os.lstat(resolved).st_mode):
        return f"excerpt path {ex.path!r} is not a regular file"
    lines = resolved.read_bytes().splitlines(keepends=True)
    end = min(ex.line_end, len(lines), ex.line_start - 1 + EXCERPT_MAX_LINES)
    chosen = lines[ex.line_start - 1 : end]
    truncated = end < min(ex.line_end, len(lines))
    numbered = b"".join(
        f"{n}: ".encode() + line for n, line in enumerate(chosen, start=ex.line_start)
    )
    return numbered, truncated


def build_evidence_pack(
    task: TaskSpec,
    *,
    env: VerifyEnv,
    writer: RunWriter,
    repeat_index: int,
    policy_sha256: str,
    snapshot_sha: str | None,
    stop_check: Callable[[], bool] = lambda: False,
    ts: Callable[[], str] = now_ts,
) -> PackBuild:
    """Build, record (``evidence.item`` per item, ``pack.built``) and return
    the pack. Commands run on ``env.snapshot_root`` (the ORIGINAL)."""
    items: list[PackItem] = []
    refused = 0
    executed: list[list[str]] = []
    items.append(
        _item(
            writer,
            kind=EvidenceKind.DOCUMENT_QUOTE,
            origin=Origin.HUMAN_ENTERED,
            label="question",
            content=task.question.encode("utf-8"),
            argv=None,
            exit_code=None,
        )
    )
    if task.plan_text:
        items.append(
            _item(
                writer,
                kind=EvidenceKind.DOCUMENT_QUOTE,
                origin=Origin.HUMAN_ENTERED,
                label="plan",
                content=task.plan_text.encode("utf-8"),
                argv=None,
                exit_code=None,
            )
        )
    commands: list[tuple[str, tuple[str, ...], EvidenceKind]] = []
    if task.diff_rev:
        commands.append(
            ("diff", ("git", "show", "--no-color", task.diff_rev), EvidenceKind.REPO_FACT)
        )
    commands.extend(("repo_fact", argv, EvidenceKind.REPO_FACT) for argv in PACK_COMMANDS)
    commands.extend(("battery", tuple(argv), EvidenceKind.TOOL_OUTPUT) for argv in task.battery)
    for label, argv, kind in commands:
        if stop_check():
            writer.append("verify.stopped", {"argv": list(argv), "source": "pack"})
            raise EvidenceStopped("STOP requested while building the evidence pack")
        ran = _run_recorded(env, writer, argv, source="pack")
        if ran is None:
            refused += 1
            continue
        executed.append(ran.argv)
        if ran.stderr:
            writer.put_blob(ran.stderr)
        items.append(
            _item(
                writer,
                kind=kind,
                origin=Origin.MECHANICALLY_OBSERVED,
                label=f"{label}: {' '.join(argv)}"
                + (" (timed out)" if ran.timed_out else "")
                + (" (VIOLATED the verification copy)" if ran.violated else ""),
                content=ran.stdout,
                argv=ran.argv,
                exit_code=ran.exit_code,
                violated=ran.violated,
            )
        )
    for ex in task.excerpts:
        got = _excerpt(env.snapshot_root, ex)
        label = f"excerpt:{ex.path}:{ex.line_start}-{ex.line_end}"
        if isinstance(got, str):
            writer.append("evidence.refused", {"label": label, "reason": got})
            refused += 1
            continue
        content, truncated = got
        item = _item(
            writer,
            kind=EvidenceKind.REPO_FACT,
            origin=Origin.MECHANICALLY_OBSERVED,
            label=label + (" (capped)" if truncated else ""),
            content=content,
            argv=None,
            exit_code=None,
        )
        items.append(item)
    rendered = canonical_bytes({"items": [i.rendered() for i in items]})
    blob = writer.put_blob(rendered)
    if blob.sha256 != sha256_hex(rendered):
        raise EvidenceError("the rendered pack changed under redaction; items were not redacted")
    now = ts()
    records = [
        _record(writer, i, task_id=task.task_id, phase=Phase.EVIDENCE_PACK, ts=now) for i in items
    ]
    pack = EvidencePack(
        pack_id=f"pack-{blob.sha256[:16]}",
        task_id=task.task_id,
        nonce=derive_nonce(
            snapshot_sha=snapshot_sha,
            task_id=task.task_id,
            repeat_index=repeat_index,
            stage="evidence_pack",
            policy_sha256=policy_sha256,
        ),
        item_ids=[i.evidence_id for i in items],
        pack_sha256=blob.sha256,
        size_bytes=blob.size_bytes,
        git_argv=executed,
        created_at=now,
    )
    writer.append("pack.built", pack)
    if refused:
        writer.append("pack.incomplete", {"refused": refused, "pack_id": pack.pack_id})
    return PackBuild(pack, items, records, rendered, blob, refused, executed)


def rebuild_pack(
    pack: EvidencePack,
    records: Sequence[EvidenceItem],
    *,
    blob_bytes: Callable[[str], bytes],
    blobs_dir: Path,
) -> PackBuild:
    """Resume: rebuild the in-memory pack from its ledger records and the
    (verified) blobs. Item order follows ``pack.item_ids``."""
    by_id = {r.evidence_id: r for r in records}
    items: list[PackItem] = []
    for evidence_id in pack.item_ids:
        r = by_id[evidence_id]
        content = blob_bytes(r.content_sha256)
        text, truncated = _cap(content.decode("utf-8", errors="replace"))
        items.append(
            PackItem(
                evidence_id=r.evidence_id,
                kind=r.kind,
                origin=r.origin,
                label=r.summary,
                argv=list(r.argv) if r.argv is not None else None,
                exit_code=r.exit_code,
                content=text,
                truncated=truncated,
                blob=BlobRef(
                    r.content_sha256,
                    r.size_bytes,
                    dict(r.redaction_counts),
                    blobs_dir / r.content_sha256,
                ),
            )
        )
    rendered = blob_bytes(pack.pack_sha256)
    blob = BlobRef(pack.pack_sha256, pack.size_bytes, {}, blobs_dir / pack.pack_sha256)
    return PackBuild(pack, items, list(records), rendered, blob, 0, list(pack.git_argv))


# --------------------------------------------------------------------------- requests


def request_key(argv: Sequence[str]) -> str:
    """Dedupe key of an ALREADY VALIDATED argv: canonical argv with the
    executable's basename and without the options Eris itself appends, so a
    recorded, resolved argv and a freshly validated one compare equal (a
    resumed run must recognise a request it already executed).

    Call this ONLY with an argv that :func:`~eris.verify.check_command` has
    accepted, or with one read back off the ledger (which is the same thing).
    Keying a RAW model request would let ``git --no-optional-locks log`` alias
    ``git log`` and come back as ``verify.duplicate`` instead of the refusal
    it must be - the stripped options are hard-denied from a model, and that
    refusal has to happen BEFORE the key is computed.
    """
    argv = list(argv)
    if argv:
        argv[0] = Path(argv[0]).name
        if argv[0] == "git":
            while len(argv) > 1 and argv[1] in GIT_ERIS_GLOBALS:
                del argv[1]
    return canonical_bytes({"argv": argv}).decode("utf-8")


@dataclass
class RequestState:
    """Per-run state of the evidence-request loop (dedupe, caps, wall clock).
    ``started_monotonic`` is taken from ``env.clock`` at the first request
    unless set; the wall budget counts from there."""

    started_monotonic: float | None = None
    executed: dict[str, str] = field(default_factory=dict)  # canonical argv -> evidence_id
    count: int = 0
    iterations: int = 0


def execute_evidence_requests(
    requests: Sequence[EvidenceRequest],
    *,
    source: str,
    env: VerifyEnv,
    writer: RunWriter,
    state: RequestState,
    task_id: str,
    stop_check: Callable[[], bool],
    ts: Callable[[], str] = now_ts,
) -> list[EvidenceItem]:
    """Run model-proposed commands on the ORIGINAL snapshot. Returns the
    recorded items; refusals/duplicates are events, never exceptions."""
    verify = env.policy.verify
    items: list[EvidenceItem] = []
    if state.started_monotonic is None:
        state.started_monotonic = env.clock()
    for req in requests:
        argv = list(req.argv)
        if stop_check():
            writer.append("verify.stopped", {"argv": argv, "source": source})
            raise EvidenceStopped("STOP requested before an evidence request")
        # Validate FIRST: a model-supplied option that Eris itself appends is a
        # refusal, never a duplicate. run_allowlisted re-applies the grammar
        # immediately before spawn regardless; this decision only keys.
        decision = check_command(argv, env.policy, Path(env.snapshot_root), hasher=env.hasher)
        if not decision.allowed:
            _refused(writer, argv, f"PermissionError: refusing to run: {decision.reason}", source)
            continue
        canon = request_key(decision.argv)
        if canon in state.executed:
            writer.append(
                "verify.duplicate",
                {"argv": argv, "evidence_id": state.executed[canon], "source": source},
            )
            continue
        if state.count >= verify.max_requests_per_run:
            _refused(
                writer,
                argv,
                f"max_requests_per_run ({verify.max_requests_per_run}) reached",
                source,
            )
            continue
        elapsed = env.clock() - state.started_monotonic
        if elapsed > verify.max_wall_s:
            _refused(writer, argv, f"max_wall_s ({verify.max_wall_s}) exceeded", source)
            continue
        ran = _run_recorded(env, writer, argv, source=source)
        if ran is None:
            continue
        rc = ran.exit_code
        state.count += 1
        if ran.stderr:
            writer.put_blob(ran.stderr)
        summary = f"{source}: exit {rc}" + (" (timed out)" if ran.timed_out else "")
        if req.expect_exit_code is not None and rc != req.expect_exit_code:
            summary += f"; expected {req.expect_exit_code}"
        if ran.violated:
            summary += "; VIOLATED the verification copy"
        item = _item(
            writer,
            kind=EvidenceKind.TOOL_OUTPUT,
            origin=Origin.MECHANICALLY_OBSERVED,
            label=summary,
            content=ran.stdout,
            argv=ran.argv,
            exit_code=rc,
            violated=ran.violated,
        )
        record = _record(writer, item, task_id=task_id, phase=Phase.VERIFICATION, ts=ts())
        state.executed[canon] = record.evidence_id
        items.append(record)
    return items


# --------------------------------------------------------------------------- scratch


@contextmanager
def verify_scratch(writer: RunWriter, scratch_root: Path, name: str = "verify") -> Iterator[Path]:
    """A private HOME/TMPDIR for mechanical commands under the run's
    SCRATCH root (never under ``runs/``); removed in ``finally``. A removal
    failure writes ``run.error`` and raises :class:`EvidenceCleanupError`."""
    writer_dir = Path(scratch_root) / name
    make_private_dir(writer_dir)
    try:
        yield writer_dir
    finally:
        try:
            shutil.rmtree(writer_dir)
        except OSError as exc:
            message = f"verify scratch cleanup failed for {writer_dir}: {exc}"
            writer.append("run.error", {"kind": "verify_scratch_cleanup_failed", "error": message})
            raise EvidenceCleanupError(message) from exc
