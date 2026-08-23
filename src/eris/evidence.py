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
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from eris.launch import KillPg, LaunchRefused, PopenFactory, make_private_dir
from eris.policy import Policy, sha256_file
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
from eris.verify import run_allowlisted
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
    key (``key.json``) is a different file the harness never opens."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    question: str = Field(min_length=1)
    category: TaskCategory
    snapshot: str = Field(min_length=1)
    battery: list[list[str]] = Field(default_factory=list)
    excerpts: list[Excerpt] = Field(default_factory=list)
    diff_rev: str | None = None
    plan_text: str | None = None


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
    )
    writer.append("evidence.item", record)
    return record


# --------------------------------------------------------------------------- commands


@dataclass
class VerifyEnv:
    """Everything a mechanical command needs; injectable for the hermetic suite."""

    policy: Policy
    snapshot_root: Path  # the ORIGINAL snapshot, never a sanitized copy
    scratch_home: Path
    popen: PopenFactory
    killpg: KillPg
    hasher: Callable[[Path], str] = sha256_file
    clock: Callable[[], float] = time.monotonic

    def run(self, argv: Sequence[str]) -> tuple[list[str], int | None, bytes, bytes, bool]:
        """(executed argv, exit code, stdout, stderr, timed_out). Raises
        PermissionError (refused), LaunchRefused or OSError."""
        decision, result = run_allowlisted(
            list(argv),
            self.policy,
            self.snapshot_root,
            self.scratch_home,
            popen=self.popen,
            killpg=self.killpg,
            clock=self.clock,
            hasher=self.hasher,
        )
        return (
            list(decision.argv),
            result.exit_code,
            result.stdout,
            result.stderr,
            result.timed_out,
        )


def _refused(writer: RunWriter, argv: Sequence[str], reason: str, source: str) -> None:
    writer.append("verify.refused", {"argv": list(argv), "reason": reason, "source": source})


def _run_recorded(
    env: VerifyEnv, writer: RunWriter, argv: Sequence[str], *, source: str
) -> tuple[list[str], int | None, bytes, bytes, bool] | None:
    try:
        return env.run(argv)
    except (PermissionError, LaunchRefused, OSError) as exc:
        _refused(writer, argv, f"{type(exc).__name__}: {exc}", source)
        return None


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
        exec_argv, rc, stdout, stderr, timed_out = ran
        executed.append(exec_argv)
        if stderr:
            writer.put_blob(stderr)
        items.append(
            _item(
                writer,
                kind=kind,
                origin=Origin.MECHANICALLY_OBSERVED,
                label=f"{label}: {' '.join(argv)}" + (" (timed out)" if timed_out else ""),
                content=stdout,
                argv=exec_argv,
                exit_code=rc,
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
        canon = canonical_bytes({"argv": argv}).decode("utf-8")
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
        exec_argv, rc, stdout, stderr, timed_out = ran
        state.count += 1
        if stderr:
            writer.put_blob(stderr)
        summary = f"{source}: exit {rc}" + (" (timed out)" if timed_out else "")
        if req.expect_exit_code is not None and rc != req.expect_exit_code:
            summary += f"; expected {req.expect_exit_code}"
        item = _item(
            writer,
            kind=EvidenceKind.TOOL_OUTPUT,
            origin=Origin.MECHANICALLY_OBSERVED,
            label=summary,
            content=stdout,
            argv=exec_argv,
            exit_code=rc,
        )
        record = _record(writer, item, task_id=task_id, phase=Phase.VERIFICATION, ts=ts())
        state.executed[canon] = record.evidence_id
        items.append(record)
    return items


# --------------------------------------------------------------------------- scratch


@contextmanager
def verify_scratch(writer: RunWriter, name: str = "verify") -> Iterator[Path]:
    """A private HOME/TMPDIR for mechanical commands under the run dir
    (after the writer holds the lock); removed in ``finally``. A removal
    failure writes ``run.error`` and raises :class:`EvidenceCleanupError`."""
    writer_dir = writer.run_dir / "scratch" / name
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
