"""RunWriter: the ONE path to disk under ``runs/``.

Layout of a run directory::

    runs/<run_id>/
        .lock            flock'd for the writer's lifetime (single writer)
        events.jsonl     append-only hash chain of Event lines
        blobs/sha256/<hex>   content-addressed, redacted BEFORE hashing
        manifest.json    written LAST by finalize()

Guarantees (each has a test in tests/test_writer.py; see docs/INVARIANTS.md):

* Everything is redacted before it is hashed or written.
* Every write is temp file -> fsync -> rename (blobs, manifest) or
  append -> flush -> fsync (events).
* ``seq`` is contiguous from 0 and ``prev_sha256`` chains line bytes.
* Only one writer per run directory (``flock(LOCK_EX | LOCK_NB)``).
* Opening for resume verifies the chain; a torn final line (no trailing
  newline, or unparsable) is truncated ONLY on resume; a malformed line in
  the middle makes the ledger INVALID and the writer refuses.
* Failures raise. Nothing is swallowed; no partial blob is left behind.
"""

from __future__ import annotations

import fcntl
import json
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from eris.redact import Redactor
from eris.schemas import (
    SCHEMA_VERSION,
    Event,
    Record,
    canonical_bytes,
    now_ts,
    sha256_hex,
)
from eris.validate import Finding, validate_events
from eris.version import __version__


class WriterError(RuntimeError):
    """Base for every writer failure. Never swallowed."""


class WriterLocked(WriterError):
    """Another writer holds the run directory."""


class LedgerInvalid(WriterError):
    """The existing events.jsonl fails chain validation (not a torn tail)."""


class RunExists(WriterError):
    """events.jsonl already exists and ``resume`` was not requested."""


class WriterClosed(WriterError):
    """append/put_blob after finalize()/close()."""


@dataclass(frozen=True)
class BlobRef:
    sha256: str
    size_bytes: int
    redaction_counts: dict[str, int]
    path: Path


FsyncFn = Callable[[int], None]


class RunWriter:
    def __init__(
        self,
        run_dir: Path,
        redactor: Redactor,
        *,
        run_id: str | None = None,
        resume: bool = False,
        fsync: FsyncFn = os.fsync,
        clock: Callable[[], str] = now_ts,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.run_id = run_id or self.run_dir.name
        self._redactor = redactor
        self._fsync = fsync
        self._clock = clock
        self._resume = resume
        self._lock_fh: IO[bytes] | None = None
        self._events_fh: IO[bytes] | None = None
        self._seq = 0
        self._prev_sha: str | None = None
        self._blobs: dict[str, BlobRef] = {}
        self._redaction_totals: dict[str, int] = {}
        self._finalized = False
        self.torn_tail_truncated = False
        self.resumed_from_seq: int | None = None

    # ------------------------------------------------------------------ paths

    @property
    def events_path(self) -> Path:
        return self.run_dir / "events.jsonl"

    @property
    def blobs_dir(self) -> Path:
        return self.run_dir / "blobs" / "sha256"

    @property
    def manifest_path(self) -> Path:
        return self.run_dir / "manifest.json"

    @property
    def lock_path(self) -> Path:
        return self.run_dir / ".lock"

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def last_sha256(self) -> str | None:
        return self._prev_sha

    # ------------------------------------------------------------------ lifecycle

    def open(self) -> RunWriter:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        lock_fh = open(self.lock_path, "ab")
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            lock_fh.close()
            raise WriterLocked(f"{self.run_dir} is held by another writer") from exc
        self._lock_fh = lock_fh
        try:
            if self.manifest_path.exists():
                raise RunExists(f"{self.run_dir} is finalized (manifest.json exists)")
            if self.events_path.exists():
                if not self._resume:
                    raise RunExists(f"{self.events_path} exists; pass resume=True to continue")
                self._recover()
            self._events_fh = open(self.events_path, "ab")
        except BaseException:
            self._release_lock()
            raise
        return self

    def __enter__(self) -> RunWriter:
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._events_fh is not None:
            self._events_fh.close()
            self._events_fh = None
        self._release_lock()
        self._finalized = True

    def _release_lock(self) -> None:
        if self._lock_fh is not None:
            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_UN)
            self._lock_fh.close()
            self._lock_fh = None

    def _recover(self) -> None:
        raw = self.events_path.read_bytes()
        lines = raw.split(b"\n")
        tail = lines.pop()  # bytes after the last newline ("" when clean)
        keep = [line + b"\n" for line in lines]
        torn = False
        if tail:
            torn = True  # no trailing newline: the final write was interrupted
        elif keep and not self._parses(keep[-1]):
            torn = True  # final line is complete but unparsable
            keep.pop()
        findings = validate_events(keep)
        if findings:
            raise LedgerInvalid(self._describe(findings))
        if torn:
            good = b"".join(keep)
            with open(self.events_path, "r+b") as fh:
                fh.truncate(len(good))
                fh.flush()
                self._fsync(fh.fileno())
            self.torn_tail_truncated = True
        self._seq = len(keep)
        self._prev_sha = sha256_hex(keep[-1].rstrip(b"\n")) if keep else None
        self.resumed_from_seq = self._seq
        for blob_path in self.blobs_dir.glob("*"):
            if blob_path.name.startswith("."):
                blob_path.unlink()  # abandoned temp file from a crashed put_blob
            else:
                self._blobs[blob_path.name] = BlobRef(
                    blob_path.name, blob_path.stat().st_size, {}, blob_path
                )

    @staticmethod
    def _parses(line: bytes) -> bool:
        try:
            Event.model_validate(json.loads(line))
        except (ValueError, TypeError):
            return False
        return True

    @staticmethod
    def _describe(findings: list[Finding]) -> str:
        return "ledger invalid: " + "; ".join(
            f"{f.code}@{f.record_id}: {f.message}" for f in findings[:5]
        )

    def _ensure_open(self) -> IO[bytes]:
        if self._finalized or self._events_fh is None:
            raise WriterClosed("writer is not open")
        return self._events_fh

    # ------------------------------------------------------------------ blobs

    def put_blob(self, data: bytes) -> BlobRef:
        """Redact -> hash -> temp+fsync+rename. Raises on any failure and
        leaves no partial file behind."""
        self._ensure_open()
        redacted, counts = self._redactor.redact_bytes(data)
        digest = sha256_hex(redacted)
        existing = self._blobs.get(digest)
        if existing is not None:
            return existing
        final = self.blobs_dir / digest
        tmp = self.blobs_dir / f".{digest}.{uuid.uuid4().hex}.tmp"
        try:
            with open(tmp, "wb") as fh:
                fh.write(redacted)
                fh.flush()
                self._fsync(fh.fileno())
            os.rename(tmp, final)
            self._fsync_dir(self.blobs_dir)
        except BaseException:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
        ref = BlobRef(digest, len(redacted), counts, final)
        self._blobs[digest] = ref
        for pid, n in counts.items():
            self._redaction_totals[pid] = self._redaction_totals.get(pid, 0) + n
        return ref

    def _fsync_dir(self, path: Path) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            self._fsync(fd)
        finally:
            os.close(fd)

    # ------------------------------------------------------------------ events

    def append(self, kind: str, payload: Record | Mapping[str, Any]) -> Event:
        """Append one chained event. The payload is redacted before hashing."""
        fh = self._ensure_open()
        raw = canonical_bytes(payload)
        redacted_text, counts = self._redactor.redact_bytes(raw)
        try:
            payload_dict: dict[str, Any] = json.loads(redacted_text)
        except ValueError as exc:  # pragma: no cover - placeholders are JSON-safe
            raise WriterError("redaction produced invalid JSON") from exc
        for pid, n in counts.items():
            self._redaction_totals[pid] = self._redaction_totals.get(pid, 0) + n
        event = Event(
            seq=self._seq,
            ts=self._clock(),
            run_id=self.run_id,
            kind=kind,
            prev_sha256=self._prev_sha,
            payload_sha256=sha256_hex(canonical_bytes(payload_dict)),
            payload=payload_dict,
        )
        line = canonical_bytes(event)
        fh.write(line + b"\n")
        fh.flush()
        self._fsync(fh.fileno())
        self._seq += 1
        self._prev_sha = sha256_hex(line)
        return event

    # ------------------------------------------------------------------ finalize

    def finalize(self, extra: Mapping[str, Any] | None = None) -> Path:
        """Write manifest.json LAST (temp+fsync+rename) and close."""
        self._ensure_open()
        manifest: dict[str, Any] = {
            "run_id": self.run_id,
            "schema_version": SCHEMA_VERSION,
            "eris_version": __version__,
            "event_count": self._seq,
            "last_sha256": self._prev_sha,
            "blobs": sorted(
                ({"sha256": b.sha256, "size_bytes": b.size_bytes} for b in self._blobs.values()),
                key=_sorted_key,
            ),
            "redaction_totals": dict(sorted(self._redaction_totals.items())),
            "torn_tail_truncated": self.torn_tail_truncated,
            "resumed_from_seq": self.resumed_from_seq,
            "finalized_at": self._clock(),
        }
        if extra:
            manifest["extra"] = json.loads(self._redactor.redact_bytes(canonical_bytes(extra))[0])
        data = canonical_bytes(manifest) + b"\n"
        tmp = self.run_dir / f".manifest.{uuid.uuid4().hex}.tmp"
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                self._fsync(fh.fileno())
            os.rename(tmp, self.manifest_path)
            self._fsync_dir(self.run_dir)
        except BaseException:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
        self.close()
        return self.manifest_path


def _sorted_key(item: Mapping[str, Any]) -> str:
    return str(item.get("sha256", ""))
