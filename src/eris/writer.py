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
* Opening for resume verifies the chain. ONLY a partial final line (no
  trailing newline: an interrupted write) is truncated, and only on resume.
  A complete line that does not validate, anywhere including last, makes
  the ledger INVALID and the writer refuses.
* Failures raise. Nothing is swallowed; no partial blob is left behind.
* The seal is DURABLE: a ledger whose last event is ``scan.result`` reopens
  sealed, so no resume can append behind the final scan. A failure that
  happens after the seal is recorded in manifest.json
  (``post_scan_errors``), not only on stderr.
* A manifest that is renamed into place but whose directory fsync fails
  raises :class:`ManifestNotDurable` - the run IS finalized, only its
  durability is unproven; it is never reported as a finalize failure.
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


class ManifestNotDurable(WriterError):
    """manifest.json was renamed into place but the directory fsync failed.

    The run IS finalized as far as every future reader is concerned (the
    manifest exists, so a later open refuses with :class:`RunExists`); only
    its durability across a power loss is unproven. It is NOT a finalize
    failure and must not be reported as one."""


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
        on_event: Callable[[Event], None] | None = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self._on_event = on_event  # observer (stderr progress stream); never a second writer
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
        self._sealed = False
        self._post_scan_errors: list[dict[str, str]] = []
        self.torn_tail_truncated = False
        self.resumed_from_seq: int | None = None
        self.corrupt_blobs: list[str] = []  # names that did not re-hash on resume (F5)

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
    def closed(self) -> bool:
        """True once finalized or closed: nothing more can be appended."""
        return self._finalized or self._events_fh is None

    @property
    def sealed(self) -> bool:
        return self._sealed

    def seal(self) -> None:
        """Close the ledger for EVENTS while leaving :meth:`finalize` able to
        write the manifest. The harness seals right after its final scan so
        that nothing can structurally appear behind ``scan.result``; a later
        ``append`` raises :class:`WriterClosed` instead of slipping in.

        Sealing is DURABLE: :meth:`open` re-derives it from the ledger (a
        ledger whose last event is ``scan.result`` opens sealed), so a resume
        after a finalize failure cannot append behind the final scan."""
        self._sealed = True

    def record_post_scan_error(self, kind: str, error: str) -> None:
        """Remember a failure that happened AFTER the final scan, when no
        event may be appended any more. :meth:`finalize` writes it into
        manifest.json (which is written after the scan), so the failure is
        durable instead of stderr-only. Ignored before the seal: while the
        ledger is open a failure is a ``run.error`` EVENT."""
        if not self._sealed:
            return
        self._post_scan_errors.append({"kind": kind, "error": error})

    @property
    def post_scan_errors(self) -> list[dict[str, str]]:
        return list(self._post_scan_errors)

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
        # Directory entries are durable only after their parent is fsynced.
        self._fsync_dir(self.run_dir.parent)
        self._fsync_dir(self.blobs_dir.parent)
        self._fsync_dir(self.blobs_dir)
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
            self._fsync_dir(self.run_dir)  # .lock and events.jsonl entries
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
        # ONLY a non-newline-terminated partial tail is recoverable (the
        # final write was interrupted). A complete but invalid line anywhere,
        # including last, is corruption, not a torn write -> LedgerInvalid.
        torn = bool(tail)
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
        # The seal is part of the RECORD, not of this process: a ledger whose
        # last event is the final scan reopens SEALED, so a resume after a
        # failed finalize can never append behind ``scan.result``.
        if keep and _kind_of(keep[-1]) == FINAL_SCAN_KIND:
            self._sealed = True
        for blob_path in sorted(self.blobs_dir.glob("*")):
            if blob_path.name.startswith("."):
                blob_path.unlink()  # abandoned temp file from a crashed put_blob
                continue
            # F5: index by CONTENT, never by name alone. A blob whose bytes do
            # not hash to its name is corrupt (or planted): it is not indexed,
            # so a later put_blob rewrites it, and it is reported so the
            # harness treats any stage that referenced it as NOT finished.
            if blob_path.is_symlink() or not blob_path.is_file():
                self.corrupt_blobs.append(blob_path.name)
                continue
            data = blob_path.read_bytes()
            if sha256_hex(data) != blob_path.name:
                self.corrupt_blobs.append(blob_path.name)
                continue
            self._blobs[blob_path.name] = BlobRef(blob_path.name, len(data), {}, blob_path)

    def blob_intact(self, sha256: str) -> bool:
        """True iff a blob named ``sha256`` exists, is a regular file (not a
        symlink) and its bytes hash to its name. Used by resume to decide
        whether a ``stage.finished`` can be trusted (F5)."""
        path = self.blobs_dir / sha256
        if path.is_symlink() or not path.is_file():
            return False
        return sha256_hex(path.read_bytes()) == sha256

    @staticmethod
    def _describe(findings: list[Finding]) -> str:
        return "ledger invalid: " + "; ".join(
            f"{f.code}@{f.record_id}: {f.message}" for f in findings[:5]
        )

    def _ensure_open(self, *, for_event: bool = True) -> IO[bytes]:
        if self._finalized or self._events_fh is None:
            raise WriterClosed("writer is not open")
        if for_event and self._sealed:
            raise WriterClosed("ledger is sealed: no event may follow the final scan")
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
        if self._on_event is not None:
            self._on_event(event)
        return event

    # ------------------------------------------------------------------ finalize

    def finalize(self, extra: Mapping[str, Any] | None = None) -> Path:
        """Write manifest.json LAST (temp+fsync+rename) and close. Allowed on a
        sealed ledger: the manifest is not an event."""
        self._ensure_open(for_event=False)
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
            # failures that happened after the seal, when no event could be
            # written any more: recorded HERE so they are durable
            "post_scan_errors": list(self._post_scan_errors),
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
        except BaseException:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
        # From here the manifest IS in place: every future open sees a
        # finalized run. A failing directory fsync leaves that visible state
        # untouched and only makes it unproven across a power loss, so it is
        # reported as its own condition, never as a finalize failure.
        try:
            self._fsync_dir(self.run_dir)
        except OSError as exc:
            self.close()
            raise ManifestNotDurable(
                f"{self.manifest_path} was renamed into place but {self.run_dir} could not be "
                f"fsynced ({exc}): the run is finalized, its durability is unproven"
            ) from exc
        self.close()
        return self.manifest_path


def _sorted_key(item: Mapping[str, Any]) -> str:
    return str(item.get("sha256", ""))


FINAL_SCAN_KIND = "scan.result"
"""The event that closes a run's ledger. Nothing may follow it, in this
process or in any later one (see :meth:`RunWriter.seal`)."""


def _kind_of(line: bytes) -> str | None:
    """The ``kind`` of one already-validated event line."""
    try:
        event = json.loads(line)
    except ValueError:  # pragma: no cover - validate_events accepted the line
        return None
    kind = event.get("kind") if isinstance(event, dict) else None
    return kind if isinstance(kind, str) else None
