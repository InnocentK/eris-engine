"""Worker-call cache: replay a finished, clean call instead of paying again.

Lives in the policy's ``cache_dir`` (``cache/``, gitignored) and NEVER under
``runs/`` (refused at construction). Layout::

    <root>/entries/<sha256 of the entry bytes>   the entry (redacted JSON)
    <root>/keys/campaigns/<epoch>/<key>          -> current-campaign entry sha256
    <root>/keys/<idempotency_key>                -> cross-campaign entry sha256
    <root>/blobs/sha256/<sha256>                 redacted worker output bytes

Every byte written here comes out of :meth:`eris.writer.RunWriter.put_blob`
(the entry) or from the run's blob directory (stdout/stderr/output file):
it is redacted BEFORE it is hashed, and the entry's file name is the hash of
its redacted bytes.

A HIT requires ALL of: the key file is a regular file; the entry file is a
regular file whose bytes hash to its name; ``schema_version`` is current;
the ``idempotency_key``, ``prompt_sha256`` and ``executable_sha256`` match
the caller's (the current pin - an unpinned or re-pinned worker never hits);
``status == ok``; ``scan_hits == 0`` (a contaminated entry is never reused);
``model_executed`` is known; the default pointer is scoped to the campaign
epoch, while ``reuse_across_campaigns`` selects only the legacy unscoped
cross-campaign pointer; every referenced blob is a regular file that
hashes to its name. Files are ``lstat``-checked and opened ``O_NOFOLLOW``.
Any failure is a :class:`CacheMiss` with a reason (the caller writes
``cache.refused{reason}`` and makes a fresh call).

Writes are once-only (``O_EXCL``). A campaign-scoped key that already points
at a DIFFERENT entry is a ``conflict``: nothing is overwritten. The unscoped
cross-campaign pointer remains first-writer-wins but cannot block publication
of another campaign's scoped pointer. ``fresh=True`` skips the lookup and still
stores when the scoped key is absent.

On a hit :func:`replay_hit` copies the blobs into the run through
``put_blob`` (hash must match), re-appends the cached ``Invocation`` with
``reused_from`` = the origin invocation, writes a ``CostRecord`` with
``counted=False`` and an ``invocation.reused`` event.

Portability: ``O_NOFOLLOW`` does not exist on Windows; the cache refuses to
construct there (:class:`CacheUnsupported`, a documented refusal - never a
silent fall-through to following symlinks). M2c adds a portable fallback.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from eris.launch import WorkerResult
from eris.policy import is_sha256
from eris.schemas import (
    SCHEMA_VERSION,
    CostRecord,
    Invocation,
    Usage,
    WorkerStatus,
    canonical_bytes,
    sha256_hex,
)
from eris.writer import BlobRef, RunWriter

MAX_ENTRY_BYTES = 64 << 20  # an entry larger than this is not a cache entry
BLOB_KINDS: tuple[str, ...] = ("stdout", "stderr", "output_file")
NO_CAMPAIGN_EPOCH = "none"


class CacheError(RuntimeError):
    """Base for cache failures that are NOT a plain miss."""


class CacheUnsupported(CacheError):
    """This platform lacks ``O_NOFOLLOW``: the cache refuses to run (documented)."""


class CacheRefused(CacheError):
    """A replay could not be completed safely (e.g. a blob did not re-hash)."""


@dataclass(frozen=True)
class CacheMiss:
    reason: str


@dataclass(frozen=True)
class CacheHit:
    entry_sha256: str
    entry: dict[str, Any]
    invocation: Invocation
    blobs: dict[str, bytes] = field(default_factory=dict)

    @property
    def result(self) -> WorkerResult:
        """The cached call as a :class:`WorkerResult` (``parse_mode="cache"``)."""
        inv = self.invocation
        e = self.entry
        return WorkerResult(
            worker_id=inv.worker_id,
            provider=inv.provider,
            model_requested=inv.model_requested,
            model_executed=inv.model_executed,
            status=WorkerStatus.OK,
            error=None,
            text=e.get("text"),
            structured=e.get("structured"),
            usage=inv.usage,
            cost_usd=inv.cost_usd,
            duration_ms=inv.duration_ms or 0,
            exit_code=inv.exit_code,
            argv=list(inv.argv),
            env_names=list(inv.env_names),
            cwd=inv.cwd,
            idempotency_key=inv.idempotency_key,
            executable_sha256=inv.executable_sha256,
            stdout=self.blobs.get("stdout", b""),
            stderr=self.blobs.get("stderr", b""),
            stdout_truncated=inv.stdout_truncated,
            stderr_truncated=inv.stderr_truncated,
            timed_out=False,
            parse_mode="cache",
            output_file=self.blobs.get("output_file"),
            output_file_truncated=inv.output_file_truncated,
            output_file_size=inv.output_file_size,
            conversation_id=inv.conversation_id,
            worker_reported_duration_ms=inv.worker_reported_duration_ms,
            warning=inv.warning,
        )


@dataclass(frozen=True)
class StoreResult:
    outcome: str  # "stored" | "exists" | "conflict"
    entry_sha256: str
    existing_sha256: str | None = None
    cross_campaign_outcome: str | None = None
    cross_campaign_existing_sha256: str | None = None


class CacheMissError(Exception):
    """Internal: turned into a :class:`CacheMiss` by ``lookup``."""


def _read_regular_nofollow(path: Path, cap: int) -> bytes:
    """lstat: regular file only; open O_NOFOLLOW; read at most ``cap`` + 1."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise CacheMissError(f"{path.name}: missing") from None
    if not stat.S_ISREG(st.st_mode):
        raise CacheMissError(f"{path.name}: not a regular file (symlink?)")
    if st.st_size > cap:
        raise CacheMissError(f"{path.name}: {st.st_size} bytes exceeds the cap {cap}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                raise CacheMissError(f"{path.name}: grew past the cap while reading")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _write_once(path: Path, data: bytes) -> bool:
    """Create ``path`` with O_EXCL and write ``data``. False when it exists."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return True


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _campaign_epoch(campaign_id: str | None) -> str:
    """Return a path-safe, collision-resistant namespace for one campaign.

    ``none`` is reserved for calls outside a campaign. Real campaign ids are
    domain-separated before hashing, so even the literal id ``"none"`` cannot
    alias that reserved epoch and path separators never enter the layout.
    """
    if campaign_id is None:
        return NO_CAMPAIGN_EPOCH
    material = b"eris-cache-campaign\x00" + campaign_id.encode("utf-8")
    return f"sha256-{sha256_hex(material)}"


class Cache:
    def __init__(
        self,
        root: Path,
        *,
        runs_dir: Path | None = None,
        reuse_across_campaigns: bool = False,
        fresh: bool = False,
    ) -> None:
        if not hasattr(os, "O_NOFOLLOW"):
            raise CacheUnsupported(
                "this platform has no O_NOFOLLOW; the call cache cannot read entries without "
                "following symlinks, so it is disabled here (documented refusal; M2c adds a "
                "portable fallback). Run without the cache."
            )
        self.root = Path(root)
        if runs_dir is not None and (
            self.root.resolve() == Path(runs_dir).resolve() or _is_under(self.root, Path(runs_dir))
        ):
            raise CacheError(f"cache dir {self.root} must not be under the runs dir {runs_dir}")
        self.reuse_across_campaigns = reuse_across_campaigns
        self.fresh = fresh

    # ------------------------------------------------------------------ paths

    @property
    def entries_dir(self) -> Path:
        return self.root / "entries"

    @property
    def keys_dir(self) -> Path:
        return self.root / "keys"

    @property
    def campaign_keys_dir(self) -> Path:
        return self.keys_dir / "campaigns"

    @property
    def blobs_dir(self) -> Path:
        return self.root / "blobs" / "sha256"

    def _inside(self, path: Path, *, miss: bool) -> Path:
        """``path`` must be a real entry inside the cache root: it may not BE a
        symlink (whatever it points at - a link to another entry inside the
        cache is still an alias we never follow), and its resolved location
        must lie under the cache root's realpath (an ancestor symlink such as
        ``keys`` -> elsewhere is refused). The path is returned UNRESOLVED so
        the caller's ``lstat`` + ``O_NOFOLLOW`` still apply to it."""

        def refuse(reason: str) -> None:
            raise (CacheMissError(reason) if miss else CacheError(reason)) from None

        if path.is_symlink():  # lstat BEFORE resolve: never followed
            refuse(f"{path} is a symlink; refusing to follow it")
        root = self.root.resolve()
        try:
            path.resolve().relative_to(root)
        except ValueError:
            refuse(f"{path} resolves outside the cache root {root} (ancestor symlink?)")
        return path

    def _campaign_key_path(self, key: str, campaign_id: str | None) -> Path:
        return self.campaign_keys_dir / _campaign_epoch(campaign_id) / key

    def _lookup_key_path(self, key: str, campaign_id: str | None) -> Path:
        if self.reuse_across_campaigns:
            return self.keys_dir / key
        return self._campaign_key_path(key, campaign_id)

    def _ensure_dirs(self, campaign_id: str | None) -> None:
        epoch_dir = self.campaign_keys_dir / _campaign_epoch(campaign_id)
        for d in (
            self.entries_dir,
            self.keys_dir,
            self.blobs_dir,
            self.campaign_keys_dir,
            epoch_dir,
        ):
            if d.is_symlink():
                raise CacheError(f"cache path {d} is a symlink; refusing")
            d.mkdir(parents=True, exist_ok=True)

    def _publish_cross_campaign_pointer(
        self, key: str, entry_sha256: str
    ) -> tuple[str, str | None]:
        """Publish the first-writer-wins unscoped index without blocking the
        campaign-scoped pointer when that legacy index is stale or malformed."""
        path = self.keys_dir / key
        try:
            path = self._inside(path, miss=False)
            if path.is_symlink() or path.exists():
                existing = _read_regular_nofollow(path, 256).decode("ascii").strip()
                if not is_sha256(existing):
                    return "refused", None
                return ("exists" if existing == entry_sha256 else "conflict"), existing
            if _write_once(path, (entry_sha256 + "\n").encode("ascii")):
                return "stored", None
            existing = _read_regular_nofollow(path, 256).decode("ascii").strip()
            if not is_sha256(existing):
                return "refused", None
            return ("exists" if existing == entry_sha256 else "conflict"), existing
        except (CacheError, CacheMissError, OSError, UnicodeError):
            return "refused", None

    # ------------------------------------------------------------------ lookup

    def lookup(
        self,
        *,
        idempotency_key: str,
        prompt_sha256: str,
        executable_sha256: str | None,
        campaign_id: str | None,
    ) -> CacheHit | CacheMiss:
        if self.fresh:
            return CacheMiss("fresh requested: lookup skipped")
        if not is_sha256(idempotency_key):
            return CacheMiss("idempotency key is not a sha256")
        if executable_sha256 is None or not is_sha256(executable_sha256):
            return CacheMiss("worker is unpinned or disabled: no current executable pin")
        try:
            return self._lookup(idempotency_key, prompt_sha256, executable_sha256, campaign_id)
        except CacheMissError as exc:
            return CacheMiss(str(exc))
        except (OSError, ValueError, ValidationError) as exc:
            return CacheMiss(f"{type(exc).__name__}: {exc!s:.200}")

    def _lookup(
        self, key: str, prompt_sha256: str, executable_sha256: str, campaign_id: str | None
    ) -> CacheHit:
        pointer = (
            _read_regular_nofollow(
                self._inside(self._lookup_key_path(key, campaign_id), miss=True), 256
            )
            .decode("ascii")
            .strip()
        )
        if not is_sha256(pointer):
            raise CacheMissError("key file does not name an entry sha256")
        raw = _read_regular_nofollow(
            self._inside(self.entries_dir / pointer, miss=True), MAX_ENTRY_BYTES
        )
        if sha256_hex(raw) != pointer:
            raise CacheMissError("entry bytes do not hash to the entry name")
        entry = json.loads(raw)
        if not isinstance(entry, dict):
            raise CacheMissError("entry is not an object")
        if entry.get("schema_version") != SCHEMA_VERSION:
            raise CacheMissError(
                f"entry schema_version {entry.get('schema_version')!r} != {SCHEMA_VERSION!r}"
            )
        if entry.get("idempotency_key") != key:
            raise CacheMissError("entry idempotency_key mismatch")
        if entry.get("prompt_sha256") != prompt_sha256:
            raise CacheMissError("prompt_sha256 mismatch")
        material = entry.get("key_material")
        if not isinstance(material, dict) or material.get("executable_sha256") != executable_sha256:
            raise CacheMissError("executable_sha256 differs from the current pin")
        if entry.get("status") != WorkerStatus.OK.value:
            raise CacheMissError(f"entry status {entry.get('status')!r} is not ok")
        hits = entry.get("scan_hits")
        if not isinstance(hits, int) or isinstance(hits, bool) or hits != 0:
            raise CacheMissError(f"entry has scan_hits={hits!r} (contaminated or unknown)")
        if not entry.get("model_executed"):
            raise CacheMissError("entry has no model_executed")
        if not self.reuse_across_campaigns and entry.get("campaign_id") != campaign_id:
            raise CacheMissError(
                f"campaign-scoped entry {entry.get('campaign_id')!r} != {campaign_id!r}"
            )
        invocation = Invocation.model_validate(entry.get("invocation"))
        if invocation.idempotency_key != key or invocation.status is not WorkerStatus.OK:
            raise CacheMissError("cached invocation does not match the entry")
        shas = entry.get("blob_shas")
        if not isinstance(shas, dict):
            raise CacheMissError("entry has no blob_shas")
        blobs: dict[str, bytes] = {}
        for kind in BLOB_KINDS:
            sha = shas.get(kind)
            if sha is None:
                continue
            if not isinstance(sha, str) or not is_sha256(sha):
                raise CacheMissError(f"blob sha for {kind} is not a sha256")
            data = _read_regular_nofollow(
                self._inside(self.blobs_dir / sha, miss=True), MAX_ENTRY_BYTES
            )
            if sha256_hex(data) != sha:
                raise CacheMissError(f"blob {kind} does not hash to its name")
            blobs[kind] = data
        return CacheHit(pointer, entry, invocation, blobs)

    # ------------------------------------------------------------------ store

    def store(
        self,
        writer: RunWriter,
        *,
        result: WorkerResult,
        invocation: Invocation,
        key_material: dict[str, Any],
        prompt_sha256: str,
        blobs: dict[str, BlobRef],
        scan_hits: int,
        campaign_id: str | None,
    ) -> StoreResult:
        """Write-once. The entry bytes are whatever ``put_blob`` wrote for
        the run (redacted); the blobs are copied from the run's blob files."""
        if invocation.idempotency_key != result.idempotency_key:
            raise CacheError("invocation and result disagree on the idempotency key")
        entry: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "idempotency_key": invocation.idempotency_key,
            "key_material": dict(key_material),
            "prompt_sha256": prompt_sha256,
            "status": result.status.value,
            "text": result.text,
            "structured": result.structured,
            "usage": result.usage.model_dump(mode="json") if result.usage else None,
            "cost_usd": result.cost_usd,
            "model_executed": result.model_executed,
            "origin_run_id": writer.run_id,
            "origin_invocation_id": invocation.invocation_id,
            "blob_shas": {k: ref.sha256 for k, ref in blobs.items() if k in BLOB_KINDS},
            "scan_hits": int(scan_hits),
            "campaign_id": campaign_id,
            "invocation": invocation.model_dump(mode="json"),
        }
        ref = writer.put_blob(canonical_bytes(entry))  # redacted before hashing
        data = ref.path.read_bytes()
        if sha256_hex(data) != ref.sha256:
            raise CacheRefused("the run's entry blob does not hash to its name")
        self._ensure_dirs(campaign_id)
        campaign_key_dir = self._campaign_key_path(invocation.idempotency_key, campaign_id).parent
        for d in (
            self.entries_dir,
            self.keys_dir,
            self.blobs_dir,
            self.campaign_keys_dir,
            campaign_key_dir,
        ):
            self._inside(d, miss=False)
        key_path = self._inside(
            self._campaign_key_path(invocation.idempotency_key, campaign_id), miss=False
        )
        if key_path.is_symlink() or key_path.exists():
            try:
                existing = _read_regular_nofollow(key_path, 256).decode("ascii").strip()
            except CacheMissError as exc:
                return StoreResult("conflict", ref.sha256, f"unreadable: {exc}")
            if existing == ref.sha256:
                cross_outcome, cross_existing = self._publish_cross_campaign_pointer(
                    invocation.idempotency_key, ref.sha256
                )
                return StoreResult("exists", ref.sha256, existing, cross_outcome, cross_existing)
            return StoreResult("conflict", ref.sha256, existing)
        _write_once(self.entries_dir / ref.sha256, data)  # same name = same bytes
        for kind, bref in blobs.items():
            if kind not in BLOB_KINDS:
                continue
            target = self.blobs_dir / bref.sha256
            if target.is_symlink():
                raise CacheRefused(f"cache blob path {target} is a symlink; refusing")
            if not target.exists():
                blob_bytes = bref.path.read_bytes()
                if sha256_hex(blob_bytes) != bref.sha256:
                    raise CacheRefused(f"run blob {bref.sha256} does not hash to its name")
                _write_once(target, blob_bytes)
        if not _write_once(key_path, (ref.sha256 + "\n").encode("ascii")):
            existing = _read_regular_nofollow(key_path, 256).decode("ascii").strip()
            scoped = StoreResult(
                "exists" if existing == ref.sha256 else "conflict", ref.sha256, existing
            )
        else:
            scoped = StoreResult("stored", ref.sha256)
        cross_outcome, cross_existing = self._publish_cross_campaign_pointer(
            invocation.idempotency_key, ref.sha256
        )
        return StoreResult(
            scoped.outcome,
            scoped.entry_sha256,
            scoped.existing_sha256,
            cross_outcome,
            cross_existing,
        )


# --------------------------------------------------------------------------- replay


@dataclass(frozen=True)
class Replay:
    invocation: Invocation
    cost: CostRecord
    result: WorkerResult
    blobs: dict[str, BlobRef]


def replay_hit(writer: RunWriter, hit: CacheHit, *, campaign_id: str | None) -> Replay:
    """Copy the cached blobs into THIS run (through ``put_blob``; the hash
    must survive re-redaction), re-append the cached ``Invocation`` with
    ``reused_from``, a ``CostRecord(counted=False)`` and ``invocation.reused``."""
    refs: dict[str, BlobRef] = {}
    for kind, data in hit.blobs.items():
        ref = writer.put_blob(data)
        expected = hit.entry["blob_shas"][kind]
        if ref.sha256 != expected:
            raise CacheRefused(
                f"cached {kind} blob changed under re-redaction ({ref.sha256[:12]} != "
                f"{expected[:12]}); not replaying"
            )
        refs[kind] = ref
    origin = hit.invocation
    invocation = origin.model_copy(update={"reused_from": origin.invocation_id})
    writer.append("invocation.finished", invocation)
    usage = origin.usage if isinstance(origin.usage, Usage) else None
    cost = CostRecord(
        invocation_id=invocation.invocation_id,
        attempt=invocation.attempt,
        cost_usd=origin.cost_usd,
        usage=usage,
        counted=False,
        estimated=False,
        cost_known=origin.cost_usd is not None,
    )
    writer.append("cost", cost)
    writer.append(
        "invocation.reused",
        {
            "invocation_id": invocation.invocation_id,
            "reused_from": origin.invocation_id,
            "origin_run_id": hit.entry.get("origin_run_id"),
            "entry_sha256": hit.entry_sha256,
            "entry_campaign_id": hit.entry.get("campaign_id"),
            "campaign_id": campaign_id,
            "contaminated": int(hit.entry.get("scan_hits", 0)) > 0,
            "blob_shas": {k: r.sha256 for k, r in refs.items()},
        },
    )
    return Replay(invocation, cost, hit.result, refs)
