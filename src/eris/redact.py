"""Redaction: the only thing that stands between worker output and disk.

Pipeline (:meth:`Redactor.redact`):

1. Strip ANSI/C1 escape sequences (so a secret interleaved with colour codes
   becomes contiguous).
2. Build a *folded* view with line breaks (and continuation indentation)
   removed, keeping an offset map back to the original text, so a secret
   wrapped across lines is still one token.
3. Match the pattern set (plus exact values) on the folded view; map spans
   back; replace with ``[REDACTED:<pattern_id>#<ordinal>]``. Placeholders
   carry NO fingerprint of the secret.
4. Find base64 runs of >= 32 chars, decode, re-match; a hit replaces the
   whole run with ``[REDACTED:b64_<pattern_id>#<ordinal>]``.

Whole-buffer semantics: :class:`StreamRedactor` buffers chunks and redacts on
``flush`` so a secret split across chunks cannot leak; output sizes are bounded
by the launcher's byte caps anyway.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from bisect import bisect_right
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MIN_EXACT_VALUE_LEN = 8
MIN_B64_RUN = 32


@dataclass(frozen=True)
class SecretPattern:
    id: str
    regex: str
    value_group: str | None = None  # replace only this named group, not the whole match


# Order matters: at the same position the first alternative wins.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "private_key_block",
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
    ),
    SecretPattern("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    SecretPattern("openai_key", r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    SecretPattern("xai_key", r"xai-[A-Za-z0-9]{20,}"),
    SecretPattern("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    SecretPattern("aws_access_key_id", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    SecretPattern(
        "github_token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
    ),
    SecretPattern("slack_token", r"xox[abpr]-[A-Za-z0-9-]{10,}"),
    SecretPattern("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    SecretPattern(
        "bearer_token",
        r"(?i:bearer)[ \t]+(?P<bearer_value>[A-Za-z0-9._~+/=-]{16,})",
        value_group="bearer_value",
    ),
    SecretPattern(
        "url_credentials",
        r"[a-z][a-z0-9+.-]*://(?P<url_userinfo>[^/\s:@]+:[^/\s@]+)@",
        value_group="url_userinfo",
    ),
    SecretPattern(
        "kv_assignment",
        r"(?i:\b(?:api[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d|authorization|"
        r"access[_-]?key|private[_-]?key|client[_-]?secret)\b)[\"']?\s*[=:]\s*[\"']?"
        r"(?P<kv_value>[^\s\"',;]{8,})",
        value_group="kv_value",
    ),
)

PATTERN_IDS: frozenset[str] = frozenset(p.id for p in SECRET_PATTERNS)

_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC
    r"|\x1b[PX^_][^\x1b]*\x1b\\"  # DCS/SOS/PM/APC
    r"|\x1b[@-Z\\-_]"  # other two-byte ESC sequences
    r"|[\x80-\x9f]"  # C1 controls
)
_FOLD_RE = re.compile(r"[\r\n]+[ \t]*")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % MIN_B64_RUN)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _compile(exact_values: Sequence[str]) -> re.Pattern[str]:
    parts: list[str] = []
    values = sorted(
        {v for v in exact_values if len(v) >= MIN_EXACT_VALUE_LEN}, key=len, reverse=True
    )
    if values:
        parts.append("(?P<exact>" + "|".join(re.escape(v) for v in values) + ")")
    parts.extend(f"(?P<{p.id}>{p.regex})" for p in SECRET_PATTERNS)
    return re.compile("|".join(parts))


_GROUP_FOR: dict[str, str] = {p.id: p.value_group or p.id for p in SECRET_PATTERNS}
_GROUP_FOR["exact"] = "exact"


def _match_id(m: re.Match[str]) -> str:
    # Each alternative is one outer named group; nested value groups close
    # before it, so the outer group is always the last matched group.
    pid = m.lastgroup
    if pid is None or pid not in _GROUP_FOR:
        raise AssertionError(f"unreachable: match outside a pattern group ({pid!r})")
    return pid


def scan(text: str, exact_values: Sequence[str] = ()) -> list[str]:
    """Pattern ids present in ``text`` (after ANSI strip + fold). No replacement."""
    folded, _ = _fold(strip_ansi(text))
    rx = _compile(exact_values)
    return sorted({_match_id(m) for m in rx.finditer(folded)})


def looks_secret_shaped(value: str) -> bool:
    return bool(scan(value))


# --------------------------------------------------------------------------- folding


def _fold(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Remove line breaks (+ continuation indentation).

    Returns the folded text and a list of (folded_offset, original_offset)
    anchors, one per removed run, for mapping folded spans back.
    """
    pieces: list[str] = []
    anchors: list[tuple[int, int]] = [(0, 0)]
    folded_len = 0
    last = 0
    for m in _FOLD_RE.finditer(text):
        seg = text[last : m.start()]
        pieces.append(seg)
        folded_len += len(seg)
        last = m.end()
        anchors.append((folded_len, last))
    pieces.append(text[last:])
    return "".join(pieces), anchors


def _to_original(anchors: list[tuple[int, int]], folded_pos: int, *, end: bool) -> int:
    """Map a folded offset to an original offset.

    For span ends (``end=True``) an offset that sits exactly on a fold anchor
    maps to the position BEFORE the removed whitespace, so a replacement does
    not swallow the trailing newline.
    """
    keys = [a[0] for a in anchors]
    idx = bisect_right(keys, folded_pos) - 1
    if end and idx > 0 and keys[idx] == folded_pos:
        idx -= 1
        f0, o0 = anchors[idx]
        return o0 + (folded_pos - f0)
    f0, o0 = anchors[idx]
    return o0 + (folded_pos - f0)


# --------------------------------------------------------------------------- redactor


@dataclass
class RedactResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    """Pattern + exact-value redactor. Instances are reusable and stateless
    across calls except for nothing: ordinals restart per call."""

    def __init__(self, exact_values: Iterable[str] = ()) -> None:
        self._exact = tuple(v for v in exact_values if len(v) >= MIN_EXACT_VALUE_LEN)
        self._rx = _compile(self._exact)

    @property
    def exact_value_count(self) -> int:
        return len(self._exact)

    def _spans(self, folded: str) -> list[tuple[int, int, str]]:
        spans: list[tuple[int, int, str]] = []
        for m in self._rx.finditer(folded):
            pid = _match_id(m)
            group = _GROUP_FOR[pid]
            spans.append((m.start(group), m.end(group), pid))
        return spans

    def _b64_spans(self, folded: str) -> list[tuple[int, int, str]]:
        spans: list[tuple[int, int, str]] = []
        for m in _B64_RE.finditer(folded):
            run = m.group(0)
            decoded = _try_b64(run)
            if decoded is None:
                continue
            inner = self._rx.search(decoded)
            if inner is None:
                continue
            spans.append((m.start(), m.end(), "b64_" + _match_id(inner)))
        return spans

    def redact(self, data: str | bytes) -> RedactResult:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        text = strip_ansi(text)
        folded, anchors = _fold(text)
        spans = self._spans(folded) + self._b64_spans(folded)
        if not spans:
            return RedactResult(text, {})
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        merged: list[tuple[int, int, str]] = []
        cursor = -1
        for start, end, pid in spans:
            if start < cursor:
                continue  # overlaps an earlier (longer) span
            merged.append((start, end, pid))
            cursor = end
        out: list[str] = []
        counts: dict[str, int] = {}
        pos = 0
        for start, end, pid in merged:
            o_start = _to_original(anchors, start, end=False)
            o_end = _to_original(anchors, end, end=True)
            if o_start < pos:
                continue
            counts[pid] = counts.get(pid, 0) + 1
            out.append(text[pos:o_start])
            out.append(f"[REDACTED:{pid}#{counts[pid]}]")
            pos = o_end
        out.append(text[pos:])
        return RedactResult("".join(out), counts)

    def redact_bytes(self, data: bytes) -> tuple[bytes, dict[str, int]]:
        result = self.redact(data)
        return result.text.encode("utf-8"), result.counts


def _try_b64(run: str) -> str | None:
    if len(run) % 4 == 1:
        return None
    alphabet_url = "-" in run or "_" in run
    padded = run + "=" * (-len(run) % 4)
    try:
        raw = (
            base64.urlsafe_b64decode(padded)
            if alphabet_url
            else base64.b64decode(padded, validate=True)
        )
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="ignore")
    return text if len(text) >= MIN_EXACT_VALUE_LEN else None


class StreamRedactor:
    """Feed chunks, flush once. Buffering is deliberate: a secret split across
    two chunks must never be emitted."""

    def __init__(self, redactor: Redactor) -> None:
        self._redactor = redactor
        self._parts: list[bytes] = []

    def feed(self, chunk: bytes) -> None:
        self._parts.append(chunk)

    def flush(self) -> RedactResult:
        data = b"".join(self._parts)
        self._parts = []
        return self._redactor.redact(data)


# --------------------------------------------------------------------------- exact-value sources

CREDENTIAL_KEY_RE = re.compile(r"(?i)(token|key|secret|password|credential|auth)")


def _collect_strings(obj: Any, key_hint: bool, out: list[str]) -> None:
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            hint = key_hint or bool(CREDENTIAL_KEY_RE.search(str(k)))
            _collect_strings(v, hint, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_strings(v, key_hint, out)
    elif isinstance(obj, str) and key_hint and len(obj) >= 16:
        out.append(obj)


def load_credential_values(paths: Iterable[Path]) -> list[str]:
    """Secret VALUES from JSON credential files (kept in memory only).

    Any string >= 16 chars under a key that looks credential-like is
    collected. Missing or unparsable files are skipped silently - this is a
    best-effort extra layer on top of the pattern set.
    """
    values: list[str] = []
    for path in paths:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        _collect_strings(data, False, values)
    return sorted(set(values))


def parse_dotenv(text: str) -> dict[str, str]:
    """Minimal .env parser: KEY=VALUE lines, optional ``export``, quotes stripped."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            out[key] = value
    return out
