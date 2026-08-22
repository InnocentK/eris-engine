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
Span = tuple[int, int, str]


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
    r"|\x1b[ -/]+[0-~]"  # nF sequences, e.g. charset designation ESC ( B
    r"|\x1b[@-Z\\-_]"  # other two-byte ESC sequences
    r"|[\x80-\x9f]"  # C1 controls
)
# A fold is exactly ONE line break (+ continuation indentation). A blank line
# ends a wrapped token, so text after it is never joined.
_FOLD_RE = re.compile(r"(?<![\r\n])(?:\r\n|\n|\r)(?![\r\n])[ \t]*")
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
    """Pattern + exact-value redactor. Reusable; ordinals restart per call.

    Two matching passes: the original text, then the folded view where only
    matches that actually CROSS a removed line break are accepted (trimmed
    back to the last fold boundary at which the candidate still fully
    matches, so a secret at end-of-line does not swallow the next line).
    """

    def __init__(self, exact_values: Iterable[str] = ()) -> None:
        self._exact = tuple(v for v in exact_values if len(v) >= MIN_EXACT_VALUE_LEN)
        self._rx = _compile(self._exact)

    @property
    def exact_value_count(self) -> int:
        return len(self._exact)

    # -- pattern spans -----------------------------------------------------

    def _direct_spans(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for m in self._rx.finditer(text):
            pid = _match_id(m)
            group = _GROUP_FOR[pid]
            spans.append((m.start(group), m.end(group), pid))
        return spans

    def _folded_spans(self, folded: str, anchors: list[tuple[int, int]]) -> list[Span]:
        fold_points = [f for f, _ in anchors[1:]]
        spans: list[Span] = []
        for m in self._rx.finditer(folded):
            s, e = m.start(), m.end()
            lo = bisect_right(fold_points, s)
            hi = bisect_right(fold_points, e - 1)
            inner = fold_points[lo:hi]
            if not inner:
                continue  # does not cross a line break: the direct pass owns it
            pid = _match_id(m)
            chosen = m
            for cut in reversed(inner):
                cand = self._rx.fullmatch(folded, s, cut)
                if cand is not None and _match_id(cand) == pid:
                    chosen = cand
                    break
            group = _GROUP_FOR[pid]
            fs, fe = chosen.start(group), chosen.end(group)
            spans.append(
                (_to_original(anchors, fs, end=False), _to_original(anchors, fe, end=True), pid)
            )
        return spans

    # -- base64 spans ------------------------------------------------------

    def _b64_hit(self, run: str) -> str | None:
        decoded = _try_b64(run)
        if decoded is None:
            return None
        inner = self._rx.search(decoded)
        return None if inner is None else "b64_" + _match_id(inner)

    def _direct_b64_spans(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for m in _B64_RE.finditer(text):
            pid = self._b64_hit(m.group(0))
            if pid is not None:
                spans.append((m.start(), m.end(), pid))
        return spans

    def _folded_b64_spans(self, folded: str, anchors: list[tuple[int, int]]) -> list[Span]:
        fold_points = [f for f, _ in anchors[1:]]
        spans: list[Span] = []
        for m in _B64_RE.finditer(folded):
            s, e = m.start(), m.end()
            inner = fold_points[bisect_right(fold_points, s) : bisect_right(fold_points, e - 1)]
            if not inner:
                continue
            for cut in (e, *reversed(inner)):
                pid = self._b64_hit(folded[s:cut])
                if pid is not None:
                    spans.append(
                        (
                            _to_original(anchors, s, end=False),
                            _to_original(anchors, cut, end=True),
                            pid,
                        )
                    )
                    break
        return spans

    # -- assembly ----------------------------------------------------------

    def redact(self, data: str | bytes) -> RedactResult:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        text = strip_ansi(text)
        direct = self._direct_spans(text) + self._direct_b64_spans(text)
        folded, anchors = _fold(text)
        crossing: list[Span] = []
        if len(anchors) > 1:
            crossing = self._folded_spans(folded, anchors) + self._folded_b64_spans(folded, anchors)
        accepted = _merge_spans(direct, crossing)
        if not accepted:
            return RedactResult(text, {})
        out: list[str] = []
        counts: dict[str, int] = {}
        pos = 0
        for start, end, pid in accepted:
            counts[pid] = counts.get(pid, 0) + 1
            out.append(text[pos:start])
            out.append(f"[REDACTED:{pid}#{counts[pid]}]")
            pos = end
        out.append(text[pos:])
        return RedactResult("".join(out), counts)

    def redact_bytes(self, data: bytes) -> tuple[bytes, dict[str, int]]:
        result = self.redact(data)
        return result.text.encode("utf-8"), result.counts


def _merge_spans(direct: list[Span], crossing: list[Span]) -> list[Span]:
    """Non-overlapping spans. Direct (unfolded) matches have priority; a
    line-crossing match is kept only where it overlaps no direct match."""
    accepted: list[Span] = []
    cursor = -1
    for span in sorted(direct, key=lambda sp: (sp[0], -(sp[1] - sp[0]))):
        if span[0] >= cursor:
            accepted.append(span)
            cursor = span[1]
    starts = [sp[0] for sp in accepted]
    extra: list[Span] = []
    for span in sorted(crossing, key=lambda sp: (sp[0], -(sp[1] - sp[0]))):
        i = bisect_right(starts, span[0])
        if i > 0 and accepted[i - 1][1] > span[0]:
            continue  # overlaps the direct span before it
        if i < len(accepted) and accepted[i][0] < span[1]:
            continue  # overlaps the direct span after it
        if extra and extra[-1][1] > span[0]:
            continue
        extra.append(span)
    return sorted(accepted + extra, key=lambda sp: sp[0])


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


class CredentialFileError(RuntimeError):
    """A declared credential file exists but cannot be parsed (fail closed)."""


@dataclass
class CredentialValues:
    values: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)  # declared but missing files


def load_credential_values(paths: Iterable[Path]) -> CredentialValues:
    """Secret VALUES from JSON credential files (kept in memory only).

    Any string >= 16 chars under a credential-looking key is collected. A
    declared file that is MISSING is a warning (for the doctor); a file that
    EXISTS but cannot be read or parsed raises :class:`CredentialFileError`
    because its secrets could not be added to the redactor.
    """
    out = CredentialValues()
    values: list[str] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            out.warnings.append(f"credential file {path} not found")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CredentialFileError(
                f"credential file {path} exists but cannot be parsed: {exc.__class__.__name__}"
            ) from exc
        _collect_strings(data, False, values)
    out.values = sorted(set(values))
    return out


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
