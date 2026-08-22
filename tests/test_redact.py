from __future__ import annotations

import base64
import json
import random
import time
from pathlib import Path

import pytest

from eris.redact import (
    MIN_B64_RUN,
    PATTERN_IDS,
    SECRET_PATTERNS,
    CredentialFileError,
    Redactor,
    StreamRedactor,
    load_credential_values,
    looks_secret_shaped,
    parse_dotenv,
    scan,
    strip_ansi,
)

ANTHROPIC = "sk-ant-api03-" + "Ab3" * 20
OPENAI = "sk-proj-" + "Zq9" * 16
XAI = "xai-" + "Kj7" * 12
GOOGLE = "AIza" + "D" * 35
AWS = "AKIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "x" * 36
SLACK = "xoxb-" + "1234567890-abcdef"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAK\nabcdef\n-----END RSA PRIVATE KEY-----"
EXACT = "hunter2-is-my-exact-secret-value"


def assert_clean(text: str, *secrets: str) -> None:
    for s in secrets:
        assert s not in text, f"secret leaked: {s[:6]}..."
        # no fingerprint: not even the distinctive tail of the secret
        assert s[-12:] not in text


# --------------------------------------------------------------------------- patterns


@pytest.mark.parametrize(
    ("pid", "secret"),
    [
        ("anthropic_key", ANTHROPIC),
        ("openai_key", OPENAI),
        ("xai_key", XAI),
        ("google_api_key", GOOGLE),
        ("aws_access_key_id", AWS),
        ("github_token", GITHUB),
        ("slack_token", SLACK),
        ("jwt", JWT),
        ("private_key_block", PRIVKEY),
    ],
)
def test_each_pattern_redacts_with_placeholder_and_count(pid: str, secret: str) -> None:
    r = Redactor().redact(f"before {secret} after")
    assert_clean(r.text, secret)
    assert r.text == f"before [REDACTED:{pid}#1] after"
    assert r.counts == {pid: 1}
    assert scan(secret) == [pid]
    assert looks_secret_shaped(secret)


def test_anthropic_prefix_wins_over_openai() -> None:
    assert scan(ANTHROPIC) == ["anthropic_key"]


def test_value_group_patterns_keep_the_key_name() -> None:
    r = Redactor().redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
    assert r.text == "Authorization: Bearer [REDACTED:bearer_token#1]"
    r = Redactor().redact('{"api_key": "abcdefgh12345678", "ok": true}')
    assert r.text == '{"api_key": "[REDACTED:kv_assignment#1]", "ok": true}'
    r = Redactor().redact("OPENAI_API_KEY=sk-live-not-a-real-prefix-but-long-enough-xyz")
    # the sk- pattern matches first at the value position
    assert r.counts == {"openai_key": 1}
    r = Redactor().redact("password = 'correct-horse-battery'; next")
    assert r.text == "password = '[REDACTED:kv_assignment#1]'; next"
    r = Redactor().redact("git clone https://alice:s3cretpass@github.com/x/y.git")
    assert r.text == "git clone https://[REDACTED:url_credentials#1]@github.com/x/y.git"


def test_short_or_benign_values_are_left_alone() -> None:
    benign = "token_count: 12345678 and sk-short and password: abc and AKIA123"
    assert Redactor().redact(benign).text == benign
    assert scan("OPENAI_API_KEY") == []
    assert not looks_secret_shaped("api_key_env: OPENAI_API_KEY")


def test_ordinals_count_per_pattern() -> None:
    r = Redactor().redact(f"{OPENAI} {XAI} {OPENAI}")
    assert r.text == "[REDACTED:openai_key#1] [REDACTED:xai_key#1] [REDACTED:openai_key#2]"
    assert r.counts == {"openai_key": 2, "xai_key": 1}
    assert r.total == 3


# --------------------------------------------------------------------------- exact values


def test_exact_values_are_redacted_and_short_ones_ignored() -> None:
    red = Redactor(exact_values=[EXACT, "short", ""])
    assert red.exact_value_count == 1
    r = red.redact(f"x={EXACT} and again {EXACT}.")
    assert r.text == "x=[REDACTED:exact#1] and again [REDACTED:exact#2]."
    assert_clean(r.text, EXACT)


def test_exact_value_with_regex_metacharacters() -> None:
    value = "p@ss.w0rd(+)[x]{y}*?"
    r = Redactor([value]).redact(f"pw {value} end")
    assert r.text == "pw [REDACTED:exact#1] end"


# --------------------------------------------------------------------------- hard cases


def test_split_across_chunks() -> None:
    stream = StreamRedactor(Redactor())
    mid = len(OPENAI) // 2
    stream.feed(f"log: {OPENAI[:mid]}".encode())
    stream.feed(f"{OPENAI[mid:]} done".encode())
    r = stream.flush()
    assert r.text == "log: [REDACTED:openai_key#1] done"
    assert_clean(r.text, OPENAI)
    assert stream.flush().text == ""  # buffer drained


def test_newline_wrapped_secret_is_redacted_without_eating_the_newline() -> None:
    wrapped = OPENAI[:20] + "\n" + OPENAI[20:40] + "\r\n    " + OPENAI[40:]
    r = Redactor().redact(f"key: {wrapped}\nnext line")
    assert r.text == "key: [REDACTED:openai_key#1]\nnext line"
    assert_clean(r.text, OPENAI)


def test_secret_at_end_of_line_keeps_following_text() -> None:
    r = Redactor().redact(f"a {XAI}\nb\nc")
    assert r.text == "a [REDACTED:xai_key#1]\nb\nc"


def test_ansi_interleaved_secret() -> None:
    colored = "\x1b[31m" + OPENAI[:10] + "\x1b[0m" + OPENAI[10:30] + "\x1b[1;32m" + OPENAI[30:]
    r = Redactor().redact(f"{colored}\x1b[0m tail \x1b]0;title\x07")
    assert r.text == "[REDACTED:openai_key#1] tail "
    assert strip_ansi("\x1b[2Ka\x9bb\x1b(Bc") == "abc"


def test_base64_encoded_secret_is_redacted_whole_run() -> None:
    payload = f"key {OPENAI}".encode()
    b64 = base64.b64encode(payload).decode()
    assert len(b64) >= MIN_B64_RUN
    r = Redactor().redact(f"blob: {b64} end")
    assert r.text == "blob: [REDACTED:b64_openai_key#1] end"
    assert b64 not in r.text
    url = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    r = Redactor().redact(f"blob: {url} end")
    assert r.counts == {"b64_openai_key": 1}
    # an encoded assignment is reported under the (earlier-matching) kv pattern
    kv = base64.b64encode(f"token={OPENAI}".encode()).decode()
    assert Redactor().redact(kv).counts == {"b64_kv_assignment": 1}
    # 76-column wrapped base64 (MIME style) is folded and still caught
    wrapped = "\n".join(b64[i : i + 16] for i in range(0, len(b64), 16))
    r = Redactor().redact(f"{wrapped}\n\nnext")
    assert r.counts == {"b64_openai_key": 1}
    assert b64[:16] not in r.text and b64[-16:] not in r.text
    assert r.text.endswith("\n\nnext")
    # Ambiguous case: an alphanumeric line directly after a wrapped run is
    # indistinguishable from more base64, so it is swallowed (over-redaction
    # is the safe side). Documented in docs/SECURITY.md.
    r = Redactor().redact(f"{wrapped}\nnext")
    assert r.counts == {"b64_openai_key": 1} and "next" not in r.text


def test_base64_of_exact_value() -> None:
    b64 = base64.b64encode(f"x:{EXACT}".encode()).decode()
    r = Redactor([EXACT]).redact(b64)
    assert r.text == "[REDACTED:b64_exact#1]"


def test_base64_false_positives_untouched() -> None:
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    r = Redactor().redact(f"sha256 {sha} and {'A' * 40}")
    assert sha in r.text and "A" * 40 in r.text


def test_bytes_input_with_invalid_utf8() -> None:
    text, counts = Redactor().redact_bytes(b"\xff\xfe " + OPENAI.encode() + b" \xc3")
    assert counts == {"openai_key": 1}
    assert OPENAI.encode() not in text


def test_overlapping_matches_prefer_longest_first() -> None:
    # A bearer token whose value is itself an sk- key: one placeholder, no leak.
    r = Redactor().redact(f"Bearer {OPENAI}")
    assert_clean(r.text, OPENAI)
    assert r.total == 1


def test_private_key_multiline_is_fully_replaced() -> None:
    r = Redactor().redact(f"cfg:\n{PRIVKEY}\nend")
    assert r.text == "cfg:\n[REDACTED:private_key_block#1]\nend"


def test_no_fingerprint_in_placeholder() -> None:
    r = Redactor([EXACT]).redact(" ".join([ANTHROPIC, OPENAI, XAI, EXACT, JWT]))
    for token in r.text.replace("[", " ").replace("]", " ").split():
        assert token.startswith("REDACTED:")
        assert not any(token.endswith(s[-6:]) for s in (ANTHROPIC, OPENAI, XAI, EXACT, JWT))


def test_fifty_megabytes_with_sprinkled_secrets() -> None:
    rng = random.Random(7)
    words = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
    line = " ".join(rng.choice(words) for _ in range(12)) + "\n"
    n_lines = (50 * 1024 * 1024) // len(line) + 1
    lines = [line] * n_lines
    positions = rng.sample(range(n_lines), 25)
    for i, pos in enumerate(positions):
        secret = [OPENAI, XAI, ANTHROPIC, EXACT][i % 4]
        lines[pos] = f"leak {secret} here\n"
    big = "".join(lines)
    assert len(big) >= 50 * 1024 * 1024
    t0 = time.monotonic()
    r = Redactor([EXACT]).redact(big)
    elapsed = time.monotonic() - t0
    assert r.total == 25
    assert_clean(r.text, OPENAI, XAI, ANTHROPIC, EXACT)
    assert elapsed < 60, f"redaction too slow: {elapsed:.1f}s"


def test_every_declared_pattern_has_a_test_secret() -> None:
    assert PATTERN_IDS == {p.id for p in SECRET_PATTERNS}
    covered = {
        "anthropic_key",
        "openai_key",
        "xai_key",
        "google_api_key",
        "aws_access_key_id",
        "github_token",
        "slack_token",
        "jwt",
        "private_key_block",
        "bearer_token",
        "url_credentials",
        "kv_assignment",
    }
    assert covered == PATTERN_IDS


# --------------------------------------------------------------------------- sources


def test_load_credential_values_from_json_files(tmp_path: Path) -> None:
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps(
            {
                "tokens": {"access_token": "A" * 40, "refresh_token": "R" * 40, "id": "short"},
                "OPENAI_API_KEY": OPENAI,
                "last_refresh": "2026-08-21T00:00:00Z",
                "nested": [{"secret": "n" * 20}],
            }
        )
    )
    creds = load_credential_values([auth, tmp_path / "missing.json"])
    assert set(creds.values) == {"A" * 40, "R" * 40, OPENAI, "n" * 20}
    assert "2026-08-21T00:00:00Z" not in creds.values
    # a declared file that is MISSING is a warning, not fatal
    assert creds.warnings == [f"credential file {tmp_path / 'missing.json'} not found"]
    # a declared file that EXISTS but cannot be parsed fails closed
    (tmp_path / "bad.json").write_text("{not json")
    with pytest.raises(CredentialFileError, match="cannot be parsed"):
        load_credential_values([auth, tmp_path / "bad.json"])
    assert load_credential_values([]).values == []


def test_parse_dotenv() -> None:
    env = parse_dotenv(
        "# comment\nOPENAI_API_KEY=sk-x\nexport XAI_API_KEY='quoted value'\n"
        'EMPTY=\nBAD LINE\n1BAD=x\nDQ="a=b"\n'
    )
    assert env == {
        "OPENAI_API_KEY": "sk-x",
        "XAI_API_KEY": "quoted value",
        "EMPTY": "",
        "DQ": "a=b",
    }
