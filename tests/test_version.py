from __future__ import annotations

import re

import eris
from eris.version import __version__


def test_version_is_semver_and_exported() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert eris.__version__ == __version__
