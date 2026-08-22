"""``eris`` console entry point: ``policy pin`` (``doctor`` is added with eris.doctor)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from eris.policy import PolicyError, pin_executables

DEFAULT_POLICY = Path("policies/default.yaml")


def _cmd_policy_pin(args: argparse.Namespace) -> int:
    try:
        report = pin_executables(Path(args.policy), Path(args.pins) if args.pins else None)
    except PolicyError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    for name, digest in sorted(report.pinned.items()):
        print(f"PINNED  {name}: {digest}")
    for name in report.missing:
        print(f"MISSING {name}: executable not found (left UNPINNED; recorded absence)")
    print(f"wrote {report.pins_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eris")
    sub = parser.add_subparsers(dest="command", required=True)

    policy = sub.add_parser("policy", help="policy helpers")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    pin = policy_sub.add_parser("pin", help="compute executable sha256 pins -> pins.yaml")
    pin.add_argument("--policy", default=str(DEFAULT_POLICY))
    pin.add_argument("--pins", default=None)
    pin.set_defaults(func=_cmd_policy_pin)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
