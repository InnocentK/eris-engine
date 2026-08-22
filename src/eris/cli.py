"""``eris`` console entry point: ``doctor`` and ``policy pin``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from eris.doctor import run_doctor
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


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = run_doctor(
        policy_path=Path(args.policy), env_file=Path(args.env_file), probe=bool(args.probe)
    )
    print(report.render())
    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eris")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="preflight: config/filesystem only; prints key NAMES")
    doctor.add_argument("--policy", default=str(DEFAULT_POLICY))
    doctor.add_argument("--env-file", default=".env")
    doctor.add_argument("--probe", action="store_true", help="also run `<cli> --version`")
    doctor.set_defaults(func=_cmd_doctor)

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
