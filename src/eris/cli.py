"""``eris`` console entry point: ``doctor`` and ``policy pin``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from eris.doctor import run_doctor
from eris.policy import LoadedPolicy, PolicyError, pin_executables
from eris.refresh import (
    CampaignSpecV1,
    RefreshError,
    RefreshNotDurable,
    detect,
    preflight,
    verify,
)
from eris.refresh import apply as apply_refresh

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


def _refresh_inputs(args: argparse.Namespace) -> tuple[CampaignSpecV1, LoadedPolicy, Path]:
    from eris.policy import load_policy

    spec = CampaignSpecV1.load(Path(args.campaign_spec))
    loaded = load_policy(Path(spec.policy_path))
    state = Path(args.state_dir) if args.state_dir else loaded.pins_path.parent / "pin-state"
    return spec, loaded, state


def _cmd_refresh_detect(args: argparse.Namespace) -> int:
    try:
        spec, loaded, _state = _refresh_inputs(args)
        report = detect(spec, loaded)
    except (PolicyError, RefreshError, ValueError, OSError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    payload = asdict(report)
    if not args.quiet or any(item.status.value != "CLEAN" for item in report.items):
        print(json.dumps(payload, sort_keys=True, default=str))
    return 1 if report.blocking else 0


def _cmd_refresh_verify(args: argparse.Namespace) -> int:
    try:
        spec, loaded, state = _refresh_inputs(args)
        registered = verify(
            spec,
            loaded,
            worker_id=args.worker,
            authorized_sha256=args.authorize_sha,
            state_dir=state,
            live_probe=bool(args.live_probe),
        )
    except (PolicyError, RefreshError, ValueError, OSError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"receipt_sha256": registered.sha256, **registered.receipt.model_dump(mode="json")},
            sort_keys=True,
        )
    )
    return 0 if registered.receipt.decision.value == "ELIGIBLE" else 1


def _cmd_refresh_apply(args: argparse.Namespace) -> int:
    try:
        spec, loaded, state = _refresh_inputs(args)
        result = apply_refresh(spec, loaded, receipt_sha256=args.receipt, state_dir=state)
    except RefreshNotDurable as exc:
        print(json.dumps({"status": "MANIFEST_NOT_DURABLE", "error": str(exc)}), file=sys.stderr)
        return 1
    except (PolicyError, RefreshError, ValueError, OSError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def _cmd_refresh_preflight(args: argparse.Namespace) -> int:
    try:
        spec, loaded, state = _refresh_inputs(args)
        if args.receipt:
            from eris.policy import load_policy

            result: dict[str, str] | None = None

            def full_postcheck() -> None:
                nonlocal result
                result = preflight(spec, load_policy(Path(spec.policy_path)))

            apply_refresh(
                spec,
                loaded,
                receipt_sha256=args.receipt,
                state_dir=state,
                postcheck=full_postcheck,
            )
            if result is None:
                raise RefreshError(
                    "refresh apply returned without running the full preflight postcheck"
                )
        else:
            result = preflight(spec, loaded)
    except RefreshNotDurable as exc:
        print(json.dumps({"status": "MANIFEST_NOT_DURABLE", "error": str(exc)}), file=sys.stderr)
        return 1
    except (PolicyError, RefreshError, ValueError, OSError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


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
    refresh = policy_sub.add_parser("refresh", help="detect, verify, and CAS-publish CLI drift")
    refresh_sub = refresh.add_subparsers(dest="refresh_command", required=True)
    for name, func in (
        ("detect", _cmd_refresh_detect),
        ("verify", _cmd_refresh_verify),
        ("apply", _cmd_refresh_apply),
        ("preflight", _cmd_refresh_preflight),
    ):
        command = refresh_sub.add_parser(name)
        command.add_argument("--campaign-spec", required=True)
        command.add_argument("--state-dir", default=None)
        command.set_defaults(func=func)
        if name == "detect":
            command.add_argument("--quiet", action="store_true")
        elif name == "verify":
            command.add_argument("--worker", required=True)
            command.add_argument("--authorize-sha", required=True)
            command.add_argument(
                "--live-probe",
                action="store_true",
                help="claim and run the one exact-SHA no-retry live probe",
            )
        elif name in ("apply", "preflight"):
            command.add_argument("--receipt", required=name == "apply", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
