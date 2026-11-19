from __future__ import annotations

import argparse
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Sequence

from scanner.scan_runner import run_scan, DEFAULT_PORTS, PORT_PROFILES
from scanner.scope import ScopePolicy, ScopeValidationError
from scanner.service_fingerprints import guess_service
from scanner.targets import ResolvedTarget, resolve_target_specs
from scanner.utils import parse_ports


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOPE_FILE = (
    PROJECT_ROOT / "config" / "scope.example.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Approved-scope infrastructure port scanner"
        )
    )
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser(
        "scan",
        help="run an approved scan",
    )
    scan_parser.add_argument(
        "--target",
        action="append",
        required=True,
        help=(
            "IP, CIDR or hostname. Repeat the option for "
            "multiple inputs."
        ),
    )
    scan_parser.add_argument(
        "--scope-file",
        type=Path,
        default=DEFAULT_SCOPE_FILE,
        help=(
            "JSON file containing the approved scan scope "
            f"(default: {DEFAULT_SCOPE_FILE})"
        ),
    )
    selection = scan_parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--ports",
        default=None,
        help="port expression such as 22,80,443 or 1-1024",
    )
    selection.add_argument("--profile", choices=tuple(PORT_PROFILES), help="Approved service-port profile; existing scope limits still apply")
    scan_parser.add_argument("--output-json", type=Path, help="New file for sanitized raw observations; saved before DB access")
    scan_parser.add_argument("--no-db", action="store_true", help="Preserve JSON without accessing the database")
    scan_parser.add_argument("--asset-namespace", default="legacy", help="Explicit customer/VPC asset namespace; default preserves legacy identity")
    scan_parser.add_argument("--max-duration", type=float, help="Stop scheduling after this many seconds; remaining ports stay NOT_TESTED")
    scan_parser.add_argument(
        "-sT",
        action="store_true",
        help="TCP scan",
    )
    scan_parser.add_argument(
        "-sU",
        action="store_true",
        help="UDP scan",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
    )
    scan_parser.add_argument(
        "--max-workers",
        type=int,
        default=100,
    )
    scan_parser.add_argument(
        "-sV",
        action="store_true",
        help="collect TCP banners and identify advertised products/versions",
    )
    scan_parser.add_argument(
        "-oN",
        "--output-normal",
        type=Path,
        metavar="FILE",
        help="save text output",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "validate and display the approved expansion "
            "without scanning or using the database"
        ),
    )
    return parser


def determine_scan_mode(
    tcp_flag: bool,
    udp_flag: bool,
) -> tuple[str, bool, bool]:
    if not tcp_flag and not udp_flag:
        return "tcp", False, False

    if tcp_flag and udp_flag:
        return "tcp+udp", True, False

    if tcp_flag:
        return "tcp", False, False

    return "udp", False, True


def attach_target_metadata(
    results: dict,
    targets: Sequence[ResolvedTarget],
) -> None:
    metadata_by_ip = {
        target.ip: target for target in targets
    }

    for target_result in results["targets"]:
        metadata = metadata_by_ip[target_result["ip"]]
        target_result["input_target"] = (
            metadata.input_target
        )
        target_result["resolution_type"] = (
            metadata.resolution_type
        )


def print_scan_plan(
    policy: ScopePolicy,
    targets: Sequence[ResolvedTarget],
    port_count: int,
    worker_count: int,
) -> None:
    print(f"Authorization: {policy.authorization_ref}")
    print(f"Scope: {policy.scope_uid} ({policy.name})")
    print(f"Resolved targets: {len(targets)}")
    print(f"Ports per target: {port_count}")
    print(f"Max workers: {worker_count}")

    for target in targets:
        print(
            f"  {target.input_target} -> {target.ip} "
            f"[{target.resolution_type}]"
        )


def render_results(
    results: dict,
    show_versions: bool,
) -> list[str]:
    lines = [f"Starting Scan at {results['started_at']}"]

    for target_info in results["targets"]:
        ip = target_info["ip"]
        lines.append("")
        lines.append(f"Scan report for {ip}")

        if target_info.get("error"):
            lines.append(
                f"[!] Error: {target_info['error']}"
            )
            continue

        port_results = target_info["results"]
        closed_count = sum(
            1
            for result in port_results
            if result["state"] == "closed"
        )
        lines.append("Target scan observations recorded")
        lines.append(f"closed ports: {closed_count}")
        counts = {state: sum(r["state"] == state for r in port_results) for state in sorted({r["state"] for r in port_results})}
        lines.append("State counts: " + json.dumps(counts, sort_keys=True))
        lines.append("Ports outside the requested range: NOT_TESTED")
        header = (
            "PORT\tSTATE\tSERVICE\tPRODUCT\tVERSION\tREASON"
            if show_versions
            else "PORT\tSTATE\tSERVICE\tREASON"
        )
        lines.append(header)

        for result in sorted(
            port_results,
            key=lambda item: (
                item["protocol"],
                item["port"],
            ),
        ):
            port = result["port"]
            protocol = result["protocol"]
            state = result["state"]
            service = (
                result.get("service")
                or guess_service(port, protocol)
                or "-"
            )
            version = result.get("version") or "-"
            product = result.get("product") or "-"
            fingerprint = result.get("fingerprint") or {}
            source = result.get("service_source") or ("observed" if fingerprint.get("source") not in (None, "port_hint") else "guessed")
            service = f"{service} ({source})"
            reason = result.get("reason") or result.get("error_code") or "-"

            if show_versions:
                lines.append(
                    f"{port}/{protocol}\t{state}\t"
                    f"{service:<15}\t{product}\t{version}\t{reason}"
                )
            else:
                lines.append(
                    f"{port}/{protocol}\t{state}\t{service}\t{reason}"
                )

    started_at = datetime.fromisoformat(
        results["started_at"]
    )
    finished_at = datetime.fromisoformat(
        results["finished_at"]
    )
    duration = results.get("duration_seconds", (
        finished_at - started_at
    ).total_seconds())
    lines.append("")
    lines.append(
        "Scan done: "
        f"{len(results['targets'])} target(s) in "
        f"{duration:.3f} seconds"
    )
    lines.append("Scan status: " + results.get("status", "LEGACY_UNKNOWN"))
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        if not math.isfinite(args.timeout) or not 0 < args.timeout <= 30:
            raise ValueError(
                "timeout은 0초 초과 30초 이하여야 합니다."
            )

        if args.max_duration is not None and (not math.isfinite(args.max_duration) or not 0 < args.max_duration <= 86400):
            raise ValueError("max-duration must be finite and in (0,86400]")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.\-/]{0,127}", args.asset_namespace):
            raise ValueError("Invalid asset namespace")
        for output in (args.output_json, args.output_normal):
            if output is not None and output.exists():
                raise ValueError("Output already exists; choose a new file")
        if args.output_json is not None and args.output_normal is not None and args.output_json.resolve() == args.output_normal.resolve():
            raise ValueError("JSON and normal output need separate new paths")
        args.ports = args.ports or PORT_PROFILES.get(args.profile, DEFAULT_PORTS)
        policy = ScopePolicy.load(args.scope_file)
        port_list = parse_ports(args.ports)

        if not port_list:
            raise ValueError(
                "유효한 스캔 포트가 하나도 없습니다."
            )

        resolved_targets = resolve_target_specs(
            args.target,
            max_targets=policy.max_targets,
        )
        policy.authorize(
            resolved_targets,
            worker_count=args.max_workers,
            port_count=len(port_list),
        )
    except (ValueError, ScopeValidationError) as exc:
        parser.error(str(exc))

    print_scan_plan(
        policy,
        resolved_targets,
        len(port_list),
        args.max_workers,
    )

    if args.dry_run:
        print("[DRY-RUN] No scan or database write was performed.")
        return 0

    scan_type, enable_udp, udp_only = determine_scan_mode(
        args.sT,
        args.sU,
    )
    results = run_scan(
        targets=[
            target.ip for target in resolved_targets
        ],
        ports=port_list,
        timeout=args.timeout,
        threaded=True,
        max_workers=args.max_workers,
        enable_udp=enable_udp,
        udp_only=udp_only,
        scan_type=scan_type,
        detect_versions=args.sV,
        server_names={target.ip: target.input_target for target in resolved_targets
                      if target.resolution_type == "HOSTNAME"},
        max_duration=args.max_duration,
    )
    attach_target_metadata(results, resolved_targets)
    results["requested_targets"] = list(args.target)
    results["asset_namespace"] = args.asset_namespace
    scope_snapshot = policy.to_snapshot()
    results["scope"] = scope_snapshot
    results["config"] = {
        "ports": args.ports,
        "timeout": args.timeout,
        "max_workers": args.max_workers,
        "service_version_requested": args.sV,
        "scope": scope_snapshot,
        "profile": args.profile,
        "asset_namespace": args.asset_namespace,
        "max_duration": args.max_duration,
    }

    # A durable, sanitized observation exists even if imports/DB authentication fail.
    from scanner.artifacts import write_scan_artifact
    raw_path = args.output_json or PROJECT_ROOT / "reports" / "raw" / (results["scan_id"] + ".json")
    try:
        write_scan_artifact(results, raw_path)
    except (OSError, ValueError) as error:
        print("[!] Raw result preservation failed (" + type(error).__name__ + "); database was not accessed.")
        return 1
    print(f"[+] Sanitized raw observations: {raw_path}")

    output_lines = render_results(
        results,
        show_versions=args.sV,
    )

    for line in output_lines:
        print(line)

    if args.output_normal:
        args.output_normal.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        with args.output_normal.open("x", encoding="utf-8") as output:
            output.write("\n".join(output_lines) + "\n")
        print(f"[+] Saved output to {args.output_normal}")

    if args.no_db:
        return 0
    try:
        from db.save_scan_results import save_scan_results
        scan_db_id = save_scan_results(results)
    except Exception as error:
        print("[!] DB save failed (" + type(error).__name__ + "); preserved JSON can be imported later.")
        return 1
    print(f"[+] DB save completed (scan_id={scan_db_id})")
    print("Storage history: " + results.get("storage", {}).get("history_capability", "LEGACY_CURRENT_STATE_ONLY"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
