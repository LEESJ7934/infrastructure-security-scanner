# scanner/scan_runner.py
from __future__ import annotations
import uuid
import time
import threading
import math
from typing import List, Dict, Iterable
from datetime import datetime, timedelta, timezone
from .tcp_scanner import sequential_scan, threaded_scan          # TCP scanner
from .udp_scanner import sequential_udp_scan, threaded_udp_scan  # UDP scanner
from .utils import format_port_range, is_valid_ip, parse_ports
from .execution import validate_execution

KST = timezone(timedelta(hours=9))
DEFAULT_PORTS = "1-1024"
PORT_PROFILES = {"standard": DEFAULT_PORTS, "lab": "21-23,80,443,3306,4280-4282,5601,8000,8080-8081,8443,9200"}

def generate_scan_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    u = uuid.uuid4().hex[:8]
    return f"scan-{ts}-{u}"


def run_scan(
    targets: Iterable[str],
    ports: Iterable[int] | str = DEFAULT_PORTS,
    timeout: float = 1.0,
    threaded: bool = True,
    max_workers: int = 100,
    enable_udp: bool = False,   # TCP + UDP
    udp_only: bool = False, 
    scan_type: str = "tcp",
    detect_versions: bool = False,
    server_names: dict[str, str] | None = None,
    *, stop_event=None, max_duration: float | None = None,
) -> Dict:
    validate_execution(timeout, max_workers)
    if max_duration is not None and (isinstance(max_duration, bool) or not isinstance(max_duration, (int, float)) or not math.isfinite(max_duration) or not 0 < max_duration <= 86400):
        raise ValueError("max_duration must be finite and in (0,86400]")
    started_clock = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    stop_event = stop_event or threading.Event()
    deadline = started_clock + max_duration if max_duration is not None else None
    
    scan_id = generate_scan_id()

    # 사용자 포트 범위
    port_list = parse_ports(ports)

    tcp_port_list = port_list
    udp_port_list = port_list

    targets_results: List[Dict] = []

    for ip in targets:
        if not is_valid_ip(ip):
            targets_results.append({
                "ip": ip,
                "error": "invalid_ip",
                "results": [],
            })
            continue

        # =====================================================
        # TCP 스캔
        # =====================================================
        if udp_only:
            tcp_results = []
        else:
            if threaded:
                tcp_results = threaded_scan(
                    ip, tcp_port_list, timeout=timeout, max_workers=max_workers,
                    detect_versions=detect_versions,
                    server_name=(server_names or {}).get(ip), stop_event=stop_event, deadline=deadline,
                )
            else:
                tcp_results = sequential_scan(
                    ip, tcp_port_list, timeout=timeout,
                    detect_versions=detect_versions,
                    server_name=(server_names or {}).get(ip), stop_event=stop_event, deadline=deadline,
                )

        # =====================================================
        # UDP 스캔
        # =====================================================
        if enable_udp or udp_only:
            if threaded:
                udp_results = threaded_udp_scan(
                    ip, udp_port_list, timeout=timeout, max_workers=max_workers,
                    stop_event=stop_event, deadline=deadline,
                )
            else:
                udp_results = sequential_udp_scan(
                    ip, udp_port_list, timeout=timeout, stop_event=stop_event, deadline=deadline,
                )
        else:
            udp_results = []

        # TCP + UDP 결과 병합
        merged = tcp_results + udp_results

        targets_results.append({
            "ip": ip,
            "results": merged,
            "coverage": {
                "requested_ports": port_list,
                "attempted_ports": {protocol: [r["port"] for r in merged if r["protocol"] == protocol and r["state"] != "not_tested"] for protocol in ("tcp", "udp")},
                "not_tested_ports": {protocol: [r["port"] for r in merged if r["protocol"] == protocol and r["state"] == "not_tested"] for protocol in ("tcp", "udp")},
                "complete": not any(r["state"] == "not_tested" for r in merged),
                "outside_requested_range": "NOT_TESTED",
            },
        })

    finished_at = datetime.now(timezone.utc).isoformat()
    observations = [r for target in targets_results for r in target["results"]]
    problems = any(target.get("error") for target in targets_results) or any(r["state"] in {"error", "unknown", "not_tested"} for r in observations)
    status = "PARTIAL" if problems else "COMPLETED"
    if problems and not any(r["state"] not in {"error", "unknown", "not_tested"} for r in observations):
        status = "FAILED"
    return {
        "schema_version": 2,
        "scan_id": scan_id,
        "scan_type": scan_type, 
        "started_at": started_at,
        "finished_at": finished_at,
        "targets": targets_results,
        "port_range": format_port_range(port_list),
        "requested_port_range": format_port_range(port_list),
        "time_basis": "UTC",
        "duration_seconds": time.monotonic()-started_clock,
        "status": status,
        "interrupted": stop_event.is_set(),
        "probe_method": {"tcp": "connect", "udp": "connected_empty_datagram"},
        "identification_summary": {state: sum(r.get("identification_status") == state for r in observations)
                                   for state in ("IDENTIFIED", "UNSUPPORTED_OR_HIDDEN", "NO_RESPONSE", "ERROR", "NOT_REQUESTED")},
    }
 
