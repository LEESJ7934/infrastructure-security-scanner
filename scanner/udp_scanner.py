# scanner/udp_scanner.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Dict, Iterable
import time

from .utils import udp_probe, parse_ports
from .execution import bounded_scan, validate_execution
from .service_fingerprints import guess_service


@dataclass
class UDPPortScanResult:
    port: int
    protocol: str   # "udp"
    state: str      # "open" / "closed" / "open|filtered"
    banner: str | None = None   # UDP는 일반적으로 배너 없음
    service: str | None = None
    reason: str | None = None
    error_code: str | None = None
    elapsed_seconds: float | None = None
    service_source: str = "guessed"

    def to_dict(self) -> Dict:
        return asdict(self)


def scan_single_udp_port(host: str, port: int, timeout: float = 1.0) -> UDPPortScanResult:
    """
    단일 UDP 포트 스캔.
    - 응답 수신       → open
    - ICMP unreachable → closed
    - 응답 없음       → open|filtered
    """
    validate_execution(timeout)
    started = time.monotonic()
    state, reason, error_code = udp_probe(host, port, timeout)
    service = guess_service(port, "udp")

    return UDPPortScanResult(
        port=port,
        protocol="udp",
        state=state,
        banner=None,
        service=service,
        reason=reason, error_code=error_code, elapsed_seconds=time.monotonic()-started,
    )


def sequential_udp_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0,
                        *, stop_event=None, deadline=None) -> List[Dict]:
    """
    단일 IP에 대해 순차 UDP 스캔.
    - 출력: [{port, protocol, state, banner, service}, ...]
    """
    return threaded_udp_scan(host, ports, timeout, 1, stop_event=stop_event, deadline=deadline)


def threaded_udp_scan(
    host: str,
    ports: Iterable[int] | str,
    timeout: float = 1.0,
    max_workers: int = 100,
    *, stop_event=None, deadline=None,
) -> List[Dict]:
    """
    단일 IP에 대해 멀티스레드 UDP 스캔.
    - ThreadPoolExecutor 사용
    - 결과는 포트 번호 기준 정렬
    """
    validate_execution(timeout, max_workers)
    return bounded_scan(parse_ports(ports), lambda port: scan_single_udp_port(host, port, timeout),
                        max_workers=max_workers, protocol="udp", stop_event=stop_event, deadline=deadline)
