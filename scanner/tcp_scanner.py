from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable
import time

from .banner_grabber import collect_banner, sanitize_banner
from .execution import bounded_scan, validate_execution
from .fingerprints import identify_service
from .service_fingerprints import guess_service
from .utils import parse_ports, tcp_connect, socket_error


@dataclass
class PortScanResult:
    port: int
    protocol: str
    state: str
    banner: str | None = None
    service: str | None = None
    version: str | None = None
    product: str | None = None
    fingerprint: dict | None = None
    reason: str | None = None
    error_code: str | None = None
    elapsed_seconds: float | None = None
    service_source: str = "guessed"
    identification_status: str = "NOT_REQUESTED"

    def to_dict(self) -> dict:
        return asdict(self)


def scan_single_port(host: str, port: int, timeout: float = 1.0,
                     detect_versions: bool = False,
                     server_name: str | None = None) -> PortScanResult:
    validate_execution(timeout)
    started = time.monotonic()
    hint = guess_service(port)
    try:
        sock = tcp_connect(host, port, timeout=timeout)
    except OSError as error:
        state, reason, code = socket_error(error)
        return PortScanResult(port, "tcp", state, service=hint, reason=reason,
                              error_code=code, elapsed_seconds=time.monotonic()-started)
    if sock is None:
        return PortScanResult(port, "tcp", "closed", service=hint, reason="connection_refused",
                              elapsed_seconds=time.monotonic()-started)
    sock.close()
    fingerprint = identify_service(None, hint)
    banner = None
    identification_status = "NOT_REQUESTED"
    if detect_versions:
        observation = collect_banner(host, port, hint, timeout, server_name)
        safe_data = sanitize_banner(observation.data)
        fingerprint = identify_service(safe_data, hint)
        fingerprint.update(probe_error=observation.error, tls=observation.tls)
        identification_status = ("NO_RESPONSE" if observation.error == "no_response" else "ERROR") if observation.error else "IDENTIFIED" if fingerprint["product"] else "UNSUPPORTED_OR_HIDDEN"
        if safe_data:
            banner = safe_data.decode("latin1")
    else:
        fingerprint["probe_error"] = "not_requested"
    return PortScanResult(port, "tcp", "open", banner=banner,
                          service=fingerprint["service"], version=fingerprint["version"],
                          product=fingerprint["product"], fingerprint=fingerprint,
                          reason="tcp_connected", elapsed_seconds=time.monotonic()-started,
                          service_source="guessed" if fingerprint["source"] == "port_hint" else "observed",
                          identification_status=identification_status)


def sequential_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0,
                    detect_versions: bool = False, server_name: str | None = None,
                    *, stop_event=None, deadline=None) -> list[dict]:
    return threaded_scan(host, ports, timeout, 1, detect_versions, server_name,
                         stop_event=stop_event, deadline=deadline)


def threaded_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0,
                  max_workers: int = 100, detect_versions: bool = False,
                  server_name: str | None = None, *, stop_event=None, deadline=None) -> list[dict]:
    validate_execution(timeout, max_workers)
    return bounded_scan(parse_ports(ports),
        lambda port: scan_single_port(host, port, timeout, detect_versions, server_name),
        max_workers=max_workers, protocol="tcp", stop_event=stop_event, deadline=deadline)
