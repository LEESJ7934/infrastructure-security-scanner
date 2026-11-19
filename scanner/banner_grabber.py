"""Bounded protocol identification on an already approved, numeric IP address."""
from __future__ import annotations

import ipaddress
import socket
import ssl
import time
import re
from dataclasses import dataclass

MAX_BANNER_BYTES = 16384


def sanitize_banner(data: bytes | str | None):
    """Preserve identity evidence, discard HTTP bodies and nonessential headers.

    An allowlist also excludes unknown authentication/token headers, redirects
    with query credentials, cookies and obsolete folded continuations. Binary
    service greetings are not treated as HTTP.
    """
    if not data:
        return data
    was_text = isinstance(data, str)
    raw = data.encode("latin1", "replace") if was_text else data
    if not raw.startswith(b"HTTP/"):
        return data
    header = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0]
    lines = re.split(rb"\r?\n", header)
    kept = [lines[0]]
    allowed = {b"server", b"x-elastic-product", b"kbn-version", b"content-type", b"content-length"}
    markers = {b"kbn-name", b"kbn-license-sig"}
    for line in lines[1:]:
        if line.startswith((b" ", b"\t")) or b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.strip().lower()
        if key in allowed:
            kept.append(name + b":" + value)
        elif key in markers:
            kept.append(name + b": [PRESENT]")
    # Do not convert a truncated response into complete-header evidence.
    suffix = b"\r\n\r\n" if re.search(rb"\r?\n\r?\n", raw) else b""
    safe = b"\r\n".join(kept) + suffix
    return safe.decode("latin1") if was_text else safe


@dataclass
class BannerObservation:
    data: bytes = b""
    error: str | None = None
    tls: str = "not_used"


def _complete(data: bytes) -> bool:
    if data.startswith(b"HTTP/"):
        return b"\r\n\r\n" in data or b"\n\n" in data
    if len(data) >= 5 and data[3:5] == b"\x00\x0a":
        return b"\x00" in data[5:]
    return b"\n" in data


def _read(sock, deadline: float, initial: bytes = b"") -> bytes:
    data = initial
    while len(data) < MAX_BANNER_BYTES and not _complete(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(4096, MAX_BANNER_BYTES - len(data)))
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def _http_request(host: str, port: int, server_name: str | None) -> bytes:
    authority = server_name or host
    # Host/SNI never changes the pinned destination IP. Reject header injection.
    if any(char in authority for char in "\r\n\x00 /\\"):
        raise ValueError("Invalid HTTP host name")
    authority = authority.encode("idna").decode("ascii")
    if ":" in authority:
        authority = f"[{authority}]"
    return (f"HEAD / HTTP/1.1\r\nHost: {authority}:{port}\r\n"
            "User-Agent: InfrastructureSecurityScanner/1.0\r\nConnection: close\r\n\r\n").encode("ascii")


def collect_banner(host: str, port: int, service: str, timeout: float = 1.0,
                   server_name: str | None = None) -> BannerObservation:
    # Resolution and scope validation belong to scripts.run_scan. No second DNS lookup.
    ipaddress.ip_address(host)
    deadline = time.monotonic() + timeout
    tls = "not_used"
    try:
        with socket.create_connection((host, port), timeout=timeout) as plain:
            if service == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                # Identification only: no credentials, redirects or trust claims.
                # Record that this certificate was not authenticated in the result.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                tls = "certificate_not_validated"
                plain.settimeout(max(0.001, deadline - time.monotonic()))
                with context.wrap_socket(plain, server_hostname=server_name or host) as sock:
                    sock.sendall(_http_request(host, port, server_name))
                    data = _read(sock, deadline)
            elif service == "http":
                plain.sendall(_http_request(host, port, server_name))
                data = _read(plain, deadline)
            else:
                # First listen for SSH/FTP/MySQL. Unknown silent ports get one HEAD.
                passive_deadline = deadline
                if service == "unknown":
                    passive_deadline = min(deadline, time.monotonic() + timeout / 3)
                data = _read(plain, passive_deadline)
                if not data and service == "unknown" and time.monotonic() < deadline:
                    plain.settimeout(max(0.001, deadline - time.monotonic()))
                    plain.sendall(_http_request(host, port, server_name))
                    data = _read(plain, deadline)
        return BannerObservation(data=sanitize_banner(data), error=None if data else "no_response", tls=tls)
    except (OSError, ValueError) as exc:
        return BannerObservation(error=type(exc).__name__, tls=tls)


def grab_banner(host: str, port: int, service: str, timeout: float = 1.0) -> str | None:
    """Compatibility wrapper. New callers use collect_banner for probe metadata."""
    data = collect_banner(host, port, service, timeout).data
    return data.decode("utf-8", "replace") if data else None
