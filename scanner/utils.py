# scanner/utils.py
import ipaddress
from typing import List, Iterable
import socket
import errno


def is_valid_ip(ip: str) -> bool:
    """IPv4/IPv6 형식 검증."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_hostname(ip: str) -> str | None:
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return host              # 문자열만 반환
    except socket.herror:
        return None              # 역방향 DNS 없으면 None

def parse_ports(ports: str | Iterable[int]) -> List[int]:
    """
    포트 범위 파싱.
    - "80" / "22,80,443" / "20-25,80,443" 형식 지원
    - 이미 리스트[int]를 넣으면 그대로 정렬해서 반환
    """
    if not isinstance(ports, str):
        result = set()
        for index, port in enumerate(ports):
            if index >= 65535:
                raise ValueError("Port input exceeds 65535 entries")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("Ports must be integers in 1..65535")
            result.add(port)
        return sorted(result)
    if len(ports) > 400000:
        raise ValueError("Port expression too long")

    result: set[int] = set()
    for token in ports.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            start_str, end_str = token.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                raise ValueError("Port range bounds must be in 1..65535")
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 0 < p <= 65535:
                    result.add(p)
        else:
            p = int(token)
            if not 1 <= p <= 65535:
                raise ValueError("Ports must be in 1..65535")
            result.add(p)

    return sorted(result)


def format_port_range(ports: str | Iterable[int]) -> str:
    """검사 포트 집합을 손실 없이 짧은 범위 문자열로 표현한다."""
    port_list = parse_ports(ports)
    if not port_list:
        return ""

    ranges: list[str] = []
    start = end = port_list[0]

    for port in port_list[1:]:
        if port == end + 1:
            end = port
            continue

        ranges.append(str(start) if start == end else f"{start}-{end}")
        start = end = port

    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(ranges)


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> socket.socket | None:
    """
    단순 TCP connect 함수.
    - 성공: 연결된 socket 반환
    - 실패: None
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return sock
    except OSError as error:
        if socket_error(error)[0] == "closed":
            return None
        raise


def socket_error(error: OSError, *, udp: bool = False) -> tuple[str, str, str | None]:
    """Classify transport evidence without guessing filtering from missing replies."""
    code = getattr(error, "winerror", None) or error.errno
    if isinstance(error, TimeoutError) or code in {errno.ETIMEDOUT, 10060}:
        return ("open|filtered" if udp else "unknown", "no_response" if udp else "timeout", None if udp else "TIMEOUT")
    if isinstance(error, ConnectionRefusedError) or code in {errno.ECONNREFUSED, 10061} or udp and code == 10054:
        return "closed", "icmp_port_unreachable" if udp else "connection_refused", None
    if isinstance(error, PermissionError) or code in {errno.EACCES, errno.EPERM, 10013}:
        return "error", "permission_denied", "PERMISSION_DENIED"
    if code in {errno.ENETUNREACH, 10051}:
        return "error", "network_unreachable", "NETWORK_UNREACHABLE"
    if code in {errno.EHOSTUNREACH, 10065}:
        return "error", "host_unreachable", "HOST_UNREACHABLE"
    if code in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, 10047}:
        return "error", "address_family_unsupported", "ADDRESS_FAMILY_UNSUPPORTED"
    return "error", "transport_error", "TRANSPORT_ERROR"


def udp_connect(host: str, port: int, timeout: float = 1.0) -> str:
    """Compatibility state-only wrapper; new observations preserve the reason."""
    return udp_probe(host, port, timeout)[0]


def udp_probe(host: str, port: int, timeout: float = 1.0) -> tuple[str, str, str | None]:
    sock = None
    try:
        address = ipaddress.ip_address(host)
        sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Connected UDP pins the peer and admits ICMP error delivery on supported OSes.
        sock.connect((str(address), port))
        sock.send(b"")
        sock.recv(1024)
        return "open", "udp_response", None
    except OSError as error:
        return socket_error(error, udp=True)
    except ValueError:
        return "error", "invalid_address", "INVALID_ADDRESS"
    finally:
        if sock is not None:
            sock.close()
