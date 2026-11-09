"""Write two synthetic Ethernet/IPv4 UDP packets without using sockets."""

from pathlib import Path
from struct import pack, unpack


def udp_frame(payload: bytes, packet_id: int) -> bytes:
    udp = pack("!HHHH", 49153, 39003, 8 + len(payload), 0)
    ip_header = pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(payload), packet_id, 0, 64, 17, 0,
        bytes((192, 0, 2, 10)), bytes((198, 51, 100, 20)),
    )
    total = sum(unpack("!10H", ip_header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    ip_header = ip_header[:10] + pack("!H", (~total) & 0xFFFF) + ip_header[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip_header + udp + payload


def main() -> None:
    output = Path(__file__).resolve().parents[1] / "artifacts" / "day3.pcap"
    output.parent.mkdir(exist_ok=True)
    with output.open("wb") as file:
        file.write(pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for packet_id, payload in enumerate((b"DAY3-IDS-CONTROL", b"DAY3-IDS-MARKER"), start=1):
            frame = udp_frame(payload, packet_id)
            file.write(pack("<IIII", 1700000000 + packet_id, 0, len(frame), len(frame)))
            file.write(frame)
    print(output)


if __name__ == "__main__":
    main()
