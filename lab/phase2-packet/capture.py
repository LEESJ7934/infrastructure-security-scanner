"""Header-only, non-promiscuous ICMP capture streamed via docker exec -i.

No payload or MAC address is stored; only the two explicitly selected LAB IPs.
"""
import json
import select
import socket
import struct
import sys
import time


def decode(frame, interface, packet_type, source, destination):
    if len(frame)<42 or frame[12:14]!=b'\x08\x00':return None
    ip=frame[14:]
    ihl=(ip[0]&15)*4
    if ip[0]>>4!=4 or ihl<20 or len(ip)<ihl+8 or ip[9]!=1 or struct.unpack('!H',ip[6:8])[0]&8191:return None
    src,dst=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20])
    if (src,dst) not in {(source,destination),(destination,source)} or ip[ihl] not in (0,8):return None
    ident,sequence=struct.unpack('!HH',ip[ihl+4:ihl+8])
    return {"interface":interface,"direction":"out" if packet_type==4 else "in","source":src,"destination":dst,
            "icmp_type":ip[ihl],"id":ident,"sequence":sequence,"ttl":ip[8]}


def main():
    source,destination=sys.argv[1:3]
    for value in (source,destination):socket.inet_aton(value)
    sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
    print(json.dumps({"ready":True}),flush=True)
    if sys.stdin.readline().strip()!='GO':return
    events=[];deadline=time.monotonic()+8
    try:
        while time.monotonic()<deadline:
            if not select.select([sock],[],[],min(.2,max(0,deadline-time.monotonic())))[0]:continue
            frame,address=sock.recvfrom(2048)
            event=decode(frame,address[0],address[2],source,destination)
            if event is not None and len(events)<128:events.append(event)
    finally:sock.close()
    print(json.dumps({"events":events,"payload_saved":False}),flush=True)


if __name__=='__main__':main()
