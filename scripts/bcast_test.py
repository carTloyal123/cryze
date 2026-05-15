#!/usr/bin/env python3
"""Test broadcast discovery protocol independently of the SDK"""
import socket, select, time, struct, random

def make_broadcast_packet(dev_type=3, local_port=8900):
    """Build a 28-byte broadcast discovery packet matching the SDK format"""
    pkt = bytearray(28)
    pkt[0] = 0x70   # protocol marker
    pkt[1] = 0x02   # version
    pkt[2] = 0x00   # length high
    pkt[3] = 0x1c   # length low (28)
    rid = random.getrandbits(30)
    struct.pack_into(">I", pkt, 4, rid)
    flags = (dev_type & 7) | 8
    struct.pack_into(">H", pkt, 8, flags)
    struct.pack_into(">H", pkt, 10, local_port)
    return bytes(pkt)

# Create recv socket on 8900
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
recv_sock.setblocking(False)
recv_sock.bind(("0.0.0.0", 8900))
print("Recv socket bound to 0.0.0.0:8900")

# Create send socket with SO_BROADCAST
send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

pkt = make_broadcast_packet()
print(f"Sending {len(pkt)}-byte broadcast: {pkt.hex()}")

start = time.time()
for i in range(30):
    if i % 2 == 0:
        send_sock.sendto(pkt, ("192.168.1.255", 8899))
    else:
        send_sock.sendto(pkt, ("255.255.255.255", 8899))
    
    for _ in range(3):
        ready = select.select([recv_sock], [], [], 0.4)
        if ready[0]:
            data, addr = recv_sock.recvfrom(1024)
            elapsed = time.time() - start
            print(f"[{elapsed:.1f}s] RESPONSE: {len(data)} bytes from {addr}")
            print(f"  hex: {data[:64].hex()}")
            if len(data) >= 4:
                proto = data[0]
                ver = data[1]
                plen = struct.unpack(">H", data[2:4])[0]
                print(f"  proto=0x{proto:02x} ver={ver} len={plen}")
            recv_sock.close()
            send_sock.close()
            exit(0)

elapsed = time.time() - start
print(f"No response after {elapsed:.0f}s")
recv_sock.close()
send_sock.close()
