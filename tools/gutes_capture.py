#!/usr/bin/env python3
"""GUTES Session Capture — records full relay-proxied sessions to pcap + JSON.

Wraps the GUTES relay in capture mode: every frame that passes through
(client↔relay and relay↔upstream) is written to a pcap file AND a
parsed JSON log.  This provides the raw bytes for Wireshark analysis
and a human-readable protocol trace for reverse engineering.

Usage:
  # Capture a full bridge session through the relay:
  python3 scripts/gutes_capture.py --output logs/capture

  # With custom upstream:
  python3 scripts/gutes_capture.py --upstream 3.19.80.22:28800 --output logs/cap2

  # Resolve Mars DNS automatically:
  python3 scripts/gutes_capture.py --resolve --output logs/cap3

Outputs:
  <output>.pcap       — Raw packet capture (open in Wireshark)
  <output>.json       — Parsed frame-by-frame protocol trace
  <output>.relay.log  — Relay operational log

The capture runs until Ctrl+C. The bridge should be started separately
with P2P_URL=|127.0.0.1 (or pointed at this machine's IP).
"""

import argparse
import asyncio
import hashlib
import json
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from rc5 import RC5, GWELL_KEY, derive_per_frame_key, id_decrypt, id_encrypt
from gutes_frame import parse_frame, GutesFrame, HEADER_SIZE, FRAME_TYPES


# ── Pcap writer ───────────────────────────────────────────────────

class PcapWriter:
    """Write packets to a pcap file (linktype=101 = Raw IPv4)."""

    # We use linktype 147 (USER0) since we're writing raw GUTES frames,
    # not IP packets.  Wireshark can display them as raw data.
    # Alternatively, we wrap each GUTES frame in a fake UDP/IP packet
    # so Wireshark can show port info.
    LINKTYPE_RAW_IPV4 = 228   # Raw IPv4
    LINKTYPE_USER0 = 147

    def __init__(self, path: str, wrap_udp: bool = True):
        self.path = path
        self.wrap_udp = wrap_udp
        self.fp = open(path, 'wb')
        self.pkt_count = 0

        # Global pcap header (24 bytes)
        # magic=0xa1b2c3d4, version 2.4, thiszone=0, sigfigs=0,
        # snaplen=65535, linktype
        linktype = self.LINKTYPE_RAW_IPV4 if wrap_udp else self.LINKTYPE_USER0
        self.fp.write(struct.pack('<IHHiIII',
            0xa1b2c3d4,  # magic
            2, 4,         # version
            0, 0,         # thiszone, sigfigs
            65535,        # snaplen
            linktype,
        ))
        self.fp.flush()

    def write_raw(self, data: bytes, ts: float = None):
        """Write a raw GUTES frame (no IP/UDP wrapping)."""
        if self.wrap_udp:
            raise ValueError("Use write_udp() for wrapped mode")
        if ts is None:
            ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        self.fp.write(struct.pack('<IIII',
            ts_sec, ts_usec, len(data), len(data)))
        self.fp.write(data)
        self.fp.flush()
        self.pkt_count += 1

    def write_udp(self, payload: bytes, src_ip: str, src_port: int,
                  dst_ip: str, dst_port: int, ts: float = None):
        """Write a GUTES frame wrapped in a fake UDP/IPv4 packet."""
        if ts is None:
            ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        # Build UDP header (8 bytes)
        udp_len = 8 + len(payload)
        udp_hdr = struct.pack('>HHHH', src_port, dst_port, udp_len, 0)

        # Build IPv4 header (20 bytes, no options)
        ip_total_len = 20 + udp_len
        ip_hdr = bytearray(20)
        ip_hdr[0] = 0x45  # version=4, ihl=5
        struct.pack_into('>H', ip_hdr, 2, ip_total_len)
        ip_hdr[8] = 64     # TTL
        ip_hdr[9] = 17     # protocol = UDP
        # Source and destination IPs
        ip_hdr[12:16] = socket.inet_aton(src_ip)
        ip_hdr[16:20] = socket.inet_aton(dst_ip)
        # Checksum (simple, optional for capture)
        cksum = self._ip_checksum(bytes(ip_hdr))
        struct.pack_into('>H', ip_hdr, 10, cksum)

        pkt = bytes(ip_hdr) + udp_hdr + payload

        # Pcap packet header
        self.fp.write(struct.pack('<IIII',
            ts_sec, ts_usec, len(pkt), len(pkt)))
        self.fp.write(pkt)
        self.fp.flush()
        self.pkt_count += 1

    @staticmethod
    def _ip_checksum(hdr: bytes) -> int:
        """Compute IPv4 header checksum."""
        if len(hdr) % 2:
            hdr = hdr + b'\x00'
        s = 0
        for i in range(0, len(hdr), 2):
            s += (hdr[i] << 8) + hdr[i+1]
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None


# ── JSON trace writer ─────────────────────────────────────────────

@dataclass
class CapturedFrame:
    """A single captured GUTES frame with metadata."""
    timestamp: float = 0.0
    elapsed_ms: float = 0.0
    direction: str = ""      # "C→R" (client→relay), "R→C", "R→U" (relay→upstream), "U→R"
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    frame_type: int = 0
    type_name: str = ""
    frm_len: int = 0
    term_id: int = 0
    opt_encrypt: int = 0
    is_ack: bool = False
    is_response: bool = False
    opt_flags_hex: str = ""
    payload_len: int = 0
    raw_hex: str = ""        # full frame hex (capped at 512 bytes)
    payload_hex: str = ""    # payload hex (capped at 256 bytes)
    decrypted_hex: str = ""  # decrypted payload (if available)
    notes: str = ""


class JsonTraceWriter:
    """Writes a JSON-lines file of parsed frames."""

    def __init__(self, path: str):
        self.path = path
        self.fp = open(path, 'w')
        self.t0 = time.time()
        self.frame_count = 0
        # Write opening metadata
        meta = {
            '_type': 'session_start',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'unix_time': self.t0,
        }
        self.fp.write(json.dumps(meta) + '\n')
        self.fp.flush()

    def write_frame(self, cf: CapturedFrame):
        cf.elapsed_ms = round((cf.timestamp - self.t0) * 1000, 2)
        self.fp.write(json.dumps(asdict(cf), default=str) + '\n')
        self.fp.flush()
        self.frame_count += 1

    def close(self):
        if self.fp:
            meta = {
                '_type': 'session_end',
                'total_frames': self.frame_count,
                'duration_s': round(time.time() - self.t0, 2),
            }
            self.fp.write(json.dumps(meta) + '\n')
            self.fp.close()
            self.fp = None


# ── Capture relay ─────────────────────────────────────────────────

class CaptureRelay:
    """GUTES relay with full session capture to pcap + JSON.

    Inherits the protocol logic from GutesRelay but adds packet-level
    recording of every frame in both directions.
    """

    def __init__(self, output_prefix: str, listen_ports: list[int] = None,
                 list_port: int = 51701, upstream: str = "3.13.212.24:28800",
                 local_ip: str = ""):
        self.listen_ports = listen_ports or [28800, 8443, 8000]
        self.list_port = list_port
        self.upstream_host = upstream.split(':')[0]
        self.upstream_port = int(upstream.split(':')[1])
        self.local_ip = local_ip or self._detect_local_ip()
        self.t0 = time.time()

        # Server identity (same as GutesRelay)
        ip_hash = hashlib.md5(self.local_ip.encode()).digest()
        self.server_term_id: int = struct.unpack_from('<q', ip_hash)[0]
        self.server_sqnum: int = int(time.time()) & 0xFFFFFFFF

        # Capture outputs
        self.pcap = PcapWriter(f"{output_prefix}.pcap", wrap_udp=True)
        self.trace = JsonTraceWriter(f"{output_prefix}.json")
        self.log_fp = open(f"{output_prefix}.relay.log", 'w')

        # Socket references
        self.relay_socks: dict[int, socket.socket] = {}
        self.list_sock: Optional[socket.socket] = None
        self.upstream_socks: dict[int, socket.socket] = {}
        self.upstream_to_client: dict[int, tuple] = {}

        # Client tracking
        self.clients: dict[int, dict] = {}  # term_id -> info

        # Import GutesRelay for frame builders
        from gutes_relay import GutesRelay
        self._relay = GutesRelay(
            listen_ports=self.listen_ports,
            list_port=self.list_port,
            mode="proxy",
            upstream=upstream,
            local_ip=self.local_ip,
        )

    def _detect_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.168.1.1", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def log(self, msg: str):
        elapsed = time.time() - self.t0
        line = f"[{elapsed:8.3f}] {msg}"
        print(line, flush=True)
        if self.log_fp:
            self.log_fp.write(line + "\n")
            self.log_fp.flush()

    def _record(self, data: bytes, src_ip: str, src_port: int,
                dst_ip: str, dst_port: int, direction: str,
                notes: str = ""):
        """Record a frame to pcap + JSON trace."""
        now = time.time()

        # Write to pcap
        self.pcap.write_udp(data, src_ip, src_port, dst_ip, dst_port, ts=now)

        # Parse and write to JSON trace
        cf = CapturedFrame(
            timestamp=now,
            direction=direction,
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            frm_len=len(data),
            notes=notes,
        )

        if len(data) >= HEADER_SIZE:
            frame = parse_frame(data)
            if frame:
                cf.frame_type = frame.frame_type
                cf.type_name = frame.type_name
                cf.frm_len = frame.frm_len
                cf.term_id = frame.term_id
                cf.opt_encrypt = frame.opt_encrypt
                cf.is_ack = frame.is_ack
                cf.is_response = frame.is_response
                cf.opt_flags_hex = f"0x{frame.opt_flags:08x}"
                cf.payload_len = len(frame.payload)
                cf.raw_hex = data[:512].hex()
                if frame.payload:
                    cf.payload_hex = frame.payload[:256].hex()
                if frame.payload_decrypted:
                    cf.decrypted_hex = frame.payload_decrypted[:256].hex()
        else:
            cf.raw_hex = data.hex()

        self.trace.write_frame(cf)

    def _decode_term_id(self, data: bytes) -> int:
        if len(data) < HEADER_SIZE:
            return 0
        encrypted_id = data[4:12]
        sqnum_bytes = data[0x0C:0x10]
        chkval_bytes = data[0x10:0x14]
        try:
            id_bytes = id_decrypt(encrypted_id, chkval_bytes, sqnum_bytes)
            return struct.unpack_from('<q', id_bytes)[0]
        except Exception:
            return 0

    def _get_upstream_sock(self, term_id: int) -> socket.socket:
        if term_id not in self.upstream_socks:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.05)
            self.upstream_socks[term_id] = sock
        return self.upstream_socks[term_id]

    def _handle_packet(self, data: bytes, addr: tuple, our_port: int) -> Optional[bytes]:
        """Process incoming packet, returning local response or None (forward)."""
        if len(data) < 4:
            return None

        ftype = data[1]
        term_id = self._decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")

        # Record inbound frame
        self._record(data, addr[0], addr[1], self.local_ip, our_port,
                     "C\u2192R", f"client {type_name}")

        # Track client
        if term_id != 0:
            if term_id not in self.clients:
                self.clients[term_id] = {
                    'addr': addr, 'port': our_port,
                    'first_seen': time.time(), 'frames': 0,
                }
                self.log(f"NEW CLIENT: term_id={term_id} from {addr[0]}:{addr[1]}")
            self.clients[term_id]['addr'] = addr
            self.clients[term_id]['port'] = our_port
            self.clients[term_id]['frames'] = self.clients[term_id].get('frames', 0) + 1

        # DETECT: respond locally
        if ftype == 0x01:  # DETECT_REQ
            self.log(f"\u2190 DETECT_REQ from {addr[0]}:{addr[1]}:{our_port} "
                     f"client_tid={term_id}")
            resp = self._relay.build_detect_resp(data)
            self._record(resp, self.local_ip, our_port, addr[0], addr[1],
                         "R\u2192C", "local DETECT_RESP")
            self.log(f"\u2192 DETECT_RESP to {addr[0]}:{addr[1]} "
                     f"server_tid={self._relay.server_term_id}")
            return resp

        # LIST_REQ: respond locally
        if ftype == 0x15:  # LIST_REQ
            self.log(f"\u2190 LIST_REQ from {addr[0]}:{addr[1]} term_id={term_id}")
            reply_ip = "127.0.0.1" if addr[0].startswith("127.") else self.local_ip
            resp = self._relay.build_list_resp(data, reply_ip)
            self._record(resp, self.local_ip, our_port, addr[0], addr[1],
                         "R\u2192C", f"local LIST_RESP (servers: {reply_ip})")
            self.log(f"\u2192 LIST_RESP to {addr[0]}:{addr[1]} (local, {reply_ip})")
            return resp

        # Everything else: log and forward to upstream
        opt_flags = struct.unpack_from('<I', data, 0x14)[0] if len(data) >= 0x18 else 0
        is_ack = bool((opt_flags >> 20) & 1)
        encrypt = (opt_flags >> 16) & 3
        self.log(f"\u2190 {type_name}{'_ACK' if is_ack else ''} from {addr[0]}:{addr[1]}:{our_port} "
                 f"tid={term_id} ({len(data)}B) enc={encrypt}")
        return None  # forward

    async def run(self):
        """Main capture loop."""
        self.log(f"GUTES Session Capture starting")
        self.log(f"  Local IP: {self.local_ip}")
        self.log(f"  Server term_id: {self._relay.server_term_id}")
        self.log(f"  Relay ports: {self.listen_ports}")
        self.log(f"  List port: {self.list_port}")
        self.log(f"  Upstream: {self.upstream_host}:{self.upstream_port}")
        self.log(f"  Pcap: {self.pcap.path}")
        self.log(f"  Trace: {self.trace.path}")
        self.log("")

        loop = asyncio.get_event_loop()

        # Bind relay ports
        for port in self.listen_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('0.0.0.0', port))
                sock.settimeout(1.0)
                self.relay_socks[port] = sock
                self.log(f"  Listening on UDP :{port}")
            except OSError as e:
                self.log(f"  WARN: Cannot bind :{port} ({e})")

        # Bind list port
        self.list_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.list_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.list_sock.bind(('0.0.0.0', self.list_port))
            self.list_sock.settimeout(1.0)
            self.log(f"  Listening on UDP :{self.list_port} (list)")
        except OSError as e:
            self.log(f"  WARN: Cannot bind list port :{self.list_port} ({e})")
            self.list_sock = None

        self.log("")
        self.log("Ready \u2014 waiting for connections (Ctrl+C to stop)...")
        self.log("=" * 60)

        tasks = []
        for port, sock in self.relay_socks.items():
            tasks.append(asyncio.create_task(self._recv_loop(sock, port)))
        if self.list_sock:
            tasks.append(asyncio.create_task(self._recv_loop(self.list_sock, self.list_port)))
        tasks.append(asyncio.create_task(self._upstream_recv_loop()))
        tasks.append(asyncio.create_task(self._status_loop()))

        await asyncio.gather(*tasks)

    async def _recv_loop(self, sock: socket.socket, port: int):
        loop = asyncio.get_event_loop()
        while True:
            try:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
            except socket.timeout:
                await asyncio.sleep(0)
                continue
            except OSError:
                await asyncio.sleep(0.01)
                continue

            resp = self._handle_packet(data, addr, port)
            if resp is not None:
                try:
                    sock.sendto(resp, addr)
                except OSError as e:
                    self.log(f"  ERROR sending to {addr}: {e}")
            else:
                await self._forward_to_upstream(data, addr, port, sock)

    async def _forward_to_upstream(self, data: bytes, client_addr: tuple,
                                   client_port: int, client_sock: socket.socket):
        term_id = self._decode_term_id(data) if len(data) >= HEADER_SIZE else 0
        upstream_sock = self._get_upstream_sock(term_id)

        fd = upstream_sock.fileno()
        self.upstream_to_client[fd] = (client_addr, client_port, client_sock, term_id)

        if client_port == self.list_port:
            dest = (self.upstream_host, 51701)
        else:
            dest = (self.upstream_host, self.upstream_port)

        # Record outbound to upstream
        self._record(data, self.local_ip, client_port,
                     dest[0], dest[1], "R\u2192U", "fwd to upstream")

        try:
            upstream_sock.sendto(data, dest)
            ftype = data[1] if len(data) > 1 else 0
            type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
            self.log(f"  \u2192 FWD {type_name} to upstream {dest[0]}:{dest[1]}")
        except OSError as e:
            self.log(f"  ERROR forwarding to upstream: {e}")

    async def _upstream_recv_loop(self):
        loop = asyncio.get_event_loop()
        while True:
            for term_id, sock in list(self.upstream_socks.items()):
                try:
                    data, upstream_addr = await loop.run_in_executor(
                        None, sock.recvfrom, 4096)
                except (socket.timeout, BlockingIOError, OSError):
                    continue

                ftype = data[1] if len(data) > 1 else 0
                type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                resp_term_id = self._decode_term_id(data) if len(data) >= HEADER_SIZE else 0

                self.log(f"  \u2190 UPS {type_name} from {upstream_addr[0]}:{upstream_addr[1]} "
                         f"({len(data)}B) tid={resp_term_id}")

                # Record upstream response
                fd = sock.fileno()
                if fd in self.upstream_to_client:
                    client_addr, client_port, client_sock, _ = self.upstream_to_client[fd]

                    self._record(data, upstream_addr[0], upstream_addr[1],
                                 self.local_ip, client_port, "U\u2192R",
                                 f"upstream {type_name}")

                    # Record relay to client
                    self._record(data, self.local_ip, client_port,
                                 client_addr[0], client_addr[1], "R\u2192C",
                                 f"relay {type_name}")

                    try:
                        client_sock.sendto(data, client_addr)
                        self.log(f"  \u2192 RELAY to {client_addr[0]}:{client_addr[1]}")
                    except OSError as e:
                        self.log(f"  ERROR relaying to client: {e}")
                elif resp_term_id in self.clients:
                    client_info = self.clients[resp_term_id]
                    client_addr = client_info['addr']
                    client_port = client_info['port']

                    self._record(data, upstream_addr[0], upstream_addr[1],
                                 self.local_ip, client_port, "U\u2192R",
                                 f"upstream {type_name}")

                    if client_port in self.relay_socks:
                        self._record(data, self.local_ip, client_port,
                                     client_addr[0], client_addr[1], "R\u2192C",
                                     f"relay {type_name} (by tid)")
                        try:
                            self.relay_socks[client_port].sendto(data, client_addr)
                            self.log(f"  \u2192 RELAY to {client_addr[0]}:{client_addr[1]} (by tid)")
                        except OSError as e:
                            self.log(f"  ERROR relaying: {e}")

            await asyncio.sleep(0.001)

    async def _status_loop(self):
        while True:
            await asyncio.sleep(30)
            self.log(f"--- STATUS: {len(self.clients)} clients, "
                     f"{self.pcap.pkt_count} pkts captured, "
                     f"{self.trace.frame_count} frames traced ---")
            for tid, info in self.clients.items():
                addr = info['addr']
                self.log(f"  tid={tid} addr={addr[0]}:{addr[1]} "
                         f"frames={info.get('frames', 0)}")

    def shutdown(self):
        """Clean shutdown — close capture files."""
        self.log(f"\nCapture complete:")
        self.log(f"  Packets in pcap: {self.pcap.pkt_count}")
        self.log(f"  Frames in trace: {self.trace.frame_count}")
        self.log(f"  Clients seen: {len(self.clients)}")
        self.pcap.close()
        self.trace.close()
        if self.log_fp:
            self.log_fp.close()


def main():
    parser = argparse.ArgumentParser(
        description="GUTES Session Capture — full protocol recording")
    parser.add_argument('--output', '-o', default='logs/capture',
                        help='Output prefix (default: logs/capture)')
    parser.add_argument('--upstream', default='3.13.212.24:28800',
                        help='Upstream Mars relay')
    parser.add_argument('--resolve', action='store_true',
                        help='Resolve Mars DNS for upstream')
    parser.add_argument('--ports', default='28800,8443,8000',
                        help='Relay ports (default: 28800,8443,8000)')
    parser.add_argument('--list-port', type=int, default=51701,
                        help='List port (default: 51701)')
    parser.add_argument('--local-ip', default='',
                        help='Override local IP')
    args = parser.parse_args()

    # Resolve upstream if requested
    upstream = args.upstream
    if args.resolve:
        try:
            results = socket.getaddrinfo("wyze-mars-asrv.wyzecam.com",
                                         None, socket.AF_INET)
            ips = list(set(r[4][0] for r in results))
            if ips:
                upstream = f"{ips[0]}:28800"
                print(f"Resolved Mars: {upstream} (from {len(ips)} IPs: {', '.join(ips)})")
        except Exception as e:
            print(f"DNS resolution failed: {e}, using default")

    ports = [int(p.strip()) for p in args.ports.split(',')]

    # Ensure output directory exists
    out_dir = Path(args.output).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    cap = CaptureRelay(
        output_prefix=args.output,
        listen_ports=ports,
        list_port=args.list_port,
        upstream=upstream,
        local_ip=args.local_ip,
    )

    try:
        asyncio.run(cap.run())
    except KeyboardInterrupt:
        pass
    finally:
        cap.shutdown()
        print(f"\nCapture saved to:")
        print(f"  {args.output}.pcap       (open in Wireshark)")
        print(f"  {args.output}.json       (parsed protocol trace)")
        print(f"  {args.output}.relay.log  (relay operational log)")


if __name__ == "__main__":
    main()
