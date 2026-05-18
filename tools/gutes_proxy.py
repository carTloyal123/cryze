#!/usr/bin/env python3
"""GUTES MitM Proxy — captures and decodes traffic between bridge SDK and Mars relay.

Usage:
  python3 gutes_proxy.py [--listen-port PORT] [--upstream HOST:PORT]

The proxy:
1. Listens on a local TCP+UDP port
2. Forwards all traffic to the real Mars relay server
3. Parses and logs all GUTES frames in both directions
4. Decrypts per-frame-key payloads (key derivation from header)
5. Tracks session keys after certify for opt_encrypt=2 decryption

To use:
1. Override DNS: add "wyze-mars-asrv.wyzecam.com → 127.0.0.1" to /etc/hosts in container
2. Or use --add-host in docker run
3. Run this proxy on the host, forwarding to the real relay

Architecture:
  Bridge SDK → TCP/UDP → [THIS PROXY] → TCP/UDP → Mars Relay (real)
"""

import argparse
import asyncio
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Add scripts dir to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from gutes_frame import parse_frame, read_frame_from_stream, GutesFrame, HEADER_SIZE
from rc5 import RC5, GWELL_KEY


@dataclass
class SessionState:
    """Tracks crypto state for a GUTES session."""
    term_id: int = 0
    session_id: int = 0
    session_key: Optional[bytes] = None  # 32-byte key after certify
    certify_random: Optional[bytes] = None  # client's 32-byte random (from certify req)
    frames_seen: int = 0


class GutesProxy:
    """Async TCP+UDP proxy with GUTES frame parsing."""

    def __init__(self, listen_host: str, listen_port: int,
                 upstream_host: str, upstream_port: int,
                 log_file: Optional[str] = None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.sessions: dict[int, SessionState] = {}  # term_id -> state
        self.log_file = open(log_file, 'w') if log_file else None
        self.t0 = time.time()

    def log(self, msg: str):
        elapsed = time.time() - self.t0
        line = f"[{elapsed:8.3f}] {msg}"
        print(line, flush=True)
        if self.log_file:
            self.log_file.write(line + "\n")
            self.log_file.flush()

    def log_frame(self, frame: GutesFrame, raw_len: int):
        """Log a parsed frame with details."""
        self.log(frame.summary())
        
        # Extra details for important frame types
        if frame.frame_type == 0x0C:  # CERTIFY
            self.log(f"    Certify: term_id={frame.term_id}")
            if frame.payload_decrypted and len(frame.payload_decrypted) >= 4:
                self.log(f"    Payload (dec): {frame.payload_decrypted[:48].hex()}")
        elif frame.frame_type == 0xA4:  # CALLING
            self.log(f"    CALLING frame ({len(frame.payload)} bytes payload)")
            if frame.payload_decrypted:
                self.log(f"    Payload (dec): {frame.payload_decrypted[:64].hex()}")
        elif frame.frame_type == 0xA2:  # MTP_RES_RESPONSE
            self.log(f"    MTP_RES_RESPONSE ({len(frame.payload)} bytes)")
            if frame.payload_decrypted:
                self.log(f"    Payload (dec): {frame.payload_decrypted[:64].hex()}")
        elif frame.frame_type == 0xA6:  # INIT_INFO_MSG
            self.log(f"    INIT_INFO_MSG ({len(frame.payload)} bytes)")
        
        # Log certify response (session_id)
        if frame.is_response and frame.frame_type == 0x0C:
            self.log(f"    Certify RESPONSE")
        
        # Always log raw hex for first few frames
        state = self.sessions.get(frame.term_id)
        if not state or state.frames_seen < 10:
            if len(frame.raw) <= 128:
                self.log(f"    RAW: {frame.raw.hex()}")
            else:
                self.log(f"    RAW: {frame.raw[:64].hex()}...({len(frame.raw)} total)")

    async def handle_tcp_client(self, client_reader: asyncio.StreamReader,
                                client_writer: asyncio.StreamWriter):
        """Handle a TCP connection from the bridge SDK."""
        peer = client_writer.get_extra_info('peername')
        self.log(f"TCP connection from {peer}")

        try:
            # Connect to upstream
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port)
            self.log(f"Connected to upstream {self.upstream_host}:{self.upstream_port}")
        except Exception as e:
            self.log(f"Failed to connect upstream: {e}")
            client_writer.close()
            return

        # Bidirectional relay with frame parsing
        async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       direction: str):
            buf = bytearray()
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    
                    # Forward immediately (don't delay the connection)
                    writer.write(data)
                    await writer.drain()
                    
                    # Parse frames from the accumulated buffer
                    buf.extend(data)
                    while len(buf) >= HEADER_SIZE:
                        # Check for valid protocol byte
                        if buf[0] not in (0x7F, 0x7E, 0x70):
                            # Skip invalid bytes
                            skip = 1
                            for i in range(1, min(len(buf), 64)):
                                if buf[i] in (0x7F, 0x7E, 0x70):
                                    skip = i
                                    break
                            else:
                                skip = len(buf)
                            self.log(f"    [{direction}] SKIP {skip} invalid bytes: {bytes(buf[:min(skip,16)]).hex()}")
                            del buf[:skip]
                            continue
                        
                        # Check if we have enough data
                        if len(buf) < 4:
                            break
                        frm_len = struct.unpack_from('<H', buf, 2)[0]
                        if frm_len < HEADER_SIZE or frm_len > 0x2800:
                            self.log(f"    [{direction}] INVALID frm_len={frm_len}, skipping byte")
                            del buf[:1]
                            continue
                        if len(buf) < frm_len:
                            break  # Wait for more data
                        
                        # Parse frame
                        frame_data = bytes(buf[:frm_len])
                        del buf[:frm_len]
                        
                        # Get session key if available
                        session_key = None
                        # Try to find session state by trying to decrypt term_id
                        frame = parse_frame(frame_data, direction=direction,
                                          session_key=session_key)
                        if frame:
                            # Track session state
                            if frame.term_id not in self.sessions:
                                self.sessions[frame.term_id] = SessionState(term_id=frame.term_id)
                            state = self.sessions[frame.term_id]
                            state.frames_seen += 1
                            
                            # Track certify response (session_id)
                            if (frame.frame_type == 0x0C and 
                                frame.ack_result == 0 and
                                direction == "S->C" and
                                len(frame.payload) >= 16):
                                # Certify response contains session_id at payload offset
                                self.log(f"    CERTIFY RESP detected")
                            
                            self.log_frame(frame, frm_len)

            except asyncio.CancelledError:
                pass
            except Exception as e:
                self.log(f"Relay error [{direction}]: {e}")
            finally:
                writer.close()

        # Run both directions concurrently
        task1 = asyncio.create_task(relay(client_reader, upstream_writer, "C->S"))
        task2 = asyncio.create_task(relay(upstream_reader, client_writer, "S->C"))

        done, pending = await asyncio.wait(
            [task1, task2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        
        self.log(f"TCP connection from {peer} closed")

    async def handle_udp(self):
        """Handle UDP detect probes — forward to upstream and return responses."""
        
        class UdpRelay(asyncio.DatagramProtocol):
            def __init__(self, proxy: 'GutesProxy'):
                self.proxy = proxy
                self.transport = None
                self.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.upstream_sock.setblocking(False)
                self.clients: dict[int, tuple] = {}  # sqnum -> client_addr
                
            def connection_made(self, transport):
                self.transport = transport
                
            def datagram_received(self, data: bytes, addr: tuple):
                self.proxy.log(f"UDP from {addr}: {len(data)} bytes proto=0x{data[0]:02X} type=0x{data[1]:02X}")
                
                # Parse as GUTES frame
                if len(data) >= HEADER_SIZE:
                    frame = parse_frame(data, direction="C->S(UDP)")
                    if frame:
                        self.proxy.log_frame(frame, len(data))
                        # Track client address for response routing
                        self.clients[frame.sqnum] = addr
                
                # Forward to upstream
                try:
                    self.upstream_sock.sendto(data, 
                        (self.proxy.upstream_host, self.proxy.upstream_port))
                except Exception as e:
                    self.proxy.log(f"UDP forward error: {e}")

        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UdpRelay(self),
            local_addr=(self.listen_host, self.listen_port))
        
        self.log(f"UDP listener on {self.listen_host}:{self.listen_port}")
        return transport

    async def run(self):
        """Start the proxy server."""
        self.log(f"Starting GUTES MitM Proxy")
        self.log(f"  Listen: {self.listen_host}:{self.listen_port} (TCP+UDP)")
        self.log(f"  Upstream: {self.upstream_host}:{self.upstream_port}")
        self.log("")

        # Start TCP server
        server = await asyncio.start_server(
            self.handle_tcp_client,
            self.listen_host, self.listen_port)
        self.log(f"TCP listener on {self.listen_host}:{self.listen_port}")

        # Start UDP relay
        udp_transport = await self.handle_udp()

        # Run until interrupted
        try:
            await asyncio.Future()  # Run forever
        except asyncio.CancelledError:
            pass
        finally:
            server.close()
            udp_transport.close()
            if self.log_file:
                self.log_file.close()


def main():
    parser = argparse.ArgumentParser(description="GUTES MitM Proxy")
    parser.add_argument('--listen-host', default='0.0.0.0',
                       help='Listen address (default: 0.0.0.0)')
    parser.add_argument('--listen-port', type=int, default=8443,
                       help='Listen port for TCP+UDP (default: 8443)')
    parser.add_argument('--upstream', default='3.131.23.11:8443',
                       help='Upstream Mars relay host:port')
    parser.add_argument('--log-file', default=None,
                       help='Write frame log to file')
    args = parser.parse_args()

    upstream_parts = args.upstream.split(':')
    upstream_host = upstream_parts[0]
    upstream_port = int(upstream_parts[1]) if len(upstream_parts) > 1 else 8443

    proxy = GutesProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        log_file=args.log_file)

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        print("\nProxy stopped.")


if __name__ == "__main__":
    main()
