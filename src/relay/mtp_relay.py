"""MTP TCP relay subsystem — pairs bridge and doorbell TCP connections for media transport."""

import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from log_config import get_logger
log = get_logger('relay.mtp')

from constants import HEADER_SIZE, FRAME_TYPES
from models import MtpConnection, MtpRelayPair, RelayState


class MtpRelay:
    """MTP TCP relay server that pairs bridge <-> doorbell connections."""

    def __init__(self, relay):
        """Initialize with a reference to the parent GutesRelay for state and helpers.
        
        Args:
            relay: GutesRelay instance (provides state, decode_term_id, local_ip, etc.)
        """
        self.relay = relay
        self.state: RelayState = relay.state

    async def tcp_listen(self):
        """Listen for MTP TCP connections from bridge and doorbell.
        
        After we send MTP_RES_RESP, the SDK connects to our mtp_port via TCP.
        The bridge connects first (it initiated the CALLING).
        The doorbell may connect later (after receiving the routed CALLING).
        
        We pair connections and forward MTP_DATA (0xCA) between them.
        """
        server = await asyncio.start_server(
            self._tcp_handle_client,
            '0.0.0.0', self.relay.mtp_port, reuse_address=True)
        log.info(f"  [MTP] Listening on TCP :{self.relay.mtp_port} (MTP relay)")
        async with server:
            await server.serve_forever()

    async def _tcp_handle_client(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter):
        """Handle an incoming MTP TCP connection.
        
        Connection identification strategy:
        - Read the first frame to determine the sender's identity
        - If from bridge IP -> bridge side
        - If from doorbell IP -> doorbell side
        - Pair bridge+doorbell and start bidirectional forwarding
        """
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else 'unknown'
        peer_port = peer[1] if peer else 0
        log.info(f"  [MTP] TCP connection from {peer_ip}:{peer_port}")
        
        # Create MTP connection object
        conn = MtpConnection(
            reader=reader,
            writer=writer,
            addr=(peer_ip, peer_port),
        )
        
        # Identify the role based on IP
        role = self._identify_role(peer_ip)
        conn.role = role
        log.info(f"  [MTP] Identified as: {role} (from {peer_ip}:{peer_port})")
        
        if role == "bridge":
            # Bridge connecting — try to pair with a waiting doorbell
            paired = self._try_pair_bridge(conn)
            if paired:
                await self._relay_loop(paired)
            else:
                # No doorbell yet — wait for one
                self.state.mtp_pending_bridges.append(conn)
                log.info(f"  [MTP] Bridge queued, waiting for doorbell connection...")
                # Wait up to 30s for doorbell to connect
                paired = await self._wait_for_pair(conn, "bridge")
                if paired:
                    await self._relay_loop(paired)
                else:
                    log.info(f"  [MTP] Bridge connection timed out waiting for doorbell")
                    writer.close()
        elif role == "doorbell":
            # Doorbell connecting — try to pair with a waiting bridge
            paired = self._try_pair_doorbell(conn)
            if paired:
                await self._relay_loop(paired)
            else:
                # No bridge yet — wait for one
                self.state.mtp_pending_doorbells.append(conn)
                log.info(f"  [MTP] Doorbell queued, waiting for bridge connection...")
                paired = await self._wait_for_pair(conn, "doorbell")
                if paired:
                    await self._relay_loop(paired)
                else:
                    log.info(f"  [MTP] Doorbell connection timed out waiting for bridge")
                    writer.close()
        else:
            # Unknown — read first frame to try to identify
            log.info(f"  [MTP] Unknown role for {peer_ip}:{peer_port}, "
                    f"reading first frame to identify...")
            try:
                first_data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
                if first_data:
                    conn.role = self._identify_role_from_frame(first_data, peer_ip)
                    log.info(f"  [MTP] Re-identified as: {conn.role} from first frame")
                    # Try pairing again
                    if conn.role == "bridge":
                        self.state.mtp_pending_bridges.append(conn)
                    else:
                        self.state.mtp_pending_doorbells.append(conn)
                    paired = await self._wait_for_pair(conn, conn.role)
                    if paired:
                        # Send the buffered first_data to the peer
                        if conn.role == "bridge" and paired.doorbell:
                            paired.doorbell.writer.write(first_data)
                        elif conn.role == "doorbell" and paired.bridge:
                            paired.bridge.writer.write(first_data)
                        await self._relay_loop(paired)
                    else:
                        writer.close()
                else:
                    writer.close()
            except (asyncio.TimeoutError, ConnectionError):
                log.info(f"  [MTP] Connection from {peer_ip}:{peer_port} failed/timed out")
                writer.close()

    def _identify_role(self, ip: str) -> str:
        """Identify whether an MTP TCP connection is from bridge or doorbell."""
        # Check against known client IPs
        for tid, client in self.state.clients.items():
            if client.addr[0] == ip:
                if client.role in ("bridge", "doorbell"):
                    return client.role
        
        # Direct IP heuristics
        if ip in ("192.168.1.245", "192.168.1.236", "127.0.0.1", "192.168.5.1"):
            return "bridge"
        elif ip == "192.168.1.81":
            return "doorbell"
        
        # If bridge is local (same machine), the IP might match local_ip
        if ip == self.relay.local_ip or ip == "127.0.0.1":
            return "bridge"
        
        return "unknown"

    def _identify_role_from_frame(self, data: bytes, ip: str) -> str:
        """Try to identify role from the first MTP frame data."""
        if len(data) >= HEADER_SIZE:
            term_id = self.relay.decode_term_id(data)
            if term_id == self.state.bridge_term_id:
                return "bridge"
            elif term_id == self.state.doorbell_term_id:
                return "doorbell"
        # Fallback: first connector is likely bridge (it initiated CALLING)
        return "bridge"

    def _try_pair_bridge(self, bridge_conn: MtpConnection) -> Optional[MtpRelayPair]:
        """Try to pair a bridge connection with a waiting doorbell."""
        if self.state.mtp_pending_doorbells:
            doorbell_conn = self.state.mtp_pending_doorbells.pop(0)
            pair = MtpRelayPair(
                link_id=self.state.mtp_link_counter,
                bridge=bridge_conn,
                doorbell=doorbell_conn,
                created=time.time(),
                active=True,
            )
            log.info(f"  [MTP] PAIRED: bridge {bridge_conn.addr} <-> doorbell {doorbell_conn.addr}")
            return pair
        return None

    def _try_pair_doorbell(self, doorbell_conn: MtpConnection) -> Optional[MtpRelayPair]:
        """Try to pair a doorbell connection with a waiting bridge."""
        if self.state.mtp_pending_bridges:
            bridge_conn = self.state.mtp_pending_bridges.pop(0)
            pair = MtpRelayPair(
                link_id=self.state.mtp_link_counter,
                bridge=bridge_conn,
                doorbell=doorbell_conn,
                created=time.time(),
                active=True,
            )
            log.info(f"  [MTP] PAIRED: bridge {bridge_conn.addr} <-> doorbell {doorbell_conn.addr}")
            return pair
        return None

    async def _wait_for_pair(self, conn: MtpConnection, role: str,
                              timeout: float = 30.0) -> Optional[MtpRelayPair]:
        """Wait for the other side to connect and pair with us."""
        start = time.time()
        while (time.time() - start) < timeout:
            await asyncio.sleep(0.1)
            # Check if we've been paired (removed from pending list means paired)
            if role == "bridge" and conn not in self.state.mtp_pending_bridges:
                # We were paired by a doorbell connecting
                # Find the pair that has us
                for pair in self.state.mtp_pairs.values():
                    if pair.bridge is conn:
                        return pair
                # Also check — the doorbell handler may have created a pair directly
                break
            elif role == "doorbell" and conn not in self.state.mtp_pending_doorbells:
                for pair in self.state.mtp_pairs.values():
                    if pair.doorbell is conn:
                        return pair
                break
            
            # Actively try to pair
            if role == "bridge" and self.state.mtp_pending_doorbells:
                doorbell_conn = self.state.mtp_pending_doorbells.pop(0)
                # Remove ourselves from pending
                if conn in self.state.mtp_pending_bridges:
                    self.state.mtp_pending_bridges.remove(conn)
                pair = MtpRelayPair(
                    link_id=self.state.mtp_link_counter,
                    bridge=conn,
                    doorbell=doorbell_conn,
                    created=time.time(),
                    active=True,
                )
                self.state.mtp_pairs[pair.link_id] = pair
                log.info(f"  [MTP] PAIRED (delayed): bridge {conn.addr} <-> doorbell {doorbell_conn.addr}")
                return pair
            elif role == "doorbell" and self.state.mtp_pending_bridges:
                bridge_conn = self.state.mtp_pending_bridges.pop(0)
                if conn in self.state.mtp_pending_doorbells:
                    self.state.mtp_pending_doorbells.remove(conn)
                pair = MtpRelayPair(
                    link_id=self.state.mtp_link_counter,
                    bridge=bridge_conn,
                    doorbell=conn,
                    created=time.time(),
                    active=True,
                )
                self.state.mtp_pairs[pair.link_id] = pair
                log.info(f"  [MTP] PAIRED (delayed): bridge {bridge_conn.addr} <-> doorbell {conn.addr}")
                return pair
        
        # Cleanup: remove from pending if still there
        if role == "bridge" and conn in self.state.mtp_pending_bridges:
            self.state.mtp_pending_bridges.remove(conn)
        elif role == "doorbell" and conn in self.state.mtp_pending_doorbells:
            self.state.mtp_pending_doorbells.remove(conn)
        return None

    async def _relay_loop(self, pair: MtpRelayPair):
        """Bidirectional relay between paired bridge and doorbell TCP connections.
        
        Forwards all data (including MTP_DATA frames, type 0xCA) between the two.
        """
        if not pair.bridge or not pair.doorbell:
            log.info(f"  [MTP] Cannot relay — incomplete pair (link_id={pair.link_id})")
            return
        
        pair.active = True
        bridge_r = pair.bridge.reader
        bridge_w = pair.bridge.writer
        doorbell_r = pair.doorbell.reader
        doorbell_w = pair.doorbell.writer
        
        log.info(f"  [MTP] RELAY ACTIVE: bridge {pair.bridge.addr} <-> doorbell {pair.doorbell.addr}")
        
        bytes_b2d = 0  # bridge -> doorbell
        bytes_d2b = 0  # doorbell -> bridge
        
        async def bridge_to_doorbell():
            nonlocal bytes_b2d
            try:
                while True:
                    data = await bridge_r.read(65536)
                    if not data:
                        break
                    doorbell_w.write(data)
                    await doorbell_w.drain()
                    bytes_b2d += len(data)
                    # Log first frame or periodically
                    if bytes_b2d == len(data) or bytes_b2d % (1024 * 1024) < len(data):
                        ftype = data[1] if len(data) >= 2 else 0
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        log.info(f"  [MTP] B->D: {type_name} ({len(data)}B) "
                                f"total={bytes_b2d}B")
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass
        
        async def doorbell_to_bridge():
            nonlocal bytes_d2b
            try:
                while True:
                    data = await doorbell_r.read(65536)
                    if not data:
                        break
                    bridge_w.write(data)
                    await bridge_w.drain()
                    bytes_d2b += len(data)
                    if bytes_d2b == len(data) or bytes_d2b % (1024 * 1024) < len(data):
                        ftype = data[1] if len(data) >= 2 else 0
                        type_name = FRAME_TYPES.get(ftype, f"0x{ftype:02X}")
                        log.info(f"  [MTP] D->B: {type_name} ({len(data)}B) "
                                f"total={bytes_d2b}B")
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass
        
        try:
            await asyncio.gather(bridge_to_doorbell(), doorbell_to_bridge())
        finally:
            pair.active = False
            log.info(f"  [MTP] RELAY CLOSED: link_id={pair.link_id} "
                    f"B->D={bytes_b2d}B D->B={bytes_d2b}B")
            # Cleanup
            try:
                bridge_w.close()
            except:
                pass
            try:
                doorbell_w.close()
            except:
                pass
