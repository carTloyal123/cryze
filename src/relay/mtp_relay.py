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
    """MTP TCP relay server that pairs bridge <-> doorbell connections by device MAC."""

    def __init__(self, relay):
        """Initialize with a reference to the parent GutesRelay.

        Args:
            relay: GutesRelay instance (provides state, decode_term_id, local_ip, etc.)
        """
        self.relay = relay
        self.state: RelayState = relay.state

    async def tcp_listen(self):
        """Listen for MTP TCP connections from bridge and doorbell.

        After we send MTP_RES_RESP, the SDK connects to our mtp_port via TCP.
        We identify each connection by IP (via registry + certified client map),
        then pair bridge↔doorbell by device MAC and link_id.
        """
        server = await asyncio.start_server(
            self._tcp_handle_client,
            '0.0.0.0', self.relay.mtp_port, reuse_address=True)
        log.info("  [MTP] Listening on TCP :%d (MTP relay)", self.relay.mtp_port)
        async with server:
            await server.serve_forever()

    async def _tcp_handle_client(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter):
        """Handle an incoming MTP TCP connection.

        Identification strategy:
        1. Check certified ClientSession map for this IP → role
        2. Check registry for doorbell IPs
        3. Check if IP matches relay's local_ip → bridge
        4. Fall back to reading the first frame for term_id matching
        """
        peer = writer.get_extra_info('peername')
        peer_ip   = peer[0] if peer else 'unknown'
        peer_port = peer[1] if peer else 0
        log.info("  [MTP] TCP connection from %s:%d", peer_ip, peer_port)

        conn = MtpConnection(reader=reader, writer=writer, addr=(peer_ip, peer_port))

        role, device_mac = self._identify_role(peer_ip)
        conn.role       = role
        conn.device_mac = device_mac
        log.info("  [MTP] Identified as: %s mac=%s (from %s:%d)",
                 role, device_mac or '?', peer_ip, peer_port)

        if role == "bridge":
            await self._handle_bridge_conn(conn)
        elif role == "doorbell":
            await self._handle_doorbell_conn(conn)
        else:
            # Unknown — read first frame, try term_id matching
            log.info("  [MTP] Unknown role for %s:%d, reading first frame...", peer_ip, peer_port)
            try:
                first_data = await asyncio.wait_for(reader.read(8192), timeout=10.0)
                if first_data:
                    role, device_mac = self._identify_role_from_frame(first_data, peer_ip)
                    conn.role       = role
                    conn.device_mac = device_mac
                    log.info("  [MTP] Re-identified as: %s mac=%s", role, device_mac or '?')
                    if role == "bridge":
                        await self._handle_bridge_conn(conn, buffered=first_data)
                    else:
                        await self._handle_doorbell_conn(conn, buffered=first_data)
                else:
                    writer.close()
            except (asyncio.TimeoutError, ConnectionError):
                log.info("  [MTP] Connection from %s:%d timed out", peer_ip, peer_port)
                writer.close()

    async def _handle_bridge_conn(self, conn: MtpConnection, buffered: bytes = b''):
        """Handle a bridge MTP connection: pair with doorbell or queue."""
        paired = self._try_pair_bridge(conn)
        if paired:
            if buffered:
                # Forward buffered data to doorbell
                if paired.doorbell:
                    paired.doorbell.writer.write(buffered)
            await self._relay_loop(paired)
        else:
            self.state.mtp_pending_bridges.setdefault(conn.device_mac, []).append(conn)
            log.info("  [MTP] Bridge queued (mac=%s), waiting for doorbell...", conn.device_mac)
            paired = await self._wait_for_pair(conn, "bridge")
            if paired:
                if buffered and paired.doorbell:
                    paired.doorbell.writer.write(buffered)
                await self._relay_loop(paired)
            else:
                log.info("  [MTP] Bridge timed out waiting for doorbell (mac=%s)", conn.device_mac)
                conn.writer.close()

    async def _handle_doorbell_conn(self, conn: MtpConnection, buffered: bytes = b''):
        """Handle a doorbell MTP connection: pair with bridge or queue."""
        paired = self._try_pair_doorbell(conn)
        if paired:
            if buffered and paired.bridge:
                paired.bridge.writer.write(buffered)
            await self._relay_loop(paired)
        else:
            self.state.mtp_pending_doorbells.setdefault(conn.device_mac, []).append(conn)
            log.info("  [MTP] Doorbell queued (mac=%s), waiting for bridge...", conn.device_mac)
            paired = await self._wait_for_pair(conn, "doorbell")
            if paired:
                if buffered and paired.bridge:
                    paired.bridge.writer.write(buffered)
                await self._relay_loop(paired)
            else:
                log.info("  [MTP] Doorbell timed out waiting for bridge (mac=%s)", conn.device_mac)
                conn.writer.close()

    def _identify_role(self, ip: str) -> tuple:
        """Identify role and device MAC for an MTP TCP connection.

        Returns (role, device_mac) where role is 'bridge', 'doorbell', or 'unknown'.
        device_mac may be empty string if unknown.
        """
        # 1. Check certified clients first (most reliable)
        for tid, client in self.state.clients.items():
            if client.addr[0] == ip and client.role in ("bridge", "doorbell"):
                return client.role, client.device_mac

        # 2. Use registry for doorbell IPs
        registry = self.state.registry
        if registry and registry.is_doorbell_ip(ip):
            info = registry.get_by_lan_ip(ip)
            return "doorbell", (info.mac if info else "")

        # 3. Relay's own IP or loopback → bridge
        if ip in (self.relay.local_ip, "127.0.0.1"):
            # For multiple bridges on loopback, we can't distinguish by IP alone.
            # Return 'bridge' with empty MAC; the link_id pairing will sort it out.
            return "bridge", ""

        return "unknown", ""

    def _identify_role_from_frame(self, data: bytes, ip: str) -> tuple:
        """Identify role from the first MTP frame's term_id."""
        if len(data) >= HEADER_SIZE:
            term_id = self.relay.decode_term_id(data)
            # Check bridge term_ids
            for mac, tid in self.state.bridge_term_ids.items():
                if tid == term_id:
                    return "bridge", mac
            # Check doorbell term_ids
            for mac, tid in self.state.doorbell_term_ids.items():
                if tid == term_id:
                    return "doorbell", mac
        # Fallback: first connector is usually bridge (it initiated CALLING)
        return "bridge", ""

    def _get_conn_mac(self, conn: MtpConnection) -> str:
        """Get the device MAC associated with an MTP connection.

        Falls back to certified client lookup by IP, then registry.
        """
        if conn.device_mac:
            return conn.device_mac
        # Try certified client map
        for tid, client in self.state.clients.items():
            if client.addr[0] == conn.addr[0] and client.device_mac:
                return client.device_mac
        # Try registry
        registry = self.state.registry
        if registry:
            info = registry.get_by_lan_ip(conn.addr[0])
            if info:
                return info.mac
        return ""

    def _try_pair_bridge(self, bridge_conn: MtpConnection) -> Optional[MtpRelayPair]:
        """Pair a bridge connection with a waiting doorbell for the same device MAC.

        Matches by:
        1. Same device MAC (primary key)
        2. Same link_id if both sides have non-zero link_id (secondary key)

        Falls back to any waiting doorbell if MAC is unknown (""→"" match).
        """
        mac     = self._get_conn_mac(bridge_conn)
        pending = self.state.mtp_pending_doorbells.get(mac, [])
        if not pending and mac:
            # Also check "" bucket (doorbell not yet MAC-identified)
            pending = self.state.mtp_pending_doorbells.get("", [])

        for i, doorbell_conn in enumerate(pending):
            link_match = (bridge_conn.link_id == 0 or doorbell_conn.link_id == 0
                          or bridge_conn.link_id == doorbell_conn.link_id)
            if link_match:
                pending.pop(i)
                return self._make_pair(bridge_conn, doorbell_conn)
        return None

    def _try_pair_doorbell(self, doorbell_conn: MtpConnection) -> Optional[MtpRelayPair]:
        """Pair a doorbell connection with a waiting bridge for the same device MAC."""
        mac     = self._get_conn_mac(doorbell_conn)
        pending = self.state.mtp_pending_bridges.get(mac, [])
        if not pending and mac:
            pending = self.state.mtp_pending_bridges.get("", [])

        for i, bridge_conn in enumerate(pending):
            link_match = (bridge_conn.link_id == 0 or doorbell_conn.link_id == 0
                          or bridge_conn.link_id == doorbell_conn.link_id)
            if link_match:
                pending.pop(i)
                return self._make_pair(bridge_conn, doorbell_conn)
        return None

    def _make_pair(self, bridge_conn: MtpConnection,
                   doorbell_conn: MtpConnection) -> MtpRelayPair:
        """Create and register an MtpRelayPair."""
        device_mac = bridge_conn.device_mac or doorbell_conn.device_mac
        pair = MtpRelayPair(
            link_id=self.state.mtp_link_counter,
            bridge=bridge_conn,
            doorbell=doorbell_conn,
            created=time.time(),
            active=True,
            device_mac=device_mac,
        )
        self.state.mtp_link_counter += 1
        self.state.mtp_pairs[pair.link_id] = pair
        log.info("  [MTP] PAIRED: bridge %s <-> doorbell %s (mac=%s link_id=%d)",
                 bridge_conn.addr, doorbell_conn.addr, device_mac, pair.link_id)
        return pair

    async def _wait_for_pair(self, conn: MtpConnection, role: str,
                              timeout: float = 30.0) -> Optional[MtpRelayPair]:
        """Wait for the other side to connect and pair with us."""
        start = time.time()
        while (time.time() - start) < timeout:
            await asyncio.sleep(0.1)

            # Check if we've been paired (removed from pending list)
            if role == "bridge":
                bucket = self.state.mtp_pending_bridges.get(conn.device_mac, [])
                if conn not in bucket:
                    # Find the pair
                    for pair in self.state.mtp_pairs.values():
                        if pair.bridge is conn:
                            return pair
                    break
                # Actively try to pair with any waiting doorbell
                doorbell_conn = None
                for mac_key in [conn.device_mac, ""]:
                    db_pending = self.state.mtp_pending_doorbells.get(mac_key, [])
                    for i, dc in enumerate(db_pending):
                        link_ok = (conn.link_id == 0 or dc.link_id == 0
                                   or conn.link_id == dc.link_id)
                        if link_ok:
                            doorbell_conn = db_pending.pop(i)
                            break
                    if doorbell_conn:
                        break
                if doorbell_conn:
                    bucket = self.state.mtp_pending_bridges.get(conn.device_mac, [])
                    if conn in bucket:
                        bucket.remove(conn)
                    return self._make_pair(conn, doorbell_conn)

            else:  # doorbell
                bucket = self.state.mtp_pending_doorbells.get(conn.device_mac, [])
                if conn not in bucket:
                    for pair in self.state.mtp_pairs.values():
                        if pair.doorbell is conn:
                            return pair
                    break
                bridge_conn = None
                for mac_key in [conn.device_mac, ""]:
                    br_pending = self.state.mtp_pending_bridges.get(mac_key, [])
                    for i, bc in enumerate(br_pending):
                        link_ok = (bc.link_id == 0 or conn.link_id == 0
                                   or bc.link_id == conn.link_id)
                        if link_ok:
                            bridge_conn = br_pending.pop(i)
                            break
                    if bridge_conn:
                        break
                if bridge_conn:
                    bucket = self.state.mtp_pending_doorbells.get(conn.device_mac, [])
                    if conn in bucket:
                        bucket.remove(conn)
                    return self._make_pair(bridge_conn, conn)

        # Cleanup: remove from pending if still there
        if role == "bridge":
            bucket = self.state.mtp_pending_bridges.get(conn.device_mac, [])
        else:
            bucket = self.state.mtp_pending_doorbells.get(conn.device_mac, [])
        if conn in bucket:
            bucket.remove(conn)
        return None

    async def _relay_loop(self, pair: MtpRelayPair):
        """Bidirectional relay between paired bridge and doorbell TCP connections."""
        if not pair.bridge or not pair.doorbell:
            log.info("  [MTP] Cannot relay — incomplete pair (link_id=%d)", pair.link_id)
            return

        pair.active = True
        bridge_r  = pair.bridge.reader
        bridge_w  = pair.bridge.writer
        doorbell_r = pair.doorbell.reader
        doorbell_w = pair.doorbell.writer

        log.info("  [MTP] RELAY ACTIVE: bridge %s <-> doorbell %s (mac=%s)",
                 pair.bridge.addr, pair.doorbell.addr, pair.device_mac)

        bytes_b2d = 0
        bytes_d2b = 0

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
                    if bytes_b2d == len(data) or bytes_b2d % (1024 * 1024) < len(data):
                        ftype = data[1] if len(data) >= 2 else 0
                        log.info("  [MTP] B->D: %s (%dB) total=%dB",
                                 FRAME_TYPES.get(ftype, f"0x{ftype:02X}"), len(data), bytes_b2d)
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
                        log.info("  [MTP] D->B: %s (%dB) total=%dB",
                                 FRAME_TYPES.get(ftype, f"0x{ftype:02X}"), len(data), bytes_d2b)
            except (ConnectionError, asyncio.IncompleteReadError, OSError):
                pass

        try:
            await asyncio.gather(bridge_to_doorbell(), doorbell_to_bridge())
        finally:
            pair.active = False
            log.info("  [MTP] RELAY CLOSED: link_id=%d B->D=%dB D->B=%dB",
                     pair.link_id, bytes_b2d, bytes_d2b)
            try:
                bridge_w.close()
            except Exception:
                pass
            try:
                doorbell_w.close()
            except Exception:
                pass
