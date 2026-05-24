"""Broadcast listener — discovers doorbells on the LAN via UDP port 8900."""

import asyncio
import socket
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from log_config import get_logger
log = get_logger('relay.broadcast')


async def broadcast_listen(state, local_ip: str, registry=None):
    """Listen on UDP port 8900 for doorbell LAN broadcast responses AND
    actively send broadcast probes to discover doorbells.

    The doorbell sends type=0x03 broadcast frames on port 8900 when awake.
    These contain:
      - dst_id at offset 0x1C (8 bytes LE) — the doorbell's device ID
      - MTP port at offset 0x2C (2 bytes LE) — the port for video MTP sessions
      - MAC address at offset 0x3A (6 bytes)

    When a response arrives we call registry.update_discovery(mac, ...) directly,
    keying on the MAC embedded in the frame (no IP guessing needed).

    Active probing sends broadcast probes every 5 seconds for any device whose
    LAN IP is not yet known. If registry provides cloud_ip for a device, we also
    send a unicast probe to that IP.

    Args:
        state:     RelayState instance
        local_ip:  Our local IP address
        registry:  DeviceRegistry (optional, enables MAC-based update and targeted probing)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.5)
    try:
        sock.bind(('0.0.0.0', 8900))
        log.info("  Broadcast listener on UDP :8900 (doorbell discovery)")
    except OSError as e:
        log.info("  WARN: Cannot bind broadcast port 8900 (%s)", e)
        return

    loop = asyncio.get_event_loop()
    probe_interval = 5  # seconds between active probes
    last_probe = 0.0

    # Build a broadcast probe (type=0x02 = probe request, proto=0x70)
    probe = bytearray(28)
    probe[0] = 0x70  # broadcast proto
    probe[1] = 0x02  # probe request type
    struct.pack_into('<H', probe, 2, 28)  # frame length

    while True:
        try:
            now = loop.time()

            # Send active probes for any device without a LAN IP yet
            if now - last_probe > probe_interval:
                last_probe = now
                # Always broadcast
                try:
                    sock.sendto(bytes(probe), ('255.255.255.255', 8899))
                except Exception:
                    pass
                # Unicast to cloud_ip for each device not yet discovered
                if registry:
                    for device in registry.devices:
                        if not device.lan_ip and device.cloud_ip:
                            try:
                                sock.sendto(bytes(probe), (device.cloud_ip, 8899))
                            except Exception:
                                pass

            data, addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
        except socket.timeout:
            await asyncio.sleep(0)
            continue
        except Exception:
            await asyncio.sleep(1)
            continue

        src_ip = addr[0]

        # Only process broadcast responses (proto=0x70, type=0x03)
        if len(data) < 0x40 or data[0] != 0x70 or data[1] != 0x03:
            if len(data) > 1 and data[0] == 0x70:
                log.info("[BROADCAST:8900] frame: proto=0x%02x type=0x%02x (%dB) from %s",
                         data[0], data[1], len(data), src_ip)
            continue

        # Extract fields from broadcast frame
        dst_id   = struct.unpack_from('<q', data, 0x1C)[0]
        mtp_port = struct.unpack_from('<H', data, 0x2C)[0]
        mac      = ':'.join(f'{b:02x}' for b in data[0x3A:0x40]).upper()

        log.info("[BROADCAST] Doorbell: %s ip=%s dst_id=%d mtp_port=%d",
                 mac, src_ip, dst_id, mtp_port)

        if registry:
            # Update registry — this indexes by MAC, no IP ambiguity
            registry.update_discovery(mac, src_ip, mtp_port, dst_id)
            # Mirror into RelayState for fast frame_builder lookups
            state.doorbell_mtp_ports[mac] = mtp_port
            state.doorbell_dst_ids[mac]   = dst_id
        else:
            # No registry — store under the src_ip as a best-effort key
            log.warning("[BROADCAST] No registry attached — storing dst_id/mtp_port by IP only")
            # We can't reliably key by MAC without a registry to confirm membership
