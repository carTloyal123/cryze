"""Broadcast listener — discovers doorbells on the LAN via UDP port 8900."""

import asyncio
import os
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from log_config import get_logger
log = get_logger('relay.broadcast')


async def broadcast_listen(state, local_ip: str):
    """Listen on UDP port 8900 for doorbell LAN broadcast responses AND
    actively send broadcast probes to discover the doorbell.
    
    The doorbell sends type=0x03 broadcast frames on port 8900 when awake.
    These contain:
      - dst_id at offset 0x1C (8 bytes LE) — the doorbell's device ID
      - MTP port at offset 0x2C (2 bytes LE) — the port for video MTP sessions
      - MAC address at offset 0x3A (6 bytes)
    
    Active probing: sends broadcast probe to doorbell every 5 seconds.
    This runs BEFORE the bridge SDK starts, so we get the response
    before the SDK binds port 8900 and steals it.
    
    Args:
        state: RelayState instance
        local_ip: Our local IP address
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.5)
    try:
        sock.bind(('0.0.0.0', 8900))
        log.info(f"  Broadcast listener on UDP :8900 (doorbell discovery)")
    except OSError as e:
        log.info(f"  WARN: Cannot bind broadcast port 8900 ({e})")
        return
    
    loop = asyncio.get_event_loop()
    doorbell_ip = os.environ.get('DOORBELL_IP', '')
    probe_interval = 5  # seconds between active probes
    last_probe = 0
    
    # Build a broadcast probe (type=0x02 = probe request, proto=0x70)
    probe = bytearray(28)
    probe[0] = 0x70  # broadcast proto
    probe[1] = 0x02  # probe request type
    struct.pack_into('<H', probe, 2, 28)  # frame length
    
    while True:
        try:
            now = asyncio.get_event_loop().time()
            
            # Send active probes to doorbell IP and broadcast
            if now - last_probe > probe_interval and state.doorbell_mtp_port == 0:
                last_probe = now
                try:
                    if doorbell_ip:
                        sock.sendto(bytes(probe), (doorbell_ip, 8899))
                    sock.sendto(bytes(probe), ('255.255.255.255', 8899))
                except Exception:
                    pass  # Best effort
            
            data, addr = await loop.run_in_executor(None, sock.recvfrom, 4096)
        except socket.timeout:
            await asyncio.sleep(0)
            continue
        except Exception:
            await asyncio.sleep(1)
            continue
        
        src_ip = addr[0]
        
        # Only process broadcast responses (proto=0x70, type=0x03)
        if len(data) < 0x2E or data[0] != 0x70 or data[1] != 0x03:
            if len(data) > 1 and data[0] == 0x70:
                log.info(f"[BROADCAST:8900] frame: proto=0x{data[0]:02x} type=0x{data[1]:02x} "
                        f"({len(data)}B) from {src_ip}")
            continue
        
        # Extract device ID from offset 0x1C (8 bytes LE)
        dst_id = struct.unpack_from('<q', data, 0x1C)[0]
        
        # Extract MTP port from offset 0x2C (2 bytes LE)
        mtp_port = struct.unpack_from('<H', data, 0x2C)[0]
        
        # Extract MAC from offset 0x3A (6 bytes)
        mac = ':'.join(f'{b:02x}' for b in data[0x3A:0x40])
        
        # Update state
        if mtp_port > 0 and mtp_port != state.doorbell_mtp_port:
            log.info(f"[BROADCAST] Doorbell discovered: {src_ip} "
                    f"dst_id={dst_id} mtp_port={mtp_port} mac={mac}")
            state.doorbell_mtp_port = mtp_port
            state.doorbell_dst_id = dst_id
            
            # Also update DOORBELL_IP if not set
            if not doorbell_ip:
                os.environ['DOORBELL_IP'] = src_ip
                log.info(f"[BROADCAST] Auto-set DOORBELL_IP={src_ip}")
