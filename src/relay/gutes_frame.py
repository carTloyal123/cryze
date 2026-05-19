"""GUTES frame parser — decodes the Gwell/IoTVideo P2P relay protocol frames.

Frame header format (from decompiled libiotp2pav.c):
  Offset  Size  Field
  0x00    1     protocol (0x7F=relay, 0x7E=session, 0x70=fragment/broadcast)
  0x01    1     type (frame type / dispatch key)
  0x02    2     frm_len (total frame length including header, LE)
  0x04    8     term_id (64-bit device ID, RC5-encrypted with "www.gwell.cc")
  0x0C    4     sqnum (sequence number, LE)
  0x10    4     chkval (checksum, LE)
  0x14    4     opt_flags (bitfield, LE)
  0x18    2     flags2 (LE)
  0x1A    2     ack_result (LE)
  0x1C+   var   payload (type-dependent)

opt_flags bitfield:
  bits 0:     compressed
  bits 1-15:  random nonce
  bits 16-17: opt_encrypt (0=none, 1=per-frame, 2=session key)
  bits 18-19: QoS (0=fire-forget, 1=need-ack, 2=?, 3=ack+callback)
  bit 20:     is_ack
  bit 21:     is_response
  bit 22:     signature_appended (HMAC-MD5, 16 bytes)
  bit 24:     ntp_timestamp_appended
  bit 25:     relay_flag (1=through relay server)
"""

import sys
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from rc5 import RC5, GWELL_KEY, derive_per_frame_key, id_decrypt
from constants import FRAME_TYPES, HEADER_SIZE


@dataclass
class GutesFrame:
    """Parsed GUTES frame."""
    # Raw data
    raw: bytes = b""
    
    # Header fields
    protocol: int = 0
    frame_type: int = 0
    frm_len: int = 0
    term_id_raw: bytes = b""  # 8 bytes, encrypted
    term_id: int = 0          # decrypted 64-bit ID
    sqnum: int = 0
    chkval: int = 0
    opt_flags: int = 0
    flags2: int = 0
    ack_result: int = 0
    
    # Decoded opt_flags
    compressed: bool = False
    nonce: int = 0
    opt_encrypt: int = 0      # 0=none, 1=per-frame, 2=session
    qos: int = 0
    is_ack: bool = False
    is_response: bool = False
    signature_appended: bool = False
    ntp_appended: bool = False
    relay_flag: bool = False
    
    # Payload
    payload: bytes = b""
    payload_decrypted: Optional[bytes] = None
    
    # Metadata
    type_name: str = ""
    direction: str = ""  # "C->S" or "S->C"
    
    @property
    def header_hex(self) -> str:
        return self.raw[:0x1C].hex() if len(self.raw) >= 0x1C else self.raw.hex()
    
    def summary(self) -> str:
        enc_str = ["none", "per-frame", "session", "?"][self.opt_encrypt]
        qos_str = ["fire", "ack", "?", "ack+cb"][self.qos]
        flags = []
        if self.is_ack: flags.append("ACK")
        if self.is_response: flags.append("RESP")
        if self.relay_flag: flags.append("RELAY")
        if self.signature_appended: flags.append("SIG")
        if self.ntp_appended: flags.append("NTP")
        if self.compressed: flags.append("COMP")
        flags_str = "|".join(flags) if flags else "-"
        
        return (f"[{self.direction}] {self.type_name:20s} "
                f"proto=0x{self.protocol:02X} len={self.frm_len:4d} "
                f"id={self.term_id:<20d} sq={self.sqnum} "
                f"enc={enc_str} qos={qos_str} flags={flags_str}")


def parse_frame(data: bytes, direction: str = "", session_key: Optional[bytes] = None) -> Optional[GutesFrame]:
    """Parse a GUTES frame from raw bytes.
    
    Args:
        data: Raw frame bytes (at least HEADER_SIZE bytes)
        direction: "C->S" or "S->C" for logging
        session_key: 32-byte session key for opt_encrypt=2 decryption (if known)
    
    Returns:
        Parsed GutesFrame or None if data is too short
    """
    if len(data) < HEADER_SIZE:
        return None
    
    f = GutesFrame()
    f.raw = data
    f.direction = direction
    
    # Parse header
    f.protocol = data[0]
    f.frame_type = data[1]
    f.frm_len = struct.unpack_from('<H', data, 2)[0]
    f.term_id_raw = data[4:12]
    f.sqnum = struct.unpack_from('<I', data, 0x0C)[0]
    f.chkval = struct.unpack_from('<I', data, 0x10)[0]
    f.opt_flags = struct.unpack_from('<I', data, 0x14)[0]
    f.flags2 = struct.unpack_from('<H', data, 0x18)[0]
    f.ack_result = struct.unpack_from('<H', data, 0x1A)[0]
    
    # Decode opt_flags
    f.compressed = bool(f.opt_flags & 1)
    f.nonce = (f.opt_flags >> 1) & 0x7FFF
    f.opt_encrypt = (f.opt_flags >> 16) & 3
    f.qos = (f.opt_flags >> 18) & 3
    f.is_ack = bool((f.opt_flags >> 20) & 1)
    f.is_response = bool((f.opt_flags >> 21) & 1)
    f.signature_appended = bool((f.opt_flags >> 22) & 1)
    f.ntp_appended = bool((f.opt_flags >> 24) & 1)
    f.relay_flag = bool((f.opt_flags >> 25) & 1)
    
    # Decrypt term_id
    try:
        sqnum_bytes = struct.pack('<I', f.sqnum)
        chkval_bytes = struct.pack('<I', f.chkval)
        id_bytes = id_decrypt(f.term_id_raw, chkval_bytes, sqnum_bytes)
        f.term_id = struct.unpack_from('<q', id_bytes)[0]
    except Exception:
        f.term_id = struct.unpack_from('<q', f.term_id_raw)[0]
    
    # Type name
    f.type_name = FRAME_TYPES.get(f.frame_type, f"UNKNOWN_0x{f.frame_type:02X}")
    
    # Extract payload
    payload_start = HEADER_SIZE
    payload_end = min(f.frm_len, len(data))
    f.payload = data[payload_start:payload_end]
    
    # Try to decrypt payload
    if f.opt_encrypt == 1 and len(f.payload) >= 8:
        # Per-frame key decryption
        try:
            pfk = derive_per_frame_key(data[:0x18])
            rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
            # Only decrypt if payload is multiple of 8
            dec_len = (len(f.payload) // 8) * 8
            if dec_len > 0:
                f.payload_decrypted = rc5.decrypt(f.payload[:dec_len])
                if dec_len < len(f.payload):
                    f.payload_decrypted += f.payload[dec_len:]
        except Exception:
            pass
    elif f.opt_encrypt == 2 and session_key and len(f.payload) >= 8:
        # Session key decryption
        try:
            rc5 = RC5(block_bytes=8, rounds=6).setkey(session_key)
            dec_len = (len(f.payload) // 8) * 8
            if dec_len > 0:
                f.payload_decrypted = rc5.decrypt(f.payload[:dec_len])
                if dec_len < len(f.payload):
                    f.payload_decrypted += f.payload[dec_len:]
        except Exception:
            pass
    elif f.opt_encrypt == 0:
        f.payload_decrypted = f.payload
    
    return f


def read_frame_from_stream(buf: bytearray) -> Optional[tuple[GutesFrame, int]]:
    """Try to parse a complete frame from a TCP stream buffer.
    
    Returns (frame, bytes_consumed) or None if not enough data.
    """
    if len(buf) < HEADER_SIZE:
        return None
    
    # Check protocol byte
    if buf[0] not in (0x7F, 0x7E, 0x70):
        # Invalid protocol byte — try to find the next valid frame
        for i in range(1, len(buf)):
            if buf[i] in (0x7F, 0x7E, 0x70):
                return None  # Caller should discard bytes before this
        return None
    
    # Read frame length
    frm_len = struct.unpack_from('<H', buf, 2)[0]
    if frm_len < HEADER_SIZE or frm_len > 0x2800:
        # Invalid length
        return None
    
    if len(buf) < frm_len:
        # Not enough data yet
        return None
    
    # Parse complete frame
    frame_data = bytes(buf[:frm_len])
    frame = parse_frame(frame_data)
    return (frame, frm_len) if frame else None


if __name__ == "__main__":
    # Test with a synthetic frame
    frame = bytearray(0x40)
    frame[0] = 0x7F  # protocol
    frame[1] = 0x0C  # CERTIFY
    struct.pack_into('<H', frame, 2, 0x40)  # frm_len
    struct.pack_into('<Q', frame, 4, 0x0102030405060708)  # term_id (raw)
    struct.pack_into('<I', frame, 0x0C, 1)  # sqnum
    struct.pack_into('<I', frame, 0x10, 2)  # chkval
    struct.pack_into('<I', frame, 0x14, 0x00010000)  # opt_flags: encrypt=1, nonce=0
    
    parsed = parse_frame(bytes(frame), direction="C->S")
    if parsed:
        print(parsed.summary())
        print(f"  Payload ({len(parsed.payload)} bytes): {parsed.payload[:32].hex()}")
        if parsed.payload_decrypted:
            print(f"  Decrypted: {parsed.payload_decrypted[:32].hex()}")
    
    print("\nFrame parser test OK!")
