"""GUTES session key crypto — decryption, verification, and extraction helpers."""

import base64
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from log_config import get_logger
log = get_logger('relay.crypto')
from rc5 import RC5, GWELL_KEY, derive_per_frame_key
from constants import HEADER_SIZE
from models import RelayState


def decrypt_session_key(encrypted_key: bytes) -> Optional[bytes]:
    """Decrypt the 32-byte session key from CERTIFY_REQ.
    
    The SDK encrypts the session key with RC5(16-byte blocks, 6 rounds)
    using certify_key = mars_access_token_bytes[0x30:0x40] (16 bytes).
    Two 16-byte blocks are encrypted separately.
    """
    # Get mars_access_token from env or cache
    access_token = os.environ.get('MARS_ACCESS_TOKEN', '')
    if not access_token:
        # Try loading from cache
        try:
            cache_path = os.environ.get('SESSION_CACHE', '/work/cache/session_keys.json')
            auth_path = os.path.join(os.path.dirname(cache_path), 'auth.json')
            with open(auth_path) as f:
                auth = json.load(f)
            access_token = auth.get('mars_access_token', '')
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
    
    if not access_token:
        log.info("  [RELAY] No mars_access_token available for session key decryption")
        return None
    
    # mars_access_token: first 128 hex chars = 64 bytes (certify key at 0x30:0x40)
    try:
        token_bytes = bytes.fromhex(access_token[:128])
    except (ValueError, IndexError):
        try:
            token_bytes = base64.b64decode(access_token)
        except Exception:
            log.warning("mars_access_token not valid hex or Base64")
            return None
    
    if len(token_bytes) < 0x40:
        log.info(f"  [RELAY] mars_access_token too short ({len(token_bytes)}B, need 64B)")
        return None
    
    # Certify key is bytes [0x30:0x40] (16 bytes)
    certify_key = token_bytes[0x30:0x40]
    log.info(f"  [RELAY] Certify key: {certify_key.hex()}")
    
    # RC5 decrypt: 16-byte blocks, 6 rounds
    rc5 = RC5(block_bytes=16, rounds=6)
    rc5.setkey(certify_key)
    
    # Decrypt two 16-byte blocks
    block1 = rc5.decrypt_block(bytes(encrypted_key[0:16]))
    block2 = rc5.decrypt_block(bytes(encrypted_key[16:32]))
    
    return block1 + block2


def load_bridge_captured_session_key() -> Optional[bytes]:
    """Load session key captured by the bridge's rc5_ctx_setkey interpose hook.
    
    The bridge C++ code hooks the SDK's RC5 key setup and writes the 32-byte
    session key to a file after CERTIFY completes. The relay reads it here.
    """
    key_path = os.environ.get("SESSION_KEY_PATH", "/app/cache/session_key_extracted.bin")
    # Also check alternate paths for different container mount points
    alt_paths = [key_path, "/cache/session_key_extracted.bin", "cache/session_key_extracted.bin"]
    for path in alt_paths:
        try:
            data = Path(path).read_bytes()
            if len(data) == 32 and data != bytes(32):
                log.info(f"loaded bridge-captured session key from {path}")
                return data
        except (FileNotFoundError, OSError):
            continue
    return None


def giot_hash_string(data: bytes) -> int:
    """Compute the hash checksum used to verify the session key.
    
    From decompiled: giot_hash_string(param_1, param_2)
    Initial value = 0x4e67c6a7
    hash = hash ^ (byte + hash * 0x20 + (hash >> 2))
    """
    h = 0x4e67c6a7
    for b in data:
        h = (h ^ (b + (h * 0x20) + (h >> 2))) & 0xFFFFFFFF
    return h


def extract_request_sequence_number(req_data: bytes, addr: tuple = None,
                                     state: RelayState = None) -> int:
    """Extract the plaintext sqnum from an encrypted request frame.
    
    For opt_encrypt=1: bytes 0x0C-0x13 encrypted with per-frame key.
    For opt_encrypt=2: bytes 0x0C-0x13 encrypted with session RC5 key.
    """
    if len(req_data) < HEADER_SIZE:
        return 0
    
    opt_flags = struct.unpack_from('<I', req_data, 0x14)[0]
    opt_encrypt = (opt_flags >> 16) & 3
    
    if opt_encrypt == 0:
        # Not encrypted — read sqnum directly
        return struct.unpack_from('<I', req_data, 0x0C)[0]
    
    if opt_encrypt == 2 and addr and state:
        # Session-encrypted — use session key
        session_key = state.addr_session_keys.get(addr)
        if not session_key:
            # Try matching by IP only (SDK may use different ports per socket)
            for a, sk in state.addr_session_keys.items():
                if a[0] == addr[0]:
                    session_key = sk
                    break
        if session_key:
            log.info(f"  [DEBUG] _extract_req_sqnum: using session_key={session_key[:8].hex()}... for addr={addr}")
            rc5 = RC5(block_bytes=8, rounds=6)
            rc5.setkey(session_key)  # Full 32-byte session key
            decrypted_block = rc5.decrypt_block(bytes(req_data[0x0C:0x14]))
            sqnum = struct.unpack_from('<I', decrypted_block, 0)[0]
            log.info(f"  [DEBUG] _extract_req_sqnum: decrypted sqnum={sqnum} from enc_bytes={req_data[0x0C:0x14].hex()}")
            return sqnum
        else:
            log.info(f"  [DEBUG] _extract_req_sqnum: NO session key for addr={addr}, keys={list(state.addr_session_keys.keys())}")
    
    # Fallback: per-frame key (for opt_encrypt=1, or if no session key)
    pfk = derive_per_frame_key(req_data)
    rc5 = RC5(block_bytes=8, rounds=6)
    rc5.setkey(pfk)
    
    # Decrypt the 8 bytes at offset 0x0C (sqnum + chkval)
    decrypted_block = rc5.decrypt_block(bytes(req_data[0x0C:0x14]))
    
    return struct.unpack_from('<I', decrypted_block, 0)[0]


def verify_session_key(session_key: bytes, req_data: bytes) -> bool:
    """Check if our stored session key can actually decrypt this frame.
    
    If we derived the session key with the WRONG certify key (e.g., bridge's
    key for a chime's CERTIFY), the decrypted session key is garbage and
    session encryption will fail. We detect this by checking if the 32-byte
    key has a repeating pattern (characteristic of wrong-key decryption).
    """
    # Check for repeating 8-byte pattern (sign of wrong certify key)
    if len(session_key) >= 16:
        if session_key[:8] == session_key[8:16]:
            return False
    return True


def extract_calling_link_id(data: bytes, addr: tuple,
                             state: RelayState) -> Optional[int]:
    """Extract link_id from CALLING_REQ frame.
    
    The CALLING_REQ has link_id at frame[0x1C] (payload[0x04]).
    For session-encrypted frames, we decrypt the payload first.
    """
    opt_flags = struct.unpack_from('<I', data, 0x14)[0]
    encrypt_mode = (opt_flags >> 16) & 3
    
    if len(data) < 0x20:
        return None
    
    if encrypt_mode == 2:
        # Session-encrypted: decrypt payload to get link_id
        session_key = state.addr_session_keys.get(addr)
        if not session_key:
            # Try IP-based lookup
            for a, sk in state.addr_session_keys.items():
                if a[0] == addr[0]:
                    session_key = sk
                    break
        if session_key:
            rc5 = RC5(block_bytes=8, rounds=6).setkey(session_key)
            # Decrypt from 0x18 (first 8 bytes of payload contain link_id at offset 4)
            enc = bytes(data[0x18:0x20])
            dec = rc5.decrypt_block(enc)
            link_id = struct.unpack_from('<I', dec, 4)[0]
            log.info(f"  [MTP] Extracted link_id={link_id} from CALLING (session-dec)")
            return link_id
    elif encrypt_mode == 1:
        # Per-frame encrypted
        pfk = derive_per_frame_key(data[:0x18])
        rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
        enc = bytes(data[0x18:0x20])
        dec = rc5.decrypt_block(enc)
        link_id = struct.unpack_from('<I', dec, 4)[0]
        log.info(f"  [MTP] Extracted link_id={link_id} from CALLING (pfk-dec)")
        return link_id
    else:
        # Plaintext
        link_id = struct.unpack_from('<I', data, 0x1C)[0]
        log.info(f"  [MTP] Extracted link_id={link_id} from CALLING (plaintext)")
        return link_id
    
    return None


def persist_session_key(session_cache_path: Path, term_id: int, session_key: bytes):
    """Persist session key to JSON cache file."""
    try:
        session_cache_path.parent.mkdir(parents=True, exist_ok=True)
        # Load existing cache
        cache = {}
        if session_cache_path.exists():
            try:
                cache = json.loads(session_cache_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        # Store key as hex string, keyed by term_id string
        cache[str(term_id)] = session_key.hex()
        session_cache_path.write_text(json.dumps(cache, indent=2))
    except OSError as e:
        log.info(f"  WARN: Failed to persist session key: {e}")


def capture_session_key_from_response(state: RelayState, data: bytes, term_id: int,
                                       session_cache_path: Path):
    """Extract and cache session key from a proxied CERTIFY_RESP.
    
    The CERTIFY_RESP payload (per-frame encrypted) contains:
      session_id(8B) + server_key(32B) + padding
    
    We need both client_key (from the original CERTIFY_REQ) and server_key
    to derive session_key = client_key XOR server_key.
    
    Since the payload is per-frame encrypted (opt_encrypt=1), we can decrypt
    it with the per-frame key derived from the response header.
    """
    if len(data) < HEADER_SIZE + 40:
        return
    
    opt_flags = struct.unpack_from('<I', data, 0x14)[0]
    encrypt_mode = (opt_flags >> 16) & 0xF
    payload = data[HEADER_SIZE:]
    
    if encrypt_mode == 1:
        # Decrypt with per-frame key
        pfk = derive_per_frame_key(data[:0x18])
        rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
        dec_len = (len(payload) // 8) * 8
        if dec_len >= 40:
            payload = rc5.decrypt(bytes(payload[:dec_len]))
        else:
            return
    
    if len(payload) < 40:
        return
    
    # Extract server key from payload bytes 8:40
    server_key = payload[8:40]
    
    # We store the raw server_key; full session key derivation requires
    # client_key which we may not have captured. Store what we can.
    # If we have the full 32 bytes and they're not all zeros, cache it.
    if server_key != b'\x00' * 32:
        state.session_keys[term_id] = server_key
        persist_session_key(session_cache_path, term_id, server_key)
        log.info(f"  [CACHE] Captured session key material from CERTIFY_RESP for term_id={term_id}")
        log.info(f"  [CACHE] server_key={server_key[:8].hex()}...")


def get_session_key(state: RelayState, term_id: int,
                     session_cache_path: Path) -> Optional[bytes]:
    """Look up session key for a term_id.
    
    Checks in-memory cache first, then falls back to persistent JSON file.
    Returns the 32-byte session key or None if not found.
    """
    # Check in-memory cache
    if term_id in state.session_keys:
        return state.session_keys[term_id]
    
    # Fall back to persistent cache
    try:
        if session_cache_path.exists():
            cache = json.loads(session_cache_path.read_text())
            key_hex = cache.get(str(term_id))
            if key_hex:
                key_bytes = bytes.fromhex(key_hex)
                # Populate in-memory cache
                state.session_keys[term_id] = key_bytes
                return key_bytes
    except (json.JSONDecodeError, OSError, ValueError):
        pass
    
    return None
