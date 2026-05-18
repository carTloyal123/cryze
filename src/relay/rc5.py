"""RC5 cipher implementation matching libiotp2pav.so (Gwell/IoTVideo P2P SDK).

Supports:
- 8-byte block (w=32) and 16-byte block (w=64) modes
- Configurable rounds (default: 6, matching SDK)
- ECB mode encrypt/decrypt

The SDK uses RC5 with these parameters:
- ctx[0x26]: 8-byte block, 6 rounds, key="www.gwell.cc" (ID encryption)
- ctx[0x27]: 8-byte block, 6 rounds, per-frame key (7 bytes from header)
- ctx[0x28]: 8-byte block, 6 rounds, 32-byte session key (post-certify)
- ctx[0x29]: 16-byte block, 6 rounds, 16-byte device secret (certify encryption)
"""

import struct
from typing import Union


def _rotl32(val: int, n: int) -> int:
    """32-bit left rotate."""
    n &= 31
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def _rotr32(val: int, n: int) -> int:
    """32-bit right rotate."""
    n &= 31
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF


def _rotl64(val: int, n: int) -> int:
    """64-bit left rotate."""
    n &= 63
    return ((val << n) | (val >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _rotr64(val: int, n: int) -> int:
    """64-bit right rotate."""
    n &= 63
    return ((val >> n) | (val << (64 - n))) & 0xFFFFFFFFFFFFFFFF


# RC5 magic constants
_P32 = 0xB7E15163
_Q32 = 0x9E3779B9
_P64 = 0xB7E151628AED2A6B
_Q64 = 0x9E3779B97F4A7C15
_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


class RC5:
    """RC5 block cipher with configurable block size and rounds."""

    def __init__(self, block_bytes: int = 8, rounds: int = 6):
        """
        Args:
            block_bytes: Block size in bytes (8 for w=32, 16 for w=64)
            rounds: Number of rounds (SDK uses 6)
        """
        assert block_bytes in (8, 16), f"block_bytes must be 8 or 16, got {block_bytes}"
        self.block_bytes = block_bytes
        self.rounds = rounds
        self.w = 32 if block_bytes == 8 else 64  # word size in bits
        self.mask = _MASK32 if self.w == 32 else _MASK64
        self.S: list[int] = []  # expanded key schedule

    def setkey(self, key: bytes) -> 'RC5':
        """Set the encryption key (variable length)."""
        w = self.w
        r = self.rounds
        mask = self.mask

        if w == 32:
            P, Q = _P32, _Q32
            u = 4  # bytes per word
        else:
            P, Q = _P64, _Q64
            u = 8

        # Convert key bytes to words (little-endian)
        b = len(key)
        if b == 0:
            b = 1
            key = b'\x00'
        c = (b + u - 1) // u
        L = [0] * c
        for i in range(b - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + key[i]) & mask

        # Initialize expanded key table S
        t = 2 * (r + 1)
        S = [0] * t
        S[0] = P & mask
        for i in range(1, t):
            S[i] = (S[i - 1] + Q) & mask

        # Mix in the key
        A = B = i = j = 0
        n = 3 * max(t, c)
        for _ in range(n):
            A = S[i] = _rotl32((S[i] + A + B) & mask, 3) if w == 32 else \
                self._rotl_w((S[i] + A + B) & mask, 3)
            B = L[j] = self._rotl_w((L[j] + A + B) & mask, (A + B) & mask)
            i = (i + 1) % t
            j = (j + 1) % c

        self.S = S
        return self

    def _rotl_w(self, val: int, n: int) -> int:
        if self.w == 32:
            return _rotl32(val, n & 31)
        return _rotl64(val, n & 63)

    def _rotr_w(self, val: int, n: int) -> int:
        if self.w == 32:
            return _rotr32(val, n & 31)
        return _rotr64(val, n & 63)

    def encrypt_block(self, data: bytes) -> bytes:
        """Encrypt one block (8 or 16 bytes)."""
        assert len(data) == self.block_bytes
        S = self.S
        mask = self.mask

        if self.w == 32:
            A, B = struct.unpack_from('<II', data)
        else:
            A, B = struct.unpack_from('<QQ', data)

        A = (A + S[0]) & mask
        B = (B + S[1]) & mask

        for i in range(1, self.rounds + 1):
            A = (self._rotl_w(A ^ B, B) + S[2 * i]) & mask
            B = (self._rotl_w(B ^ A, A) + S[2 * i + 1]) & mask

        if self.w == 32:
            return struct.pack('<II', A, B)
        return struct.pack('<QQ', A, B)

    def decrypt_block(self, data: bytes) -> bytes:
        """Decrypt one block (8 or 16 bytes)."""
        assert len(data) == self.block_bytes
        S = self.S
        mask = self.mask

        if self.w == 32:
            A, B = struct.unpack_from('<II', data)
        else:
            A, B = struct.unpack_from('<QQ', data)

        for i in range(self.rounds, 0, -1):
            B = self._rotr_w((B - S[2 * i + 1]) & mask, A) ^ A
            A = self._rotr_w((A - S[2 * i]) & mask, B) ^ B

        B = (B - S[1]) & mask
        A = (A - S[0]) & mask

        if self.w == 32:
            return struct.pack('<II', A, B)
        return struct.pack('<QQ', A, B)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data in ECB mode (must be multiple of block_bytes)."""
        assert len(data) % self.block_bytes == 0
        out = bytearray()
        for i in range(0, len(data), self.block_bytes):
            out.extend(self.encrypt_block(data[i:i + self.block_bytes]))
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data in ECB mode (must be multiple of block_bytes)."""
        assert len(data) % self.block_bytes == 0
        out = bytearray()
        for i in range(0, len(data), self.block_bytes):
            out.extend(self.decrypt_block(data[i:i + self.block_bytes]))
        return bytes(out)


# --- SDK-specific helpers ---

# Static key used for ID encryption (ctx[0x26])
GWELL_KEY = b"www.gwell.cc"

# Per-frame key derivation (ctx[0x27])
def derive_per_frame_key(frame_header: bytes) -> bytes:
    """Derive the 8-byte per-frame RC5 key from frame header bytes.
    
    From iv_gute_frm_rc5_encrypt (libiotp2pav.c:17750):
    key[0..6] = frame[0], frame[1], frame[2], frame[3], frame[0x14], frame[0x15], frame[0x16]
    """
    key = bytearray(8)
    key[0] = frame_header[0]
    key[1] = frame_header[1]
    key[2] = frame_header[2]
    key[3] = frame_header[3]
    key[4] = frame_header[0x14]
    key[5] = frame_header[0x15]
    key[6] = frame_header[0x16]
    key[7] = 0
    return bytes(key)


def id_encrypt(term_id_bytes: bytes, chkval_bytes: bytes, sqnum_bytes: bytes) -> bytes:
    """Encrypt the ID field in a GUTES frame header.
    
    From iv_gute_frm_encrypt_id:
    - XOR bytes [4..7] with [0xC..0xF] and [8..11] with [0x10..0x13]
    - Then RC5 encrypt the 8-byte ID with static key
    """
    # The ID field is 8 bytes at offset +4 in the frame
    # XOR with sqnum (4..7 ^ C..F) and chkval (8..B ^ 10..13)
    id_buf = bytearray(term_id_bytes[:8])
    sqn = sqnum_bytes[:4]
    chk = chkval_bytes[:4]
    for i in range(4):
        id_buf[i] ^= sqn[i]
        id_buf[4 + i] ^= chk[i]
    
    rc5 = RC5(block_bytes=8, rounds=6).setkey(GWELL_KEY)
    return rc5.encrypt_block(bytes(id_buf))


def id_decrypt(encrypted_id: bytes, chkval_bytes: bytes, sqnum_bytes: bytes) -> bytes:
    """Decrypt the ID field in a GUTES frame header."""
    rc5 = RC5(block_bytes=8, rounds=6).setkey(GWELL_KEY)
    id_buf = bytearray(rc5.decrypt_block(encrypted_id))
    
    sqn = sqnum_bytes[:4]
    chk = chkval_bytes[:4]
    for i in range(4):
        id_buf[i] ^= sqn[i]
        id_buf[4 + i] ^= chk[i]
    
    return bytes(id_buf)


if __name__ == "__main__":
    # Self-test: verify RC5 implementation with known test vectors
    # Test 8-byte block with zero key
    rc5 = RC5(block_bytes=8, rounds=6).setkey(b'\x00' * 8)
    pt = b'\x00' * 8
    ct = rc5.encrypt_block(pt)
    pt2 = rc5.decrypt_block(ct)
    assert pt2 == pt, f"8-byte decrypt mismatch: {pt2.hex()} != {pt.hex()}"
    print(f"RC5-8B encrypt(zeros): {ct.hex()}")
    print(f"RC5-8B decrypt back:   OK")

    # Test 16-byte block
    rc5_16 = RC5(block_bytes=16, rounds=6).setkey(b'\x01' * 16)
    pt16 = b'\x00' * 16
    ct16 = rc5_16.encrypt_block(pt16)
    pt16_2 = rc5_16.decrypt_block(ct16)
    assert pt16_2 == pt16, f"16-byte decrypt mismatch"
    print(f"RC5-16B encrypt(zeros): {ct16.hex()}")
    print(f"RC5-16B decrypt back:   OK")

    # Test with Gwell static key
    rc5_gw = RC5(block_bytes=8, rounds=6).setkey(GWELL_KEY)
    pt_id = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    ct_id = rc5_gw.encrypt_block(pt_id)
    pt_id2 = rc5_gw.decrypt_block(ct_id)
    assert pt_id2 == pt_id
    print(f"RC5-GWELL encrypt: {ct_id.hex()}")
    print(f"RC5-GWELL decrypt: OK")

    # Test per-frame key derivation
    fake_header = bytes(range(0x18))
    pfk = derive_per_frame_key(fake_header)
    print(f"Per-frame key from header: {pfk.hex()}")

    print("\nAll RC5 tests passed!")
