"""GUTES relay data models — dataclass definitions for relay state."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ClientSession:
    """Tracks a connected client (bridge, chime, or doorbell)."""
    term_id: int = 0
    addr: tuple = ('', 0)
    session_id: int = 0
    last_seen: float = 0.0
    frames_in: int = 0
    frames_out: int = 0
    role: str = "unknown"  # "bridge", "chime", "doorbell"
    certified: bool = False
    # Track which port the client uses to talk to us
    our_port: int = 0
    # TCP connection (if connected via TCP)
    tcp_writer: Optional[object] = None  # asyncio.StreamWriter
    # Known device IDs associated with this client (from INIT_INFO_MSG)
    device_ids: list = field(default_factory=list)


@dataclass
class PendingWakeup:
    """A CALLING that's waiting for the doorbell to connect."""
    calling_data: bytes = b''
    bridge_term_id: int = 0
    timestamp: float = 0.0
    timeout: float = 30.0  # Max wait time (seconds)


@dataclass
class MtpConnection:
    """Tracks one side of an MTP TCP relay connection."""
    reader: object = None  # asyncio.StreamReader
    writer: object = None  # asyncio.StreamWriter
    addr: tuple = ('', 0)
    term_id: int = 0
    role: str = "unknown"  # "bridge" or "doorbell"
    link_id: int = 0
    bytes_relayed: int = 0


@dataclass
class MtpRelayPair:
    """A paired MTP relay session (bridge <-> doorbell)."""
    link_id: int = 0
    bridge: Optional[MtpConnection] = None
    doorbell: Optional[MtpConnection] = None
    created: float = 0.0
    active: bool = False


@dataclass
class RelayState:
    """Global relay state."""
    clients: dict[int, ClientSession] = field(default_factory=dict)  # term_id -> session
    addr_to_term: dict[tuple, int] = field(default_factory=dict)  # (ip, port) -> term_id
    next_session_id: int = 7640526817926134784  # Match real Mars session IDs
    
    # Session key cache: term_id -> 32-byte session key (client_key XOR server_key)
    session_keys: dict[int, bytes] = field(default_factory=dict)
    # Also index session keys by source address for session-encrypted frame lookup
    addr_session_keys: dict[tuple, bytes] = field(default_factory=dict)
    # Session ID returned in CERTIFY_RESP (addr → 8-byte session_id)
    # INIT_INFO_RESP must use this as its term_id field for routing validation
    addr_session_id: dict[tuple, bytes] = field(default_factory=dict)
    # Track per-client sqnum for prediction (CERTIFY sqnum → INIT_INFO sqnum = +1)
    addr_last_sqnum: dict[tuple, int] = field(default_factory=dict)
    
    # Wakeup infrastructure
    pending_callings: list = field(default_factory=list)  # PendingWakeup queue
    
    # Known device mapping (from captured GDM/INIT_INFO)
    # These are the 64-bit device IDs from the Wyze ecosystem
    known_devices: dict[int, str] = field(default_factory=dict)  # numeric_did -> role
    
    # Chime → doorbell association
    chime_term_id: int = 0  # Term ID of the connected chime
    doorbell_term_id: int = 0  # Term ID of the doorbell (when connected)
    bridge_term_id: int = 0  # Term ID of our bridge
    
    # Keepalive state
    doorbell_addr: tuple = ('', 0)  # Last known (ip, port) of doorbell
    doorbell_last_ack: float = 0.0  # Timestamp of last received keepalive ACK
    keepalive_misses: int = 0  # Consecutive unacknowledged keepalives
    keepalive_enabled: bool = False  # Whether the keepalive loop is active
    
    # Doorbell broadcast discovery
    doorbell_mtp_port: int = 0  # Discovered from LAN broadcast response (type=0x03)
    doorbell_dst_id: int = 0  # Device ID from broadcast response
    
    # MTP relay state
    mtp_link_counter: int = 1  # Incrementing link_id for MTP sessions
    mtp_pairs: dict[int, 'MtpRelayPair'] = field(default_factory=dict)  # link_id -> pair
    mtp_pending_bridges: list = field(default_factory=list)  # MtpConnections waiting for doorbell
    mtp_pending_doorbells: list = field(default_factory=list)  # MtpConnections waiting for bridge
