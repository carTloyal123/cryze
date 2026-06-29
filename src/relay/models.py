"""GUTES relay data models — dataclass definitions for relay state."""

from dataclasses import dataclass, field
from typing import Optional

from device_registry import DeviceRegistry


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
    # Which device MAC this session belongs to (set after CERTIFY identification)
    device_mac: str = ""
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
    device_mac: str = ""   # MAC of the associated camera


@dataclass
class MtpRelayPair:
    """A paired MTP relay session (bridge <-> doorbell)."""
    link_id: int = 0
    bridge: Optional[MtpConnection] = None
    doorbell: Optional[MtpConnection] = None
    created: float = 0.0
    active: bool = False
    device_mac: str = ""   # MAC of the camera this pair belongs to


@dataclass
class RelayState:
    """Global relay state — all per-device fields are keyed by MAC string."""

    # All connected clients, indexed by term_id
    clients: dict[int, ClientSession] = field(default_factory=dict)  # term_id -> ClientSession
    addr_to_term: dict = field(default_factory=dict)       # (ip, port) -> term_id
    next_session_id: int = 7640526817926134784             # Match real Mars session IDs

    # Session key cache
    session_keys: dict = field(default_factory=dict)       # term_id -> 32-byte session key
    addr_session_keys: dict = field(default_factory=dict)  # (ip, port) -> 32-byte session key
    addr_session_id: dict = field(default_factory=dict)    # (ip, port) -> 8-byte session_id
    addr_last_sqnum: dict = field(default_factory=dict)    # (ip, port) -> int

    # ----------------------------------------------------------------
    # Per-device role term IDs  (mac -> term_id)
    # ----------------------------------------------------------------
    chime_term_ids:    dict[str, int] = field(default_factory=dict)  # mac -> term_id
    doorbell_term_ids: dict[str, int] = field(default_factory=dict)  # mac -> term_id
    bridge_term_ids:   dict[str, int] = field(default_factory=dict)  # mac -> term_id

    # ----------------------------------------------------------------
    # Per-device keepalive state  (mac -> value)
    # ----------------------------------------------------------------
    doorbell_addrs:     dict[str, tuple] = field(default_factory=dict)  # mac -> (ip, port)
    doorbell_last_acks: dict[str, float] = field(default_factory=dict)  # mac -> timestamp
    keepalive_misses:   dict[str, int] = field(default_factory=dict)  # mac -> int count
    keepalive_enabled: bool = False  # global flag

    # ----------------------------------------------------------------
    # Per-device broadcast discovery  (mac -> value)
    # ----------------------------------------------------------------
    doorbell_mtp_ports: dict[str, int] = field(default_factory=dict)  # mac -> int
    doorbell_dst_ids:   dict[str, int] = field(default_factory=dict)  # mac -> int

    # ----------------------------------------------------------------
    # Per-device pending CALLING queue  (mac -> list[PendingWakeup])
    # ----------------------------------------------------------------
    pending_callings: dict = field(default_factory=dict)    # mac -> [PendingWakeup]

    # ----------------------------------------------------------------
    # Known device mapping (from captured GDM/INIT_INFO)
    # ----------------------------------------------------------------
    known_devices: dict = field(default_factory=dict)  # numeric_did -> role

    # ----------------------------------------------------------------
    # MTP relay state
    # ----------------------------------------------------------------
    mtp_link_counter: int = 1
    mtp_pairs: dict = field(default_factory=dict)              # link_id -> MtpRelayPair
    # Pending connections keyed by device MAC (mac -> list[MtpConnection])
    mtp_pending_bridges:   dict = field(default_factory=dict)  # mac -> [MtpConnection]
    mtp_pending_doorbells: dict = field(default_factory=dict)  # mac -> [MtpConnection]

    # ----------------------------------------------------------------
    # DeviceRegistry reference (injected at relay startup)
    # ----------------------------------------------------------------
    registry: Optional[DeviceRegistry] = None

    # ----------------------------------------------------------------
    # Convenience helpers
    # ----------------------------------------------------------------

    def get_doorbell_mac_for_bridge(self, bridge_term_id: int) -> str:
        """Return the MAC associated with the bridge that has this term_id."""
        for mac, tid in self.bridge_term_ids.items():
            if tid == bridge_term_id:
                return mac
        # Fall back: check client session
        client = self.clients.get(bridge_term_id)
        return client.device_mac if client else ""

    def get_bridge_mac_for_doorbell(self, doorbell_term_id: int) -> str:
        """Return the MAC associated with the doorbell that has this term_id."""
        for mac, tid in self.doorbell_term_ids.items():
            if tid == doorbell_term_id:
                return mac
        client = self.clients.get(doorbell_term_id)
        return client.device_mac if client else ""
