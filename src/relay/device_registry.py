"""Device registry — enumerate, discover, and track all GWELL cameras."""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from log_config import get_logger
log = get_logger('relay.registry')

# ---------------------------------------------------------------------------
# Wyze API constants (matching wyze_auth.cpp)
# ---------------------------------------------------------------------------
_AUTH_BASE    = "https://auth-prod.api.wyze.com"
_APP_BASE     = "https://app.wyzecam.com"
_PATH_LOGIN   = "/api/user/login"
_PATH_DEVICES = "/app/v2/home_page/get_object_list"

_APP_NAME    = "com.hualai"
_APP_VER     = "com.hualai___3.13.0.784"
_APP_VERSION = "3.13.0.784"
_PHONE_SYS   = "1"
_USER_AGENT  = "wyze_android_3.13.0"
_SC          = "9f275790cab94a72bd206c8876429f3c"
_SV_DEVICES  = "c86fa16fc99d4d6580f4efeae8b4b13c"

_REGISTRY_TTL = 3600  # seconds before re-fetching from API (1 hour)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """One GWELL camera on the Wyze account."""
    mac: str          # Canonical uppercase: "AA:BB:CC:DD:EE:FF"
    name: str         # Human name: "Front Door"
    model: str        # Product model: "GW_GC2"
    cloud_ip: str     # IP from Wyze API response (may be stale)
    lan_ip: str = ""  # Discovered via broadcast or ARP
    mtp_port: int = 0 # Discovered MTP port from broadcast frame offset 0x2C
    dst_id: int = 0   # 64-bit numeric ID from broadcast frame offset 0x1C
    stream_name: str = ""  # "camera_aabbccddeeff" — set at creation
    raw_port: int = 0
    overlay_port: int = 0

    @property
    def mac_clean(self) -> str:
        """MAC without colons, lowercase: 'aabbccddeeff'"""
        return self.mac.replace(':', '').lower()

    def to_dict(self) -> dict:
        return {
            'mac': self.mac,
            'name': self.name,
            'model': self.model,
            'cloud_ip': self.cloud_ip,
            'lan_ip': self.lan_ip,
            'mtp_port': self.mtp_port,
            'dst_id': self.dst_id,
            'stream_name': self.stream_name,
            'raw_port': self.raw_port,
            'overlay_port': self.overlay_port,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'DeviceInfo':
        return cls(
            mac=d['mac'], name=d.get('name', ''), model=d.get('model', ''),
            cloud_ip=d.get('cloud_ip', ''), lan_ip=d.get('lan_ip', ''),
            mtp_port=d.get('mtp_port', 0), dst_id=d.get('dst_id', 0),
            stream_name=d.get('stream_name', ''),
            raw_port=d.get('raw_port', 0), overlay_port=d.get('overlay_port', 0),
        )


@dataclass
class DeviceMetrics:
    """Live metrics for one camera device."""
    mac: str
    battery_pct:  Optional[int]   = None
    signal_dbm:   Optional[int]   = None
    bitrate_kbps: Optional[int]   = None
    fps:          Optional[float] = None
    resolution:   Optional[str]   = None
    updated_at:   float           = 0.0

    def render_text(self) -> str:
        parts = []
        if self.battery_pct is not None:
            parts.append(f"Batt: {self.battery_pct}%")
        if self.bitrate_kbps is not None:
            kbps = self.bitrate_kbps
            parts.append(f"{kbps/1000:.1f} Mbps" if kbps >= 1000 else f"{kbps} kbps")
        if self.fps is not None:
            parts.append(f"{self.fps:.0f} fps")
        if self.signal_dbm is not None:
            parts.append(f"Sig: {self.signal_dbm} dBm")
        return "  ".join(parts)


class DeviceRegistry:
    """Single source of truth for all enrolled cameras.

    Provides O(1) lookups by MAC, LAN IP, and broadcast dst_id.
    Thread-safe for read access; writes use update_discovery() which is
    called from a single thread (broadcast listener).
    """

    def __init__(self, devices: list[DeviceInfo]):
        self.devices: list[DeviceInfo] = devices
        self._by_mac:    dict[str, DeviceInfo] = {}
        self._by_lan_ip: dict[str, DeviceInfo] = {}
        self._by_dst_id: dict[int, DeviceInfo] = {}
        for d in devices:
            self._by_mac[d.mac.upper()] = d
            if d.lan_ip:
                self._by_lan_ip[d.lan_ip] = d
            if d.dst_id:
                self._by_dst_id[d.dst_id] = d

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_wyze_api(cls, email: str, password: str, key_id: str, api_key: str,
                      filter_macs: Optional[list] = None) -> 'DeviceRegistry':
        """Authenticate with Wyze and enumerate all GW_* cameras.

        Args:
            filter_macs: If not None, only include these MACs (uppercase).
                         None = enroll all GW_* cameras.
        """
        import uuid as _uuid

        phone_id = str(_uuid.uuid4())

        def _md5(s: str) -> str:
            return hashlib.md5(s.encode()).hexdigest()

        def _scramble(pw: str) -> str:
            return _md5(_md5(_md5(pw)))

        now_ms = int(time.time() * 1000)

        def _post(url: str, body: dict, headers: dict) -> dict:
            data = json.dumps(body).encode()
            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', _USER_AGENT)
            for k, v in headers.items():
                req.add_header(k, v)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                body_text = e.read().decode('utf-8', errors='replace')
                raise RuntimeError(f"HTTP {e.code} from {url}: {body_text[:300]}")

        # 1. Login
        log.info("Authenticating with Wyze API as %s...", email)
        login_resp = _post(
            _AUTH_BASE + _PATH_LOGIN,
            {
                'email':    email,
                'password': _scramble(password),
                'nonce':    str(now_ms),
            },
            {'keyid': key_id, 'apikey': api_key,
             'phone-id': phone_id, 'requestid': _md5(str(now_ms))},
        )
        access_token = login_resp.get('access_token', '')
        if not access_token:
            raise RuntimeError(f"Login failed — no access_token: {login_resp}")
        log.info("Wyze login OK, user_id=%s", login_resp.get('user_id', '?'))

        # 2. Get device list
        dev_resp = _post(
            _APP_BASE + _PATH_DEVICES,
            {
                'access_token':    access_token,
                'app_name':        _APP_NAME,
                'app_ver':         _APP_VER,
                'app_version':     _APP_VERSION,
                'phone_id':        phone_id,
                'phone_system_type': _PHONE_SYS,
                'sc':              _SC,
                'sv':              _SV_DEVICES,
                'ts':              now_ms,
            },
            {'phone-id': phone_id, 'requestid': _md5(str(now_ms + 1))},
        )

        raw_list = dev_resp.get('data', {}).get('device_list', [])
        devices = []
        raw_port_base     = int(os.environ.get("RAW_PORT_BASE",     "18000"))
        overlay_port_base = int(os.environ.get("OVERLAY_PORT_BASE", "19000"))
        initial_metrics: list[tuple['DeviceInfo', int]] = []  # (info, battery_pct)
        for dev in raw_list:
            model = dev.get('product_model', '')
            ptype = dev.get('product_type', '')
            mac   = dev.get('mac', '').upper()
            if ptype != 'Camera' or not model.startswith('GW_'):
                continue
            if filter_macs is not None and mac not in filter_macs:
                continue
            mac_clean = mac.replace(':', '').lower()
            index = len(devices)
            info = DeviceInfo(
                mac=mac,
                name=dev.get('nickname', dev.get('product_model', mac)),
                model=model,
                cloud_ip=dev.get('ip', ''),
                stream_name=f'camera_{mac_clean}',
            )
            info.raw_port     = raw_port_base + index
            info.overlay_port = overlay_port_base + index

            # Extract battery from API response:
            #   device_params.electricity  (integer 0-100)  — most GW_ cameras
            #   property_list[pid=P5]      (string "0"-"100") — older firmware
            battery_pct = None
            dp = dev.get('device_params', {})
            if isinstance(dp, dict):
                elec = dp.get('electricity')
                if elec is not None:
                    try:
                        battery_pct = int(elec)
                    except (ValueError, TypeError):
                        pass
            if battery_pct is None:
                for prop in dev.get('property_list', []):
                    if prop.get('pid') == 'P5':
                        try:
                            battery_pct = int(prop.get('value', ''))
                        except (ValueError, TypeError):
                            pass
                        break
            if battery_pct is not None:
                log.info("  Found camera: %s (%s) model=%s battery=%d%%",
                         info.name, info.mac, info.model, battery_pct)
                initial_metrics.append((info, battery_pct))
            else:
                dp_keys = list(dp.keys()) if isinstance(dp, dict) else []
                log.info("  Found camera: %s (%s) model=%s (no battery in API — device_params keys: %s)",
                         info.name, info.mac, info.model, dp_keys)
            devices.append(info)

        if not devices:
            raise RuntimeError(
                "No GW_* cameras found on account"
                + (f" matching filter {filter_macs}" if filter_macs else ""))

        log.info("Enumerated %d camera(s) from Wyze API", len(devices))
        registry = cls(devices)

        # Write initial battery metrics so the overlay has data before any stream starts.
        for info, battery_pct in initial_metrics:
            m = DeviceMetrics(mac=info.mac, battery_pct=battery_pct, updated_at=time.time())
            try:
                registry.write_metrics(info.mac, m)
                log.info("  Wrote initial metrics for %s: %s", info.mac, m.render_text())
            except Exception as e:
                log.warning("  Could not write metrics for %s: %s", info.mac, e)

        return registry

    @classmethod
    def from_cache(cls, cache_path: Path) -> Optional['DeviceRegistry']:
        """Load from JSON cache. Returns None if missing, corrupt, or expired."""
        try:
            data = json.loads(cache_path.read_text())
            saved_at = data.get('saved_at', 0)
            if time.time() - saved_at > _REGISTRY_TTL:
                log.info("Device registry cache expired (age=%.0fs)", time.time() - saved_at)
                return None
            devices = [DeviceInfo.from_dict(d) for d in data.get('devices', [])]
            if not devices:
                return None
            log.info("Loaded device registry from cache (%d devices)", len(devices))
            return cls(devices)
        except (FileNotFoundError, KeyError, json.JSONDecodeError):
            return None

    def save_cache(self, cache_path: Path) -> None:
        """Serialize to JSON cache file."""
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'saved_at': time.time(),
            'devices':  [d.to_dict() for d in self.devices],
        }
        cache_path.write_text(json.dumps(data, indent=2))
        log.info("Device registry saved to %s", cache_path)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_by_mac(self, mac: str) -> Optional[DeviceInfo]:
        """Lookup by MAC (case-insensitive, colon-insensitive)."""
        normalized = mac.upper().replace('-', ':')
        # Handle no-colon form
        if ':' not in normalized and len(normalized) == 12:
            normalized = ':'.join(normalized[i:i+2] for i in range(0, 12, 2))
        return self._by_mac.get(normalized)

    def get_by_lan_ip(self, ip: str) -> Optional[DeviceInfo]:
        """Lookup by LAN IP. Returns None if IP not yet discovered."""
        return self._by_lan_ip.get(ip)

    def get_by_dst_id(self, dst_id: int) -> Optional[DeviceInfo]:
        """Lookup by 64-bit broadcast dst_id."""
        return self._by_dst_id.get(dst_id)

    def is_doorbell_ip(self, ip: str) -> bool:
        """True if ip matches any DeviceInfo.lan_ip."""
        return ip in self._by_lan_ip

    def all_lan_ips(self) -> list:
        """Return list of all discovered LAN IPs."""
        return list(self._by_lan_ip.keys())

    # ------------------------------------------------------------------
    # Discovery update
    # ------------------------------------------------------------------

    def update_discovery(self, mac: str, lan_ip: str,
                         mtp_port: int, dst_id: int) -> None:
        """Update a device with discovered LAN network info.

        Called by broadcast_listen() when a doorbell announces itself.
        Also called by the LAN discovery probe in entrypoint.py.
        Thread-safe for dict updates on CPython (GIL).
        """
        info = self.get_by_mac(mac)
        if info is None:
            log.warning("update_discovery: unknown MAC %s (ip=%s)", mac, lan_ip)
            return

        changed = (info.lan_ip != lan_ip or info.mtp_port != mtp_port
                   or info.dst_id != dst_id)
        if changed:
            # Remove old LAN-IP index if IP changed
            if info.lan_ip and info.lan_ip != lan_ip:
                self._by_lan_ip.pop(info.lan_ip, None)
            if info.dst_id and info.dst_id != dst_id:
                self._by_dst_id.pop(info.dst_id, None)

            info.lan_ip   = lan_ip
            info.mtp_port = mtp_port
            info.dst_id   = dst_id

            self._by_lan_ip[lan_ip] = info
            if dst_id:
                self._by_dst_id[dst_id] = info
            log.info("Registry updated: %s (%s) → %s mtp=%d dst_id=%d",
                     info.name, info.mac, lan_ip, mtp_port, dst_id)

    # ------------------------------------------------------------------
    # Metrics helpers
    # ------------------------------------------------------------------

    def write_metrics(self, mac: str, metrics) -> None:
        info = self.get_by_mac(mac)
        if not info: return
        mc   = info.mac_clean
        base = Path("/cache")
        base.mkdir(parents=True, exist_ok=True)
        tmp_j = base / f"metrics_{mc}.json.tmp"
        tmp_j.write_text(json.dumps(asdict(metrics), indent=2))
        tmp_j.rename(base / f"metrics_{mc}.json")
        tmp_t = base / f"metrics_{mc}.txt.tmp"
        tmp_t.write_text(metrics.render_text())
        tmp_t.rename(base / f"metrics_{mc}.txt")

    def read_metrics(self, mac: str):
        info = self.get_by_mac(mac)
        if not info: return None
        try:
            d = json.loads(Path(f"/cache/metrics_{info.mac_clean}.json").read_text())
            return DeviceMetrics(
                mac=d.get('mac', mac), battery_pct=d.get('battery_pct'),
                signal_dbm=d.get('signal_dbm'), bitrate_kbps=d.get('bitrate_kbps'),
                fps=d.get('fps'), resolution=d.get('resolution'),
                updated_at=d.get('updated_at', 0.0))
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None

    # ------------------------------------------------------------------
    # Cryptographic helpers for bridge identification
    # ------------------------------------------------------------------

    def get_certify_key(self, mac: str) -> Optional[bytes]:
        """Load mars_access_token from cache/auth_{mac_clean}.json.

        Returns the 16-byte certify key (token_bytes[0x30:0x40]) or None
        if the cache file hasn't been written yet (bridge not authenticated).
        """
        info = self.get_by_mac(mac)
        if info is None:
            return None

        # Try MAC-specific auth cache (written by run_bridge.sh / wyze_auth.cpp)
        mac_clean = info.mac_clean
        candidate_paths = [
            f"/cache/auth_{mac_clean}.json",
            f"/work/cache/auth_{mac_clean}.json",
            f"cache/auth_{mac_clean}.json",
        ]
        for path in candidate_paths:
            try:
                auth = json.loads(Path(path).read_text())
                token = auth.get('mars_access_token', '')
                if not token:
                    continue
                # Decode token bytes
                try:
                    token_bytes = bytes.fromhex(token[:128])
                except (ValueError, IndexError):
                    try:
                        token_bytes = base64.b64decode(token)
                    except Exception:
                        continue
                if len(token_bytes) >= 0x40:
                    return token_bytes[0x30:0x40]
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                continue
        return None

    def identify_bridge_mac(self, certify_req_data: bytes) -> Optional[str]:
        """Identify which device MAC this CERTIFY_REQ belongs to.

        Tries each device's certify_key against the CERTIFY payload.
        Returns the MAC of the device whose key successfully decrypts
        the payload (non-zero, non-repeating result), or None.

        The payload structure (after per-frame decryption):
          [0:8]   session_id
          [8:40]  RC5-encrypted client key (16-byte RC5, certify_key)
        """
        if len(certify_req_data) < 0x18 + 40:
            return None

        # Import locally to avoid circular imports
        try:
            from rc5 import RC5, derive_per_frame_key
        except ImportError:
            return None

        opt_flags = struct.unpack_from('<I', certify_req_data, 0x14)[0]
        encrypt_mode = (opt_flags >> 16) & 3
        payload = certify_req_data[0x18:]

        # Decrypt payload if per-frame encrypted (encrypt_mode == 1)
        if encrypt_mode == 1:
            try:
                pfk = derive_per_frame_key(certify_req_data[:0x18])
                rc5_pf = RC5(block_bytes=8, rounds=6).setkey(pfk)
                dec_len = (len(payload) // 8) * 8
                if dec_len >= 40:
                    payload = rc5_pf.decrypt(bytes(payload[:dec_len]))
            except Exception:
                return None

        if len(payload) < 40:
            return None

        encrypted_client_key = payload[8:40]

        for device in self.devices:
            certify_key = self.get_certify_key(device.mac)
            if certify_key is None or len(certify_key) < 16:
                continue
            try:
                rc5 = RC5(block_bytes=16, rounds=6).setkey(certify_key)
                block1 = rc5.decrypt_block(bytes(encrypted_client_key[0:16]))
                block2 = rc5.decrypt_block(bytes(encrypted_client_key[16:32]))
                client_key = block1 + block2
                # Reject all-zero or simple repeating-8-byte-pattern keys
                # (characteristic of wrong-key decryption)
                if client_key == bytes(32):
                    continue
                if client_key[:8] == client_key[8:16] == client_key[16:24]:
                    continue
                log.info("Identified bridge MAC=%s from CERTIFY payload", device.mac)
                return device.mac
            except Exception:
                continue

        return None

    def __repr__(self) -> str:
        return (f"DeviceRegistry({len(self.devices)} devices: "
                f"{[d.mac for d in self.devices]})")


