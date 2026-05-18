#!/usr/bin/env python3
"""Network setup: iptables DNAT and ARP redirect for offline doorbell bridge."""

import os
import socket
import struct
import subprocess
import sys
import time
import fcntl
import signal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from log_config import get_logger
log = get_logger('network')

DOORBELL_IP = os.environ.get("DOORBELL_IP", "")
CHIME_IP = os.environ.get("CHIME_IP", "")
RELAY_IP = os.environ.get("RELAY_IP", "")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "192.168.1.1")
INTERFACE = os.environ.get("NET_INTERFACE", "")

MARS_IPS_FALLBACK = {
    "3.19.80.22", "35.85.21.174", "34.215.36.59", "18.118.90.161",
    "52.201.137.206", "3.13.212.24", "3.131.23.11", "35.81.136.54",
    "54.208.16.245",
}
MARS_PORTS = [28800, 51701, 8443, 8000]

DNAT_CHAIN = "WYZE_DNAT"
DNS_INTERCEPT_PORT = 5354  # NOT 5353 (mDNS) — avahi/homebridge may steal packets
DNS_UPSTREAM = "8.8.8.8"
MARS_HOSTNAME = b"wyze-mars-asrv.wyzecam.com"


def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10)


def detect_relay_ip() -> str:
    """Auto-detect the host's IP on the same subnet as the doorbell."""
    if RELAY_IP:
        return RELAY_IP
    if not DOORBELL_IP:
        return ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((DOORBELL_IP, 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def detect_interface(relay_ip: str) -> str:
    """Find the network interface for the relay IP."""
    if INTERFACE:
        return INTERFACE
    # Try ip command
    try:
        result = run(["ip", "-o", "addr", "show"])
        for line in result.stdout.splitlines():
            if relay_ip in line:
                return line.split()[1]
    except Exception:
        pass
    # Try reading /proc/net/route for default route interface
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.split()
                if parts[1] == "00000000":  # default route
                    return parts[0]
    except Exception:
        pass
    # Try netifaces approach via socket
    try:
        import fcntl
        # Try common interface names
        for name in ["eno1", "eth0", "enp0s3", "wlan0", "en0"]:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", name.encode()))
                s.close()
                return name
            except OSError:
                s.close()
    except Exception:
        pass
    return "eth0"


def detect_gateway() -> str:
    """Detect the default gateway IP."""
    if GATEWAY_IP != "192.168.1.1":
        return GATEWAY_IP
    try:
        result = run(["ip", "route", "show", "default"])
        parts = result.stdout.strip().split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except Exception:
        pass
    return GATEWAY_IP


def resolve_mars_ips() -> set[str]:
    """Resolve Mars server IPs from DNS + fallbacks."""
    ips = set(MARS_IPS_FALLBACK)
    try:
        results = socket.getaddrinfo("wyze-mars-asrv.wyzecam.com", None, socket.AF_INET)
        for r in results:
            ips.add(r[4][0])
    except Exception:
        pass
    return ips


def setup_iptables_dnat(relay_ip: str, mars_ips: set[str], device_ips: list[str]):
    """Create iptables DNAT rules for device(s) → relay."""
    # Clean up old chain
    run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", DNAT_CHAIN])
    run(["iptables", "-t", "nat", "-F", DNAT_CHAIN])
    run(["iptables", "-t", "nat", "-X", DNAT_CHAIN])

    # Create chain
    run(["iptables", "-t", "nat", "-N", DNAT_CHAIN])

    count = 0
    for dev_ip in device_ips:
        for mars_ip in sorted(mars_ips):
            for port in MARS_PORTS:
                result = run([
                    "iptables", "-t", "nat", "-A", DNAT_CHAIN,
                    "-s", dev_ip, "-d", mars_ip,
                    "-p", "udp", "--dport", str(port),
                    "-j", "DNAT", "--to-destination", f"{relay_ip}:{port}",
                ])
                if result.returncode == 0:
                    count += 1

    # Insert into PREROUTING
    run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", DNAT_CHAIN])
    log.info("  iptables: %d DNAT rules for %d device(s), %d Mars IPs", count, len(device_ips), len(mars_ips))
    return count


def disable_icmp_redirects():
    """Prevent the host from sending ICMP redirects to devices."""
    for path in ["/proc/sys/net/ipv4/conf/all/send_redirects",
                 "/proc/sys/net/ipv4/conf/default/send_redirects"]:
        try:
            with open(path, "w") as f:
                f.write("0\n")
        except (PermissionError, FileNotFoundError, OSError):
            pass

    # Also disable for the specific interface
    if INTERFACE:
        path = f"/proc/sys/net/ipv4/conf/{INTERFACE}/send_redirects"
        try:
            with open(path, "w") as f:
                f.write("0\n")
        except (PermissionError, FileNotFoundError, OSError):
            pass

    log.info("  ICMP send_redirects disabled")


def flush_conntrack():
    """Flush connection tracking to force re-evaluation of DNAT rules."""
    result = run(["conntrack", "-F"])
    if result.returncode == 0:
        log.info("  conntrack flushed")
    else:
        # conntrack might not be installed
        log.info("  conntrack flush skipped (not available)")


def enable_ip_forwarding():
    """Enable IP forwarding (required for DNAT)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        log.info("  IP forwarding enabled")
    except (PermissionError, FileNotFoundError, OSError) as e:
        log.warning("  could not enable IP forwarding (%s)", e)
        log.warning("  Ensure host has: sysctl net.ipv4.ip_forward=1")


def get_mac(ifname: str) -> bytes:
    """Get MAC address of interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", ifname[:15].encode()))
    s.close()
    return info[18:24]


def get_target_mac(ip: str) -> bytes:
    """Get target's MAC from ARP cache, or broadcast."""
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    return bytes.fromhex(parts[3].replace(":", ""))
    except Exception:
        pass
    return b"\xff\xff\xff\xff\xff\xff"


def build_arp_reply(src_mac: bytes, src_ip: str, dst_mac: bytes, dst_ip: str) -> bytes:
    """Build an ARP reply packet."""
    eth = dst_mac + src_mac + b"\x08\x06"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    arp += src_mac + socket.inet_aton(src_ip)
    arp += dst_mac + socket.inet_aton(dst_ip)
    return eth + arp


def start_arp_redirect(device_ip: str, gateway_ip: str, iface: str):
    """Fork a child process that continuously sends spoofed ARP replies.

    Tells the device that the gateway is at our MAC address, forcing all
    its traffic through this host where iptables DNAT can intercept it.
    """
    our_mac = get_mac(iface)
    target_mac = get_target_mac(device_ip)

    pid = os.fork()
    if pid > 0:
        mac_str = ":".join(f"{b:02x}" for b in our_mac)
        log.info("  ARP redirect: %s -> %s is at %s (pid=%d)", device_ip, gateway_ip, mac_str, pid)
        return pid

    # Child process — run forever sending ARP replies
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((iface, 0))
        pkt = build_arp_reply(our_mac, gateway_ip, target_mac, device_ip)

        # Fast initially (100ms) to catch boot, then slow down (2s)
        for _ in range(50):
            s.send(pkt)
            time.sleep(0.1)

        while True:
            s.send(pkt)
            time.sleep(2.0)
    except Exception:
        pass
    finally:
        sys.exit(0)


# ---------------------------------------------------------------------------
# DNS interception
# ---------------------------------------------------------------------------

def parse_dns_name(data: bytes, offset: int) -> tuple[bytes, int]:
    """Parse a DNS QNAME from *data* starting at *offset*.

    Returns (dotted-name as bytes, new offset after QNAME).
    Handles label-length encoding (no compression pointers needed for queries).
    """
    labels: list[bytes] = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # compression pointer — follow it (rare in queries but handle it)
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            suffix, _ = parse_dns_name(data, ptr)
            labels.append(suffix)
            offset += 2
            return b".".join(labels), offset
        offset += 1
        labels.append(data[offset:offset + length])
        offset += length
    return b".".join(labels), offset


def build_dns_response(query: bytes, answer_ip: str) -> bytes:
    """Build a minimal DNS A-record response for *query* with *answer_ip*."""
    # Copy header, flip QR bit, set RA, 1 answer
    if len(query) < 12:
        return query
    txn_id = query[:2]
    flags = struct.pack("!H", 0x8180)  # QR=1, RD=1, RA=1, RCODE=0
    qdcount = struct.pack("!H", 1)
    ancount = struct.pack("!H", 1)
    nscount = struct.pack("!H", 0)
    arcount = struct.pack("!H", 0)
    header = txn_id + flags + qdcount + ancount + nscount + arcount

    # Question section — copy from query
    q_start = 12
    q_offset = q_start
    while q_offset < len(query) and query[q_offset] != 0:
        q_offset += 1 + query[q_offset]
    q_offset += 1  # trailing zero
    q_offset += 4  # QTYPE + QCLASS
    question = query[q_start:q_offset]

    # Answer — pointer to name in question (0xC00C), type A, class IN, TTL 60
    answer = struct.pack("!H", 0xC00C)          # name pointer
    answer += struct.pack("!HH", 1, 1)           # type A, class IN
    answer += struct.pack("!I", 60)              # TTL 60s
    answer += struct.pack("!H", 4)               # RDLENGTH
    answer += socket.inet_aton(answer_ip)         # RDATA

    return header + question + answer


def dns_responder_loop(relay_ip: str):
    """Main loop for the DNS responder child process.

    Listens on 0.0.0.0:DNS_INTERCEPT_PORT (UDP).  For queries matching
    the Mars hostname, returns *relay_ip*.  Everything else is proxied
    to DNS_UPSTREAM.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", DNS_INTERCEPT_PORT))
    sock.settimeout(5.0)  # allow periodic signal checks

    mars_lower = MARS_HOSTNAME.lower()

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except OSError:
            break

        if len(data) < 12:
            continue

        # Parse QNAME from question section
        try:
            qname, qname_end = parse_dns_name(data, 12)
        except Exception:
            qname = b""

        qname_lower = qname.lower()

        if qname_lower == mars_lower:
            # Spoof: return our relay IP
            log.info("  DNS intercept: %s -> %s (from %s:%d)", qname.decode(errors='replace'), relay_ip, addr[0], addr[1])
            resp = build_dns_response(data, relay_ip)
            try:
                sock.sendto(resp, addr)
            except OSError:
                pass
        else:
            # Proxy to upstream DNS
            try:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(3.0)
                fwd.sendto(data, (DNS_UPSTREAM, 53))
                resp, _ = fwd.recvfrom(4096)
                fwd.close()
                sock.sendto(resp, addr)
            except Exception:
                pass


def setup_dns_iptables(device_ips: list[str]):
    """Add iptables REDIRECT rules to capture DNS queries from devices."""
    count = 0
    for dev_ip in device_ips:
        # Remove existing rule if present (idempotent)
        run([
            "iptables", "-t", "nat", "-D", "PREROUTING",
            "-s", dev_ip, "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-port", str(DNS_INTERCEPT_PORT),
        ])
        # Add the rule
        result = run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-s", dev_ip, "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-port", str(DNS_INTERCEPT_PORT),
        ])
        if result.returncode == 0:
            count += 1
            log.info("  iptables: DNS REDIRECT %s udp/53 -> localhost:%d", dev_ip, DNS_INTERCEPT_PORT)
        else:
            log.error("  iptables: DNS REDIRECT failed for %s: %s", dev_ip, result.stderr.strip())
    return count


def cleanup_dns_iptables(device_ips: list[str]):
    """Remove DNS REDIRECT rules."""
    for dev_ip in device_ips:
        run([
            "iptables", "-t", "nat", "-D", "PREROUTING",
            "-s", dev_ip, "-p", "udp", "--dport", "53",
            "-j", "REDIRECT", "--to-port", str(DNS_INTERCEPT_PORT),
        ])


def start_dns_intercept(device_ips: list[str], relay_ip: str) -> int:
    """Set up DNS interception: iptables REDIRECT + forked responder.

    Returns the PID of the DNS responder child process.
    """
    # 1. Install iptables REDIRECT rules
    setup_dns_iptables(device_ips)

    # 2. Fork a child to run the DNS responder
    pid = os.fork()
    if pid > 0:
        log.info("  DNS responder listening on :%d (pid=%d)", DNS_INTERCEPT_PORT, pid)
        return pid

    # Child process
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    try:
        dns_responder_loop(relay_ip)
    except Exception:
        pass
    finally:
        sys.exit(0)


def cleanup_on_exit(signum, frame):
    """Clean up iptables rules on SIGTERM/SIGINT."""
    log.info("Cleaning up network rules...")
    # Clean up DNS REDIRECT rules
    device_ips = [DOORBELL_IP]
    if CHIME_IP:
        device_ips.append(CHIME_IP)
    cleanup_dns_iptables(device_ips)
    # Clean up DNAT chain
    run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", DNAT_CHAIN])
    run(["iptables", "-t", "nat", "-F", DNAT_CHAIN])
    run(["iptables", "-t", "nat", "-X", DNAT_CHAIN])
    log.info("Cleanup complete.")
    sys.exit(0)


def main():
    log.info("Starting network configuration...")

    if not DOORBELL_IP:
        log.info("DOORBELL_IP not set. Skipping network setup (relay-only mode).")
        log.info("Set DOORBELL_IP in .env for full offline operation.")
        return

    relay_ip = detect_relay_ip()
    if not relay_ip:
        log.error("Could not detect relay IP. Set RELAY_IP in .env.")
        sys.exit(1)

    gateway_ip = detect_gateway()
    iface = detect_interface(relay_ip)

    log.info("  Relay IP: %s", relay_ip)
    log.info("  Gateway: %s", gateway_ip)
    log.info("  Interface: %s", iface)
    log.info("  Doorbell: %s", DOORBELL_IP)
    if CHIME_IP:
        log.info("  Chime: %s", CHIME_IP)

    # 1. Enable IP forwarding
    enable_ip_forwarding()

    # Build device list
    device_ips = [DOORBELL_IP]
    if CHIME_IP:
        device_ips.append(CHIME_IP)

    # 2. DNS interception (primary mechanism for Mars redirection)
    #    Intercepts ALL DNS queries from the doorbell (even to 8.8.8.8)
    #    and spoofs wyze-mars-asrv.wyzecam.com → relay_ip
    dns_pid = start_dns_intercept(device_ips, relay_ip)

    # 3. Resolve Mars IPs (for DNAT fallback)
    mars_ips = resolve_mars_ips()
    log.info("  Mars IPs: %d resolved", len(mars_ips))

    # 4. Set up iptables DNAT (fallback for already-cached DNS)
    setup_iptables_dnat(relay_ip, mars_ips, device_ips)

    # 5. Disable ICMP redirects
    disable_icmp_redirects()

    # 6. Flush conntrack
    flush_conntrack()

    # 7. Start ARP redirect (needed so traffic routes through us for DNAT)
    arp_pids = []
    for dev_ip in device_ips:
        pid = start_arp_redirect(dev_ip, gateway_ip, iface)
        arp_pids.append(pid)

    child_pids = [dns_pid] + arp_pids
    log.info("Network setup complete. Child pids: %s (dns=%d, arp=%s)", child_pids, dns_pid, arp_pids)
    log.info("Waiting for SIGTERM to clean up...")

    # Keep parent alive so Docker doesn't kill the ARP redirect children
    signal.signal(signal.SIGTERM, cleanup_on_exit)
    signal.signal(signal.SIGINT, cleanup_on_exit)

    # Wait for children
    try:
        while True:
            time.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        cleanup_on_exit(None, None)


if __name__ == "__main__":
    main()
