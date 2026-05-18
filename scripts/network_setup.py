#!/usr/bin/env python3
"""network_setup.py — One-shot network configuration for offline doorbell bridge.

Runs as an init container before the relay starts. Sets up:
  1. iptables DNAT — redirects doorbell's Mars-bound UDP to the local relay
  2. ARP redirect — spoofs the gateway MAC so doorbell routes through us
  3. ICMP redirect disable — prevents host from telling doorbell to bypass us
  4. conntrack flush — clears stale NAT entries

Requires: network_mode=host, cap_add=[NET_ADMIN, NET_RAW]
"""

import os
import socket
import struct
import subprocess
import sys
import time
import fcntl
import signal

# --- Configuration from environment ---

DOORBELL_IP = os.environ.get("DOORBELL_IP", "")
CHIME_IP = os.environ.get("CHIME_IP", "")
RELAY_IP = os.environ.get("RELAY_IP", "")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "192.168.1.1")
INTERFACE = os.environ.get("NET_INTERFACE", "")

# Known Mars IPs (fallback if DNS fails)
MARS_IPS_FALLBACK = {
    "3.19.80.22", "35.85.21.174", "34.215.36.59", "18.118.90.161",
    "52.201.137.206", "3.13.212.24", "3.131.23.11", "35.81.136.54",
    "54.208.16.245",
}
MARS_PORTS = [28800, 51701, 8443, 8000]

DNAT_CHAIN = "WYZE_DNAT"


def log(msg: str):
    print(f"[network-setup] {msg}", flush=True)


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
    log(f"  iptables: {count} DNAT rules for {len(device_ips)} device(s), {len(mars_ips)} Mars IPs")
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

    log("  ICMP send_redirects disabled")


def flush_conntrack():
    """Flush connection tracking to force re-evaluation of DNAT rules."""
    result = run(["conntrack", "-F"])
    if result.returncode == 0:
        log("  conntrack flushed")
    else:
        # conntrack might not be installed
        log("  conntrack flush skipped (not available)")


def enable_ip_forwarding():
    """Enable IP forwarding (required for DNAT)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        log("  IP forwarding enabled")
    except (PermissionError, FileNotFoundError, OSError) as e:
        log(f"  WARNING: could not enable IP forwarding ({e})")
        log(f"  Ensure host has: sysctl net.ipv4.ip_forward=1")


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
        log(f"  ARP redirect: {device_ip} -> {gateway_ip} is at {mac_str} (pid={pid})")
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


def cleanup_on_exit(signum, frame):
    """Clean up iptables rules on SIGTERM/SIGINT."""
    log("Cleaning up network rules...")
    run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", DNAT_CHAIN])
    run(["iptables", "-t", "nat", "-F", DNAT_CHAIN])
    run(["iptables", "-t", "nat", "-X", DNAT_CHAIN])
    log("Cleanup complete.")
    sys.exit(0)


def main():
    log("Starting network configuration...")

    if not DOORBELL_IP:
        log("DOORBELL_IP not set. Skipping network setup (relay-only mode).")
        log("Set DOORBELL_IP in .env for full offline operation.")
        return

    relay_ip = detect_relay_ip()
    if not relay_ip:
        log("ERROR: Could not detect relay IP. Set RELAY_IP in .env.")
        sys.exit(1)

    gateway_ip = detect_gateway()
    iface = detect_interface(relay_ip)

    log(f"  Relay IP: {relay_ip}")
    log(f"  Gateway: {gateway_ip}")
    log(f"  Interface: {iface}")
    log(f"  Doorbell: {DOORBELL_IP}")
    if CHIME_IP:
        log(f"  Chime: {CHIME_IP}")

    # 1. Enable IP forwarding
    enable_ip_forwarding()

    # 2. Resolve Mars IPs
    mars_ips = resolve_mars_ips()
    log(f"  Mars IPs: {len(mars_ips)} resolved")

    # 3. Set up iptables DNAT
    device_ips = [DOORBELL_IP]
    if CHIME_IP:
        device_ips.append(CHIME_IP)
    setup_iptables_dnat(relay_ip, mars_ips, device_ips)

    # 4. Disable ICMP redirects
    disable_icmp_redirects()

    # 5. Flush conntrack
    flush_conntrack()

    # 6. Start ARP redirect (stays running as child process)
    arp_pids = []
    for dev_ip in device_ips:
        pid = start_arp_redirect(dev_ip, gateway_ip, iface)
        arp_pids.append(pid)

    log(f"Network setup complete. ARP redirect pids: {arp_pids}")
    log("Waiting for SIGTERM to clean up...")

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
