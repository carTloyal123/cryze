#!/usr/bin/env python3
"""Mars Relay Probe — capture real DETECT_RESP and LIST_RESP from Wyze Mars servers.

Sends real protocol frames to Mars relay servers and logs the exact byte-level
responses. Used to validate our local relay's response format against the real thing.

Usage:
  python3 scripts/mars_probe.py                          # Probe default Mars server
  python3 scripts/mars_probe.py --server 3.13.212.24     # Probe specific server
  python3 scripts/mars_probe.py --resolve                # Resolve DNS first
  python3 scripts/mars_probe.py --compare                # Compare with our relay builder

Outputs byte-level comparison of real Mars responses vs our locally-built responses.
"""

import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from rc5 import RC5, GWELL_KEY, derive_per_frame_key, id_encrypt, id_decrypt


# --- Constants ---
HEADER_SIZE = 0x1C
TYPE_DETECT_REQ = 0x01
TYPE_DETECT_RESP = 0x02
TYPE_LIST_REQ = 0x15
TYPE_LIST_RESP = 0x16

KNOWN_MARS_SERVERS = [
    "3.13.212.24",      # From relay.log upstream
    "3.131.23.11",      # From gutes_proxy.py default
]

RELAY_PORTS = [28800, 8443, 8000]
LIST_PORT = 51701


def hexdump(data: bytes, prefix: str = "", width: int = 16) -> str:
    """Pretty hex dump with ASCII."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{i:04x}: {hex_part:<{width*3}}  {ascii_part}")
    return '\n'.join(lines)


def build_detect_req(term_id: int = 0x38B8DA1234567890) -> bytes:
    """Build a DETECT_REQ frame matching SDK format."""
    # DETECT_REQ is 0x24 bytes (36 bytes) based on SDK analysis
    req = bytearray(0x24)
    req[0] = 0x7F  # protocol = relay
    req[1] = TYPE_DETECT_REQ  # type
    struct.pack_into('<H', req, 2, 0x24)  # frm_len = 36

    # Generate sqnum and chkval
    sqnum = int(time.time()) & 0xFFFFFFFF
    chkval = (sqnum ^ 0xDEADBEEF) & 0xFFFFFFFF

    struct.pack_into('<I', req, 0x0C, sqnum)
    struct.pack_into('<I', req, 0x10, chkval)

    # Encrypt term_id
    term_bytes = struct.pack('<q', term_id)
    sqnum_bytes = struct.pack('<I', sqnum)
    chkval_bytes = struct.pack('<I', chkval)
    encrypted_id = id_encrypt(term_bytes, chkval_bytes, sqnum_bytes)
    req[4:12] = encrypted_id

    # opt_flags: QoS=1 (need ack), nonce=random
    import random
    nonce = random.randint(0, 0x7FFF)
    opt_flags = (nonce << 1) | (1 << 18)  # QoS=1
    struct.pack_into('<I', req, 0x14, opt_flags)

    # flags2 and ack_result
    struct.pack_into('<H', req, 0x18, 0x0000)
    struct.pack_into('<H', req, 0x1A, 0x0000)

    # Payload: 8 bytes (0x24 - 0x1C = 8)
    # From SDK: detect_req payload contains timestamp or zeros
    now = int(time.time())
    struct.pack_into('<I', req, 0x1C, now)
    struct.pack_into('<I', req, 0x20, 0)

    return bytes(req)


def build_list_req(term_id: int = 0x38B8DA1234567890) -> bytes:
    """Build a LIST_REQ frame matching SDK format."""
    # LIST_REQ is 0x28 bytes (40 bytes) based on relay.log: "(40B)"
    req = bytearray(0x28)
    req[0] = 0x7F
    req[1] = TYPE_LIST_REQ
    struct.pack_into('<H', req, 2, 0x28)  # frm_len = 40

    sqnum = int(time.time()) & 0xFFFFFFFF
    chkval = (sqnum ^ 0xCAFEBABE) & 0xFFFFFFFF

    struct.pack_into('<I', req, 0x0C, sqnum)
    struct.pack_into('<I', req, 0x10, chkval)

    # Encrypt term_id
    term_bytes = struct.pack('<q', term_id)
    sqnum_bytes = struct.pack('<I', sqnum)
    chkval_bytes = struct.pack('<I', chkval)
    encrypted_id = id_encrypt(term_bytes, chkval_bytes, sqnum_bytes)
    req[4:12] = encrypted_id

    # opt_flags: per-frame encrypt (encrypt=1), QoS=1
    import random
    nonce = random.randint(0, 0x7FFF)
    opt_flags = (nonce << 1) | (1 << 16) | (1 << 18)  # encrypt=1, QoS=1
    struct.pack_into('<I', req, 0x14, opt_flags)

    struct.pack_into('<H', req, 0x18, 0x0000)
    struct.pack_into('<H', req, 0x1A, 0x0000)

    # Payload: 12 bytes
    # From SDK: list_req contains some session/version info
    struct.pack_into('<I', req, 0x1C, int(time.time()))
    struct.pack_into('<I', req, 0x20, 0)
    struct.pack_into('<I', req, 0x24, 0)

    return bytes(req)


def decode_opt_flags(opt: int) -> dict:
    """Decode opt_flags bitfield into human-readable dict."""
    return {
        'compressed': bool(opt & 1),
        'nonce': (opt >> 1) & 0x7FFF,
        'opt_encrypt': (opt >> 16) & 3,
        'qos': (opt >> 18) & 3,
        'is_ack': bool((opt >> 20) & 1),
        'is_response': bool((opt >> 21) & 1),
        'signature': bool((opt >> 22) & 1),
        'ntp_appended': bool((opt >> 24) & 1),
        'relay_flag': bool((opt >> 25) & 1),
        'raw': f'0x{opt:08x}',
    }


def parse_response_header(data: bytes) -> dict:
    """Parse a GUTES frame header into a dict."""
    if len(data) < HEADER_SIZE:
        return {'error': f'too short ({len(data)} bytes)'}

    protocol = data[0]
    ftype = data[1]
    frm_len = struct.unpack_from('<H', data, 2)[0]
    sqnum = struct.unpack_from('<I', data, 0x0C)[0]
    chkval = struct.unpack_from('<I', data, 0x10)[0]
    opt_flags = struct.unpack_from('<I', data, 0x14)[0]
    flags2 = struct.unpack_from('<H', data, 0x18)[0]
    ack_result = struct.unpack_from('<H', data, 0x1A)[0]

    # Decrypt term_id
    try:
        encrypted_id = data[4:12]
        sqnum_bytes = struct.pack('<I', sqnum)
        chkval_bytes = struct.pack('<I', chkval)
        id_bytes = id_decrypt(encrypted_id, chkval_bytes, sqnum_bytes)
        term_id = struct.unpack_from('<q', id_bytes)[0]
    except:
        term_id = 0

    return {
        'protocol': f'0x{protocol:02x}',
        'type': f'0x{ftype:02x}',
        'frm_len': frm_len,
        'term_id': term_id,
        'sqnum': sqnum,
        'chkval': chkval,
        'opt_flags': decode_opt_flags(opt_flags),
        'flags2': f'0x{flags2:04x}',
        'ack_result': f'0x{ack_result:04x}',
        'payload_len': frm_len - HEADER_SIZE if frm_len > HEADER_SIZE else 0,
    }


def probe_detect(server_ip: str, port: int, timeout: float = 3.0) -> dict:
    """Send DETECT_REQ to a Mars server and capture the response."""
    term_id = int(time.time() * 1000) & 0x7FFFFFFFFFFFFFFF
    req = build_detect_req(term_id)

    result = {
        'server': f'{server_ip}:{port}',
        'term_id_sent': term_id,
        'req_size': len(req),
        'req_hex': req.hex(),
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        t0 = time.time()
        sock.sendto(req, (server_ip, port))
        data, addr = sock.recvfrom(4096)
        rtt_ms = (time.time() - t0) * 1000

        result['rtt_ms'] = round(rtt_ms, 2)
        result['resp_size'] = len(data)
        result['resp_hex'] = data.hex()
        result['resp_from'] = f'{addr[0]}:{addr[1]}'
        result['header'] = parse_response_header(data)

        # Parse payload
        if len(data) > HEADER_SIZE:
            payload = data[HEADER_SIZE:]
            result['payload_hex'] = payload.hex()

            # For DETECT_RESP, payload is typically unencrypted
            if data[1] == TYPE_DETECT_RESP:
                result['payload_parsed'] = parse_detect_payload(payload)

    except socket.timeout:
        result['error'] = 'timeout'
    except Exception as e:
        result['error'] = str(e)
    finally:
        sock.close()

    return result


def parse_detect_payload(payload: bytes) -> dict:
    """Parse DETECT_RESP payload fields."""
    parsed = {}
    if len(payload) >= 4:
        parsed['field_00'] = struct.unpack_from('<I', payload, 0)[0]
        parsed['field_00_desc'] = 'NTP time or timestamp'
    if len(payload) >= 8:
        parsed['field_04'] = struct.unpack_from('<I', payload, 4)[0]
    if len(payload) >= 12:
        b = payload[8:12]
        parsed['field_08'] = f'{b[0]:02x} {b[1]:02x} {b[2]:02x} {b[3]:02x}'
        parsed['field_08_desc'] = 'MTU info'
    if len(payload) >= 16:
        parsed['field_0c'] = struct.unpack_from('<I', payload, 12)[0]
    if len(payload) >= 20:
        parsed['field_10'] = struct.unpack_from('<I', payload, 16)[0]
    if len(payload) >= 24:
        parsed['field_14'] = struct.unpack_from('<I', payload, 20)[0]
        parsed['field_14_desc'] = 'uptime/random'
    if len(payload) >= 28:
        parsed['field_18'] = struct.unpack_from('<I', payload, 24)[0]
        parsed['field_18_desc'] = 'server load'
    return parsed


def probe_list(server_ip: str, port: int = 51701, timeout: float = 3.0) -> dict:
    """Send LIST_REQ to Mars list port and capture response."""
    term_id = int(time.time() * 1000) & 0x7FFFFFFFFFFFFFFF
    req = build_list_req(term_id)

    result = {
        'server': f'{server_ip}:{port}',
        'term_id_sent': term_id,
        'req_size': len(req),
        'req_hex': req.hex(),
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        t0 = time.time()
        sock.sendto(req, (server_ip, port))
        data, addr = sock.recvfrom(4096)
        rtt_ms = (time.time() - t0) * 1000

        result['rtt_ms'] = round(rtt_ms, 2)
        result['resp_size'] = len(data)
        result['resp_hex'] = data.hex()
        result['resp_from'] = f'{addr[0]}:{addr[1]}'
        result['header'] = parse_response_header(data)

        # Try to decrypt payload (per-frame key)
        if len(data) > HEADER_SIZE:
            payload = data[HEADER_SIZE:]
            result['payload_hex_encrypted'] = payload.hex()

            try:
                pfk = derive_per_frame_key(data[:0x18])
                rc5 = RC5(block_bytes=8, rounds=6).setkey(pfk)
                dec_len = (len(payload) // 8) * 8
                if dec_len > 0:
                    decrypted = rc5.decrypt(payload[:dec_len])
                    result['payload_hex_decrypted'] = decrypted.hex()
                    result['payload_decrypted_parsed'] = parse_list_payload(decrypted)
            except Exception as e:
                result['decrypt_error'] = str(e)

    except socket.timeout:
        result['error'] = 'timeout'
    except Exception as e:
        result['error'] = str(e)
    finally:
        sock.close()

    return result


def parse_list_payload(payload: bytes) -> dict:
    """Try to parse decrypted LIST_RESP payload for server entries."""
    parsed = {'raw_preview': payload[:64].hex()}

    # Scan for IPv4 addresses that look like public IPs
    servers = []
    for offset in range(0, len(payload) - 5, 2):
        ip_bytes = payload[offset:offset+4]
        # Check if it looks like a public IP
        if (ip_bytes[0] not in (0, 10, 127, 192, 172, 255) and
            ip_bytes != b'\x00\x00\x00\x00' and
            1 <= ip_bytes[0] <= 223):
            # Check if next 2 bytes are a valid port
            if offset + 5 < len(payload):
                port = struct.unpack_from('<H', payload, offset + 4)[0]
                if port in (28800, 8443, 8000, 443, 51701, 80):
                    ip = f'{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}'
                    servers.append({
                        'offset': f'0x{offset:04x}',
                        'ip': ip,
                        'port': port,
                    })
                    # Check for srv_id after port
                    if offset + 7 < len(payload):
                        srv_id = struct.unpack_from('<H', payload, offset + 6)[0]
                        servers[-1]['srv_id'] = srv_id

    parsed['detected_servers'] = servers
    return parsed


def compare_detect_resp(real_resp: bytes, our_builder_resp: bytes) -> list:
    """Compare real Mars DETECT_RESP with our locally-built one."""
    diffs = []
    max_len = max(len(real_resp), len(our_builder_resp))

    # Header field comparison
    field_map = [
        (0, 1, 'protocol'),
        (1, 1, 'type'),
        (2, 2, 'frm_len'),
        (4, 8, 'term_id (encrypted)'),
        (0x0C, 4, 'sqnum'),
        (0x10, 4, 'chkval'),
        (0x14, 4, 'opt_flags'),
        (0x18, 2, 'flags2'),
        (0x1A, 2, 'ack_result'),
    ]

    for offset, size, name in field_map:
        if offset + size <= len(real_resp) and offset + size <= len(our_builder_resp):
            real_val = real_resp[offset:offset+size]
            our_val = our_builder_resp[offset:offset+size]
            if real_val != our_val:
                diffs.append({
                    'field': name,
                    'offset': f'0x{offset:02x}',
                    'real': real_val.hex(),
                    'ours': our_val.hex(),
                    'match': False,
                })
            else:
                diffs.append({
                    'field': name,
                    'offset': f'0x{offset:02x}',
                    'value': real_val.hex(),
                    'match': True,
                })

    # Payload comparison
    if len(real_resp) > HEADER_SIZE and len(our_builder_resp) > HEADER_SIZE:
        real_payload = real_resp[HEADER_SIZE:]
        our_payload = our_builder_resp[HEADER_SIZE:]
        for i in range(min(len(real_payload), len(our_payload))):
            if real_payload[i] != our_payload[i]:
                diffs.append({
                    'field': f'payload[{i}]',
                    'offset': f'0x{HEADER_SIZE + i:02x}',
                    'real': f'0x{real_payload[i]:02x}',
                    'ours': f'0x{our_payload[i]:02x}',
                    'match': False,
                })

    return diffs


def build_our_detect_resp(req_data: bytes) -> bytes:
    """Build DETECT_RESP using our relay's builder logic (copied from gutes_relay.py)."""
    resp = bytearray(0x38)  # 56 bytes
    resp[0] = 0x7F
    resp[1] = TYPE_DETECT_RESP
    struct.pack_into('<H', resp, 2, 0x38)

    resp[4:12] = req_data[4:12]
    resp[0x0C:0x10] = req_data[0x0C:0x10]
    resp[0x10:0x14] = req_data[0x10:0x14]

    struct.pack_into('<I', resp, 0x14, 0x0000a6d0)
    struct.pack_into('<H', resp, 0x18, 0x0001)
    struct.pack_into('<H', resp, 0x1A, 0x0000)

    now = int(time.time())
    struct.pack_into('<I', resp, 0x1C, now)
    struct.pack_into('<I', resp, 0x20, 0)
    resp[0x24] = 0x5A
    resp[0x25] = 0x00
    resp[0x26] = 0x58
    resp[0x27] = 0x00
    struct.pack_into('<I', resp, 0x28, now)
    struct.pack_into('<I', resp, 0x2C, 0)
    struct.pack_into('<I', resp, 0x30, int(time.time()) & 0x7FFFFFFF)
    struct.pack_into('<I', resp, 0x34, 1)

    return bytes(resp)


def resolve_mars_dns() -> list:
    """Resolve wyze-mars-asrv.wyzecam.com to get current server IPs."""
    try:
        results = socket.getaddrinfo("wyze-mars-asrv.wyzecam.com", None, socket.AF_INET)
        ips = list(set(r[4][0] for r in results))
        return ips
    except Exception as e:
        print(f"DNS resolution failed: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Mars Relay Probe")
    parser.add_argument('--server', default=None, help='Mars server IP (default: resolve DNS)')
    parser.add_argument('--resolve', action='store_true', help='Resolve Mars DNS and probe all')
    parser.add_argument('--compare', action='store_true', help='Compare real vs our DETECT_RESP')
    parser.add_argument('--ports', default='28800,8443,8000',
                       help='Ports to probe (default: 28800,8443,8000)')
    parser.add_argument('--list-port', type=int, default=51701, help='List port')
    parser.add_argument('--timeout', type=float, default=3.0, help='Timeout in seconds')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--save', default=None, help='Save results to file')
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(',')]

    # Determine servers to probe
    servers = []
    if args.server:
        servers = [args.server]
    elif args.resolve:
        print("Resolving wyze-mars-asrv.wyzecam.com...")
        servers = resolve_mars_dns()
        if servers:
            print(f"  Found {len(servers)} IPs: {', '.join(servers)}")
        else:
            print("  Failed — using known IPs")
            servers = KNOWN_MARS_SERVERS
    else:
        servers = KNOWN_MARS_SERVERS

    all_results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'servers_probed': servers,
        'detect_results': [],
        'list_results': [],
    }

    # --- DETECT probes ---
    print("\n" + "=" * 70)
    print("DETECT PROBE — sending DETECT_REQ to Mars servers")
    print("=" * 70)

    for server in servers:
        for port in ports:
            print(f"\n--- {server}:{port} ---")
            result = probe_detect(server, port, timeout=args.timeout)
            all_results['detect_results'].append(result)

            if 'error' in result:
                print(f"  ERROR: {result['error']}")
                continue

            print(f"  RTT:       {result['rtt_ms']}ms")
            print(f"  Resp size: {result['resp_size']} bytes")
            print(f"  Resp from: {result['resp_from']}")

            hdr = result['header']
            print(f"  Protocol:  {hdr['protocol']}")
            print(f"  Type:      {hdr['type']}")
            print(f"  Frm len:   {hdr['frm_len']}")
            print(f"  Term ID:   {hdr['term_id']}")
            print(f"  Flags2:    {hdr['flags2']}")
            print(f"  Ack result:{hdr['ack_result']}")

            of = hdr['opt_flags']
            print(f"  opt_flags: {of['raw']}")
            print(f"    encrypt:     {of['opt_encrypt']}")
            print(f"    qos:         {of['qos']}")
            print(f"    is_ack:      {of['is_ack']}")
            print(f"    is_response: {of['is_response']}")
            print(f"    signature:   {of['signature']}")
            print(f"    ntp:         {of['ntp_appended']}")
            print(f"    relay:       {of['relay_flag']}")
            print(f"    nonce:       0x{of['nonce']:04x}")

            if 'payload_parsed' in result:
                pp = result['payload_parsed']
                for k, v in pp.items():
                    print(f"  payload.{k}: {v}")

            print(f"\n  Full response hex:")
            resp_bytes = bytes.fromhex(result['resp_hex'])
            print(hexdump(resp_bytes, prefix="    "))

            # Compare with our builder
            if args.compare:
                print(f"\n  --- COMPARISON with our builder ---")
                req_bytes = bytes.fromhex(result['req_hex'])
                our_resp = build_our_detect_resp(req_bytes)
                print(f"  Our response ({len(our_resp)} bytes):")
                print(hexdump(our_resp, prefix="    "))

                diffs = compare_detect_resp(resp_bytes, our_resp)
                mismatches = [d for d in diffs if not d.get('match', True)]
                if mismatches:
                    print(f"\n  MISMATCHES ({len(mismatches)}):")
                    for d in mismatches:
                        print(f"    {d['field']:25s} @ {d['offset']}: "
                              f"real={d.get('real','?')} ours={d.get('ours','?')}")
                else:
                    print(f"\n  All header fields MATCH!")

    # --- LIST probes ---
    print("\n" + "=" * 70)
    print("LIST PROBE — sending LIST_REQ to Mars list port")
    print("=" * 70)

    for server in servers:
        print(f"\n--- {server}:{args.list_port} ---")
        result = probe_list(server, args.list_port, timeout=args.timeout)
        all_results['list_results'].append(result)

        if 'error' in result:
            print(f"  ERROR: {result['error']}")
            continue

        print(f"  RTT:       {result['rtt_ms']}ms")
        print(f"  Resp size: {result['resp_size']} bytes")
        print(f"  Resp from: {result['resp_from']}")

        hdr = result['header']
        print(f"  Protocol:  {hdr['protocol']}")
        print(f"  Type:      {hdr['type']}")
        print(f"  Frm len:   {hdr['frm_len']}")
        print(f"  opt_flags: {hdr['opt_flags']['raw']}")

        if 'payload_hex_encrypted' in result:
            print(f"\n  Encrypted payload ({len(result['payload_hex_encrypted'])//2} bytes):")
            enc_bytes = bytes.fromhex(result['payload_hex_encrypted'])
            print(hexdump(enc_bytes[:64], prefix="    "))
            if len(enc_bytes) > 64:
                print(f"    ... (+{len(enc_bytes)-64} more bytes)")

        if 'payload_hex_decrypted' in result:
            print(f"\n  Decrypted payload:")
            dec_bytes = bytes.fromhex(result['payload_hex_decrypted'])
            print(hexdump(dec_bytes[:128], prefix="    "))
            if len(dec_bytes) > 128:
                print(f"    ... (+{len(dec_bytes)-128} more bytes)")

        if 'payload_decrypted_parsed' in result:
            pp = result['payload_decrypted_parsed']
            if 'detected_servers' in pp:
                print(f"\n  Detected servers in LIST_RESP:")
                for srv in pp['detected_servers']:
                    print(f"    @ {srv['offset']}: {srv['ip']}:{srv['port']}"
                          f"{' srv_id=' + str(srv['srv_id']) if 'srv_id' in srv else ''}")

        if 'decrypt_error' in result:
            print(f"  Decrypt error: {result['decrypt_error']}")

        print(f"\n  Full response hex:")
        resp_bytes = bytes.fromhex(result['resp_hex'])
        print(hexdump(resp_bytes, prefix="    "))

    # --- TCP CERTIFY probe (just test connection) ---
    print("\n" + "=" * 70)
    print("TCP CONNECT PROBE — testing TCP connectivity to Mars")
    print("=" * 70)

    for server in servers:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(args.timeout)
            try:
                t0 = time.time()
                sock.connect((server, port))
                rtt = (time.time() - t0) * 1000
                print(f"  {server}:{port} TCP connected ({rtt:.1f}ms)")

                # Try to receive any banner or initial data
                sock.settimeout(1.0)
                try:
                    data = sock.recv(1024)
                    if data:
                        print(f"    Banner ({len(data)} bytes): {data[:64].hex()}")
                    else:
                        print(f"    No banner (server waits for client to speak)")
                except socket.timeout:
                    print(f"    No banner (timeout — server waits for client)")
            except socket.timeout:
                print(f"  {server}:{port} TCP TIMEOUT")
            except ConnectionRefusedError:
                print(f"  {server}:{port} TCP REFUSED")
            except Exception as e:
                print(f"  {server}:{port} TCP ERROR: {e}")
            finally:
                sock.close()

    # Save results
    if args.save:
        with open(args.save, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nResults saved to {args.save}")

    if args.json:
        print("\n" + json.dumps(all_results, indent=2, default=str))

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    detect_ok = sum(1 for r in all_results['detect_results'] if 'error' not in r)
    detect_fail = sum(1 for r in all_results['detect_results'] if 'error' in r)
    list_ok = sum(1 for r in all_results['list_results'] if 'error' not in r)

    print(f"  DETECT: {detect_ok} responses, {detect_fail} failures")
    print(f"  LIST:   {list_ok} responses")

    # Key findings
    if detect_ok > 0:
        r = next(r for r in all_results['detect_results'] if 'error' not in r)
        of = r['header']['opt_flags']
        print(f"\n  Real Mars DETECT_RESP opt_flags: {of['raw']}")
        print(f"    Our builder uses: 0x0000a6d0")
        if of['raw'] != '0x0000a6d0':
            print(f"    *** MISMATCH — this is likely why the SDK rejects our response! ***")

        print(f"\n  Real resp size: {r['resp_size']} bytes (our builder: 56 bytes)")
        if r['resp_size'] != 56:
            print(f"    *** SIZE MISMATCH — SDK may expect {r['resp_size']} bytes! ***")


if __name__ == "__main__":
    main()
