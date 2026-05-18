#!/usr/bin/env python3
"""Parse a pcap file containing GUTES UDP frames and decode them.

Usage: python3 scripts/parse_gutes_pcap.py logs/gutes_session.pcap
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gutes_frame import parse_frame, HEADER_SIZE, FRAME_TYPES
from rc5 import RC5, GWELL_KEY, derive_per_frame_key


def parse_pcap(path: str):
    """Parse a pcap file and extract UDP payloads."""
    with open(path, 'rb') as f:
        # Global header (24 bytes)
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
            link_type_offset = 20
        elif magic == 0xd4c3b2a1:
            endian = '>'
            link_type_offset = 20
        elif magic == 0xa1b2cd34:  # nanosecond pcap
            endian = '<'
            link_type_offset = 20
        else:
            print(f"Unknown pcap magic: 0x{magic:08x}")
            return
        
        header = f.read(20)
        version_major, version_minor, thiszone, sigfigs, snaplen, link_type = \
            struct.unpack(f'{endian}HHiIII', header)
        
        print(f"PCAP: version={version_major}.{version_minor} linktype={link_type} snaplen={snaplen}")
        
        # Link type determines header size before IP
        if link_type == 1:  # LINKTYPE_ETHERNET
            l2_header_size = 14
        elif link_type == 113:  # LINKTYPE_LINUX_SLL
            l2_header_size = 16
        elif link_type == 276:  # LINKTYPE_LINUX_SLL2
            l2_header_size = 20
        else:
            print(f"Unsupported link type: {link_type}")
            return
        
        packets = []
        pkt_num = 0
        
        while True:
            # Packet header (16 bytes)
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_header)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            
            pkt_num += 1
            
            # Skip L2 header
            if len(pkt_data) <= l2_header_size:
                continue
            
            ip_data = pkt_data[l2_header_size:]
            
            # Parse IP header
            if len(ip_data) < 20:
                continue
            ip_version = (ip_data[0] >> 4) & 0xF
            if ip_version != 4:
                continue
            ip_hdr_len = (ip_data[0] & 0xF) * 4
            ip_proto = ip_data[9]
            src_ip = f"{ip_data[12]}.{ip_data[13]}.{ip_data[14]}.{ip_data[15]}"
            dst_ip = f"{ip_data[16]}.{ip_data[17]}.{ip_data[18]}.{ip_data[19]}"
            
            if ip_proto != 17:  # Not UDP
                continue
            
            # Parse UDP header
            udp_data = ip_data[ip_hdr_len:]
            if len(udp_data) < 8:
                continue
            src_port, dst_port, udp_len = struct.unpack('>HHH', udp_data[:6])
            payload = udp_data[8:8 + udp_len - 8]
            
            if len(payload) < 4:
                continue
            
            # Check if it's a GUTES frame (starts with 0x7F, 0x7E, or 0x70)
            if payload[0] not in (0x7F, 0x7E, 0x70):
                continue
            
            # Determine direction
            # Heuristic: if dst_port is a known relay port, it's C->S
            relay_ports = {51701, 8443, 28800, 8000, 443}
            if dst_port in relay_ports:
                direction = "C->S"
            elif src_port in relay_ports:
                direction = "S->C"
            else:
                direction = "????"
            
            packets.append({
                'num': pkt_num,
                'ts': ts_sec + ts_usec / 1_000_000,
                'src': f"{src_ip}:{src_port}",
                'dst': f"{dst_ip}:{dst_port}",
                'direction': direction,
                'payload': payload,
            })
    
    return packets


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    path = sys.argv[1]
    print(f"Parsing {path}...")
    print()
    
    packets = parse_pcap(path)
    if not packets:
        print("No GUTES packets found")
        return
    
    t0 = packets[0]['ts']
    
    print(f"{'#':>3} {'T':>7} {'Dir':>5} {'Src':>22} {'Dst':>22} {'Type':>20} {'Len':>4} {'Details'}")
    print("-" * 120)
    
    for pkt in packets:
        payload = pkt['payload']
        frame = parse_frame(payload, direction=pkt['direction'])
        
        if not frame:
            print(f"{pkt['num']:3d} {pkt['ts']-t0:7.3f} {pkt['direction']:>5} "
                  f"{pkt['src']:>22} {pkt['dst']:>22} {'UNPARSED':>20} {len(payload):4d}")
            continue
        
        elapsed = pkt['ts'] - t0
        details = ""
        
        # Add type-specific details
        if frame.frame_type == 0x15:  # LIST_REQ
            details = "list_request"
        elif frame.frame_type == 0x16:  # LIST_RESP
            details = "list_response (server list)"
        elif frame.frame_type == 0x01:  # DETECT_REQ
            details = f"detect probe"
        elif frame.frame_type == 0x02:  # DETECT_RESP
            details = f"detect response ack_result={frame.ack_result}"
        elif frame.frame_type == 0x0C:  # CERTIFY
            details = f"term_id={frame.term_id}"
            if frame.opt_encrypt == 1:
                details += " [per-frame-enc]"
        elif frame.frame_type == 0xA6:  # INIT_INFO_MSG
            details = f"register capabilities"
        
        # Show encryption info
        enc_info = ""
        if frame.opt_encrypt > 0:
            enc_info = f" enc={frame.opt_encrypt}"
        if frame.is_ack:
            enc_info += " ACK"
        if frame.signature_appended:
            enc_info += " SIG"
        
        print(f"{pkt['num']:3d} {elapsed:7.3f} {pkt['direction']:>5} "
              f"{pkt['src']:>22} {pkt['dst']:>22} "
              f"{frame.type_name:>20} {frame.frm_len:4d} "
              f"{details}{enc_info}")
        
        # For certify frames, show more detail
        if frame.frame_type == 0x0C and frame.opt_encrypt == 1:
            # Try to show the encrypted payload
            print(f"      Payload: {frame.payload[:32].hex()}{'...' if len(frame.payload)>32 else ''}")
            if frame.payload_decrypted:
                print(f"      Decrypt: {frame.payload_decrypted[:32].hex()}{'...' if len(frame.payload_decrypted)>32 else ''}")
    
    # Summary
    print()
    print(f"Total GUTES packets: {len(packets)}")
    type_counts = {}
    for pkt in packets:
        frame = parse_frame(pkt['payload'])
        if frame:
            key = f"0x{frame.frame_type:02X} {frame.type_name}"
            type_counts[key] = type_counts.get(key, 0) + 1
    print("Frame type distribution:")
    for k, v in sorted(type_counts.items()):
        print(f"  {k}: {v}")


# Add LIST_REQ and LIST_RESP to the frame types
FRAME_TYPES[0x15] = "LIST_REQ"
FRAME_TYPES[0x16] = "LIST_RESP"

if __name__ == "__main__":
    main()
