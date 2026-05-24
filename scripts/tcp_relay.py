#!/usr/bin/env python3
"""tcp_relay.py — pipes bridge stdout to one TCP client on a loopback port.

Usage:  bridge --stdout --device MAC | python3 tcp_relay.py --port 18000

Accepts one TCP client (the overlay container). Forwards stdin bytes to the
client. Reconnects automatically when the client drops. Exits when stdin
closes (bridge exited).
"""
import argparse
import socket
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(1)
    print(f"[tcp_relay] listening on 127.0.0.1:{args.port}", file=sys.stderr, flush=True)

    stdin = sys.stdin.buffer

    while True:
        conn, addr = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"[tcp_relay] client connected from {addr}", file=sys.stderr, flush=True)
        try:
            while True:
                chunk = stdin.read(65536)
                if not chunk:
                    conn.close()
                    return   # bridge exited
                conn.sendall(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            print("[tcp_relay] client disconnected, waiting for next", file=sys.stderr, flush=True)
        finally:
            try: conn.close()
            except Exception: pass


if __name__ == "__main__":
    main()
