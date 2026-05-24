#!/usr/bin/env python3
"""
BLE Sniffer Terminal - Interactive serial monitor for the ESP32-C6 BLE sniffer.

Curses-based TUI with scrolling output and command input bar.

Usage:
    python3 tools/ble_sniffer/terminal.py [--port /dev/cu.usbmodem101] [--baud 115200]

Keys:
    c/r/s/f/v/m/h  - Send sniffer commands directly (when not in input mode)
    Enter           - Focus input bar (type arbitrary text, Enter to send)
    Escape          - Cancel input / exit input mode
    q               - Quit (when not in input mode)
    PgUp/PgDn       - Scroll output
    Home/End        - Jump to top/bottom of output
    Ctrl-C          - Force quit
"""

import argparse
import curses
import os
import serial
import sys
import threading
import time
from collections import deque
from datetime import datetime

DEFAULT_PORT = "/dev/cu.usbmodem101"
DEFAULT_BAUD = 115200
MAX_LINES = 5000  # Max scrollback
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


def open_serial(port, baud):
    s = serial.Serial()
    s.port = port
    s.baudrate = baud
    s.timeout = 0.1
    s.dsrdtr = False
    s.rtscts = False
    s.dtr = False
    s.rts = False
    s.open()
    return s


def reader_thread(ser, lines, lock, stop_event, log_file):
    """Background thread: read serial lines into shared buffer and log to file."""
    buf = b""
    while not stop_event.is_set():
        try:
            data = ser.read(256)
            if data:
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", errors="replace").rstrip("\r")
                    with lock:
                        lines.append(text)
                        if len(lines) > MAX_LINES:
                            lines.popleft()
                    # Always log to file
                    if log_file:
                        try:
                            log_file.write(text + "\n")
                            log_file.flush()
                        except Exception:
                            pass
        except serial.SerialException:
            with lock:
                lines.append("[SERIAL DISCONNECTED]")
            stop_event.set()
        except Exception as e:
            with lock:
                lines.append(f"[ERROR] {e}")
            time.sleep(0.1)


def main(stdscr, port, baud):
    # Setup curses
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # status bar
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_GREEN)  # input bar
    curses.init_pair(3, curses.COLOR_YELLOW, -1)  # NEW highlights
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # timestamps
    curses.init_pair(5, curses.COLOR_RED, -1)      # errors
    curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)   # input active
    stdscr.nodelay(True)
    stdscr.timeout(50)  # 50ms refresh

    # Connect serial
    try:
        ser = open_serial(port, baud)
    except Exception as e:
        stdscr.addstr(0, 0, f"Failed to open {port}: {e}")
        stdscr.addstr(1, 0, "Press any key to exit...")
        stdscr.nodelay(False)
        stdscr.getch()
        return

    # Shared state
    lines = deque(maxlen=MAX_LINES)
    lock = threading.Lock()
    stop_event = threading.Event()

    # Setup log file
    os.makedirs(LOG_DIR, exist_ok=True)
    log_name = datetime.now().strftime("ble_capture_%Y%m%d_%H%M%S.log")
    log_path = os.path.join(LOG_DIR, log_name)
    log_file = open(log_path, "w")
    log_file.write(f"# BLE Sniffer capture started {datetime.now().isoformat()}\n")
    log_file.write(f"# Port: {port}  Baud: {baud}\n\n")
    log_file.flush()

    # Start reader
    t = threading.Thread(target=reader_thread, args=(ser, lines, lock, stop_event, log_file), daemon=True)
    t.start()

    # UI state
    scroll_offset = 0  # 0 = bottom (auto-scroll)
    input_mode = False
    input_buf = ""
    auto_scroll = True
    sent_count = 0
    connected_time = time.time()

    status_msg = ""
    status_time = 0

    def set_status(msg):
        nonlocal status_msg, status_time
        status_msg = msg
        status_time = time.time()

    set_status(f"Connected to {port} | Log: {log_name}")

    try:
        while not stop_event.is_set():
            h, w = stdscr.getmaxyx()
            output_h = h - 2  # Reserve 2 lines: status + input

            # --- Handle input ---
            try:
                key = stdscr.getch()
            except curses.error:
                key = -1

            if key == -1:
                pass
            elif key == 27:  # Escape
                if input_mode:
                    input_mode = False
                    input_buf = ""
                    curses.curs_set(0)
                else:
                    break
            elif key == ord("q") and not input_mode:
                break
            elif key == curses.KEY_PPAGE:  # Page Up
                auto_scroll = False
                scroll_offset = min(scroll_offset + output_h // 2, max(0, len(lines) - output_h))
            elif key == curses.KEY_NPAGE:  # Page Down
                scroll_offset = max(0, scroll_offset - output_h // 2)
                if scroll_offset == 0:
                    auto_scroll = True
            elif key == curses.KEY_HOME:
                auto_scroll = False
                scroll_offset = max(0, len(lines) - output_h)
            elif key == curses.KEY_END:
                scroll_offset = 0
                auto_scroll = True
            elif key == curses.KEY_UP and not input_mode:
                auto_scroll = False
                scroll_offset = min(scroll_offset + 1, max(0, len(lines) - output_h))
            elif key == curses.KEY_DOWN and not input_mode:
                scroll_offset = max(0, scroll_offset - 1)
                if scroll_offset == 0:
                    auto_scroll = True
            elif key == 10 or key == 13:  # Enter
                if input_mode:
                    if input_buf:
                        try:
                            ser.write(input_buf.encode())
                            set_status(f"Sent: {repr(input_buf)}")
                            sent_count += 1
                        except Exception as e:
                            set_status(f"Send failed: {e}")
                        input_buf = ""
                    input_mode = False
                    curses.curs_set(0)
                else:
                    input_mode = True
                    input_buf = ""
                    curses.curs_set(1)
            elif key == curses.KEY_BACKSPACE or key == 127:
                if input_mode and input_buf:
                    input_buf = input_buf[:-1]
            elif input_mode and 32 <= key < 127:
                input_buf += chr(key)
            elif not input_mode and key in (ord("c"), ord("r"), ord("s"), ord("f"),
                                             ord("v"), ord("m"), ord("h")):
                # Direct command send
                cmd = chr(key)
                cmd_names = {
                    "c": "baseline", "r": "reset", "s": "stats",
                    "f": "filter", "v": "verbose", "m": "mark", "h": "help"
                }
                try:
                    ser.write(cmd.encode())
                    set_status(f"Sent: {cmd} ({cmd_names.get(cmd, '')})")
                    sent_count += 1
                except Exception as e:
                    set_status(f"Send failed: {e}")

            # --- Draw output ---
            stdscr.erase()

            with lock:
                total = len(lines)
                if auto_scroll:
                    start = max(0, total - output_h)
                else:
                    start = max(0, total - output_h - scroll_offset)
                end = start + output_h
                visible = list(lines)[start:end]

            for row, line in enumerate(visible):
                if row >= output_h:
                    break
                try:
                    # Color coding
                    if ">>> NEW" in line:
                        stdscr.addnstr(row, 0, line, w - 1, curses.color_pair(3) | curses.A_BOLD)
                    elif "[ERROR]" in line or "[SERIAL DISCONNECTED]" in line or "Guru Meditation" in line:
                        stdscr.addnstr(row, 0, line, w - 1, curses.color_pair(5))
                    elif line.startswith("---") or line.startswith("==="):
                        stdscr.addnstr(row, 0, line, w - 1, curses.color_pair(4))
                    elif "MARK" in line:
                        stdscr.addnstr(row, 0, line, w - 1, curses.color_pair(3))
                    elif line.startswith("    "):
                        stdscr.addnstr(row, 0, line, w - 1, curses.color_pair(4))
                    else:
                        stdscr.addnstr(row, 0, line, w - 1)
                except curses.error:
                    pass

            # --- Status bar ---
            uptime = int(time.time() - connected_time)
            scroll_indicator = "SCROLL" if not auto_scroll else "LIVE"
            status_left = f" {port} | {total} lines | {scroll_indicator} | sent:{sent_count} | up:{uptime}s | log:{log_name}"
            if status_msg and time.time() - status_time > 3:
                status_msg = ""
            status_right = f" {status_msg} " if status_msg else ""

            status_line = status_left + " " * max(0, w - len(status_left) - len(status_right)) + status_right
            try:
                stdscr.addnstr(h - 2, 0, status_line[:w], w, curses.color_pair(2))
            except curses.error:
                pass

            # --- Input bar ---
            if input_mode:
                prompt = f" > {input_buf}"
                padding = " " * max(0, w - len(prompt))
                try:
                    stdscr.addnstr(h - 1, 0, (prompt + padding)[:w], w, curses.color_pair(6))
                    stdscr.move(h - 1, min(len(prompt), w - 1))
                except curses.error:
                    pass
            else:
                hint = " [c]lear [f]ilter [m]ark [s]tats [v]erbose [r]eset | Enter=input q=quit"
                try:
                    stdscr.addnstr(h - 1, 0, hint[:w], w, curses.color_pair(1))
                except curses.error:
                    pass

            stdscr.refresh()

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        try:
            ser.close()
        except Exception:
            pass
        try:
            log_file.write(f"\n# Capture ended {datetime.now().isoformat()}\n")
            log_file.close()
        except Exception:
            pass


def run():
    parser = argparse.ArgumentParser(description="BLE Sniffer Terminal")
    parser.add_argument("--port", "-p", default=DEFAULT_PORT, help=f"Serial port (default: {DEFAULT_PORT})")
    parser.add_argument("--baud", "-b", type=int, default=DEFAULT_BAUD, help=f"Baud rate (default: {DEFAULT_BAUD})")
    args = parser.parse_args()

    # Kill any existing holders of the port
    import subprocess
    subprocess.run(["pkill", "-f", f"picocom.*{args.port}"], capture_output=True)
    time.sleep(0.2)

    curses.wrapper(main, args.port, args.baud)


if __name__ == "__main__":
    run()
