#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
honey_port.py
A simple honeypot for opening obfuscation ports based on port_config.json.

Usage:
    python3 honey_port.py
"""

import socket
import threading
import json
import os
import sys

CONFIG_FILE = "port_config.json"

DEFAULT_CONFIG = {
    "obfuscation_ports": [2223, 8081],
    "bind_addr": "0.0.0.0",
    "banner": "Fake Service Ready\r\n"
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"[*] Default {CONFIG_FILE} created.")
        return DEFAULT_CONFIG

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("[!] Failed to load config:", e)
        return DEFAULT_CONFIG


def handle_client(conn, addr, banner):
    try:
        if banner:
            conn.sendall(banner.encode("utf-8", errors="ignore"))
        conn.close()
    except Exception:
        pass


def start_listener(port, bind_addr, banner):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_addr, port))
        sock.listen(100)
        print(f"[*] Fake service listening on {bind_addr}:{port}")
    except OSError as e:
        print(f"[!] Failed to bind {bind_addr}:{port} - {e}")
        return

    while True:
        try:
            conn, addr = sock.accept()
            print(f"[+] Connection from {addr} on port {port}")
            t = threading.Thread(target=handle_client, args=(conn, addr, banner), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("[*] Shutting down listener on port", port)
            sock.close()
            break
        except Exception as e:
            print(f"[!] Exception on port {port}: {e}")
            continue


def main_honeyport():
    cfg = load_config()
    ports = cfg.get("obfuscation_ports", [])
    bind_addr = cfg.get("bind_addr", "0.0.0.0")
    banner = cfg.get("banner", "")

    if not ports:
        print("[!] No ports specified in config.")
        sys.exit(1)

    for port in ports:
        t = threading.Thread(target=start_listener, args=(port, bind_addr, banner), daemon=True)
        t.start()

    # 主线程保持运行
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("[*] Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main_honeyport()

