#!/usr/bin/env python3
"""
server.py - AES-GCM secure file receiver

Usage:
    python server.py --host 0.0.0.0 --port 9000 --out-dir received_files
"""

import argparse
import json
import os
import socket
import struct
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Helper to recv exactly n bytes
def recvall(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def derive_key(password: str, salt: bytes, iterations=200_000) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password_bytes)

def handle_client(conn, addr, password, out_dir: Path):
    print(f"[+] Connection from {addr}")
    try:
        # Read handshake length (4 bytes)
        len_bytes = recvall(conn, 4)
        if not len_bytes:
            print("[-] No handshake length received.")
            return
        (hl,) = struct.unpack(">I", len_bytes)
        handshake_json = recvall(conn, hl)
        if not handshake_json:
            print("[-] Handshake payload missing")
            return
        handshake = json.loads(handshake_json.decode('utf-8'))
        filename = os.path.basename(handshake['filename'])
        filesize = int(handshake['filesize'])
        salt = bytes.fromhex(handshake['salt'])
        iterations = handshake.get('iterations', 200_000)

        print(f"[i] Handshake: file={filename} size={filesize} bytes salt={salt.hex()}")

        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)

        out_path = out_dir / filename
        # Ensure unique filename to avoid overwrite
        base, ext = os.path.splitext(out_path)
        i = 1
        while out_path.exists():
            out_path = Path(f"{base}_{i}{ext}")
            i += 1

        received = 0
        with open(out_path, 'wb') as f:
            while True:
                # read frame length (4 bytes)
                len_b = recvall(conn, 4)
                if not len_b:
                    print("[i] Connection closed by client.")
                    break
                (payload_len,) = struct.unpack(">I", len_b)
                if payload_len == 0:
                    print("[i] Received EOF frame.")
                    break

                payload = recvall(conn, payload_len)
                if not payload:
                    print("[-] Incomplete payload.")
                    break

                # first 12 bytes nonce for AESGCM
                if len(payload) < 12:
                    print("[-] Payload too small for nonce.")
                    break
                nonce = payload[:12]
                ct = payload[12:]
                try:
                    pt = aesgcm.decrypt(nonce, ct, None)  # no AAD
                except Exception as e:
                    print(f"[-] Decryption failed: {e}")
                    return

                f.write(pt)
                received += len(pt)

                # simple progress output
                if filesize:
                    pct = (received / filesize) * 100
                    print(f"\r[>] Received {received}/{filesize} bytes ({pct:.1f}%)", end='', flush=True)

        print("\n[+] Transfer complete. Saved to:", out_path)
        # Send an acknowledgment (optional)
        try:
            ack = json.dumps({"status": "ok", "saved_as": str(out_path)}).encode('utf-8')
            conn.sendall(struct.pack(">I", len(ack)) + ack)
        except Exception:
            pass

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--password", required=True, help="Pre-shared password for key derivation")
    parser.add_argument("--out-dir", default="received_files", help="Directory to write incoming files")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"[+] Listening on {args.host}:{args.port} - writing files to {out_dir.resolve()}")

    try:
        while True:
            conn, addr = srv.accept()
            # handle one client at a time (simple). For concurrency, use threads/processes.
            handle_client(conn, addr, args.password, out_dir)
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")
    finally:
        srv.close()

if __name__ == "__main__":
    main()
