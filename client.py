#!/usr/bin/env python3
"""
client.py - AES-GCM secure file sender

Usage:
    python client.py --host 127.0.0.1 --port 9000 --password mysecret file_to_send.bin
"""

import argparse
import json
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Helper to send all bytes
def sendall(sock, b):
    totalsent = 0
    while totalsent < len(b):
        sent = sock.send(b[totalsent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        totalsent += sent

def derive_key(password: str, salt: bytes, iterations=200_000) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password_bytes)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--password", required=True, help="Pre-shared password for key derivation")
    parser.add_argument("--chunk-size", type=int, default=64*1024, help="Plaintext chunk size")
    parser.add_argument("--iterations", type=int, default=200_000, help="PBKDF2 iterations")
    parser.add_argument("file", help="File to send")
    args = parser.parse_args()

    file_path = args.file
    if not os.path.isfile(file_path):
        print("File not found:", file_path)
        sys.exit(1)

    filesize = os.path.getsize(file_path)
    filename = os.path.basename(file_path)

    # salt for PBKDF2 (send to server in handshake)
    salt = os.urandom(16)
    key = derive_key(args.password, salt, iterations=args.iterations)
    aesgcm = AESGCM(key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    try:
        # handshake (length-prefixed JSON)
        handshake = {
            "filename": filename,
            "filesize": filesize,
            "salt": salt.hex(),
            "iterations": args.iterations
        }
        handshake_bytes = json.dumps(handshake).encode('utf-8')
        sendall(sock, struct.pack(">I", len(handshake_bytes)))
        sendall(sock, handshake_bytes)

        sent_bytes = 0
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(args.chunk_size)
                if not chunk:
                    break
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, chunk, None)
                payload = nonce + ct
                sendall(sock, struct.pack(">I", len(payload)))
                sendall(sock, payload)
                sent_bytes += len(chunk)
                if filesize:
                    pct = (sent_bytes / filesize) * 100
                    print(f"\r[>] Sent {sent_bytes}/{filesize} bytes ({pct:.1f}%)", end='', flush=True)

        # send zero-length frame to indicate EOF
        sendall(sock, struct.pack(">I", 0))
        print("\n[+] File sent. Waiting for server acknowledgement...")

        # optionally read ack (length-prefixed)
        len_b = sock.recv(4)
        if len_b:
            (ack_len,) = struct.unpack(">I", len_b)
            if ack_len:
                ack = sock.recv(ack_len)
                print("[i] Server ack:", ack.decode('utf-8', errors='ignore'))
    finally:
        sock.close()

if __name__ == "__main__":
    main()
