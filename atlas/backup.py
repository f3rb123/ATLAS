"""Streaming authenticated backups using scrypt and AES-GCM via cryptography.
Framed AES-GCM records include a final authenticated empty record; truncation fails.
KEK material is never included by backup scripts.
"""

import os, struct, sys, argparse
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

MAGIC = b"ATLASBACKUP1\n"
CHUNK = 1024 * 1024


def key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)


def encrypt(source, dest, password):
    salt = os.urandom(16)
    prefix = os.urandom(8)
    header = MAGIC + salt + prefix
    dest.write(header)
    cipher = AESGCM(key(password, salt))
    index = 0
    while True:
        chunk = source.read(CHUNK)
        aad = header + struct.pack(">I", index)
        nonce = prefix + struct.pack(">I", index)
        ct = cipher.encrypt(nonce, chunk, aad)
        dest.write(struct.pack(">I", len(ct)))
        dest.write(ct)
        index += 1
        if not chunk:
            break


def read_exact(source, n):
    result = b""
    while len(result) < n:
        data = source.read(n - len(result))
        if not data:
            raise ValueError("Truncated backup")
        result += data
    return result


def decrypt(source, dest, password):
    header = read_exact(source, len(MAGIC) + 24)
    if not header.startswith(MAGIC):
        raise ValueError("Unknown backup format")
    salt = header[len(MAGIC) : len(MAGIC) + 16]
    prefix = header[-8:]
    cipher = AESGCM(key(password, salt))
    index = 0
    while True:
        length = struct.unpack(">I", read_exact(source, 4))[0]
        if length < 16 or length > CHUNK + 16:
            raise ValueError("Invalid frame size")
        ct = read_exact(source, length)
        chunk = cipher.decrypt(
            prefix + struct.pack(">I", index), ct, header + struct.pack(">I", index)
        )
        index += 1
        if not chunk:
            if source.read(1):
                raise ValueError("Trailing backup data")
            return
        dest.write(chunk)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["encrypt", "decrypt"])
    p.add_argument("--password-file", required=True)
    args = p.parse_args()
    password = Path(args.password_file).read_bytes()
    if len(password) < 32:
        raise ValueError("Backup password must have at least 32 random bytes")
    (encrypt if args.action == "encrypt" else decrypt)(
        sys.stdin.buffer, sys.stdout.buffer, password
    )


if __name__ == "__main__":
    main()
