#!/usr/bin/env python3
"""
Stego Terminal Tool
===================
Single-file steganography CLI tool (LSB) for hiding/retrieving messages inside PNG/BMP images.

Features:
- `encode` subcommand: hide a text message or binary file inside an image.
  - optional password-based encryption (AES via Fernet + PBKDF2) before embedding
- `decode` subcommand: extract hidden data and optionally decrypt if password was used
- `info` subcommand: reports image capacity and whether it appears to contain a STEG payload

Usage examples (after creating virtual environment & installing requirements):
  python3 stego-terminal-tool.py encode --in input.png --out out.png --message "hello" \
      --password mypass
  python3 stego-terminal-tool.py decode --in out.png --out extracted.bin --password mypass
  python3 stego-terminal-tool.py info --in out.png

Requirements (requirements.txt):
  Pillow>=9.0.0
  cryptography>=40.0.0

License: MIT (add LICENSE file in repo)

"""

import argparse
import os
import sys
import struct
from PIL import Image
from typing import Optional, Tuple

# Optional encryption requires cryptography. If not installed, encode/decode without encryption still works.
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    import base64
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

MAGIC = b'STEG'  # 4 bytes magic
VERSION = 1      # 1 byte version
HEADER_FMT = '>4sBBI'  # magic(4s), version(B), flags(B), length(I)
HEADER_SIZE = struct.calcsize(HEADER_FMT)
FLAG_ENCRYPTED = 0x01

# --- Utilities for optional password-based encryption ---
def _derive_key(password: str, salt: bytes) -> bytes:
    # Derive a 32-byte key for Fernet using PBKDF2HMAC(SHA256)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    # returns: salt(16) + token
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library not available. Install 'cryptography' to use encryption")
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(plaintext)
    return salt + token

def decrypt_bytes(data: bytes, password: str) -> bytes:
    # expects salt(16) + token
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library not available. Install 'cryptography' to use decryption")
    if len(data) < 17:
        raise ValueError("invalid encrypted data")
    salt = data[:16]
    token = data[16:]
    key = _derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(token)

# --- LSB embed / extract ---

def _bytes_to_bits(data: bytes) -> list:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def _bits_to_bytes(bits: list) -> bytes:
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        for bit in chunk:
            byte = (byte << 1) | (bit & 1)
        b.append(byte)
    return bytes(b)


def calculate_capacity(img: Image.Image) -> int:
    width, height = img.size
    # 3 bits per pixel (one per R,G,B LSB)
    return width * height * 3


def encode_image(input_path: str, output_path: str, payload: bytes) -> None:
    img = Image.open(input_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    width, height = img.size
    capacity = calculate_capacity(img)
    required_bits = len(payload) * 8
    if required_bits > capacity:
        raise ValueError(f"Payload too large for image capacity. Need {required_bits} bits but image has {capacity} bits")

    pixels = img.load()
    bits = _bytes_to_bits(payload)
    bit_iter = iter(bits)

    done = False
    for y in range(height):
        for x in range(width):
            if done:
                break
            r, g, b = pixels[x, y]
            r_bit = next(bit_iter, None)
            g_bit = next(bit_iter, None)
            b_bit = next(bit_iter, None)
            if r_bit is None:
                done = True
                break
            if g_bit is None:
                g_bit = (g & 1)
            if b_bit is None:
                b_bit = (b & 1)
            r = (r & ~1) | r_bit
            g = (g & ~1) | g_bit
            b = (b & ~1) | b_bit
            pixels[x, y] = (r, g, b)
    img.save(output_path, format='PNG')


def decode_image(input_path: str) -> bytes:
    img = Image.open(input_path)
    img = img.convert('RGB')
    width, height = img.size
    pixels = img.load()

    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)

    data = _bits_to_bytes(bits)
    # data might be longer than embedded payload; we need to find header
    if len(data) < HEADER_SIZE:
        raise ValueError('No valid payload found (too small)')

    # search for MAGIC at start
    # assume payload starts at byte 0
    header = data[:HEADER_SIZE]
    try:
        magic, version, flags, length = struct.unpack(HEADER_FMT, header)
    except struct.error:
        raise ValueError('Invalid header structure')
    if magic != MAGIC:
        raise ValueError('No STEG payload found (magic mismatch)')
    if version != VERSION:
        raise ValueError(f'Unsupported version: {version}')
    payload_start = HEADER_SIZE
    payload_end = payload_start + length
    if payload_end > len(data):
        # Maybe the image had more pixels but not all bytes were filled; try trimming to available size
        raise ValueError('Payload length indicates more data than available. Possibly corrupted or wrong image.')

    payload = data[payload_start:payload_end]
    encrypted = bool(flags & FLAG_ENCRYPTED)
    return payload, encrypted

# --- CLI ---

def cmd_info(args):
    img = Image.open(args.infile)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    cap = calculate_capacity(img)
    print(f'Image: {args.infile}')
    print(f'Format: {img.format}, Size: {img.size}, Mode: {img.mode}')
    print(f'Capacity (bits): {cap}  (bytes: {cap//8})')
    # try to detect a STEG payload
    try:
        payload, encrypted = decode_image(args.infile)
        print('STEG payload detected!')
        print(f'Payload length: {len(payload)} bytes')
        print('Encrypted:' , encrypted)
    except Exception as e:
        print('No valid STEG payload detected:', e)


def cmd_encode(args):
    # prepare payload: header + data
    if args.infile and args.message and args.file:
        raise ValueError('Provide either --message or --file for payload, not both')
    if not args.message and not args.file:
        raise ValueError('Provide --message or --file to embed')
    if args.message:
        data = args.message.encode()
    else:
        with open(args.file, 'rb') as f:
            data = f.read()

    flags = 0
    if args.password:
        if not CRYPTO_AVAILABLE:
            print('Encryption requested but cryptography package not available. Install it and retry.')
            sys.exit(2)
        data = encrypt_bytes(data, args.password)
        flags |= FLAG_ENCRYPTED

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, flags, len(data))
    payload = header + data
    encode_image(args.infile, args.outfile, payload)
    print(f'Encoded {len(data)} bytes into {args.outfile}')


def cmd_decode(args):
    payload, encrypted = decode_image(args.infile)
    if encrypted:
        if not args.password:
            print('Payload is encrypted. Provide --password to decrypt.')
            sys.exit(2)
        try:
            payload = decrypt_bytes(payload, args.password)
        except Exception as e:
            print('Decryption failed:', e)
            sys.exit(3)
    if args.outfile:
        with open(args.outfile, 'wb') as f:
            f.write(payload)
        print(f'Written {len(payload)} bytes to {args.outfile}')
    else:
        # try to decode as utf-8 text
        try:
            text = payload.decode('utf-8')
            print('---- extracted text ----')
            print(text)
            print('------------------------')
        except Exception:
            print(f'Payload is binary ({len(payload)} bytes). Use --outfile to save it.')


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='stego-tool', description='LSB steganography terminal tool')
    sub = p.add_subparsers(dest='command', required=True)

    p_info = sub.add_parser('info', help='Show image info and capacity, detect STEG payload')
    p_info.add_argument('--in', dest='infile', required=True, help='Input image file')
    p_info.set_defaults(func=cmd_info)

    p_enc = sub.add_parser('encode', help='Embed message or file into image')
    p_enc.add_argument('--in', dest='infile', required=True, help='Cover image (PNG/BMP recommended)')
    p_enc.add_argument('--out', dest='outfile', required=True, help='Output image (PNG recommended)')
    g = p_enc.add_mutually_exclusive_group(required=True)
    g.add_argument('--message', help='Message string to embed')
    g.add_argument('--file', help='Path to binary file to embed')
    p_enc.add_argument('--password', help='Optional password to encrypt payload before embedding')
    p_enc.set_defaults(func=cmd_encode)

    p_dec = sub.add_parser('decode', help='Extract embedded message/file from image')
    p_dec.add_argument('--in', dest='infile', required=True, help='Stego image file')
    p_dec.add_argument('--out', dest='outfile', help='Write extracted payload to file')
    p_dec.add_argument('--password', help='Password to decrypt payload if encrypted')
    p_dec.set_defaults(func=cmd_decode)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        print('Error:', e)
        sys.exit(1)


if __name__ == '__main__':
    main()

