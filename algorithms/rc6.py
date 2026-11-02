"""RC6-32/20 encryption, implemented in pure Python (OpenSSL has no RC6).

Follows the AES submission: little-endian words and 20 rounds.
"""

from __future__ import annotations

import random
import struct

from algorithms._bits import MASK32, rotl32, rotr32
from algorithms._block_cipher import Transform, block_transform
from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes

BLOCK_SIZE = 16
KEY_LENGTHS = (16, 24, 32)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 32)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("RC6 keys must be 16, 24, or 32 bytes.")


def _transform(key: bytes) -> Transform:
    subkeys = _expand_key(key)
    return block_transform(
        lambda block: _encrypt_block(subkeys, block),
        lambda block: _decrypt_block(subkeys, block),
        BLOCK_SIZE,
    )


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)


_ROUNDS = 20
_P32 = 0xB7E15163
_Q32 = 0x9E3779B9


def _expand_key(key: bytes) -> list[int]:
    words = list(struct.unpack(f"<{len(key) // 4}I", key))
    subkeys = [(_P32 + index * _Q32) & MASK32 for index in range(2 * _ROUNDS + 4)]
    a = b = i = j = 0
    for _ in range(3 * max(len(words), len(subkeys))):
        a = subkeys[i] = rotl32((subkeys[i] + a + b) & MASK32, 3)
        b = words[j] = rotl32((words[j] + a + b) & MASK32, a + b)
        i = (i + 1) % len(subkeys)
        j = (j + 1) % len(words)
    return subkeys


def _mix(word: int) -> int:
    return rotl32((word * (2 * word + 1)) & MASK32, 5)


def _encrypt_block(subkeys: list[int], block: bytes) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    b = (b + subkeys[0]) & MASK32
    d = (d + subkeys[1]) & MASK32
    for round_index in range(1, _ROUNDS + 1):
        t = _mix(b)
        u = _mix(d)
        a = (rotl32(a ^ t, u) + subkeys[2 * round_index]) & MASK32
        c = (rotl32(c ^ u, t) + subkeys[2 * round_index + 1]) & MASK32
        a, b, c, d = b, c, d, a
    a = (a + subkeys[2 * _ROUNDS + 2]) & MASK32
    c = (c + subkeys[2 * _ROUNDS + 3]) & MASK32
    return struct.pack("<4I", a, b, c, d)


def _decrypt_block(subkeys: list[int], block: bytes) -> bytes:
    a, b, c, d = struct.unpack("<4I", block)
    c = (c - subkeys[2 * _ROUNDS + 3]) & MASK32
    a = (a - subkeys[2 * _ROUNDS + 2]) & MASK32
    for round_index in range(_ROUNDS, 0, -1):
        a, b, c, d = d, a, b, c
        u = _mix(d)
        t = _mix(b)
        c = rotr32((c - subkeys[2 * round_index + 1]) & MASK32, t) ^ u
        a = rotr32((a - subkeys[2 * round_index]) & MASK32, u) ^ t
    d = (d - subkeys[1]) & MASK32
    b = (b - subkeys[0]) & MASK32
    return struct.pack("<4I", a, b, c, d)
