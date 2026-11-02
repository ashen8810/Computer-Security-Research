"""LEA encryption, implemented in pure Python (OpenSSL has no LEA).

Follows the KISA specification: little-endian words and 24/28/32 rounds for
128/192/256-bit keys.
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
        raise ValueError("LEA keys must be 16, 24, or 32 bytes.")


def _transform(key: bytes) -> Transform:
    round_keys = _expand_key(key)
    return block_transform(
        lambda block: _encrypt_block(round_keys, block),
        lambda block: _decrypt_block(round_keys, block),
        BLOCK_SIZE,
    )


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)


_DELTA = (
    0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC,
    0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957,
)
_KEY_ROTATIONS = (1, 3, 6, 11, 13, 17)


def _expand_key(key: bytes) -> list[tuple[int, ...]]:
    words = list(struct.unpack(f"<{len(key) // 4}I", key))
    round_keys = []
    if len(key) == 16:
        for index in range(24):
            delta = _DELTA[index % 4]
            for position in range(4):
                words[position] = rotl32(
                    (words[position] + rotl32(delta, index + position)) & MASK32,
                    _KEY_ROTATIONS[position],
                )
            round_keys.append((words[0], words[1], words[2], words[1], words[3], words[1]))
    elif len(key) == 24:
        for index in range(28):
            delta = _DELTA[index % 6]
            for position in range(6):
                words[position] = rotl32(
                    (words[position] + rotl32(delta, index + position)) & MASK32,
                    _KEY_ROTATIONS[position],
                )
            round_keys.append(tuple(words))
    else:
        for index in range(32):
            delta = _DELTA[index % 8]
            for offset in range(6):
                position = (6 * index + offset) % 8
                words[position] = rotl32(
                    (words[position] + rotl32(delta, index + offset)) & MASK32,
                    _KEY_ROTATIONS[offset],
                )
            round_keys.append(tuple(words[(6 * index + offset) % 8] for offset in range(6)))
    return round_keys


def _encrypt_block(round_keys: list[tuple[int, ...]], block: bytes) -> bytes:
    x0, x1, x2, x3 = struct.unpack("<4I", block)
    for k0, k1, k2, k3, k4, k5 in round_keys:
        x0, x1, x2, x3 = (
            rotl32(((x0 ^ k0) + (x1 ^ k1)) & MASK32, 9),
            rotr32(((x1 ^ k2) + (x2 ^ k3)) & MASK32, 5),
            rotr32(((x2 ^ k4) + (x3 ^ k5)) & MASK32, 3),
            x0,
        )
    return struct.pack("<4I", x0, x1, x2, x3)


def _decrypt_block(round_keys: list[tuple[int, ...]], block: bytes) -> bytes:
    x0, x1, x2, x3 = struct.unpack("<4I", block)
    for k0, k1, k2, k3, k4, k5 in reversed(round_keys):
        previous0 = x3
        previous1 = ((rotr32(x0, 9) - (previous0 ^ k0)) & MASK32) ^ k1
        previous2 = ((rotl32(x1, 5) - (previous1 ^ k2)) & MASK32) ^ k3
        previous3 = ((rotl32(x2, 3) - (previous2 ^ k4)) & MASK32) ^ k5
        x0, x1, x2, x3 = previous0, previous1, previous2, previous3
    return struct.pack("<4I", x0, x1, x2, x3)
