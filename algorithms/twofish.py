"""Twofish encryption, implemented in pure Python (OpenSSL has no Twofish).

Follows the AES submission: little-endian words, key-dependent S-boxes folded
together with the MDS matrix into four lookup tables per key.
"""

from __future__ import annotations

import random
import struct

from algorithms._bits import MASK32, gf_multiply, rotl32, rotr32
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
        raise ValueError("Twofish keys must be 16, 24, or 32 bytes.")


def _transform(key: bytes) -> Transform:
    tables, subkeys = _expand_key(key)
    return block_transform(
        lambda block: _encrypt_block(tables, subkeys, block),
        lambda block: _decrypt_block(tables, subkeys, block),
        BLOCK_SIZE,
    )


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)


_Q_NIBBLES = (
    (
        (8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4),
        (14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13),
        (11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1),
        (13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10),
    ),
    (
        (2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5),
        (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8),
        (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15),
        (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10),
    ),
)
_MDS = ((0x01, 0xEF, 0x5B, 0x5B), (0x5B, 0xEF, 0xEF, 0x01), (0xEF, 0x5B, 0x01, 0xEF), (0xEF, 0x01, 0xEF, 0x5B))
_MDS_POLYNOMIAL = 0x169
_RS = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)
_RS_POLYNOMIAL = 0x14D
_RHO = 0x01010101


def _build_q(nibbles: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    def ror4(value: int) -> int:
        return ((value >> 1) | (value << 3)) & 0xF

    table = []
    for value in range(256):
        a, b = value >> 4, value & 0xF
        a, b = a ^ b, (a ^ ror4(b) ^ (a << 3)) & 0xF
        a, b = nibbles[0][a], nibbles[1][b]
        a, b = a ^ b, (a ^ ror4(b) ^ (a << 3)) & 0xF
        a, b = nibbles[2][a], nibbles[3][b]
        table.append((b << 4) | a)
    return tuple(table)


_Q0, _Q1 = (_build_q(nibbles) for nibbles in _Q_NIBBLES)
# q-box order applied to each input byte, from the k=4 layer down to the last.
_Q_ORDER = (
    (_Q1, _Q1, _Q0, _Q0, _Q1),
    (_Q0, _Q1, _Q1, _Q0, _Q0),
    (_Q0, _Q0, _Q0, _Q1, _Q1),
    (_Q1, _Q0, _Q1, _Q1, _Q0),
)
_MDS_COLUMNS = tuple(
    tuple(
        int.from_bytes(
            bytes(gf_multiply(_MDS[row][column], value, _MDS_POLYNOMIAL) for row in range(4)),
            "little",
        )
        for value in range(256)
    )
    for column in range(4)
)


def _key_sbox(position: int, value: int, key_words: list[int]) -> int:
    """The h-function's byte path for one input byte position."""
    order = _Q_ORDER[position]
    shift = 8 * position
    layers = len(key_words)
    for layer in range(layers - 1, -1, -1):
        value = order[3 - layer][value] ^ ((key_words[layer] >> shift) & 0xFF)
    return order[4][value]


def _h(word: int, key_words: list[int]) -> int:
    result = 0
    for position in range(4):
        result ^= _MDS_COLUMNS[position][
            _key_sbox(position, (word >> (8 * position)) & 0xFF, key_words)
        ]
    return result


def _expand_key(key: bytes) -> tuple[tuple[tuple[int, ...], ...], list[int]]:
    words = list(struct.unpack(f"<{len(key) // 4}I", key))
    even, odd = words[0::2], words[1::2]
    sbox_words = []
    for chunk in range(len(key) // 8):
        key_bytes = key[8 * chunk : 8 * chunk + 8]
        reduced = bytes(_rs_dot(row, key_bytes) for row in _RS)
        sbox_words.append(int.from_bytes(reduced, "little"))
    sbox_words.reverse()

    subkeys = []
    for index in range(20):
        a = _h(2 * index * _RHO, even)
        b = rotl32(_h((2 * index + 1) * _RHO, odd), 8)
        subkeys.append((a + b) & MASK32)
        subkeys.append(rotl32((a + 2 * b) & MASK32, 9))

    tables = tuple(
        tuple(
            _MDS_COLUMNS[position][_key_sbox(position, value, sbox_words)]
            for value in range(256)
        )
        for position in range(4)
    )
    return tables, subkeys


def _rs_dot(row: tuple[int, ...], key_bytes: bytes) -> int:
    result = 0
    for coefficient, value in zip(row, key_bytes):
        result ^= gf_multiply(coefficient, value, _RS_POLYNOMIAL)
    return result


def _g(tables: tuple[tuple[int, ...], ...], word: int) -> int:
    return (
        tables[0][word & 0xFF]
        ^ tables[1][(word >> 8) & 0xFF]
        ^ tables[2][(word >> 16) & 0xFF]
        ^ tables[3][word >> 24]
    )


def _encrypt_block(
    tables: tuple[tuple[int, ...], ...], subkeys: list[int], block: bytes
) -> bytes:
    a, b, c, d = (word ^ key for word, key in zip(struct.unpack("<4I", block), subkeys))
    for round_index in range(16):
        t0 = _g(tables, a)
        t1 = _g(tables, rotl32(b, 8))
        c = rotr32(c ^ ((t0 + t1 + subkeys[2 * round_index + 8]) & MASK32), 1)
        d = rotl32(d, 1) ^ ((t0 + 2 * t1 + subkeys[2 * round_index + 9]) & MASK32)
        a, b, c, d = c, d, a, b
    return struct.pack("<4I", c ^ subkeys[4], d ^ subkeys[5], a ^ subkeys[6], b ^ subkeys[7])


def _decrypt_block(
    tables: tuple[tuple[int, ...], ...], subkeys: list[int], block: bytes
) -> bytes:
    c, d, a, b = (word ^ key for word, key in zip(struct.unpack("<4I", block), subkeys[4:8]))
    for round_index in range(15, -1, -1):
        a, b, c, d = c, d, a, b
        t0 = _g(tables, a)
        t1 = _g(tables, rotl32(b, 8))
        c = rotl32(c, 1) ^ ((t0 + t1 + subkeys[2 * round_index + 8]) & MASK32)
        d = rotr32(d ^ ((t0 + 2 * t1 + subkeys[2 * round_index + 9]) & MASK32), 1)
    return struct.pack("<4I", a ^ subkeys[0], b ^ subkeys[1], c ^ subkeys[2], d ^ subkeys[3])
