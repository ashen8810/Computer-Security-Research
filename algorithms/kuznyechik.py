"""Kuznyechik (GOST R 34.12-2015) encryption, implemented in pure Python.

OpenSSL ships Kuznyechik only through the separate GOST engine/provider, so
this follows RFC 7801 directly. Bytes are taken in the RFC's written order.
"""

from __future__ import annotations

import random

from algorithms._bits import gf_multiply, gf_table
from algorithms._block_cipher import Transform, block_transform
from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes

BLOCK_SIZE = 16
KEY_LENGTHS = (32,)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 32)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Kuznyechik keys must be 32 bytes.")


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


# Pi' from RFC 7801 section 4.1.
_PI = (
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
)
_PI_BYTES = bytes(_PI)
_INVERSE_PI_BYTES = bytes(_PI.index(value) for value in range(256))
_POLYNOMIAL = 0x1C3  # x^8 + x^7 + x^6 + x + 1
# Coefficients of l(a_15, ..., a_0), in block byte order.
_L_COEFFICIENTS = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
_PRODUCTS = {constant: gf_table(constant, _POLYNOMIAL) for constant in set(_L_COEFFICIENTS)}


def _l(block: list[int]) -> int:
    mixed = 0
    for coefficient, value in zip(_L_COEFFICIENTS, block):
        mixed ^= _PRODUCTS[coefficient][value]
    return mixed


def _r(block: list[int]) -> list[int]:
    return [_l(block)] + block[:15]


def _r_inverse(block: list[int]) -> list[int]:
    return block[1:] + [_l(block[1:] + block[:1])]


def _linear_tables(inverse: bool) -> tuple[tuple[int, ...], ...]:
    """L (or L^-1) is linear, so precompute its effect on each byte position.

    Entry [position][value] is the transform of a block holding only ``value``
    at ``position``, as a 128-bit integer; a block's image is their XOR.
    """
    columns = []
    for position in range(16):
        block = [0] * 16
        block[position] = 1
        for _ in range(16):
            block = _r_inverse(block) if inverse else _r(block)
        columns.append(block)
    return tuple(
        tuple(
            int.from_bytes(
                bytes(gf_multiply(value, factor, _POLYNOMIAL) for factor in columns[position]), "big"
            )
            for value in range(256)
        )
        for position in range(16)
    )


_L_TABLE = _linear_tables(inverse=False)
_INVERSE_L_TABLE = _linear_tables(inverse=True)


def _linear(block: bytes, table: tuple[tuple[int, ...], ...]) -> bytes:
    result = 0
    for position, value in enumerate(block):
        result ^= table[position][value]
    return result.to_bytes(16, "big")


def _xor(left: bytes, right: bytes) -> bytes:
    return (int.from_bytes(left, "big") ^ int.from_bytes(right, "big")).to_bytes(16, "big")


def _lsx(key: bytes, block: bytes) -> bytes:
    return _linear(_xor(key, block).translate(_PI_BYTES), _L_TABLE)


def _expand_key(key: bytes) -> list[bytes]:
    left, right = key[:16], key[16:]
    round_keys = [left, right]
    for pair in range(4):
        for step in range(1, 9):
            constant = _linear((8 * pair + step).to_bytes(16, "big"), _L_TABLE)
            left, right = _xor(_lsx(constant, left), right), left
        round_keys.extend((left, right))
    return round_keys


def _encrypt_block(round_keys: list[bytes], block: bytes) -> bytes:
    for round_key in round_keys[:9]:
        block = _lsx(round_key, block)
    return _xor(round_keys[9], block)


def _decrypt_block(round_keys: list[bytes], block: bytes) -> bytes:
    block = _xor(round_keys[9], block)
    for round_key in reversed(round_keys[:9]):
        block = _xor(round_key, _linear(block, _INVERSE_L_TABLE).translate(_INVERSE_PI_BYTES))
    return block
