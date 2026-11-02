"""Serpent encryption, implemented in pure Python (OpenSSL has no Serpent).

Uses the bitsliced form from the AES submission with little-endian words,
matching the NESSIE, Botan, and Linux test vectors.
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
        raise ValueError("Serpent keys must be 16, 24, or 32 bytes.")


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


_SBOXES = (
    (3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12),
    (15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4),
    (8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2),
    (0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14),
    (1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13),
    (15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1),
    (7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0),
    (1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6),
)
_PHI = 0x9E3779B9


def _algebraic_normal_form(sbox: tuple[int, ...]) -> tuple[tuple[int, ...], ...]:
    """For each output bit, the input-bit monomials whose XOR gives that bit.

    This lets a 4-bit S-box be applied to all 32 bit-slices of a word at once.
    """
    forms = []
    for bit in range(4):
        coefficients = [(sbox[value] >> bit) & 1 for value in range(16)]
        for variable in range(4):
            for value in range(16):
                if value & (1 << variable):
                    coefficients[value] ^= coefficients[value ^ (1 << variable)]
        forms.append(tuple(monomial for monomial in range(16) if coefficients[monomial]))
    return tuple(forms)


def _invert(sbox: tuple[int, ...]) -> tuple[int, ...]:
    inverse = [0] * 16
    for value, output in enumerate(sbox):
        inverse[output] = value
    return tuple(inverse)


_FORWARD = tuple(_algebraic_normal_form(sbox) for sbox in _SBOXES)
_INVERSE = tuple(_algebraic_normal_form(_invert(sbox)) for sbox in _SBOXES)


def _substitute(form: tuple[tuple[int, ...], ...], words: list[int]) -> list[int]:
    monomials = [MASK32] * 16
    for monomial in range(1, 16):
        lowest = monomial & -monomial
        monomials[monomial] = monomials[monomial ^ lowest] & words[lowest.bit_length() - 1]
    output = []
    for terms in form:
        value = 0
        for monomial in terms:
            value ^= monomials[monomial]
        output.append(value)
    return output


def _linear(x0: int, x1: int, x2: int, x3: int) -> list[int]:
    x0 = rotl32(x0, 13)
    x2 = rotl32(x2, 3)
    x1 ^= x0 ^ x2
    x3 ^= x2 ^ ((x0 << 3) & MASK32)
    x1 = rotl32(x1, 1)
    x3 = rotl32(x3, 7)
    x0 ^= x1 ^ x3
    x2 ^= x3 ^ ((x1 << 7) & MASK32)
    return [rotl32(x0, 5), x1, rotl32(x2, 22), x3]


def _inverse_linear(x0: int, x1: int, x2: int, x3: int) -> list[int]:
    x2 = rotr32(x2, 22)
    x0 = rotr32(x0, 5)
    x2 ^= x3 ^ ((x1 << 7) & MASK32)
    x0 ^= x1 ^ x3
    x3 = rotr32(x3, 7)
    x1 = rotr32(x1, 1)
    x3 ^= x2 ^ ((x0 << 3) & MASK32)
    x1 ^= x0 ^ x2
    return [rotr32(x0, 13), x1, rotr32(x2, 3), x3]


def _expand_key(key: bytes) -> list[list[int]]:
    padded = key + (b"\x01" + bytes(31 - len(key)) if len(key) < 32 else b"")
    prekeys = list(struct.unpack("<8I", padded))
    for index in range(132):
        prekeys.append(
            rotl32(
                prekeys[index]
                ^ prekeys[index + 3]
                ^ prekeys[index + 5]
                ^ prekeys[index + 7]
                ^ _PHI
                ^ index,
                11,
            )
        )
    words = prekeys[8:]
    return [
        _substitute(_FORWARD[(3 - index) % 8], words[4 * index : 4 * index + 4])
        for index in range(33)
    ]


def _encrypt_block(subkeys: list[list[int]], block: bytes) -> bytes:
    state = list(struct.unpack("<4I", block))
    for round_index in range(32):
        state = [word ^ key for word, key in zip(state, subkeys[round_index])]
        state = _substitute(_FORWARD[round_index % 8], state)
        if round_index < 31:
            state = _linear(*state)
    state = [word ^ key for word, key in zip(state, subkeys[32])]
    return struct.pack("<4I", *state)


def _decrypt_block(subkeys: list[list[int]], block: bytes) -> bytes:
    state = [word ^ key for word, key in zip(struct.unpack("<4I", block), subkeys[32])]
    for round_index in range(31, -1, -1):
        if round_index < 31:
            state = _inverse_linear(*state)
        state = _substitute(_INVERSE[round_index % 8], state)
        state = [word ^ key for word, key in zip(state, subkeys[round_index])]
    return struct.pack("<4I", *state)
