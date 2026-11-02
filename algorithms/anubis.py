"""Anubis encryption, implemented in pure Python (OpenSSL has no Anubis).

Implements the "tweaked" Anubis from the NESSIE submission: big-endian words,
128- to 320-bit keys in 32-bit steps, and 8 + key_words rounds.
"""

from __future__ import annotations

import random
import struct

from algorithms._bits import gf_multiply
from algorithms._block_cipher import Transform, block_transform
from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes

BLOCK_SIZE = 16
KEY_LENGTHS = tuple(range(16, 41, 4))


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 40)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Anubis keys must be 16 to 40 bytes in steps of 4.")


def _transform(key: bytes) -> Transform:
    encryption_keys, decryption_keys = _expand_key(key)
    return block_transform(
        lambda block: _crypt_block(encryption_keys, block),
        lambda block: _crypt_block(decryption_keys, block),
        BLOCK_SIZE,
    )


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)


# The tweaked, involutional Anubis S-box.
_SBOX = bytes.fromhex(
    "ba542f7453d3d24d50ac8dbf70529a4cead597d133515ba6de48a899db32b7fc"
    "e39e919be2bb416ea5cb6b95a1f3b102ccc41d14c363da5d5fdc7dcd7f5a6c5c"
    "f726ffede89d6f8e19a0f0890f07affb08150d040164df7679dd3d163f376d38"
    "b973e93555717b8c7288f62a3e5e27460c65686103c157d6d958d866d73ac83c"
    "fa96a798ecb8c7ae694baba9670a47f2b522e5eebe2b8112831b0e23f54521ce"
    "492cf9e6b62817821a8bfe8a09c9874ee12ee4e0eb90a41e85600025f4f1940b"
    "e775ef3431d4d0867eadfd29303b9ff8c6130605c511777c7a78361c39591856"
    "b3b02420b292a3c0446210b4844393c24abd8f2dbc9c6a40cfa2804f1fcaaa42"
)
_POLYNOMIAL = 0x11D  # x^8 + x^4 + x^3 + x^2 + 1
# theta multiplies by the Hadamard matrix had(1, 2, 4, 6); omega uses (1, 2, 6, 8).
_HADAMARD = ((1, 2, 4, 6), (2, 1, 6, 4), (4, 6, 1, 2), (6, 4, 2, 1))
_VANDERMONDE = (1, 2, 6, 8)


def _word(factors: tuple[int, ...], value: int) -> int:
    return int.from_bytes(bytes(gf_multiply(factor, value, _POLYNOMIAL) for factor in factors), "big")


# _ROUND[i][x] combines gamma and theta for state word i; _SUBSTITUTE spreads S[x]
# over all four bytes; _OMEGA[x] is the key-extraction product for byte x.
_ROUND = tuple(tuple(_word(row, _SBOX[value]) for value in range(256)) for row in _HADAMARD)
_SUBSTITUTE = tuple(_SBOX[value] * 0x01010101 for value in range(256))
_OMEGA = tuple(_word(_VANDERMONDE, value) for value in range(256))
_BYTE_MASKS = (0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF)
_ROUND_CONSTANTS = tuple(
    int.from_bytes(_SBOX[4 * index : 4 * index + 4], "big") for index in range(18)
)


def _byte(word: int, position: int) -> int:
    return (word >> (24 - 8 * position)) & 0xFF


def _extract_round_key(kappa: list[int]) -> list[int]:
    """omega(gamma(kappa)) transposed into a 4x4 round key."""
    round_key = [_SUBSTITUTE[_byte(kappa[-1], column)] for column in range(4)]
    for word in reversed(kappa[:-1]):
        for column in range(4):
            mixed = _SUBSTITUTE[_byte(word, column)]
            for position, mask in enumerate(_BYTE_MASKS):
                mixed ^= _OMEGA[_byte(round_key[column], position)] & mask
            round_key[column] = mixed
    return round_key


def _expand_key(key: bytes) -> tuple[list[list[int]], list[list[int]]]:
    count = len(key) // 4
    rounds = 8 + count
    kappa = list(struct.unpack(f">{count}I", key))
    encryption_keys = []
    for round_index in range(rounds + 1):
        encryption_keys.append(_extract_round_key(kappa))
        if round_index == rounds:
            break
        kappa = [
            _ROUND[0][_byte(kappa[index], 0)]
            ^ _ROUND[1][_byte(kappa[(index - 1) % count], 1)]
            ^ _ROUND[2][_byte(kappa[(index - 2) % count], 2)]
            ^ _ROUND[3][_byte(kappa[(index - 3) % count], 3)]
            for index in range(count)
        ]
        kappa[0] ^= _ROUND_CONSTANTS[round_index]

    # Decryption reuses the cipher with K'0 = K^R, K'R = K^0, K'r = theta(K^(R-r)).
    # S is an involution, so _ROUND[i][S[x]] is theta alone.
    decryption_keys = [encryption_keys[rounds]]
    for round_index in range(1, rounds):
        decryption_keys.append(
            [
                _ROUND[0][_SBOX[_byte(word, 0)]]
                ^ _ROUND[1][_SBOX[_byte(word, 1)]]
                ^ _ROUND[2][_SBOX[_byte(word, 2)]]
                ^ _ROUND[3][_SBOX[_byte(word, 3)]]
                for word in encryption_keys[rounds - round_index]
            ]
        )
    decryption_keys.append(encryption_keys[0])
    return encryption_keys, decryption_keys


def _crypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    state = [word ^ key for word, key in zip(struct.unpack(">4I", block), round_keys[0])]
    for round_key in round_keys[1:-1]:
        state = [
            _ROUND[0][_byte(state[0], column)]
            ^ _ROUND[1][_byte(state[1], column)]
            ^ _ROUND[2][_byte(state[2], column)]
            ^ _ROUND[3][_byte(state[3], column)]
            ^ round_key[column]
            for column in range(4)
        ]
    final = [
        (
            (_ROUND[0][_byte(state[0], column)] & 0xFF000000)
            ^ (_ROUND[1][_byte(state[1], column)] & 0x00FF0000)
            ^ (_ROUND[2][_byte(state[2], column)] & 0x0000FF00)
            ^ (_ROUND[3][_byte(state[3], column)] & 0x000000FF)
        )
        ^ round_keys[-1][column]
        for column in range(4)
    ]
    return struct.pack(">4I", *final)
