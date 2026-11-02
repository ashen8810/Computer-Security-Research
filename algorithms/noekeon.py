"""Noekeon encryption, implemented in pure Python (OpenSSL has no Noekeon).

Follows the NESSIE submission in indirect-key mode (the working key is the
cipher key encrypted under the all-zero key), with big-endian words.
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
KEY_LENGTHS = (16,)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 16)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Noekeon keys must be 16 bytes.")


def _transform(key: bytes) -> Transform:
    encryption_key, decryption_key = _expand_key(key)
    return block_transform(
        lambda block: _pack(_encrypt_words(encryption_key, _unpack(block))),
        lambda block: _pack(_decrypt_words(decryption_key, _unpack(block))),
        BLOCK_SIZE,
    )


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)


_ROUND_CONSTANTS = (
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F,
    0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4,
)
_NULL_KEY = (0, 0, 0, 0)

Words = tuple[int, int, int, int]


def _unpack(block: bytes) -> Words:
    return struct.unpack(">4I", block)


def _pack(words: Words) -> bytes:
    return struct.pack(">4I", *words)


def _theta(key: Words, words: Words) -> Words:
    a0, a1, a2, a3 = words
    temp = a0 ^ a2
    temp ^= rotr32(temp, 8) ^ rotl32(temp, 8)
    a1 ^= temp
    a3 ^= temp
    a0, a1, a2, a3 = a0 ^ key[0], a1 ^ key[1], a2 ^ key[2], a3 ^ key[3]
    temp = a1 ^ a3
    temp ^= rotr32(temp, 8) ^ rotl32(temp, 8)
    return a0 ^ temp, a1, a2 ^ temp, a3


def _pi_gamma_pi(words: Words) -> Words:
    """Pi1, then the nonlinear Gamma, then Pi2."""
    a0, a1, a2, a3 = words
    a1, a2, a3 = rotl32(a1, 1), rotl32(a2, 5), rotl32(a3, 2)
    a1 ^= ~(a3 | a2) & MASK32
    a0 ^= a2 & a1
    a0, a3 = a3, a0
    a2 ^= a0 ^ a1 ^ a3
    a1 ^= ~(a3 | a2) & MASK32
    a0 ^= a2 & a1
    return a0, rotr32(a1, 1), rotr32(a2, 5), rotr32(a3, 2)


def _encrypt_words(key: Words, words: Words) -> Words:
    for constant in _ROUND_CONSTANTS[:16]:
        words = (words[0] ^ constant, *words[1:])
        words = _pi_gamma_pi(_theta(key, words))
    words = (words[0] ^ _ROUND_CONSTANTS[16], *words[1:])
    return _theta(key, words)


def _decrypt_words(key: Words, words: Words) -> Words:
    for constant in reversed(_ROUND_CONSTANTS[1:]):
        words = _theta(key, words)
        words = _pi_gamma_pi((words[0] ^ constant, *words[1:]))
    words = _theta(key, words)
    return (words[0] ^ _ROUND_CONSTANTS[0], *words[1:])


def _expand_key(key: bytes) -> tuple[Words, Words]:
    encryption_key = _encrypt_words(_NULL_KEY, _unpack(key))
    return encryption_key, _theta(_NULL_KEY, encryption_key)
