"""Blowfish encryption using PyCryptodome (for research compatibility only)."""

from __future__ import annotations

import random

from Crypto.Cipher import Blowfish

from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes

BLOCK_SIZE = Blowfish.block_size
KEY_LENGTHS = tuple(range(4, 57))


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 32)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Blowfish keys must be between 4 and 56 bytes.")


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(Blowfish, BLOCK_SIZE, plaintext, key, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(Blowfish, BLOCK_SIZE, ciphertext, key, mode, iv)
