"""DES encryption using PyCryptodome (for research compatibility only)."""

from __future__ import annotations

import random

from Crypto.Cipher import DES

from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes

BLOCK_SIZE = DES.block_size
KEY_LENGTHS = (8,)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 8)


def _validate_key(key: bytes) -> None:
    if len(key) != 8:
        raise ValueError("DES keys must be 8 bytes.")


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(DES, BLOCK_SIZE, plaintext, key, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(DES, BLOCK_SIZE, ciphertext, key, mode, iv)
