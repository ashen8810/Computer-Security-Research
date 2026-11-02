"""ARIA encryption using OpenSSL (via libcrypto's EVP API).

The cryptography package does not expose ARIA, so this module calls the
system OpenSSL directly; see algorithms._libcrypto.
"""

from __future__ import annotations

import random

from algorithms._block_cipher import Transform
from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes
from algorithms._libcrypto import evp_transform

BLOCK_SIZE = 16
KEY_LENGTHS = (16, 24, 32)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 32)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("ARIA keys must be 16, 24, or 32 bytes.")


def _transform(key: bytes) -> Transform:
    return evp_transform(lambda mode: f"ARIA-{len(key) * 8}-{mode}", key)


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)
