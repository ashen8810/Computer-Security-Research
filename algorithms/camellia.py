"""Camellia encryption using OpenSSL (via the cryptography package).

The cryptography package exposes only ECB and CBC for Camellia, so CTR is built
from OpenSSL's Camellia-ECB in algorithms._block_cipher.
"""

from __future__ import annotations

import random

from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia

from algorithms._block_cipher import Transform
from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt
from algorithms._block_cipher import generate_bytes
from algorithms._block_cipher import openssl_transform

BLOCK_SIZE = Camellia.block_size // 8
KEY_LENGTHS = (16, 24, 32)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 32)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Camellia keys must be 16, 24, or 32 bytes.")


def _transform(key: bytes) -> Transform:
    return openssl_transform(Camellia, key, BLOCK_SIZE)


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(_transform(key), BLOCK_SIZE, plaintext, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(_transform(key), BLOCK_SIZE, ciphertext, mode, iv)
