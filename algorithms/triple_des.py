"""Triple DES encryption using PyCryptodome (for research compatibility only)."""

from __future__ import annotations

import random

from Crypto.Cipher import DES3

from algorithms._block_cipher import decrypt as _decrypt
from algorithms._block_cipher import encrypt as _encrypt

BLOCK_SIZE = DES3.block_size
KEY_LENGTHS = (16, 24)


def generate_key(rng: random.Random | None = None) -> bytes:
    source = rng or random.Random()
    while True:
        candidate = DES3.adjust_key_parity(source.randbytes(24))
        try:
            DES3.new(candidate, DES3.MODE_ECB)
        except ValueError:
            continue
        return candidate


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Triple DES keys must be 16 or 24 bytes.")
    try:
        DES3.new(key, DES3.MODE_ECB)
    except ValueError as error:
        raise ValueError("Triple DES key is weak or degenerate.") from error


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _encrypt(DES3, BLOCK_SIZE, plaintext, key, mode, iv)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    return _decrypt(DES3, BLOCK_SIZE, ciphertext, key, mode, iv)
