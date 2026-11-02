"""Shared mode, IV, and padding handling for PyCryptodome block ciphers."""

from __future__ import annotations

import random
from typing import Any

from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

SUPPORTED_MODES = ("ECB", "CBC", "CTR")


def generate_bytes(rng: random.Random | None, length: int) -> bytes:
    return rng.randbytes(length) if rng is not None else get_random_bytes(length)


def _cipher(factory: Any, key: bytes, mode: str, iv: bytes | None, block_size: int) -> Any:
    normalized_mode = mode.upper()
    if normalized_mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode {mode!r}; choose ECB, CBC, or CTR.")
    if normalized_mode == "ECB":
        if iv is not None:
            raise ValueError("ECB mode does not use an IV.")
        return factory.new(key, factory.MODE_ECB)

    if iv is None:
        iv = get_random_bytes(block_size)
    if len(iv) != block_size:
        raise ValueError(f"{normalized_mode} mode requires an IV of {block_size} bytes.")
    if normalized_mode == "CBC":
        return factory.new(key, factory.MODE_CBC, iv=iv)
    return factory.new(
        key,
        factory.MODE_CTR,
        nonce=b"",
        initial_value=int.from_bytes(iv, byteorder="big"),
    )


def encrypt(
    factory: Any, block_size: int, plaintext: str, key: bytes, mode: str, iv: bytes | None
) -> bytes:
    cipher = _cipher(factory, key, mode, iv, block_size)
    data = plaintext.encode("utf-8")
    if mode.upper() in ("ECB", "CBC"):
        data = pad(data, block_size)
    return cipher.encrypt(data)


def decrypt(
    factory: Any, block_size: int, ciphertext: bytes, key: bytes, mode: str, iv: bytes | None
) -> bytes:
    cipher = _cipher(factory, key, mode, iv, block_size)
    data = cipher.decrypt(ciphertext)
    if mode.upper() in ("ECB", "CBC"):
        data = unpad(data, block_size)
    return data
