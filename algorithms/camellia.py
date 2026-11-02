"""Camellia encryption using the cryptography package."""

from __future__ import annotations

import random

from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from algorithms._block_cipher import generate_bytes

BLOCK_SIZE = 16
KEY_LENGTHS = (16, 24, 32)


def generate_key(rng: random.Random | None = None) -> bytes:
    return generate_bytes(rng, 32)


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_LENGTHS:
        raise ValueError("Camellia keys must be 16, 24, or 32 bytes.")


def _cipher(key: bytes, mode: str, iv: bytes | None) -> Cipher:
    normalized_mode = mode.upper()
    if normalized_mode not in ("ECB", "CBC", "CTR"):
        raise ValueError(f"Unsupported mode {mode!r}; choose ECB, CBC, or CTR.")
    if normalized_mode == "ECB":
        if iv is not None:
            raise ValueError("ECB mode does not use an IV.")
        cipher_mode = modes.ECB()
    else:
        if iv is None:
            iv = generate_bytes(None, BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"{normalized_mode} mode requires an IV of {BLOCK_SIZE} bytes.")
        if normalized_mode == "CTR":
            raise ValueError("Camellia CTR uses the dedicated counter transform.")
        cipher_mode = modes.CBC(iv)
    return Cipher(Camellia(key), cipher_mode)


def _counter_transform(data: bytes, key: bytes, iv: bytes | None) -> bytes:
    if iv is None:
        iv = generate_bytes(None, BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"CTR mode requires an IV of {BLOCK_SIZE} bytes.")
    encryptor = Cipher(Camellia(key), modes.ECB()).encryptor()
    counter = int.from_bytes(iv, byteorder="big")
    maximum_counter = (1 << (BLOCK_SIZE * 8)) - 1
    transformed = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        if counter > maximum_counter:
            raise ValueError("Camellia CTR counter overflow.")
        counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
        key_stream = encryptor.update(counter_block)
        block = data[offset : offset + BLOCK_SIZE]
        transformed.extend(left ^ right for left, right in zip(block, key_stream))
        counter += 1
    encryptor.finalize()
    return bytes(transformed)


def encrypt(plaintext: str, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    normalized_mode = mode.upper()
    data = plaintext.encode("utf-8")
    if normalized_mode == "CTR":
        return _counter_transform(data, key, iv)
    encryptor = _cipher(key, normalized_mode, iv).encryptor()
    if normalized_mode in ("ECB", "CBC"):
        padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
        data = padder.update(data) + padder.finalize()
    return encryptor.update(data) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    _validate_key(key)
    normalized_mode = mode.upper()
    if normalized_mode == "CTR":
        return _counter_transform(ciphertext, key, iv)
    decryptor = _cipher(key, normalized_mode, iv).decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    if normalized_mode in ("ECB", "CBC"):
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
    return data
