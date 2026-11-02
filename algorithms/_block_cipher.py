"""Shared mode, IV, and padding handling for the 128-bit block ciphers.

Every cipher module provides a *transform*: a function that runs raw ECB, CBC,
or CTR over data whose padding has already been handled here. OpenSSL-backed
ciphers build one with ``openssl_transform``; pure-Python ciphers build one
from single-block functions with ``block_transform``.
"""

from __future__ import annotations

import os
import random
from typing import Any, Callable

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes

SUPPORTED_MODES = ("ECB", "CBC", "CTR")

BlockFunction = Callable[[bytes], bytes]
Transform = Callable[[str, "bytes | None", bytes, bool], bytes]


def generate_bytes(rng: random.Random | None, length: int) -> bytes:
    return rng.randbytes(length) if rng is not None else os.urandom(length)


def _normalize(mode: str, iv: bytes | None, block_size: int) -> tuple[str, bytes | None]:
    normalized_mode = mode.upper()
    if normalized_mode not in SUPPORTED_MODES:
        raise ValueError(f"Unsupported mode {mode!r}; choose ECB, CBC, or CTR.")
    if normalized_mode == "ECB":
        if iv is not None:
            raise ValueError("ECB mode does not use an IV.")
        return normalized_mode, None

    if iv is None:
        iv = os.urandom(block_size)
    if len(iv) != block_size:
        raise ValueError(f"{normalized_mode} mode requires an IV of {block_size} bytes.")
    return normalized_mode, iv


def _xor(left: bytes, right: bytes) -> bytes:
    return (int.from_bytes(left, "big") ^ int.from_bytes(right, "big")).to_bytes(
        len(left), "big"
    )


def ctr_xor(
    encrypt_blocks: BlockFunction, block_size: int, iv: bytes, data: bytes
) -> bytes:
    """CTR mode from an ECB primitive; the whole IV is a big-endian counter."""
    block_count = -(-len(data) // block_size)
    start = int.from_bytes(iv, "big")
    modulus = 1 << (8 * block_size)
    counters = b"".join(
        ((start + index) % modulus).to_bytes(block_size, "big")
        for index in range(block_count)
    )
    keystream = encrypt_blocks(counters)[: len(data)]
    return _xor(data, keystream)


def openssl_transform(factory: Any, key: bytes, block_size: int) -> Transform:
    """Transform backed by OpenSSL through the ``cryptography`` package.

    ``cryptography`` does not expose CTR for every cipher OpenSSL implements,
    so CTR falls back to OpenSSL's ECB plus ``ctr_xor`` when needed.
    """
    algorithm = factory(key)

    def ecb_encrypt(data: bytes) -> bytes:
        encryptor = Cipher(algorithm, modes.ECB()).encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def transform(mode: str, iv: bytes | None, data: bytes, encrypting: bool) -> bytes:
        if mode == "ECB":
            cipher = Cipher(algorithm, modes.ECB())
        elif mode == "CBC":
            cipher = Cipher(algorithm, modes.CBC(iv))
        else:
            cipher = Cipher(algorithm, modes.CTR(iv))
        try:
            context = cipher.encryptor() if encrypting else cipher.decryptor()
        except UnsupportedAlgorithm:
            if mode != "CTR":
                raise
            return ctr_xor(ecb_encrypt, block_size, iv, data)
        return context.update(data) + context.finalize()

    return transform


def block_transform(
    encrypt_block: BlockFunction, decrypt_block: BlockFunction, block_size: int
) -> Transform:
    """Transform for a pure-Python cipher given its single-block functions."""

    def ecb(function: BlockFunction, data: bytes) -> bytes:
        return b"".join(
            function(data[offset : offset + block_size])
            for offset in range(0, len(data), block_size)
        )

    def transform(mode: str, iv: bytes | None, data: bytes, encrypting: bool) -> bytes:
        if mode == "CTR":
            return ctr_xor(lambda blocks: ecb(encrypt_block, blocks), block_size, iv, data)
        if mode == "ECB":
            return ecb(encrypt_block if encrypting else decrypt_block, data)

        output = []
        previous = iv
        for offset in range(0, len(data), block_size):
            block = data[offset : offset + block_size]
            if encrypting:
                previous = encrypt_block(_xor(block, previous))
                output.append(previous)
            else:
                output.append(_xor(decrypt_block(block), previous))
                previous = block
        return b"".join(output)

    return transform


def encrypt(
    transform: Transform, block_size: int, plaintext: str, mode: str, iv: bytes | None
) -> bytes:
    normalized_mode, iv = _normalize(mode, iv, block_size)
    data = plaintext.encode("utf-8")
    if normalized_mode != "CTR":
        padder = padding.PKCS7(block_size * 8).padder()
        data = padder.update(data) + padder.finalize()
    return transform(normalized_mode, iv, data, True)


def decrypt(
    transform: Transform, block_size: int, ciphertext: bytes, mode: str, iv: bytes | None
) -> bytes:
    normalized_mode, iv = _normalize(mode, iv, block_size)
    if normalized_mode != "CTR" and (not ciphertext or len(ciphertext) % block_size):
        raise ValueError(f"Ciphertext must be a non-empty multiple of {block_size} bytes.")
    data = transform(normalized_mode, iv, ciphertext, False)
    if normalized_mode != "CTR":
        unpadder = padding.PKCS7(block_size * 8).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
    return data
