"""Word rotation and GF(2^8) helpers shared by the pure-Python ciphers."""

from __future__ import annotations

MASK32 = 0xFFFFFFFF


def rotl32(value: int, amount: int) -> int:
    amount &= 31
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def rotr32(value: int, amount: int) -> int:
    return rotl32(value, 32 - (amount & 31))


def gf_multiply(left: int, right: int, polynomial: int) -> int:
    """Multiply two GF(2^8) elements modulo ``polynomial`` (including x^8)."""
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        if left & 0x100:
            left ^= polynomial
        right >>= 1
    return product


def gf_table(constant: int, polynomial: int) -> tuple[int, ...]:
    """Products ``constant * x`` for every byte ``x``."""
    return tuple(gf_multiply(constant, value, polynomial) for value in range(256))
