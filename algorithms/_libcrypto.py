"""Direct OpenSSL EVP access through ctypes for ciphers ``cryptography`` omits.

The system libcrypto (OpenSSL 3.0 or later) is located automatically. Set the
``OPENSSL_LIBCRYPTO`` environment variable to its full path to override the
search, e.g. on Windows where the DLL name varies by build.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from functools import cache
from typing import Callable

from algorithms._block_cipher import Transform

# Loading macOS's stub libcrypto aborts the process instead of raising.
_UNSAFE_LIBRARIES = {"/usr/lib/libcrypto.dylib"}
_FALLBACK_NAMES = (
    "libcrypto.so.3",
    "libcrypto-3-x64.dll",
    "libcrypto-3.dll",
    "/opt/homebrew/lib/libcrypto.dylib",
    "/usr/local/lib/libcrypto.dylib",
)


@cache
def _library() -> ctypes.CDLL:
    candidates = [os.environ.get("OPENSSL_LIBCRYPTO"), ctypes.util.find_library("crypto")]
    candidates.extend(_FALLBACK_NAMES)
    for candidate in candidates:
        if not candidate or candidate in _UNSAFE_LIBRARIES:
            continue
        try:
            library = ctypes.CDLL(candidate)
        except OSError:
            continue
        if hasattr(library, "EVP_CIPHER_fetch"):
            _declare(library)
            return library
    raise OSError(
        "OpenSSL 3+ libcrypto was not found; set OPENSSL_LIBCRYPTO to its path."
    )


def _declare(library: ctypes.CDLL) -> None:
    pointer, integer = ctypes.c_void_p, ctypes.c_int
    signatures = {
        "EVP_CIPHER_fetch": (pointer, [pointer, ctypes.c_char_p, ctypes.c_char_p]),
        "EVP_CIPHER_free": (None, [pointer]),
        "EVP_CIPHER_CTX_new": (pointer, []),
        "EVP_CIPHER_CTX_free": (None, [pointer]),
        "EVP_CipherInit_ex2": (
            integer,
            [pointer, pointer, ctypes.c_char_p, ctypes.c_char_p, integer, pointer],
        ),
        "EVP_CIPHER_CTX_set_padding": (integer, [pointer, integer]),
        "EVP_CipherUpdate": (
            integer,
            [pointer, pointer, ctypes.POINTER(integer), ctypes.c_char_p, integer],
        ),
        "EVP_CipherFinal_ex": (
            integer,
            [pointer, pointer, ctypes.POINTER(integer)],
        ),
    }
    for name, (restype, argtypes) in signatures.items():
        function = getattr(library, name)
        function.restype = restype
        function.argtypes = argtypes


def _run(cipher_name: str, key: bytes, iv: bytes | None, data: bytes, encrypting: bool) -> bytes:
    library = _library()
    cipher = library.EVP_CIPHER_fetch(None, cipher_name.encode("ascii"), None)
    if not cipher:
        raise ValueError(f"OpenSSL does not provide {cipher_name}.")
    context = library.EVP_CIPHER_CTX_new()
    try:
        if not context or not library.EVP_CipherInit_ex2(
            context, cipher, key, iv, int(encrypting), None
        ):
            raise ValueError(f"OpenSSL could not initialise {cipher_name}.")
        # Padding is applied by algorithms._block_cipher, not by OpenSSL.
        library.EVP_CIPHER_CTX_set_padding(context, 0)
        output = ctypes.create_string_buffer(len(data) + 32)
        address = ctypes.addressof(output)
        written = ctypes.c_int(0)
        final_written = ctypes.c_int(0)
        if not library.EVP_CipherUpdate(
            context, address, ctypes.byref(written), data, len(data)
        ) or not library.EVP_CipherFinal_ex(
            context, address + written.value, ctypes.byref(final_written)
        ):
            raise ValueError(f"OpenSSL {cipher_name} operation failed.")
        return output.raw[: written.value + final_written.value]
    finally:
        library.EVP_CIPHER_CTX_free(context)
        library.EVP_CIPHER_free(cipher)


def evp_transform(cipher_name: Callable[[str], str], key: bytes) -> Transform:
    """Transform that runs ``cipher_name(mode)`` (e.g. "ARIA-256-CBC") in OpenSSL."""

    def transform(mode: str, iv: bytes | None, data: bytes, encrypting: bool) -> bytes:
        return _run(cipher_name(mode), key, iv, data, encrypting)

    return transform
