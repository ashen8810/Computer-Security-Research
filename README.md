# Encryption Dataset Generator

This project creates a reproducible CSV dataset of synthetic plaintext and
ciphertext samples from 15 block ciphers with a 128-bit block size. Each
cipher has its own module in `algorithms/`, and every cipher supports ECB,
CBC, and CTR. CBC/ECB use PKCS#7 padding to the 16-byte block; CTR encrypts
the original bytes without padding, so its ciphertext is the plaintext length.

| Group | Algorithm | Family | Key sizes (bits) | Implementation |
| --- | --- | --- | --- | --- |
| 1 | AES | SPN | 128/192/256 | OpenSSL (cryptography) |
| 1 | Camellia | Feistel | 128/192/256 | OpenSSL (cryptography)\* |
| 1 | SM4 | Unbalanced Feistel | 128 | OpenSSL (cryptography) |
| 1 | SEED | Feistel | 128 | OpenSSL (cryptography)\* |
| 1 | ARIA | SPN | 128/192/256 | OpenSSL (libcrypto via ctypes) |
| 2 | Serpent | SPN | 128/192/256 | Pure Python |
| 2 | Twofish | Feistel | 128/192/256 | Pure Python |
| 2 | RC6 | Generalized Feistel / ARX | 128/192/256 | Pure Python |
| 2 | CAST-256 | Generalized Feistel | 128/160/192/224/256 | Pure Python |
| 2 | Kuznyechik | SPN | 256 | Pure Python |
| 3 | MARS | Generalized / heterogeneous Feistel | 128–448 (step 32) | Pure Python |
| 3 | CLEFIA | Generalized Feistel (Type-2) | 128/192/256 | Pure Python |
| 3 | LEA | ARX | 128/192/256 | Pure Python |
| 3 | Anubis | SPN (involutional) | 128–320 (step 32) | Pure Python |
| 3 | Noekeon | SPN | 128 | Pure Python |

OpenSSL is used for every cipher it implements. The `cryptography` package
exposes only ECB and CBC for the ciphers marked \*, so their CTR mode is built
from OpenSSL's ECB (identical output to OpenSSL's native CTR). ARIA is not
exposed by `cryptography` at all, so `algorithms/_libcrypto.py` calls the
system OpenSSL 3+ EVP API directly. The remaining ten ciphers are not in
OpenSSL and are implemented in pure Python; each is checked against its
published test vectors (see Tests).

Generated keys use each cipher's largest key size. The CTR counter is the
full 16-byte IV, incremented as a big-endian integer.

> These implementations are for academic comparison only and are not
> constant-time. A seeded run uses Python's deterministic pseudo-random
> generator for keys and IVs to make a dataset reproducible; these generated
> keys are not suitable for real-world encryption.

## Install

Python 3.10 or later and an OpenSSL 3.0+ `libcrypto` (for ARIA) are required.

```powershell
python -m pip install -r requirements.txt
```

`libcrypto` is located automatically on macOS and Linux. If it is not found
(commonly on Windows), set `OPENSSL_LIBCRYPTO` to the library's full path,
for example `C:\Program Files\OpenSSL-Win64\libcrypto-3-x64.dll`.

## Generate a dataset

```powershell
python runner.py --output datasets/encryption_dataset.csv --seed 42
```

`SAMPLES_PER_MODE` in `runner.py` defaults to 200. This creates 200 records
for every algorithm/mode combination (9,000 total for all fifteen algorithms).
Each plaintext is reused across all selected algorithms and modes. Override
the default using `--samples`; the value still means samples per combination.

Choose a subset of algorithms with their registry names:

```powershell
python runner.py --samples 20 --algorithms AES,Serpent,CAST-256 --seed 42
```

Omit `--seed` to generate a different dataset each run. The generator validates
the schema, key and IV representation, Base64 ciphertext, and plaintext
recovery before writing the CSV. The CSV columns are exactly `Algorithm`,
`Family`, `Mode`, `Original text`, `Key`, `Cipher Text`, and `IV`. Keys and IVs
are hexadecimal; ciphertext is Base64; ECB IV fields are empty.

## Add an algorithm

Create a module under `algorithms/` with `BLOCK_SIZE`, `KEY_LENGTHS`,
`generate_key(rng)`, `encrypt(plaintext, key, mode, iv)`, and
`decrypt(ciphertext, key, mode, iv)`, following `aes.py`. Each module's
`_transform(key)` supplies the raw cipher to the shared helpers in
`algorithms._block_cipher`, which handle modes, IVs, and padding:

- `openssl_transform` for ciphers the `cryptography` package exposes,
- `algorithms._libcrypto.evp_transform` for other OpenSSL ciphers,
- `block_transform` for pure-Python single-block encrypt/decrypt functions.

Register the module and its accurate family and supported modes in
`runner.py`, and add a known-answer vector to `tests/test_algorithms.py`.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The tests check one published known-answer vector per cipher, round trips in
every mode and key size, CTR counter wrap-around, input validation, and the
dataset's schema, balance, and reproducibility.
