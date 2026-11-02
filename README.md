# Encryption Dataset Generator

This project creates a reproducible CSV dataset of synthetic plaintext and
ciphertext samples. Each cipher has its own implementation in `algorithms/`.
AES, DES, Triple DES, Blowfish, and Camellia each support ECB, CBC, and CTR.
All block modes and algorithms are selected explicitly; CBC/ECB use PKCS#7
padding and CTR encrypts the original bytes without padding.

> DES, Triple DES, and Blowfish are included for academic comparison only.
> They are legacy ciphers and should not be used to protect real data.
> A seeded run uses Python's deterministic pseudo-random generator for keys
> and IVs to make a dataset reproducible; these generated keys are not suitable
> for real-world encryption.

## Install

Python 3.10 or later is required.

```powershell
python -m pip install -r requirements.txt
```

## Generate a dataset

```powershell
python runner.py --output datasets/encryption_dataset.csv --seed 42
```

`SAMPLES_PER_MODE` in `runner.py` defaults to 200. This creates 200 records
for every algorithm/mode combination (3,000 total for all five algorithms).
Each plaintext is reused across all selected algorithms and modes. Override
the default using `--samples`; the value still means samples per combination.

Choose a subset of algorithms with their registry names:

```powershell
python runner.py --samples 20 --algorithms AES,Camellia --seed 42
```

Omit `--seed` to generate a different dataset each run. The generator validates
the schema, key and IV representation, Base64 ciphertext, and plaintext
recovery before writing the CSV. The CSV columns are exactly `Algorithm`,
`Family`, `Mode`, `Original text`, `Key`, `Cipher Text`, and `IV`. Keys and IVs
are hexadecimal; ciphertext is Base64; ECB IV fields are empty.

## Add an algorithm

Create a module under `algorithms/` with `BLOCK_SIZE`, `generate_key(rng)`,
`encrypt(plaintext, key, mode, iv)`, and `decrypt(ciphertext, key, mode, iv)`.
Use the shared `algorithms._block_cipher` helpers when the chosen library
matches their interface. Register the module and its accurate family and
supported modes in `runner.py`.

## Tests

```powershell
python -m unittest discover -s tests -v
```
