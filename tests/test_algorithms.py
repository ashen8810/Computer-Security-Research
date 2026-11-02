"""Tests for each block cipher module and the generated dataset."""

from __future__ import annotations

import base64
import csv
import random
import tempfile
import unittest
from pathlib import Path

from algorithms import (
    aes,
    anubis,
    aria,
    camellia,
    cast256,
    clefia,
    kuznyechik,
    lea,
    mars,
    noekeon,
    rc6,
    seed,
    serpent,
    sm4,
    twofish,
)
from runner import ALGORITHM_REGISTRY, CSV_COLUMNS, generate_dataset

MODULES = (
    aes, camellia, sm4, seed, aria, serpent, twofish, rc6,
    cast256, kuznyechik, mars, clefia, lea, anubis, noekeon,
)

# One single-block ECB vector per cipher (key, plaintext, ciphertext), from
# the algorithm's standard/RFC or the Botan/Crypto++ known-answer suites.
KNOWN_ANSWERS = {
    aes: (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    ),
    camellia: (
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
    ),
    sm4: (
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246",
    ),
    seed: (
        "00000000000000000000000000000000",
        "000102030405060708090a0b0c0d0e0f",
        "5ebac6e0054e166819aff1cc6d346cdb",
    ),
    aria: (
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "d718fbd6ab644c739da95f3be6451778",
    ),
    serpent: (
        "0000000000000000000000000000000000000000000000000000000000000080",
        "00000000000000000000000000000000",
        "1908ef821ad2ebc0cb28bf66e796edab",
    ),
    twofish: (
        "57ff739d4dc92c1bd7fc01700cc8216f00000000000000000000000000000000",
        "d43bb7556ea32e46f2a282b7d45b4e0d",
        "90afe91bb288544f2c32dc239b2635e6",
    ),
    rc6: (
        "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe",
        "02132435465768798a9bacbdcedfe0f1",
        "c8241816f0d7e48920ad16a1674e5d48",
    ),
    cast256: (
        "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
        "00000000000000000000000000000000",
        "4f6a2038286897b9c9870136553317fa",
    ),
    kuznyechik: (
        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        "1122334455667700ffeeddccbbaa9988",
        "7f679d90bebc24305a468d42b9d4edcd",
    ),
    mars: (
        "fba167983e7aef22317ce28c02aae1a3e8e5cc3cedbea82a99dbc39ad65e7227",
        "1344aba4d3c44708a8a72116d4f49384",
        "458335d95ea42a9f4dccd41aecc2390d",
    ),
    clefia: (
        "ffeeddccbbaa99887766554433221100f0e0d0c0b0a090807060504030201000",
        "000102030405060708090a0b0c0d0e0f",
        "a1397814289de80c10da46d1fa48b38a",
    ),
    lea: (
        "4f6779e2bd1e9319c63015acffefd7a791f0ed59df1b700769fe82e2f0668c35",
        "dc31cae3da5e0a11c966b020d7cffede",
        "eda2042098f667e857a02db8caa7dff2",
    ),
    anubis: (
        "35353535353535353535353535353535353535353535353535353535353535353535353535353535",
        "35353535353535353535353535353535",
        "a52c856f9cbaa0979ec6840f172107ee",
    ),
    noekeon: (
        "ba6933819299c71699a99f08f678178b",
        "52f88a7b283c1f7bdf7b6faa5011c7d8",
        "5096f2bfc82ae6e2d9495515c277fa70",
    ),
}


class AlgorithmTests(unittest.TestCase):
    def test_each_algorithm_matches_known_answer(self) -> None:
        self.assertEqual(set(KNOWN_ANSWERS), set(MODULES))
        for module, (key, plaintext, ciphertext) in KNOWN_ANSWERS.items():
            with self.subTest(algorithm=module.__name__):
                transform = module._transform(bytes.fromhex(key))
                self.assertEqual(
                    transform("ECB", None, bytes.fromhex(plaintext), True).hex(), ciphertext
                )
                self.assertEqual(
                    transform("ECB", None, bytes.fromhex(ciphertext), False).hex(), plaintext
                )

    def test_each_algorithm_round_trips_all_modes(self) -> None:
        for module in MODULES:
            with self.subTest(algorithm=module.__name__):
                self.assertEqual(module.BLOCK_SIZE, 16)
                key = module.generate_key(random.Random(1234))
                for mode in ("ECB", "CBC", "CTR"):
                    iv = None if mode == "ECB" else bytes(module.BLOCK_SIZE)
                    ciphertext = module.encrypt("Variable-length test! 123", key, mode, iv)
                    self.assertTrue(ciphertext)
                    if mode == "CTR":
                        self.assertEqual(len(ciphertext), len("Variable-length test! 123"))
                    else:
                        self.assertEqual(len(ciphertext) % module.BLOCK_SIZE, 0)
                    self.assertEqual(
                        module.decrypt(ciphertext, key, mode, iv),
                        b"Variable-length test! 123",
                    )

    def test_every_supported_key_length_round_trips(self) -> None:
        for module in MODULES:
            for length in module.KEY_LENGTHS:
                with self.subTest(algorithm=module.__name__, key_length=length):
                    key = random.Random(length).randbytes(length)
                    iv = bytes(range(16))
                    ciphertext = module.encrypt("key length check", key, "CBC", iv)
                    self.assertEqual(
                        module.decrypt(ciphertext, key, "CBC", iv), b"key length check"
                    )

    def test_ctr_counter_spans_the_whole_block(self) -> None:
        # The counter wraps from all-ones to zero across the full 128 bits.
        for module in (camellia, serpent):
            with self.subTest(algorithm=module.__name__):
                key = module.generate_key(random.Random(5))
                iv = b"\xff" * 16
                ciphertext = module.encrypt("x" * 32, key, "CTR", iv)
                keystream = module._transform(key)("ECB", None, bytes(16), True)
                self.assertEqual(
                    ciphertext[16:], bytes(byte ^ ord("x") for byte in keystream)
                )

    def test_mode_key_and_iv_validation(self) -> None:
        with self.assertRaises(ValueError):
            aes.encrypt("text", b"short", "CBC", bytes(aes.BLOCK_SIZE))
        with self.assertRaises(ValueError):
            aes.encrypt("text", aes.generate_key(random.Random(1)), "OFB")
        with self.assertRaises(ValueError):
            serpent.encrypt("text", serpent.generate_key(random.Random(1)), "CBC", b"short")
        with self.assertRaises(ValueError):
            aes.encrypt("text", aes.generate_key(random.Random(1)), "ECB", b"unexpected")
        with self.assertRaises(ValueError):
            kuznyechik.encrypt("text", bytes(16), "ECB")
        with self.assertRaises(ValueError):
            twofish.decrypt(b"not a whole block", twofish.generate_key(random.Random(1)), "ECB")

    def test_modes_generate_iv_when_omitted(self) -> None:
        for module in (aes, mars):
            key = module.generate_key(random.Random(7))
            for mode in ("CBC", "CTR"):
                with self.subTest(algorithm=module.__name__, mode=mode):
                    self.assertTrue(module.encrypt("generated IV", key, mode))


class DatasetTests(unittest.TestCase):
    def test_dataset_schema_balance_reproducibility_and_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            first = Path(temporary_directory) / "first.csv"
            second = Path(temporary_directory) / "second.csv"
            samples_per_mode = 2
            expected_rows = samples_per_mode * len(ALGORITHM_REGISTRY) * 3
            self.assertEqual(generate_dataset(samples_per_mode, first, 99), expected_rows)
            self.assertEqual(generate_dataset(samples_per_mode, second, 99), expected_rows)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            with first.open(newline="", encoding="utf-8") as csv_file:
                reader = csv.DictReader(csv_file)
                self.assertEqual(tuple(reader.fieldnames or ()), CSV_COLUMNS)
                rows = list(reader)
            self.assertEqual(len(rows), expected_rows)
            self.assertEqual(
                {
                    combination: sum(
                        row["Algorithm"] == combination[0]
                        and row["Mode"] == combination[1]
                        for row in rows
                    )
                    for combination in {
                        (row["Algorithm"], row["Mode"]) for row in rows
                    }
                },
                {
                    (algorithm, mode): samples_per_mode
                    for algorithm in ALGORITHM_REGISTRY
                    for mode in ("ECB", "CBC", "CTR")
                },
            )
            for row in rows:
                self.assertTrue(base64.b64decode(row["Cipher Text"], validate=True))
                self.assertEqual(bool(row["IV"]), row["Mode"] != "ECB")


if __name__ == "__main__":
    unittest.main()
