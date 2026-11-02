"""Unit tests for each independent cipher and the generated dataset."""

from __future__ import annotations

import base64
import csv
import random
import tempfile
import unittest
from pathlib import Path

from algorithms import aes, blowfish, camellia, des, triple_des
from runner import ALGORITHM_REGISTRY, CSV_COLUMNS, generate_dataset

MODULES = (aes, des, triple_des, blowfish, camellia)


class AlgorithmTests(unittest.TestCase):
    def test_each_algorithm_round_trips_all_modes(self) -> None:
        for module in MODULES:
            with self.subTest(algorithm=module.__name__):
                key = module.generate_key(random.Random(1234))
                for mode in ("ECB", "CBC", "CTR"):
                    iv = None if mode == "ECB" else bytes(module.BLOCK_SIZE)
                    ciphertext = module.encrypt("Variable-length test! 123", key, mode, iv)
                    self.assertTrue(ciphertext)
                    if mode == "CTR":
                        self.assertEqual(len(ciphertext), len("Variable-length test! 123"))
                    self.assertEqual(
                        module.decrypt(ciphertext, key, mode, iv),
                        b"Variable-length test! 123",
                    )

    def test_mode_key_and_iv_validation(self) -> None:
        with self.assertRaises(ValueError):
            aes.encrypt("text", b"short", "CBC", bytes(aes.BLOCK_SIZE))
        with self.assertRaises(ValueError):
            aes.encrypt("text", aes.generate_key(random.Random(1)), "OFB")
        with self.assertRaises(ValueError):
            des.encrypt("text", des.generate_key(random.Random(1)), "CBC", b"short")
        with self.assertRaises(ValueError):
            aes.encrypt("text", aes.generate_key(random.Random(1)), "ECB", b"unexpected")

    def test_modes_generate_iv_when_omitted(self) -> None:
        key = aes.generate_key(random.Random(7))
        for mode in ("CBC", "CTR"):
            ciphertext = aes.encrypt("generated IV", key, mode)
            self.assertTrue(ciphertext)


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
