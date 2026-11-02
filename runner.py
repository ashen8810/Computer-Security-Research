"""Generate a balanced CSV dataset of synthetic ciphertext samples."""

from __future__ import annotations

import argparse
import base64
import csv
import random
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Sequence

from algorithms import aes, blowfish, camellia, des, triple_des
from utils.data_generator import generate_plaintexts

DEFAULT_OUTPUT = Path("datasets") / "encryption_dataset.csv"
SAMPLES_PER_MODE = 200
CSV_COLUMNS = (
    "Algorithm",
    "Family",
    "Mode",
    "Original text",
    "Key",
    "Cipher Text",
    "IV",
)


@dataclass(frozen=True)
class AlgorithmSpec:
    name: str
    family: str
    module: ModuleType
    modes: tuple[str, ...]


ALGORITHM_REGISTRY: dict[str, AlgorithmSpec] = {
    "AES": AlgorithmSpec("AES", "SPN", aes, ("ECB", "CBC", "CTR")),
    "DES": AlgorithmSpec("DES", "Feistel", des, ("ECB", "CBC", "CTR")),
    "Triple DES": AlgorithmSpec(
        "Triple DES", "Feistel", triple_des, ("ECB", "CBC", "CTR")
    ),
    "Blowfish": AlgorithmSpec(
        "Blowfish", "Feistel", blowfish, ("ECB", "CBC", "CTR")
    ),
    "Camellia": AlgorithmSpec(
        "Camellia", "Feistel", camellia, ("ECB", "CBC", "CTR")
    ),
}


def _validate_records(records: Sequence[dict[str, str]]) -> None:
    seen: set[tuple[str, ...]] = set()
    for row_number, record in enumerate(records, start=2):
        if tuple(record) != CSV_COLUMNS:
            raise ValueError(f"Record {row_number} does not match the CSV schema.")
        if not all(record[column] for column in CSV_COLUMNS if column != "IV"):
            raise ValueError(f"Record {row_number} has an empty required value.")
        spec = ALGORITHM_REGISTRY.get(record["Algorithm"])
        if spec is None or record["Family"] != spec.family:
            raise ValueError(f"Record {row_number} has incorrect algorithm metadata.")
        if record["Mode"] not in spec.modes:
            raise ValueError(f"Record {row_number} has an unsupported mode.")

        key = bytes.fromhex(record["Key"])
        iv = bytes.fromhex(record["IV"]) if record["IV"] else None
        mode = record["Mode"]
        if mode == "ECB" and iv is not None:
            raise ValueError(f"Record {row_number}: ECB must not have an IV.")
        if mode != "ECB" and (iv is None or len(iv) != spec.module.BLOCK_SIZE):
            raise ValueError(f"Record {row_number} has an invalid IV length.")

        ciphertext = base64.b64decode(record["Cipher Text"], validate=True)
        if not ciphertext:
            raise ValueError(f"Record {row_number} has empty ciphertext.")
        plaintext = spec.module.decrypt(ciphertext, key, mode, iv)
        if plaintext.decode("utf-8") != record["Original text"]:
            raise ValueError(f"Record {row_number} failed decryption validation.")

        identity = tuple(record[column] for column in CSV_COLUMNS)
        if identity in seen:
            raise ValueError(f"Duplicate record found at row {row_number}.")
        seen.add(identity)


def generate_dataset(
    samples_per_mode: int,
    output: Path,
    seed: int | None = None,
    algorithm_names: Sequence[str] | None = None,
) -> int:
    """Generate an equal number of samples for each selected algorithm/mode pair."""
    if samples_per_mode <= 0:
        raise ValueError("samples_per_mode must be a positive integer.")

    selected = list(algorithm_names) if algorithm_names else list(ALGORITHM_REGISTRY)
    if not selected:
        raise ValueError("At least one algorithm must be selected.")
    if len(set(selected)) != len(selected):
        raise ValueError("Algorithm names must not contain duplicates.")
    unknown = [name for name in selected if name not in ALGORITHM_REGISTRY]
    if unknown:
        raise ValueError(f"Unsupported algorithm(s): {', '.join(unknown)}")

    rng = random.Random(seed)
    specs = [ALGORITHM_REGISTRY[name] for name in selected]
    combinations = [(spec, mode) for spec in specs for mode in spec.modes]
    plaintexts = generate_plaintexts(samples_per_mode, rng)

    records: list[dict[str, str]] = []
    for plaintext in plaintexts:
        for spec, mode in combinations:
            module = spec.module
            key = module.generate_key(rng)
            iv = None if mode == "ECB" else rng.randbytes(module.BLOCK_SIZE)
            ciphertext = module.encrypt(plaintext, key, mode, iv)
            record = {
                "Algorithm": spec.name,
                "Family": spec.family,
                "Mode": mode,
                "Original text": plaintext,
                "Key": key.hex(),
                "Cipher Text": base64.b64encode(ciphertext).decode("ascii"),
                "IV": iv.hex() if iv is not None else "",
            }
            records.append(record)

    rng.shuffle(records)
    _validate_records(records)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(records)
    return len(records)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples",
        type=int,
        default=SAMPLES_PER_MODE,
        help=f"samples per algorithm and mode (default: {SAMPLES_PER_MODE})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"CSV output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="seed for reproducible plaintexts, keys, and IVs",
    )
    parser.add_argument(
        "--algorithms",
        default=",".join(ALGORITHM_REGISTRY),
        help="comma-separated algorithm names (default: all registered algorithms)",
    )
    args = parser.parse_args()
    args.algorithms = [name.strip() for name in args.algorithms.split(",") if name.strip()]
    return args


def main() -> None:
    args = _parse_args()
    try:
        count = generate_dataset(
            args.samples, args.output, args.seed, args.algorithms
        )
    except (OSError, ValueError) as error:
        raise SystemExit(f"Dataset generation failed: {error}") from error
    print(f"Wrote {count} validated records to {args.output}")


if __name__ == "__main__":
    main()
