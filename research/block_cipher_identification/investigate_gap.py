#!/usr/bin/env python3
"""
Investigates why hknnrf_replication.py lands at near-chance accuracy while the
paper reports 69.5% (binary) / 34% (5-class). Tests two concrete, falsifiable
hypotheses against the SAME validated pipeline (imported, not reimplemented):

  H1 (structured plaintext): the paper's "random numbers" plaintext source may
     not have been uniformly random. If it had any repeating/low-entropy
     structure, ECB mode would leak it differently depending on block size
     (64-bit Feistel ciphers vs 128-bit AES) and possibly beyond. Tested by
     swapping random plaintext for a repeating, low-entropy pattern and
     re-running the identical pipeline.

  H2 (small-sample variance/overfitting): the paper never states N. A small N
     could make HKNNRF's KNN-on-leaf-embeddings overfit a specific small
     dataset, inflating apparent accuracy. Tested by rerunning at small N
     multiple times and checking whether results spike above chance.

Both hypotheses are run at a single size (64 KB) to keep this fast; the full
pipeline (all 5 sizes, N=200) is the one already reported in methodology.md.
"""

import sys
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from hknnrf_replication import (
    build_cipher_specs, encrypt_ecb, extract_features, FEATURE_NAMES,
    evaluate_task, RNG_SEED,
)

SIZE_BYTES = 64 * 1024


# --------------------------------------------------------------------------
# H1: structured / low-entropy plaintext instead of uniformly random bytes
# --------------------------------------------------------------------------

BASE_PHRASE = (
    b"The quick brown fox jumps over the lazy dog. Pack my box with five "
    b"dozen liquor jugs. "
)


def structured_plaintext(size_bytes: int) -> bytes:
    """Repeating English-like text — lots of repeated 8-byte and 16-byte
    windows, the opposite of uniformly random plaintext."""
    reps = (size_bytes // len(BASE_PHRASE)) + 1
    return (BASE_PHRASE * reps)[:size_bytes]


def generate_dataset_custom(specs, size_bytes, n_per_class, plaintext_fn, rng):
    rows = []
    for name, spec in specs.items():
        for _ in range(n_per_class):
            pt = plaintext_fn(size_bytes, rng)
            ct = encrypt_ecb(spec, pt)
            feats = extract_features(ct)
            rows.append(list(feats) + [name])
    return pd.DataFrame(rows, columns=FEATURE_NAMES + ["label"])


def random_plaintext_fn(size_bytes, rng):
    return bytes(rng.integers(0, 256, size=size_bytes, dtype=np.uint8))


def structured_plaintext_fn(size_bytes, rng):
    # same structured text for every sample — deliberately low entropy,
    # deliberately repeating, to maximize any ECB block-repeat leak
    return structured_plaintext(size_bytes)


def run_h1(n_per_class=100):
    print(f"\n{'='*70}\nH1: structured vs random plaintext, 64 KB, n={n_per_class}/class\n{'='*70}")
    specs = build_cipher_specs(RNG_SEED)
    rng = np.random.default_rng(RNG_SEED + 1)

    print("\n-- Random plaintext (same as main replication) --")
    df_random = generate_dataset_custom(specs, SIZE_BYTES, n_per_class, random_plaintext_fn, rng)
    res = evaluate_task(df_random, "label", seed=RNG_SEED)
    for m, r in res.items():
        print(f"  {m}: accuracy={r['accuracy']:.3f}")

    print("\n-- Structured (repeating text) plaintext --")
    df_struct = generate_dataset_custom(specs, SIZE_BYTES, n_per_class, structured_plaintext_fn, rng)
    res2 = evaluate_task(df_struct, "label", seed=RNG_SEED)
    for m, r in res2.items():
        print(f"  {m}: accuracy={r['accuracy']:.3f}")

    print("\n-- Feature means by class, structured plaintext --")
    print(df_struct.groupby("label")[FEATURE_NAMES].mean().round(4).T)

    return df_random, df_struct


# --------------------------------------------------------------------------
# H2: does small N inflate / destabilize accuracy via overfitting?
# --------------------------------------------------------------------------

def run_h2(n_values=(20, 50, 100, 200), n_repeats=5):
    print(f"\n{'='*70}\nH2: accuracy vs sample size, repeated trials, 64 KB\n{'='*70}")
    specs = build_cipher_specs(RNG_SEED)

    rows = []
    for n_per_class in n_values:
        for trial in range(n_repeats):
            rng = np.random.default_rng(RNG_SEED + 1000 * n_per_class + trial)
            df = generate_dataset_custom(specs, SIZE_BYTES, n_per_class, random_plaintext_fn, rng)
            res = evaluate_task(df, "label", seed=trial)  # vary split each trial
            for model, metrics in res.items():
                rows.append(dict(n_per_class=n_per_class, trial=trial, model=model,
                                  accuracy=metrics["accuracy"]))

    results = pd.DataFrame(rows)
    summary = results.groupby(["n_per_class", "model"])["accuracy"].agg(["mean", "std", "min", "max"])
    print(summary.round(3))
    return results


if __name__ == "__main__":
    df_random, df_struct = run_h1(n_per_class=100)
    h2_results = run_h2()
