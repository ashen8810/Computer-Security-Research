#!/usr/bin/env python3
"""
Replication of:
Yuan K, Yu D, Feng J, Yang L, Jia C, Huang Y. (2022). A block cipher algorithm
identification scheme based on hybrid k-nearest neighbor and random forest
algorithm. PeerJ Computer Science 8:e1110. https://doi.org/10.7717/peerj-cs.1110

See methodology.md in this same folder for the full write-up of what is an exact
replication, what is reimplemented, and what the paper left unspecified.

Pipeline:
  1. Encrypt AES / 3DES / Blowfish / CAST / RC2 in ECB mode, one fixed key per
     cipher, fresh random plaintext per sample, at 5 ciphertext sizes.
  2. Extract 10 NumPy/SciPy reimplementations of NIST SP 800-22-style randomness
     statistics from each ciphertext.
  3. Train SVM / KNN / RF baselines and the HKNNRF hybrid (RF used to engineer
     leaf-index features, consumed by a final KNN) on those features.
  4. Run binary classification (all 10 cipher pairs) and 5-class classification,
     at every ciphertext size, and report accuracy / precision / recall.

Usage:
    python3 hknnrf_replication.py                  # full run (slow)
    python3 hknnrf_replication.py --quick           # small smoke test
    python3 hknnrf_replication.py --n-per-class 50  # override sample count
"""

import argparse
import math
import time
import warnings
from dataclasses import dataclass, field
from itertools import combinations

import numpy as np
import pandas as pd
from scipy import stats as sstats

from Crypto.Cipher import AES, DES3, Blowfish, CAST, ARC2
from Crypto.Util.Padding import pad

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score

warnings.filterwarnings("ignore")

RNG_SEED = 20261113  # fixed for reproducibility of this replication run


# --------------------------------------------------------------------------
# 1. Cipher setup — Table 1 of the paper: all 5 algorithms, ECB, fixed key
# --------------------------------------------------------------------------

@dataclass
class CipherSpec:
    name: str
    module: object
    block_size: int   # bytes
    key_size: int     # bytes
    key: bytes = field(default=None)


def build_cipher_specs(seed: int) -> dict:
    """One fixed key per cipher, generated once and reused for every sample —
    replicates the paper's 'Key: Fixed' column in Table 1."""
    rng = np.random.default_rng(seed)

    def fixed_key(n_bytes):
        return bytes(rng.integers(0, 256, size=n_bytes, dtype=np.uint8))

    specs = {
        "AES": CipherSpec("AES", AES, block_size=16, key_size=16),
        "3DES": CipherSpec("3DES", DES3, block_size=8, key_size=24),
        "Blowfish": CipherSpec("Blowfish", Blowfish, block_size=8, key_size=16),
        "CAST": CipherSpec("CAST", CAST, block_size=8, key_size=16),
        "RC2": CipherSpec("RC2", ARC2, block_size=8, key_size=16),
    }

    for spec in specs.values():
        if spec.name == "3DES":
            # 3DES needs a non-degenerate key (its 2-3 sub-keys must differ
            # enough that triple-DES doesn't collapse to single/double DES).
            while True:
                candidate = fixed_key(spec.key_size)
                try:
                    DES3.adjust_key_parity(candidate)
                    spec.key = candidate
                    break
                except ValueError:
                    continue
        else:
            spec.key = fixed_key(spec.key_size)

    return specs


def encrypt_ecb(spec: CipherSpec, plaintext: bytes) -> bytes:
    padded = pad(plaintext, spec.block_size)
    cipher = spec.module.new(spec.key, spec.module.MODE_ECB)
    return cipher.encrypt(padded)


# --------------------------------------------------------------------------
# 2. Feature extraction — 10 reimplemented randomness statistics
#    (see methodology.md section 4 for exactly which 10, and why)
# --------------------------------------------------------------------------

def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def monobit_test(bits: np.ndarray) -> float:
    n = bits.size
    s = np.sum(2 * bits.astype(np.int64) - 1)
    stat = abs(s) / math.sqrt(n)
    return math.erfc(stat / math.sqrt(2))


def block_frequency_test(bits: np.ndarray, m: int = 128) -> float:
    n = bits.size
    num_blocks = n // m
    if num_blocks == 0:
        return 1.0
    blocks = bits[: num_blocks * m].reshape(num_blocks, m)
    pi = blocks.mean(axis=1)
    chi_sq = 4 * m * np.sum((pi - 0.5) ** 2)
    return float(sstats.chi2.sf(chi_sq, df=num_blocks))


def runs_test(bits: np.ndarray) -> float:
    n = bits.size
    pi = bits.mean()
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return 0.0
    v_obs = 1 + np.sum(bits[:-1] != bits[1:])
    num = abs(v_obs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    return math.erfc(num / den) if den > 0 else 1.0


def longest_run_of_ones_test(bits: np.ndarray) -> float:
    n = bits.size
    # NIST's standard regime table by bit-stream length
    if n < 6272:
        m, k, categories, probs = 8, 3, [1, 2, 3, 4], [0.2148, 0.3672, 0.2305, 0.1875]
    elif n < 750000:
        m, k, categories, probs = 128, 5, [4, 5, 6, 7, 8, 9], \
            [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
    else:
        m, k, categories, probs = 10000, 6, [10, 11, 12, 13, 14, 15, 16], \
            [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]

    num_blocks = n // m
    if num_blocks == 0:
        return 1.0

    blocks = bits[: num_blocks * m].reshape(num_blocks, m)
    longest = np.zeros(num_blocks, dtype=int)
    for i in range(num_blocks):
        row = blocks[i]
        if row.sum() == 0:
            longest[i] = 0
            continue
        # vectorized longest run of 1s in a single row
        diffs = np.diff(np.concatenate(([0], row, [0])))
        starts = np.where(diffs == 1)[0]
        ends = np.where(diffs == -1)[0]
        longest[i] = (ends - starts).max() if starts.size else 0

    v = np.zeros(len(categories))
    for idx, cat in enumerate(categories):
        if idx == 0:
            v[idx] = np.sum(longest <= cat)
        elif idx == len(categories) - 1:
            v[idx] = np.sum(longest >= cat)
        else:
            v[idx] = np.sum(longest == cat)

    chi_sq = np.sum((v - num_blocks * np.array(probs)) ** 2 / (num_blocks * np.array(probs)))
    return float(sstats.chi2.sf(chi_sq, df=k))


def dft_spectral_test(bits: np.ndarray) -> float:
    n = bits.size
    x = 2 * bits.astype(np.float64) - 1
    s = np.fft.fft(x)
    modulus = np.abs(s[: n // 2])
    threshold = math.sqrt(math.log(1 / 0.05) * n)
    n0 = 0.95 * n / 2
    n1 = np.sum(modulus < threshold)
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4)
    return math.erfc(abs(d) / math.sqrt(2))


def approximate_entropy_test(bits: np.ndarray, m: int = 2) -> float:
    """Vectorized: builds all length-m_val sliding windows at once (via
    stride tricks) and turns each into an integer code, instead of looping
    over every bit in Python — the loop version is O(n) in pure Python and
    becomes the dominant cost at 512 KB (~4.2M bits)."""
    n = bits.size

    def phi(m_val):
        if m_val == 0:
            return 0.0
        padded = np.concatenate([bits, bits[: m_val - 1]])
        windows = np.lib.stride_tricks.sliding_window_view(padded, m_val)[:n]
        weights = 1 << np.arange(m_val - 1, -1, -1)
        values = windows.astype(np.int64).dot(weights)
        counts = np.bincount(values, minlength=2**m_val)
        freqs = counts[counts > 0] / n
        return float(np.sum(freqs * np.log(freqs)))

    return phi(m) - phi(m + 1)


def poker_test(bits: np.ndarray, m: int = 4) -> float:
    """Classical (non-overlapping-block) Poker Test — NOT the same as NIST
    SP 800-22's 'Serial Test' (which uses overlapping m, m-1, m-2 patterns
    and a psi-squared statistic). Named precisely to avoid conflating the
    two in any write-up that cites this feature."""
    n = bits.size
    num_blocks = n // m
    if num_blocks == 0:
        return 0.0
    blocks = bits[: num_blocks * m].reshape(num_blocks, m)
    weights = (1 << np.arange(m - 1, -1, -1))
    values = blocks.dot(weights)
    counts = np.bincount(values, minlength=2**m)
    chi_sq = (2**m / num_blocks) * np.sum(counts**2) - num_blocks
    return float(chi_sq)


def cumulative_sums_test(bits: np.ndarray, forward: bool = True) -> float:
    """NIST's bound1/bound2 require ceil(...) and floor(...) respectively.
    Python's int() truncates toward zero, which equals ceil() for the
    (typically negative) bound1 expression and floor() for the (typically
    positive) bound2 expression here — so plain int() is correct, not an
    approximation, as long as that sign pattern holds (it does for any
    real ciphertext, since z >= 1 always)."""
    n = bits.size
    x = 2 * bits.astype(np.int64) - 1
    if not forward:
        x = x[::-1]
    s = np.cumsum(x)
    z = int(np.max(np.abs(s)))
    if z == 0:
        return 1.0

    def norm_cdf(v):
        return sstats.norm.cdf(v)

    total = 0.0
    bound1 = int((-n / z + 1) / 4)
    bound2 = int((n / z - 1) / 4)
    for k in range(bound1, bound2 + 1):
        total += norm_cdf((4 * k + 1) * z / math.sqrt(n)) - norm_cdf((4 * k - 1) * z / math.sqrt(n))
    sum1 = total

    bound1 = int((-n / z - 3) / 4)
    bound2 = int((n / z - 1) / 4)
    total = 0.0
    for k in range(bound1, bound2 + 1):
        total += norm_cdf((4 * k + 3) * z / math.sqrt(n)) - norm_cdf((4 * k + 1) * z / math.sqrt(n))
    sum2 = total

    p = 1.0 - sum1 + sum2
    return float(min(max(p, 0.0), 1.0))


def byte_entropy(data: bytes) -> float:
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    probs = counts[counts > 0] / arr.size
    return float(-np.sum(probs * np.log2(probs)))


FEATURE_NAMES = [
    "monobit_p",
    "block_freq_p",
    "runs_p",
    "longest_run_p",
    "dft_spectral_p",
    "approx_entropy",
    "poker_chisq",
    "cusum_fwd_p",
    "cusum_rev_p",
    "byte_entropy",
]


def extract_features(ciphertext: bytes) -> np.ndarray:
    bits = bytes_to_bits(ciphertext)
    return np.array([
        monobit_test(bits),
        block_frequency_test(bits),
        runs_test(bits),
        longest_run_of_ones_test(bits),
        dft_spectral_test(bits),
        approximate_entropy_test(bits),
        poker_test(bits),
        cumulative_sums_test(bits, forward=True),
        cumulative_sums_test(bits, forward=False),
        byte_entropy(ciphertext),
    ])


# --------------------------------------------------------------------------
# 3. Dataset generation (streamed — ciphertext itself is never written to
#    disk, only the resulting feature vectors, to keep this script light)
# --------------------------------------------------------------------------

def generate_dataset(specs: dict, size_bytes: int, n_per_class: int, rng: np.random.Generator) -> pd.DataFrame:
    rows = []
    for name, spec in specs.items():
        for _ in range(n_per_class):
            plaintext = bytes(rng.integers(0, 256, size=size_bytes, dtype=np.uint8))
            ciphertext = encrypt_ecb(spec, plaintext)
            feats = extract_features(ciphertext)
            rows.append(list(feats) + [name])
    return pd.DataFrame(rows, columns=FEATURE_NAMES + ["label"])


# --------------------------------------------------------------------------
# 4. HKNNRF hybrid model (paper's training-stage steps 1–12, condensed)
# --------------------------------------------------------------------------

class HKNNRF:
    def __init__(self, n_estimators=100, k_neighbors=5, random_state=0):
        self.rf = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)
        self.scaler = StandardScaler()
        self.ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        self.knn = KNeighborsClassifier(n_neighbors=k_neighbors)

    def _augmented_features(self, X_scaled, fit_ohe=False):
        leaf_idx = self.rf.apply(X_scaled)
        if fit_ohe:
            leaf_feats = self.ohe.fit_transform(leaf_idx)
        else:
            leaf_feats = self.ohe.transform(leaf_idx)
        return np.hstack([X_scaled, leaf_feats])

    def fit(self, X, y):
        X_scaled = self.scaler.fit_transform(X)
        self.rf.fit(X_scaled, y)
        X_aug = self._augmented_features(X_scaled, fit_ohe=True)
        self.knn.fit(X_aug, y)
        return self

    def predict(self, X):
        X_scaled = self.scaler.transform(X)
        X_aug = self._augmented_features(X_scaled, fit_ohe=False)
        return self.knn.predict(X_aug)


# --------------------------------------------------------------------------
# 5. Experiment runner — binary (10 pairs) + 5-class, per size, 4 models
# --------------------------------------------------------------------------

def make_models():
    return {
        "SVM": SVC(kernel="rbf"),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "RF": RandomForestClassifier(n_estimators=100, random_state=0),
        "HKNNRF": HKNNRF(n_estimators=100, k_neighbors=5, random_state=0),
    }


def evaluate_task(df: pd.DataFrame, label_col: str, test_size: float = 0.2, seed: int = 0) -> dict:
    X = df[FEATURE_NAMES].values
    y = df[label_col].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=seed
    )
    scaler = StandardScaler().fit(X_train)
    X_train_s, X_test_s = scaler.transform(X_train), scaler.transform(X_test)

    results = {}
    for model_name, model in make_models().items():
        if model_name == "HKNNRF":
            model.fit(X_train, y_train)  # HKNNRF scales internally
            pred = model.predict(X_test)
        else:
            model.fit(X_train_s, y_train)
            pred = model.predict(X_test_s)
        results[model_name] = dict(
            accuracy=accuracy_score(y_test, pred),
            precision=precision_score(y_test, pred, average="macro", zero_division=0),
            recall=recall_score(y_test, pred, average="macro", zero_division=0),
        )
    return results


def run_experiments(n_per_class: int, sizes_kb: list, seed: int = RNG_SEED) -> pd.DataFrame:
    specs = build_cipher_specs(seed)
    cipher_names = list(specs.keys())
    rng = np.random.default_rng(seed + 1)

    all_rows = []
    for size_kb in sizes_kb:
        t0 = time.time()
        print(f"\n=== Ciphertext size: {size_kb} KB ===")
        df = generate_dataset(specs, size_kb * 1024, n_per_class, rng)
        print(f"  generated {len(df)} samples in {time.time() - t0:.1f}s")

        # 5-class task
        res = evaluate_task(df, "label", seed=seed)
        for model_name, metrics in res.items():
            all_rows.append(dict(task="5-class", pair="all-5", size_kb=size_kb,
                                  model=model_name, **metrics))
        print(f"  5-class accuracy: " +
              ", ".join(f"{m}={r['accuracy']:.3f}" for m, r in res.items()))

        # Binary tasks: all 10 pairs
        for a, b in combinations(cipher_names, 2):
            sub = df[df["label"].isin([a, b])].reset_index(drop=True)
            res = evaluate_task(sub, "label", seed=seed)
            for model_name, metrics in res.items():
                all_rows.append(dict(task="binary", pair=f"{a}-{b}", size_kb=size_kb,
                                      model=model_name, **metrics))

    return pd.DataFrame(all_rows)


# --------------------------------------------------------------------------
# 6. CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true",
                         help="small smoke test: 10 samples/class, sizes [1, 8] KB")
    parser.add_argument("--n-per-class", type=int, default=200,
                         help="samples per class per size (default: 200)")
    parser.add_argument("--sizes-kb", type=int, nargs="+", default=[1, 8, 64, 256, 512],
                         help="ciphertext sizes in KB (default: 1 8 64 256 512)")
    parser.add_argument("--out", type=str, default="results.csv",
                         help="output CSV path")
    args = parser.parse_args()

    if args.quick:
        n_per_class, sizes_kb = 10, [1, 8]
    else:
        n_per_class, sizes_kb = args.n_per_class, args.sizes_kb

    print(f"Running with n_per_class={n_per_class}, sizes_kb={sizes_kb}")
    results = run_experiments(n_per_class, sizes_kb)
    results.to_csv(args.out, index=False)
    print(f"\nSaved {len(results)} result rows to {args.out}")

    print("\n=== 5-class accuracy summary (mirrors paper's Table 5) ===")
    summary = results[results.task == "5-class"].pivot_table(
        index="size_kb", columns="model", values="accuracy"
    )
    print(summary.round(3))

    print("\n=== Binary classification accuracy summary (mirrors paper's Table 4, HKNNRF) ===")
    binary_hknnrf = results[(results.task == "binary") & (results.model == "HKNNRF")].pivot_table(
        index="pair", columns="size_kb", values="accuracy"
    )
    print(binary_hknnrf.round(3))


if __name__ == "__main__":
    main()
