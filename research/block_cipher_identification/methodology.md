# Methodology — Block Cipher Algorithm Identification (HKNNRF Replication)

Adapted from: Yuan K, Yu D, Feng J, Yang L, Jia C, Huang Y. (2022). *A block cipher
algorithm identification scheme based on hybrid k-nearest neighbor and random forest
algorithm.* PeerJ Computer Science 8:e1110. https://doi.org/10.7717/peerj-cs.1110

This document records exactly what the paper did, what is being replicated as-is,
what is reimplemented for portability, and what the paper left unspecified (filled
with a stated assumption instead of a guess presented as fact).

## 1. Threat model / task

Ciphertext-only cryptographic algorithm identification: given only a ciphertext
file (no key, no plaintext), predict which block cipher produced it. Two tasks are
run, exactly as in the paper:

- **Binary classification** — for every pair among the 5 ciphers (10 pairs total),
  predict which of the two produced a given ciphertext.
- **5-class classification** — predict the exact cipher among all 5.

## 2. Ciphers, mode, and keys (Table 1 of the paper, replicated exactly)

| Algorithm | Structure | Block size | Key length | Mode | Key handling | Library |
|---|---|---|---|---|---|---|
| AES | SPN | 128 bits | 128 bits | ECB | **Fixed** (one key, reused for every sample) | PyCryptodome (`Crypto`) |
| 3DES | Feistel | 64 bits | 192 bits | ECB | Fixed | PyCryptodome |
| Blowfish | Feistel | 64 bits | 128 bits | ECB | Fixed | PyCryptodome |
| CAST (CAST-128) | Feistel | 64 bits | 128 bits | ECB | Fixed | PyCryptodome |
| RC2 | Feistel | 64 bits | 128 bits | ECB | Fixed | PyCryptodome |

**Important, and worth stating explicitly:** the paper uses a **fixed key per
algorithm**, reused across every sample of that class, not a fresh key per sample.
This is a deliberate replication choice, not an error in this script — but it is
also exactly the condition under which above-chance identification is *expected*,
per the hypothesis we set out earlier (fresh keys + a secure mode should push
same-block-size accuracy toward chance; fixed keys remove that protection and let
subtler, key-specific artifacts leak through). The paper's 5-class accuracy (24–34%,
against a 20% chance baseline for 5 classes) is consistent with a small but real
leak under this weaker setup — not proof that a well-designed cipher leaks its
identity in general. This caveat belongs in your discussion section if you report
these numbers.

Plaintext for every sample is generated fresh and random (the paper describes using
the Fortuna-based CSPRNG inside PyCryptodome's `Crypto.Random`); only the key is
held fixed per class.

## 3. Dataset construction

- **Ciphertext sizes:** 1, 8, 64, 256, 512 KB (exactly as in the paper).
- **Samples per class per size:** the paper does not state this number anywhere in
  the text. **This is a gap in the source paper, not an oversight here.** This
  replication uses **200 samples per class per size** (chosen for this
  reproduction), giving 200 × 5 ciphers × 5 sizes = **5,000 ciphertext samples**
  total.
- **Train/test split:** also unstated in the paper. This replication uses an
  **80/20 stratified split**, fit independently for each (task, size) combination.
- Padding: PKCS#7 to the cipher's own block size before ECB encryption.

## 4. Feature extraction

The paper extracts features via 15 NIST SP 800-22 randomness-test statistics (using
the `sp800_22_tests` Python package), then keeps **10 selected features** for
classification — but never names which 10. That package is also unmaintained and
awkward to install cleanly today.

**This replication reimplements 10 statistics in pure NumPy/SciPy**, chosen to
cover the same families of randomness test the NIST suite is built from:

1. Monobit (frequency) test — p-value
2. Block frequency test (M = 128 bits) — p-value
3. Runs test — p-value
4. Longest run of ones test — p-value (NIST's standard M/K/N table by bit length)
5. Discrete Fourier Transform (spectral) test — p-value
6. Approximate entropy test (m = 2) — statistic
7. Serial/poker test (4-bit patterns) — chi-square statistic
8. Cumulative sums test, forward — p-value
9. Cumulative sums test, reverse — p-value
10. Byte-level Shannon entropy — bits per byte

This is **not** a byte-for-byte port of `sp800_22_tests`; it is a self-contained
reimplementation covering the same statistical ground, documented here so the
substitution is visible rather than silent.

## 5. The HKNNRF hybrid model

As described in the paper (training stage, 12 steps; condensed here):

1. Fit a `RandomForestClassifier` on the 10 (standardized) original features.
2. Use the trained forest's leaf assignment per tree (`rf.apply(X)`) as a new,
   per-sample categorical feature vector — one column per tree, value = which leaf
   the sample landed in.
3. One-hot encode those leaf-index features.
4. Concatenate the one-hot leaf features with the original (standardized) 10
   features → the final, augmented feature matrix.
5. Train a `KNeighborsClassifier` on the augmented feature matrix.

At inference time, a new sample passes through the same fitted scaler → fitted
forest (for leaf indices only, not its own prediction) → fitted one-hot encoder →
concatenation → the KNN makes the final call. This matches the paper's description:
RF is used to *engineer features*, not to vote; KNN produces the actual prediction.

**Also unstated in the paper, and filled with explicit defaults here:** exact
hyperparameters for every model (SVM: RBF kernel, default C; KNN and the KNN
stage of HKNNRF: k = 5; RF and the RF stage of HKNNRF: 100 trees). These are
reasonable defaults, not values recovered from the paper — treat any precision
gained by tuning them as a possible extension, not a reproduction gap.

## 6. Baselines

Three single-layer baselines are trained on the same 10 raw (standardized)
features, exactly as in the paper:
- SVM (RBF kernel)
- KNN
- Random Forest (used directly as a classifier, not as a feature engineer)

## 7. Evaluation

- **Accuracy** — reported for every (task, cipher-pair-or-5-class, size) combination,
  mirroring the paper's Tables 3–5. This is a direct, apples-to-apples comparison.
- **Precision / Recall** — computed here as **sklearn macro-average across all
  classes**, for both the binary and 5-class tasks. The paper's Table 2 instead
  frames precision/recall around a single designated "positive" class per binary
  comparison (classic TP/FP/FN/TN). These are *not* the same number for a binary
  pair, even though both are valid metrics — macro-average is the average of
  "cipher A as positive" and "cipher B as positive" precision/recall, while the
  paper reports only one side. **Accuracy is unaffected by this and compares
  directly; only the precision/recall columns carry this caveat.**
- Each (task, size) combination is evaluated on its own held-out 20% test split.

## 8. Actual result of this replication (2026-11-13 run, 200 samples/class/size)

5-class accuracy stayed in the 0.145–0.240 band across all 5 sizes (chance = 0.20),
and every one of the 10 binary pairs stayed in the 0.39–0.56 band (chance = 0.50) —
**near-chance throughout**, for every model including HKNNRF. This does **not**
reproduce the paper's headline numbers (69.5% binary average, 34% 5-class).

This was checked for a bug before being reported as a result: ciphertexts are
confirmed distinct per sample and per cipher (correct lengths, different bytes),
but per-class feature means are statistically indistinguishable — `approx_entropy`
matches to 6 decimal places across all 5 ciphers (≈0.6931 = ln 2, the theoretical
ceiling for random bits), and `byte_entropy` sits at ≈7.997/8.0 for every cipher.
The pipeline is working correctly; there is simply no detectable per-cipher
structure in these features once plaintext is genuinely random.

This is, in fact, the theoretically expected result (see §9 below) and casts doubt
on whether the paper's above-chance numbers reflect a generalizable signal, versus
an artifact of its unstated sample count, unstated 10-of-15 feature subset, or
plaintext source. This replication cannot settle which, without the paper's own
code or data — but it does mean the 69.5%/34% figures should not be taken as a
settled empirical fact to build directly on without first understanding the gap.

## 9. What to expect, and why

Per the hypothesis framing from earlier in this project: because keys are **fixed**
and mode is **ECB** (the leakiest mode, and the one the paper tests), accuracy well
above chance is the *expected* outcome here — this setup is not the "fresh key,
properly randomized mode" condition that would make near-chance accuracy the
meaningful null result. If you later extend this to CBC with fresh keys per sample
(the contrast this project discussed earlier), a drop toward chance on the 5-class
task is the prediction to state in advance, not something to discover after the
fact.
