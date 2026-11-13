# Block Cipher Identification — HKNNRF Replication

> **Headline finding:** this replication gets **near-chance accuracy**, not the
> paper's reported 69.5% (binary) / 34% (5-class). Across every ciphertext
> size and model, 5-class accuracy is 0.145–0.240 (chance = 0.20) and binary
> accuracy averages 0.497 (chance = 0.50). This is documented as a real
> result, not a bug — see [methodology.md §8](methodology.md#8-actual-result-of-this-replication-2026-11-13-run-200-samplesclasssize)
> for the checks behind that conclusion.

Replicates Yuan K, Yu D, Feng J, Yang L, Jia C, Huang Y. (2022).
*A block cipher algorithm identification scheme based on hybrid k-nearest
neighbor and random forest algorithm.* PeerJ Computer Science 8:e1110.
[doi:10.7717/peerj-cs.1110](https://doi.org/10.7717/peerj-cs.1110)

The full write-up — what is replicated exactly, what is reimplemented, and
what the paper left unspecified — is in [methodology.md](methodology.md).

## Contents

| File | Purpose |
| --- | --- |
| `hknnrf_replication.py` | Main pipeline: encrypt, extract 10 randomness features, train SVM/KNN/RF/HKNNRF, evaluate binary and 5-class tasks |
| `investigate_gap.py` | Diagnostic script testing two hypotheses for the gap with the paper (structured plaintext; small-sample variance) |
| `methodology.md` | Full methodology and results discussion |
| `results/results_full.csv` | Recorded result of the full run (200 samples/class/size, sizes 1/8/64/256/512 KB) |

## Running

Install dependencies from the repository root:

```bash
python -m pip install -r requirements.txt
```

Then run the scripts **from this directory** (`investigate_gap.py` imports
`hknnrf_replication` from the current directory):

```bash
cd research/block_cipher_identification

# Smoke test: 10 samples/class, sizes 1 and 8 KB
python hknnrf_replication.py --quick --out results/quick.csv

# Full run, as recorded in results/results_full.csv (slow)
python hknnrf_replication.py --out results/full_rerun.csv

# Diagnostic: hypotheses H1 and H2 at 64 KB (prints results, writes no files)
python investigate_gap.py
```

Re-run outputs are ignored by git; only `results/results_full.csv` is tracked.
