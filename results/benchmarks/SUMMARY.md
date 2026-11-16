# Measured same-backend results

Actual registry population: 4. Independent trials: 3. Single-threaded C++20. Default OpenSSL CSPRNG.

| Preset | Ciphertext bytes | Enc + serialization median (ms) | Parse + Dec median (ms) | Peak RSS (MiB) |
|---|---:|---:|---:|---:|
| main | 3,742,724 | 312.843 | 326.728 | 93.64 |
| matched | 3,741,636 | 341.003 | 334.110 | 93.64 |
| two-independent | 5,691,716 | 533.303 | 628.390 | 147.96 |
| two-radix | 5,910,628 | 609.707 | 722.248 | 148.34 |
| published-gadget | 6,786,276 | 524.630 | 621.257 | 150.10 |

The `main` capacity is 2^30 with 31 slots, not a claim that 2^30 users were registered in memory. Compare `matched` and the retuned controls at 30 slots.

Setup, public NTT preparation, registration, witness generation and serialization are separately recorded. Encryption includes all randomness and Gaussian/quantizer work. Decryption includes exact CRT arithmetic. CLI startup/log replay and filesystem I/O are not in these in-memory algorithm timings.

These are fresh same-backend controls. No upstream KLSS Rust runtime was measured, and no speedup over that implementation is claimed.

Raw trials, standard deviations and environment metadata accompany this summary. Shared-host scheduling affects absolute times.
