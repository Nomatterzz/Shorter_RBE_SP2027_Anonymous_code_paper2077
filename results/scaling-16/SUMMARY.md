# Measured same-backend results

Actual registry population: 16. Independent trials: 1. Single-threaded C++20. Default OpenSSL CSPRNG.

| Preset | Ciphertext bytes | Enc + serialization median (ms) | Parse + Dec median (ms) | Peak RSS (MiB) |
|---|---:|---:|---:|---:|
| main | 3,742,724 | 327.656 | 330.011 | 285.83 |
| two-independent | 5,691,716 | 567.531 | 745.327 | 508.51 |

The `main` capacity is 2^30 with 31 slots, not a claim that 2^30 users were registered in memory. Compare `matched` and the retuned controls at 30 slots.

Setup, public NTT preparation, registration, witness generation and serialization are separately recorded. Encryption includes all randomness and Gaussian/quantizer work. Decryption includes exact CRT arithmetic. CLI startup/log replay and filesystem I/O are not in these in-memory algorithm timings.

These are fresh same-backend controls. No upstream KLSS Rust runtime was measured, and no speedup over that implementation is claimed.

Raw trials, standard deviations and environment metadata accompany this summary. Shared-host scheduling affects absolute times.
