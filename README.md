# Shorter Ciphertexts for Transparent Registration-Based Encryption from Lattices

Anonymous research artifact, version 1.0.0. C++20 implementation and independent
Python verification scripts. No author names, institutional identifiers or
repository URL are embedded. This archive is ready to be placed at the root of
an anonymous review repository; it has **not** itself been uploaded to GitHub.

## What is implemented

All six RBE algorithms are implemented: explicit transparent setup, local key
generation, registration with actual binary-counter bucket merges, current and
historical membership-witness generation, encryption, and decryption. The
implementation includes the single-coordinate construction and three retuned
two-coordinate controls, canonical bit-level serialization, exact randomized
compression, and finite-precision discrete Gaussian sampling with an explicit
statistical error budget. A complete 256-bit message is encrypted at the main
parameters. Both the large identity domain and the full 31-slot capacity boundary
are preserved.

The implementation is **research software, not production cryptography**. It is
variable-time and implements CPA encryption, not authenticated encryption or
CCA security. See [SECURITY.md](SECURITY.md) before using generated keys.

## Build and test

Supported environment: Linux/POSIX, x86-64 or another compiler target supporting
`__int128`, C++20 compiler, CMake 3.20+, OpenSSL 3 development headers, Boost
multiprecision headers, and Python 3.10+. Python scripts use only the standard
library. No external dataset, GPU, proprietary dependency, or network access is
needed after dependency installation.

On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build libssl-dev libboost-dev python3
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
python3 scripts/reproduce.py --binary-dir build --out-dir results/local
```

`reproduce.py` runs the complete C++ test suite, frozen deterministic KATs,
independent rational parameter certificates, independent exact quantizer checks,
CDT regeneration, separate-process CLI tests, and Python-only verification of a
full-parameter current/historical decryption. Its JSON report records pass/fail,
exit codes and wall times. A failing command stops the pipeline with a nonzero
exit code. `results/local` does not overwrite the submitted measurement data.

## One-command end-to-end example

```sh
./build/rbe_cli demo --preset main --out /tmp/rbe-main-demo
python3 scripts/reference_verify.py /tmp/rbe-main-demo
```

The demo generates three real user keys, executes a bucket merge, encrypts at
snapshots 1 and 3, reconstructs a historical witness by replay, and verifies both
messages. The main ciphertext is **3,742,724 bytes**, including its four-byte
snapshot counter. The directory contains secret key material; do not publish it.
A deterministic `--test-seed` is available exclusively for tests and prints a
warning. Ordinary commands use OpenSSL `RAND_priv_bytes`.

## Persistent command-line workflow

The primary interface is `rbe_cli help`. For example:

```sh
./build/rbe_cli setup --dir /tmp/rbe-registry --preset main
./build/rbe_cli keygen --dir /tmp/rbe-registry --out /tmp/alice
ID=$(./build/rbe_cli identity --preset main --label alice@example.invalid)
./build/rbe_cli register --dir /tmp/rbe-registry --id "$ID" --public-key /tmp/alice.pk
./build/rbe_cli witness --dir /tmp/rbe-registry --id "$ID" --out /tmp/alice.witness
python3 -c 'from pathlib import Path; Path("/tmp/message.bin").write_bytes(bytes(range(32)))'
./build/rbe_cli encrypt --dir /tmp/rbe-registry --id "$ID" --message /tmp/message.bin --out /tmp/message.ct
./build/rbe_cli decrypt --dir /tmp/rbe-registry --secret-key /tmp/alice.sk --witness /tmp/alice.witness --ciphertext /tmp/message.ct --out /tmp/plaintext.bin
cmp /tmp/message.bin /tmp/plaintext.bin
```

`--version V` on `witness` reconstructs the witness at an old registration
snapshot. Save the corresponding `state.bin` to encrypt against that snapshot
using `encrypt --state FILE`. The registration log is append-only and public.
The CLI serializes registry mutation with `flock`, atomically replaces individual
files and gives secret files mode 0600. It is not a distributed database or an
identity-authentication service. On startup it rebuilds the registry from the
public log, deliberately prioritizing an auditable reference implementation over
an optimized persistent database.

## Presets and comparison scope

| Preset | Capacity | Slots | Coordinates | Bits/coefficient | Ciphertext bytes |
|---|---:|---:|---:|---:|---:|
| `main` | 2^30 | 31 | 1 | 34 | 3,742,724 |
| `matched` | 2^30 − 1 | 30 | 1 | 34 | 3,741,636 |
| `two-independent` | 2^30 − 1 | 30 | 2 | 26 | 5,691,716 |
| `two-radix` | 2^30 − 1 | 30 | 2 | 27 | 5,910,628 |
| `published-gadget` | 2^30 − 1 | 30 | 2 | 31 | 6,786,276 |
| `toy` | 16 | 5 | 1 | 34 | 1,055 |

`toy` has **insecure test dimensions** and is not a security parameter set.
`published-gadget` keeps the published gadget but uses the new analysis and
quantizer. It is **not** the original KLSS executable. The original 32-bit KLSS
row, 7,005,188 bytes, is a reference size only.

The source ring, module rank, modulus, and scalar secret/error distribution laws
are matched for the controls. The source sample counts differ (51, 52, 72).
Comparisons do not call those differently dimensioned instances identical.
The 34.3% claim compares `matched` to `two-independent`, both with 30 slots.

## Reproduce measurements

```sh
python3 scripts/benchmark.py --binary build/rbe_cli --iterations 5 --users 4 --out-dir results/my-benchmarks
```

The runner records all raw trials, machine information without hostname, mean,
median, standard deviation, operation counts, serialization sizes and process
peak RSS. Randomness generation is included. Setup and public NTT preparation
are separately timed. No private encryption randomness is precomputed across
trials. The algorithm timings are in-memory measurements; filesystem I/O and
CLI startup/log replay are not included. See [BENCHMARKS.md](docs/BENCHMARKS.md).
A configured capacity of 2^30 does **not** imply an experiment with 2^30 actual
registered users. The raw files state the actual population.

## Map of the artifact

- `include/rbe/rbe.hpp`: typed public API and parameter definitions.
- `src/arithmetic.cpp`: decomposition, source-ring NTT and exact CRT arithmetic.
- `src/sampling.cpp`: randomness, certified finite Gaussian samplers and exact quantizer.
- `src/scheme.cpp`: setup, key generation, trees, merges, snapshots, encryption/decryption.
- `src/serialization.cpp`: canonical encodings, public log and file operations.
- `src/main.cpp`: independent command-line programs and benchmark driver.
- `tests/tests.cpp`: unit, malformed-input, history, full-parameter and control tests.
- `scripts/`: independent verification, reproduction, benchmarks and packaging audits.
- `data/`: committed Gaussian table certificates and frozen public test-vector hashes.
- `results/`: actual local test/measurement outputs, not illustrative numbers.
- `docs/`: algorithm mapping, sampling derivation, byte formats, claim/evidence mapping,
  paper synchronization notes and anonymous submission instructions.

[Artifact guide](docs/ARTIFACT.md) · [Sampling](docs/SAMPLING.md) ·
[Serialization](docs/SERIALIZATION.md) · [S&P 2027 checklist](docs/SP2027_SUBMISSION.md)

Docker and GitHub Actions configurations are supplied. Only runs explicitly
listed in the final self-check report were executed locally. Supplying a CI
workflow or Dockerfile is not evidence of a successful remote CI/container run.
