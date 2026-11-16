# Artifact evaluation guide

## Scope of the claims

The artifact implements the paper's fixed-length, append-only RBE specialization.
It makes no claim to implement arbitrary BLE deletion/update functionality or a
complete messaging application. Public matrices, terminators and wire metadata
are fully accounted for. There are no unprovided datasets or network services.

| Claim | Evidence and entry point |
|---|---|
| Complete RBE algorithms and genuine merges | `src/scheme.cpp`, `rbe_cli demo`, `rbe_tests --all`, `scripts/cli_smoke.py` |
| Exact full-capacity serialized ciphertext size | `encode_ct`, all full-parameter tests, `results/parameters.json` |
| Fair 30-slot 34.3% / 36.7% comparisons | `matched`, `two-independent`, `two-radix` presets and rational parameter script |
| Exact compression law | C++ exhaustive moment checks and independent Python triangular integration |
| Finite Gaussian output error budget | committed integer tables, reproducible interval certificates and `docs/SAMPLING.md` |
| Main implementation correctness bound | sum of ideal paper bound and finite-sampler TV in the parameter report |
| Historical ciphertext decryptability | real merge, public-log replay, separate-process CLI and independent Python oracle |
| Operation counts and observed runtime | per-trial benchmark JSON, same-backend summary, raw environment |
| Source-level reproducibility | CMake, Python standard library, frozen KAT digests, manifest |

Not established by running this artifact: Module-LWE hardness, full independent
security proof review, production side-channel resistance, a measured 2^-143 DFR,
original KLSS implementation speedups, or an actual population of a billion users.

## Reviewer sequence

1. Build the Release target as in the README. Run `ctest`.
2. Run `scripts/reproduce.py`. Inspect every JSON result and the final report,
   not just the last line of terminal output.
3. Run the default five-preset benchmark. Change registry population/trial counts
   as desired; the raw metadata records both capacity and actual users.
4. Regenerate the tables with `scripts/generate_gaussian_tables.py --check`.
5. Build a second compiler and compare `scripts/verify_kats.py` outputs.
6. Build with `-DRBE_SANITIZE=ON` and run the same tests. Sanitizer performance is
   not used as a release benchmark.

All included tests fit on an ordinary CPU system with a few GiB of memory. Exact
requirements for the submitted run are recorded by the benchmark environment and
peak-RSS fields. The compiler/build process can consume more memory than one
cryptographic operation. Larger real registries use proportionally more memory
and more update work. A 2^30 live-user experiment is not part of the quick-start.

## Expected outputs

The test executable reports named PASS groups followed by a check count. It emits
five deterministic parameter/ciphertext hashes, checked against the frozen KAT
file. The numerical verifier requires exact rational sufficient inequalities to
hold and reports both ideal and finite-sampler correctness bounds. The independent
quantizer verifier checks 2,016 modulus pairs and 87,360 inputs. The Python oracle
reads only public serialization plus the designated test secret key and checks
the key equation, every selected path decomposition, the root, and both current
and historical decryptions using big-integer multiplication rather than NTT.

The byte counts for main and matched instances are 3,742,724 and 3,741,636. The
full-capacity main source modulus is the odd value 2^48-16383. Do not substitute
2^48 on the basis of an approximate equality in informal overview text.

## Dependencies and licenses

Original artifact code is supplied under MIT. OpenSSL and Boost are external
system dependencies with their respective licenses, not vendored binary blobs.
The code does not copy the KLSS Rust implementation. Optional GitHub Actions and
Docker configurations require the corresponding hosted/network environment to
install dependencies; local reproduction after installation is offline.

## Availability and submission metadata

This directory contains an anonymous artifact, not an assigned artifact DOI or
a submission-system record. The authors fill actual metadata and the anonymous
review URL using the official S&P 2027 instructions and `artmeta` tool. No badge
has been awarded. After acceptance, archive the exact evaluated version with a
persistent identifier if applying for the Available badge.
