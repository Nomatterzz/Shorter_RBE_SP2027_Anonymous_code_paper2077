# Statements to synchronize in the paper

The code follows the formal parameter and algorithm sections, not contradictory
informal shorthand. No manuscript text was changed as part of this artifact.

## Correct source modulus

Use q=281474976694273=2^48-16383, not q=2^48. Approximate notation q≈2^48 is fine
in a high-level discussion. The odd modulus matters for centered representatives,
the source-ring NTT, decomposition bounds and the exact compression law.

## Implementation description

The artifact now provides all RBE algorithms, actual binary-counter bucket merges,
historical replay, canonical serialization, exact rational quantization, and
finite-precision discrete Gaussian samplers. It is no longer merely a collection
of parameter-checking programs. However, it remains a variable-time research
reference implementation, with in-memory benchmarks and a simple log-replay CLI.
Do not copy the upstream Rust implementation description or its performance data.

## Finite Gaussian sampling

The mathematical construction uses ideal discrete Gaussians. This implementation
uses finite approximations with per-coefficient TV at most 2^-240 in the ideal-bit
model. Add the total Gaussian sample count times this distance to the ideal
correctness/security experiment bounds. For the main encryption the count is
1,172,736, so the extra term is below 2^-219 and does not invalidate the stated
2^-143 main correctness target. Some retuned controls have much smaller ideal
DFR bounds, for which the finite-sampling term dominates. The report separates
those bounds. OpenSSL CSPRNG security contributes a computational hybrid term.

## Capacity and sizes

The full 2^30 boundary uses 31 slots and a 3,742,724-byte ciphertext. The matched
30-slot instance supports capacity 2^30-1 and uses 3,741,636 bytes. The 34.3%
comparison uses the latter and the 5,691,716-byte independently scaled control.
Every ciphertext figure includes the four-byte snapshot counter. Explicit public
parameters, witnesses and registry costs are reported separately rather than hidden.

## Runtime and security language

Use only the actual benchmark files and include hardware, trial counts, threading,
actual registered users, preprocessing boundaries and serialization boundaries.
A capacity of 2^30 is not a measured billion-user registry. Encryption includes
all fresh random coins, Gaussian sampling, quantization and ring operations.
The artifact contains no fresh lattice-estimator run and does not establish a
new concrete post-quantum security level. The ciphertexts are CPA-secure under the
paper's assumptions, not authenticated or CCA-secure merely because decoders
validate their byte formats.
