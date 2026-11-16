# Mapping the paper to the implementation

## Parameters and arithmetic

The source ring is Z[X]/(X^phi+1), with q = 281474976694273 = 2^48 − 16383.
The main preset fixes phi=256, n=7, L=162, inclusive key coefficients in
[-32768,32768], Gaussian mass parameter sigma=32, message-noise width
6,000,000,000,000, scale g=2^28, and transmission modulus M=2^34.
These are mass parameters in exp(-pi*x^2/s^2), not standard deviations.

Every source-ring product uses a twisted negacyclic NTT. Setup validates the
prime, divisibility and primitive 2*phi-th root. Matrix transforms are public
preparation cached by `Engine`. Normal execution does not use floating point for
ring arithmetic, sampling, encryption, compression or decryption.

`CRTDot` evaluates the integer negacyclic dot product exactly using three auxiliary
NTT primes 998244353, 1004535809 and 469762049. Before reconstruction it verifies
that the sum of coefficient bounds is below half their product. Signed CRT
reconstruction is then reduced modulo M. These primes are an arithmetic device,
not cryptographic assumptions. Their cost is included in decryption.

## Setup and key generation

`Engine::setup` samples A (n by 3nd), B (n by n) and B_slots independent
terminators (n ring coordinates each). The number of slots is bits_for(N), so
N=2^30 uses 31 slots and N=2^30-1 uses 30. Public parameters are stored explicitly.

`Engine::keygen` draws independent coefficientwise-uniform x,z from the inclusive
integer interval [-K,K], computes y=B*x+z mod q, and returns (y,x). The error z
is not retained. Uniform integer draws use rejection, not biased modular reduction.

## Tree decomposition and real registration

Child/ring-coordinate/gadget-coordinate ordering is fixed in the encodings.
For one coordinate, u(a)=-floor((cen(a)+g/2)/g), f(a)=cen(a)+g*u(a).
Half-integer ties round toward positive infinity before negation. Bounds are
U=2^19,V=2^27. For two independent scales, compute the high quotient first,
then decompose the high-quotient residual at the low scale. The radix controls
use the balanced-digit offset convention with the declared low digits dropped.
Every decomposition verifies its modular relation and coefficient bounds.

An internal node concatenates three child decompositions into u and labels the
parent A*u. Missing child pointers mean a public terminator. Leaf/internal/empty
types are structural, not inferred by comparing labels to a terminator: even an
adversarial public key equal to a terminator remains a registered leaf.

`Registry::register_key` executes the binary carry and rebuilds the merged bucket
with its destination-slot terminator. It does not substitute prebuilt final trees
for a merge benchmark. The new bucket has the current creation counter. Other
buckets are immutable until consumed by a later merge. The implementation stores
the registration log, distinct-identity index, and a membership set for each bucket. Current witness lookup uses these sets rather than scanning all registered keys. Building the complete sparse
ternary path has real O(n_users * L) node work; the artifact does not claim a
compressed trie or a database optimization that it does not implement.

## Historical witness generation

A witness consists of bucket creation counter, slot, and L openings. Unrelated
registrations do not alter this witness. The default registry reconstructs old
versions by replaying the public log. An optional in-memory snapshot cache exists
for testing and is disabled in ordinary CLI/benchmark runs. Both paths are tested
against each other. Log replay does not use any secret key.

## Encryption and decryption

For j=0,...,L sample independent n-coordinate r_j, and all header/terminal errors,
from the finite Gaussian approximation. Form

    c_j^T = r_j^T A + r_{j+1}^T J_id[j] + e_j^T  (j<L)
    c_L^T = r_L^T B + e_L^T
    d_t   = r_0^T root_t + tilde_e_t + floor(q/2)*mu.

The header is generated once. Every slot, including empty slots, receives a message
component. All phi bits of the message use the paper's ring encoding. Each output
coefficient is independently quantized. No dither is transmitted, and no secret
randomness is precomputed across messages.

Decryption forms the dot product with the public path openings and the local
secret key directly in R_M, subtracts it from the selected d_t, and rounds to a
bit. It does not first round the grid values back into R_q. Correctly generated
plaintexts and real merges are tested at every full parameter set.

## Operational boundaries

The API implements append-only fixed-length ternary identities as in the current
paper. It does not implement every operation of the more general KLSS BLE syntax
(such as arbitrary subset messages, deletions or key replacement). RBE encryption
uses all slots and one common message, precisely the specialization evaluated.
The optional application identity helper hashes a string with a domain separator;
it authenticates neither the string nor the party registering it.

The CLI file reader uses a 1-GiB per-file safety limit. This is a reference storage workflow, not evidence of handling a billion live records. Custom API parameters are not assigned a security level by syntactic parameter validation.
