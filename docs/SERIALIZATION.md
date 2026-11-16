# Canonical byte formats

All unsigned fixed-width integers are little-endian. All bitpacked sequences are
least-significant-bit first, with coefficients in increasing polynomial degree.
Unused final bits are zero and nonzero padding is rejected. The fixed preset is
out-of-band public context. There is no uncounted per-ciphertext parameter header,
identity string, seed, dither, evaluation key, or authentication tag.

Let w=3nd, B_slots=bits_for(capacity), c=ceil(bits_for(capacity)/8), and
qbytes=ceil(bitlength(q-1)/8). Main qbytes=6,c=4. Matrices are serialized row-major.
An identity is a fixed-length base-3 string but is serialized in the public log
as one base-3 integer in ceil(bitlength(3^L-1)/8) little-endian bytes (33 main).

| Object | Serialized order | Main bytes |
|---|---|---:|
| Public parameters | A (n by w), public-key matrix B (n by n), all slot terminators | 634,368 |
| Public key | n polynomials modulo q | 10,752 |
| Secret key | n polynomials; signed coefficient x encoded as x+K in bitlength(2K) bits | 3,808 |
| Compact state | c-byte global version, all slot roots | 333,316 |
| Witness | c-byte bucket-creation version, one-byte slot, L*w polynomials; u encoded as u+U | 2,286,149 |
| Ciphertext | c-byte global snapshot, c_0,...,c_(L-1), terminal c_L, then all d_t; kappa bits/coefficient | 3,742,724 |
| Message | phi binary coefficients, one bit each | 32 |
| One registration-log record | c-byte sequential version, identity integer, public key | 10,789 |

Opening order is level, child, ring coordinate, retained gadget coordinate,
polynomial coefficient. Headers have the same opening-coordinate order.
Only the final terminal block uses n coordinates, and each d_t is one polynomial.
The 30-slot `matched` ciphertext is 3,741,636 bytes.

Decoders reject incorrect lengths, reserved shifted-integer encodings, noncanonical
q residues, padding, out-of-range versions and invalid slot indices. Whole logs
are syntactically parsed before replay so malformed log records do not partially
mutate the registry. Arbitrary canonical ciphertexts remain accepted, as appropriate
for the CPA scheme; rejecting them as unauthenticated would invent a security
property not present in the paper.

The public log and sparse registry are linear in the actual population and are
not part of the compact sender state. Their serialized size, live node count,
rebuilt node count and measured process memory are separately reported. The
in-memory data structures have larger overhead than packed wire formats.
