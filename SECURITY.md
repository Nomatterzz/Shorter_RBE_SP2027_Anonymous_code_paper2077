# Security scope

This is a research implementation of the CPA RBE construction in the submitted
paper, not a production secure messaging system.

## Implemented model

Users generate independent secret/public keys. The curator executes public,
deterministic append-only registration and witness algorithms. Non-target public
keys may be malicious but have the declared shape and canonical coefficients.
The curator possesses no master secret. All public matrices and terminators are
explicitly serialized; no hidden evaluation keys or auxiliary transmission data
are omitted from the size accounting. A witness is public, a secret key is not.

## Explicit limits

- No IND-CCA transformation, ciphertext authentication, sender authentication,
  identity ownership verification, revocation, rollback protection or distributed
  curator consensus is implemented. Malicious well-formed ciphertexts may decrypt
  to arbitrary bits. Parsing is not authentication.
- The implementation is variable-time: table searches, Gaussian rejection,
  arbitrary-precision arithmetic, registry operations and error paths are not
  constant-time. There is no timing, cache, power or fault-resistance claim.
- Secret data are not comprehensively erased from process memory. The RNG buffer
  is cleansed and secret files use mode 0600, but these are not a secure-memory or
  crash-dump guarantee.
- Snapshot validation checks public metadata and shape. An old witness may be
  structurally valid but inappropriate for a newer ciphertext after a merge.
  Applications obtain the witness for the ciphertext snapshot from the public log.
- The CLI is a single-host reference workflow. An interrupted operation can leave
  a cached state behind the authoritative log. Replay reconstructs the log's
  state, and subsequent registration refreshes it. This is not a fully
  transactional, authenticated or crash-durable database.
- `--test-seed` makes every generated secret predictable. It is for deterministic
  testing only; never use it for real confidential data. `toy` is insecure.
- No new lattice-estimator run, independent cryptanalysis, NIST category, or
  end-to-end 128-bit quantum-security claim is supplied. The code uses the formal
  parameters and source assumptions of the paper. Estimated classical attack
  costs from an earlier notebook are not rebranded as measurements here.

## Sampling guarantees

The randomized quantizer is exact in the ideal-random-bit model. Gaussian output
is an explicitly bounded finite approximation, not an exact infinite-support
sampler. `docs/SAMPLING.md` bounds the per-coefficient total variation distance by
2^-240. The parameter verifier adds that distance to the ideal correctness bound.
With many encryptions, the coupling loss scales with their total sampled
coefficients. Replacing ideal independent bits with the OpenSSL CSPRNG adds a
computational, not statistical, assumption. Exhaustive tests on small moduli and
statistical smoke tests do not replace these analytical statements.

## Reporting issues during anonymous review

Use the review-repository issue mechanism without disclosing author identities.
Avoid attaching real keys, plaintexts, hostnames, private paths, or credentials.
