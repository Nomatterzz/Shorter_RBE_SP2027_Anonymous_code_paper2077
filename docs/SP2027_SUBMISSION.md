# S&P 2027 anonymous submission preparation

Consult the current official instructions before submission:

- https://www.ieee-security.org/TC/SP2027/artifact_instructions.html
- https://www.ieee-security.org/TC/SP2027/cfpapers.html
- https://github.com/jelenamirkovic/artmeta

This repository supplies the implementation and reproducibility materials. It
does not create a paper submission, artifact metadata record, GitHub account,
review invitation or archival DOI on behalf of the authors. Official instructions
and the current `artmeta` schema take precedence over this local checklist.

## Anonymous review repository

Use a fresh anonymous review repository/account, not a public personal account
with a renamed project. Copy only this clean source tree, without old `.git`
history, existing remotes, personal key material, host paths or full demo output.
Set an anonymous author and committer identity before the first commit and avoid
personal signing keys, revealing profile links, organizational ownership and
CI integrations that expose account identity. Inspect commit metadata, issues,
release metadata and Actions logs in the same way as the source files.

The content scanner helps identify credentials, generated keys and absolute user
paths. It cannot establish anonymity of a GitHub account or historical metadata.
For local identifying strings, run for example:

    python3 scripts/anonymity_audit.py --forbid '<actual personal identifier>'

Replace that argument locally; do not commit a list of real author identifiers.
Published references to prior work are not author-identification leaks by
themselves. Do not strip legitimate attribution to upstream research.

## Paper and artifact consistency

Link the review artifact according to the CFP. Complete the actual metadata using
the official tool after the anonymous URL and submitted version exist. Freeze a
specific commit and archive hash for review. Do not silently modify the evaluated
code or substitute new benchmark data after the applicable deadline; follow the
venue's permitted update process. Include the README, dependencies, commands,
claim-to-evidence mapping, raw measurements and expected outputs.

The paper can now describe a full *research reference implementation*, including
actual merges and historical replay, rather than only a parameter checker.
It should not claim constant-time operation, upstream KLSS speedups or a new
lattice security estimate. Cite only observed timings from the raw result files,
with actual registry population and hardware conditions. Account for the finite
Gaussian sampler in correctness/security statements; see PAPER_SYNC.md.

## Archive and badges

An anonymous GitHub repository is useful for review, but it is not a permanent
archival identifier by itself. For long-term availability, archive the final
version in a suitable persistent repository, record its identifier, and follow
the official process. Functional, available and reproduced results are distinct
claims; this package does not claim any badge or independent evaluator approval.

## Optional infrastructure

The supplied workflow and Dockerfile are ready-to-run configurations. Check the
self-check report to see which environments were actually executed locally.
Do not describe a supplied configuration as a successful remote run unless the
corresponding logs exist. Review network/privacy implications before enabling
public Actions on an anonymous account.
