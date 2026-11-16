# Release self-check

**All required checks passed: true.**

| Check | Result | Evidence |
|---|---|---|
| python_syntax | PASS | results/release_python_syntax.txt |
| gcc_configure | PASS | results/release_gcc_configure.txt |
| gcc_build | PASS | results/release_gcc_build.txt |
| gcc_full_tests | PASS | results/release_gcc_full_tests.txt |
| gcc_kat_check | PASS | results/release_gcc_kat_check.txt |
| reproduction | PASS | results/release_reproduction.txt |
| reproduction_completeness | PASS | Expected eleven complete reproduction stages, not an in-progress success report. |
| clang_configure | PASS | results/release_clang_configure.txt |
| clang_build | PASS | results/release_clang_build.txt |
| clang_full_tests | PASS | results/release_clang_full_tests.txt |
| clang_kat_check | PASS | results/release_clang_kat_check.txt |
| sanitizer_configure | PASS | results/release_sanitizer_configure.txt |
| sanitizer_build | PASS | results/release_sanitizer_build.txt |
| address_undefined_leak_sanitizers | PASS | results/release_address_undefined_leak_sanitizers.txt |
| matched_backend_benchmarks | PASS | results/release_matched_backend_benchmarks.txt |
| population16_main | PASS | results/release_population16_main.txt |
| population16_two-independent | PASS | results/release_population16_two-independent.txt |
| anonymity_scan | PASS | results/release_anonymity_scan.txt |
| clean_archive_configure | PASS | results/release_clean_archive_configure.txt |
| clean_archive_build | PASS | results/release_clean_archive_build.txt |
| clean_archive_full_tests | PASS | results/release_clean_archive_full_tests.txt |
| clean_archive_kat_check | PASS | results/release_clean_archive_kat_check.txt |
| final_anonymity_scan | PASS | results/release_final_anonymity_scan.txt |

## Scope

The test results concern the supplied research implementation, not an independent cryptographic security audit or a production-security certification.
The main parameter capacity is 2^30, but the timing experiments use the explicitly recorded smaller populations. Toy configurations have no security claim.
No empirical experiment establishes a failure rate of 2^-143. The probability statements follow the analytical bounds and the finite-sampler coupling calculation.
Docker and GitHub Actions configurations are provided but have not been executed here. No new lattice-estimator run or upstream KLSS timing benchmark was performed.
The anonymous account, repository ownership/history and actual submission metadata require author-side review. The package has not been uploaded to a remote service.
