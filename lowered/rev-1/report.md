# Lowering checkpoint — Bitcoin SVN r1

## Completed
- Lowered `CryptoPP::SHA256::Transform` from `rev-1/sha.cpp:141-164` into `sha256_transform.c`.
- Expanded all 64 rounds, source macros, and rotate helper; kept the 16-word rolling schedule and 8-word working state.
- Verification passed: strict C99 compile, NIST `abc` known-answer test, and 100 deterministic comparisons against the original in-tree Crypto++ transform. Exact commands/results are in `logs/verification.txt`.

## Boundary reached in `key.h`
- The next source is `rev-1/key.h`; its `CKey::Sign` code calls `ECDSA_sign` at line 126, an OpenSSL boundary.
- A pure C99 signature preserving the existing C++ `std::vector` contract cannot be produced with the supplied transforms alone. `key_boundary.md` records the precise blocker. No replacement crypto, new wrapper, or change to the original source was made.

## Provenance
The uploaded tar's `repo/evidence/rev-1` sources for `sha.cpp`, `sha.h`, `key.h`, `bignum.h`, and `util.h` match the Git blobs at the pinned repository snapshot. Source files remain unchanged.
