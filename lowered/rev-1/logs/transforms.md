# Transform log — rev-1 SHA256::Transform

Pinned source: `bakaxbaka/bakaxbaka@5152c87a0d607a68432ef1bb2daf1a1a7a14bd33`, `rev-1/sha.cpp` and `rev-1/sha.h`. The newly supplied tar archive contains byte-identical files (their Git blob IDs match the pinned repository blobs).

1. **Typedef erasure:** `CryptoPP::word32` (`sha.h:19`, `unsigned int`) becomes `uint32_t`.
2. **C++ member lowering:** `CryptoPP::SHA256::Transform` (`sha.h:132-137`, implementation `sha.cpp:141-164`) becomes the C identifier `SHA256_Transform`; the namespace/class qualification is removed for C linkage.
3. **Fixed-trip loop unrolling:** the loop at `sha.cpp:148` (`j=0,16,32,48`) and its four rows of `R(0..15)` calls (`sha.cpp:150-153`) become 64 rounds with constant indexes. No runtime loop remains.
4. **Macro expansion:** `blk0` (`sha.cpp:21`), `blk2` (`118`), `Ch`/`Maj` (`120-121`), `a..h` (`123-130`), `R` (`132-133`), and `S0/S1/s0/s1` (`136-139`) are expanded directly at the round sites.
5. **Inline helper:** `rotrFixed` is expanded to the shifts/OR defined in `sha.h:32-35`.
6. **Constant substitution:** all 64 `SHA256_K` values are copied unchanged and in order from `sha.cpp:99-116`.
7. **Feed-forward:** `state[0..7] += a(0)..h(0)` is expanded to the fixed-index additions corresponding to `sha.cpp:156-163`.
8. **Portability adaptation, explicitly outside the listed transform set:** the old `<memory.h>` include (`sha.cpp:13`) is mapped to standard C99 `<string.h>` for the retained `memcpy` call. No `memcpy` implementation is authored.

No OpenSSL call is present in this transform. This is an in-tree SHA implementation; the audit notes that Bitcoin's signing sighash instead calls OpenSSL `SHA256()` through `util.h`, so this first lowering is not a replacement on the signing path.
