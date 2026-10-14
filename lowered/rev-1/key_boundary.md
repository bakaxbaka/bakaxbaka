# r1 key.h boundary review

Pinned input: `repo/evidence/rev-1/key.h` in the uploaded `workspace_(8).tar` archive; byte-identical to `bakaxbaka/bakaxbaka@5152c87a0d607a68432ef1bb2daf1a1a7a14bd33/rev-1/key.h` (Git blob `26e1ae2adabd1bf27555eeb6b78188f0e7f12290`).

## Existing source trace
- `CKey` is a C++ class with `EC_KEY* pkey` (`key.h:43-46`). OpenSSL declarations enter through `headers.h:18` (`<openssl/ecdsa.h>`).
- Instance signing method: `CKey::Sign(uint256, vector<unsigned char>&)` (`key.h:121-131`). It clears/resizes a `std::vector`, uses a local `pchSig[10000]`, calls `ECDSA_sign` (`key.h:126`), then copies the generated DER bytes into the vector (`key.h:128-129`).
- Static signing overload: `key.h:141-147`; it constructs a `CKey`, imports the private key through `SetPrivKey` (`key.h:81-87`, `d2i_ECPrivateKey` at line 84), and calls the instance method at line 146.
- The OpenSSL call remains an external API boundary. This snapshot does not contain OpenSSL implementation source; the archive's review identifies the shipped version as 0.9.8h, but does not supply its implementation source.

## Lowering status: blocked under the supplied transform rules
A standalone C99 function cannot preserve the source contract using only the listed transforms: the method depends on the C++ `CKey` object, the `uint256` C++ value type, and `std::vector` operations (`clear`, `resize`, indexing). Converting that vector to a pointer/capacity/length tuple or allocating a C buffer would define a new C ABI and memory-ownership contract not present in the old source. Mapping C++ exceptions from constructors to C error returns would likewise alter error semantics.

No C implementation was authored for `CKey::Sign`. To continue without inventing behavior, either keep this as an explicitly unlowered external/API boundary or authorize a separate C ABI adapter workstream. The existing old `key.h` remains unchanged.
