# Type erasure — rev-1 SHA256::Transform

| Original | Lowered | Source |
|---|---|---|
| `CryptoPP::word32` (`unsigned int`) | `uint32_t` | `rev-1/sha.h:19` |
| `word32 W[16]` | `uint32_t W[16]` | `rev-1/sha.cpp:143` |
| `word32 T[8]` | `uint32_t T[8]` | `rev-1/sha.cpp:144` |

The input/output signature remains two word arrays, matching `SHA256::Transform(word32 *state, const word32 *data)` in `rev-1/sha.h:137`.