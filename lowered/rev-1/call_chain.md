# Call-chain checkpoint — rev-1

## First file (completed)
`CryptoPP::SHA256::Transform(state, data)` is lowered from `repo/evidence/rev-1/sha.cpp:141-164`. Bitcoin invokes it through `BlockSHA256` (`main.cpp:2186-2210`), including calls at lines 2200 and 2208. `BlockSHA256` is used on the mining path.

## Key/signing path (next; blocked at current boundary)
The signing hash path uses OpenSSL `SHA256()` through `util.h:339-346`; that is distinct from the in-tree Crypto++ transform. `CKey::Sign` is in `key.h:121-131` and calls external `ECDSA_sign` at line 126. `key.h:141-147` is the static overload that imports through `d2i_ECPrivateKey` and then delegates to instance `Sign`.

The SHA lowering is therefore the requested first-file checkpoint, not a substitute for the signing hash. See `key_boundary.md` for why the next C99 conversion is blocked without expanding the allowed transforms.
