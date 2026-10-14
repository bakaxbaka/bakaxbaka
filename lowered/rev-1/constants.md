# Constants — rev-1 SHA256::Transform

- `SHA256_K[64]`: copied unchanged from `rev-1/sha.cpp:99-116`.
- Big sigma rotation counts `2,13,22` and `6,11,25`; `rev-1/sha.cpp:136-137`.
- Small sigma counts `7,18,3` and `17,19,10`; `rev-1/sha.cpp:138-139`.
- Word width 32 bits: `word32` typedef in `rev-1/sha.h:19`; lowered as `uint32_t`.
- KAT initial state: `SHA256::InitState` in `rev-1/sha.cpp:93-96`.
- KAT message: ASCII `abc`; NIST digest `BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD`, source https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data.
