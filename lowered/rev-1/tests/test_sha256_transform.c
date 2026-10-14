#include <stdint.h>
#include <stdio.h>

void SHA256_Transform(uint32_t *state, const uint32_t *data);

int main(void)
{
    /* NIST SHA-256 KAT: ASCII abc -> BA7816BF...F20015AD.
       Padded one-block input; https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data */
    uint32_t state[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    const uint32_t block[16] = {0x61626380u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0x00000018u};
    const uint32_t expected[8] = {0xba7816bfu,0x8f01cfeau,0x414140deu,0x5dae2223u,0xb00361a3u,0x96177a9cu,0xb410ff61u,0xf20015adu};
    unsigned int i;
    SHA256_Transform(state, block);
    for (i=0;i<8;++i) if (state[i] != expected[i]) { fprintf(stderr, "word %u mismatch\n", i); return 1; }
    puts("NIST SHA-256 abc vector: PASS");
    return 0;
}
