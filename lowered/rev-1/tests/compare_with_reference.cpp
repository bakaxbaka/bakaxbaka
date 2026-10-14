#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sha.h"

extern "C" void SHA256_Transform(uint32_t *state,const uint32_t *data);
static uint32_t rng=0x51a25601u;
static uint32_t next_u32(void){rng=rng*1664525u+1013904223u;return rng;}
int main(void)
{
    unsigned int t,i;
    for(t=0;t<100;++t){uint32_t a[8],b[8],d[16];for(i=0;i<8;++i)a[i]=next_u32();for(i=0;i<16;++i)d[i]=next_u32();memcpy(b,a,sizeof(a));CryptoPP::SHA256::Transform(a,d);SHA256_Transform(b,d);if(memcmp(a,b,sizeof(a))!=0){fprintf(stderr,"reference mismatch at sample %u\n",t);return 1;}}
    puts("100 deterministic blocks vs original Crypto++ SHA256::Transform: PASS");
    return 0;
}
