#include <esha_locl.h>

#define INIT_DATA_h0 0x67452301UL
#define INIT_DATA_h1 0xefcdab89UL
#define INIT_DATA_h2 0x98badcfeUL
#define INIT_DATA_h3 0x10325476UL
#define INIT_DATA_h4 0xc3d2e1f0UL

#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL


int sha1_init(EVP_MD_CTX *ctx);
int sha1_update(EVP_MD_CTX *c, const void *data_, size_t len);
int sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

