#include <esha_locl.h>

#  define Sigma0(x)       (ROTATE((x),30) ^ ROTATE((x),19) ^ ROTATE((x),10))
#  define Sigma1(x)       (ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))
#  define sigma0(x)       (ROTATE((x),25) ^ ROTATE((x),14) ^ ((x)>>3))
#  define sigma1(x)       (ROTATE((x),15) ^ ROTATE((x),13) ^ ((x)>>10))

#  define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
#  define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#   define ROUND_00_15(i,a,b,c,d,e,f,g,h)          do {    \
        T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];      \
        h = Sigma0(a) + Maj(a,b,c);                     \
        d += T1;        h += T1;                } while (0)

#   define ROUND_16_63(i,a,b,c,d,e,f,g,h,X)        do {    \
        s0 = X[(i+1)&0x0f];     s0 = sigma0(s0);        \
        s1 = X[(i+14)&0x0f];    s1 = sigma1(s1);        \
        T1 = X[(i)&0x0f] += s0 + s1 + X[(i+9)&0x0f];    \
        ROUND_00_15(i,a,b,c,d,e,f,g,h);         } while (0)

int sha256_init(EVP_MD_CTX *ctx);
int sha256_update(EVP_MD_CTX *ctx, const void *data_, size_t len);
int sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

