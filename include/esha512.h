#include <openssl/sha.h>

# define SHA512_CBLOCK	(SHA_LBLOCK*8)

typedef struct SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

int sha512_init(EVP_MD_CTX *ctx);
int sha512_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int sha512_final(EVP_MD_CTX *ctx, unsigned char *md);

int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
