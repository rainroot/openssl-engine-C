#include <openssl/aria.h>

typedef struct
{
    ARIA_KEY_SCHEDULE ks;
} EOPENSSL_ARIA_KEY;

#define eopenssl_aria(ctx)  EVP_C_DATA(EOPENSSL_ARIA_KEY,ctx)

int aria_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int aria_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int aria_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);


