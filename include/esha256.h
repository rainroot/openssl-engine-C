#include <esha_locl.h>

int sha256_init(EVP_MD_CTX *ctx);
int sha256_update(EVP_MD_CTX *ctx, const void *data_, size_t len);
int sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

