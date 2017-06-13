#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int sha256_init(EVP_MD_CTX *ctx)
{
	SHA256_CTX *c = ctx->md_data;
    memset(c, 0, sizeof(*c));
    c->h[0] = 0x6a09e667UL;
    c->h[1] = 0xbb67ae85UL;
    c->h[2] = 0x3c6ef372UL;
    c->h[3] = 0xa54ff53aUL;
    c->h[4] = 0x510e527fUL;
    c->h[5] = 0x9b05688cUL;
    c->h[6] = 0x1f83d9abUL;
    c->h[7] = 0x5be0cd19UL;
    c->md_len = SHA256_DIGEST_LENGTH;
	return 1;
//    return SHA256_Init(ctx->md_data);
}

static void SHA256_BLOCK_DATA_ORDER(SHA_CTX *c, const void *p, size_t num)
{
    const unsigned char *data = p;
    register unsigned MD32_REG_T A, B, C, D, E, T, l;
    int i;
    SHA_LONG X[16];

    A = c->h0;
    B = c->h1;
    C = c->h2;
    D = c->h3;
    E = c->h4;

    for (;;) {
        for (i = 0; i < 16; i++) {
            HOST_c2l(data, l);
            X[i] = l;
            BODY_00_15(X[i]);
        }
        for (i = 0; i < 4; i++) {
            BODY_16_19(X[i], X[i + 2], X[i + 8], X[(i + 13) & 15]);
        }
        for (; i < 24; i++) {
            BODY_20_39(X[i & 15], X[(i + 2) & 15], X[(i + 8) & 15],
                       X[(i + 13) & 15]);
        }
        for (i = 0; i < 20; i++) {
            BODY_40_59(X[(i + 8) & 15], X[(i + 10) & 15], X[i & 15],
                       X[(i + 5) & 15]);
        }
        for (i = 4; i < 24; i++) {
            BODY_60_79(X[(i + 8) & 15], X[(i + 10) & 15], X[i & 15],
                       X[(i + 5) & 15]);
        }

        c->h0 = (c->h0 + A) & 0xffffffffL;
        c->h1 = (c->h1 + B) & 0xffffffffL;
        c->h2 = (c->h2 + C) & 0xffffffffL;
        c->h3 = (c->h3 + D) & 0xffffffffL;
        c->h4 = (c->h4 + E) & 0xffffffffL;

        if (--num == 0)
            break;
        A = c->h0;
        B = c->h1;
        C = c->h2;
        D = c->h3;
        E = c->h4;

    }
}

int sha256_update(EVP_MD_CTX *ctx, const void *data_, size_t len)
{
    SHA256_CTX *c = ctx->md_data;
    const unsigned char *data = data_;
    unsigned char *p;
    SHA_LONG l;
    size_t n;

    if (len == 0)
        return 1;

    l = (c->Nl + (((SHA_LONG) len) << 3)) & 0xffffffffUL;
    if (l < c->Nl)
        c->Nh++;
    c->Nh += (SHA_LONG) (len >> 29);

    c->Nl = l;

    n = c->num;
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= SHA256_CBLOCK || len + n >= SHA256_CBLOCK) {
            memcpy(p + n, data, SHA256_CBLOCK - n);
            SHA256_BLOCK_DATA_ORDER(c, p, 1);
            n = SHA256_CBLOCK - n;
            data += n;
            len -= n;
            c->num = 0;
            memset(p, 0, SHA256_CBLOCK);
        } else {
            memcpy(p + n, data, len);
            c->num += (unsigned int)len;
            return 1;
        }
    }

    n = len / SHA256_CBLOCK;
    if (n > 0) {
        SHA256_BLOCK_DATA_ORDER(c, data, n);
        n *= SHA256_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (unsigned char *)c->data;
        c->num = (unsigned int)len;
        memcpy(p, data, len);
    }
    return 1;
//    return SHA256_Update(ctx->md_data, data, count);
}

int sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA256_Final(md, ctx->md_data);
}
