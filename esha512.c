#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int sha512_init(EVP_MD_CTX *ctx)
{
	SHA512_CTX *c = ctx->md_data;
	memset(c, 0, sizeof(*c));
    c->h[0] = U64(0x6a09e667f3bcc908);
    c->h[1] = U64(0xbb67ae8584caa73b);
    c->h[2] = U64(0x3c6ef372fe94f82b);
    c->h[3] = U64(0xa54ff53a5f1d36f1);
    c->h[4] = U64(0x510e527fade682d1);
    c->h[5] = U64(0x9b05688c2b3e6c1f);
    c->h[6] = U64(0x1f83d9abfb41bd6b);
    c->h[7] = U64(0x5be0cd19137e2179);

    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = SHA512_DIGEST_LENGTH;
    return 1;
}

#  ifndef PULL64
#   define B(x,j)    (((SHA_LONG64)(*(((const unsigned char *)(&x))+j)))<<((7-j)*8))
#   define PULL64(x) (B(x,0)|B(x,1)|B(x,2)|B(x,3)|B(x,4)|B(x,5)|B(x,6)|B(x,7))
#  endif
#  ifndef ROTR
#   define ROTR(x,s)       (((x)>>s) | (x)<<(64-s))
#  endif
#  define Sigma0(x)       (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
#  define Sigma1(x)       (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
#  define sigma0(x)       (ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
#  define sigma1(x)       (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))
#  define Ch(x,y,z)       (((x) & (y)) ^ ((~(x)) & (z)))
#  define Maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#   define ROUND_00_15(i,a,b,c,d,e,f,g,h)          do {    \
        T1 += h + Sigma1(e) + Ch(e,f,g) + K512[i];      \
        h = Sigma0(a) + Maj(a,b,c);                     \
        d += T1;        h += T1;                } while (0)
#   define ROUND_16_80(i,j,a,b,c,d,e,f,g,h,X)      do {    \
        s0 = X[(j+1)&0x0f];     s0 = sigma0(s0);        \
        s1 = X[(j+14)&0x0f];    s1 = sigma1(s1);        \
        T1 = X[(j)&0x0f] += s0 + s1 + X[(j+9)&0x0f];    \
        ROUND_00_15(i+j,a,b,c,d,e,f,g,h);               } while (0)


static void sha512_block_data_order(SHA512_CTX *ctx, const void *in,
                                    size_t num)
{
    const SHA_LONG64 *W = in;
    SHA_LONG64 a, b, c, d, e, f, g, h, s0, s1, T1;
    SHA_LONG64 X[16];
    int i;

    while (num--) {

        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        T1 = X[0] = PULL64(W[0]);
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = PULL64(W[1]);
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = PULL64(W[2]);
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = PULL64(W[3]);
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = PULL64(W[4]);
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = PULL64(W[5]);
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = PULL64(W[6]);
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = PULL64(W[7]);
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = PULL64(W[8]);
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = PULL64(W[9]);
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = PULL64(W[10]);
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = PULL64(W[11]);
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = PULL64(W[12]);
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = PULL64(W[13]);
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = PULL64(W[14]);
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = PULL64(W[15]);
        ROUND_00_15(15, b, c, d, e, f, g, h, a);

        for (i = 16; i < 80; i += 16) {
            ROUND_16_80(i, 0, a, b, c, d, e, f, g, h, X);
            ROUND_16_80(i, 1, h, a, b, c, d, e, f, g, X);
            ROUND_16_80(i, 2, g, h, a, b, c, d, e, f, X);
            ROUND_16_80(i, 3, f, g, h, a, b, c, d, e, X);
            ROUND_16_80(i, 4, e, f, g, h, a, b, c, d, X);
            ROUND_16_80(i, 5, d, e, f, g, h, a, b, c, X);
            ROUND_16_80(i, 6, c, d, e, f, g, h, a, b, X);
            ROUND_16_80(i, 7, b, c, d, e, f, g, h, a, X);
            ROUND_16_80(i, 8, a, b, c, d, e, f, g, h, X);
            ROUND_16_80(i, 9, h, a, b, c, d, e, f, g, X);
            ROUND_16_80(i, 10, g, h, a, b, c, d, e, f, X);
            ROUND_16_80(i, 11, f, g, h, a, b, c, d, e, X);
            ROUND_16_80(i, 12, e, f, g, h, a, b, c, d, X);
            ROUND_16_80(i, 13, d, e, f, g, h, a, b, c, X);
            ROUND_16_80(i, 14, c, d, e, f, g, h, a, b, X);
            ROUND_16_80(i, 15, b, c, d, e, f, g, h, a, X);
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        W += SHA_LBLOCK;
    }
}

int sha512_update(EVP_MD_CTX *ctx, const void *_data, size_t len)
{
	SHA512_CTX *c = ctx->md_data;
    SHA_LONG64 l;
    unsigned char *p = c->u.p;
    const unsigned char *data = (const unsigned char *)_data;

    if (len == 0)
        return 1;

    l = (c->Nl + (((SHA_LONG64) len) << 3)) & U64(0xffffffffffffffff);
    if (l < c->Nl)
        c->Nh++;
    if (sizeof(len) >= 8)
        c->Nh += (((SHA_LONG64) len) >> 61);
    c->Nl = l;

    if (c->num != 0) {
        size_t n = sizeof(c->u) - c->num;

        if (len < n) {
            memcpy(p + c->num, data, len), c->num += (unsigned int)len;
            return 1;
        } else {
            memcpy(p + c->num, data, n), c->num = 0;
            len -= n, data += n;
            sha512_block_data_order(c, p, 1);
        }
    }

    if (len >= sizeof(c->u)) {
            sha512_block_data_order(c, data, len / sizeof(c->u)),
                data += len, len %= sizeof(c->u), data -= len;
    }

    if (len != 0)
        memcpy(p, data, len), c->num = (int)len;

    return 1;
//    return SHA512_Update(ctx->md_data, data, count);
}

int sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	SHA512_CTX *c = ctx->md_data;
    unsigned char *p = (unsigned char *)c->u.p;
    size_t n = c->num;

    p[n] = 0x80;                /* There always is a room for one */
    n++;
    if (n > (sizeof(c->u) - 16))
        memset(p + n, 0, sizeof(c->u) - n), n = 0,
            sha512_block_data_order(c, p, 1);

    memset(p + n, 0, sizeof(c->u) - 16 - n);
    
    p[sizeof(c->u) - 1] = (unsigned char)(c->Nl);
    p[sizeof(c->u) - 2] = (unsigned char)(c->Nl >> 8);
    p[sizeof(c->u) - 3] = (unsigned char)(c->Nl >> 16);
    p[sizeof(c->u) - 4] = (unsigned char)(c->Nl >> 24);
    p[sizeof(c->u) - 5] = (unsigned char)(c->Nl >> 32);
    p[sizeof(c->u) - 6] = (unsigned char)(c->Nl >> 40);
    p[sizeof(c->u) - 7] = (unsigned char)(c->Nl >> 48);
    p[sizeof(c->u) - 8] = (unsigned char)(c->Nl >> 56);
    p[sizeof(c->u) - 9] = (unsigned char)(c->Nh);
    p[sizeof(c->u) - 10] = (unsigned char)(c->Nh >> 8);
    p[sizeof(c->u) - 11] = (unsigned char)(c->Nh >> 16);
    p[sizeof(c->u) - 12] = (unsigned char)(c->Nh >> 24);
    p[sizeof(c->u) - 13] = (unsigned char)(c->Nh >> 32);
    p[sizeof(c->u) - 14] = (unsigned char)(c->Nh >> 40);
    p[sizeof(c->u) - 15] = (unsigned char)(c->Nh >> 48);
    p[sizeof(c->u) - 16] = (unsigned char)(c->Nh >> 56);
    
	sha512_block_data_order(c, p, 1);

    if (md == 0)
        return 0;

    switch (c->md_len) {
    case SHA384_DIGEST_LENGTH:
        for (n = 0; n < SHA384_DIGEST_LENGTH / 8; n++) {
            SHA_LONG64 t = c->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
    case SHA512_DIGEST_LENGTH:
        for (n = 0; n < SHA512_DIGEST_LENGTH / 8; n++) {
            SHA_LONG64 t = c->h[n];

            *(md++) = (unsigned char)(t >> 56);
            *(md++) = (unsigned char)(t >> 48);
            *(md++) = (unsigned char)(t >> 40);
            *(md++) = (unsigned char)(t >> 32);
            *(md++) = (unsigned char)(t >> 24);
            *(md++) = (unsigned char)(t >> 16);
            *(md++) = (unsigned char)(t >> 8);
            *(md++) = (unsigned char)(t);
        }
        break;
        /* ... as well as make sure md_len is not abused. */
    default:
        return 0;
    }

    return 1;

//    return SHA512_Final(md, ctx->md_data);
}
