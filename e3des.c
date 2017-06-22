#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule)
{
    static const int shifts2[16] =
        { 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0 };
    register DES_LONG c, d, t, s, t2;
    register const unsigned char *in;
    register DES_LONG *k;
    register int i;

    k = &schedule->ks->deslong[0];
    in = &(*key)[0];

    c2l(in, c);
    c2l(in, d);

    PERM_OP(d, c, t, 4, 0x0f0f0f0fL);
    HPERM_OP(c, t, -2, 0xcccc0000L);
    HPERM_OP(d, t, -2, 0xcccc0000L);
    PERM_OP(d, c, t, 1, 0x55555555L);
    PERM_OP(c, d, t, 8, 0x00ff00ffL);
    PERM_OP(d, c, t, 1, 0x55555555L);
    d = (((d & 0x000000ffL) << 16L) | (d & 0x0000ff00L) |
         ((d & 0x00ff0000L) >> 16L) | ((c & 0xf0000000L) >> 4L));
    c &= 0x0fffffffL;

    for (i = 0; i < ITERATIONS; i++) {
        if (shifts2[i]) {
            c = ((c >> 2L) | (c << 26L));
            d = ((d >> 2L) | (d << 26L));
        } else {
            c = ((c >> 1L) | (c << 27L));
            d = ((d >> 1L) | (d << 27L));
        }
        c &= 0x0fffffffL;
        d &= 0x0fffffffL;

        s = des_skb[0][(c) & 0x3f] |
            des_skb[1][((c >> 6L) & 0x03) | ((c >> 7L) & 0x3c)] |
            des_skb[2][((c >> 13L) & 0x0f) | ((c >> 14L) & 0x30)] |
            des_skb[3][((c >> 20L) & 0x01) | ((c >> 21L) & 0x06) |
                       ((c >> 22L) & 0x38)];
        t = des_skb[4][(d) & 0x3f] |
            des_skb[5][((d >> 7L) & 0x03) | ((d >> 8L) & 0x3c)] |
            des_skb[6][(d >> 15L) & 0x3f] |
            des_skb[7][((d >> 21L) & 0x0f) | ((d >> 22L) & 0x30)];

        t2 = ((t << 16L) | (s & 0x0000ffffL)) & 0xffffffffL;
        *(k++) = ROTATE(t2, 30) & 0xffffffffL;

        t2 = ((s >> 16L) | (t & 0xffff0000L));
        *(k++) = ROTATE(t2, 26) & 0xffffffffL;
    }
}

int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
	if(enc){}
    fprintf(stderr, "(ENGINE_OPENSSL_DES3) eopenssl_des_ede3_init_key() called\n");

    DES_cblock *deskey = (DES_cblock *)key;
    EOPENSSL_DES_EDE_KEY *dat = eopenssl_des3(ctx);

    dat->stream.cbc = NULL;

    DES_set_key_unchecked(&deskey[0], &dat->ks.ks[0]);
    DES_set_key_unchecked(&deskey[1], &dat->ks.ks[1]);
    DES_set_key_unchecked(&deskey[2], &dat->ks.ks[2]);

    return 1;
}

void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc)
{
    register DES_LONG l, r, t, u;
#ifndef DES_UNROLL
    register int i;
#endif
    register DES_LONG *s;

    r = data[0];
    l = data[1];

    r = ROTATE(r, 29) & 0xffffffffL;
    l = ROTATE(l, 29) & 0xffffffffL;

    s = ks->ks->deslong;

    if (enc) {
        for (i = 0; i < 32; i += 4) {
            D_ENCRYPT(l, r, i + 0); /* 1 */
            D_ENCRYPT(r, l, i + 2); /* 2 */
        }
        for (i = 30; i > 0; i -= 4) {
            D_ENCRYPT(l, r, i - 0); /* 16 */
            D_ENCRYPT(r, l, i - 2); /* 15 */
        }
	}
    data[0] = ROTATE(l, 3) & 0xffffffffL;
    data[1] = ROTATE(r, 3) & 0xffffffffL;
    l = r = t = u = 0;
}

void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3)
{
    register DES_LONG l, r;

    l = data[0];
    r = data[1];
    IP(l, r);
    data[0] = l;
    data[1] = r;
    DES_encrypt2((DES_LONG *)data, ks1, DES_ENCRYPT);
    DES_encrypt2((DES_LONG *)data, ks2, DES_DECRYPT);
    DES_encrypt2((DES_LONG *)data, ks3, DES_ENCRYPT);
    l = data[0];
    r = data[1];
    FP(r, l);
    data[0] = l;
    data[1] = r;
}

void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1,
                  DES_key_schedule *ks2, DES_key_schedule *ks3)
{
    register DES_LONG l, r;

    l = data[0];
    r = data[1];
    IP(l, r);
    data[0] = l;
    data[1] = r;
    DES_encrypt2((DES_LONG *)data, ks3, DES_DECRYPT);
    DES_encrypt2((DES_LONG *)data, ks2, DES_ENCRYPT);
    DES_encrypt2((DES_LONG *)data, ks1, DES_DECRYPT);
    l = data[0];
    r = data[1];
    FP(r, l);
    data[0] = l;
    data[1] = r;
}

void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec, int enc)
{
    register DES_LONG tin0, tin1;
    register DES_LONG tout0, tout1, xor0, xor1;
    register const unsigned char *in;
    unsigned char *out;
    register long l = length;
    DES_LONG tin[2];
    unsigned char *iv;

    in = input;
    out = output;
    iv = &(*ivec)[0];

    if (enc) {
        c2l(iv, tout0);
        c2l(iv, tout1);
        for (l -= 8; l >= 0; l -= 8) {
            c2l(in, tin0);
            c2l(in, tin1);
            tin0 ^= tout0;
            tin1 ^= tout1;

            tin[0] = tin0;
            tin[1] = tin1;
            DES_encrypt3((DES_LONG *)tin, ks1, ks2, ks3);
            tout0 = tin[0];
            tout1 = tin[1];

            l2c(tout0, out);
            l2c(tout1, out);
        }
        if (l != -8) {
            c2ln(in, tin0, tin1, l + 8);
            tin0 ^= tout0;
            tin1 ^= tout1;

            tin[0] = tin0;
            tin[1] = tin1;
            DES_encrypt3((DES_LONG *)tin, ks1, ks2, ks3);
            tout0 = tin[0];
            tout1 = tin[1];

            l2c(tout0, out);
            l2c(tout1, out);
        }
        iv = &(*ivec)[0];
        l2c(tout0, iv);
        l2c(tout1, iv);
    } else {
        register DES_LONG t0, t1;

        c2l(iv, xor0);
        c2l(iv, xor1);
        for (l -= 8; l >= 0; l -= 8) {
            c2l(in, tin0);
            c2l(in, tin1);

            t0 = tin0;
            t1 = tin1;

            tin[0] = tin0;
            tin[1] = tin1;
            DES_decrypt3((DES_LONG *)tin, ks1, ks2, ks3);
            tout0 = tin[0];
            tout1 = tin[1];

            tout0 ^= xor0;
            tout1 ^= xor1;
            l2c(tout0, out);
            l2c(tout1, out);
            xor0 = t0;
            xor1 = t1;
        }
        if (l != -8) {
            c2l(in, tin0);
            c2l(in, tin1);

            t0 = tin0;
            t1 = tin1;

            tin[0] = tin0;
            tin[1] = tin1;
            DES_decrypt3((DES_LONG *)tin, ks1, ks2, ks3);
            tout0 = tin[0];
            tout1 = tin[1];

            tout0 ^= xor0;
            tout1 ^= xor1;
            l2cn(tout0, tout1, out, l + 8);
            xor0 = t0;
            xor1 = t1;
        }

        iv = &(*ivec)[0];
        l2c(xor0, iv);
        l2c(xor1, iv);
    }
    tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
    tin[0] = tin[1] = 0;
}

int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_DES3) des_ede_cbc_cipher() called\n");

    EOPENSSL_DES_EDE_KEY *dat = eopenssl_des3(ctx);

    if (dat->stream.cbc) {
        (*dat->stream.cbc) (in, out, inl, dat->ks.ks, ctx->iv);
        return 1;
    }

    while (inl >= EVP_MAXCHUNK) {
        DES_ede3_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &dat->ks.ks[0], &dat->ks.ks[1], &dat->ks.ks[2], (DES_cblock *)ctx->iv, ctx->encrypt);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl)
        DES_ede3_cbc_encrypt(in, out, (long)inl, &dat->ks.ks[0], &dat->ks.ks[1], &dat->ks.ks[2], (DES_cblock *)ctx->iv, ctx->encrypt);

    return 1;
}
