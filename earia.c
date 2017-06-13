#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int aria_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
    fprintf(stderr, "(ENGINE_OPENSSL_ARIA) aria_init_key() called\n");

    int ret;

    if ((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CFB_MODE
        || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_OFB_MODE
        || enc)
        ret=ARIA_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
    else
        ret=ARIA_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);

    if(ret < 0)
    {
        EVPerr(EVP_F_ARIA_INIT_KEY,EVP_R_ARIA_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

int aria_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_ARIA) aria_ecb_cipher() called\n");

    size_t i, bl;
    EOPENSSL_ARIA_KEY *dat = (EOPENSSL_ARIA_KEY *) ctx->cipher_data;

    bl = ctx->cipher->block_size;

    if(inl < bl)
        return 1;

    inl -= bl;

    for(i=0; i <= inl; i+=bl)
        ARIA_ecb_encrypt(in + i, out + i, &dat->ks, ctx->encrypt);

    return 1;
}

int aria_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_ARIA) aria_cbc_cipher() called\n");

    EOPENSSL_ARIA_KEY *dat = (EOPENSSL_ARIA_KEY *) ctx->cipher_data;

    while(inl>=EVP_MAXCHUNK)
    {
        ARIA_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &dat->ks, ctx->iv, ctx->encrypt);
        inl-=EVP_MAXCHUNK;
        in +=EVP_MAXCHUNK;
        out+=EVP_MAXCHUNK;
    }
    if (inl)
        ARIA_cbc_encrypt(in, out, (long)inl, &dat->ks, ctx->iv, ctx->encrypt);
    return 1;
}
