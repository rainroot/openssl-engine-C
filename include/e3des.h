typedef struct {
    union {
        double align;
        DES_key_schedule ks[3];
    } ks;
    union {
        void (*cbc) (const void *, void *, size_t,
                     const DES_key_schedule *, unsigned char *);
    } stream;
} EOPENSSL_DES_EDE_KEY;
# define eopenssl_des3(ctx) ((EOPENSSL_DES_EDE_KEY *)(ctx)->cipher_data)


int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);
void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec, int enc);
int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

