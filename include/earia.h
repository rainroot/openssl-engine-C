#define ARIA_ENCRYPT    1
#define ARIA_DECRYPT    0

#define ARIA_MAXNR		16
#define ARIA_BLOCK_SIZE 16

struct aria_key_st {
    unsigned char rd_key[ARIA_BLOCK_SIZE*(ARIA_MAXNR+1)];
    int rounds;
};
typedef struct aria_key_st ARIA_KEY_SCHEDULE;

typedef struct
{
    ARIA_KEY_SCHEDULE ks;
} EOPENSSL_ARIA_KEY;

#define eopenssl_aria(ctx)  EVP_C_DATA(EOPENSSL_ARIA_KEY,ctx)

void DL (const unsigned char *i, unsigned char *o);
void RotXOR (const unsigned char *s, int n, unsigned char *t);
int ARIA_set_encrypt_key(const unsigned char *userKey, int bits, ARIA_KEY_SCHEDULE *key);
int ARIA_set_decrypt_key(const unsigned char *userKey, int bits, ARIA_KEY_SCHEDULE *key);
void ARIA_encrypt(const unsigned char *in, unsigned char *out, ARIA_KEY_SCHEDULE *key, const int enc);
int aria_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int aria_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
void ARIA_cbc_encrypt(const unsigned char *in, unsigned char *out, const unsigned long length, ARIA_KEY_SCHEDULE *key, unsigned char *ivec, const int enc);
int aria_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);


