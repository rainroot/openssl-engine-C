# define KC0     0x9e3779b9
# define KC1     0x3c6ef373
# define KC2     0x78dde6e6
# define KC3     0xf1bbcdcc
# define KC4     0xe3779b99
# define KC5     0xc6ef3733
# define KC6     0x8dde6e67
# define KC7     0x1bbcdccf
# define KC8     0x3779b99e
# define KC9     0x6ef3733c
# define KC10    0xdde6e678
# define KC11    0xbbcdccf1
# define KC12    0x779b99e3
# define KC13    0xef3733c6
# define KC14    0xde6e678d
# define KC15    0xbcdccf1b
# define KC16    0x79b99e37
# define KC17    0xf3733c6e
# define KC18    0xe6e678dd
# define KC19    0xcdccf1bb
# define KC20    0x9b99e377
# define KC21    0x3733c6ef
# define KC22    0x6e678dde
# define KC23    0xdccf1bbc

# define SEED_BLOCK_SIZE 16
# define SEED_KEY_LENGTH 16
# define SEED192_KEY_LENGTH 24
# define SEED256_KEY_LENGTH 32

typedef unsigned int seed_word;

# define G_FUNC(v)       \
        SS[0][(unsigned char)      (v) & 0xff] ^ SS[1][(unsigned char) ((v)>>8) & 0xff] ^ \
        SS[2][(unsigned char)((v)>>16) & 0xff] ^ SS[3][(unsigned char)((v)>>24) & 0xff]

# define char2word(c, i)  \
        (i) = ((((seed_word)(c)[0]) << 24) | (((seed_word)(c)[1]) << 16) | (((seed_word)(c)[2]) << 8) | ((seed_word)(c)[3]))

# define word2char(l, c)  \
        *((c)+0) = (unsigned char)((l)>>24) & 0xff; \
        *((c)+1) = (unsigned char)((l)>>16) & 0xff; \
        *((c)+2) = (unsigned char)((l)>> 8) & 0xff; \
        *((c)+3) = (unsigned char)((l))     & 0xff

# define KEYSCHEDULE_UPDATE0(T0, T1, X1, X2, X3, X4, KC)  \
        (T0) = (X3);                                     \
        (X3) = (((X3)<<8) ^ ((X4)>>24)) & 0xffffffff;    \
        (X4) = (((X4)<<8) ^ ((T0)>>24)) & 0xffffffff;    \
        (T0) = ((X1) + (X3) - (KC))     & 0xffffffff;    \
        (T1) = ((X2) + (KC) - (X4))     & 0xffffffff

# define KEYSCHEDULE_UPDATE1(T0, T1, X1, X2, X3, X4, KC)  \
        (T0) = (X1);                                     \
        (X1) = (((X1)>>8) ^ ((X2)<<24)) & 0xffffffff;    \
        (X2) = (((X2)>>8) ^ ((T0)<<24)) & 0xffffffff;    \
        (T0) = ((X1) + (X3) - (KC))     & 0xffffffff;     \
        (T1) = ((X2) + (KC) - (X4))     & 0xffffffff

# define KEYSCHEDULE192_UPDATE0(T0, T1, X1, X2, X3, X4, X5, X6, KC, rot)    \
    (T0) = (X3);                                \
    (X3) = ((X3)>>rot) ^ ((X2)<<(32-rot));                  \
    (X2) = ((X2)>>rot) ^ ((X1)<<(32-rot));                  \
    (X1) = ((X1)>>rot) ^ ((T0)<<(32-rot));                  \
    (T0) = (((X1) + (X3)) ^ (X4)) - (KC);                   \
    (T1) = (((X2) - (X5)) ^ (X6)) + (KC)

# define KEYSCHEDULE192_UPDATE1(T0, T1, X1, X2, X3, X4, X5, X6, KC, rot)    \
    (T0) = (X6);                                \
    (X6) = ((X6)>>rot) ^ ((X5)>>(32-rot));                  \
    (X5) = ((X5)>>rot) ^ ((X4)>>(32-rot));                  \
    (X4) = ((X4)>>rot) ^ ((X3)>>(32-rot));                  \
    (T0) = (((X1) + (X3)) ^ (X4)) - (KC);                                   \
        (T1) = (((X2) - (X5)) ^ (X6)) + (KC)

# define KEYSCHEDULE256_UPDATE1(T0, T1, X1, X2, X3, X4, X5, X6, X7, X8, KC, rot)    \
    (T0) = (X4);                                    \
    (X4) = (((X4)>>rot) ^ ((X3)<<(32-rot)));                        \
    (X3) = (((X3)>>rot) ^ ((X2)<<(32-rot)));                        \
    (X2) = (((X2)>>rot) ^ ((X1)<<(32-rot)));                        \
    (X1) = (((X1)>>rot) ^ ((T0)<<(32-rot)));                        \
    (T0) = (((((X1) + (X3)) ^ (X5)) - (X4)) ^ KC);                  \
    (T1) = (((((X2) - (X4)) ^ (X7)) + (X8)) ^ KC)

# define KEYSCHEDULE256_UPDATE0(T0, T1, X1, X2, X3, X4, X5, X6, X7, X8, KC, rot)    \
    (T0) = (X5);                                    \
    (X5) = (((X5)<<rot) ^ ((X4)>>(32-rot)));                        \
    (X4) = (((X4)<<rot) ^ ((X7)>>(32-rot)));                        \
    (X7) = (((X7)<<rot) ^ ((X8)>>(32-rot)));                        \
    (X8) = (((X8)<<rot) ^ ((T0)>>(32-rot)));                        \
    (T0) = (((((X1) + (X3)) ^ (X5)) - (X4)) ^ KC);                  \
    (T1) = (((((X2) - (X4)) ^ (X7)) + (X8)) ^ KC)

# define KEYUPDATE_TEMP(T0, T1, K)   \
        (K)[0] = G_FUNC((T0));      \
        (K)[1] = G_FUNC((T1))

# define E_SEED(T0, T1, X1, X2, X3, X4, rbase)   \
        (T0) = (X3) ^ (ks->data)[(rbase)];       \
        (T1) = (X4) ^ (ks->data)[(rbase)+1];     \
        (T1) ^= (T0);                            \
        (T1) = G_FUNC((T1));                     \
        (T0) = ((T0) + (T1)) & 0xffffffff;       \
        (T0) = G_FUNC((T0));                     \
        (T1) = ((T1) + (T0)) & 0xffffffff;       \
        (T1) = G_FUNC((T1));                     \
        (T0) = ((T0) + (T1)) & 0xffffffff;       \
        (X1) ^= (T0);                            \
        (X2) ^= (T1)

#if 0
#define ROTL(x, n)     (((x) << (n)) | ((x) >> (32-(n))))
#define ROTR(x, n)     (((x) >> (n)) | ((x) << (32-(n))))

#define GetB0(A)  ( (unsigned char)((A)    ) )
#define GetB1(A)  ( (unsigned char)((A)>> 8) )
#define GetB2(A)  ( (unsigned char)((A)>>16) )
#define GetB3(A)  ( (unsigned char)((A)>>24) )
#endif


typedef struct seed_key_st {
    unsigned int data[48];
} SEED_KEY_SCHEDULE;

typedef struct {
	SEED_KEY_SCHEDULE ks;
} EOPENSSL_SEED_KEY;

int seed_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int seed_192_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int seed_256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int seed_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int seed_192_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int seed_256_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int seed_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int seed_192_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int seed_256_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

