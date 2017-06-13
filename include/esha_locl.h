#define F_00_19(b,c,d)  ((((c) ^ (d)) & (b)) ^ (d))
#define F_20_39(b,c,d)  ((b) ^ (c) ^ (d))
#define F_40_59(b,c,d)  (((b) & (c)) | (((b)|(c)) & (d)))
#define F_60_79(b,c,d)  F_20_39(b,c,d)

#  define MD32_REG_T int

#  define HOST_c2l(c,l)   (l =(((unsigned long)(*((c)++)))<<24),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))    )           )

#  define HOST_l2c(l,c)   (*((c)++)=(unsigned char)(((l)>>24)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)    )&0xff),      \
                         l)

# define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

#  define Xupdate(a,ix,ia,ib,ic,id)     ( (a)=(ia^ib^ic^id),    \
                                          ix=(a)=ROTATE((a),1)  \
                                        )

#define HASH_MAKE_STRING(c,s)   do {    \
        unsigned long ll;               \
        ll=(c)->h0; (void)HOST_l2c(ll,(s));     \
        ll=(c)->h1; (void)HOST_l2c(ll,(s));     \
        ll=(c)->h2; (void)HOST_l2c(ll,(s));     \
        ll=(c)->h3; (void)HOST_l2c(ll,(s));     \
        ll=(c)->h4; (void)HOST_l2c(ll,(s));     \
        } while (0)


# define BODY_00_15(xi)           do {   \
        T=E+K_00_19+F_00_19(B,C,D);     \
        E=D, D=C, C=ROTATE(B,30), B=A;  \
        A=ROTATE(A,5)+T+xi;         } while(0)

# define BODY_16_19(xa,xb,xc,xd)  do {   \
        Xupdate(T,xa,xa,xb,xc,xd);      \
        T+=E+K_00_19+F_00_19(B,C,D);    \
        E=D, D=C, C=ROTATE(B,30), B=A;  \
        A=ROTATE(A,5)+T;            } while(0)

# define BODY_20_39(xa,xb,xc,xd)  do {   \
        Xupdate(T,xa,xa,xb,xc,xd);      \
        T+=E+K_20_39+F_20_39(B,C,D);    \
        E=D, D=C, C=ROTATE(B,30), B=A;  \
        A=ROTATE(A,5)+T;            } while(0)

# define BODY_40_59(xa,xb,xc,xd)  do {   \
        Xupdate(T,xa,xa,xb,xc,xd);      \
        T+=E+K_40_59+F_40_59(B,C,D);    \
        E=D, D=C, C=ROTATE(B,30), B=A;  \
        A=ROTATE(A,5)+T;            } while(0)

# define BODY_60_79(xa,xb,xc,xd)  do {   \
        Xupdate(T,xa,xa,xb,xc,xd);      \
        T=E+K_60_79+F_60_79(B,C,D);     \
        E=D, D=C, C=ROTATE(B,30), B=A;  \
        A=ROTATE(A,5)+T+xa;         } while(0)
