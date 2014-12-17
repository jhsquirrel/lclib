#ifndef rsa_h
#define rsa_h
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "lbn32.h"
#include "kludge.h"
#include "bn.h"
#include "prime.h"
#include "bnprint.h"
#include "err.h"

typedef struct{
unsigned long int bits;
unsigned long int ebits;
struct BigNum n;
struct BigNum e;
struct BigNum d;
}RSA_CTX;

int rsa_INIT(RSA_CTX *ctx,unsigned long int bitlen);
int rsa_INIT_N(RSA_CTX *ctx,unsigned long int bitlen);
int rsa_INIT_d(RSA_CTX *ctx,unsigned long int bitlen);
int rsa_INIT_e(RSA_CTX *ctx);

int rsa_END(RSA_CTX *ctx);
int rsa_END_N(RSA_CTX *ctx);
int rsa_END_d(RSA_CTX *ctx);
int rsa_END_e(RSA_CTX *ctx);

int rsa_GENKEYS(RSA_CTX *ctx,unsigned char *s1,unsigned char *s2);
int rsa_SETKEYS(RSA_CTX *ctx,unsigned char *N,unsigned char *d,
unsigned char *e);

int rsa_SETKEY_N(RSA_CTX *ctx,unsigned char *N);
int rsa_SETKEY_e(RSA_CTX *ctx,unsigned char *e);
int rsa_SETKEY_d(RSA_CTX *ctx,unsigned char *d);

int rsa_EXTRACTKEYS(RSA_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e);
int rsa_FREEKEYS(RSA_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e);
int rsa_ENCRYPTPUBLIC(RSA_CTX *ctx,unsigned char *data,unsigned long int 
*datLen);
int rsa_DECRYPTPUBLIC(RSA_CTX *ctx,unsigned char *data,unsigned long int 
*datLen);
int rsa_ENCRYPTPRIVATE(RSA_CTX *ctx,unsigned char *data,unsigned long int 
*datLen);
int rsa_DECRYPTPRIVATE(RSA_CTX *ctx,unsigned char *data,unsigned long int 
*datLen);
#endif
