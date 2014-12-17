/*
 * Author	: John Horton
 * E-mail	: jh_squirrel@yahoo.com
 * Date		: 2002
 * Description	: C implementation of blowfish (in ebc and cbc modes) 
 *			and SHA along with RSA using bnlib-1.1
 */

#ifndef lclib_h
#define lclib_h
#include <stdio.h>
#include "Blowfish.h"
#include "sha.h"
#include "rsa.h"

#define BFBLOCKLENGTH 8
#define MAXBITS 1024

typedef struct{
unsigned long l;
unsigned long r;
}IV;

typedef struct{
IV bf_iv;
BLOWFISH_CTX bf_ctx;
SHA_INFO sha_ctx;
RSA_CTX rsa_ctx;
}LCLIB_CTX;


int bf_ebc_init(LCLIB_CTX *ctx, unsigned char *key, unsigned int keyLen);
int bf_ebc_enc(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datlen,
int pad);
int bf_ebc_dec(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datlen,
int pad);

int bf_cbc_init(LCLIB_CTX *ctx, unsigned char *key, unsigned int keyLen,
 unsigned long int l,unsigned long int r);
int bf_cbc_enc(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datlen,
int pad);
int bf_cbc_dec(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datlen,
int pad);

int sha_hash_init(LCLIB_CTX *ctx);
int sha_hash_update(LCLIB_CTX *ctx, unsigned char *data, unsigned int datLen);
int sha_hash_final(LCLIB_CTX *ctx);

int rsa_init(LCLIB_CTX *ctx,unsigned long int bitlen);

int rsa_init_n(LCLIB_CTX *ctx,unsigned long int bitlen);
int rsa_init_d(LCLIB_CTX *ctx,unsigned long int bitlen);
int rsa_init_e(LCLIB_CTX *ctx);

void rsa_end_n(LCLIB_CTX *ctx);
void rsa_end_d(LCLIB_CTX *ctx);
void rsa_end_e(LCLIB_CTX *ctx);

int rsa_genkeys(LCLIB_CTX *ctx,unsigned char *s1,unsigned long int l1,\
unsigned char *s2,unsigned long int l2);
int rsa_genkeys_internal(LCLIB_CTX *ctx);
int rsa_setkeys(LCLIB_CTX *ctx,unsigned char *N,unsigned char *d,
unsigned char *e);

int rsa_setkey_n(LCLIB_CTX *ctx,unsigned char *N);
int rsa_setkey_e(LCLIB_CTX *ctx,unsigned char *e);
int rsa_setkey_d(LCLIB_CTX *ctx,unsigned char *d);

int rsa_extractkeys(LCLIB_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e);
int rsa_freekeys(LCLIB_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e);
int rsa_encrypt(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen);
int rsa_decrypt(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen);

int rsa_sign(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen);
int rsa_verify(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen);

void lclib_end(LCLIB_CTX *ctx);

unsigned char* rsa_alloc(LCLIB_CTX *ctx,unsigned char *data,unsigned long size);
void rsa_free(unsigned char *data);
#endif
