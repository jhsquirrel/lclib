/* lclib - linux cryptography library
**
** Copyright © 2002 by John Horton <jh_squirrel@yahoo.com>. All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#ifndef rsa_c
#define rsa_c
#include "rsa.h"
static unsigned char* Lmalloc(int size);
static int Lfree(unsigned char *mem,int size);

static unsigned char* Lmalloc(int size){
	unsigned char *a;
	int r;
	a=(unsigned char*)malloc(size);
	if(a==NULL)
		return NULL;
	r=mlock((void*)a,size);
	return a;
}

static int Lfree(unsigned char *mem,int size){
	int r;
	r=munlock((void*)mem,size);
	if(r<0)
		return BADFREE;
	free(mem);
	return OK;
}

int rsa_INIT(RSA_CTX *ctx,unsigned long int bitlen){
/* e is <i> always </i> 3 ;) */
int t;
bnBegin(&ctx->n);
bnBegin(&ctx->e);
bnBegin(&ctx->d);
t=bnSetQ(&ctx->e,(unsigned long int)3);
if(t<0){
	bnEnd(&ctx->n);
	bnEnd(&ctx->e);
	bnEnd(&ctx->d);
	return BADTHINGS;
}
ctx->bits=bitlen;
ctx->ebits=sizeof(unsigned long int);
return OK;
}

int rsa_INIT_N(RSA_CTX *ctx,unsigned long int bitlen){
bnBegin(&ctx->n);
ctx->bits=bitlen;
return OK;
}

int rsa_INIT_d(RSA_CTX *ctx,unsigned long int bitlen){
bnBegin(&ctx->d);
ctx->bits=bitlen;
return OK;
}

int rsa_INIT_e(RSA_CTX *ctx){
bnBegin(&ctx->e);
ctx->ebits=sizeof(unsigned long int);
return OK;
}

int rsa_END(RSA_CTX *ctx){
bnEnd(&ctx->n);
bnEnd(&ctx->e);
bnEnd(&ctx->d);
return OK;
}

int rsa_END_N(RSA_CTX *ctx){
bnEnd(&ctx->n);
return OK;
}

int rsa_END_d(RSA_CTX *ctx){
bnEnd(&ctx->d);
return OK;
}

int rsa_END_e(RSA_CTX *ctx){
bnEnd(&ctx->e);
return OK;
}

int rsa_GENKEYS(RSA_CTX *ctx,unsigned char *s1,unsigned char *s2){
int t,c;
unsigned long int MB=(ctx->bits)/2;
struct BigNum bn;
struct BigNum p,q;
int len=MB/8;
if(ctx->bits==0)
	return BADDATALEN;
bnBegin(&bn);
bnBegin(&p);
bnBegin(&q);
t=bnInsertBigBytes(&p,(void*)s1,0,len);
c=bnInsertBigBytes(&q,(void*)s2,0,len);
if(t<0 || c<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
	return BADTHINGS;
}
t=primeGen(&p,NULL,NULL,NULL,1,3,5,0);
c=primeGen(&q,NULL,NULL,NULL,1,3,5,0);
if(t<0 || c<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
	return BADTHINGS;
}

t=bnMul(&ctx->n,&p,&q);
if(t<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
	return BADTHINGS;
}
t=bnSubQ(&p,1);
if(t<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
        return BADTHINGS;
}
t=bnSubQ(&q,1);
if(t<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
        return BADTHINGS;
}
t=bnMul(&bn,&p,&q);
if(t<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
        return BADTHINGS;
}
t=bnInv(&ctx->d,&ctx->e,&bn);
if(t<0){
	bnEnd(&bn);
	bnEnd(&p);
	bnEnd(&q);
        return BADTHINGS;
}
bnEnd(&bn);
bnEnd(&p);
bnEnd(&q);
return OK;
}

int rsa_SETKEYS(RSA_CTX *ctx,unsigned char *N,unsigned char *d,
unsigned char *e){
int t;
/* we store in big - endian */
t=bnInsertBigBytes(&ctx->n,(void*)N,0,/*strlen(N)*/ctx->bits/8);
if(t<0)
	return BADTHINGS;
t=bnInsertBigBytes(&ctx->d,(void*)d,0,/*strlen(d)*/ctx->bits/8);
if(t<0)
	return BADTHINGS;
t=bnInsertBigBytes(&ctx->e,(void*)e,0,/*strlen(e)*/ctx->bits/8);
if(t<0)
	return BADTHINGS;

bnNorm(&ctx->e);
return OK;
}

int rsa_SETKEY_N(RSA_CTX *ctx,unsigned char *N){
int t;
/* we store in big - endian */
t=bnInsertBigBytes(&ctx->n,(void*)N,0,/*strlen(N)*/ctx->bits/8);
if(t<0)
	return BADTHINGS;
return OK;
}

int rsa_SETKEY_e(RSA_CTX *ctx,unsigned char *e){
int t;
/* we store in big - endian */
t=bnInsertBigBytes(&ctx->e,(void*)e,0,ctx->bits/8);
if(t<0)
	return BADTHINGS;
return OK;
}

int rsa_SETKEY_d(RSA_CTX *ctx,unsigned char *d){
int t;
/* we store in big - endian */
t=bnInsertBigBytes(&ctx->d,(void*)d,0,/*strlen(N)*/ctx->bits/8);
if(t<0)
	return BADTHINGS;
return OK;
}

int rsa_EXTRACTKEYS(RSA_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e){
/* we extract as big - endian */
/*
unsigned int a=bnBits(&ctx->e);
unsigned int b=a/8;
b+=1;
*/
*N=(unsigned char*)Lmalloc((ctx->bits/8)+1);
*d=(unsigned char*)Lmalloc((ctx->bits/8)+1);
*e=(unsigned char*)Lmalloc((ctx->bits/8)+1);
memset(*N,0,(ctx->bits/8)+1);
memset(*d,0,(ctx->bits/8)+1);
memset(*e,0,(ctx->bits/8)+1);

bnExtractBigBytes(&ctx->n,(void*)*N,0,ctx->bits/8);
bnExtractBigBytes(&ctx->d,(void*)*d,0,ctx->bits/8);
bnExtractBigBytes(&ctx->e,(void*)*e,0,ctx->bits/8);

N[(ctx->bits/8)+1]='\0';
d[(ctx->bits/8)+1]='\0';
e[(ctx->bits/8)+1]='\0';
return OK;
}

int rsa_FREEKEYS(RSA_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e){
int r;
r=Lfree(*N,ctx->bits/8);
if(r<0)
	return r;
Lfree(*d,ctx->bits/8);
if(r<0)
	return r;
Lfree(*e,ctx->bits/8);
if(r<0)
	return r;
return OK;
}

int rsa_ENCRYPTPUBLIC(RSA_CTX *ctx,unsigned char *data,unsigned long int 
*datLen){
int t;
struct BigNum enc,m;
/* encrypt data using public key */
/* datLen must be == to bitsize/8 */
if(*datLen!=ctx->bits/8)
	return BADDATALEN;
bnBegin(&enc);
bnBegin(&m);
t=bnInsertLittleBytes(&m,(void*)data,0,ctx->bits/8);
if(t<0){
	bnEnd(&enc);
	bnEnd(&m);
	return BADTHINGS;
}
t=bnExpMod(&enc,&m,&ctx->e,&ctx->n);
if(t<0){
	bnEnd(&enc);
	bnEnd(&m);
	return BADTHINGS;
}
bnExtractLittleBytes(&enc,(void*)data,0,(ctx->bits/8));
bnEnd(&enc);
bnEnd(&m);
return OK;
}

int rsa_DECRYPTPRIVATE(RSA_CTX *ctx,unsigned char *data,unsigned long 
int *datLen){
int t;
struct BigNum dec,enc;
/* decrypt data encrypted with private key */
/* datLen must be == to bitsize/8 */
if(*datLen!=ctx->bits/8)
	return BADDATALEN;
bnBegin(&dec);
bnBegin(&enc);
t=bnInsertLittleBytes(&enc,(void*)data,0,(ctx->bits/8));
if(t<0){
	bnEnd(&dec);
	bnEnd(&enc);
	return BADTHINGS;
}
t=bnExpMod(&dec,&enc,&ctx->d,&ctx->n);
if(t<0){
	bnEnd(&dec);
	bnEnd(&enc);
	return BADMOD;
}
bnExtractLittleBytes(&dec,(void*)data,0,ctx->bits/8);
bnEnd(&dec);
bnEnd(&enc);
return OK;
}

int rsa_ENCRYPTPRIVATE(RSA_CTX *ctx,unsigned char *data,unsigned long 
int *datLen){
int t;
struct BigNum enc,m;
/* encrypt (sign) data with private key */
/* datLen must be == to bitsize/8 */
if(*datLen!=ctx->bits/8)
	return BADDATALEN;
bnBegin(&enc);
bnBegin(&m);
t=bnInsertLittleBytes(&m,(void*)data,0,ctx->bits/8);
if(t<0){
	bnEnd(&enc);
	bnEnd(&m);
	return BADTHINGS;
}
t=bnExpMod(&enc,&m,&ctx->d,&ctx->n);
if(t<0){
	bnEnd(&enc);
	bnEnd(&m);
	return BADMOD;
}
bnExtractLittleBytes(&enc,(void*)data,0,ctx->bits/8);
bnEnd(&enc);
bnEnd(&m);
return OK;
}

int rsa_DECRYPTPUBLIC(RSA_CTX *ctx,unsigned char *data,unsigned long 
int *datLen){
int t;
struct BigNum enc,m;
/* decrypt (verify) data encrypted with private key (verfied by public key) */
/* datLen must be == to bitsize/8 */
if(*datLen!=ctx->bits/8)
	return BADDATALEN;
bnBegin(&enc);
bnBegin(&m);
t=bnInsertLittleBytes(&m,(void*)data,0,ctx->bits/8);
if(t<0){
	bnEnd(&enc);
	bnEnd(&m);
	return BADTHINGS;
}
t=bnExpMod(&enc,&m,&ctx->e,&ctx->n);
if(t<0){
	bnEnd(&enc);
	bnEnd(&m);
	return BADMOD;
}
bnExtractLittleBytes(&enc,(void*)data,0,ctx->bits/8);
bnEnd(&enc);
bnEnd(&m);
return OK;
}
#endif
