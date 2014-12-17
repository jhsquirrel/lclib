/*
 * Author       : John Horton
 * E-mail       : jh_squirrel@yahoo.com
 * Date         : 2002
 * Description  : C implementation of blowfish (in ebc and cbc modes)
 *                      and SHA along with RSA using bnlib-1.1
*/
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

#ifndef lclib_c
#define lclib_c
#include "lclib.h"
#include "endian_funcs.h"
#include "bn.h"
#include "prime.h"
#include "bnprint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "err.h"

/* The MGF1 function was derived from code by Ulf Moeller used in the
   openssl-0.9.6c library
*/
static int MGF1(unsigned char *mask, long len, unsigned char *seed, long \
seedlen);
static int EME_OAEP_ENCODE(unsigned char *M,unsigned long int MLen, \
unsigned char*P,unsigned long int PLen,unsigned long int emLen);
static int EME_OAEP_DECODE(unsigned char *EM,unsigned long int *EMLen, \
unsigned char*P,unsigned long int PLen);
static int getRandBytes(unsigned char*bytes,unsigned long int len);

int MGF1(unsigned char *mask, long len, unsigned char *seed, long 
seedlen){
	long i, outlen = 0;
	unsigned char cnt[4];
	LCLIB_CTX c;
	unsigned char md[SHA_DIGESTSIZE];
	for (i = 0; outlen < len; i++)
	{
		cnt[0] = (i >> 24) & 255, cnt[1] = (i >> 16) & 255,
			cnt[2] = (i >> 8) & 255, cnt[3] = i & 255;
		sha_hash_init(&c);
		sha_hash_update(&c, seed, seedlen);
		sha_hash_update(&c, cnt, 4);
		if (outlen + SHA_DIGESTSIZE <= len){
			sha_hash_final(/*mask + outlen,*/ &c);
			memcpy(mask + outlen,&c.sha_ctx.digest,SHA_DIGESTSIZE);
			outlen += SHA_DIGESTSIZE;
		}
		else{
			sha_hash_final(/*md,*/ &c);
			memcpy(md,&c.sha_ctx.digest,SHA_DIGESTSIZE);
			memcpy(mask + outlen, md, len - outlen);
			outlen = len;
		}
	}
return OK;
}

int EME_OAEP_ENCODE(unsigned char *M,unsigned long int MLen, 
unsigned char*P,unsigned long int PLen,unsigned long int emLen){
unsigned char *PS;
unsigned char pHash[SHA_DIGESTSIZE];
unsigned char *dbMask;
unsigned char *maskedDB;
unsigned char *DB;
unsigned char seedMask[SHA_DIGESTSIZE];
unsigned char seed[SHA_DIGESTSIZE];
unsigned char maskedSeed[SHA_DIGESTSIZE];
unsigned char a=0x01;
LCLIB_CTX c;
long i,j,q;
i=emLen - (2*SHA_DIGESTSIZE) - 1;
if(MLen>i)
	return MESSAGETOOLONG;
i=(emLen - MLen) - (2*SHA_DIGESTSIZE) - 1;
PS=(unsigned char*)malloc(i);
if(PS==NULL)
	return BADALLOC;
memset(PS,0,i);

sha_hash_init(&c);
sha_hash_update(&c, P, PLen);
sha_hash_final(&c);
memcpy(pHash,&c.sha_ctx.digest,SHA_DIGESTSIZE);

j=SHA_DIGESTSIZE + i + 1 + MLen;
DB=(unsigned char*)malloc(j);
if(DB==NULL){
	free(PS);
	return BADALLOC;
}
memcpy(DB,pHash,SHA_DIGESTSIZE);
memcpy(&DB[SHA_DIGESTSIZE],PS,i);
memcpy(&DB[SHA_DIGESTSIZE + i],&a,1);
memcpy(&DB[SHA_DIGESTSIZE + i + 1],M,MLen);

q=getRandBytes(seed,SHA_DIGESTSIZE);
if(q!=OK)
	return q;

q=emLen-SHA_DIGESTSIZE;
dbMask=(unsigned char*)malloc(q);
if(dbMask==NULL){
	free(PS);
	free(DB);
	return BADALLOC;
}
memset(dbMask,0,q);
MGF1(dbMask,q,seed,SHA_DIGESTSIZE);

maskedDB=(unsigned char*)malloc(q);
if(maskedDB==NULL){
	free(PS);
	free(DB);
	free(dbMask);
	return BADALLOC;
}

for(i=0;i<q;i++)
	maskedDB[i]=DB[i] ^ dbMask[i];

memset(seedMask,0,SHA_DIGESTSIZE);
MGF1(seedMask,SHA_DIGESTSIZE,maskedDB,q);

for(i=0;i<SHA_DIGESTSIZE;i++)
	maskedSeed[i] = seed[i] ^ seedMask[i];

for(i=0;i<emLen;i++){
	if(i<SHA_DIGESTSIZE)
		M[i] = maskedSeed[i];
	else
		M[i] = maskedDB[i - SHA_DIGESTSIZE];
}

free(PS);
free(DB);
free(dbMask);
free(maskedDB);
return OK;
}

int EME_OAEP_DECODE(unsigned char *EM,unsigned long int *
EMLen, unsigned char*P,unsigned long int PLen){
unsigned char pHash[SHA_DIGESTSIZE];
unsigned char *dbMask;
unsigned char *maskedDB;
unsigned char *DB;
unsigned char seedMask[SHA_DIGESTSIZE];
unsigned char seed[SHA_DIGESTSIZE];
unsigned char maskedSeed[SHA_DIGESTSIZE];
LCLIB_CTX c;
long i,j,q;
int cnt,a=0;
unsigned char b=0x01;

i=(2*SHA_DIGESTSIZE) + 1;
if(*EMLen<i)
	return MESSAGETOOSHORT;

memcpy(maskedSeed,EM,SHA_DIGESTSIZE);
j=*EMLen - SHA_DIGESTSIZE;
maskedDB=(unsigned char*)malloc(j);
if(maskedDB==NULL)
	return BADALLOC;

for(cnt=SHA_DIGESTSIZE;cnt<*EMLen/* - SHA_DIGESTSIZE*/;cnt++){
	maskedDB[a]=EM[cnt];
	a++;
}
memset(seedMask,0,SHA_DIGESTSIZE);

MGF1(seedMask,SHA_DIGESTSIZE,maskedDB,j);

for(q=0;q<SHA_DIGESTSIZE;q++)
	seed[q] = maskedSeed[q] ^ seedMask[q];

dbMask=(unsigned char*)malloc(j);
if(dbMask==NULL){
	free(maskedDB);
	return BADALLOC;
}
memset(dbMask,0,j);
MGF1(dbMask,j,seed,SHA_DIGESTSIZE);

DB=(unsigned char*)malloc(j);
if(DB==NULL){
	free(maskedDB);
	free(dbMask);
	return BADALLOC;
}
for(q=0;q<j;q++)
	DB[q] = maskedDB[q] ^ dbMask[q];

sha_hash_init(&c);
sha_hash_update(&c, P, PLen);
sha_hash_final(&c);
memcpy(pHash,&c.sha_ctx.digest,SHA_DIGESTSIZE);

if(strncmp(pHash,DB,SHA_DIGESTSIZE)!=0)
	return BADDIGEST;

j=0;
i=SHA_DIGESTSIZE;
memset(EM,0,*EMLen);
while(strncmp(&DB[i],&b,1)!=0 && i<*EMLen)
	i++;
if(i>*EMLen)
	return BADPSBLOCK;

for(q=i + 1;q<*EMLen - SHA_DIGESTSIZE;q++){
	EM[j]=DB[q];
	j++;
}
*EMLen=j;

free(maskedDB);
free(dbMask);
return OK;
}

int getRandBytes(unsigned char*bytes,unsigned long int len){
int r,t;
r=open("/dev/urandom",O_RDONLY);
        if(r<0)
                return BADOPEN;
                t=read(r,bytes,len);
		if(t<0){
			close(r);
			return BADREAD;
		}
close(r);
return OK;
}



int bf_ebc_init(LCLIB_CTX *ctx, unsigned char *key, unsigned int keyLen){
if(key==NULL)
	return BADPOINTER;
Blowfish_Init(&ctx->bf_ctx,key,keyLen);
return OK;
}

int bf_ebc_enc(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datLen,
int pad){
int count,j,i,padded=0;
unsigned char s1[5],s2[5];
unsigned char a='1',b='0';
UWORD_32bits Xl;
UWORD_32bits Xr;
count = 0;
/* if pad == 0 then only multiples of BFBLOCKLENGTH bytes should be allowed */
if(pad == 0 && *datLen == 0)
	return BADDATALEN;
if(pad == 0 && *datLen%BFBLOCKLENGTH!=0)
	return BADBLOCKLEN;

/* realloc enough space */
if(pad == 1){
	int t=*datLen%BFBLOCKLENGTH;
	t=*datLen+(BFBLOCKLENGTH-t);
	data=(unsigned char*)realloc(data,t);
}

if(pad == 1 && *datLen == 0 && !padded){
	for(j=0;j<7;j++){
		a++;
		data[j]=b;		
	}
data[j]=a;
*datLen=8;
padded=1;
}

if(pad == 1 && *datLen%BFBLOCKLENGTH == 0 && !padded){
	for(j=*datLen;j<*datLen + 7;j++){
		a++;
		data[j]=b;
	}
data[j]=a;
*datLen+=8;
padded=1;
}

if(pad == 1 && *datLen%BFBLOCKLENGTH != 0 && !padded){
int pv=BFBLOCKLENGTH - (*datLen%BFBLOCKLENGTH);
	for(j=*datLen;j<*datLen + (pv - 1);j++){
		a++;
		data[j]=b;
	}
data[j]=a;
*datLen+=pv;
padded=1;
}

	while(count<*datLen){
		memcpy(s1,&data[count],4);
		s1[4]=(char)NULL;

		memcpy(s2,&data[4+count],4);
		s2[4]=(char)NULL;

		/* I then convert the char arrays into 32 bit numbers 
		   (Xl and Xr) 
		*/
		Xl = convert_to_32(s1);
		Xr = convert_to_32(s2);

		/* I pass Xl and Xr to the bf encipher function */
		Blowfish_Encrypt(&ctx->bf_ctx,&Xl,&Xr);

		/* I re-use the char array to store the encrypted data 
		   (I convert back from 32 bit number to char) 
		*/

		for(i=0;i<4;i++)
			s1[i]=convert_from_32(Xl,i);
		for(i=0;i<4;i++)
			s2[i]=convert_from_32(Xr,i);

		memcpy(&data[count],s1,4);
		memcpy(&data[4+count],s2,4);
	count += BFBLOCKLENGTH;
	}
return OK;
}

int bf_ebc_dec(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datLen,
int pad){
int count,i,padded=0;
unsigned int ui;
unsigned char s1[5],s2[5];
unsigned char a;
UWORD_32bits Xl;
UWORD_32bits Xr;
count=0;
	while(count<*datLen && !padded){
		memcpy(s1,&data[count],4);
		s1[4]=(char)NULL;

		memcpy(s2,&data[4+count],4);
		s2[4]=(char)NULL;
                
		/* I then convert the char arrays into 32 bit numbers
		   (Xl and Xr) 
		*/
		Xl = convert_to_32(s1);
		Xr = convert_to_32(s2);

		/* I pass Xl and Xr to the bf encipher function */
		Blowfish_Decrypt(&ctx->bf_ctx,&Xl,&Xr);

		/* I re-use the char array to store the encrypt
		   (I convert back from 32 bit number to char) 
		*/

		for(i=0;i<4;i++)
			s1[i]=convert_from_32(Xl,i);
		for(i=0;i<4;i++)
			s2[i]=convert_from_32(Xr,i);

		memcpy(&data[count],s1,4);
		memcpy(&data[4+count],s2,4);
		count += BFBLOCKLENGTH;

		if(count>=*datLen && pad==1){
			a=data[*datLen-1];
			ui=a;
			ui-=48;
			*datLen=(*datLen-ui);
			data=(unsigned char*)realloc(data,*datLen);
			padded=1;
		}
        }
return OK;
}

int bf_cbc_init(LCLIB_CTX *ctx, unsigned char *key, unsigned int keyLen,
 unsigned long int l,unsigned long int r){
if(key==NULL)
	return BADPOINTER;
Blowfish_Init(&ctx->bf_ctx,key,keyLen);
ctx->bf_iv.l=l;
ctx->bf_iv.r=r;
return OK;
}

int bf_cbc_enc(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datLen,
int pad){
int count,j,i,padded=0,initial=1;
unsigned char s1[5],s2[5];
unsigned char a='1',b='0';
UWORD_32bits Xl,tl;
UWORD_32bits Xr,tr;
count = 0;

/* if pad == 0 then only multiples of BFBLOCKLENGTH bytes should be allowed */
if(pad == 0 && *datLen == 0)
        return BADDATALEN;
if(pad == 0 && *datLen%BFBLOCKLENGTH!=0)
        return BADBLOCKLEN;

/* realloc enough space */
if(pad == 1){
	int t=*datLen%BFBLOCKLENGTH;
	t=*datLen+(BFBLOCKLENGTH-t);
	data=(unsigned char*)realloc(data,t);
}

if(pad == 1 && *datLen == 0 && !padded){
        for(j=0;j<7;j++){
                a++;
                data[j]=b;
        }
data[j]=a;
*datLen=8;
padded=1;
}

if(pad == 1 && *datLen%BFBLOCKLENGTH == 0 && !padded){
        for(j=*datLen;j<*datLen + 7;j++){
                a++;
                data[j]=b;
        }
data[j]=a;
*datLen+=8;
padded=1;
}

if(pad == 1 && *datLen%BFBLOCKLENGTH != 0 && !padded){
int pv=BFBLOCKLENGTH - (*datLen%BFBLOCKLENGTH);
        for(j=*datLen;j<*datLen + (pv - 1);j++){
                a++;
                data[j]=b;
        }
data[j]=a;
*datLen+=pv;
padded=1;
}


 	while(count<*datLen){
		memcpy(s1,&data[count],4);
		s1[4]=(char)NULL;

		memcpy(s2,&data[4+count],4);
		s2[4]=(char)NULL;

		/* I then convert the char arrays into 32 bit numbers 
		   (Xl and Xr) 
		*/
		Xl = convert_to_32(s1);
		Xr = convert_to_32(s2);

		/* I pass Xl and Xr to the bf encipher function
		   Because we are using CBC mode, we need to XOR with the IV 
		   which will contain either a random block or the previous 
		   ciphertext 
		*/
		tl=Xl^ctx->bf_iv.l;
		tr=Xr^ctx->bf_iv.r;

		Blowfish_Encrypt(&ctx->bf_ctx,&tl,&tr);
		initial=0;
		/* Now place the encrypted data back into the feedback
		   register (the IV)
		*/
		ctx->bf_iv.l=tl;
		ctx->bf_iv.r=tr;
		/* I re-use the char array to store the encrypted data 
		(I convert back from 32 bit number to char) */

		for(i=0;i<4;i++)
			s1[i]=convert_from_32(tl,i);
		for(i=0;i<4;i++)
			s2[i]=convert_from_32(tr,i);

		memcpy(&data[count],s1,4);
		memcpy(&data[4+count],s2,4);
	count += BFBLOCKLENGTH;
	}
return OK;
}

int bf_cbc_dec(LCLIB_CTX *ctx, unsigned char *data, unsigned int *datLen,
int pad){
int count,i,padded=0,initial=1;
unsigned int ui;
unsigned char s1[5],s2[5];
unsigned char a;
UWORD_32bits Xl,tl;
UWORD_32bits Xr,tr;
count=0;

/* if pad == 0 then only multiples of BFBLOCKLENGTH bytes should be allowed */
if((pad == 0 || pad == 1) && *datLen%BFBLOCKLENGTH!=0)
        return BADBLOCKLEN;

	while(count<*datLen && !padded){
		memcpy(s1,&data[count],4);
		s1[4]=(char)NULL;

		memcpy(s2,&data[4+count],4);
		s2[4]=(char)NULL;
                
		/* I then convert the char arrays into 32 bit numbers
		(Xl and Xr) */
		Xl = convert_to_32(s1);
		Xr = convert_to_32(s2);
		tl=Xl;
		tr=Xr;
		/* I pass Xl and Xr to the bf encipher function */
		Blowfish_Decrypt(&ctx->bf_ctx,&tl,&tr);
		if(!padded){
		tl=tl^ctx->bf_iv.l;
		tr=tr^ctx->bf_iv.r;
		ctx->bf_iv.l=Xl;
		ctx->bf_iv.r=Xr;
		}

		initial=0;
		/* I re-use the char array to store the encrypt
		(I convert back from 32 bit number to char) */

		for(i=0;i<4;i++)
			s1[i]=convert_from_32(tl,i);
		for(i=0;i<4;i++)
			s2[i]=convert_from_32(tr,i);

		memcpy(&data[count],s1,4);
		memcpy(&data[4+count],s2,4);
		count += BFBLOCKLENGTH;

		if(count>=*datLen && pad==1){
			a=data[*datLen-1];
			ui=a;
			ui-=48;
			*datLen=(*datLen-ui);
			data=(unsigned char*)realloc(data,*datLen);
			padded=1;
		}
	}
return OK;
}

int sha_hash_init(LCLIB_CTX *ctx){
sha_init(&ctx->sha_ctx);
return OK;
}

int sha_hash_update(LCLIB_CTX *ctx,unsigned char *data, unsigned int datLen){
sha_update(&ctx->sha_ctx,data,(int)datLen);
return OK;
}

int sha_hash_final(LCLIB_CTX *ctx){
sha_final(&ctx->sha_ctx);
return OK;
}

int rsa_init(LCLIB_CTX *ctx,unsigned long int bitlen){
/* e is <i> always </i> 3 ;) */
int t;
t=rsa_INIT(&ctx->rsa_ctx,bitlen);
return t;
}

int rsa_init_n(LCLIB_CTX *ctx,unsigned long int bitlen){
int t;
t=rsa_INIT_N(&ctx->rsa_ctx,bitlen);
return t;
}

int rsa_init_d(LCLIB_CTX *ctx,unsigned long int bitlen){
int t;
t=rsa_INIT_d(&ctx->rsa_ctx,bitlen);
return t;
}

int rsa_init_e(LCLIB_CTX *ctx){
int t;
t=rsa_INIT_e(&ctx->rsa_ctx);
return t;
}

void rsa_end_n(LCLIB_CTX *ctx){
rsa_END_N(&ctx->rsa_ctx);
}

void rsa_end_d(LCLIB_CTX *ctx){
rsa_END_d(&ctx->rsa_ctx);
}

void rsa_end_e(LCLIB_CTX *ctx){
rsa_END_e(&ctx->rsa_ctx);
}

int rsa_genkeys(LCLIB_CTX *ctx,unsigned char *s1,unsigned long int l1, \
unsigned char *s2,unsigned long int l2){
int t;
if(l1<ctx->rsa_ctx.bits/8 || l2<ctx->rsa_ctx.bits/8)
	return BADDATALEN;
t=rsa_GENKEYS(&ctx->rsa_ctx,s1,s2);
return t;
}

int rsa_genkeys_internal(LCLIB_CTX *ctx){
// get random bytes from yarrow
int t=0;
unsigned char s1[ctx->rsa_ctx.bits/8];
unsigned char s2[ctx->rsa_ctx.bits/8];

t=getRandBytes(s1,ctx->rsa_ctx.bits/8);
if(t<0)
	return t;
t=getRandBytes(s2,ctx->rsa_ctx.bits/8);
if(t<0)
	return t;
t=rsa_GENKEYS(&ctx->rsa_ctx,s1,s2);
return t;
}

int rsa_setkeys(LCLIB_CTX *ctx,unsigned char *N,unsigned char *d,
unsigned char *e){
int t;
t=rsa_SETKEYS(&ctx->rsa_ctx,N,d,e);
return t;
}

int rsa_setkey_n(LCLIB_CTX *ctx,unsigned char *N){
int t;
t=rsa_SETKEY_N(&ctx->rsa_ctx,N);
return t;
}

int rsa_setkey_e(LCLIB_CTX *ctx,unsigned char *e){
int t;
t=rsa_SETKEY_e(&ctx->rsa_ctx,e);
return t;
}

int rsa_setkey_d(LCLIB_CTX *ctx,unsigned char *d){
int t;
t=rsa_SETKEY_d(&ctx->rsa_ctx,d);
return t;
}

int rsa_extractkeys(LCLIB_CTX *ctx,unsigned char **N,unsigned char **d,
unsigned char **e){
int t;
t=rsa_EXTRACTKEYS(&ctx->rsa_ctx,N,d,e);
return t;
}

int rsa_freekeys(LCLIB_CTX *ctx,unsigned char **N,unsigned char **d,\
unsigned char **e){
int t;
t=rsa_FREEKEYS(&ctx->rsa_ctx,N,d,e);
return 0;
}

int rsa_encrypt(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen){
int t;

t=EME_OAEP_ENCODE(data,*datLen,NULL,0,(ctx->rsa_ctx.bits/8)-1);
if(t!=0)
	return t;

*datLen=ctx->rsa_ctx.bits/8;
t=rsa_ENCRYPTPUBLIC(&ctx->rsa_ctx,data,datLen);
return t;
}

int rsa_decrypt(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen){
int t;
*datLen=ctx->rsa_ctx.bits/8;
t=rsa_DECRYPTPRIVATE(&ctx->rsa_ctx,data,datLen);
if(t!=0)
	return t;

*datLen=(ctx->rsa_ctx.bits/8) - 1;
t=EME_OAEP_DECODE(data,datLen,NULL,0);
return t;
}

int rsa_sign(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen){
int t;
t=EME_OAEP_ENCODE(data,*datLen,NULL,0,(ctx->rsa_ctx.bits/8)-1);
if(t!=0)
	return t;
*datLen=ctx->rsa_ctx.bits/8;
t=rsa_ENCRYPTPRIVATE(&ctx->rsa_ctx,data,datLen);
return t;
}

int rsa_verify(LCLIB_CTX *ctx,unsigned char *data,unsigned long int *datLen){
int t;
t=rsa_DECRYPTPUBLIC(&ctx->rsa_ctx,data,datLen);
if(t!=0)
	return t;
*datLen=(ctx->rsa_ctx.bits/8) - 1;
t=EME_OAEP_DECODE(data,datLen,NULL,0);
return t;
}

void lclib_end(LCLIB_CTX *ctx){
rsa_END(&ctx->rsa_ctx);
}

unsigned char* rsa_alloc(LCLIB_CTX *ctx,unsigned char *data,unsigned long size){
unsigned char *a=NULL;
if(data==NULL)
	return NULL;
if(size>ctx->rsa_ctx.bits/8)
	return NULL;
a=(unsigned char*)malloc(ctx->rsa_ctx.bits/8);
if(a==NULL)
	return NULL;
memset(a,0,ctx->rsa_ctx.bits/8);
memcpy(a,data,size);
return a;
}

void rsa_free(unsigned char *data){
if(data != NULL)
	free(data);
}
#endif
