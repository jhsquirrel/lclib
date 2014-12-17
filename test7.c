#include "lclib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#define BSIZE 512
int main(){
LCLIB_CTX lclib_ctx;
unsigned char data1[16];
unsigned char *data=NULL;
unsigned long int datLen=16;
unsigned char s1[BSIZE/8];
unsigned char s2[BSIZE/8];
unsigned long int l1=BSIZE/8;
unsigned long int l2=BSIZE/8;
int i,r;
unsigned char *N,*d,*e;

struct timeval tvs,tve,tvd;
struct timezone tz;

r=open("/dev/urandom",O_RDONLY);
i=read(r,s1,BSIZE/8);
i=read(r,s2,BSIZE/8);

memcpy(data1,"abcdef0123456789",16);

printf("clear text\n");
for(i=0;i<16;i++)
	printf("%x",data1[i]);
printf("\n\n");

rsa_init(&lclib_ctx,BSIZE);

data=rsa_alloc(&lclib_ctx,data1,16);
if(data==NULL){   
        printf("unable to alloc\n");
        exit(0);   
}

gettimeofday(&tvs,&tz);
printf("calculating %d bit rsa key pair\n",BSIZE);
i=rsa_genkeys(&lclib_ctx,s1,l1,s2,l2);
gettimeofday(&tve,&tz);

i=rsa_encrypt(&lclib_ctx,data,&datLen);
printf("->%d\n",i);

printf("encrypted data\n");
for(i=0;i<BSIZE/8;i++)
        printf("%x",data[i]);
printf("\n\n");

i=rsa_decrypt(&lclib_ctx,data,&datLen);
printf("->%d\n",i);

printf("decrypted / clear text\n");
for(i=0;i<(int)datLen;i++)
        printf("%x",data[i]);
printf("\n");

tvd.tv_sec=tve.tv_sec - tvs.tv_sec;
printf("time taken to generate a %d bit key was %ld \
seconds\n",BSIZE,tvd.tv_sec);

printf("bnBits=%u\n",bnBits(&lclib_ctx.rsa_ctx.e));
rsa_extractkeys(&lclib_ctx,&N,&d,&e);

printf("N=\n");
for(i=0;i<(int)lclib_ctx.rsa_ctx.bits/8;i++)
	printf("%x",N[i]);
printf("\n");

printf("d=\n");
for(i=0;i<(int)lclib_ctx.rsa_ctx.bits/8;i++)
        printf("%x",d[i]);
printf("\n");

printf("e=\n");
for(i=0;i<(int)lclib_ctx.rsa_ctx.bits/8;i++)
	printf("%x",e[i]);
printf("\n");

rsa_setkeys(&lclib_ctx,N,d,e);
/*
rsa_encrypt(&lclib_ctx,data,&datLen);

printf("encrypted data\n");
for(i=0;i<BSIZE/8;i++)
        printf("%x",data[i]);
printf("\n\n");

rsa_decrypt(&lclib_ctx,data,&datLen);

printf("decrypted / clear text\n");
for(i=0;i<(int)datLen;i++)
        printf("%x",data[i]);
printf("\n");
*/

rsa_sign(&lclib_ctx,data,&datLen);
printf("\nsigned data\n");
for(i=0;i<BSIZE/8;i++)
        printf("%x",data[i]);
printf("\n\n");

rsa_verify(&lclib_ctx,data,&datLen);

printf("clear text\n");
for(i=0;i<(int)datLen;i++)
        printf("%x",data[i]);
printf("\n");

rsa_freekeys(&lclib_ctx,&N,&d,&e);
lclib_end(&lclib_ctx);
rsa_free(data);
return 0;
}
