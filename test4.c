#include "lclib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main(){

LCLIB_CTX lclib_ctx;
unsigned long int i;
unsigned char *t1=(unsigned char*)"abc";
unsigned char *t2=
(unsigned char*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
unsigned char *t3=(unsigned char*)"abc0123456789abc0123456789abc0123456789abc0123456789abc0123456789abc0123456789";

sha_hash_init(&lclib_ctx);
sha_hash_update(&lclib_ctx,t1,strlen((char*)t1));
sha_hash_final(&lclib_ctx);
for(i=0;i<5;i++)
	printf("%08lx ",lclib_ctx.sha_ctx.digest[i]);
printf("\n");

sha_hash_init(&lclib_ctx);
sha_hash_update(&lclib_ctx,t2,strlen((char*)t2));
sha_hash_final(&lclib_ctx);
for(i=0;i<5;i++)
        printf("%08lx ",lclib_ctx.sha_ctx.digest[i]);
printf("\n");

sha_hash_init(&lclib_ctx);
sha_hash_update(&lclib_ctx,t3,strlen((char*)t3));
sha_hash_final(&lclib_ctx);
for(i=0;i<5;i++)
        printf("%08lx ",lclib_ctx.sha_ctx.digest[i]);
printf("\n");

return 0;
}
