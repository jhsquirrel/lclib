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
unsigned char *data,*data2;
unsigned char key[16];
unsigned int s,s1,s2;
unsigned int c;
unsigned long int l,r;

data=(unsigned char*)malloc(16);
data2=(unsigned char*)malloc(8);
l=1234;
r=5678;
s=16;
s1=16;
s2=4;
strncpy((char*)key,"mykeykeep_secret\n",s);
strncpy((char*)data,"maryhadalittlela\n",s1);
strncpy((char*)data2,"data\n",s2);

/* ebc */
printf("ebc mode blowfish test\n");
bf_ebc_init(&lclib_ctx,key,s);
if(bf_ebc_enc(&lclib_ctx,data,&s1,0)!=0)
        printf("problem during encryption\n");
printf("len = %d encrypted data\n",s1);

if(bf_ebc_enc(&lclib_ctx,data2,&s2,1)!=0)
        printf("problem during encryption\n");
printf("len = %d encrypted data\n",s2);


bf_ebc_init(&lclib_ctx,key,s);
bf_ebc_dec(&lclib_ctx,data,&s1,0);
printf("decrypted data = ");
for(c=0;c<s1;c++)
	printf("%c",data[c]);
printf("\n");
printf("length of decrpyted data = %d\n",s1);

bf_ebc_dec(&lclib_ctx,data2,&s2,1);
printf("decrypted data = ");
for(c=0;c<s2;c++)
        printf("%c",data2[c]);
printf("\n");
printf("length of decrpyted data = %d\n",s2);


/* cbc */
printf("cbc mode blowfish test\n");
bf_cbc_init(&lclib_ctx,key,s,l,r);
if(bf_cbc_enc(&lclib_ctx,data,&s1,0)!=0)
        printf("problem during encryption\n");
printf("len = %d encrypted data\n",s1);

if(bf_cbc_enc(&lclib_ctx,data2,&s2,1)!=0)
        printf("problem during encryption\n");
printf("len = %d encrypted data\n",s2);


bf_cbc_init(&lclib_ctx,key,s,l,r);
bf_cbc_dec(&lclib_ctx,data,&s1,0);
printf("decrypted data = ");
for(c=0;c<s1;c++)
        printf("%c",data[c]);
printf("\n");
printf("length of decrpyted data = %d\n",s1);

bf_cbc_dec(&lclib_ctx,data2,&s2,1);
printf("decrypted data = ");
for(c=0;c<s2;c++)
        printf("%c",data2[c]);
printf("\n");
printf("length of decrpyted data = %d\n",s2);

free(data);
free(data2);
return 0;
}
