#include "lclib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct rv{
char a;
char b;
};

typedef struct rv rv;

rv convertToHex(char byte);
char convertToByte(rv hex);

int main(int argc,char*argv[]){
LCLIB_CTX lclib_ctx;
unsigned char *data;
unsigned char *out;
unsigned char key[8];
unsigned int s,s1,b1;
unsigned int c,t;


if(argc != 3){
	printf("test6 key cleartext\n");
	exit(0);
}

data=(unsigned char*)malloc(8);
out=(unsigned char*)malloc(16);
s=8;
s1=8;
b1=8;

t=0;
for(c=0;c<8;c++){
	rv a;
	a.a=argv[1][t];
	a.b=argv[1][t+1];
	key[c]=convertToByte(a);
	t+=2;
}
t=0;
for(c=0;c<8;c++){
	rv a;
        a.a=argv[2][t];
        a.b=argv[2][t+1];
        data[c]=convertToByte(a);
        t+=2;
}

/* ebc */
bf_ebc_init(&lclib_ctx,key,s);
if(bf_ebc_enc(&lclib_ctx,data,&s1,0)!=0)
        printf("problem during encryption\n");
t=0;
for(c=0;c<8;c++){
        rv a;
        a=convertToHex(data[c]);
        out[t]=a.a;
        out[t+1]=a.b;
        t+=2;
}
for(c=0;c<16;c++)
        printf("%c",out[c]);
printf("\n");

bf_ebc_init(&lclib_ctx,key,s);
bf_ebc_dec(&lclib_ctx,data,&s1,0);
/*
printf("decrypted data = ");
t=0;
for(c=0;c<8;c++){
	rv a;
        a=convertToHex(data[c]);
	out[t]=a.a;
	out[t+1]=a.b;
        t+=2;
}
for(c=0;c<16;c++)
	printf("%c",out[c]);
printf("\n");
*/
free(data);
free(out);
return 0;
}

rv convertToHex(char byte){
rv hexval;
unsigned char a;
unsigned char c;
unsigned char d;
c=(unsigned char)byte;

c=(unsigned char)byte;
a=(char)240;
d=c&a;
d=d>>4;
a=d;

if(a==(char)0){hexval.a='0';}
if(a==(char)1){hexval.a='1';}
if(a==(char)2){hexval.a='2';}
if(a==(char)3){hexval.a='3';}
if(a==(char)4){hexval.a='4';}
if(a==(char)5){hexval.a='5';}
if(a==(char)6){hexval.a='6';}
if(a==(char)7){hexval.a='7';}
if(a==(char)8){hexval.a='8';}
if(a==(char)9){hexval.a='9';}
if(a==(char)10){hexval.a='A';}
if(a==(char)11){hexval.a='B';}
if(a==(char)12){hexval.a='C';}
if(a==(char)13){hexval.a='D';}
if(a==(char)14){hexval.a='E';}
if(a==(char)15){hexval.a='F';}

c=(unsigned char)byte;
a=(char)15;
d=c&a;
a=d;
if(a==(char)0){hexval.b='0';}
if(a==(char)1){hexval.b='1';}
if(a==(char)2){hexval.b='2';}
if(a==(char)3){hexval.b='3';}
if(a==(char)4){hexval.b='4';}
if(a==(char)5){hexval.b='5';}
if(a==(char)6){hexval.b='6';}
if(a==(char)7){hexval.b='7';}
if(a==(char)8){hexval.b='8';}
if(a==(char)9){hexval.b='9';}
if(a==(char)10){hexval.b='A';}
if(a==(char)11){hexval.b='B';}
if(a==(char)12){hexval.b='C';}
if(a==(char)13){hexval.b='D';}
if(a==(char)14){hexval.b='E';}
if(a==(char)15){hexval.b='F';}

return hexval;
}

char convertToByte(rv hex){
char a=0;
if(hex.a=='0')
	a+=0;
if(hex.a=='1')
	a+=16;
if(hex.a=='2')
	a+=32;
if(hex.a=='3')
	a+=48;
if(hex.a=='4')
	a+=64;
if(hex.a=='5')
	a+=80;
if(hex.a=='6')
	a+=96;
if(hex.a=='7')
	a+=112;
if(hex.a=='8')
	a+=128;
if(hex.a=='9')
	a+=144;
if(hex.a=='A')
	a+=160;
if(hex.a=='B')
	a+=176;
if(hex.a=='C')
	a+=192;
if(hex.a=='D')
	a+=208;
if(hex.a=='E')
	a+=224;
if(hex.a=='F')
	a+=240;


if(hex.b=='0') 
        a+=0; 
if(hex.b=='1') 
        a+=1;
if(hex.b=='2') 
        a+=3;
if(hex.b=='3') 
        a+=3;
if(hex.b=='4') 
        a+=4;
if(hex.b=='5') 
        a+=5;
if(hex.b=='6') 
        a+=6;
if(hex.b=='7')
        a+=7;
if(hex.b=='8')
        a+=8;
if(hex.b=='9')
        a+=9;
if(hex.b=='A')
        a+=10;
if(hex.b=='B')
        a+=11;
if(hex.b=='C')
        a+=12;
if(hex.b=='D')
        a+=13;
if(hex.b=='E')
        a+=14;
if(hex.b=='F')
        a+=15;
return a;
}
