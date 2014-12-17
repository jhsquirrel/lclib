#include "hashC.hh"
#include <iostream.h>
#include <stdio.h>

int f(unsigned char* out,unsigned char*in){
hashC h;
int i,t=0;
h.hashInit();
try{
h.calcHash(in,strlen((char*)in));
}catch(Error::IOErrC e){
        //if(e.type==1)
cout<<e.message;
                return -1;//exit
}
in=h.getHash();
// convert to little endian

unsigned char tmp[4];
for(i=0;i<20;i++){
        //memset(tmp,0,4);
        tmp[0]=in[i];
        tmp[1]=in[i+1];
        tmp[2]=in[i+2];
        tmp[3]=in[i+3];
        //memset(&a[i],0,4);
	in[i]=tmp[3];
        in[i+1]=tmp[2];
        in[i+2]=tmp[1];
        in[i+3]=tmp[0];
        i+=3;
}

unsigned char tmp2[2];
unsigned char tmp1;

memset(out,0,40);

for(i=0;i<20;i++){
	tmp1=in[i];
	memset(tmp2,0,2);
/*printf("tmp1=%x",tmp1);*/
	sprintf((char*)&out[t],"%02lx",tmp1);
/*	printf(":%x:",in[i]);*/
	/*out[t]=tmp2[0];
	out[t+1]=tmp2[1];*/
/*printf("%c%c %d %d..",out[t],out[t+1],t,i);*/
	t+=2;
}
/*
for(i=0;i<40;i++){
	printf("%c",out[i]);
}
*/
/*
for(i=0;i<20;i++){
        printf("%02lx",in[i]);
        if((i+1)%4==0)
                printf(" ");
}
*/
//printf("\n");

return 0;
}

int main(){
hashC h;
int i;
//unsigned long *c;
unsigned char *a=(unsigned char*)"fbe93da3306e79884c2911391610ec3eb743f9dc";
//unsigned char *a=(unsigned char*)"d5d4b12e9cbc13b172a3da6c055b54e5ad1dcf9e";
unsigned char b[40];
unsigned char c[40];
i=f(b,a);
for(i=0;i<40;i++){
        printf("%c",b[i]);
}
printf("\n");
i=f(c,b);
for(i=0;i<40;i++){
        printf("%c",c[i]);
}
/*try{
h.calcHash(a,strlen((char*)a));
}catch(Error::IOErrC e){
	//if(e.type==1)
cout<<e.message;
		return -1;//exit
}
a=h.getHash();

// convert to little endian

unsigned char tmp[4];
for(i=0;i<20;i++){
	//memset(tmp,0,4);
	tmp[0]=a[i];
	tmp[1]=a[i+1];
	tmp[2]=a[i+2];
	tmp[3]=a[i+3];
	//memset(&a[i],0,4);
	a[i]=tmp[3];
	a[i+1]=tmp[2];
	a[i+2]=tmp[1];
	a[i+3]=tmp[0];
	i+=3;
}
	
for(i=0;i<20;i++){
	printf("%02lx",a[i]);
	if((i+1)%4==0)
		printf(" ");
}
printf("\n");
*/
/*
unsigned long int b[5];
memcpy(b,a,20);
for(i=0;i<5;i++)
	printf("%08lx ",b[i]);
*/

return 0;
}
