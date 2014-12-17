#include <iostream.h>
#include <stdio.h>
#include <list.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "hashC.hh"
#include "symmetricC.hh"

struct priDataFormat{
  unsigned char ident[20];
  unsigned int nbits;
  unsigned int pkl;
  unsigned char *d;
  unsigned char fingerprint[20];
} pridf;

struct pubDataFormat{
  unsigned char ident[20];
  unsigned int nbits;
  unsigned char *n;
  unsigned char *e;
  unsigned char fingerprint[20];
} pubdf;

typedef struct pubDataFormat pubDataFormat;
typedef struct priDataFormat priDataFormat;

list<priDataFormat> lpri;
list<pubDataFormat> lpub;

int loadPub();
int loadPri();
pubDataFormat *getPubKey(char *ident);
priDataFormat *getPriKey(char *ident,char *key,int keylen);


int loadPub(){
  int t=1,fd;
  unsigned char buf[24];
  back_insert_iterator<list<pubDataFormat> > it(lpub);

  fd=open("pubkeys",O_RDWR);
  while(t>0){
    pubDataFormat spdf;
    t=read(fd,(void*)buf,24);
    if(t==0)
      break;
    unsigned int *c=(unsigned int*)&buf[20];
    unsigned int j=*c;
    j/=8;
    char *buf2=new char[(j*2)+20];
    memcpy(spdf.ident,buf,20);
    t=read(fd,buf2,(j*2)+20);
    spdf.nbits=j*8;;
    spdf.n=new unsigned char[j];
    spdf.e=new unsigned char[j];
    memcpy(spdf.n,buf2,j);
    memcpy(spdf.e,&buf2[j],j);
    memcpy(spdf.fingerprint,&buf2[j+j],20);
    it++=spdf;
    delete[] buf2;
  }
  close(fd);
  return 0;
}

int loadPri(){
  int t=1,fd;
  unsigned char buf[28];
  back_insert_iterator<list<priDataFormat> > it(lpri);

  fd=open("prikeys",O_RDWR);
  while(t>0){
    priDataFormat spdf;
    t=read(fd,(void*)buf,28);
    if(t==0)
      break;
    unsigned int *c=(unsigned int*)&buf[20];
    unsigned int j=*c;
    unsigned int r;
    c=(unsigned int*)&buf[24];
    j/=8;
    r=*c;
    char *buf2=new char[r+20];
    memcpy(spdf.ident,buf,20);
    memset(buf2,0,r+20);
    t=read(fd,(void*)buf2,r+20);
    spdf.nbits=j*8;
    spdf.pkl=r;
    spdf.d=new unsigned char[r];
    //spdf.e=new unsigned char[j];
    memcpy(spdf.d,buf2,r);
    //memcpy(spdf.e,&buf2[j],j);
    memcpy(spdf.fingerprint,&buf2[r],20);
    it++=spdf;
    delete[] buf2;
  }
  close(fd);
  return 0;
}

int savePub(){
  // go thru list and write to disk


  return 0;
}

int savePri(){
  // go thru list and write to disk

  return 0;
}

pubDataFormat *getPubKey(char *ident){
  pubDataFormat *spdf=new pubDataFormat;
  memset(spdf,0,sizeof(pubDataFormat));
  list<pubDataFormat>::iterator it2;
  it2=lpub.begin();
  while(1){
    pubDataFormat s=*it2;
    if(strncmp((char*)s.ident,ident,20)==0){
//      s.n=new unsigned char[s.nbits/8];
//      s.e=new unsigned char[s.nbits/8];
      memcpy(spdf,&s,sizeof(pubDataFormat));
      return spdf;
    }
    printf("\n");
//    delete[] s.n;
//    delete[] s.e;
    it2++;
    if(it2==lpub.end())
      break;
  }
  return spdf;
}

priDataFormat *getPriKey(char *ident,char *key,int keylen){
  priDataFormat *spdf=new priDataFormat;
  memset(spdf,0,sizeof(priDataFormat));
  list<priDataFormat>::iterator it2;
  it2=lpri.begin();
  while(1){
    priDataFormat s=*it2;
/*
for(int i=0;i<20;i++)
  printf("%x",s.ident[i]);
printf("\n");
for(int i=0;i<20;i++)
  printf("%x",ident[i]);
printf("\n");
*/
    if(strncmp((char*)s.ident,ident,20)==0){
      hashC h;
      h.hashInit();
      h.calcHash((unsigned char*)key,(unsigned long int)keylen);
      unsigned char k[SHA_DIGESTSIZE];
      memcpy(k,h.getHash(),SHA_DIGESTSIZE);
      symmetricC sd(0,(unsigned char*)k,SHA_DIGESTSIZE);
      unsigned char *tmp_k=new unsigned char[s.nbits/8];
      unsigned int r=s.pkl;
      memcpy(tmp_k,s.d,s.pkl);
      try{
        sd.decipher(tmp_k,&r,1);
      }catch(Error::CryptoErrC e){
        cout<<e.message;
        throw e;
      }

      h.hashInit();
      h.calcHash(tmp_k,r);
      if(strncmp((char*)h.getHash(),(char*)s.fingerprint,SHA_DIGESTSIZE)==0){
        memcpy(spdf,&s,sizeof(priDataFormat));
        spdf->d=new unsigned char[spdf->nbits/8];
        memcpy(spdf->d,tmp_k,r);
        delete[] tmp_k;
        return spdf;
      }
      delete[] tmp_k;
    }
    it2++;
    if(it2==lpri.end())
      break;
  }
  return spdf;
}

delPubKey(char *ident){
  pubDataFormat *spdf=new pubDataFormat;
  list<pubDataFormat>::iterator it2;
  it2=lpub.begin();
  while(1){
    pubDataFormat s=*it2;
    if(strncmp((char*)s.ident,ident,20)==0){
      //memcpy(spdf,&s,sizeof(pubDataFormat));
      //return spdf;
      lpub.erase(it2);
      delete[] s.n;
      delete[] s.e;
      break;
    }
    printf("\n");
//    delete[] s.n;
//    delete[] s.e;
    it2++;
    if(it2==lpub.end())
      break;
  }
}

delPriKey(char *ident){
  priDataFormat *spdf;
  list<priDataFormat>::iterator it2;
  it2=lpri.begin();
  while(1){
    priDataFormat s=*it2;
    if(strncmp((char*)s.ident,ident,20)==0){
      //spdf=&s;
      //return spdf;
      lpri.erase(it2);
      delete[] s.d;
    }
    printf("\n");
//    delete[] s.n;
//    delete[] s.e;
    it2++;
    if(it2==lpri.end())
      break;
  }
}

int main(){
  int t=1,fd;
  char *i="jh_squirrel";
  char ident[20];
  hashC h;
  h.calcHash((unsigned char*)i,strlen("jh_squirrelA"));
  memcpy(ident,(char*)h.getHash(),20);
  loadPub();
//  delPubKey(ident);
  loadPri();
  pubDataFormat *s=getPubKey(ident);
  priDataFormat *s2;
  s2=getPriKey(ident,"mykey",5);

  for(int i=0;i<20;i++)
    printf("%02x",s->ident[i]);
  printf("\n");
  cout<<s->nbits<<'\n';
  for(int i=0;i<s->nbits/8;i++)
    printf("%02x",s->n[i]);
  delete s;

  cout<<"\n";
  cout<<"s2=";
  cout<<s2->nbits<<'\n';
  for(int i=0;i<s2->nbits/8;i++)
    printf("%02x",s2->d[i]);

  delete[] s2->d;
  delete s2;
  return 0;
}
