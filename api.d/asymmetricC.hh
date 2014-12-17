#ifndef asymmetricC_hh
#define asymmetricC_hh
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list.h>
#include <fcntl.h>
#include "hashC.hh"
#include "symmetricC.hh"
#include "errC.hh"

extern "C" {
#include "lclib.h"
}

class asymmetricC{
protected:
  LCLIB_CTX ctx;

  struct pubDataFormat{

    pubDataFormat(){
      n=NULL;
      e=NULL;
    }
    ~pubDataFormat(){
      if(n!=NULL)
        delete[] n;
      if(e!=NULL)
        delete[] e;
    }
    pubDataFormat(const pubDataFormat &pdf){
      memcpy(ident,pdf.ident,20);
      nbits=pdf.nbits;
      n=new unsigned char[nbits];
      e=new unsigned char[nbits];
      memcpy(n,pdf.n,nbits);
      memcpy(e,pdf.e,nbits);
      memcpy(fingerprint,pdf.fingerprint,20);
    }
    pubDataFormat& operator=(const pubDataFormat &pdf){
      memcpy(ident,pdf.ident,20);
      nbits=pdf.nbits;
      n=new unsigned char[nbits];  
      e=new unsigned char[nbits];
      memcpy(n,pdf.n,nbits);
      memcpy(e,pdf.e,nbits);
      memcpy(fingerprint,pdf.fingerprint,20);
      return *this;
    }

    unsigned char ident[20];
    unsigned int nbits;
    unsigned char *n;
    unsigned char *e;
    unsigned char fingerprint[20];
  }pubdf;

  struct priDataFormat{

    priDataFormat(){
      d=NULL;
    }
    ~priDataFormat(){
      if(d!=NULL)
        delete[] d;
    }
    priDataFormat(const priDataFormat &pdf){
      memcpy(ident,pdf.ident,20);
      nbits=pdf.nbits;
      pkl=pdf.pkl;
      d=new unsigned char[nbits];
      memcpy(d,pdf.d,nbits);
      memcpy(fingerprint,pdf.fingerprint,20);
    }
    priDataFormat& operator=(const priDataFormat &pdf){
      memcpy(ident,pdf.ident,20);
      nbits=pdf.nbits;
      pkl=pdf.pkl;
      d=new unsigned char[nbits];
      memcpy(d,pdf.d,nbits);
      memcpy(fingerprint,pdf.fingerprint,20);
      return *this;
    }
    unsigned char ident[20];
    unsigned int nbits;
    unsigned int pkl;
    unsigned char *d;
    unsigned char fingerprint[20];
  }pridf;

  typedef struct pubDataFormat pubDataFormat;
  typedef struct priDataFormat priDataFormat;

  list<priDataFormat> lpri;
  list<pubDataFormat> lpub;

  int loadPub(const char *pathname);
  int loadPri(const char *pathname);
  pubDataFormat * getPubKey(char *ident);
  priDataFormat * getPriKey(char *ident,char *key,int keylen);
  setPubKey(pubDataFormat *spdf,int update);
  setPriKey(priDataFormat *spdf,int update);
  delPubKey(char *ident);
  delPriKey(char *ident);
  savePub(const char *pathname);
  savePri(const char *pathname);

public:
  asymmetricC();
  asymmetricC(int s);
  ~asymmetricC();
	
  asymmetricC(const asymmetricC &a);
  asymmetricC& operator=(const asymmetricC &a);

  int getKeySize();
  init(int s);
  genKeys();
  setNKey(unsigned char *N);
  setKeys(unsigned char *N,unsigned char *d,unsigned char *e);
  getKeys(unsigned char **N,unsigned char **d,unsigned char **e);
  freeKeys(unsigned char **N,unsigned char **d,unsigned char **e);
	
  savePubKeys(const char*pathname,char*ident);
  savePriKeys(const char*pathname,char*ident,char*key,int keylen);
  loadPubKeys(const char*pathname,char*ident);
  loadPriKeys(const char*pathname,char*ident,char*key,int keylen);
	

  encrypt(unsigned char *d,unsigned long int *datLen);
  decrypt(unsigned char *data,unsigned long int *datLen);

  sign(unsigned char *data,unsigned long int *datLen);
  verify(unsigned char *data,unsigned long int *datLen);

  unsigned char* alloc(unsigned char *data,unsigned long int size);
  free(unsigned char *data);
};
#endif
