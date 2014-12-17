#ifndef asymmetricC_cc
#define asymmetricC_cc
#include "asymmetricC.hh"
#include <iostream.h>
  asymmetricC::asymmetricC(){
    rsa_init(&ctx,(unsigned long int)512);
  }

  asymmetricC::asymmetricC(int s){
    rsa_init(&ctx,(unsigned long int)s);
  }

  asymmetricC::~asymmetricC(){
    lclib_end(&ctx);
  }
	
  asymmetricC::asymmetricC(const asymmetricC &a){
    memcpy(&ctx,&a.ctx,sizeof(LCLIB_CTX));
  }

  asymmetricC & asymmetricC::operator=(const asymmetricC &a){
    memcpy(&ctx,&a.ctx,sizeof(LCLIB_CTX));
    return *this;
  }
	
  asymmetricC::init(int s){
    lclib_end(&ctx);
    rsa_init(&ctx,(unsigned long int)s);
  }

  int asymmetricC::getKeySize() {
	return ctx.rsa_ctx.bits/8;
  }

  asymmetricC::genKeys(){
    int t=rsa_genkeys_internal(&ctx);
    if(t<0)
      throw(Error::CryptoErrC("could not generate keys\n"));
    }

  asymmetricC::setNKey(unsigned char *N){
    int t;
    t=rsa_setkey_n(&ctx, N);
    if(t<0)
      throw(Error::CryptoErrC("could not set keys\n"));
  }

  asymmetricC::setKeys(unsigned char *N,unsigned char *d,\
    unsigned char *e){
    int t;
    t=rsa_setkeys(&ctx,N,d,e);
    if(t<0)
      throw(Error::CryptoErrC("could not set keys\n"));
  }

  asymmetricC::getKeys(unsigned char **N,unsigned char **d,\
    unsigned char **e){
    int t=rsa_extractkeys(&ctx,N,d,e);
    if(t<0)
      throw(Error::CryptoErrC("could not extract keys\n"));
  }

  asymmetricC::freeKeys(unsigned char **N,unsigned char **d,\
    unsigned char **e){
      rsa_freekeys(&ctx,N,d,e);
  }
	
  asymmetricC::savePubKeys(const char*pathname,char*ident){
    unsigned char *N,*d,*e;
    struct pubDataFormat spdf;
    hashC h;
    int size=0;
	
    h.calcHash((unsigned char*)ident,strlen((char*)ident));
    try{
      getKeys(&N,&d,&e);
    }catch(Error::CryptoErrC e){cout<<e.message<<"\n";}

    memcpy(spdf.ident,h.getHash(),20);
    memcpy(&spdf.nbits,&ctx.rsa_ctx.bits,4);

    spdf.n=new unsigned char[ctx.rsa_ctx.bits/8];
    spdf.e=new unsigned char[ctx.rsa_ctx.bits/8];

    memcpy(spdf.n,N,ctx.rsa_ctx.bits/8);
    memcpy(spdf.e,e,ctx.rsa_ctx.bits/8);
    h.hashInit();
    h.calcHash(spdf.n,ctx.rsa_ctx.bits/8);
    memcpy(spdf.fingerprint,h.getHash(),20);

    setPubKey(&spdf,1);
    int rv=savePub(pathname);
    if(rv<0)
      throw(Error::IOErrC("could not open keydb\n"));

    freeKeys(&N,&d,&e);
  }

  asymmetricC::savePriKeys(const char*pathname,char*ident,char*key,\
    int keylen){
    unsigned char *N,*d,*e;
    struct priDataFormat spdf;
    hashC h;
    int size=0;

    h.calcHash((unsigned char*)ident,strlen((char*)ident));
    getKeys(&N,&d,&e);

    memcpy(spdf.ident,h.getHash(),20);
    memcpy(&spdf.nbits,&ctx.rsa_ctx.bits,4);

    spdf.d=new unsigned char[ctx.rsa_ctx.bits/8];
    memcpy(spdf.d,d,ctx.rsa_ctx.bits/8);

    h.hashInit();
    h.calcHash(spdf.d,ctx.rsa_ctx.bits/8);
    memcpy(spdf.fingerprint,h.getHash(),20);

    h.hashInit();
    h.calcHash((unsigned char*)key,(unsigned long int)keylen);
    unsigned char k[SHA_DIGESTSIZE];
    memcpy(k,h.getHash(),SHA_DIGESTSIZE);
    symmetricC s(0,(unsigned char*)k,SHA_DIGESTSIZE);
    unsigned int kl=spdf.nbits/8;

    try{
      s.encipher((unsigned char*)spdf.d,&kl,1);
    }catch(Error::CryptoErrC e){
      throw e;
    }
    spdf.pkl=kl;

    setPriKey(&spdf,1);
    int rv=savePri(pathname);
    if(rv<0)
      throw(Error::IOErrC("could not open keydb\n"));
    freeKeys(&N,&d,&e);
  }

/* load from public key ring into list */
  int asymmetricC::loadPub(const char* pathname){
    int t=1,fd;
    unsigned char buf[24];
    back_insert_iterator<list<pubDataFormat> > it(lpub);

    fd=open(pathname,O_RDWR);
    if(fd<0)
      return -1;
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
      *it++=spdf;
      delete[] buf2;
    }
    close(fd);
    return 0;
  }

/* load from private key ring into list */
  int asymmetricC::loadPri(const char *pathname){
    int t=1,fd;
    unsigned char buf[28];
    back_insert_iterator<list<priDataFormat> > it(lpri);
    fd=open("prikeys",O_RDWR);
    if(fd<0)
      return -1;
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
      memcpy(spdf.d,buf2,r);
      memcpy(spdf.fingerprint,&buf2[r],20);
      *it++=spdf;
      delete[] buf2;
    }
    close(fd);
    return 0;
  }

/* save from list to public key ring */
  int asymmetricC::savePub(const char *pathname){
    int fd=open(pathname,O_RDWR|O_CREAT,S_IRUSR|S_IWUSR);
    if(fd<0){
      return -1;
    }  
    list<pubDataFormat>::iterator it2;
    it2=lpub.begin();
    while(1){
      pubDataFormat s=*it2;
      write(fd,s.ident,20);
      write(fd,&s.nbits,4);
      write(fd,s.n,s.nbits/8);
      write(fd,s.e,s.nbits/8);
      write(fd,s.fingerprint,20);
      it2++;
      if(it2==lpub.end())
        break;
    }
    close(fd);
    return 0;
  }

/* save from list to private key ring (assumes all data is correctly
   encrypted 
*/
  int asymmetricC::savePri(const char *pathname){
    int fd=open(pathname,O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR);
    if(fd<0){
      return -1;
    }
    list<priDataFormat>::iterator it2;
    it2=lpri.begin();
    while(1){
      priDataFormat s;
      s=*it2;
      write(fd,s.ident,20);
      write(fd,&s.nbits,4);
      write(fd,&s.pkl,4);
      write(fd,s.d,s.pkl/*nbits/8*/);
      write(fd,s.fingerprint,20);      
      it2++;
      if(it2==lpri.end())
        break;
    }
    close(fd);
    return 0;
  }

/* for a given ident - return the key from the public key ring */
  asymmetricC::pubDataFormat* asymmetricC::getPubKey(char *ident){
    pubDataFormat *spdf=NULL;//new pubDataFormat;
    //memset(spdf,0,sizeof(pubDataFormat));
    list<pubDataFormat>::iterator it2;
    it2=lpub.begin();
    while(1){
      pubDataFormat s=*it2;
      if(strncmp((char*)s.ident,ident,20)==0){
        spdf=new pubDataFormat;
        memset(spdf,0,sizeof(pubDataFormat));
        spdf->n=new unsigned char[s.nbits/8];
        spdf->e=new unsigned char[s.nbits/8];
        memcpy(spdf->ident,s.ident,20);      
        memcpy(&spdf->nbits,&s.nbits,4);
        memcpy(spdf->n,s.n,s.nbits/8);
        memcpy(spdf->e,s.e,s.nbits/8);
        memcpy(spdf->fingerprint,s.fingerprint,20);
        return spdf;
      }
      it2++;
      if(it2==lpub.end())
        break;
    }
    return spdf;
  }

/* for a given ident return the key from the private key ring */
  asymmetricC::priDataFormat *asymmetricC::getPriKey(char *ident,char *key,\
    int keylen){
    priDataFormat *spdf=NULL;//new priDataFormat;
    //memset(spdf,0,sizeof(priDataFormat));
    list<priDataFormat>::iterator it2;
    it2=lpri.begin();
    while(1){
      priDataFormat s=*it2;
      if(strncmp((char*)s.ident,ident,20)==0){
        hashC h;
        h.hashInit();
        h.calcHash((unsigned char*)key,(unsigned long int)keylen);
        unsigned char k[SHA_DIGESTSIZE];
        memcpy(k,h.getHash(),SHA_DIGESTSIZE);
        symmetricC sd(0,(unsigned char*)k,SHA_DIGESTSIZE);
        unsigned char *tmp_k=new unsigned char[s.pkl];
        unsigned int r=s.pkl;
        memcpy(tmp_k,s.d,s.pkl);
        try{
          sd.decipher(tmp_k,&r,1);
        }catch(Error::CryptoErrC e){
          throw e;
        }
        if(s.pkl>=r){
        h.hashInit();
        h.calcHash(tmp_k,r);
        if(strncmp((char*)h.getHash(),(char*)s.fingerprint,SHA_DIGESTSIZE)==0){
          priDataFormat *spdf=new priDataFormat;
          memset(spdf,0,sizeof(priDataFormat));
          memset(s.d,0,spdf->nbits/8);
          memcpy(s.d,tmp_k,r);
          spdf->d=new unsigned char[s.nbits/8];
          memcpy(spdf->ident,s.ident,20);
          memcpy(&spdf->nbits,&s.nbits,4);
          memcpy(&spdf->pkl,&s.pkl,4);
          memcpy(spdf->d,s.d,s.nbits/8);
          memcpy(spdf->fingerprint,s.fingerprint,20);
          delete[] tmp_k;
          return spdf;
        }
        }
        delete[] tmp_k;
      }
      it2++;
      if(it2==lpri.end())
        break;
    }
    return spdf;
  }

/* remove a key from the public list */
  asymmetricC::delPubKey(char *ident){
    pubDataFormat *spdf=new pubDataFormat;
    list<pubDataFormat>::iterator it2;
    it2=lpub.begin();
    while(1){
      pubDataFormat s=*it2;
      if(strncmp((char*)s.ident,ident,20)==0){
        lpub.erase(it2);
        delete[] s.n;
        delete[] s.e;
        break;
      }
      it2++;
      if(it2==lpub.end())
        break;
    }
  }

/* remove a key from the private list */
  asymmetricC::delPriKey(char *ident){
    priDataFormat *spdf;
    list<priDataFormat>::iterator it2;
    it2=lpri.begin();
    while(1){
      priDataFormat s=*it2;
      if(strncmp((char*)s.ident,ident,20)==0){
        lpri.erase(it2);
        delete[] s.d;
      }
      it2++;
      if(it2==lpri.end())
        break;
    }
  }

/* take public key data and add it to the list - but check whether we should 
   update or not! if update is 1 then update data - if zero and ident 
   is found (ident specified in spdf) then throw error
   * I assume that spdf has memory correctly allocated! *
*/
  asymmetricC::setPubKey(pubDataFormat *spdf,int update){
    list<pubDataFormat>::iterator it2;
    it2=lpub.begin();
    int s1=0;

    while(1){
      pubDataFormat s=*it2;
      if(strncmp((char*)s.ident,(char*)spdf->ident,20)==0 && update==1){
        lpub.erase(it2);
        delete[] s.n;
        delete[] s.e;
        s.n=NULL;
        s.e=NULL;
        back_insert_iterator<list<pubDataFormat> > it(lpub);
        *it++=*spdf;
        s1=1;
        break;
      }
      if(strncmp((char*)s.ident,(char*)spdf->ident,20)==0 && update==0)
        throw(Error::CryptoErrC("ident already exists\n"));

      it2++;
      if(it2==lpub.end()){
        break;
      }
    }  	
    if(s1==0){
      back_insert_iterator<list<pubDataFormat> > it(lpub);
      *it++=*spdf;
    }
  }

/* take private key data and add it to the list - but check whether we should 
   update or not! - if update is 1 then update data - if zero and ident 
   is found (ident specified in spdf) then throw error
*/
  asymmetricC::setPriKey(priDataFormat *spdf,int update){
    list<priDataFormat>::iterator it2;
    it2=lpri.begin();
    int s1=0;
    while(1){
      priDataFormat s=*it2;
      if(strncmp((char*)s.ident,(char*)spdf->ident,20)==0 && update==1){
        lpri.erase(it2);
        delete[] s.d;
        s.d=NULL;
        back_insert_iterator<list<priDataFormat> > it(lpri);
        *it++=*spdf;
        s1=1;
        break;
      }
      if(strncmp((char*)s.ident,(char*)spdf->ident,20)==0 && update==0)
        throw(Error::CryptoErrC("ident already exists\n"));

      it2++;
      if(it2==lpri.end())
        break;
    }
    if(s1==0){
      back_insert_iterator<list<priDataFormat> > it(lpri);
      it=*spdf;
    }
  }

  asymmetricC::loadPubKeys(const char*pathname,char*ident){
    struct pubDataFormat spdf;
    hashC h;
    int s=0;

    h.calcHash((unsigned char*)ident,strlen((char*)ident));
    memcpy(spdf.ident,h.getHash(),20);

    int rv=loadPub(pathname);
    if(rv==0){
      pubDataFormat* p_spdf=getPubKey((char*)&spdf.ident);
      if(p_spdf!=NULL){
        rsa_end_n(&ctx);
        rsa_end_e(&ctx);
        rsa_init_n(&ctx,p_spdf->nbits);
        rsa_init_e(&ctx);
        rsa_setkey_n(&ctx,p_spdf->n);
        rsa_setkey_e(&ctx,p_spdf->e);
      }
    }else{
      throw(Error::IOErrC("cannot open file\n"));
    }

//    delete[] p_spdf->n;
//    delete[] p_spdf->e;
//    delete p_spdf;
  }

  asymmetricC::loadPriKeys(const char*pathname,char*ident,char*key,\
    int keylen){
    struct priDataFormat spdf;
    hashC h;
    int s=0;

    h.calcHash((unsigned char*)ident,strlen((char*)ident));

    memcpy(spdf.ident,h.getHash(),20);

    int rv=loadPri(pathname);
    if(rv==0){
      priDataFormat* p_spdf=getPriKey((char*)&spdf.ident,key,keylen);
      if(p_spdf!=NULL){
        rsa_end_d(&ctx);
        rsa_init_d(&ctx,p_spdf->nbits);
        rsa_setkey_d(&ctx,p_spdf->d);
      }
    }else{
      throw(Error::IOErrC("cannot open file\n"));
    }
//    delete[] p_spdf->d;
//    delete p_spdf;
  }

  asymmetricC::encrypt(unsigned char *data,unsigned long int *datLen){
    int t=rsa_encrypt(&ctx,data,datLen);
    if(t<0)
      throw(Error::CryptoErrC("bad encrypt\n"));
  }

  asymmetricC::decrypt(unsigned char *data,unsigned long int *datLen){
    int t=rsa_decrypt(&ctx,data,datLen);
    if(t<0)
    throw(Error::CryptoErrC("bad decrypt\n"));
  }

  asymmetricC::sign(unsigned char *data,unsigned long int *datLen){
    int t=rsa_sign(&ctx,data,datLen);
    if(t<0)
    throw(Error::CryptoErrC("bad sign\n"));
  }

  asymmetricC::verify(unsigned char *data,unsigned long int *datLen){
    int t=rsa_verify(&ctx,data,datLen);
    if(t<0)
    throw(Error::CryptoErrC("bad verify\n"));
  }

  unsigned char* asymmetricC::alloc(unsigned char*data,\
    unsigned long int size){
    unsigned char *a;
    a=rsa_alloc(&ctx,data,size);
    if(a==NULL)
      throw(Error::CryptoErrC("bad alloc\n"));
    return a;
  }

  asymmetricC::free(unsigned char* data){
    rsa_free(data);
  }
#endif	
