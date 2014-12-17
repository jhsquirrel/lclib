#include "hashC.hh"

hashC::hashC(){
	type=0;
	sha_hash_init(&ctx);
	memset(hash,0,SHA_DIGESTSIZE);
}

hashC::hashC(int type){
	type=type;
	switch(type){
		case 0:
			sha_hash_init(&ctx);
			memset(hash,0,SHA_DIGESTSIZE);
		break;
		case 1:
		break;
		default:
			throw(Error::CryptoErrC("unknown type\n"));
	
	};
}

hashC::~hashC(){
	memset(&ctx,0,sizeof(LCLIB_CTX));
}

hashC::hashC(const hashC & h){
	type=h.type;
	memcpy(&ctx,&h.ctx,sizeof(LCLIB_CTX));
}

hashC & hashC::operator=(const hashC &h){
	type=h.type;
	memcpy(&ctx,&h.ctx,sizeof(LCLIB_CTX));
return *this;
}

int hashC::hashInit(){
	type=0;
	sha_hash_init(&ctx);
	memset(hash,0,SHA_DIGESTSIZE);
	return 0;
}

int hashC::calcHash(int fd){
	int h=0;
	unsigned char buf[1024];
	memset(buf,0,1024);
	while(h!=-1){
		h=read(fd,buf,1024);
		if(h<0){
			throw(Error::IOErrC("bad read\n"));
		}
		if(h==0)
			return 0;
		sha_hash_update(&ctx,buf,h);
	}
	h=0;
return h;
}

int hashC::calcHash(FILE *fp){
	int h=0;
	unsigned char buf[1024];
	memset(buf,0,1024);
	while(feof(fp)==0){
		h=fread(buf,1024,1,fp);
		if(h<0){
			throw(Error::IOErrC("bad read\n"));
		}
		if(h==0)
			return 0;
		sha_hash_update(&ctx,buf,h);
	}
	h=0;
return h;
}

int hashC::calcHash(unsigned char *d, unsigned long len){
	int h;
	h=sha_hash_update(&ctx,d,len);
return h;
}

int hashC::calcHash(const char * pathname){
	int h=0;
	int fd;
	unsigned char buf[1024];

	fd=open(pathname,O_RDONLY);
	if(fd<0){
		throw(Error::IOErrC("unable to open file\n"));
	}
	memset(buf,0,1024);
	while(h!=-1){
		h=read(fd,buf,1024);
		if(h<0){
			throw(Error::IOErrC("bad read\n"));
		}
		if(h==0)
			return 0;
		sha_hash_update(&ctx,buf,h);
	}
	h=0;
	close(fd);
return h;
}

int hashC::convertToL_Endian(unsigned char* in){
  if(in==NULL)
    return -1;
  unsigned char tmp[4];
  for(int i=0;i<20;i++){
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
  return 0;
}

int hashC::convertHashToHex(unsigned char*hh,unsigned char*a,int len){
  if(hh==NULL ||a==NULL)
    return -1;
  int hh_i=0;
  unsigned char tmp[4];
   for(int i=0;i<len;i++){
    tmp[0]=a[i];
    tmp[1]=a[i+1];
    tmp[2]=a[i+2];
    tmp[3]=a[i+3];
    a[i]=tmp[3];
    a[i+1]=tmp[2];
    a[i+2]=tmp[1];
    a[i+3]=tmp[0];
    i+=3;
  }
  unsigned char tmp2[2];
  for(int i=0;i<len;i++){
    memset(tmp2,0,2);
    sprintf((char*)tmp2,"%02lx",a[i]);
    hh[hh_i]=tmp2[0];
    hh[hh_i+1]=tmp2[1];
    hh_i+=2;
  }
  return 0;
}

unsigned char * hashC::getHash(){
	sha_hash_final(&ctx);
	memcpy(hash,&ctx.sha_ctx.digest,SHA_DIGESTSIZE);
return hash;
}
