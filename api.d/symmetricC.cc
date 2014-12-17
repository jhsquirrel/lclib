#include "symmetricC.hh"
#include <iostream.h>

symmetricC::symmetricC(){
	type=0;
	mode=0;
	bf_ebc_init(&ctx,NULL,0);
}

symmetricC::symmetricC(int t,int m){
	type=t;
	mode=m;
	switch(type){
		case 0:
			if(mode==0)
				bf_ebc_init(&ctx,NULL,0);
			if(mode==1)
				bf_cbc_init(&ctx,NULL,0,0,0);
			break;
		case 1:
			break;
		default:
			throw(Error::CryptoErrC("unknown type\n"));
			break;
	};
}

symmetricC::symmetricC(int t,unsigned char * key,unsigned long keylen){
	type=t;
	mode=0;
	switch(type){
		case 0:
			bf_ebc_init(&ctx,key,keylen);	
			break;
		case 1:
			break;
		default:
			throw(Error::CryptoErrC("unknown type\n"));
			break;
	};
}

symmetricC::symmetricC(int t,unsigned char * key,unsigned long l, \
unsigned long r,unsigned long keylen){
	type=t;
	mode=1;
	switch(type){
		case 0:
			bf_cbc_init(&ctx,key,keylen,l,r);			
			break;
		case 1:
			break;
		default:
			throw(Error::CryptoErrC("unknown type\n"));
			break;
	};
}

symmetricC::~symmetricC(){
	memset(&ctx,0,sizeof(LCLIB_CTX));
}


symmetricC::symmetricC(const symmetricC &s){
	type=s.type;
	mode=s.mode;
	memcpy(&ctx,&s.ctx,sizeof(LCLIB_CTX));
}

symmetricC & symmetricC::operator=(const symmetricC &s){
	type=s.type;
	mode=s.mode;
	memcpy(&ctx,&s.ctx,sizeof(LCLIB_CTX));
return *this;
}

symmetricC::setKey(unsigned char *key,unsigned long keylen){
	int r;
	switch(type){
		case 0:
			if(MAXKEYBYTES<keylen)
				throw(Error::CryptoErrC("keylen to big\n"));
			if(mode==0){
				r=bf_ebc_init(&ctx,key,keylen);
				if(r!=0)
					throw(Error::CryptoErrC("key invalid \
					\n"));
				}
			if(mode==1){
				r=bf_cbc_init(&ctx,key,keylen,ctx.bf_iv.l,\
				ctx.bf_iv.r);
				if(r!=0)
					throw(Error::CryptoErrC("key invalid \
                                        \n"));
				}
			break;
		case 1:
			break;
		default:
			throw(Error::CryptoErrC("unknown type\n"));
			break;
	};
}

symmetricC::setIV(unsigned long l,unsigned long r){
	if(mode==1){
		ctx.bf_iv.l=l;
		ctx.bf_iv.r=r;
	}else{
		throw(Error::CryptoErrC("bad mode for operation\n"));
	}	
}

symmetricC::encipher(int fde,int fdp,int fl){
	int e=0,p=0,s=0;
	int count=0;
	unsigned char *buf;
	buf=new unsigned char[8];	
	while(p!=-1){
		memset(buf,0,8);
		p=read(fdp,buf,8);
		count+=p;
		if(p<0){
			delete[] buf;
			throw(Error::IOErrC("bad read\n"));
		}

		switch(mode){
			case 0:
			if(p==BFBLOCKLENGTH){
				if(count==fl){
					bf_ebc_enc(&ctx,buf,\
						(unsigned int*)&p,1);
					s=1;			
				}
				else{
					bf_ebc_enc(&ctx,buf,\
						(unsigned int*)&p,0);	
				}
					e=write(fde,buf,p);
				if(e<0){
					delete[] buf;
					throw(Error::IOErrC("bad write\n"));
				}
			}else{
				bf_ebc_enc(&ctx,buf,\
					(unsigned int*)&p,1);
				s=1;
			
				e=write(fde,buf,p);
				if(e<0){
					delete[] buf;
					throw(Error::IOErrC("bad write\n"));
				}
			}
			if(s==1)
				p=-1;
			break;
			case 1:
			if(e==BFBLOCKLENGTH){
				if(count==fl){
					bf_cbc_enc(&ctx,buf,\
						(unsigned int*)&p,1);
					s=1;
				}
				else{
					bf_cbc_enc(&ctx,buf,\
						(unsigned int*)&p,0);
				}
				e=write(fde,buf,p);
				if(e<0){
					delete[] buf;
					throw(Error::IOErrC("bad write\n"));
				}
			}else{
				bf_cbc_enc(&ctx,buf,\
					(unsigned int*)&p,1);
				s=1;
				e=write(fde,buf,p);
				if(e<0){
					delete[] buf;
					throw(Error::IOErrC("bad write\n"));
				}
			}
			if(s==1)
				p=-1;
			break;
		};
	}
//	printf("Ebuf=%p\n",buf);
	delete[] buf;
}

symmetricC::decipher(int fdd,int fde,int fl){
	int d=0,e=0,s=0;
	int count=0;
	unsigned char *buf;
	buf=new unsigned char[8];
// remove last SHA_DIGESTSIZE from file
// after decryption - obtain hash and test for equality
	while(e!=-1){
		memset(buf,0,8);
		e=read(fde,buf,8);
		count+=e;
		if(e<0){
			delete[] buf;
			throw(Error::IOErrC("bad read\n"));
		}
		
		switch(mode){
			case 0:
			if(e==BFBLOCKLENGTH){
				if(count==fl){
					bf_ebc_dec(&ctx,buf,(unsigned \
						int*)&e,1);
					s=1;
				}
				else{
					bf_ebc_dec(&ctx,buf,(unsigned \
						int*)&e,0);
				}
				d=write(fdd,buf,e);
				if(d<0){
					delete[] buf;
					throw(Error::IOErrC("bad write\n"));
				}
				if(s==1)
					e=-1;
			}else{
				delete[] buf;
				throw(Error::IOErrC("bad datalength\n"));
			}
			break;
			case 1:
			if(e==BFBLOCKLENGTH){
				if(count==fl){
					bf_cbc_dec(&ctx,buf,(unsigned \
						int*)&e,1);
					s=1;
				}
				else{
					bf_cbc_dec(&ctx,buf,(unsigned \
						int*)&e,0);
				}
				d=write(fdd,buf,e);
				if(d<0){
					delete[] buf;
					throw(Error::IOErrC("bad write\n"));
				}
				if(s==1)
					e=-1;
			}else{
				delete[] buf;
				throw(Error::IOErrC("bad datalen\n"));
                        }
                        break;
		};
	}
//	printf("Dbuf=%p e=%d\n",buf,e);
	// already deleted
//	delete[] buf;
}

symmetricC::encipher(const char *fpe,const char *fpp){
	int fde,fdp;
	struct stat buf;
	int fl;
	int r;
	// calc hash of file
	hashC h;
	try{
	h.calcHash(fpp);
	}
	catch(Error::IOErrC &e){
		throw(e);
	}


	fdp=open(fpp,O_RDONLY);
	if(fdp<0){
		close(fdp);
		throw(Error::IOErrC("bad open (plain)\n"));
	}

	fstat(fdp,&buf);
	fl=buf.st_size;

	fde=open(fpe,O_WRONLY|O_CREAT);
	if(fde<0){
		close(fde);
		throw(Error::IOErrC("bad open (enc)\n"));
	}

	try{
		encipher(fde,fdp,fl);
	}
	catch(Error::IOErrC &io){
		close(fde);
		close(fdp);
		throw io;
	}
	catch(Error::CryptoErrC &ce){
		close(fde);
		close(fdp);
		throw ce;
	}

	r=write(fde,h.getHash(),SHA_DIGESTSIZE);
	if(r<0){
		close(fde);
		close(fdp);
		throw(Error::IOErrC("bad write\n"));
	}

	close(fde);
	close(fdp);

}

symmetricC::decipher(const char *fpd,const char *fpe){
	int fdd,fde;
	struct stat buf;
	int fl;
	int r;

	fde=open(fpe,O_RDONLY);
	if(fde<0){
		close(fde);
	        throw(Error::IOErrC("bad open (enc)\n"));
	}
	fstat(fde,&buf);
	fl=buf.st_size;

	fdd=open(fpd,O_RDWR|O_CREAT);
	if(fdd<0){
		close(fde);
		close(fdd);
		throw(Error::IOErrC("bad open (dec)\n"));
	}

// seek to end and read hash
	r=lseek(fde,fl - SHA_DIGESTSIZE,SEEK_SET);
	if(r<0){
		close(fde);
		close(fdd);
		throw(Error::IOErrC("bad seek\n"));
	}

	r=read(fde,(void*)hash1,SHA_DIGESTSIZE);
	if(r<0){
		close(fde);
		close(fdd);
		throw(Error::IOErrC("bad read\n"));
	}
	// do not decrypt last few bytes!
	fl-=SHA_DIGESTSIZE;
	// rewind back to start!
	r=lseek(fde,0,SEEK_SET);
	if(r<0){
		close(fde);
		close(fdd);
		throw(Error::IOErrC("bad seek\n"));
	}

	try{
		decipher(fdd,fde,fl);
	}
	catch(Error::IOErrC &io){
		close(fde);
		close(fdd);	
		throw io;
	}
	catch(Error::CryptoErrC &ce){
		close(fde);
		close(fdd);
		throw ce;
	}

	// reset decrypted file back to zero!
	r=lseek(fdd,0,SEEK_SET);
	if(r<0){
		close(fde);
		close(fdd);
		throw(Error::IOErrC("bad seek\n"));
	}
	
	hashC h;
	try{
		h.calcHash(fdd);
	}catch(Error::IOErrC &e){
		close(fde);
		close(fdd);
		throw e;
	}

	close(fde);
	close(fdd);

	const char *hash2=(char*)h.getHash();
	if(strncmp(hash2,(char*)hash1,SHA_DIGESTSIZE)==0){
	// ok  - remove orig encrypted file?
	}else{
		throw(Error::CryptoErrC("hash of decrypted file does not match\n"));
	}

}

symmetricC::encipher(unsigned char *de,unsigned int *len,int pad){
	int r;
	switch(type){
		case 0:
		switch(mode){
			case 0:
			if(!pad)
				bf_ebc_enc(&ctx,de,len,0);
			else
				bf_ebc_enc(&ctx,de,len,1);
			break;
			case 1:
			if(!pad)
				bf_cbc_enc(&ctx,de,len,0);
			else
				bf_cbc_enc(&ctx,de,len,1);
			break;
		};
		break;
		case 1:
		break;
		default:
		throw(Error::CryptoErrC("unknown type\n"));
	};
}

symmetricC::decipher(unsigned char *dd,unsigned int *len,int unpad){
	int r;
	switch(type){
		case 0:
		switch(mode){
			case 0:
			if(!unpad)
				bf_ebc_dec(&ctx,dd,len,0);
			else
				bf_ebc_dec(&ctx,dd,len,1);
			break;
			case 1:
			if(!unpad)
				bf_cbc_dec(&ctx,dd,len,0);
			else
				bf_cbc_dec(&ctx,dd,len,1);
			break;
		};
		break;
		case 1:
		break;
		default:
		throw(Error::CryptoErrC("unknown type\n")); 
	};
}
