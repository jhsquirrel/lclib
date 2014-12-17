#include "sskeyC.hh"

sskeyC::sskeyC(){
  state=0; 
  key=NULL;
  keylen=0;
}

sskeyC::~sskeyC(){
  if(key!=NULL)
    delete[] key;
}

sskeyC::sskeyC(const sskeyC &ssk){
  skeyC s=ssk;
  sym=ssk.sym;
  key=new char[keylen];
  memcpy(key,ssk.key,strlen(ssk.key));
  keylen=ssk.keylen;
  skeys_hash=ssk.skeys_hash;
}

sskeyC& sskeyC::operator=(const sskeyC &ssk){
  skeyC::operator=(ssk);
  sym=ssk.sym;
  key=new char[keylen];
  memcpy(key,ssk.key,strlen(ssk.key));
  keylen=ssk.keylen;
  skeys_hash=ssk.skeys_hash;
  return *this;
}

sskeyC::setkey(char *p_key, int len){
// set enc/dec key
  if(len<0)
    throw(Error::CryptoErrC("length of key must be greater than 0!\n"));

  try{ 
    sym.setKey((unsigned char*)p_key,len);
  }catch(Error::CryptoErrC e){
    cout<<e.message;
    throw(e);
  }
  if(key==NULL){
    key=new char[len];
    memcpy(key,p_key,len);  
    keylen=len;
  }else if(memcmp(key,p_key,len)!=0){
    delete[] key;
    key=new char[len];
    memcpy(key,p_key,len);
    keylen=len;
  }
}

sskeyC::init_skeys(int n){
  state=0;
  skeys_hash.clear();
  skeys_hash.resize(n);
  skeyC::init_skeys(n);
//cout<<"n="<<n<<"index="<<index;
}

sskeyC::calchashes(){
// go thru all skeys and calculate their hash (done before encryption!)
// throw exception if encryption already done
  if(state!=0)
    throw(Error::CryptoErrC("hashes must be calculated before encryption\n"));

  for(int i=0;i<skeys.size();i++){
    unsigned char *rv=new unsigned char[SHA_DIGESTSIZE*2];
    unsigned char *rv2=new unsigned char[SHA_DIGESTSIZE*2];
    unsigned char *hv=new unsigned char[SHA_DIGESTSIZE];

    memcpy(rv,(unsigned char*)skeys[i].data(),SHA_DIGESTSIZE*2);
/*
printf("TT");
for(int t=0;t<40;t++)
printf("%c",rv[t]);
printf("TT");
*/
    hashC h;
    h.hashInit();
    try{
      h.calcHash(rv,/*strlen((char*)rv)*/SHA_DIGESTSIZE*2);
    }catch(Error::IOErrC e){
      cout<<e.message;
      throw(e);
    }
    
    memcpy(hv,h.getHash(),SHA_DIGESTSIZE);
    //convertToL_Endian(hv);
    convertHashToHex(rv2,hv,SHA_DIGESTSIZE);
    skeys_hash[i].set((char*)rv2,SHA_DIGESTSIZE*2);

printf("skey_hash->:%s:\n",skeys_hash[i].data());
printf("skey->:%s:\n",skeys[i].data());

    delete[] rv2;
    delete[] hv;
    delete[] rv;
  }
  state=1;
}

sskeyC::encryptkeys(){
// go thru all skeys and encrypt them
// thow exception if hash not yet calculated
  if(state!=1)
    throw(Error::CryptoErrC("hashes must be calculated before encryption\n"));

  unsigned int len=SHA_DIGESTSIZE*2;
  for(int i=0;i<skeys.size();i++){
    unsigned char* rv=new unsigned char[SHA_DIGESTSIZE*2];
    memcpy(rv,(unsigned char*)skeys[i].data(),SHA_DIGESTSIZE*2);

    try{
      setkey(key,keylen);
    }catch(Error::CryptoErrC e){
      cout<<e.message;
      throw(e);
    }
/*
printf("!.");
for(int y=0;y<SHA_DIGESTSIZE*2;y++)
  printf("%c",rv[y]);
printf(".!");
*/
    try{
      sym.encipher(rv,&len,0);
    }
    catch(Error::IOErrC io){
      cout<<io.message;
     // return -1;
      throw(io);
    }catch(Error::CryptoErrC co){
      cout<<co.message;
      throw(co);
     // return -1;
    }
    skeys[i].set((char*)rv,SHA_DIGESTSIZE*2);
  }
  state=2;
}

unsigned char* sskeyC::decryptskey(unsigned char *rv,unsigned int len){
//unsigned char *rv=new unsigned char[SHA_DIGESTSIZE*2];
	try{
		setkey(key,keylen);
	}catch(Error::CryptoErrC e){
		//cout<<e.message;
		//delete[] rv;
		throw(e);
	}
	try{
		sym.decipher(rv,&len,0);
	}catch(Error::IOErrC io){
		//cout<<io.message;
		//delete[] rv;
		throw(io);
		//  return -1;   
	}catch(Error::CryptoErrC co){
		cout<<co.message;
		//delete[] rv;
		throw(co);
		//  return -1;
	}
	hashC h;
	h.hashInit();
	try{
		h.calcHash(rv,SHA_DIGESTSIZE*2);
	}catch(Error::IOErrC e){
		//cout<<e.message;
		//delete[] rv;
		throw(e);
	}
	unsigned char* Shash=new unsigned char[SHA_DIGESTSIZE];
	unsigned char* Dhash=new unsigned char[SHA_DIGESTSIZE*2];
	memcpy(Shash,h.getHash(),SHA_DIGESTSIZE);
	h.convertHashToHex(Dhash,Shash,SHA_DIGESTSIZE);
	//printf(":%s %s:\n",Dhash,skeys_hash[index].data());
	if(memcmp(Dhash,skeys_hash[index+1].data(),SHA_DIGESTSIZE*2)==0){
	//cout<<"in pop\n";
		current_key=skeys[index-1].data();
		popdkey.set((char*)rv,SHA_DIGESTSIZE*2);
		//delete[] rv;
		delete[] Shash;
		delete[] Dhash;
		return (unsigned char*)popdkey.data();
		//stringC s((char*)rv,SHA_DIGESTSIZE*2);
		//return s.data()
	}else{
		//  delete[] rv;
		delete[] Shash;
		delete[] Dhash;
		throw(Error::CryptoErrC("bad skey decrypt\n"));
	}
	
}

unsigned char * sskeyC::pop(){
// pop next skey off (throw exception if hash of pop'd key
// is not equal to that stored for equivalent position
//cout<<"in popA"<<index<<"\n";
  //if(state!=2)
   // throw(Error::CryptoErrC("incorrect state for pop\n"));
/*  if(index==0)
    return NULL;
  if(skeys[index].data()==NULL)
    return NULL;
*/
cout<<"index"<<index<<'\n';
	if(index >= max_index && state == 0){
		index = max_index - 1;
		unsigned char *rvs=decryptskey(last_skey,40);
		//return last_skey;
		return rvs;
	}
	if(index<0)
		throw(Error::CryptoErrC("no more keys\n"));

	if(skeys[index].data()==NULL)
		throw(Error::CryptoErrC("key is null\n"));

//  unsigned char *rv=new unsigned char[SHA_DIGESTSIZE*2];
/* jah added from skey */
unsigned char *rvs;
int len;
//cout<<"state="<<state<<'\n';
//cout<<"index="<<index<<'\n';
switch(state){
        case 0:
                index--;
                // if index is valid && state 0:return skey
                if(index >= 0){
                        current_key = skeys[index].data();
                        popped = 1;
			rvs=decryptskey((unsigned char*)skeys[index+1].data(),
				40);
			return rvs;
                        //return (unsigned char*)skeys[index+1].data();
                }
                // if index is last one && state 0: goto state 1
                if(index < 0){
			cout<"wibble\n";
                        state = 1;
                        memcpy(last_skey,skeys[0].data(),SHA_DIGESTSIZE*2);
                        throw(Error::CryptoErrC("last skey\n"));
                }
        break;

        case 1:
                throw(Error::CryptoErrC("no more skeys\n"));
        break;

        case 2:
                index--;
                if(index >= 0){
                        state = 3;
                        current_key = skeys[index].data();
                        popped = 1;
			rvs=decryptskey((unsigned char*)skeys[index+1].data(),
				40);
			return rvs;
                        //return (unsigned char*)skeys[index+1].data();
                }
                if(index == 0){
                        state = 1;
                }
        break;
        case 3:
                index--;
                if(index >= 0){
                        state = 0;
                        current_key = skeys[index].data();
                        popped = 1;
	 		rvs=decryptskey((unsigned char*)skeys[index+1].data(),
                                40);
			return rvs;
                        //return (unsigned char*)skeys[index+1].data();
                }
                if(index < 0){
                        state = 1;
                }
        break;
        }


/* end jah added */

}

sskeyC::save_keys(const char *pathname){
        int fd;
        int r,c;
        int len,i;
        fd=open(pathname,O_WRONLY|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
        if(fd<0)
                throw(Error::IOErrC("unable to open file\n"));
        len=skeys.size();
        // write out no of items, index, state, popped ,last and all the data

        r=write(fd,(void*)&len,sizeof(int));
        if(r<0){
                close(fd);
                throw(Error::IOErrC("bad write\n"));
        }
        i=index;
        r=write(fd,(void*)&i,sizeof(int));
        if(r<0){
                close(fd);
                throw(Error::IOErrC("bad write\n"));
        }
        r=write(fd,(void*)&state,sizeof(int));
        if(r<0){
             close(fd);
                throw(Error::IOErrC("bad write\n"));
        }
        r=write(fd,(void*)&popped,sizeof(int));
        if(r<0){  
                close(fd);
                throw(Error::IOErrC("bad write\n"));
        }
        r=write(fd,(void*)last_skey,SHA_DIGESTSIZE*2);
        if(r<0){
                close(fd);
                throw(Error::IOErrC("bad write\n"));
        }
        for(c=0;c<len;c++){
                r=write(fd,skeys[c].data(),SHA_DIGESTSIZE*2);
                if(r<0){
                        close(fd);
                        throw(Error::IOErrC("bad write\n"));
                }
        }
	for(c=0;c<len;c++){
		r=write(fd,skeys_hash[c].data(),SHA_DIGESTSIZE*2);
		if(r<0){
                        close(fd);
                        throw(Error::IOErrC("bad write\n"));
                }
	}
        close(fd);
#ifdef DEBUG
printf("save\n");
        for(c=0;c<len;c++){
                unsigned char a[40];
                memcpy(a,skeys[c].data(),40);
                for(int i=0;i<40;i++)
                        printf("%c",a[i]);
                printf("\n");
        }
#endif

}

sskeyC::load_keys(const char *pathname){
        int fd;
        int r,c;
        int len;
        unsigned char data[SHA_DIGESTSIZE*2];

        fd=open(pathname,O_RDONLY);
        if(fd<0)
                throw(Error::IOErrC("unable to open file\n"));
        r=read(fd,(void*)&len,sizeof(int));
        skeys.clear;
        skeys.resize(len);
	skeys_hash.clear;
	skeys_hash.resize(len);
        r=read(fd,(void*)&index,sizeof(int));
        r=read(fd,(void*)&state,sizeof(int));
        r=read(fd,(void*)&popped,sizeof(int));
        r=read(fd,(void*)last_skey,SHA_DIGESTSIZE*2);
        for(c=0;c<len;c++){
                r=read(fd,(void*)data,SHA_DIGESTSIZE*2);
                if(r<0){
                        close(fd);
                        throw(Error::IOErrC("bad read\n"));
                }
               skeys[c].set((char*)data,SHA_DIGESTSIZE*2);
        }
	for(c=0;c<len;c++){
                r=read(fd,(void*)data,SHA_DIGESTSIZE*2);
                if(r<0){
                        close(fd);
                        throw(Error::IOErrC("bad read\n"));
                }
               skeys_hash[c].set((char*)data,SHA_DIGESTSIZE*2);
        }
        close(fd);

#ifdef DEBUG
printf("loaded keys\n");
        for(c=0;c<len;c++){
                unsigned char a[40];
                memcpy(a,skeys[c].data(),40);
                for(int i=0;i<40;i++)
                        printf("%c",a[i]);
                printf("\n");
        }
#endif

}
