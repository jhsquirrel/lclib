#include "skeyC.hh"
#include <iostream.h>
#include <stdio.h>
/*#define DEBUG */

skeyC::skeyC(){
	index=0;
	max_index=0;      
	seed=NULL;
	state=0;
	popped=0;
	memset(last_skey,255,SHA_DIGESTSIZE *2);
}

skeyC::skeyC(unsigned char *c){
	current_key=stringC((char*)c,SHA_DIGESTSIZE*2);
	index=0;
	max_index=0;
	seed=NULL;
	state=0;
	popped=0;
	memset(last_skey,255,SHA_DIGESTSIZE *2);
}

skeyC::~skeyC(){
	if(seed)
		delete[] seed;
}

skeyC::skeyC(const skeyC &sk){
	skeys=sk.skeys;
	current_key=sk.current_key;
	index=sk.index;
	max_index=sk.index;     
	state=sk.state;
	popped=sk.popped;
	memcpy(last_skey,sk.last_skey,SHA_DIGESTSIZE*2);
	seed=new unsigned char[sk.seedlen];
	memcpy(seed,sk.seed,sk.seedlen);
}

skeyC & skeyC::operator=(const skeyC &sk){
	skeys=sk.skeys;
	current_key=sk.current_key;
	index=sk.index;
	max_index=sk.index;
	state=sk.state;
	popped=sk.popped;
	memcpy(last_skey,sk.last_skey,SHA_DIGESTSIZE*2);
	seed=new unsigned char[sk.seedlen];
	memcpy(seed,sk.seed,sk.seedlen);
	return *this;
}

skeyC::convertHashToHex(unsigned char*hh,unsigned char*a,int len){
// hexhash orighash len_of_orig_hash
// convert to little endian
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
}

skeyC::set_seed(unsigned char*s,int len){
  int i;
  if(len<0)
    throw(Error::MemErrC("length is less than zero\n"));
  if(!s)
    throw(Error::MemErrC("memory is not valid\n"));
  if(seed != NULL)
    delete[] seed;
  seed=new unsigned char[len];
  memcpy(seed,s,len);
  seedlen=len;
}

skeyC::init_skeys(int n){
  int i;
  unsigned char *ch;
  unsigned char *ch2;

  if(n<0)
    throw(Error::MemErrC("index is less than zero\n"));
  skeys.clear();
  skeys.resize(n);
  max_index=n;
	
  hashInit();

  calcHash(seed,seedlen);

  ch=new unsigned char[SHA_DIGESTSIZE];
  ch2=new unsigned char[SHA_DIGESTSIZE*2];
	
  getHash();

  memcpy(ch,hash,SHA_DIGESTSIZE);
  convertHashToHex(ch2,ch,SHA_DIGESTSIZE);

  skeys[0].set((char*)ch2,SHA_DIGESTSIZE *2);
  index=0;

#ifdef DEBUG
printf("init\n");
for(int y=0;y<40;y++)
	printf("%c",ch2[y]);
printf("\n");
#endif
  for(i=1;i<n;i++){
    hashInit();
    calcHash(ch2,SHA_DIGESTSIZE*2);
    getHash();
    memcpy(ch,hash,SHA_DIGESTSIZE);
    convertHashToHex(ch2,ch,SHA_DIGESTSIZE);
    skeys[i].set((char*)ch2,SHA_DIGESTSIZE*2);
    index++;

#ifdef DEBUG
printf("init\n");
		for(int y=0;y<40;y++){
                       printf("%c",ch2[y]);
		}
		printf("\n");
#endif
  }
  current_key=skeys[i];	
  delete[] ch;
  delete[] ch2;

  state = 0;
}

int skeyC::check_key(unsigned char *c){
	unsigned char *ch2;
	unsigned char *ch;
	ch2=new unsigned char[SHA_DIGESTSIZE*2];
	ch=new unsigned char[SHA_DIGESTSIZE];

	if(current_key.data()==NULL){
		current_key=stringC((char*)c,SHA_DIGESTSIZE*2);
		return 0;
	}
	hashInit();
	calcHash(c,SHA_DIGESTSIZE*2);
	getHash();
	memcpy(ch,hash,SHA_DIGESTSIZE);
	convertHashToHex(ch2,ch,SHA_DIGESTSIZE);
	stringC tc((char*)ch2,SHA_DIGESTSIZE*2);

#ifdef DEBUG
	for(int i=0;i<SHA_DIGESTSIZE*2;i++)
		printf("%c",ch2[i]);
	printf("\n");
#endif

	delete[] ch;
	delete[] ch2;
	if(tc==current_key){
		current_key=tc;
		return 0;
	}
	return -1;
}

int skeyC::check_key_reset(unsigned char *c,unsigned char *c2){
	unsigned char *ch2;
	unsigned char *ch;
	ch2=new unsigned char[SHA_DIGESTSIZE*2];
	ch=new unsigned char[SHA_DIGESTSIZE];
	if(current_key.data()==NULL){
		current_key=stringC((char*)c,SHA_DIGESTSIZE*2);
		return 0;
	}
	hashInit();
	calcHash(c,SHA_DIGESTSIZE*2);
	getHash();
	memcpy(ch,hash,SHA_DIGESTSIZE);
	convertHashToHex(ch2,ch,SHA_DIGESTSIZE);
	stringC tc((char*)ch2,SHA_DIGESTSIZE*2);
	stringC tc2((char*)c2,SHA_DIGESTSIZE*2);
	if(tc==current_key){
		current_key=tc2;
		return 0;
	}
	return -1;
}

skeyC::load_keys(const char *pathname){
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
	r=read(fd,(void*)&index,sizeof(int));
	r=read(fd,(void*)&max_index,sizeof(int));
	r=read(fd,(void*)&state,sizeof(int));
	r=read(fd,(void*)&popped,sizeof(int));
	r=read(fd,(void*)last_skey,SHA_DIGESTSIZE*2);
//cout<<"index->"<<index<<'\n';
	for(c=0;c<len;c++){
		r=read(fd,(void*)data,SHA_DIGESTSIZE*2);
		if(r<0){
			close(fd);
			throw(Error::IOErrC("bad read\n"));
		}
		skeys[c].set((char*)data,SHA_DIGESTSIZE*2);
//cout<<"data->"<<data<<'\n';
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

skeyC::save_keys(const char *pathname){
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
	r=write(fd,(void*)&max_index,sizeof(int));
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

unsigned char * skeyC::print_keys(){
  int len=skeys.size();
  unsigned char *rv=new unsigned char[len*40];
  int c=0;
  for(int i=0;i<len;i++){
    memcpy(&rv[c],skeys[i].data(),40);
  c+=40;
  }
  return rv;
}

skeyC::read_keys(unsigned char * k,int len){
  skeys.clear;
  skeys.resize(len);
  index=len-1;
  for(int i=0;i<len;i++){
	skeys[i].set((char*)&k[i*(SHA_DIGESTSIZE*2)],SHA_DIGESTSIZE*2);
  }
}

unsigned char* skeyC::pop(){
//	cout<<"popped state="<<state<<'\n';
//	cout<<"popped index="<<index<<'\n';
	// if we have just init but we are off index then return last_skey
	if(index >= max_index && state == 0){
		index = max_index - 1;
		return last_skey;
		
	}
	if(index<0)
		throw(Error::CryptoErrC("no more keys\n"));

	if(skeys[index].data()==NULL)
		throw(Error::CryptoErrC("key is null\n"));

	switch(state){
	case 0:
		index--;
		// if index is valid && state 0:return skey
		if(index >= 0){
			current_key = skeys[index].data();
			popped = 1;
			return (unsigned char*)skeys[index+1].data();
		}
		// if index is last one && state 0: goto state 1
		if(index < 0){
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
			return (unsigned char*)skeys[index+1].data();
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
			return (unsigned char*)skeys[index+1].data();
		}
		if(index < 0){
			state = 1;
		}
	break;
	}

	return NULL;
}

skeyC::unpop(){
//	cout<<"unpoped state="<<state<<'\n';
//	cout<<"unpopped index="<<index<<'\n';
	if(popped == 1)
		popped == 0;
	else
		throw(Error::CryptoErrC("cannot pop\n"));
	
	index++;
	switch(state){
	case 0:
		if(index > max_index)
			throw(Error::CryptoErrC("pop out of range\n"));		
	break;

	case 1:
		// add one to index
		if(index > max_index)
			throw(Error::CryptoErrC("pop out of range\n"));
	break;
	
	case 2:
		throw(Error::CryptoErrC("bad unpop\n"));
	break;

	case 3:
		if(index > max_index)
			throw(Error::CryptoErrC("pop out of range\n"));
	break;
	}
/*
	index++;
	if(index>max_index)
		throw(Error::CryptoErrC("pop out of range\n"));
*/
}

unsigned char* skeyC::getLastSkey(){
	if(state == 1 || state == 2)
		return (unsigned char*)skeys[index + 1].data();
	throw(Error::CryptoErrC("no last skey\n"));	
}
