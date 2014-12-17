#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "errC.hh"
#include "hashC.hh"

extern "C" {
#include "lclib.h"
}

class symmetricC {

protected:
	LCLIB_CTX ctx;
	int type;
	int mode;
	unsigned char hash1[SHA_DIGESTSIZE];

public:
	symmetricC();
	symmetricC(int type,int mode);
	symmetricC(int type,unsigned char * key,unsigned long keylen);
	symmetricC(int type,unsigned char * key,unsigned long l, \
	unsigned long r,unsigned long keylen);
	~symmetricC();
	
	symmetricC(const symmetricC &s);
	symmetricC & operator = (const symmetricC &s);

	setKey(unsigned char *key,unsigned long keylen);
	setIV(unsigned long l,unsigned long r);

protected:	
	encipher(int fde,int fdp,int fl);
	decipher(int fdd,int fde,int fl);

public:
	encipher(const char *fpe,const char *fpp);
	decipher(const char *fpd,const char *fpe);

	encipher(unsigned char *de,unsigned int *len,int pad);
	decipher(unsigned char *d,unsigned int *len,int unpad);

};
