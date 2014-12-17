#ifndef hashC_hh
#define hashC_hh
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "errC.hh"

extern "C"{
#include "lclib.h"
}

class hashC{

protected:
	LCLIB_CTX ctx;
	int type;
	unsigned char hash[SHA_DIGESTSIZE];

public:
	hashC();
	hashC(int type);
	~hashC();
	
	hashC(const hashC &h);
	hashC & operator = (const hashC &h);

	int hashInit();
	
	int calcHash(int fd);
	int calcHash(FILE *fp);
	int calcHash(unsigned char *d, unsigned long len);
	int calcHash(const char * pathname);
        int convertToL_Endian(unsigned char* in);
        int convertHashToHex(unsigned char*hh,unsigned char*h,int len);
	unsigned char * getHash();

};
#endif
