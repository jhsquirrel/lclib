#ifndef errC_hh
#define errC_hh
#include <string.h>
namespace Error{

	class errC{
	public:
		const char *message;
	public:
	errC(){

	}
	errC(const char *m){
		message=m;
	}
	~errC(){
	}


	};


	class IOErrC :public errC{
	public:
	IOErrC(const char *m){
		message=m;
	}	
	};

	class CryptoErrC :public errC{
	public:
	CryptoErrC(const char *m){
		message=m;
	}
	};

	class MemErrC :public errC{
	public:
	MemErrC(const char *m){
		message=m;
	}
	};
};
#endif
