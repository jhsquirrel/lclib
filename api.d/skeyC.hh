#include "hashC.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector.h>
#include "stringC.hh"
#include <time.h>

class skeyC : public hashC {
protected:
convertHashToHex(unsigned char*hh,unsigned char*h,int len);
vector<stringC> skeys;
stringC current_key;
int index, max_index, seedlen/*,toggle*/,state,popped;
unsigned char *seed;
unsigned char last_skey[SHA_DIGESTSIZE*2]/*,prev_skey[SHA_DIGESTSIZE]*/;

public:
skeyC();
skeyC(unsigned char *c);

~skeyC();

skeyC(const skeyC &sk);
skeyC & operator=(const skeyC &sk);

set_seed(unsigned char*seed,int len);
init_skeys(int no_of_skeys);

int check_key(unsigned char *c);
int check_key_reset(unsigned char *c,unsigned char *c2);

load_keys(const char *pathname);

save_keys(const char *pathname);
unsigned char * print_keys();
read_keys(unsigned char * k,int len);
unsigned char* pop();
unpop();
unsigned char* getLastSkey();
};
