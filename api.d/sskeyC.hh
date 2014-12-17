#ifndef sskeyC_hh
#define sskeyC_hh
#include "skeyC.hh"
#include "symmetricC.hh"

class sskeyC : public skeyC {
  protected:
  symmetricC sym;
  char *key;
  int keylen;
  int state;
  stringC popdkey;

  /* state meaning
     0     start
     1     hash done
     2     encryption done
  */  
  vector<stringC> skeys_hash; 
  unsigned char* decryptskey(unsigned char *rv,unsigned int len);

  public:
  sskeyC();
  ~sskeyC();
  sskeyC(const sskeyC &ssk);
  sskeyC & operator=(const sskeyC &ssk);
  setkey(char *key,int len);
  init_skeys(int n);
  calchashes();
  encryptkeys();
  unsigned char * pop();  
  save_keys(const char *pathname);  
  load_keys(const char *pathname);
};

#endif
