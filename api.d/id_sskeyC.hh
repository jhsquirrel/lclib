#ifndef id_sskeyC_hh
#define id_sskeyC_hh
#include "sskeyC.hh"

class id_sskeyC : public sskeyC {
  public:
  char id[20];
  id_sskeyC();
  ~id_sskeyC();
  id_sskeyC(const id_sskeyC &ssk);
  id_sskeyC & operator=(const id_sskeyC &ssk);
};

#endif
