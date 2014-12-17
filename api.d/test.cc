#include <list.h>
#include <iostream.h>

class test{
  public:
  test(){

  }
  ~test(){

  }
  struct pubDataFormat{

    pubDataFormat(){
//      cout<<"cons\n";
      n=NULL;
      e=NULL;
    }
    ~pubDataFormat(){
//      cout<<"dest\n";
      delete[] n;
      delete[] e;
    }
    pubDataFormat(const pubDataFormat &pdf){
//      cout<<"copy cons\n";
      memcpy(ident,pdf.ident,20);
      nbits=pdf.nbits;
      n=new unsigned char[nbits];
      e=new unsigned char[nbits];
      memcpy(n,pdf.n,nbits);
      memcpy(e,pdf.e,nbits);
      memcpy(fingerprint,pdf.fingerprint,20);
    }
    pubDataFormat& operator=(const pubDataFormat &pdf){
//      cout<<"operator = \n";
      memcpy(ident,pdf.ident,20);
      nbits=pdf.nbits;
       n=new unsigned char[nbits];  
      e=new unsigned char[nbits];
      memcpy(n,pdf.n,nbits);
      memcpy(e,pdf.e,nbits);
      memcpy(fingerprint,pdf.fingerprint,20);
      return *this;
    }

    unsigned char ident[20];
    unsigned int nbits;
    unsigned char *n;
    unsigned char *e;
    unsigned char fingerprint[20];
  }pubdf;

  typedef struct pubDataFormat pubDataFormat;

  list<pubDataFormat> lpub;

  loadPub(){

  }
  addPub(int a){
    back_insert_iterator<list<pubDataFormat> > it2(lpub);
    //it2=lpub.begin();
    pubDataFormat s;
    s.nbits=a;
    memcpy(s.ident,"abcdef0123456789abcd",20);
    s.n=new unsigned char[10];
    s.e=new unsigned char[10];
    memcpy(s.n,"abcdef0123",10);
    memcpy(s.e,"abcdef0123",10);
    memcpy(s.fingerprint,"abcdef0123456789abcd",20);
    *it2++=s;
    //delete[] s.n;
    //delete[] s.e;
  }
  writePub(){
    list<pubDataFormat>::iterator it2;
    it2=lpub.begin();
    while(1/*it2!=lpub.end()*/){
      pubDataFormat s=*it2++;
      cout<<"s.nbits="<<s.nbits<<'\n';
      if(it2==lpub.end())
        break;
    }
  }
  clearPub(){
    list<pubDataFormat>::iterator it2;
    it2=lpub.begin();
    while(1/*it2!=lpub.end()*/){
      pubDataFormat s=*it2++;
      //cout<<"s.nbits="<<s.nbits<<'\n';
      delete[] s.n;
      delete[] s.e;
      if(it2==lpub.end())
        break;
    }
  }
};

int main(){
  test a;
  a.addPub(2);
  a.addPub(4);
  a.addPub(10);
  a.writePub();
  a.clearPub();
}
