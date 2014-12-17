#include "id_sskeyC.hh"

int main(){
id_sskeyC sk,skserver;
sk.set_seed((unsigned char*)"fbe93da3306e79884c2911391610ec3eb743f9dc",40);
sk.init_skeys(3);

//sk.set_seed((unsigned char*)"seeddat1",8);
//sk.init_skeys(10);
unsigned char *a1=sk.print_keys();
for(int c=0;c<3;c++){
  for(int i=0;i<40;i++){
    printf("%c",a1[i+(c*40)]);
  }
  printf("\n");
}

try{
sk.save_keys("./id_sskey.dat");
}
catch(Error::IOErrC &e){
	cout<<e.message<<'\n';
}

try{
sk.load_keys("./id_sskey.dat");
}
catch(Error::IOErrC &e){
	cout<<e.message<<'\n';
}

try{
  sk.setkey("my_key",6);
}catch(Error::CryptoErrC e){
  cout<<e.message;
  return -1;
}

try{
  sk.calchashes();
}catch(Error::CryptoErrC e){
  cout<<e.message;
  return -1;
}

try{
  sk.encryptkeys();
}catch(Error::CryptoErrC e){
  cout<<e.message;
  return -1;
}

try{
sk.save_keys("./id_sskey.encdat");
}
catch(Error::IOErrC &e){
        cout<<e.message<<'\n';
}

unsigned char *s;
try{
  s=sk.pop();
}catch(Error::CryptoErrC e){
  cout<<e.message;
  return -1;
}
//printf("%p\n",s);
int a=skserver.check_key(s);
cout<<a<<'\n';
for(int i=0;i<40;i++)
	printf("%c",s[i]);
printf("\n");

try{
  s=sk.pop();
}catch(Error::CryptoErrC e){
  cout<<e.message;
  return -1;
}
//printf("%p\n",s);


a=skserver.check_key(s);
cout<<a<<'\n';

for(int i=0;i<40;i++)
        printf("%c",s[i]);
printf("\n");

unsigned char *rv=sk.print_keys();
sk.read_keys(rv,3);

try{
  s=sk.pop();
}catch(Error::CryptoErrC e){
  cout<<e.message;
  return -1;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

return 0;
}
