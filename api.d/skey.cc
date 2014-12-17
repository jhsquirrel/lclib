#include "skeyC.hh"

int main(){
skeyC sk,skserver;
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

delete[] a1;

try{
sk.save_keys("./skey.dat");
}
catch(Error::IOErrC &e){
	cout<<e.message<<'\n';
}

try{
sk.load_keys("./skey.dat");
}
catch(Error::IOErrC &e){
	cout<<e.message<<'\n';
}

cout<<"popA\n";
unsigned char *s;
try{
	s=sk.pop();
}
catch(Error::CryptoErrC &c){
	cout<<c.message;
}

int a=skserver.check_key(s);
cout<<"a="<<a<<'\n';
for(int i=0;i<40;i++)
	printf("%c",s[i]);
printf("\n");

cout<<"popB\n";
s=sk.pop();
a=skserver.check_key(s);
cout<<a<<'\n';
for(int i=0;i<40;i++)
        printf("%c",s[i]);
printf("\n");

unsigned char *rv=sk.print_keys();
sk.read_keys(rv,3);
cout<<"read skey\n";

cout<<"popC\n";
try{
	s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

cout<<"popD\n";
try{
	s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

cout<<"popE\n";
try{
	s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

try{
	sk.unpop();
}
catch(Error::CryptoErrC &c){
	cout<<c.message;
}

cout<<"popF\n";
try{
        s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

cout<<"popG\n";
try{
        s=sk.pop();
}   
catch(Error::CryptoErrC &c){
        cout<<c.message;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

cout<<"popHa\n";
try{
        s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}   

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

sk.set_seed((unsigned char*)"fbe93da3306e79884c2911391610ec3eb743f9ab",40);
sk.init_skeys(3);

try{
        sk.unpop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}
cout<<"unpop lala\n";

a1=sk.print_keys();
for(int c=0;c<3;c++){
  for(int i=0;i<40;i++){
    printf("%c",a1[i+(c*40)]);
  }
  printf("\n");
}

delete[] a1;

cout<<"popH\n";
try{
        s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}
/*
try{
        s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
}
*/
for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

cout<<"pop last\n";
try{
        s=sk.pop();
}
catch(Error::CryptoErrC &c){  
        cout<<c.message;
}

try{
	s=sk.getLastSkey();
}
catch(Error::CryptoErrC &c){
	cout<<c.message;
}

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

try{
        s=sk.pop();
}
catch(Error::CryptoErrC &c){
        cout<<c.message;
} 

for(int i=0;i<40;i++)
  printf("%c",s[i]);
printf("\n");

return 0;
}
