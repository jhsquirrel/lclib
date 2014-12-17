#include "symmetricC.hh" 
#include <iostream.h> 
int main(){ 
symmetricC s;
int i; 
unsigned char a[10];
memcpy(a,"mydatakeys",10);

try{ 
s.setKey(a,10);
}catch(Error::CryptoErrC e){
        //if(e.type==1)
cout<<e.message;
                return -1;//exit
}

try{
s.encipher("test.enc","test");
}
catch(Error::IOErrC io){
	cout<<io.message;
	return -1;
}
catch(Error::CryptoErrC co){
	cout<<co.message;
	return -1;
}

try{
s.decipher("test.dec","test.enc");
}
catch(Error::IOErrC io){
	cout<<io.message;
	return -1;
}
catch(Error::CryptoErrC co){
	cout<<co.message;
	return -1;
}

unsigned char * data;
unsigned int len=8;
data=new unsigned char[8];
memcpy(data,"test.enc",8);

try{
s.encipher(data,&len,1);
}
catch(Error::IOErrC io){
        cout<<io.message;
        return -1;
}
catch(Error::CryptoErrC co){
        cout<<co.message;
        return -1;
}

try{
s.decipher(data,&len,1);
}
catch(Error::IOErrC io){
        cout<<io.message;
        return -1;
}
catch(Error::CryptoErrC co){
        cout<<co.message;
        return -1;
}
cout<<data<<":"<<len<<'\n';
return 0;
}
