#include "stringC.hh"

stringC::stringC(){
//cout<<"cons\n";
	str=NULL;
	len=0;
}

stringC::stringC(const char *s){
//	if (str != NULL)
//		delete[] str;
//
//cout<<"char cons"<<s<<'\n';
	str=new char[strlen(s) + 1];
	len=strlen(s);
	memcpy(str,s,len);
	str[len] = '\0';
}

stringC::stringC(const char *s,int l){
//	if (str != NULL)
//		delete[] str;
//
//cout<<"char cons int"<<s<<'\n';
	str=new char[l + 1];
	len=l;
	memcpy(str,s,len);
	str[len] = '\0';
}

stringC::~stringC(){
//cout<<"des"<<str<<this<<'\n';
	if(str!=NULL)
		delete[] str;
}

stringC::stringC(const stringC &s){
//	if(str!=NULL)
//		delete[] str;
//
//cout<<"copy cons"<<s.str<<s.len<<'\n';
	str=new char[s.len + 1];
	len=s.len;
	memcpy(str,s.str,s.len);
	str[len] = '\0';
//cout<<"copy cons str="<<str<<this<<'\n';
}

stringC & stringC::operator=(const stringC &s){
//	if(str != NULL)
//		delete[] str;
//
//cout<<"op =\n";
//cout<<"str="<<str<<s.len<<s.str<<&s<<'\n';
	str=new char[s.len + 1];
//cout<<"A";
	len=s.len;
//cout<<"B";
	memcpy(str,s.str,len);
//cout<<"C";
	str[len] = '\0';
//cout<<"D";
//cout<<"str="<<str<<'\n';
	return *this;
}

/*
ostream& stringC::operator<<(stringC &s) {
	cout<<s.data();
}
*/

char * stringC::data(){
	return str;
}

int stringC::size(){
	return len;
}

stringC::set(char *s,int l){
	if(str!=NULL)
		delete[] str;
//cout<<"set"<<s<<'\n';
	str=new char[l + 1];
	memcpy(str,s,l);
	len = l;
	str[len] = '\0';
}
