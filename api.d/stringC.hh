#include <iostream.h>
#include <string.h>

class stringC{
private:
	char *str;
	int len;
public:
stringC();
stringC(const char *s);
stringC(const char *s,int l);
~stringC();
stringC(const stringC &s);
stringC & operator=(const stringC &s);
//ostream& operator<<(os);
set(char *s,int l);
char * data();
int size();
};

inline bool operator==(stringC s1,stringC s2){
	char *a,*b;
	a=s1.data();   
	b=s2.data();
	if(a==NULL || b==NULL)
		return false;
	if(strncmp(s1.data(),s2.data(),s1.size())==0)
		return true;
	else
		return false;
}

inline bool operator!=(stringC s1,stringC s2){
	char *a,*b;
	a=s1.data();
	b=s2.data();
	if(a==NULL || b==NULL)
		return false;
	if(strncmp(s1.data(),s2.data(),s1.size())==0)
		return false;
	else
		return true;
}			
