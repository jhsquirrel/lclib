#include "id_sskeyC.hh"

id_sskeyC::id_sskeyC(){
	memset(id,0,20);
}

id_sskeyC::~id_sskeyC(){

}

id_sskeyC::id_sskeyC(const id_sskeyC &ssk){
	sskeyC s=ssk;
	memcpy(id,ssk.id,20);
}

id_sskeyC& id_sskeyC::operator=(const id_sskeyC &ssk){
	sskeyC s=ssk;
	memcpy(id,ssk.id,20);
}
