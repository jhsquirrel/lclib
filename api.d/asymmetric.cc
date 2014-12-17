#include "asymmetricC.hh"
#include <iostream.h>

int gen(char * id, char *key);
int test(char *ida, char *idb, char *keya, char *keyb);

	asymmetricC a(512);
	asymmetricC b(512);

int gen(char * id, char *key) {
	// load keyrings
	try{
		a.loadPriKeys("./prikeys","","",0);
	}catch(Error::IOErrC e){
		cout<<e.message;
		}
	catch(Error::CryptoErrC e){
		cout<<e.message;
	}

	try{
		a.loadPubKeys("./pubkeys","");
	}catch(Error::IOErrC e){
		cout<<e.message;
	}
	catch(Error::CryptoErrC e){
		cout<<e.message;
	}
	

	// gen and save new keys

	try{
		a.genKeys();
	}catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}

	try{
	a.savePubKeys("./pubkeys",id);
	}catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}
	catch(Error::IOErrC e){
		cout<<e.message;
		return -1;
	}

	try{
	a.savePriKeys("./prikeys",id,key,strlen(key));
	}catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}
	catch(Error::IOErrC e){
		cout<<e.message;
		return -1;
	}
	return 0;
}

int test(char *ida, char *idb, char *keya, char *keyb) {
	unsigned char *data;
	unsigned char *data1=(unsigned char *)"my secret data1";
	unsigned char *data2=(unsigned char *)"my secret data2";	
	unsigned long int s1=strlen((char*)data1);
	unsigned long int s2=strlen((char*)data2);

	data1=a.alloc(data1,15);
	data2=b.alloc(data2,15);

	try{
		a.loadPriKeys("./prikeys",ida,keya,strlen(keya));
	}catch(Error::IOErrC e){
		cout<<e.message;
		return -1;
	}
	catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}

	try{
		a.loadPubKeys("./pubkeys",ida);
	}catch(Error::IOErrC e){
		cout<<e.message;
		return -1;
	}
	catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}



	try{
		b.loadPriKeys("./prikeys",idb,keyb,strlen(keyb));
	}catch(Error::IOErrC e){
		cout<<e.message;
		return -1;
	}
	catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}

	try{
		b.loadPubKeys("./pubkeys",idb);
	}catch(Error::IOErrC e){
		cout<<e.message;
		return -1;
	}
	catch(Error::CryptoErrC e){
		cout<<e.message;
		return -1;
	}

cout<<"ida="<<ida<<" idb="<<idb<<" keya="<<keya<<" keyb="<<keyb<<'\n';
	unsigned char *Na, *da, *ea;
	unsigned char *Nb, *db, *eb;

	// alice gets her keys and effectivly gives N to bob
	a.getKeys(&Na, &da, &ea);
	// bob gets her keys and effectivly gives N to alice
	b.getKeys(&Nb, &db, &eb);

	printf("\n");
	for(int i=0; i<a.getKeySize(); i++) {
		printf("%02x", Na[i]);
	}
	printf("\n");
	for(int i=0; i<b.getKeySize(); i++) {
		printf("%02x", Nb[i]);
	}
	printf("\n");

	// exchange keys
	try{
		a.setNKey(Nb);
	}catch(Error::CryptoErrC e){cout<<e.message;}

	try{
		b.setNKey(Na);
	}catch(Error::CryptoErrC e){cout<<e.message;}

	unsigned char *dta = (unsigned char*)"data a";
	unsigned char *dtb = (unsigned char*)"data b";
	unsigned char *dataA;
	unsigned char *dataB;

	dataA=a.alloc(dta,strlen((char*)dta));
	dataB=b.alloc(dtb,strlen((char*)dtb));
	unsigned long int sa=strlen((char*)dataA);
	unsigned long int sb=strlen((char*)dataB);

	printf("\nalice data:\n");
	for(int i=0; i<sa; i++){
		printf("%02x", dataA[i]);
	}
	printf("\nbob data:\n");
	for(int i=0; i<sb; i++){
		printf("%02x", dataB[i]);
	}
	printf("\n");

// alice encrypts with bobs public key
	try{
		a.encrypt(dataA,&sa);
	}catch(Error::CryptoErrC e){cout<<e.message;}

// bob encrypts with alices public key
	try{
		b.encrypt(dataB,&sb);
	}catch(Error::CryptoErrC e){cout<<e.message;}



// print out encrypted data

	printf("\nalice enc data:\n");
	for(int i=0; i<sa; i++){
		printf("%02x", dataA[i]);
	}
	printf("\nbob enc data:\n");
	for(int i=0; i<sb; i++){
		printf("%02x", dataB[i]);
	}
	printf("\n");



// set the correct public keys back - this necessary - may be a bug!
	try{
		a.setNKey(Na);
	}catch(Error::CryptoErrC e){cout<<e.message;}

	try{
		b.setNKey(Nb);
	}catch(Error::CryptoErrC e){cout<<e.message;}


cout<<"sb==="<<sb<<'\n';

// alice decrypts bobs message with her private key
	try{
		a.decrypt(dataB,&sb);
	}catch(Error::CryptoErrC e){cout<<e.message;}
	
// bobs decrypts alice message with his private key
	try{
		b.decrypt(dataA,&sa);
	}catch(Error::CryptoErrC e){cout<<e.message;}


// print out recv data

	printf("\nalice gets:\n");
	for(int i=0; i<sa; i++){
		printf("%02x", dataB[i]);
	}
	printf("\nbob gets:\n");
	for(int i=0; i<sb; i++){
		printf("%02x", dataA[i]);
	}
	printf("\n");
	return 0;
}




int main(int argc, char **argv){

	int rv;
	if (argc == 1) {
		cout<<"asymmetric [-g ida idb|-t ida idb keya keyb]"<<'\n';
		exit(0);
	}
	if (strcmp(argv[1],"-g")==0) {
		rv=gen(argv[2],argv[3]);
	} 
	if (strcmp(argv[1],"-t")==0) {
		rv=test(argv[2],argv[3],argv[4],argv[5]);
	}

}
