INCLUDES = /opt/lclib/api/head


all: stringC.o hashC.o skeyC.o symmetricC.o asymmetricC.o hash symmetric \
asymmetric skey readpub sskeyC.o sskey id_sskeyC.o id_sskey

readpub: hashC.o readpub.cc
	g++ -g -O2 -o readpub readpub.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1 ./hashC.o symmetricC.o -I. ../lclib.a

hashC.o: hashC.cc hashC.hh errC.hh
	g++ -g -c hashC.cc -I../lclib.d/ -I../bf.d/ -I../rsa.d/ -I../sha.d \
	-I../bnlib-1.1

symmetricC.o: symmetricC.cc symmetricC.hh errC.hh
	g++ -g -c symmetricC.cc -I../lclib.d/ -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1

asymmetricC.o: asymmetricC.cc asymmetricC.hh errC.hh
	g++ -g -c asymmetricC.cc -I../lclib.d/ -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1

stringC.o: stringC.cc stringC.hh
	g++ -g -c stringC.cc

skeyC.o: stringC.cc stringC.hh skeyC.cc skeyC.hh errC.hh
	g++ -g -c skeyC.cc stringC.cc -I../lclib.d/ -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1

sskeyC.o: stringC.cc stringC.hh skeyC.hh errC.hh sskeyC.cc sskeyC.hh
	g++ -g -c sskeyC.cc stringC.cc -I../lclib.d/ -I../bf.d/ \
	-I../rsa.d/ -I../sha.d -I../bnlib-1.1

id_sskeyC.o: stringC.cc stringC.hh skeyC.cc skeyC.hh errC.hh sskeyC.cc \
	id_sskeyC.cc
	g++ -g -c id_sskeyC.cc stringC.cc -I../lclib.d/ -I../bf.d/ \
	-I../rsa.d/ -I../sha.d -I../bnlib-1.1

hash: hashC.o hash.cc
	g++ -Wall -g -o hash hash.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ -I../sha.d \
	-I../bnlib-1.1 ./hashC.o -I. ../lclib.a

symmetric: symmetricC.o symmetric.cc hashC.hh hashC.o 
	g++ -g -o symmetric symmetric.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1 ./symmetricC.o ./hashC.o -I. ../lclib.a

asymmetric: asymmetricC.o hashC.o symmetricC.o asymmetric.cc
	g++ -g -o asymmetric asymmetric.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1 ./asymmetricC.o ./hashC.o ./symmetricC.o \
	-I. ../lclib.a

skey: skeyC.o skey.cc stringC.hh
	g++ -g -o skey skey.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1 ./stringC.o ./skeyC.o ./hashC.o -I. \
	../lclib.a

sskey: sskeyC.o skeyC.o symmetricC.o sskey.cc stringC.hh 
	g++ -g -o sskey sskey.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1 ./stringC.o ./sskeyC.o ./skeyC.o ./hashC.o \
	./symmetricC.o -I. ../lclib.a

id_sskey: id_sskeyC.o sskeyC.o skeyC.o symmetricC.o sskey.cc stringC.hh
	g++ -g -o id_sskey id_sskey.cc -I../lclib.d -I../bf.d/ -I../rsa.d/ \
	-I../sha.d -I../bnlib-1.1 ./stringC.o ./id_sskeyC.o ./sskeyC.o \
	./skeyC.o ./hashC.o ./symmetricC.o -I. ../lclib.a

clean:
	rm *.o hash skey symmetric asymmetric
