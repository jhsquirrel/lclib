INCLUDES=-I./bf.d -I./sha.d -I./rsa.d -I./lclib.d -I./bnlib-1.1 -I/usr/include
BNOBJS=bnlib-1.1/bn00.o bnlib-1.1/lbn00.o bnlib-1.1/bn.o bnlib-1.1/lbnmem.o \
bnlib-1.1/sieve.o bnlib-1.1/prime.o bnlib-1.1/bnprint.o bnlib-1.1/legal.o \
bnlib-1.1/jacobi.o bnlib-1.1/germain.o

all: libbn.a Blowfish.o sha.o rsa.o lclib.o lclib.a
	gcc -O2 -W -Wall -pedantic -g -o test4 test4.c lclib.a $(INCLUDES)
	gcc -O2 -W -Wall -pedantic -g -o test5 test5.c lclib.a $(INCLUDES)
	gcc -O2 -W -Wall -pedantic -g -o test6 test6.c lclib.a $(INCLUDES)
	gcc -O2 -W -Wall -pedantic -g -o test7 test7.c lclib.a $(INCLUDES)
	gcc -O2 -W -Wall -pedantic -g -o test8 test8.c lclib.a $(INCLUDES)

lclib.a: lclib.o
	ar rcs lclib.a lclib.o Blowfish.o sha.o rsa.o $(BNOBJS)

Blowfish.o: ./bf.d/Blowfish.c
	gcc -Wall -g -c ./bf.d/Blowfish.c $(INCLUDES)

lclib.o: ./lclib.d/lclib.c
	gcc -Wall -g -c -DLE ./lclib.d/lclib.c $(INCLUDES)

sha.o: ./sha.d/sha.c
	gcc -c -O2 -ansi -Wall -pedantic -DUNROLL_LOOPS -DLITTLE_ENDIAN \
	./sha.d/sha.c

rsa.o: ./rsa.d/rsa.c
	gcc -Wall -g -c ./rsa.d/rsa.c $(INCLUDES)

libbn.a:
	cd bnlib-1.1;sh ./configure;make libbn.a;cp libbn.a ../;


install: lclib.a 
	rm -rf /opt/lclib;
	mkdir /opt/lclib;
	mkdir /opt/lclib/lib;
	mkdir /opt/lclib/head;
	mkdir /opt/lclib/api;
	mkdir /opt/lclib/api/head;
	cp lclib.a /opt/lclib/lib/;
	cp lclib.d/lclib.h /opt/lclib/head/;
	cp lclib.d/Blowfish.h /opt/lclib/head/;
	cp lclib.d/rsa.h /opt/lclib/head/;
	cp lclib.d/sha.h /opt/lclib/head/;
	cp lclib.d/err.h /opt/lclib/head/;
	cp bnlib-1.1/lbn32.h /opt/lclib/head/;
	cp bnlib-1.1/kludge.h /opt/lclib/head/;
	cp bnlib-1.1/bn.h /opt/lclib/head/;
	cp bnlib-1.1/prime.h /opt/lclib/head/;
	cp bnlib-1.1/bnprint.h /opt/lclib/head/;
	cp bnlib-1.1/*.h /opt/lclib/head;
	cp api.d/asymmetricC.hh /opt/lclib/api/head/;
	cp api.d/symmetricC.hh /opt/lclib/api/head/;
	cp api.d/hashC.hh /opt/lclib/api/head/;
	cp api.d/skeyC.hh /opt/lclib/api/head/;
	cp api.d/sskeyC.hh /opt/lclib/api/head/;
	cp api.d/errC.hh /opt/lclib/api/head/;
	cp api.d/stringC.hh /opt/lclib/api/head/;
	cp api.d/asymmetricC.o /opt/lclib/api/;
	cp api.d/symmetricC.o /opt/lclib/api/;
	cp api.d/hashC.o /opt/lclib/api/;
	cp api.d/skeyC.o /opt/lclib/api/;
	cp api.d/sskeyC.o /opt/lclib/api/;
	cp api.d/stringC.o /opt/lclib/api/;

clean:
	rm *.o test4 test5 test6 test7 test8 libbn.a bnlib-1.1/libbn.a;
	cd bnlib-1.1;make clean;
