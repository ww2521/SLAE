CFLAGS = -g -Wall -fno-stack-protector -z execstack
LDFLAGS = -g -fno-stack-protector -z execstack
CC = gcc
LIBS_PATH = -L.
LDLIBS = $(LIBS_PATH) -lrsa -lm

encoder: encoder.o librsa.a rsa.h

decoder: decoder.o librsa.a rsa.h

librsa.a: rsa.o
	ar rc librsa.a rsa.o
	ranlib librsa.a

rsa.o: rsa.c rsa.h
	gcc -c rsa.c

.PHONY: clean, all

clean:
	rm -f *.o a.out rsa.o rsa librsa.a

all: clean rsa
