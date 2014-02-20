SHELL=/bin/bash
CC=gcc
#Took -std=c99 out of cflags
CFLAGS=-std=c99 -Wall -pedantic -g -D_POSIX_C_SOURCE=1 
LDFLAGS=

sc: sc.o lib.o md5.o scfuncs.o
scfuncs.o: scfuncs.h scfuncs.c
lib.o: lib.c lib.h common.h
md5.o: md5.c md5.h
sc.o: sc.c lib.h md5.h 
clean:
	$(RM) sc {sc,lib,md5,scfuncs}.o 
