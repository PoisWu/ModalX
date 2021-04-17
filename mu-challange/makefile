
all:source_code

clean:
	rm -f source_code source_code.o

source_code.o:source_code.c
	cc -c -Wall -g source_code.c

source_code:source_code.o
	cc -o source_code source_code.o