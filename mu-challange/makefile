
all:source_code

clean:
	rm -f source_code source_code.c

source_code.o:source_code.c
	cc -c -Wall -g source_code.c
	
source_code:source_code.o
	cc -c -o source_code source_code.o