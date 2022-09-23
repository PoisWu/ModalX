
all:analyse

clean:
	rm -f source_code source_code.o

source_code.o:source_code.c
	cc -c -Wall -g source_code.c

source_code:source_code.o
	cc -o source_code source_code.o

client: client.o
	cc -g -o $@ $< 

analyse: analyse.c
	cc analyse.c -o analyse
analyse.o:analyse.c
	gcc analyse.c -o
