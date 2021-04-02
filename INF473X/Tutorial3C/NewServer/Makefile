all: client server fancyclient

client: client.o
	cc -g -o client client.o

client.o: client.c
	cc -c client.c 

server: server.o
	cc -g -lpthread -pthread -o server server.o

server.o:
	cc -c server.c

fancyclient: fancyclient.o
	cc -g -lpthread -pthread -o fancyclient fancyclient.o

fancyclient.o: fancyclient.c
	cc -c fancyclient.c

clean:
	rm client client.o fancyclient fancyclient.o server server.o
	