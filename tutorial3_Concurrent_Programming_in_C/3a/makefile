TARG= client server 

all:$(TARG)

fancy_client: fancy_client.o
	cc -g -o $@ $< 

server: server.o
	cc -g -o $@ $< 

client: client.o
	cc -g -o $@ $< 


%.o:%.c
	cc -g -Wall -o $@ -c $<

clean:
	rm -f *.o $(TARG)