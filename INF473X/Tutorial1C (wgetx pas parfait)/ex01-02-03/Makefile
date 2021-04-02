all: hello-world international-hello-world fancy-hello-world address


hello-world: hello-world.o
	cc -g -o hello-world hello-world.o

hello-world.o: hello-world.c
	cc -c hello-world.c 


LANGUAGE=FRENCH
international-hello-world: international-hello-world.o
	cc -g -o international-hello-world international-hello-world.o

international-hello-world.o: international-hello-world.c
	cc -c -Wall -g international-hello-world.c -D$(LANGUAGE)



fancy-hello-world: fancy-hello-world.o
	cc -g -o fancy-hello-world fancy-hello-world.o

fancy-hello-world.o: fancy-hello-world.c
	cc -c fancy-hello-world.c 




address: address.o
	cc -g -o address address.o

address.o: address.c
	cc -c address.c


clean:
	rm hello-world hello-world.o 
	rm international-hello-world international-hello-world.o 
	rm fancy-hello-world fancy-hello-world.o 
	rm address address.o