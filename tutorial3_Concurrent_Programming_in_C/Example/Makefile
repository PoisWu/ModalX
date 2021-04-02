

all:pthreads_example pthreads_example_broken
 
lock_example: lock_example.o
	cc -g -o lock_example lock_example.o 	

lock_example.o: lock_example.c
	cc -c -Wall -g lock_example.c


pthrads_example: pthreads_example.o
	cc -g -o pthreads_example pthreads_example.o -lpthreads

pthreads_example.o: pthreads_example.c
	cc -c -Wall -g pthreads_example.c

pthrads_example_broken: pthreads_example_broken.o
	cc -g -o pthreads_example_broken pthreads_example_broken.o -lpthreads

pthreads_example_broken.o: pthreads_example_broken.c
	cc -c -Wall -g pthreads_example_broken.c

clean:
	rm pthreads_example pthreads_example.o
	rm pthreads_example_broken pthreads_example_broken.o