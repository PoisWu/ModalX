/*
 * mutex.c
 *
 *  Created on: Mar 19, 2016
 *      Author: jiaziyi
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#define NTHREADS 50
void *increase_counter(void *);


int  counter = 0;

pthread_t thread[NTHREADS];
pthread_mutex_t lock;

int main()
{

	if(pthread_mutex_init(&lock, NULL)) {
		puts("Impossible to create Mutex\n"); 
		return -1;
	}

	//create 50 threads of increase_counter, each thread adding 1 to the counter
	int k = 0;
    while (k < NTHREADS) {
        pthread_create(&(thread[k]), NULL, increase_counter, NULL);
        k++;
    }

	k=0;
	while (k < NTHREADS) {
        pthread_join((thread[k]), NULL);
		k++;
    }

	printf("\nFinal counter value: %d\n", counter);
	//pthread_mutex_destroy(&lock);
	return 1;
}

void *increase_counter(void *arg)
{
	if(pthread_mutex_lock(&lock)) puts("Incapable of locking");
	printf("Thread number %ld, working on counter. The current value is %d\n", (long)pthread_self(), counter);
	counter++;
	if(pthread_mutex_unlock(&lock)) puts("Incapable of unlocking");
	return NULL;
}
